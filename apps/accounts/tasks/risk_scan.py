import hashlib
from celery import shared_task
from django.db import models
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

from accounts.models import RiskRule, RiskFinding, Account
from accounts.risk_engine import registry
from common.utils import get_logger
from ops.celery.decorator import register_as_period_task
from orgs.utils import tmp_to_root_org, tmp_to_org

logger = get_logger(__name__)

__all__ = [
    'scan_accounts_for_policy',
    'enqueue_due_risk_rules'
]


@shared_task(
    verbose_name=_('Enqueue due risk rules'),
    description=_('Evaluate enabled risk rules and scan accounts to create findings')
)
@register_as_period_task(interval=60 * 60)
def enqueue_due_risk_rules():
    now = timezone.now()
    created = 0
    with tmp_to_root_org():
        due_rules = RiskRule.objects.filter(enabled=True).filter(
            models.Q(next_run_at__lte=now) | models.Q(next_run_at__isnull=True)
        )

    for rule in due_rules:
        scan_accounts_for_policy.delay(str(rule.id))
        rule.mark_scheduled(now, commit=True)
        created += 1
    return created


def _build_digest_map(accounts):
    digest_map = {}
    for account in accounts:
        if not account.secret:
            continue
        digest = hashlib.md5(account.secret.encode()).hexdigest()
        digest_map.setdefault(digest, []).append(account.id)
    return digest_map


@shared_task(
    queue='ansible',
    verbose_name=_('Scan accounts for risk rules'),
    description=_('Execute risk rule scans and persist findings')
)
def scan_accounts_for_policy(rule_id=None):
    with tmp_to_root_org():
        rules = RiskRule.objects.filter(enabled=True)
        if rule_id:
            rules = rules.filter(id=rule_id)

    for rule in rules:
        engine_fn = registry.get(rule.engine)
        if not engine_fn:
            logger.warning('Unknown risk engine %s', rule.engine)
            continue

        with tmp_to_org(rule.org_id):
            accounts = rule.get_accounts().select_related('asset')
            digest_map = _build_digest_map(accounts) if rule.engine == 'repeated_password' else {}
            ctx_conditions = dict(rule.conditions or {})
            if digest_map:
                ctx_conditions['__digest_map'] = digest_map

            # quick map of existing findings for dedupe
            existing = RiskFinding.objects.filter(rule=rule, account__in=accounts)
            existing_map = {f.fingerprint: f for f in existing}

            for account in accounts:
                triggered, evidence = engine_fn(account, ctx_conditions)
                fp = RiskFinding.build_fingerprint(rule.id, account.id)
                finding = existing_map.get(fp)
                if triggered:
                    if finding:
                        finding.status = RiskFinding.Status.OPEN
                        finding.evidence = evidence
                        finding.severity = rule.severity
                        finding.save(update_fields=['status', 'evidence', 'severity', 'last_seen'])
                    else:
                        RiskFinding.objects.create(
                            rule=rule,
                            asset=account.asset,
                            account=account,
                            fingerprint=fp,
                            evidence=evidence,
                            severity=rule.severity,
                        )
                else:
                    if finding and finding.status == RiskFinding.Status.OPEN:
                        finding.status = RiskFinding.Status.RESOLVED
                        finding.save(update_fields=['status', 'last_seen'])

        rule.mark_scheduled(commit=True)
