import uuid
from django.db import models
from celery import shared_task
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

from accounts.const import AutomationTypes, SecretStrategy
from accounts.models import SecretRotationPolicy, SecretRotationJob, AutomationExecution
from assets.tasks.common import generate_automation_execution_data
from common.const.choices import Status, Trigger
from common.utils import get_logger
from ops.celery.decorator import register_as_period_task
from orgs.utils import tmp_to_org, tmp_to_root_org

logger = get_logger(__name__)

__all__ = [
    'enqueue_due_rotation_policies',
    'run_rotation_job',
]


@shared_task(
    verbose_name=_('Enqueue due secret rotation policies'),
    description=_('Evaluate rotation policies and enqueue jobs when due')
)
@register_as_period_task(interval=60 * 60)
def enqueue_due_rotation_policies():
    now = timezone.now()
    created = 0
    with tmp_to_root_org():
        due_policies = SecretRotationPolicy.objects.filter(enabled=True).filter(
            models.Q(next_run_at__lte=now) | models.Q(next_run_at__isnull=True)
        )

    for policy in due_policies:
        with tmp_to_org(policy.org_id):
            if policy.jobs.filter(status__in=[Status.pending, Status.running]).exists():
                continue
            job = SecretRotationJob.objects.create(
                policy=policy,
                trigger=Trigger.timing,
                status=Status.pending,
            )
            policy.mark_scheduled(now, commit=True)
            run_rotation_job.delay(str(job.id))
            created += 1

    return created


@shared_task(
    queue='ansible',
    verbose_name=_('Run secret rotation job'),
    description=_('Execute a secret rotation job using change_secret automation')
)
def run_rotation_job(job_id):
    with tmp_to_root_org():
        job = SecretRotationJob.objects.select_related('policy').filter(id=job_id).first()

    if not job:
        logger.error('SecretRotationJob %s not found', job_id)
        return

    policy = job.policy
    if not policy or not policy.enabled:
        job.mark_finished(Status.canceled, error=_('Policy disabled'))
        return

    job.mark_running()

    try:
        with tmp_to_org(policy.org_id):
            accounts_qs = policy.get_target_accounts().filter(is_active=True, secret_reset=True)
            account_ids = list(accounts_qs.values_list('id', flat=True))
            assets_qs = policy.get_all_assets()
            asset_ids = list(assets_qs.values_list('id', flat=True))
            if not asset_ids and account_ids:
                asset_ids = list(accounts_qs.values_list('asset_id', flat=True))

            if not account_ids:
                job.mark_finished(Status.failed, error=_('No accounts matched policy scope'))
                return

            if policy.secret_strategy == SecretStrategy.custom and not policy.secret:
                job.mark_finished(Status.failed, error=_('Custom strategy requires a secret'))
                return

            snapshot = {
                'name': _('Secret rotation: %s') % policy.name,
                'secret_strategy': policy.secret_strategy,
                'secret_type': policy.secret_type,
                'secret': policy.secret,
                'password_rules': policy.password_rules,
                'ssh_key_change_strategy': policy.ssh_key_change_strategy,
                'check_conn_after_change': policy.check_conn_after_change,
                'accounts': [str(i) for i in account_ids],
                'assets': [str(a) for a in asset_ids],
                'nodes': [str(n) for n in policy.nodes.values_list('id', flat=True)],
                'params': policy.params,
                'recipients': [str(u.id) for u in policy.recipients.all()],
                'policy_id': str(policy.id),
            }

            if policy.secret_strategy != SecretStrategy.custom:
                snapshot.pop('secret', None)

            task_name = _('Secret rotation job: %s') % policy.name
            data = generate_automation_execution_data(task_name, AutomationTypes.change_secret, snapshot)
            while AutomationExecution.objects.filter(id=data['id']).exists():
                data['id'] = str(uuid.uuid4())

            execution = AutomationExecution.objects.create(
                type=AutomationTypes.change_secret,
                trigger=job.trigger,
                **data,
            )
            job.snapshot = snapshot
            job.execution = execution
            job.save(update_fields=['snapshot', 'execution'])

            execution.start()
            execution.refresh_from_db()

            exec_status = Status.success if execution.is_success else Status.failed
            error_msg = '' if execution.is_success else str(execution.summary or execution.result or '')
            job.mark_finished(exec_status, summary=execution.summary or {}, error=error_msg, execution=execution)
    except Exception as exc:
        logger.exception(exc)
        job.mark_finished(Status.error, error=str(exc))
