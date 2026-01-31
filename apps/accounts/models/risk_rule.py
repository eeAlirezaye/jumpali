from datetime import timedelta
import hashlib

from django.db import models
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

from orgs.mixins.models import JMSOrgBaseModel
from assets.models import Asset, Node
from accounts.models import Account

__all__ = ['RiskSeverity', 'RiskRule', 'RiskFinding']


class RiskSeverity(models.TextChoices):
    LOW = 'low', _('Low')
    MEDIUM = 'medium', _('Medium')
    HIGH = 'high', _('High')
    CRITICAL = 'critical', _('Critical')


class RiskRule(JMSOrgBaseModel):
    name = models.CharField(max_length=128, verbose_name=_('Name'))
    enabled = models.BooleanField(default=True, verbose_name=_('Enabled'))
    engine = models.CharField(max_length=64, verbose_name=_('Engine'))
    severity = models.CharField(
        max_length=16, choices=RiskSeverity.choices,
        default=RiskSeverity.MEDIUM, verbose_name=_('Severity')
    )
    conditions = models.JSONField(default=dict, verbose_name=_('Conditions'))
    accounts = models.JSONField(default=list, verbose_name=_('Account usernames'), blank=True)
    nodes = models.ManyToManyField(Node, blank=True, verbose_name=_('Nodes'))
    assets = models.ManyToManyField(Asset, blank=True, verbose_name=_('Assets'))
    interval_hours = models.PositiveIntegerField(default=24, verbose_name=_('Interval hours'))
    start_time = models.DateTimeField(null=True, blank=True, verbose_name=_('First run after'))
    next_run_at = models.DateTimeField(null=True, blank=True, db_index=True, verbose_name=_('Next run at'))
    last_run_at = models.DateTimeField(null=True, blank=True, verbose_name=_('Last run at'))

    class Meta:
        verbose_name = _('Risk rule')
        unique_together = (('org_id', 'name'),)
        ordering = ('-date_created',)

    def __str__(self):
        return self.name

    def get_assets(self):
        node_asset_ids = Node.get_nodes_all_assets(*self.nodes.all()).values_list('id', flat=True)
        asset_ids = set(list(node_asset_ids) + list(self.assets.values_list('id', flat=True)))
        if not asset_ids:
            return Asset.objects.all()
        return Asset.objects.filter(id__in=asset_ids)

    def get_accounts(self):
        assets = self.get_assets()
        qs = Account.objects.filter(asset__in=assets)
        if self.accounts:
            qs = qs.filter(username__in=self.accounts)
        return qs

    def compute_next_run(self, base=None):
        now = base or timezone.now()
        if not self.interval_hours:
            return None
        if self.start_time and not self.last_run_at and self.start_time > now:
            return self.start_time
        pivot = self.last_run_at or self.start_time or now
        return pivot + timedelta(hours=self.interval_hours)

    def mark_scheduled(self, run_time=None, commit=True):
        self.last_run_at = run_time or timezone.now()
        self.next_run_at = self.compute_next_run(self.last_run_at)
        if commit:
            self.save(update_fields=['last_run_at', 'next_run_at'])
        return self.next_run_at

    def save(self, *args, **kwargs):
        if self.enabled and not self.next_run_at:
            self.next_run_at = self.start_time or timezone.now()
        if not self.enabled:
            self.next_run_at = None
        return super().save(*args, **kwargs)


class RiskFinding(JMSOrgBaseModel):
    class Status(models.TextChoices):
        OPEN = 'open', _('Open')
        IGNORED = 'ignored', _('Ignored')
        RESOLVED = 'resolved', _('Resolved')

    rule = models.ForeignKey(RiskRule, related_name='findings', on_delete=models.CASCADE, verbose_name=_('Rule'))
    asset = models.ForeignKey(Asset, related_name='risk_findings', on_delete=models.CASCADE, verbose_name=_('Asset'))
    account = models.ForeignKey(Account, related_name='risk_findings', on_delete=models.CASCADE, verbose_name=_('Account'))
    fingerprint = models.CharField(max_length=64, db_index=True, verbose_name=_('Fingerprint'))
    status = models.CharField(max_length=16, choices=Status.choices, default=Status.OPEN, verbose_name=_('Status'))
    first_seen = models.DateTimeField(auto_now_add=True, verbose_name=_('First seen'))
    last_seen = models.DateTimeField(auto_now=True, verbose_name=_('Last seen'))
    evidence = models.JSONField(default=dict, verbose_name=_('Evidence'))
    severity = models.CharField(
        max_length=16, choices=RiskSeverity.choices,
        default=RiskSeverity.MEDIUM, verbose_name=_('Severity')
    )

    class Meta:
        verbose_name = _('Risk finding')
        unique_together = (('rule', 'fingerprint'),)
        ordering = ('-last_seen',)

    def __str__(self):
        return f"{self.rule.name}: {self.account.username}@{self.asset}"

    @staticmethod
    def build_fingerprint(rule_id, account_id, extra=None):
        payload = f"{rule_id}:{account_id}:{extra or ''}"
        return hashlib.md5(payload.encode()).hexdigest()

    def resolve(self, status=None):
        self.status = status or self.Status.RESOLVED
        self.save(update_fields=['status'])
