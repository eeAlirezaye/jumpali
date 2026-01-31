from datetime import timedelta

from django.db import models
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

from accounts.const import SecretType, SecretStrategy, SSHKeyStrategy
from common.const.choices import Status, Trigger
from common.db import fields
from orgs.mixins.models import JMSOrgBaseModel

__all__ = [
    'SecretRotationPolicy', 'SecretRotationJob'
]


class SecretRotationPolicy(JMSOrgBaseModel):
    name = models.CharField(max_length=128, verbose_name=_('Name'))
    enabled = models.BooleanField(default=True, verbose_name=_('Enabled'))
    accounts = models.JSONField(default=list, verbose_name=_('Account usernames'))
    nodes = models.ManyToManyField('assets.Node', blank=True, verbose_name=_('Nodes'))
    assets = models.ManyToManyField('assets.Asset', blank=True, verbose_name=_('Assets'))
    secret_type = models.CharField(
        max_length=16, choices=SecretType.choices,
        default=SecretType.PASSWORD, verbose_name=_('Secret type')
    )
    secret_strategy = models.CharField(
        max_length=16, choices=SecretStrategy.choices,
        default=SecretStrategy.random, verbose_name=_('Secret strategy')
    )
    secret = fields.EncryptTextField(blank=True, null=True, verbose_name=_('Secret'))
    password_rules = models.JSONField(default=dict, verbose_name=_('Password rules'))
    ssh_key_change_strategy = models.CharField(
        max_length=16, choices=SSHKeyStrategy.choices,
        default=SSHKeyStrategy.set_jms, verbose_name=_('SSH key change strategy')
    )
    check_conn_after_change = models.BooleanField(
        default=True, verbose_name=_('Check connection after change')
    )
    params = models.JSONField(default=dict, verbose_name=_('Parameters'))
    recipients = models.ManyToManyField('users.User', blank=True, verbose_name=_('Recipients'))
    interval_hours = models.PositiveIntegerField(default=24, verbose_name=_('Interval hours'))
    start_time = models.DateTimeField(null=True, blank=True, verbose_name=_('First run after'))
    next_run_at = models.DateTimeField(
        null=True, blank=True, db_index=True, verbose_name=_('Next run at')
    )
    last_run_at = models.DateTimeField(null=True, blank=True, verbose_name=_('Last run at'))

    class Meta:
        verbose_name = _('Secret rotation policy')
        unique_together = (('org_id', 'name'),)
        ordering = ('-date_created',)

    def __str__(self):
        return self.name

    def get_all_assets(self):
        from assets.models import Asset, Node
        nodes = self.nodes.all()
        node_asset_ids = Node.get_nodes_all_assets(*nodes).values_list('id', flat=True)
        direct_asset_ids = self.assets.all().values_list('id', flat=True)
        asset_ids = set(list(node_asset_ids) + list(direct_asset_ids))
        return Asset.objects.filter(id__in=asset_ids)

    def get_target_accounts(self):
        from accounts.models import Account
        assets = self.get_all_assets()
        asset_ids = assets.values_list('id', flat=True)
        qs = Account.objects.filter(asset_id__in=asset_ids)
        usernames = self.accounts or []
        if usernames:
            qs = qs.filter(username__in=usernames)
        if self.secret_type:
            qs = qs.filter(secret_type=self.secret_type)
        return qs

    def compute_next_run(self, from_time=None):
        now = from_time or timezone.now()
        if not self.interval_hours:
            return None
        if self.start_time and not self.last_run_at and self.start_time > now:
            return self.start_time
        base = self.last_run_at or self.start_time or now
        return base + timedelta(hours=self.interval_hours)

    def ensure_next_run(self):
        if not self.enabled:
            self.next_run_at = None
            return self.next_run_at
        if not self.next_run_at:
            self.next_run_at = self.start_time if self.start_time else timezone.now()
        return self.next_run_at

    def mark_scheduled(self, now=None, commit=True):
        now = now or timezone.now()
        self.last_run_at = now
        self.next_run_at = self.compute_next_run(now)
        if commit:
            self.save(update_fields=['last_run_at', 'next_run_at'])
        return self.next_run_at

    def save(self, *args, **kwargs):
        self.ensure_next_run()
        return super().save(*args, **kwargs)


class SecretRotationJob(JMSOrgBaseModel):
    policy = models.ForeignKey(
        SecretRotationPolicy, related_name='jobs', on_delete=models.CASCADE,
        verbose_name=_('Policy')
    )
    requested_by = models.ForeignKey(
        'users.User', null=True, blank=True, on_delete=models.SET_NULL,
        related_name='secret_rotation_jobs', verbose_name=_('Requested by')
    )
    status = models.CharField(
        max_length=16, choices=Status.choices,
        default=Status.pending, verbose_name=_('Status')
    )
    trigger = models.CharField(
        max_length=16, choices=Trigger.choices,
        default=Trigger.manual, verbose_name=_('Trigger')
    )
    execution = models.ForeignKey(
        'accounts.AutomationExecution', null=True, blank=True,
        related_name='rotation_jobs', on_delete=models.SET_NULL,
        verbose_name=_('Automation execution')
    )
    started_at = models.DateTimeField(null=True, blank=True, verbose_name=_('Started at'))
    ended_at = models.DateTimeField(null=True, blank=True, verbose_name=_('Ended at'))
    summary = models.JSONField(default=dict, verbose_name=_('Summary'))
    error = models.TextField(default='', blank=True, verbose_name=_('Error message'))
    snapshot = models.JSONField(default=dict, verbose_name=_('Payload snapshot'))

    class Meta:
        verbose_name = _('Secret rotation job')
        ordering = ('-date_created',)

    def __str__(self):
        return f"{self.policy.name} @ {self.date_created:%Y-%m-%d %H:%M:%S}"

    def save(self, *args, **kwargs):
        if self.policy_id and not self.org_id:
            self.org_id = self.policy.org_id
        return super().save(*args, **kwargs)

    def mark_running(self):
        self.status = Status.running
        self.started_at = timezone.now()
        self.error = ''
        self.save(update_fields=['status', 'started_at', 'error'])

    def mark_finished(self, status, summary=None, error=None, execution=None):
        self.status = status
        self.ended_at = timezone.now()
        if summary is not None:
            self.summary = summary
        if error is not None:
            self.error = error
        if execution is not None:
            self.execution = execution
        self.save(update_fields=['status', 'ended_at', 'summary', 'error', 'execution'])
