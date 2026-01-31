from django.contrib import admin

from accounts.models import (
    SecretRotationPolicy, SecretRotationJob,
    RiskRule, RiskFinding
)


@admin.register(SecretRotationPolicy)
class SecretRotationPolicyAdmin(admin.ModelAdmin):
    list_display = ('name', 'org_id', 'enabled', 'interval_hours', 'next_run_at', 'last_run_at')
    search_fields = ('name', 'org_id')
    list_filter = ('enabled', 'secret_type', 'secret_strategy')


@admin.register(SecretRotationJob)
class SecretRotationJobAdmin(admin.ModelAdmin):
    list_display = ('id', 'policy', 'status', 'trigger', 'started_at', 'ended_at', 'org_id')
    list_filter = ('status', 'trigger')
    search_fields = ('policy__name', 'policy__org_id')


@admin.register(RiskRule)
class RiskRuleAdmin(admin.ModelAdmin):
    list_display = ('name', 'engine', 'severity', 'enabled', 'org_id', 'next_run_at')
    search_fields = ('name', 'engine', 'org_id')
    list_filter = ('severity', 'enabled')


@admin.register(RiskFinding)
class RiskFindingAdmin(admin.ModelAdmin):
    list_display = ('rule', 'account', 'asset', 'status', 'severity', 'last_seen', 'org_id')
    list_filter = ('status', 'severity')
    search_fields = ('rule__name', 'account__username', 'asset__name', 'org_id')
