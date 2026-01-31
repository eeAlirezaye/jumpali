from django.utils.translation import gettext_lazy as _
from rest_framework import serializers

from accounts.models import RiskRule, RiskSeverity
from common.serializers.fields import ObjectRelatedField, LabeledChoiceField
from orgs.mixins.serializers import BulkOrgResourceModelSerializer

__all__ = ['RiskRuleSerializer']


class RiskRuleSerializer(BulkOrgResourceModelSerializer):
    severity = LabeledChoiceField(choices=RiskSeverity.choices, required=False, label=_('Severity'))
    nodes = ObjectRelatedField(many=True, required=False, queryset=None, label=_('Nodes'))
    assets = ObjectRelatedField(many=True, required=False, queryset=None, label=_('Assets'))

    class Meta:
        model = RiskRule
        read_only_fields = ['next_run_at', 'last_run_at', 'date_created', 'date_updated']
        fields = [
            'id', 'name', 'comment', 'enabled', 'engine', 'severity', 'conditions', 'accounts',
            'nodes', 'assets', 'interval_hours', 'start_time', 'next_run_at', 'last_run_at'
        ] + read_only_fields

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        from assets.models import Node, Asset
        self.fields['nodes'].queryset = Node.objects
        self.fields['assets'].queryset = Asset.objects

    def validate_accounts(self, accounts):
        if accounts is None:
            return []
        return list(dict.fromkeys([a for a in accounts if a]))
