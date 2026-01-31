from django.utils.translation import gettext_lazy as _
from rest_framework import serializers

from accounts.models import RiskFinding, RiskSeverity
from common.serializers.fields import ObjectRelatedField, LabeledChoiceField
from orgs.mixins.serializers import BulkOrgResourceModelSerializer

__all__ = ['RiskFindingSerializer']


class RiskFindingSerializer(BulkOrgResourceModelSerializer):
    status = LabeledChoiceField(choices=RiskFinding.Status.choices, required=False, label=_('Status'))
    severity = LabeledChoiceField(choices=RiskSeverity.choices, required=False, label=_('Severity'))
    rule = ObjectRelatedField(queryset=None, label=_('Rule'))
    asset = ObjectRelatedField(queryset=None, label=_('Asset'))
    account = ObjectRelatedField(queryset=None, label=_('Account'), attrs=("id", "username"))

    class Meta:
        model = RiskFinding
        read_only_fields = [
            'first_seen', 'last_seen', 'fingerprint', 'severity',
            'date_created', 'date_updated', 'org_id'
        ]
        fields = [
            'id', 'rule', 'asset', 'account', 'status', 'first_seen', 'last_seen',
            'fingerprint', 'evidence', 'severity', 'date_created', 'date_updated'
        ]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        from accounts.models import RiskRule, Account
        from assets.models import Asset
        self.fields['rule'].queryset = RiskRule.objects
        self.fields['asset'].queryset = Asset.objects
        self.fields['account'].queryset = Account.objects
