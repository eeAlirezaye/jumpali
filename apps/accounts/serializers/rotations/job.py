from django.utils.translation import gettext_lazy as _
from rest_framework import serializers

from accounts.models import SecretRotationJob, SecretRotationPolicy, AutomationExecution
from common.const.choices import Status, Trigger
from common.serializers.fields import LabeledChoiceField, ObjectRelatedField
from orgs.mixins.serializers import BulkOrgResourceModelSerializer
from users.models import User

__all__ = ['SecretRotationJobSerializer']


class SecretRotationJobSerializer(BulkOrgResourceModelSerializer):
    status = LabeledChoiceField(choices=Status.choices, read_only=True, label=_('Status'))
    trigger = LabeledChoiceField(choices=Trigger.choices, read_only=True, label=_('Trigger mode'))
    policy = ObjectRelatedField(queryset=SecretRotationPolicy.objects, label=_('Policy'))
    requested_by = ObjectRelatedField(queryset=User.objects, required=False, label=_('Requested by'))
    execution = ObjectRelatedField(
        queryset=AutomationExecution.objects, required=False, label=_('Automation execution')
    )

    class Meta:
        model = SecretRotationJob
        read_only_fields = [
            'status', 'trigger', 'started_at', 'ended_at', 'summary',
            'error', 'execution', 'snapshot', 'date_created', 'date_updated',
            'requested_by', 'policy'
        ]
        fields = [
            'id', 'policy', 'requested_by', 'status', 'trigger', 'started_at',
            'ended_at', 'execution', 'summary', 'error', 'snapshot',
            'date_created', 'date_updated',
        ]

    def to_representation(self, instance):
        data = super().to_representation(instance)
        if instance.execution:
            data['execution_id'] = str(instance.execution_id)
        return data
