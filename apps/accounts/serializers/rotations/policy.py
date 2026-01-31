from django.utils.translation import gettext_lazy as _
from rest_framework import serializers

from accounts.const import SecretType, SecretStrategy, SSHKeyStrategy
from accounts.models import SecretRotationPolicy
from accounts.serializers import AuthValidateMixin, PasswordRulesSerializer
from common.serializers.fields import LabeledChoiceField, ObjectRelatedField
from orgs.mixins.serializers import BulkOrgResourceModelSerializer

__all__ = ['SecretRotationPolicySerializer']


class SecretRotationPolicySerializer(AuthValidateMixin, BulkOrgResourceModelSerializer):
    secret_strategy = LabeledChoiceField(
        choices=SecretStrategy.choices, required=True, label=_('Secret strategy')
    )
    secret_type = LabeledChoiceField(
        choices=SecretType.choices, required=True, label=_('Secret type')
    )
    ssh_key_change_strategy = LabeledChoiceField(
        choices=SSHKeyStrategy.choices, required=False, label=_('SSH key change strategy'),
        default=SSHKeyStrategy.set_jms
    )
    password_rules = PasswordRulesSerializer(required=False, label=_('Password rules'))
    accounts = serializers.ListField(
        child=serializers.CharField(max_length=128), allow_empty=False, label=_('Account usernames')
    )
    assets = ObjectRelatedField(many=True, required=False, queryset=None, label=_('Assets'))
    nodes = ObjectRelatedField(many=True, required=False, queryset=None, label=_('Nodes'))
    recipients = ObjectRelatedField(many=True, required=False, queryset=None, label=_('Recipients'))
    interval_hours = serializers.IntegerField(min_value=1, required=False, label=_('Interval hours'))

    class Meta:
        model = SecretRotationPolicy
        read_only_fields = ['next_run_at', 'last_run_at', 'date_created', 'date_updated', 'created_by']
        fields = [
            'id', 'name', 'comment', 'enabled', 'accounts', 'nodes', 'assets', 'secret_type',
            'secret_strategy', 'secret', 'passphrase', 'password_rules', 'ssh_key_change_strategy',
            'check_conn_after_change', 'params', 'recipients', 'interval_hours',
            'start_time', 'next_run_at', 'last_run_at',
        ] + read_only_fields
        extra_kwargs = {
            'name': {'required': True},
            'enabled': {'required': False},
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        from assets.models import Asset, Node
        from users.models import User
        self.fields['assets'].queryset = Asset.objects
        self.fields['nodes'].queryset = Node.objects
        self.fields['recipients'].queryset = User.objects

    def validate_password_rules(self, password_rules):
        secret_type = self.initial_data.get('secret_type') or (
            self.instance.secret_type if self.instance else SecretType.PASSWORD
        )
        secret_strategy = self.initial_data.get('secret_strategy') or (
            self.instance.secret_strategy if self.instance else SecretStrategy.random
        )
        if secret_type != SecretType.PASSWORD:
            return {}
        if secret_strategy == SecretStrategy.custom:
            return password_rules or {}

        password_rules = password_rules or {}
        length = password_rules.get('length')
        if length is None:
            return password_rules
        try:
            length = int(length)
        except Exception:
            raise serializers.ValidationError(_('* Please enter the correct password length'))

        if length < 8 or length > 36:
            raise serializers.ValidationError(_('* Password length range 8-36 bits'))
        return password_rules

    def validate_accounts(self, accounts):
        cleaned = [a for a in accounts if a]
        if not cleaned:
            raise serializers.ValidationError(_('At least one account username is required'))
        return list(dict.fromkeys(cleaned))

    def validate(self, attrs):
        attrs = super().validate(attrs)
        secret_type = attrs.get('secret_type', getattr(self.instance, 'secret_type', None))
        secret_strategy = attrs.get('secret_strategy', getattr(self.instance, 'secret_strategy', None))
        secret = attrs.get('secret', getattr(self.instance, 'secret', ''))

        if secret_type == SecretType.PASSWORD:
            attrs.pop('ssh_key_change_strategy', None)
        elif secret_type == SecretType.SSH_KEY:
            attrs.pop('password_rules', None)

        if secret_strategy == SecretStrategy.custom and not secret:
            raise serializers.ValidationError({'secret': _('Custom strategy requires a secret')})

        if secret_strategy != SecretStrategy.custom:
            attrs.pop('secret', None)
        return attrs
