from django.utils import timezone
from rest_framework import status
from rest_framework.decorators import action
from rest_framework.response import Response

from accounts import serializers
from accounts.models import RiskRule
from accounts.permissions import RiskRuleRBACPermission
from common.permissions import IsValidLicense
from orgs.mixins.api import OrgBulkModelViewSet

__all__ = ['RiskRuleViewSet']


class RiskRuleViewSet(OrgBulkModelViewSet):
    model = RiskRule
    serializer_class = serializers.RiskRuleSerializer
    permission_classes = [RiskRuleRBACPermission, IsValidLicense]
    filterset_fields = ('name', 'engine', 'enabled', 'severity')
    search_fields = ('name',)
    rbac_perms = {
        'test': 'accounts.view_riskfinding',
    }

    @action(methods=['post'], detail=True, url_path='test')
    def test_rule(self, request, *args, **kwargs):
        rule = self.get_object()
        rule.last_run_at = timezone.now()
        rule.next_run_at = rule.compute_next_run(rule.last_run_at)
        rule.save(update_fields=['last_run_at', 'next_run_at'])
        return Response({'detail': 'Rule scheduled'} , status=status.HTTP_200_OK)
