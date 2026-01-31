from rest_framework import status, mixins, viewsets
from rest_framework.decorators import action
from rest_framework.response import Response

from accounts import serializers
from accounts.models import RiskFinding
from accounts.permissions import RiskFindingRBACPermission
from common.permissions import IsValidLicense

__all__ = ['RiskFindingViewSet']


class RiskFindingViewSet(mixins.ListModelMixin,
                         mixins.RetrieveModelMixin,
                         viewsets.GenericViewSet):
    model = RiskFinding
    serializer_class = serializers.RiskFindingSerializer
    permission_classes = [RiskFindingRBACPermission, IsValidLicense]
    filterset_fields = ('status', 'rule', 'severity', 'asset')
    search_fields = ('account__username', 'asset__name', 'rule__name')
    rbac_perms = {
        'resolve': 'accounts.change_riskfinding',
        'ignore': 'accounts.change_riskfinding',
    }

    def get_queryset(self):
        return RiskFinding.objects.select_related('rule', 'account', 'asset')

    @action(methods=['post'], detail=True, url_path='resolve')
    def resolve(self, request, *args, **kwargs):
        finding = self.get_object()
        finding.status = RiskFinding.Status.RESOLVED
        finding.save(update_fields=['status'])
        return Response({'detail': 'resolved'}, status=status.HTTP_200_OK)

    @action(methods=['post'], detail=True, url_path='ignore')
    def ignore(self, request, *args, **kwargs):
        finding = self.get_object()
        finding.status = RiskFinding.Status.IGNORED
        finding.save(update_fields=['status'])
        return Response({'detail': 'ignored'}, status=status.HTTP_200_OK)
