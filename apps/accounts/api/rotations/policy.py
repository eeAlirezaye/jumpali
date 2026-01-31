from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from rest_framework import status
from rest_framework.decorators import action
from rest_framework.response import Response

from accounts import serializers
from accounts.models import SecretRotationPolicy, SecretRotationJob
from accounts.permissions import SecretRotationRBACPermission
from accounts.tasks import run_rotation_job
from common.const.choices import Status as ExecStatus, Trigger
from common.permissions import IsValidLicense
from orgs.mixins.api import OrgBulkModelViewSet

__all__ = ['SecretRotationPolicyViewSet']


class SecretRotationPolicyViewSet(OrgBulkModelViewSet):
    model = SecretRotationPolicy
    serializer_class = serializers.SecretRotationPolicySerializer
    permission_classes = [SecretRotationRBACPermission, IsValidLicense]
    filterset_fields = ('name', 'enabled', 'secret_type', 'secret_strategy')
    search_fields = ('name',)
    rbac_perms = {
        'run_now': 'accounts.add_secretrotationjob',
    }

    @action(methods=['post'], detail=True, url_path='run-now')
    def run_now(self, request, *args, **kwargs):
        policy = self.get_object()
        if not policy.enabled:
            return Response({'detail': _('Policy is disabled')}, status=status.HTTP_400_BAD_REQUEST)
        job = SecretRotationJob.objects.create(
            policy=policy,
            requested_by=request.user if request.user.is_authenticated else None,
            trigger=Trigger.manual,
            status=ExecStatus.pending,
        )
        policy.mark_scheduled(timezone.now(), commit=True)

        task = run_rotation_job.delay(str(job.id))
        data = serializers.SecretRotationJobSerializer(job).data
        data.update({'task': task.id})
        return Response(data, status=status.HTTP_202_ACCEPTED)
