from rest_framework import status, mixins, viewsets
from rest_framework.decorators import action
from rest_framework.response import Response

from accounts import serializers
from accounts.models import SecretRotationJob
from accounts.permissions import SecretRotationRBACPermission
from accounts.tasks import run_rotation_job
from common.const.choices import Status as ExecStatus, Trigger
from common.permissions import IsValidLicense

__all__ = ['SecretRotationJobViewSet']


class SecretRotationJobViewSet(mixins.ListModelMixin,
                               mixins.RetrieveModelMixin,
                               viewsets.GenericViewSet):
    model = SecretRotationJob
    serializer_class = serializers.SecretRotationJobSerializer
    permission_classes = [SecretRotationRBACPermission, IsValidLicense]
    filterset_fields = ('status', 'trigger', 'policy')
    search_fields = ('policy__name',)
    rbac_perms = {
        'retry': 'accounts.add_secretrotationjob',
        'logs': 'accounts.view_secretrotationjob',
    }

    def get_queryset(self):
        return SecretRotationJob.objects.select_related('policy', 'execution', 'requested_by')

    @action(methods=['get'], detail=True, url_path='logs')
    def logs(self, request, *args, **kwargs):
        job = self.get_object()
        execution = job.execution
        data = {
            'job': serializers.SecretRotationJobSerializer(job).data,
            'execution': None,
        }
        if execution:
            data['execution'] = {
                'id': str(execution.id),
                'status': execution.status,
                'summary': execution.summary,
                'result': execution.result,
                'date_start': execution.date_start,
                'date_finished': execution.date_finished,
            }
        return Response(data)

    @action(methods=['post'], detail=True, url_path='retry')
    def retry(self, request, *args, **kwargs):
        job = self.get_object()
        if job.status == ExecStatus.running:
            return Response({'detail': 'Job is still running'}, status=status.HTTP_400_BAD_REQUEST)

        job.status = ExecStatus.pending
        job.trigger = Trigger.manual
        job.error = ''
        job.summary = {}
        job.execution = None
        job.started_at = None
        job.ended_at = None
        job.requested_by = request.user if request.user.is_authenticated else None
        job.save(update_fields=[
            'status', 'trigger', 'error', 'summary', 'execution',
            'started_at', 'ended_at', 'requested_by'
        ])

        task = run_rotation_job.delay(str(job.id))
        data = serializers.SecretRotationJobSerializer(job).data
        data.update({'task': task.id})
        return Response(data, status=status.HTTP_202_ACCEPTED)
