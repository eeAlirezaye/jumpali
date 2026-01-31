from rest_framework import permissions
from rbac.permissions import RBACPermission
from accounts.models import RiskRule, RiskFinding


def check_permissions(request):
    act = request.data.get('action')
    if act == 'push':
        code = 'accounts.push_account'
    elif act == 'remove':
        code = 'accounts.remove_account'
    else:
        code = 'accounts.verify_account'
    return request.user.has_perm(code)


class AccountTaskActionPermission(permissions.IsAuthenticated):

    def has_permission(self, request, view):
        return super().has_permission(request, view) \
            and check_permissions(request)


class SecretRotationRBACPermission(RBACPermission):
    """
    Custom RBAC helper to add common action mappings for rotation policy/job APIs.
    """
    extra_perms = (
        ('run_now', 'accounts.add_secretrotationjob'),
        ('retry', 'accounts.add_secretrotationjob'),
        ('logs', 'accounts.view_secretrotationjob'),
    )

    def get_rbac_perms(self, view, model_cls):
        perms = super().get_rbac_perms(view, model_cls)
        for action, perm in self.extra_perms:
            if action not in perms:
                perms[action] = {perm}
        return perms


class RiskRuleRBACPermission(RBACPermission):
    perm_model = RiskRule


class RiskFindingRBACPermission(RBACPermission):
    perm_model = RiskFinding
