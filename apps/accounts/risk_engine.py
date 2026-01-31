"""Simple rule engine registry for account risk detection."""
import hashlib
from typing import Callable, Tuple

from django.utils.translation import gettext_lazy as _

from accounts.automations.check_account.manager import CheckSecretHandler
from accounts.models import Account
from settings.models import LeakPasswords

RegistryType = dict[str, Callable[[Account, dict], Tuple[bool, dict]]]


class RiskEngineRegistry:
    def __init__(self):
        self._registry: RegistryType = {}

    def register(self, slug: str):
        def decorator(func):
            self._registry[slug] = func
            return func
        return decorator

    def get(self, slug):
        return self._registry.get(slug)

    def all_slugs(self):
        return list(self._registry.keys())


registry = RiskEngineRegistry()


@registry.register('weak_password')
def weak_password(account: Account, conditions: dict):
    secret = account.secret
    if not secret:
        return False, {}
    is_weak = CheckSecretHandler.is_weak_password(secret)
    return is_weak, {'reason': _('Password too weak')}


@registry.register('leaked_password')
def leaked_password(account: Account, conditions: dict):
    secret = account.secret
    if not secret:
        return False, {}
    exists = LeakPasswords.objects.using('sqlite').filter(password=secret).exists()
    return exists, {'reason': _('Password appears in leak database')}


@registry.register('repeated_password')
def repeated_password(account: Account, conditions: dict):
    """Repeated password detection is precomputed; conditions expects digest_map in runtime context."""
    secret = account.secret
    if not secret:
        return False, {}
    digest = hashlib.md5(secret.encode()).hexdigest()
    digest_map = conditions.get('__digest_map', {})
    count = len(digest_map.get(digest, []))
    return count > 1, {'count': count, 'digest': digest}


@registry.register('password_too_short')
def password_too_short(account: Account, conditions: dict):
    secret = account.secret or ''
    min_len = int(conditions.get('min_length', 8))
    return len(secret) < min_len, {'length': len(secret), 'min_length': min_len}
