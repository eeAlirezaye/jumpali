from common.utils import get_logger
from accounts.tasks.risk_scan import scan_accounts_for_policy

logger = get_logger(__file__)

__all__ = ['scan_accounts_for_policy']
