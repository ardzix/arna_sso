"""Time-limited, proxy-attested Home exception for three POST endpoints only."""
import hmac
import json
import re
import time
from rest_framework.throttling import AnonRateThrottle, UserRateThrottle, ScopedRateThrottle

CONFIG_PATH = "/run/secrets/sso_home_exception"
HOME_IP = "103.157.59.181"
ALLOWED_PATHS = frozenset((
    "/api/auth/login/",
    "/api/auth/token/refresh/",
    "/api/auth/sso/token/",
))
MAX_LIFETIME_SECONDS = 86400

def _read_config():
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as handle:
            raw = handle.read(8193)
        if len(raw) > 8192:
            return None
        value = json.loads(raw)
        return value if isinstance(value, dict) else None
    except (OSError, ValueError, UnicodeError):
        return None

def _home_exception_valid(request):
    # Missing, malformed, not-yet-valid and expired credentials all fail closed.
    if request.method != "POST" or request.path not in ALLOWED_PATHS:
        return False
    meta = request.META
    if meta.get("HTTP_X_FORWARDED_PROTO") != "https":
        return False
    if meta.get("HTTP_X_ARNA_HOME_SOURCE") != HOME_IP:
        return False
    config = _read_config()
    if not config or config.get("ip") != HOME_IP:
        return False
    issued = config.get("issued_at")
    expires = config.get("expires_at")
    if type(issued) is not int or type(expires) is not int:
        return False
    if not 0 < expires - issued <= MAX_LIFETIME_SECONDS:
        return False
    if not issued <= time.time() < expires:
        return False
    expected = config.get("attestation")
    received = meta.get("HTTP_X_ARNA_HOME_EXCEPTION_SECRET", "")
    if not isinstance(expected, str) or not re.fullmatch(r"[0-9a-f]{64}", expected):
        return False
    if not isinstance(received, str) or len(received) != 64:
        return False
    return hmac.compare_digest(received.encode("utf-8"), expected.encode("ascii"))

class HomeExceptionAnonRateThrottle(AnonRateThrottle):
    def allow_request(self, request, view):
        if _home_exception_valid(request):
            return True
        return super().allow_request(request, view)

class HomeExceptionUserRateThrottle(UserRateThrottle):
    def get_ident(self, request):
        # Keep the remaining 1,000/day limit on one stable Home IP key.
        # Client-supplied XFF cannot split its bucket during the exception.
        if _home_exception_valid(request):
            return HOME_IP
        return super().get_ident(request)

HOME_EXCEPTION_THROTTLES = (
    HomeExceptionAnonRateThrottle,
    HomeExceptionUserRateThrottle,
    ScopedRateThrottle,
)
