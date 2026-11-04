"""Temporary proxy-attested exemption from the device authorize daily quota."""
import hashlib
import hmac
import json
from datetime import datetime, timedelta
from functools import lru_cache
from ipaddress import IPv4Address
from pathlib import Path

from django.utils import timezone
from rest_framework.throttling import AnonRateThrottle


EXEMPTION_PATH = Path("/run/sso-device-authorize-exemption.json")
AUTHORIZE_PATH = "/api/v1/devices/authorize/"


@lru_cache(maxsize=1)
def load_exemption():
    """An absent or invalid immutable Swarm config never grants an exception."""
    try:
        data = json.loads(EXEMPTION_PATH.read_text(encoding="utf-8"))
        ip = str(IPv4Address(data["ip"]))
        digest = data["sha256"]
        starts = datetime.fromisoformat(data["starts_at"])
        expires = datetime.fromisoformat(data["expires_at"])
        if (not isinstance(digest, str) or len(bytes.fromhex(digest)) != 32
                or starts.utcoffset() != timedelta(0) or expires.utcoffset() != timedelta(0)
                or not timedelta(0) < expires - starts <= timedelta(days=7)):
            return None
        return ip, digest, starts, expires
    except (OSError, ValueError, TypeError, KeyError, OverflowError):
        return None


class DeviceAuthorizeAnonThrottle(AnonRateThrottle):
    def get_cache_key(self, request, view):
        if request.method == "POST" and request.path == AUTHORIZE_PATH:
            marker = request.META.get("HTTP_X_ARNA_DEVICE_EXEMPTION", "")
            config = load_exemption() if len(marker) == 64 else None
            if config:
                ip, digest, starts, expires = config
                if (request.META.get("HTTP_X_REAL_IP") == ip
                        and starts <= timezone.now() < expires
                        and hmac.compare_digest(hashlib.sha256(marker.encode()).hexdigest(), digest)):
                    return None
        return super().get_cache_key(request, view)
