"""Bounded local readiness probe, no credentials or external messages."""
import json
import os
import sys
from urllib.request import Request, urlopen

try:
    # The production host is already allowed in the unchanged configuration.
    request = Request("http://127.0.0.1:8001/health/ready", headers={"Host": "sso.arnatech.id"})
    with urlopen(request, timeout=4) as response:
        if response.status != 200 or json.load(response) != {"status": "ready"}:
            raise RuntimeError("Not ready")
except Exception:
    sys.exit(1)
