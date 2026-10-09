"""Load a complete operator-owned JSON environment secret before Django starts."""
import json
import os
from pathlib import Path


def load_runtime_secret():
    path = os.environ.get("SSO_RUNTIME_SECRET_PATH")
    if not path:
        return  # Preserve existing environment-based consumers and isolated tests.
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict) or not data:
        raise RuntimeError("Invalid SSO runtime configuration secret")
    for name, value in data.items():
        if not isinstance(name, str) or not name.isidentifier() or not isinstance(value, str):
            raise RuntimeError("Invalid SSO runtime configuration entry")
        os.environ[name] = value
