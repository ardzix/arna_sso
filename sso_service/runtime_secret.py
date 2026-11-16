"""Load operator runtime configuration and optional dedicated SMTP credential."""
import json
import os
from pathlib import Path

def load_runtime_secret():
    path = os.environ.get("SSO_RUNTIME_SECRET_PATH")
    if path:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        if not isinstance(data, dict) or not data:
            raise RuntimeError("Invalid SSO runtime configuration secret")
        for name, value in data.items():
            if not isinstance(name, str) or not name.isidentifier() or not isinstance(value, str):
                raise RuntimeError("Invalid SSO runtime configuration entry")
            os.environ[name] = value
    smtp_path = os.environ.get("SSO_SMTP_SECRET_PATH")
    if smtp_path:
        smtp = json.loads(Path(smtp_path).read_text(encoding="utf-8"))
        allowed = {"EMAIL_HOST_USER", "EMAIL_HOST_PASSWORD", "DEFAULT_FROM_EMAIL"}
        if set(smtp) != allowed or any(not isinstance(v, str) or not v for v in smtp.values()):
            raise RuntimeError("Invalid dedicated SMTP configuration")
        os.environ.update(smtp)
