"""HTTP is permitted only for explicitly registered development loopback callbacks."""
from urllib.parse import urlsplit


def is_http_loopback_redirect(value):
    try:
        parsed = urlsplit(value)
        port = parsed.port
        return (
            parsed.scheme == "http"
            and parsed.hostname in {"localhost", "127.0.0.1"}
            and parsed.username is None and parsed.password is None
            and not parsed.fragment
            and (port is None or 1 <= port <= 65535)
            and not any(character.isspace() or ord(character) < 32 for character in value)
            and "\\" not in value
        )
    except (ValueError, TypeError, AttributeError):
        return False
