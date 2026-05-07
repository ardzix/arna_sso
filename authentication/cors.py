from urllib.parse import urlparse

from django.core.cache import cache
from django.db import DatabaseError
from django.db.models.signals import post_delete, post_save
from django.dispatch import receiver

from corsheaders.signals import check_request_enabled

from authentication.models import CorsAllowedOrigin


CORS_DB_CACHE_KEY = "cors:allowed_origins:active:v1"
CORS_DB_CACHE_TTL_SECONDS = 300


def _normalize_origin(value: str) -> str:
    return (value or "").strip().rstrip("/")


def _is_valid_origin(value: str) -> bool:
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"}:
        return False
    if not parsed.netloc:
        return False
    if parsed.path not in {"", "/"}:
        return False
    if parsed.params or parsed.query or parsed.fragment:
        return False
    return True


def _load_active_origins_from_db() -> set[str]:
    try:
        origins = set(
            CorsAllowedOrigin.objects.filter(is_active=True).values_list("origin", flat=True)
        )
        normalized = {_normalize_origin(origin) for origin in origins if _normalize_origin(origin)}
        return {origin for origin in normalized if _is_valid_origin(origin)}
    except DatabaseError:
        # Backward compatible fallback during migration/startup issues:
        # env-based CORS rules will still be applied by django-cors-headers.
        return set()


def get_active_db_origins() -> set[str]:
    cached = cache.get(CORS_DB_CACHE_KEY)
    if cached is not None:
        return cached
    origins = _load_active_origins_from_db()
    cache.set(CORS_DB_CACHE_KEY, origins, CORS_DB_CACHE_TTL_SECONDS)
    return origins


@receiver(post_save, sender=CorsAllowedOrigin)
@receiver(post_delete, sender=CorsAllowedOrigin)
def invalidate_cors_origin_cache(**kwargs):
    cache.delete(CORS_DB_CACHE_KEY)


def cors_allow_db_origins(sender, request, **kwargs):
    origin = _normalize_origin(request.headers.get("Origin", ""))
    if not origin:
        return False
    return origin in get_active_db_origins()


check_request_enabled.connect(
    cors_allow_db_origins,
    dispatch_uid="authentication.cors.cors_allow_db_origins",
)
