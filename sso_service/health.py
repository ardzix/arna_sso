from django.db import connection
from django.http import JsonResponse
from django.views.decorators.http import require_GET


@require_GET
def live(request):
    return JsonResponse({"status": "ok"})


@require_GET
def ready(request):
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1")
            if cursor.fetchone() != (1,):
                raise RuntimeError("Not ready")
    except Exception:
        return JsonResponse({"status": "not_ready"}, status=503)
    return JsonResponse({"status": "ready"})
