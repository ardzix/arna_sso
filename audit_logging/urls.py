from rest_framework.routers import DefaultRouter
from .views import AuditLogViewSet

router = DefaultRouter()
router.register(r'audit-logs', AuditLogViewSet)

urlpatterns = router.urls
