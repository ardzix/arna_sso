from rest_framework.routers import DefaultRouter
from .views import OrganizationViewSet, OrganizationMemberViewSet

router = DefaultRouter()
router.register(r'organizations', OrganizationViewSet)
router.register(r'members', OrganizationMemberViewSet, basename='members')

urlpatterns = router.urls
