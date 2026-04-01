from rest_framework.routers import DefaultRouter
from rest_framework_nested import routers
from .views import OrganizationViewSet, OrganizationMemberViewSet

# Main router for organizations
router = DefaultRouter()
router.register(r'', OrganizationViewSet, basename='organizations')

# Nested router for members under organizations
organizations_router = routers.NestedDefaultRouter(router, r'', lookup='organization')
organizations_router.register(r'members', OrganizationMemberViewSet, basename='organization-members')

urlpatterns = router.urls + organizations_router.urls
