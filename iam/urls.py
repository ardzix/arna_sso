from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import RoleViewSet, PermissionViewSet, UserRoleViewSet, UserPermissionViewSet
from .product_catalog import ProductCatalogProvisionView

router = DefaultRouter()
# Automatically generates URLs:
# GET /roles/ -> RoleViewSet.list()
# POST /roles/ -> RoleViewSet.create()
# GET /roles/{id}/ -> RoleViewSet.retrieve()
router.register(r'roles', RoleViewSet, basename='roles')
router.register(r'permissions', PermissionViewSet, basename='permissions')
router.register(r'user-roles', UserRoleViewSet, basename='user-roles')
router.register(r'user-permissions', UserPermissionViewSet, basename='user-permissions')

urlpatterns = [
    path('product-catalogs/<slug:product_key>/provision/', ProductCatalogProvisionView.as_view(), name='product-catalog-provision'),
    path('', include(router.urls)),
]
