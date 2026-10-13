"""Versioned contract; legacy /api/auth/device routes remain compatible aliases."""
from django.urls import path
from .device_views import (DeviceAuthorizeView, DeviceVerificationView, DeviceTokenView, DeviceRefreshView,
                           DeviceRevokeView, DeviceReviewView, DeviceInventoryView, DeviceDetailView)
from .device_status import DeviceStatusView, DeviceIntrospectionView
from .device_resources import DeviceContextView, DeviceAccessView, ResourceTokenView

app_name = "devices"
urlpatterns = [
    path('context/', DeviceContextView.as_view(), name='context'),
    path('resource-token/', ResourceTokenView.as_view(), name='resource-token'),
    path('registrations/<uuid:device_id>/access/', DeviceAccessView.as_view(), name='access'),
    path("authorize/", DeviceAuthorizeView.as_view(), name="authorize"),
    path("review/", DeviceReviewView.as_view(), name="review"),
    path("verification/", DeviceVerificationView.as_view(), name="verification"),
    path("token/", DeviceTokenView.as_view(), name="token"),
    path("refresh/", DeviceRefreshView.as_view(), name="refresh"),
    path("revoke/", DeviceRevokeView.as_view(), name="revoke"),
    path("registrations/", DeviceInventoryView.as_view(), name="registrations"),
    path("registrations/<uuid:device_id>/", DeviceDetailView.as_view(), name="detail"),
    path("status/", DeviceStatusView.as_view(), name="status"),
    path("introspect/", DeviceIntrospectionView.as_view(), name="introspect"),
]
