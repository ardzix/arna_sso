from rest_framework import viewsets
from rest_framework.permissions import IsAuthenticated
from django.contrib.auth.models import AnonymousUser
from .models import Organization
from .serializers import OrganizationSerializer

class OrganizationViewSet(viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated]
    queryset = Organization.objects.all()
    serializer_class = OrganizationSerializer

    def get_queryset(self):
        # Handle Swagger schema generation where user is AnonymousUser
        if getattr(self, 'swagger_fake_view', False) or isinstance(self.request.user, AnonymousUser):
            return Organization.objects.none()
        
        user = self.request.user
        return Organization.objects.filter(owner=user)

    def perform_create(self, serializer):
        serializer.save(owner=self.request.user)
