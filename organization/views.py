from rest_framework import viewsets
from rest_framework.permissions import IsAuthenticated
from .models import Organization
from .serializers import OrganizationSerializer

class OrganizationViewSet(viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated]
    queryset = Organization.objects.all()
    serializer_class = OrganizationSerializer

    def get_queryset(self):
        user = self.request.user
        return Organization.objects.filter(owner=user)

    def perform_create(self, serializer):
        serializer.save(owner=self.request.user)
