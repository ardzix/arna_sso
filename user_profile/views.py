from rest_framework import viewsets, mixins
from rest_framework.permissions import IsAuthenticated
from django.contrib.auth.models import AnonymousUser
from .models import UserProfile
from .serializers import UserProfileSerializer


class UserProfileViewSet(viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated]
    serializer_class = UserProfileSerializer

    def get_queryset(self):
        # Handle Swagger schema generation where user is AnonymousUser
        if getattr(self, 'swagger_fake_view', False) or isinstance(self.request.user, AnonymousUser):
            return UserProfile.objects.none()
        
        return UserProfile.objects.filter(user=self.request.user)

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)
