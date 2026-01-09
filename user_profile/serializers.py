from rest_framework import serializers
from .models import UserProfile


class UserProfileSerializer(serializers.ModelSerializer):
    user_name = serializers.ReadOnlyField(source='user.email')

    class Meta:
        model = UserProfile
        fields = [
            'id',
            'user',
            'user_name',
            'bio',
            'profile_picture',
            'phone_number',
            'preferences',
        ]
        read_only_fields = ['id', 'user']


