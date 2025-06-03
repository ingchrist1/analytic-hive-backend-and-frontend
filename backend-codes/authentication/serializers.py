from rest_framework import serializers
from django.contrib.auth import get_user_model
from allauth.socialaccount.models import SocialAccount
import re

User = get_user_model()

class UserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, min_length=8)
    email = serializers.EmailField(required=True)

    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'password', 'first_name', 'last_name', 'profile_picture']
        extra_kwargs = {
            'password': {'write_only': True},
            'username': {'min_length': 3},
            'profile_picture': {'read_only': True}
        }

    def validate_password(self, value):
        """Validate password strength"""
        if not re.search(r'[A-Z]', value):
            raise serializers.ValidationError('Password must contain at least one uppercase letter.')
        if not re.search(r'[a-z]', value):
            raise serializers.ValidationError('Password must contain at least one lowercase letter.')
        if not re.search(r'\d', value):
            raise serializers.ValidationError('Password must contain at least one number.')
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', value):
            raise serializers.ValidationError('Password must contain at least one special character.')
        return value

    def validate_username(self, value):
        """Validate username format"""
        if not re.match(r'^[a-zA-Z0-9_]+$', value):
            raise serializers.ValidationError(
                'Username can only contain letters, numbers, and underscores.'
            )
        return value

    def create(self, validated_data):
        user = User.objects.create_user(**validated_data)
        return user

class GoogleAuthSerializer(serializers.Serializer):
    access_token = serializers.CharField(required=True)
    id_token = serializers.CharField(required=True)

class SocialAccountSerializer(serializers.ModelSerializer):
    """Serializer for social accounts"""
    class Meta:
        model = SocialAccount
        fields = ('provider', 'uid', 'extra_data')
        read_only_fields = ('provider', 'uid', 'extra_data')
