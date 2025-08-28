from rest_framework import serializers
from django.contrib.auth import get_user_model, password_validation
from django.core.validators import validate_email

User = get_user_model()

class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)
    role = serializers.ChoiceField(choices=User.ROLE_CHOICES, default="user")
    mfa_enabled = serializers.BooleanField(read_only=True)
    
    
    class Meta:
        model = User
        fields = ("username", "email", "password", "first_name", "last_name", "role" ,"mfa_enabled")

    def validate_email(self, value):
        validate_email(value)
        if User.objects.filter(email__iexact=value).exists():
            raise serializers.ValidationError("A user with that email already exists.")
        return value

    def validate_password(self, value):
        password_validation.validate_password(value, self.instance)
        return value

    def create(self, validated_data):
        password = validated_data.pop("password")
        user = User(**validated_data)
        user.set_password(password)
       
        user.save()
        return user


class ProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ("id", "username", "email", "first_name", "last_name", "role", "mfa_enabled")


class MFAEnableSerializer(serializers.Serializer):
   
    pass


class MFAVerifySerializer(serializers.Serializer):
    code = serializers.CharField(max_length=6)
