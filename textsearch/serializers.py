
from rest_framework import serializers
from django.contrib.auth.models import User
from rest_framework.validators import UniqueValidator
from django.contrib.auth.password_validation import validate_password

from .models import *

class SendZohoRegistrationLinkSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)
    userid = serializers.CharField(required=True)

    class Meta:
        fields = '__all__'
