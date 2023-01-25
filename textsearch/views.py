from django.shortcuts import render

# Create your views here.
from django.shortcuts import render

# Create your views here.
from django.shortcuts import render
from ast import Try
import imp
# from .distance_matrix import  coordinates_preprocesing
import json
from operator import truediv
from select import select
from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework import status
from rest_framework.response import Response
# Create your views here.
from rest_framework.permissions import BasePermission, IsAuthenticated, SAFE_METHODS
from rest_framework.exceptions import APIException
from datetime import datetime
from django.core.mail import EmailMultiAlternatives
from .serializers import *
import re
from rest_framework import generics
from rest_framework_simplejwt.tokens import RefreshToken
from .models import *
from django.contrib.auth import authenticate
from rest_framework.permissions import IsAuthenticated
from django.core import serializers
import requests
import hashlib
import ast
from django.utils import timezone
# Create your views here.

def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)

    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }
# Define Create User (Register User) API with only post request


class SignupUser(APIView):
    # Handling Post Reuqest
    def post(self, request):
        try:
            # serializer = SignupUserSerializer(data=request.data)
            # if serializer.is_valid():
            #     branch_id = serializer.validated_data.get('branch_id')
            #     user = User.objects.create(
            #         username=serializer.validated_data['username'],
            #         email=serializer.validated_data['email'],
            #         first_name=serializer.validated_data.get('first_name', ''),
            #         last_name=serializer.validated_data.get('last_name', ''),
            #         mobile=serializer.validated_data.get('mobile', ''),
            #         branch_id=branch_id,
            #         is_zoho_active=1
            #     )
            #     user.set_password(serializer.validated_data['password'])
            #     user.save()
            #     refresh = RefreshToken.for_user(user)
            #     if user:
            #         json_data = {
            #             'status_code': 201,
            #             'status': 'Success',
            #             'username': str(user),
            #             'refresh': str(refresh),
            #             'access': str(refresh.access_token),
            #             'message': 'User created'
            #         }
            #         return Response(json_data, status.HTTP_201_CREATED)
            #     else:
                    # json_data = {
                    #     'status_code': 200,
                    #     'status': 'Success',
                    #     'data': 'User not created',
                    #     'message': 'data not created'
                    # }
                    # return Response(json_data, status.HTTP_200_OK)
            
            print("I am api called-------")
            json_data = {
                'status_code': 200,
                'status': 'Failed',
                'error': '',
                'remark': 'Serializer error'
            }
            return Response(json_data, status.HTTP_200_OK)
        except Exception as err:
            print("Error :", err)
            json_data = {
                'status_code': 500,
                'status': 'Failed',
                'error': err,
                'remark': 'Landed in exception',
            }
            return Response(json_data, status.HTTP_500_INTERNAL_SERVER_ERROR)
