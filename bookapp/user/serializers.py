from rest_framework import serializers
from rest_framework.serializers import SerializerMethodField
from .models import User,Profile
from django.contrib import auth
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import smart_bytes,smart_str,force_str,DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode,urlsafe_base64_decode
from django.urls import reverse
from rest_framework_simplejwt.tokens import RefreshToken
from .utils import Util
import requests,json
from .exception import *


class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(max_length=68,min_length=6,write_only=True)

    class Meta:
        model = User
        fields = ['email','password']
    
    def create(self,validated_data):
        return User.objects.create_user(**validated_data)


class EmailVerificationSerializer(serializers.ModelSerializer):
    token = serializers.CharField(max_length = 555)
    class Meta:
        model = User
        fields = ['token']

class SendEmailVerificationSerializer(serializers.Serializer):
    email = serializers.EmailField(max_length=255,required=True)

    class Meta:
        fields = ['email']

class LoginSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(max_length=255)
    password = serializers.CharField(max_length = 68,min_length = 6,write_only=True)
    tokens = serializers.SerializerMethodField()
    first_time_login = serializers.SerializerMethodField()

    def get_tokens(self, obj):
        user = User.objects.get(email=obj['email'])
        return {
            'refresh': user.tokens()['refresh'],
            'access': user.tokens()['access']
        }
    def get_first_time_login(self,obj):
        qs = Profile.objects.get(owner__email = obj['email'])
        if qs.name is None:
            return True
        return False



    class Meta:
        model = User
        fields = ['id','email','password','tokens','first_time_login']

    def validate(self,attrs):
        email =  attrs.get('email','')
        password =  attrs.get('password','')
        user_obj_email = User.objects.filter(email=email).first()
        if user_obj_email:
            user = auth.authenticate(email = user_obj_email.email,password=password)
            if user_obj_email.auth_provider != 'email':
                raise AuthenticationException(
                    detail='Please continue your login using ' + filtered_user_by_email[0].auth_provider)
            if not user:
                raise AuthenticationException('Invalid credentials. Try again')
            if not user.is_active:
                raise AuthenticationException('Account disabled. contact admin')
            if not user.is_verified:
                email = user.email
                token = RefreshToken.for_user(user).access_token
                current_site = self.context.get('current_site')
                relative_link = reverse('email-verify')
                absurl = 'https://' + current_site + relative_link + "?token=" + str(token)
                email_body = 'Hi ' + user.email + '. Use link below to verify your email \n' + absurl
                data = {'email_body' : email_body,'email_subject' : 'Verify your email','to_email' : user.email}
                Util.send_email(data)
                raise AuthenticationException('Email is not verified, A Verification Email has been sent to your email address')
            return {
                'email' : user.email,
                'tokens': user.tokens
            }
            return super().validate(attrs)
        raise AuthenticationException('Invalid credentials. Try again')
        


class ProfileSerializer(serializers.ModelSerializer):
    owner_id = SerializerMethodField()

    def get_owner_id(self,obj):
        user = self.context.get('user')
        return User.objects.get(email=user).id
    class Meta:
        model = Profile
        fields = ['owner_id','name','phone','institution_type','institution','about',]




class RequestPasswordResetEmailSeriliazer(serializers.Serializer):
    email = serializers.EmailField(min_length=2)

    class Meta:
        fields = ['email']


    
class ResetPasswordEmailRequestSerializer(serializers.Serializer):
    email = serializers.EmailField(min_length=2)

    redirect_url = serializers.CharField(max_length=500, required=False)

    class Meta:
        fields = ['email']

class SetNewPasswordSerializer(serializers.Serializer):
    password = serializers.CharField(
        min_length=6, max_length=68, write_only=True)
    token = serializers.CharField(
        min_length=1, write_only=True)
    uidb64 = serializers.CharField(
        min_length=1, write_only=True)

    class Meta:
        fields = ['password', 'token', 'uidb64']

    def validate(self, attrs):
        try:
            password = attrs.get('password')
            token = attrs.get('token')
            uidb64 = attrs.get('uidb64')

            id = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(id=id)
            if not PasswordResetTokenGenerator().check_token(user, token):
                raise AuthenticationException('The reset link is invalid', 401)

            user.set_password(password)
            user.save()

            return (user)
        except Exception as e:
            raise AuthenticationException('The reset link is invalid', 401)
        return super().validate(attrs)

class PasswordChangeSerializer(serializers.Serializer):
    old_pass = serializers.CharField(max_length = 68,min_length = 6,required=True)
    new_pass = serializers.CharField(max_length = 68,min_length = 6,required=True)

    class Meta:
        fields = ['old_pass','new_pass']