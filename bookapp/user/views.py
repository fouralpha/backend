from django.shortcuts import render
from rest_framework import generics,status,permissions,views
from .serializers import (
    RegisterSerializer,
    EmailVerificationSerializer,
    LoginSerializer,
    RequestPasswordResetEmailSeriliazer,
    ResetPasswordEmailRequestSerializer,
    SetNewPasswordSerializer,
    ProfileSerializer,
    SendEmailVerificationSerializer,
    PasswordChangeSerializer
)
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from .models import User,Profile,Interest
from .utils import Util
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse
from django.conf import settings  
import jwt , json
from rest_framework.generics import RetrieveAPIView
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from rest_framework.generics import UpdateAPIView,ListAPIView,ListCreateAPIView
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import smart_str, force_str, smart_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse
from .utils import Util
from django.shortcuts import redirect
from django.http import HttpResponsePermanentRedirect
from django.contrib.auth import authenticate
from .permissions import *
import os
from dotenv import load_dotenv, find_dotenv
load_dotenv(find_dotenv())

class RegisterView(generics.GenericAPIView):
    serializer_class = RegisterSerializer

    def post(self,request):
        user = request.data
        serializer = self.serializer_class(data = user)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        user_data = serializer.data
        user = User.objects.get(email=user_data['email'])

        token = RefreshToken.for_user(user).access_token

        current_site = get_current_site(request).domain

        relative_link = reverse('email-verify')


        absurl = 'https://' + current_site + relative_link + "?token=" + str(token)
        email_body = 'Hi ' + user.email + '. Use link below to verify your email \n' + absurl
        data = {'email_body' : email_body,'email_subject' : 'Verify your email','to_email' : user.email}
        Util.send_email(data)
        return Response({'status' : "OK",'result': user_data},status = status.HTTP_201_CREATED)

algorithm = "HS256"
class VerifyEmail(views.APIView):
    serializer_class = EmailVerificationSerializer
    
    token_param_config = openapi.Parameter(
        'token', in_=openapi.IN_QUERY, description='Description', type=openapi.TYPE_STRING)
    @swagger_auto_schema(manual_parameters=[token_param_config])
    def get(self,request):
        token = request.GET.get('token')
        try:
            payload = jwt.decode(token,settings.SECRET_KEY,algorithms = [algorithm])
            user = User.objects.get(id=payload['user_id'])
            if not user.is_verified:
                user.is_verified = True
                user.save()
            return redirect(os.getenv('EMAIL_REDIRECT') + '?email=SuccessfullyActivated')
        except jwt.ExpiredSignatureError as identifier:
            return redirect(os.getenv('EMAIL_REDIRECT') + '?email=ActivationLinkExpired')
        except jwt.exceptions.DecodeError as identifier:
            return redirect(os.getenv('EMAIL_REDIRECT') + '?email=InvalidToken')


class LoginApiView(generics.GenericAPIView):
    serializer_class = LoginSerializer

    def post(self,request):
        serializer = self.serializer_class(data=request.data,context = {'current_site' : get_current_site(request).domain})
        serializer.is_valid(raise_exception = True)
        return Response(serializer.data,status = status.HTTP_200_OK)

class CheckAuthView(views.APIView):
    permission_classes = [Authenticated]

    def get(self,request,*args, **kwargs):
        return Response({'status' : 'OK',"result" : "Token is Valid"},status=status.HTTP_200_OK)



class SendVerificationMail(generics.GenericAPIView):
    serializer_class = SendEmailVerificationSerializer

    def post(self,request,*args, **kwargs):
        email = request.data.get('email',None)
        if email is None:
            return Response({'status' : 'FAILED','error' : 'Email not provided'},status=status.HTTP_400_BAD_REQUEST)
        if not User.objects.filter(email = email).exists():
            return Response({'status' : 'FAILED','error' :'The given email does not exist'},status = status.HTTP_400_BAD_REQUEST)
        user = User.objects.get(email=email)
        token = RefreshToken.for_user(user).access_token
        current_site = get_current_site(request).domain
        relative_link = reverse('email-verify')
        absurl = 'https://' + current_site + relative_link + "?token=" + str(token)
        email_body = 'Hi ' + user.email + '. Use link below to verify your email \n' + absurl
        data = {'email_body' : email_body,'email_subject' : 'Verify your email','to_email' : user.email}
        Util.send_email(data)
        return Response({'status' : 'OK','result' :'A Verification Email has been sent'},status = status.HTTP_200_OK)


class ProfileGetView(ListAPIView):
    serializer_class = ProfileSerializer
    permission_classes = [Authenticated,IsOwner]
    queryset = Profile.objects.all()

    def get_serializer_context(self,**kwargs):
            data = super().get_serializer_context(**kwargs)
            data['user'] = self.request.user.email
            return data
    def get_queryset(self):
        return self.queryset.filter(owner=self.request.user)



class ProfileUpdateView(UpdateAPIView):
    serializer_class = ProfileSerializer
    permission_classes = [Authenticated,IsOwner]
    queryset = Profile.objects.all()
    lookup_field = "owner_id__id"

    def get_serializer_context(self,**kwargs):
        data = super().get_serializer_context(**kwargs)
        if self.request.user:
            data['user'] = self.request.user.email
        else:
            data['user'] = None
        return data

    def get_queryset(self):
        return self.queryset.filter(owner=self.request.user)

class ChangePassword(generics.GenericAPIView):
    permission_classes = [Authenticated]
    serializer_class = PasswordChangeSerializer

    def post(self,request,*args,**kwargs):
        data = request.data
        old_pass = data.get('old_pass',None)
        new_pass = data.get('new_pass',None)
        if old_pass is None or new_pass is None:
            return Response({'status' : 'FAILED','error' :'Either the old or new password was not provided'},status=status.HTTP_400_BAD_REQUEST)
        user = authenticate(username=self.request.user.username,password=old_pass)
        if new_pass == old_pass:
            return Response({'status' : 'FAILED','error' :"The new password is same as the old password"},status=status.HTTP_400_BAD_REQUEST)
        if len(new_pass) < 6:
            return Response({'status' : 'FAILED','error' :"The password is too short, should be of minimum length 6"},status=status.HTTP_400_BAD_REQUEST)
        if user is None:
            return Response({'status' : 'FAILED','error' :"Wrong Password"},status=status.HTTP_400_BAD_REQUEST)
        user.set_password(new_pass)
        user.save()
        return Response({'status' : 'OK','result' :"Password Change Complete"},status=status.HTTP_200_OK)

class RequestPasswordResetEmail(generics.GenericAPIView):
    serializer_class = ResetPasswordEmailRequestSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)

        email = request.data.get('email', '')

        if User.objects.filter(email=email).exists():
            user = User.objects.get(email=email)
            uidb64 = urlsafe_base64_encode(smart_bytes(user.id))
            token = PasswordResetTokenGenerator().make_token(user)
            current_site = get_current_site(
                request=request).domain
            relativeLink = reverse(
                'password-reset-confirm', kwargs={'uidb64': uidb64, 'token': token})

            redirect_url = request.data.get('redirect_url', '')
            absurl = 'https://'+current_site + relativeLink
            email_body = 'Hello, \n Use link below to reset your password  \n' + \
                absurl+"?redirect_url="+redirect_url
            data = {'email_body': email_body, 'to_email': user.email,
                    'email_subject': 'Reset your passsword'}
            Util.send_email(data)
        return Response({'status': 'OK','result' :'We have sent you a link to reset your password'}, status=status.HTTP_200_OK)


class PasswordTokenCheckAPI(generics.GenericAPIView):
    serializer_class = SetNewPasswordSerializer

    def get(self, request, uidb64, token):
        redirect_url = request.GET.get('redirect_url')
        try:
            id = smart_str(urlsafe_base64_decode(uidb64))
            if not User.objects.filter(id=id).exists():
                return Response({"status" : 'FAILED','error' :"UIDB Token is invalid"},status=status.HTTP_400_BAD_REQUEST)
            user = User.objects.get(id=id)

            if not PasswordResetTokenGenerator().check_token(user, token):
                if redirect_url and len(redirect_url) > 3:
                    return redirect(redirect_url+'?token_valid=False')
                else:
                    return redirect(os.getenv('FRONTEND_URL', '')+'?token_valid=False')
                return Response({'status' : 'FAILED','error' : 'Token is invalid. Please request a new one'})
            if redirect_url and len(redirect_url) > 3:
                return redirect(redirect_url+'?token_valid=True&message=Credentials Valid&uidb64='+uidb64+'&token='+token)
            else:
                return redirect(os.getenv('FRONTEND_URL', '')+'?token_valid=False')

        except DjangoUnicodeDecodeError as identifier:
            try:
                if not PasswordResetTokenGenerator().check_token(user):
                    return redirect(redirect_url+'?token_valid=False')
                    
            except UnboundLocalError as e:
                return Response({'status' : 'FAILED','error': 'Token is not valid, please request a new one'}, status=status.HTTP_400_BAD_REQUEST)
            if not PasswordResetTokenGenerator().check_token(user, token):
                return Response({'status' : 'FAILED','error' : 'Token is invalid. Please request a new one'},status=status.HTTP_400_BAD_REQUEST)


class SetNewPasswordAPIView(generics.GenericAPIView):
    serializer_class = SetNewPasswordSerializer

    def patch(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response({'status': 'OK', 'result': 'Password reset success'}, status=status.HTTP_200_OK)


class InterestView(views.APIView):
    permission_classes = [Authenticated]
    def post(self,request):
        data = request.data
        if data.get('interests',None):
            for ele in data.get('interests',None):
                if Interest.objects.filter(user = self.request.user,interest=ele).exists():
                    continue
                Interest.objects.create(user = self.request.user,interest=interest)
        return Response({'status' : 'ok'},status = status.HTTP_200_OK)
