from django.db import models
from django.dispatch import receiver
from django.contrib.auth.models import AbstractBaseUser,BaseUserManager,PermissionsMixin
from django.db.models.signals import post_save
from rest_framework_simplejwt.tokens import RefreshToken

class UserManager(BaseUserManager):
    def create_user(self,email,password=None):
        if email is None:
            raise TypeError('User should have an email')

        user = self.model(email = self.normalize_email(email))
        user.set_password(password)
        user.save() 
        return user

    def create_superuser(self,email,password=None):
        if password is None:
            raise TypeError('Password should not be none')
        user = self.create_user(email,password)
        user.is_superuser = True
        user.is_staff = True
        user.is_verified = True
        user.save()
        return user




class User(AbstractBaseUser,PermissionsMixin):
    email = models.EmailField(max_length=255,unique=True,db_index=True)
    is_verified = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now = True)
    auth_provider = models.CharField(
        max_length=255, blank=False,
        null=False, default='email')
    USERNAME_FIELD = 'email'

    objects = UserManager()

    def __str__(self):
        return self.email

    def tokens(self):
        refresh = RefreshToken.for_user(self)
        return {
            'refresh':str(refresh),
            'access': str(refresh.access_token),
        }

    
