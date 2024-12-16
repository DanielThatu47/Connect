from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from django.conf import settings
from django.shortcuts import redirect
from django.urls import reverse
from .models import User

def get_google_auth_flow():
    flow = Flow.from_client_config(
        {
            "web": {
                "client_id": settings.GOOGLE_CLIENT_ID,
                "client_secret": settings.GOOGLE_CLIENT_SECRET,
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
            }
        },
        scopes=['https://www.googleapis.com/auth/userinfo.email', 'https://www.googleapis.com/auth/userinfo.profile', 'openid']
    )
    flow.redirect_uri = settings.GOOGLE_REDIRECT_URI
    return flow

def get_google_user_info(credentials):
    service = build('oauth2', 'v2', credentials=credentials)
    user_info = service.userinfo().get().execute()
    return user_info

def create_or_get_user(user_info):
    email = user_info['email']
    name = user_info['name']
    profile_image = user_info.get('picture')
    user = User.objects(email=email).first()
    if not user:
        user = User(email=email, name=name, profile_image=profile_image)
        user.save()
    else:
        user.profile_image = profile_image
        user.save()
    return user
