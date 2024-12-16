"""
URL configuration for connect project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.urls import path ,include
from django.contrib.auth import views as auth_views
from Application import views
from django.contrib import admin
from django.conf import settings
from django.conf.urls.static import static
from Application.views import delete_avatar, handle_avatar_upload, password_reset_request, password_reset_confirm


urlpatterns = [
    path('', views.home, name='home'),
    path('main/', views.main, name='main'),
    path('about/', views.about, name='about'),
    path('main/about/', views.about, name='about'),
    path('main/contactus/', views.contactus, name='contactus'),
    path('register/', views.register, name='register'),
    path('login/', views.login, name='login'),
    path('main/', views.main, name='main'),
    path('logout/', views.logout, name='logout'),
    path('admin/login/', views.admin_login, name='admin_login'),
    path('admin/dashboard/', views.admin_dashboard, name='admin_dashboard'),
    path('admin/logout/', views.admin_logout, name='admin_logout'),
    path('admin/add_ngo/', views.add_ngo, name='add_ngo'),
    path('admin/delete_ngo/<str:ngo_id>/', views.delete_ngo, name='delete_ngo'),
    # path('google/login/', views.google_login, name='google_login'),
    # path('google/callback/', views.google_callback, name='google_callback'),
    path('search/', views.search_ngos, name='search_ngos'),
    path('profile/', views.profile, name='profile'),
    path('update-password/', views.update_password, name='update_password'),
    path('delete_avatar/', delete_avatar, name='delete_avatar'),  # URL pattern for deleting avatar
    path('change_avatar/', handle_avatar_upload, name='change_avatar'),  # URL pattern for changing avatar
    path('update-email/', views.update_email, name='update_email'),
    path('password-reset/', password_reset_request, name='password_reset'),
    path('password-reset-confirm/<uidb64>/<token>/', password_reset_confirm, name='password_reset_confirm'),
    path('password-reset-success/', views.password_reset_success, name='password_reset_success'),
    path('ngo-detail/<str:ngo_id>/', views.ngo_detail, name='ngo_detail'),
    path('admin/edit-ngo/<str:ngo_id>/', views.edit_ngo, name='edit_ngo'),
    path('donate/<str:ngo_id>/', views.donate, name='donate'),
    path('payment-success/', views.payment_success, name='payment_success'),
    path('generate-receipt/', views.generate_receipt, name='generate_receipt'),
    path("__reload__/", include("django_browser_reload.urls")),
] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)

