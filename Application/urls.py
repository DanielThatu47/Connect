# myapp/urls.py

from django.urls import path
from . import views
from django.conf.urls.static import static
from django.conf import settings
from .views import delete_avatar, handle_avatar_upload

urlpatterns = [
    # ... other URL patterns ...
    path('change-avatar/', views.handle_avatar_upload, name='change_avatar'),
    path('', views.home, name='home'),
    path('register/', views.register, name='register'),
    path('login/', views.login, name='login'),
    path('about/', views.about, name='about'),
    path('main/about/', views.about, name='about'),
    path('main/contactus/', views.contactus, name='contactus'),
    path('main/', views.main, name='main'),
    path('logout/', views.logout_view, name='logout'),
    path('admin/login/', views.admin_login, name='admin_login'),
    path('admin/dashboard/', views.admin_dashboard, name='admin_dashboard'),
    path('admin/logout/', views.admin_logout, name='admin_logout'),
    path('admin/add_ngo/', views.add_ngo, name='add_ngo'),
    # path('google/login/', views.google_login, name='google_login'),
    # path('google/callback/', views.google_callback, name='google_callback'),
    path('search/', views.search_ngos, name='search_ngos'),
    path('profile/', views.profile, name='profile'),
    
    path('delete_avatar/', delete_avatar, name='delete_avatar'),  # URL pattern for deleting avatar
    path('change_avatar/', handle_avatar_upload, name='change_avatar'),  # URL pattern for changing avatar
    path('update-email/', views.update_email, name='update_email'),
    path('update-password/', views.update_password, name='update_password'),
]+ static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
