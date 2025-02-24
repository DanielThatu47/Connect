"""
Django settings for connect project.

Generated by 'django-admin startproject' using Django 5.1.

For more information on this file, see
https://docs.djangoproject.com/en/5.1/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/5.1/ref/settings/
"""

from pathlib import Path
import os
from mongoengine import connect
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent


# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/5.1/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = 'django-insecure-d5yk&5o5e^kj!cuz*=jh6%3!tj!9^&e#)1@7%+&c(0j9q&e8-t'

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

ALLOWED_HOSTS = [
    'connect-gf04.onrender.com',
    '0.0.0.0',
    '.now.sh',  # Keep the existing ones
]


# Application definition

INSTALLED_APPS = [
    'django_mongoengine',
    'django_mongoengine.mongo_auth',
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
   'django_extensions',
    'Application',
    'django_browser_reload',
    'cloudinary_storage',  # Add Cloudinary storage app
    'cloudinary',
   
]


# Default file storage for media
DEFAULT_FILE_STORAGE = 'cloudinary_storage.storage.MediaCloudinaryStorage'

# Cloudinary credentials
CLOUDINARY_STORAGE = {
    'CLOUD_NAME': os.getenv('CLOUDINARY_CLOUD_NAME'),
    'API_KEY': os.getenv('CLOUDINARY_API_KEY'),
    'API_SECRET': os.getenv('CLOUDINARY_API_SECRET'),
}

# Optional: Media URL
MEDIA_URL = 'https://res.cloudinary.com/drmlojk3o/'


RUNSERVERPLUS_SERVER_RELOAD_HOOKS = ['watchman']

MIDDLEWARE = [
       'django.middleware.security.SecurityMiddleware',
       'django.contrib.sessions.middleware.SessionMiddleware',
       'django.middleware.common.CommonMiddleware',
       'django.middleware.csrf.CsrfViewMiddleware',  # Ensure this is included
       'django.contrib.auth.middleware.AuthenticationMiddleware',  # Place this before your middleware
       'django.contrib.messages.middleware.MessageMiddleware',
       'django.middleware.clickjacking.XFrameOptionsMiddleware',
      
       'Application.middleware.guest_access.GuestAccessRestrictionMiddleware',
      

        
   
]


CSRF_TRUSTED_ORIGINS = [
    'http://localhost:8000',
    'http://127.0.0.1:8000',
    'https://connect-gf04.onrender.com',
    'http://0.0.0.0:8000',
    'http://192.168.44.1:8000',
      'http://192.168.64.238:8000' , # Add this if you are accessing from this IP
]



ROOT_URLCONF = 'connect.urls'


# AUTH_USER_MODEL = 'Application.User'


TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [os.path.join(BASE_DIR, 'templates')],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]




# Database
# https://docs.djangoproject.com/en/5.1/ref/settings/#databases

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': ':memory:',  # In-memory database just to prevent errors
    }
}




MONGODB_DATABASES = {
    'default': {
        'name': os.getenv('MONGODB_NAME'),
        'host': os.getenv('MONGODB_HOST'),
        'username': os.getenv('MONGODB_USERNAME'),
        'password': os.getenv('MONGODB_PASSWORD'),
        'authentication_source': os.getenv('MONGODB_AUTH_SOURCE'),
         'ssl': True,  # Ensure SSL is enabled
        'ssl_cert_reqs': 'CERT_NONE'  # Disable SSL certificate verification (not recommended for production)
    }
}


# MongoDB configuration with MongoEngine
connect(
    db=MONGODB_DATABASES['default']['name'],
    host=MONGODB_DATABASES['default']['host'],
    username=MONGODB_DATABASES['default']['username'],
    password=MONGODB_DATABASES['default']['password'],
    authentication_source=MONGODB_DATABASES['default']['authentication_source']
)


AUTHENTICATION_BACKENDS = (
    'mongoengine.django.auth.MongoEngineBackend',
)

MONGOENGINE_USER_DOCUMENT = 'django_mongoengine.mongo_auth.models.User'
AUTH_USER_MODEL = 'mongo_auth.MongoUser'

SESSION_ENGINE = 'django_mongoengine.sessions'
SESSION_SERIALIZER = 'django_mongoengine.sessions.BSONSerializer'


# Session will last for 2 weeks (in seconds)
SESSION_COOKIE_AGE = 1209600  # 2 weeks
SESSION_EXPIRE_AT_BROWSER_CLOSE = False
SESSION_COOKIE_SECURE = True  # Use HTTPS


# CSRF settings for testing on mobile devices
CSRF_COOKIE_SECURE = False
CSRF_COOKIE_HTTPONLY = True
CSRF_COOKIE_SAMESITE = 'Lax'
CSRF_USE_SESSIONS = False





# LOGGING = {
#     'version': 1,
#     'disable_existing_loggers': False,
#     'handlers': {
#         'console': {
#             'class': 'logging.StreamHandler',
#         },
#     },
#     'root': {
#         'handlers': ['console'],
#         'level': 'DEBUG',
#     },
# }




# settings.py

# LOGGING = {
#     'version': 1,
#     'disable_existing_loggers': False,
#     'handlers': {
#         'file': {
#             'level': 'WARNING',
#             'class': 'logging.FileHandler',
#             'filename': 'django.log',
#         },
#     },
#     'loggers': {
#         'django': {
#             'handlers': ['console'],
#             'level': 'WARNING',
#             'propagate': True,
#         },
#         'django.request': {
#             'handlers': ['console'],
#             'level': 'ERROR',
#             'propagate': False,
#         },
#         # Add other loggers if needed
#     },
# }

# Password validation
# https://docs.djangoproject.com/en/5.1/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]


# Internationalization
# https://docs.djangoproject.com/en/5.1/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'UTC'

USE_I18N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/5.1/howto/static-files/

STATIC_URL = 'static/'

# Default primary key field type
# https://docs.djangoproject.com/en/5.1/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'


# settings.py

# Set session expiration based on a defined time or when the user logs out
SESSION_COOKIE_AGE = 60 * 60 * 24 * 30  # 30 days (in seconds)

# Don't expire sessions when the browser is closed
SESSION_EXPIRE_AT_BROWSER_CLOSE = False

# Use a secure session cookie if using HTTPS
SESSION_COOKIE_SECURE = True # Only for HTTPS

# Session cookie name (optional, custom name for your app)
SESSION_COOKIE_NAME = 'your_app_session'

# Ensure cookies are HttpOnly (recommended for security)
SESSION_COOKIE_HTTPONLY = True

# Set the storage engine for sessions
SESSION_ENGINE = 'django.contrib.sessions.backends.signed_cookies'  # or use cache or db-based sessions

# Optionally, enable longer session storage with database caching or external storage (like Redis)

# MEDIA_URL = '/media/'
# MEDIA_ROOT = os.path.join(BASE_DIR, 'media')

# Email settings
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = 'sdanielthatu10@gmail.com'  # Or your email provider's SMTP server
EMAIL_PORT = 3000
EMAIL_USE_TLS = True
EMAIL_HOST_USER = 'danielthatu10@gmail.com'  # Your email
EMAIL_HOST_PASSWORD = 'Daniel@#47'  # Your email app password





#Razor Pay Settings
import razorpay
from django.conf import settings

RAZORPAY_KEY_ID = 'rzp_test_T4nxUdjKukDKO8'
RAZORPAY_KEY_SECRET = 'QVmINC0f2LmjZiFRtB9UfSt9'

razorpay_client = razorpay.Client(
    auth=(settings.RAZORPAY_KEY_ID, settings.RAZORPAY_KEY_SECRET)
)

