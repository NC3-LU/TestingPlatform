"""
Django settings for testing_platform project.

Generated by 'django-admin startproject' using Django 3.2.6.

For more information on this file, see
https://docs.djangoproject.com/en/3.2/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/3.2/ref/settings/
"""
import os
import sys
from datetime import timedelta
from pathlib import Path

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent

# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/3.2/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!

SECRET_KEY = os.environ.get("SECRET_KEY", "secret")

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = os.environ.get("DEBUG", "1") == "1"

allowed_hosts = os.environ.get("ALLOWED_HOSTS", "localhost")
ALLOWED_HOSTS = list(map(str.strip, allowed_hosts.split(",")))

if DEBUG:
    CSRF_TRUSTED_ORIGINS = ["https://*.srv.office.lhc.lu"]
else:
    CSRF_TRUSTED_ORIGINS = ["https://testing.nc3.lu"]

EMAIL_BACKEND = os.environ.get(
    "EMAIL_BACKEND", "django.core.mail.backends.smtp.EmailBackend"
)
EMAIL_HOST = os.environ.get("EMAIL_HOST", "localhost")
EMAIL_USE_TLS = os.environ.get("EMAIL_USE_TLS", "0") == "1"
EMAIL_PORT = int(os.environ.get("EMAIL_PORT", "25"))
EMAIL_HOST_USER = os.environ.get("EMAIL_HOST_USER", "")
EMAIL_HOST_PASSWORD = os.environ.get("EMAIL_HOST_PASSWORD", "")
DEFAULT_FROM_EMAIL = os.environ.get("DEFAULT_FROM_EMAIL", "webmaster@localhost")

# Maximum size of the file that can be sent to the API (/api/v1/InfraTesting/File/)
MAX_UPLOAD_FILE_SIZE = 5000000

# Application definition

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "django_extensions",
    "django_icons",
    "django_q",
    "widget_tweaks",
    "django_bootstrap5",
    "api",
    "landing_page",
    "legal_section",
    "authentication",
    "testing",
    "iot_inspector",
    "onekey",
    "automation",
    "contact",
    "c3_protocols",
    "specialized_testing",
    "knowledge_base",
    "testing.templatetags",
    "rest_framework",
    "drf_spectacular",
    "drf_spectacular_sidecar",  # required for Django collectstatic discovery
    "corsheaders",
    "rest_framework_simplejwt.token_blacklist",
]

REST_FRAMEWORK = {
    # Use Django's standard `django.contrib.auth` permissions,
    # or allow read-only access for unauthenticated users.
    "DEFAULT_AUTHENTICATION_CLASSES": [
        "rest_framework.authentication.BasicAuthentication",
        "rest_framework.authentication.SessionAuthentication",
        "rest_framework_simplejwt.authentication.JWTAuthentication",
    ],
    "DEFAULT_PAGINATION_CLASS": "rest_framework.pagination.PageNumberPagination",
    "PAGE_SIZE": 10,
    "DEFAULT_SCHEMA_CLASS": "drf_spectacular.openapi.AutoSchema",
}

SIMPLE_JWT = {
    "ACCESS_TOKEN_LIFETIME": timedelta(minutes=120),
    "SLIDING_TOKEN_REFRESH_LIFETIME": timedelta(days=1),
    "ALGORITHM": "HS256",
    "SIGNING_KEY": SECRET_KEY,
    "VERIFYING_KEY": None,
    "AUTH_HEADER_TYPES": ("Bearer",),
}

SPECTACULAR_SETTINGS = {
    "TITLE": "NC3-LU Testing Platform",
    "DESCRIPTION": 'Back to the <a href="/">home page</a>.'
    "<br /><br />API for the "
    '<a href="https://github.com/NC3-LU/TestingPlatform" rel="noopener noreferrer" target="_blank">'
    "Testing Platform</a> by NC3-LU.",
    "VERSION": "1.0.0",
    "SERVE_INCLUDE_SCHEMA": True,
}

GRAPH_MODELS = {
    "all_applications": True,
    "group_models": True,
}

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    "corsheaders.middleware.CorsMiddleware",
]
CORS_ALLOWED_ORIGINS = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
]


CSRF_COOKIE_SAMESITE = "None"
SESSION_COOKIE_SAMESITE = "None"
CSRF_COOKIE_SECURE = True
SESSION_COOKIE_SECURE = True
CORS_ALLOW_CREDENTIALS = True
Q_CLUSTER = {"name": "scheduler", "orm": "default", "timeout": 300, "retry": 330}

ROOT_URLCONF = "testing_platform.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [os.path.join(BASE_DIR / "templates")],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
                "testing_platform.context_processors.get_version",
            ],
        },
    },
]

WSGI_APPLICATION = "testing_platform.wsgi.application"

# Database
# https://docs.djangoproject.com/en/3.2/ref/settings/#databases

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": os.path.join(BASE_DIR, "db", "db.sqlite3"),
    }
}

# Password validation
# https://docs.djangoproject.com/en/3.2/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        "NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.CommonPasswordValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.NumericPasswordValidator",
    },
]

# Internationalization
# https://docs.djangoproject.com/en/3.2/topics/i18n/

LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True

# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/3.2/howto/static-files/

STATIC_URL = "static/"
STATIC_ROOT = BASE_DIR / "static"
STATICFILES_DIRS = [
    BASE_DIR / "static_global",
]

# Default primary key field type
# https://docs.djangoproject.com/en/3.2/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

MEDIA_ROOT = os.environ.get("MEDIA_ROOT", os.path.join(BASE_DIR, "files"))

AUTH_USER_MODEL = "authentication.User"

LOGIN_REDIRECT_URL = "/"
LOGOUT_REDIRECT_URL = "/"

PANDORA_ROOT_URL = os.environ.get("PANDORA_ROOT_URL", "https://pandora.circl.lu/")

IOT_API_URL = os.environ.get("IOT_API_URL", "")
IOT_CLIENT_ID = os.environ.get("IOT_CLIENT_ID", "")
IOT_API_EMAIL = os.environ.get("IOT_API_EMAIL", "")
IOT_API_PASSWORD = os.environ.get("IOT_API_PASSWORD", "")

ONEKEY_API_URL = "https://app.eu.onekey.com/api"
ONEKEY_API_EMAIL = os.environ.get("ONEKEY_API_EMAIL", "")
ONEKEY_API_PASSWORD = os.environ.get("ONEKEY_API_PASSWORD", "")

DMARC_API_KEY = os.environ.get("DMARC_API_KEY", "")

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "simple": {
            "format": "{levelname} {asctime} {module} {process:d} {thread:d} {message}",
            "style": "{",
        },
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "level": "DEBUG",
            "stream": sys.stdout,
            "formatter": "simple",
        },
    },
    "root": {
        "handlers": ["console"],
        "level": "INFO",
    },
    "loggers": {
        "testing": {
            "handlers": ["console"],
            "level": os.getenv("DJANGO_LOG_LEVEL", "INFO"),
            "propagate": False,
        },
    },
}

STATIC_DIR = BASE_DIR / "static"
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))

BOOTSTRAP5 = {
    "css_url": {
        "url": "/static/npm_components/bootstrap/dist/css/bootstrap.min.css",
        "crossorigin": "anonymous",
    },
    # The complete URL to the Bootstrap JavaScript file
    "javascript_url": {
        "url": "/static/npm_components/bootstrap/dist/js/bootstrap.bundle.min.js",
        "crossorigin": "anonymous",
    },
}

if not DEBUG and SECRET_KEY == "secret":
    print("FATAL: the secret key in the config has not yet been configured. Quitting.")
    exit(-1)
