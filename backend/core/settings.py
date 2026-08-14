"""
Django settings for Sentinel Windows EDR Agent.
"""

import os
from datetime import timedelta
from pathlib import Path

from dotenv import load_dotenv
import dj_database_url


# ============================================================
# BASE DIRECTORIES
# ============================================================

BASE_DIR = Path(__file__).resolve().parent.parent
PROJECT_ROOT = BASE_DIR.parent


# ============================================================
# ENVIRONMENT
# ============================================================

ENV_FILE = PROJECT_ROOT / ".env"

if ENV_FILE.exists():
    load_dotenv(ENV_FILE)


# ============================================================
# HELPERS
# ============================================================

def env_bool(name, default=False):
    value = os.getenv(name, str(default)).strip().lower()
    return value in {"1", "true", "yes", "on"}


def env_list(name, default=""):
    return [
        item.strip()
        for item in os.getenv(name, default).split(",")
        if item.strip()
    ]


# ============================================================
# SECURITY
# ============================================================

SECRET_KEY = os.getenv("DJANGO_SECRET_KEY", "M5TZCnJ5TuNgmQ7kkxKvNSHtMMAMP70HCdoG47m4C4hGxkV81HOtMsAb2Ma75-xFeW9iqssFMZg9inrXwxBBzg").strip()

if not SECRET_KEY:
    raise RuntimeError(
        f"DJANGO_SECRET_KEY is missing. Add it to {ENV_FILE}"
    )

DEBUG = env_bool("DJANGO_DEBUG", True)

ALLOWED_HOSTS = env_list(
    "DJANGO_ALLOWED_HOSTS",
    "127.0.0.1,localhost",
)


# ============================================================
# APPLICATIONS
# ============================================================

INSTALLED_APPS = [
    # Real-time / ASGI
    "daphne",
    "channels",

    # Django
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",

    # Third-party
    "rest_framework",
    "rest_framework_simplejwt",
    "rest_framework_simplejwt.token_blacklist",
    "corsheaders",

    # Project
    "monitoring.apps.MonitoringConfig",
]



# ============================================================
# MIDDLEWARE
# ============================================================

MIDDLEWARE = [
    "corsheaders.middleware.CorsMiddleware",

    "django.middleware.security.SecurityMiddleware",
    "whitenoise.middleware.WhiteNoiseMiddleware",

    "django.contrib.sessions.middleware.SessionMiddleware",

    "django.middleware.common.CommonMiddleware",

    "django.middleware.csrf.CsrfViewMiddleware",

    "django.contrib.auth.middleware.AuthenticationMiddleware",

    "django.contrib.messages.middleware.MessageMiddleware",

    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]


# ============================================================
# URL / ASGI / WSGI
# ============================================================

ROOT_URLCONF = "core.urls"

WSGI_APPLICATION = "core.wsgi.application"

ASGI_APPLICATION = "core.asgi.application"


# ============================================================
# TEMPLATES
# ============================================================

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",

        "DIRS": [
            BASE_DIR / "templates",
            PROJECT_ROOT / "templates",
        ],

        "APP_DIRS": True,

        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]


# ============================================================
# DATABASE
# ============================================================

DATABASE_URL = os.getenv("DATABASE_URL")

if DATABASE_URL:
    DATABASES = {
        "default": dj_database_url.config(
            default=DATABASE_URL,
            conn_max_age=600,
            conn_health_checks=True,
        )
    }
else:
    DB_ENGINE = os.getenv(
        "DB_ENGINE",
        "django.db.backends.sqlite3",
    ).strip()

    if DB_ENGINE == "django.db.backends.postgresql":
        DATABASES = {
            "default": {
                "ENGINE": DB_ENGINE,
                "NAME": os.getenv("DB_NAME", "sentinel_db"),
                "USER": os.getenv("DB_USER", "postgres"),
                "PASSWORD": os.getenv("DB_PASSWORD", ""),
                "HOST": os.getenv("DB_HOST", "localhost"),
                "PORT": os.getenv("DB_PORT", "5432"),
            }
        }
    else:
        DATABASES = {
            "default": {
                "ENGINE": "django.db.backends.sqlite3",
                "NAME": BASE_DIR / "db.sqlite3",
            }
        }


# ============================================================
# PASSWORD VALIDATION
# ============================================================

AUTH_PASSWORD_VALIDATORS = [
    {
        "NAME": (
            "django.contrib.auth.password_validation."
            "UserAttributeSimilarityValidator"
        ),
    },

    {
        "NAME": (
            "django.contrib.auth.password_validation."
            "MinimumLengthValidator"
        ),
    },

    {
        "NAME": (
            "django.contrib.auth.password_validation."
            "CommonPasswordValidator"
        ),
    },

    {
        "NAME": (
            "django.contrib.auth.password_validation."
            "NumericPasswordValidator"
        ),
    },
]


# ============================================================
# INTERNATIONALIZATION
# ============================================================

LANGUAGE_CODE = "en-us"

TIME_ZONE = os.getenv(
    "TIME_ZONE",
    "Asia/Kolkata",
)

USE_I18N = True

USE_TZ = True


# ============================================================
# STATIC FILES
# ============================================================

STATIC_URL = "/static/"

STATIC_ROOT = BASE_DIR / "staticfiles"

STATIC_DIRS = [
    BASE_DIR / "static",
    PROJECT_ROOT / "static",
]

STATICFILES_DIRS = [
    directory
    for directory in STATIC_DIRS
    if directory.exists()
]


# ============================================================
# MEDIA FILES
# ============================================================

MEDIA_URL = "/media/"

MEDIA_ROOT = BASE_DIR / "media"


# ============================================================
# DEFAULT PRIMARY KEY
# ============================================================

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"


# ============================================================
# AUTHENTICATION
# ============================================================

AUTH_USER_MODEL = "auth.User"

LOGIN_URL = "/login/"

LOGIN_REDIRECT_URL = "/"

LOGOUT_REDIRECT_URL = "/login/"


# ============================================================
# DJANGO REST FRAMEWORK
# ============================================================

REST_FRAMEWORK = {

    "DEFAULT_AUTHENTICATION_CLASSES": (
        "rest_framework_simplejwt.authentication.JWTAuthentication",
    ),

    "DEFAULT_PERMISSION_CLASSES": (
        "rest_framework.permissions.IsAuthenticated",
    ),

    "DEFAULT_PAGINATION_CLASS": (
        "rest_framework.pagination.PageNumberPagination"
    ),

    "PAGE_SIZE": 25,
}


# ============================================================
# JWT / SIMPLE JWT
# ============================================================

JWT_SECRET_KEY = os.getenv(
    "JWT_SECRET_KEY",
    "UmUoxNPY30GE68vRVxcZOfxS_weBDYKuuHmwCG8NAKxRA6NStlm8WYfODofDHWYutJTg4UI-gbb75LuzODkuMQ",
).strip()


if not JWT_SECRET_KEY:

    raise RuntimeError(
        f"JWT_SECRET_KEY is missing. Add it to {ENV_FILE}"
    )


SIMPLE_JWT = {

    "ACCESS_TOKEN_LIFETIME": timedelta(
        minutes=int(
            os.getenv(
                "JWT_ACCESS_MINUTES",
                "30",
            )
        )
    ),

    "REFRESH_TOKEN_LIFETIME": timedelta(
        days=int(
            os.getenv(
                "JWT_REFRESH_DAYS",
                "7",
            )
        )
    ),

    "ROTATE_REFRESH_TOKENS": True,

    "BLACKLIST_AFTER_ROTATION": True,

    "UPDATE_LAST_LOGIN": True,

    "ALGORITHM": "HS256",

    "SIGNING_KEY": JWT_SECRET_KEY,

    "AUTH_HEADER_TYPES": ("Bearer",),

    "USER_ID_FIELD": "id",

    "USER_ID_CLAIM": "user_id",
}


# ============================================================
# CORS
# ============================================================

CORS_ALLOW_ALL_ORIGINS = env_bool(
    "CORS_ALLOW_ALL_ORIGINS",
    False,
)

CORS_ALLOWED_ORIGINS = env_list(
    "CORS_ALLOWED_ORIGINS",
    "http://127.0.0.1:5000,http://localhost:5000",
)


# ============================================================
# CSRF
# ============================================================

CSRF_TRUSTED_ORIGINS = env_list(
    "CSRF_TRUSTED_ORIGINS",
    "http://127.0.0.1:5000,http://localhost:5000",
)


# ============================================================
# EMAIL / GMAIL SMTP
# ============================================================

EMAIL_BACKEND = (
    "django.core.mail.backends.smtp.EmailBackend"
)

EMAIL_HOST = os.getenv(
    "SMTP_HOST",
    "smtp.gmail.com",
)

EMAIL_PORT = int(
    os.getenv(
        "SMTP_PORT",
        "587",
    )
)

EMAIL_USE_TLS = env_bool(
    "SMTP_USE_TLS",
    True,
)

EMAIL_USE_SSL = env_bool(
    "SMTP_USE_SSL",
    False,
)

EMAIL_HOST_USER = os.getenv(
    "SMTP_USERNAME",
    "",
).strip()

EMAIL_HOST_PASSWORD = os.getenv(
    "SMTP_PASSWORD",
    "",
)

DEFAULT_FROM_EMAIL = os.getenv(
    "EMAIL_FROM",
    EMAIL_HOST_USER,
).strip()

SERVER_EMAIL = DEFAULT_FROM_EMAIL


# ============================================================
# EMAIL VERIFICATION / SECURITY ALERT
# ============================================================

EMAIL_VERIFICATION_TIMEOUT = int(
    os.getenv(
        "EMAIL_VERIFICATION_TIMEOUT",
        "600",
    )
)

SECURITY_ALERT_EMAIL = os.getenv(
    "SECURITY_ALERT_EMAIL",
    EMAIL_HOST_USER,
).strip()


# ============================================================
# OPENAI
# ============================================================

OPENAI_API_KEY = os.getenv(
    "OPENAI_API_KEY",
    "",
).strip()

OPENAI_MODEL = os.getenv(
    "OPENAI_MODEL",
    "gpt-4o-mini",
)


# ============================================================
# REAL-TIME CHANNELS / REDIS
# ============================================================

REDIS_URL = os.getenv(
    "REDIS_URL",
    "",
).strip()

REDIS_HOST = os.getenv(
    "REDIS_HOST",
    "localhost",
).strip()

REDIS_PORT = int(
    os.getenv(
        "REDIS_PORT",
        "6379",
    )
)


if REDIS_URL:

    REDIS_HOSTS = [
        REDIS_URL
    ]

else:

    REDIS_HOSTS = [
        (
            REDIS_HOST,
            REDIS_PORT,
        )
    ]


CHANNEL_LAYERS = {

    "default": {

        "BACKEND":
            "channels_redis.core.RedisChannelLayer",

        "CONFIG": {

            "hosts": REDIS_HOSTS,

        },
    },
}


# ============================================================
# SECURITY HARDENING
# ============================================================

if not DEBUG:

    SECURE_SSL_REDIRECT = env_bool(
        "SECURE_SSL_REDIRECT",
        True,
    )

    SESSION_COOKIE_SECURE = True

    CSRF_COOKIE_SECURE = True

    SECURE_HSTS_SECONDS = int(
        os.getenv(
            "SECURE_HSTS_SECONDS",
            "31536000",
        )
    )

    SECURE_HSTS_INCLUDE_SUBDOMAINS = True

    SECURE_HSTS_PRELOAD = True

    SECURE_CONTENT_TYPE_NOSNIFF = True

    X_FRAME_OPTIONS = "DENY"

    SESSION_COOKIE_HTTPONLY = True

    SESSION_COOKIE_SAMESITE = "Lax"

    CSRF_COOKIE_HTTPONLY = False

    CSRF_COOKIE_SAMESITE = "Lax"

    SECURE_REFERRER_POLICY = "same-origin"


else:

    SECURE_SSL_REDIRECT = False

    SESSION_COOKIE_SECURE = False

    CSRF_COOKIE_SECURE = False

    SECURE_HSTS_SECONDS = 0

    SECURE_CONTENT_TYPE_NOSNIFF = True

    X_FRAME_OPTIONS = "DENY"

    SESSION_COOKIE_HTTPONLY = True

    SESSION_COOKIE_SAMESITE = "Lax"

    CSRF_COOKIE_HTTPONLY = False

    CSRF_COOKIE_SAMESITE = "Lax"


# ============================================================
# PROXY
# ============================================================

USE_X_FORWARDED_HOST = env_bool(
    "USE_X_FORWARDED_HOST",
    False,
)


if env_bool(
    "USE_X_FORWARDED_PROTO",
    False,
):

    SECURE_PROXY_SSL_HEADER = (
        "HTTP_X_FORWARDED_PROTO",
        "https",
    )


# ============================================================
# LOGGING
# ============================================================

LOG_DIR = BASE_DIR / "logs"

LOG_DIR.mkdir(
    parents=True,
    exist_ok=True,
)


LOGGING = {

    "version": 1,

    "disable_existing_loggers": False,

    "formatters": {

        "verbose": {

            "format": (
                "{levelname} {asctime} "
                "{module} {process:d} "
                "{thread:d} {message}"
            ),

            "style": "{",
        },

        "simple": {

            "format": "{levelname} {message}",

            "style": "{",
        },
    },


    "handlers": {

        "console": {

            "class":
                "logging.StreamHandler",

            "formatter":
                "simple",
        },

        "file": {

            "class":
                "logging.FileHandler",

            "filename":
                str(
                    LOG_DIR /
                    "sentinel.log"
                ),

            "formatter":
                "verbose",
        },
    },


    "root": {

        "handlers": [
            "console",
            "file",
        ],

        "level": os.getenv(
            "LOG_LEVEL",
            "INFO",
        ),
    },


    "loggers": {

        "django": {

            "handlers": [
                "console",
                "file",
            ],

            "level": os.getenv(
                "DJANGO_LOG_LEVEL",
                "INFO",
            ),

            "propagate": False,
        },


        "monitoring": {

            "handlers": [
                "console",
                "file",
            ],

            "level": "INFO",

            "propagate": False,
        },
    },
}