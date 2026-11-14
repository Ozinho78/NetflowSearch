"""
Django settings for nfsearch (netflow02).
"""

import os
from pathlib import Path

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent

load_dotenv(BASE_DIR / ".env")


# --- Sicherheit -------------------------------------------------------------

# NEU: KeyError beim Start, wenn der Key fehlt -> bewusst kein Fallback
SECRET_KEY = os.environ["DJANGO_SECRET_KEY"]

# NEU: Werte aus .env sind Strings, "False" wäre truthy -> expliziter Vergleich
DEBUG = os.environ.get("DJANGO_DEBUG", "False").lower() == "true"

# NEU: kommaseparierte Liste aus .env
ALLOWED_HOSTS = [
    h.strip()
    for h in os.environ.get("DJANGO_ALLOWED_HOSTS", "").split(",")
    if h.strip()
]


# --- Apps -------------------------------------------------------------------

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    # NEU: eigene Apps
    "accounts",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "config.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "templates"],  # NEU: globaler Template-Ordner
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "config.wsgi.application"


# --- Datenbank --------------------------------------------------------------
# SQLite reicht für Entwicklung und das Lab; Benutzer + Audit-Log sind klein.

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": BASE_DIR / "db.sqlite3",
    }
}


# --- Authentifizierung ------------------------------------------------------

# NEU: eigenes User-Model – MUSS vor dem ersten migrate gesetzt sein
AUTH_USER_MODEL = "accounts.User"

AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {
        "NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
        "OPTIONS": {"min_length": 12},  # NEU: Default wäre 8
    },
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]


# --- Sprache und Zeit -------------------------------------------------------

LANGUAGE_CODE = "de-de"          # NEU
TIME_ZONE = "Europe/Berlin"      # NEU: nfdump zeigt lokale Zeit
USE_I18N = True
USE_TZ = True                    # DB speichert UTC, Anzeige in Europe/Berlin


# --- Statische Dateien ------------------------------------------------------

STATIC_URL = "static/"

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"


# --- E-Mail -----------------------------------------------------------------

# NEU: Mails erscheinen in der Entwicklung im runserver-Terminal
EMAIL_BACKEND = "django.core.mail.backends.console.EmailBackend"
DEFAULT_FROM_EMAIL = "nfsearch <noreply@localhost>"



