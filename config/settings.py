"""
Django settings for nfsearch (netflow02).
"""

import ipaddress
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
        # eigene Apps
    "accounts",
    "search",
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

STATIC_URL = "static/"
STATICFILES_DIRS = [BASE_DIR / "static"]   # NEU: projektweite statische Dateien


# --- E-Mail -----------------------------------------------------------------

# NEU: Mails erscheinen in der Entwicklung im runserver-Terminal
# EMAIL_BACKEND = "django.core.mail.backends.console.EmailBackend"
# DEFAULT_FROM_EMAIL = "nfsearch <noreply@localhost>"
# --- E-Mail -----------------------------------------------------------------
# Backend per .env umschaltbar: console (Entwicklung) oder smtp (echter Versand)
EMAIL_BACKEND = os.environ.get(
    "EMAIL_BACKEND", "django.core.mail.backends.console.EmailBackend"
)

EMAIL_HOST = os.environ.get("EMAIL_HOST", "localhost")
EMAIL_PORT = int(os.environ.get("EMAIL_PORT", "465"))
# 465 = implizites TLS (SMTPS), 587 = STARTTLS -> nie beides gleichzeitig
EMAIL_USE_SSL = os.environ.get("EMAIL_USE_SSL", "True").lower() == "true"
EMAIL_USE_TLS = os.environ.get("EMAIL_USE_TLS", "False").lower() == "true"
EMAIL_HOST_USER = os.environ.get("EMAIL_HOST_USER", "")
EMAIL_HOST_PASSWORD = os.environ.get("EMAIL_HOST_PASSWORD", "")
# Ohne Timeout hängt ein Request bei Netzproblemen sehr lange (Default: None)
EMAIL_TIMEOUT = int(os.environ.get("EMAIL_TIMEOUT", "10"))

DEFAULT_FROM_EMAIL = os.environ.get("DEFAULT_FROM_EMAIL", "nfsearch <noreply@localhost>")
# Absender für Fehlermails an ADMINS (später relevant)
SERVER_EMAIL = DEFAULT_FROM_EMAIL


# --- Login / Logout ---------------------------------------------------------
# URL-Namen statt fester Pfade -> funktionieren auch, wenn sich Pfade ändern
LOGIN_URL = "accounts:login"          # wohin @login_required umleitet
# LOGIN_REDIRECT_URL = "home"           # nach erfolgreichem Login (ohne ?next=)
LOGIN_REDIRECT_URL = "search:index"   # war: "home"
LOGOUT_REDIRECT_URL = "accounts:login"


# Erlaubte Domains für die Selbstregistrierung, leer = keine Einschränkung
REGISTRATION_ALLOWED_DOMAINS = [
    d.strip().lower()
    for d in os.environ.get("REGISTRATION_ALLOWED_DOMAINS", "").split(",")
    if d.strip()
]


# --- Kontoaktivierung -------------------------------------------------------
# Basis-URL für Links in Mails. Bewusst aus der Config und NICHT aus dem
# Host-Header des Requests -> verhindert Host-Header-Injection in Mail-Links.
SITE_URL = os.environ.get("SITE_URL", "http://127.0.0.1:8000").rstrip("/")


# Gültigkeit von Aktivierungs- UND Passwort-Reset-Links (Sekunden)
PASSWORD_RESET_TIMEOUT = 60 * 60 * 24   # 24 Stunden (Default wären 3 Tage)


# --- Suche ------------------------------------------------------------------
# Öffentliche CGN-Pools des Providers. Nur IPs daraus sind gültige Suchanfragen.
# ip_network() wirft beim Start einen Fehler, wenn z. B. Host-Bits gesetzt sind
# (203.0.113.5/24) -> Konfigurationsfehler fallen sofort auf.
NAT_POOLS = [
    ipaddress.ip_network(n.strip())
    for n in os.environ.get("NAT_POOLS", "203.0.113.0/24").split(",")
    if n.strip()
]

# Wie weit darf der gesuchte Zeitpunkt zurückliegen? Muss zur tatsächlichen
# Aufbewahrung der nfcapd-Dateien passen (nfexpire / Löschkonzept).
SEARCH_MAX_AGE_DAYS = int(os.environ.get("SEARCH_MAX_AGE_DAYS", "7"))
