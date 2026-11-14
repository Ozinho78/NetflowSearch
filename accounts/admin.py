from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin

from .forms import CustomUserChangeForm, CustomUserCreationForm
from .models import User


@admin.register(User)
class UserAdmin(BaseUserAdmin):
    # Formulare aus forms.py
    form = CustomUserChangeForm          # Seite "Benutzer ändern"
    add_form = CustomUserCreationForm    # Seite "Benutzer hinzufügen"

    # Listenansicht
    ordering = ("email",)                # BaseUserAdmin sortiert nach "username" -> Fehler
    list_display = ("email", "first_name", "last_name", "is_active", "is_staff", "date_joined")
    # 🛠️ 3: Ergänze 'last_login' in list_display (Reihenfolge = Spaltenreihenfolge)
    list_filter = ("is_active", "is_staff", "is_superuser", "groups")
    search_fields = ("email", "first_name", "last_name")

    # Layout der Bearbeiten-Seite: Tupel aus (Überschrift, {"fields": (...)})
    fieldsets = (
        (None, {"fields": ("email", "password")}),
        ("Persönliche Daten", {"fields": ("first_name", "last_name")}),
        ("Berechtigungen", {
            "fields": ("is_active", "is_staff", "is_superuser", "groups", "user_permissions"),
        }),
        ("Wichtige Daten", {"fields": ("last_login", "date_joined")}),
    )

    # Layout der Anlegen-Seite
    add_fieldsets = (
        (None, {
            "classes": ("wide",),
            "fields": ("email", "usable_password", "password1", "password2"),
        }),
    )