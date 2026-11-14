from django.contrib.auth.forms import AdminUserCreationForm, UserChangeForm
from django import forms
from django.conf import settings
from django.contrib.auth.forms import (
    AdminUserCreationForm,
    BaseUserCreationForm,
    UserChangeForm,
)
from .models import User


class CustomUserCreationForm(AdminUserCreationForm):
    """Formular 'Benutzer hinzufügen' im Admin.

    AdminUserCreationForm (seit Django 5.1) bringt password1, password2
    und den Schalter 'usable_password' mit. Wir tauschen nur das Model
    und die Felder aus – die Basisklasse ist auf auth.User mit 'username'
    ausgelegt, das es bei uns nicht gibt.
    """

    class Meta:
        model = User
        fields = ("email",)


class CustomUserChangeForm(UserChangeForm):
    """Formular 'Benutzer ändern' im Admin.

    Das Passwort wird hier nur als Hash angezeigt (ReadOnlyPasswordHashField)
    mit Link auf das separate Passwort-ändern-Formular.
    """

    class Meta:
        model = User
        fields = ("email", "first_name", "last_name")


class RegistrationForm(BaseUserCreationForm):
    """Selbstregistrierung im Frontend.

    BaseUserCreationForm bringt mit:
      - password1 / password2 inkl. Abgleich
      - validate_password() gegen AUTH_PASSWORD_VALIDATORS (min. 12 Zeichen usw.)
      - Hilfetext mit den Passwortregeln
      - save(): hasht das Passwort per set_password()
    """

    class Meta:
        model = User
        fields = ("email", "first_name", "last_name")

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Klarnamen sind Pflicht – wichtig fürs spätere Audit-Log
        self.fields["first_name"].required = True
        self.fields["last_name"].required = True
        # Browser/Passwortmanager korrekt unterstützen
        self.fields["email"].widget.attrs["autocomplete"] = "email"
        self.fields["password1"].widget.attrs["autocomplete"] = "new-password"
        self.fields["password2"].widget.attrs["autocomplete"] = "new-password"

    def clean_email(self):
        """Feld-Validierung für 'email' (Namensschema: clean_<feldname>)."""
        email = self.cleaned_data["email"].strip().lower()

        # 🛠️ 8: Domain-Whitelist – hier einbauen (siehe Aufgabe unten)

        # Befund 1: Duplikat VOR dem Speichern erkennen, case-insensitive
        if User.objects.filter(email__iexact=email).exists():
            raise forms.ValidationError(
                "Für diese E-Mail-Adresse existiert bereits ein Konto.",
                code="duplicate_email",
            )
        return email
