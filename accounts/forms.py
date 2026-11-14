from django.contrib.auth.forms import AdminUserCreationForm, UserChangeForm

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