from django.contrib.auth.models import AbstractUser, BaseUserManager
from django.db import models
from django.db.models.functions import Lower


class UserManager(BaseUserManager):
    """Manager für ein User-Model ohne username – Login per E-Mail."""

    # Manager wird in Migrationen verfügbar gemacht (z. B. für Data-Migrations)
    use_in_migrations = True

    def _create_user(self, email, password, **extra_fields):
        if not email:
            raise ValueError("Die E-Mail-Adresse ist ein Pflichtfeld.")

        # 🛠️ 1: normalize_email() macht nur den Domain-Teil klein.
        #        Ersetze die nächste Zeile so, dass die GESAMTE Adresse
        #        kleingeschrieben und von Leerzeichen am Anfang/Ende befreit wird.
        # email = self.normalize_email(email)
        # komplette Adresse normalisieren, nicht nur den Domain-Teil
        email = email.strip().lower()

        user = self.model(email=email, **extra_fields)
        user.set_password(password)   # hasht (PBKDF2); bei None -> unbrauchbares Passwort
        user.save(using=self._db)
        return user

    def create_user(self, email, password=None, **extra_fields):
        extra_fields.setdefault("is_staff", False)
        extra_fields.setdefault("is_superuser", False)
        return self._create_user(email, password, **extra_fields)

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)
        extra_fields.setdefault("is_active", True)

        if extra_fields.get("is_staff") is not True:
            raise ValueError("Superuser muss is_staff=True haben.")
        if extra_fields.get("is_superuser") is not True:
            raise ValueError("Superuser muss is_superuser=True haben.")

        return self._create_user(email, password, **extra_fields)


class User(AbstractUser):
    # Feld 'username' aus AbstractUser entfernen
    username = None
    email = models.EmailField("E-Mail-Adresse", unique=True)

    USERNAME_FIELD = "email"    # Login-Feld
    REQUIRED_FIELDS = []        # zusätzliche Pflichtfelder bei createsuperuser

    objects = UserManager()

    class Meta:
        verbose_name = "Benutzer"
        verbose_name_plural = "Benutzer"
        constraints = [
            # DB-seitig eindeutig ohne Rücksicht auf Groß-/Kleinschreibung
            models.UniqueConstraint(
                Lower("email"),
                name="user_email_ci_unique",
            ),
        ]

    def clean(self):
        # wird von ModelForms (Admin, Registrierung) vor dem Speichern aufgerufen
        super().clean()
        if self.email:
            self.email = self.email.strip().lower()

    def __str__(self):
        return self.email


