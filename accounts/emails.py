from django.conf import settings
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.urls import reverse
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode

from .tokens import account_activation_token


def build_activation_url(user):
    """Absoluter Aktivierungslink: SITE_URL + /accounts/activate/<uidb64>/<token>/"""
    uidb64 = urlsafe_base64_encode(force_bytes(user.pk))
    token = account_activation_token.make_token(user)
    path = reverse("accounts:activate", kwargs={"uidb64": uidb64, "token": token})
    return f"{settings.SITE_URL}{path}"


def send_activation_email(user):
    context = {
        "user": user,
        "activation_url": build_activation_url(user),
        "valid_hours": settings.PASSWORD_RESET_TIMEOUT // 3600,
    }
    body = render_to_string("accounts/emails/activation.txt", context)

    send_mail(
        subject="NetflowSearch – E-Mail-Adresse bestätigen",
        message=body,
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=[user.email],
        fail_silently=False,   # Fehler sollen hochkommen, nicht verschluckt werden
    )
