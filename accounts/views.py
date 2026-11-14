import logging

from django.contrib import messages
from django.db import transaction
from django.shortcuts import redirect, render
from django.urls import reverse_lazy
from django.utils.encoding import force_str
from django.utils.http import urlsafe_base64_decode
from django.views import View
from django.views.generic import CreateView

from .emails import send_activation_email
from .forms import RegistrationForm
from .models import User
from .tokens import account_activation_token

logger = logging.getLogger(__name__)


class RegisterView(CreateView):
    form_class = RegistrationForm
    template_name = "accounts/register.html"
    success_url = reverse_lazy("accounts:login")

    def dispatch(self, request, *args, **kwargs):
        if request.user.is_authenticated:
            return redirect("home")
        return super().dispatch(request, *args, **kwargs)

    def form_valid(self, form):
        try:
            # atomic: schlägt der Mailversand fehl, wird der User NICHT angelegt
            # (sonst bliebe ein inaktives Konto ohne Aktivierungslink übrig)
            with transaction.atomic():
                user = form.save(commit=False)
                user.is_active = False
                user.save()
                send_activation_email(user)
        except OSError:
            # OSError deckt smtplib.SMTPException, Connection refused, Timeouts ab
            logger.exception("Aktivierungsmail an %s fehlgeschlagen", form.cleaned_data["email"])
            form.add_error(
                None,
                "Die Bestätigungsmail konnte nicht versendet werden. Bitte später erneut versuchen.",
            )
            return self.form_invalid(form)

        self.object = user
        messages.success(
            self.request,
            "Fast geschafft: Wir haben Ihnen eine E-Mail mit einem Bestätigungslink gesendet.",
        )
        return redirect(self.get_success_url())


class ActivateView(View):
    """GET zeigt eine Bestätigungsseite, erst POST aktiviert das Konto.

    Warum nicht direkt beim GET aktivieren? Mail-Security-Gateways
    (z. B. Microsoft Defender "Safe Links") rufen Links in eingehenden
    Mails automatisch auf, um sie zu scannen. Ein GET mit Seiteneffekt
    würde das Konto aktivieren, bevor ein Mensch geklickt hat.
    """

    template_name = "accounts/activate.html"

    def _get_valid_user(self, uidb64, token):
        """User zurückgeben, wenn Link gültig, sonst None."""
        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            return None

        if user.is_active:
            return None
        if not account_activation_token.check_token(user, token):
            return None
        return user

    def get(self, request, uidb64, token):
        user = self._get_valid_user(uidb64, token)
        return render(request, self.template_name, {"valid": user is not None})

    def post(self, request, uidb64, token):
        user = self._get_valid_user(uidb64, token)   # erneut prüfen, nie dem GET vertrauen
        if user is None:
            messages.error(request, "Der Aktivierungslink ist ungültig oder abgelaufen.")
            return redirect("accounts:login")

        user.is_active = True
        user.save(update_fields=["is_active"])   # nur diese Spalte schreiben
        logger.info("Konto aktiviert: %s", user.email)

        messages.success(request, "Ihr Konto ist aktiviert. Sie können sich jetzt anmelden.")
        return redirect("accounts:login")
