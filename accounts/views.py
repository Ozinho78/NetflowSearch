from django.contrib import messages
from django.shortcuts import redirect
from django.urls import reverse_lazy
from django.views.generic import CreateView

from .forms import RegistrationForm


class RegisterView(CreateView):
    """GET: leeres Formular anzeigen. POST: validieren, bei Erfolg User anlegen."""

    form_class = RegistrationForm
    template_name = "accounts/register.html"
    success_url = reverse_lazy("accounts:login")

    def dispatch(self, request, *args, **kwargs):
        # dispatch() läuft vor get()/post() – eingeloggte User brauchen keine Registrierung
        if request.user.is_authenticated:
            return redirect("home")
        return super().dispatch(request, *args, **kwargs)

    def form_valid(self, form):
        # Wird nur aufgerufen, wenn form.is_valid() True ist
        user = form.save(commit=False)   # Objekt bauen, Passwort hashen, noch NICHT speichern
        user.is_active = False           # Login erst nach Bestätigung (Etappe 2.3)
        user.save()
        self.object = user

        messages.success(
            self.request,
            "Ihr Konto wurde angelegt und muss noch aktiviert werden.",
        )
        return redirect(self.get_success_url())
