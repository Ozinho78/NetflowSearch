from django.contrib.auth.mixins import LoginRequiredMixin
from django.views.generic import FormView

from .forms import SearchForm


class SearchView(LoginRequiredMixin, FormView):
    """GET: leeres Suchformular. POST: validieren und Abfrage anzeigen.

    Etappe 3: nur Vorschau der normalisierten Abfrage.
    Etappe 4: hier wird nfdump aufgerufen.
    """

    template_name = "search/search.html"
    form_class = SearchForm

    def form_valid(self, form):
        data = form.cleaned_data
        query = {
            "public_ip": data["public_ip"],
            "port": data["port"],
            "protocol": data["protocol"],
            "protocol_label": dict(form.fields["protocol"].choices)[data["protocol"]],
            "timestamp_utc": data["timestamp_utc"],
            "input_timestamp": data["timestamp"],
            "input_tz": data["tz"],
            "reference": data["reference"],
        }
        # Kein Redirect: Ergebnis wird direkt unter dem Formular angezeigt.
        # Formular bleibt ausgefüllt -> schnell eine Variante suchen.
        return self.render_to_response(self.get_context_data(form=form, query=query))
