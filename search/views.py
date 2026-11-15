import logging

from django.contrib.auth.mixins import LoginRequiredMixin
from django.views.generic import FormView

from . import services
from .forms import SearchForm
from .nfdump import NfdumpError

logger = logging.getLogger(__name__)


class SearchView(LoginRequiredMixin, FormView):
    """GET: leeres Suchformular. POST: validieren, nfdump abfragen, Ergebnis anzeigen."""

    template_name = "search/search.html"
    form_class = SearchForm

    def form_valid(self, form):
        data = form.cleaned_data

        try:
            result = services.search(
                public_ip=data["public_ip"],
                port=data["port"],
                protocol=data["protocol"],
                timestamp=data["timestamp_utc"],
            )
        except NfdumpError:
            # Details (Pfade, Filter, Exit-Code) nur ins Log, nicht in die Oberfläche
            logger.exception("nfdump-Fehler bei Suche durch %s", self.request.user.email)
            form.add_error(
                None,
                "Die Netflow-Daten konnten nicht abgefragt werden. Der Fehler wurde protokolliert.",
            )
            return self.form_invalid(form)

        context = self.get_context_data(
            form=form,
            result=result,
            input_timestamp=data["timestamp"],
            input_tz=data["tz"],
            reference=data["reference"],
        )
        return self.render_to_response(context)