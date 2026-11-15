import datetime
import ipaddress
from zoneinfo import ZoneInfo

from django import forms
from django.conf import settings
from django.core.exceptions import ValidationError
from django.utils import timezone
from django.utils.dateparse import parse_datetime

PROTOCOL_CHOICES = [
    ("any", "alle"),
    ("tcp", "TCP"),
    ("udp", "UDP"),
    ("icmp", "ICMP"),
]

TIMEZONE_CHOICES = [
    ("Europe/Berlin", "Deutsche Zeit (MEZ/MESZ)"),
    ("UTC", "UTC"),
]


class NaiveDateTimeField(forms.DateTimeField):
    """DateTimeField OHNE automatische Zeitzone.

    Das normale DateTimeField hängt bei USE_TZ=True sofort TIME_ZONE
    (Europe/Berlin) an – und lehnt dabei Uhrzeiten ab, die es in Berlin
    nicht gibt (Zeitumstellung). Das wäre falsch, wenn der Nutzer UTC
    gemeint hat. Deshalb liefern wir eine naive datetime und setzen die
    Zeitzone selbst in SearchForm.clean(), wenn wir sie kennen.
    """

    def to_python(self, value):
        if value in self.empty_values:
            return None
        if isinstance(value, datetime.datetime):
            return value.replace(tzinfo=None)
        try:
            # Format von <input type="datetime-local">: 2026-11-14T13:45:12
            result = parse_datetime(str(value).strip())
        except ValueError:
            result = None
        if result is None:
            raise ValidationError(self.error_messages["invalid"], code="invalid")
        return result


class SearchForm(forms.Form):
    public_ip = forms.GenericIPAddressField(
        label="Öffentliche IP-Adresse",
        protocol="IPv4",
        widget=forms.TextInput(attrs={"placeholder": "203.0.113.17", "autofocus": True}),
    )
    port = forms.IntegerField(
        label="Port",
        min_value=1,
        max_value=65535,
        widget=forms.NumberInput(attrs={"placeholder": "51234"}),
    )
    protocol = forms.ChoiceField(
        label="Protokoll",
        choices=PROTOCOL_CHOICES,
        initial="any",
    )
    timestamp = NaiveDateTimeField(
        label="Zeitpunkt",
        # step=1 -> Browser erlaubt Sekunden
        widget=forms.DateTimeInput(attrs={"type": "datetime-local", "step": "1"}),
    )
    tz = forms.ChoiceField(
        label="Zeitzone der Angabe",
        choices=TIMEZONE_CHOICES,
        initial="Europe/Berlin",
    )
    reference = forms.CharField(
        label="Anlass / Aktenzeichen",
        max_length=100,
        help_text="Pflichtangabe für das Protokoll, z. B. BSI-Vorgang oder Ticketnummer.",
    )

    def clean_public_ip(self):
        value = self.cleaned_data["public_ip"]   # String, z. B. "203.0.113.17"

        # 🛠️ 12: Prüfen, ob die IP in einem der settings.NAT_POOLS liegt.
        #         Wenn nicht -> ValidationError mit eigener Meldung und code.

        return value

    def clean(self):
        """Feldübergreifend: Zeitpunkt + Zeitzone -> aware datetime in UTC."""
        cleaned = super().clean()
        naive = cleaned.get("timestamp")
        tzname = cleaned.get("tz")
        if naive is None or tzname is None:
            return cleaned   # Feldfehler sind schon gemeldet

        tz = ZoneInfo(tzname)
        aware = naive.replace(tzinfo=tz)   # fold=0 -> bei Doppeldeutigkeit die erste

        # 1) Nicht existierende Zeit (Sommerzeit-Beginn, z. B. 29.03. 02:30 in Berlin):
        #    Hin- und Rückrechnung über UTC ergibt eine andere Wanduhrzeit.
        roundtrip = aware.astimezone(datetime.timezone.utc).astimezone(tz).replace(tzinfo=None)
        if roundtrip != naive:
            self.add_error(
                "timestamp",
                "Diese Uhrzeit gibt es in deutscher Zeit nicht (Beginn der Sommerzeit). "
                "Bitte die Zeitzone der Anfrage prüfen oder in UTC angeben.",
            )
            return cleaned

        # 2) Doppelte Zeit (Sommerzeit-Ende, z. B. 25.10. 02:30 in Berlin):
        #    fold=0 und fold=1 haben unterschiedliche UTC-Offsets.
        if aware.utcoffset() != naive.replace(tzinfo=tz, fold=1).utcoffset():
            self.add_error(
                "timestamp",
                "Diese Uhrzeit gibt es in deutscher Zeit zweimal (Ende der Sommerzeit). "
                "Bitte in UTC angeben, damit die Zuordnung eindeutig ist.",
            )
            return cleaned

        ts_utc = aware.astimezone(datetime.timezone.utc)
        now = timezone.now()   # aware, UTC

        if ts_utc > now + datetime.timedelta(minutes=5):   # kleine Toleranz für Uhrenabweichung
            self.add_error("timestamp", "Der Zeitpunkt liegt in der Zukunft.")
        elif ts_utc < now - datetime.timedelta(days=settings.SEARCH_MAX_AGE_DAYS):
            self.add_error(
                "timestamp",
                f"Der Zeitpunkt liegt mehr als {settings.SEARCH_MAX_AGE_DAYS} Tage zurück. "
                "Für diesen Zeitraum liegen keine Daten mehr vor.",
            )
        else:
            cleaned["timestamp_utc"] = ts_utc   # Ergebnis für die View

        return cleaned
