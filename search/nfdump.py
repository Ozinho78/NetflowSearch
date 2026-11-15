"""Anbindung an nfdump 1.6 (NSEL/NEL) – Aufruf und Parsing.

Alle Zeitstempel werden in UTC verarbeitet: nfdump läuft mit TZ=UTC,
dadurch sind Ausgabe (%ts) und Eingabe (-t) eindeutig, auch während
der Zeitumstellung.
"""

import datetime
import logging
import subprocess
from dataclasses import dataclass
from pathlib import Path
from zoneinfo import ZoneInfo

from django.conf import settings

logger = logging.getLogger(__name__)

# Reihenfolge der Felder = Reihenfolge der Spalten in der Ausgabe
FIELDS = ["%ts", "%nevt", "%pr", "%sa", "%xsa", "%pbstart", "%pbend", "%ra"]
OUTPUT_FORMAT = "fmt:" + "|".join(FIELDS)
TIMESTAMP_FORMAT = "%Y-%m-%d %H:%M:%S.%f"

# Minimale Umgebung für den Kindprozess:
#  - TZ=UTC: eindeutige Zeitstempel
#  - LANG=C.UTF-8: keine länderspezifischen Zahlen-/Datumsformate
#  - PATH: nur Systemverzeichnisse (nfdump wird ohnehin absolut aufgerufen)
# Alles andere aus der Umgebung von Django (z. B. Secrets aus .env) wird
# NICHT an nfdump weitergereicht.
NFDUMP_ENV = {
    "TZ": "UTC",
    "LANG": "C.UTF-8",
    "PATH": "/usr/local/bin:/usr/bin:/bin",
}

# nfcapd-Dateien: nfcapd.YYYYMMDDhhmm, Rotation alle 5 Minuten
FILE_PREFIX = "nfcapd."
FILE_TIME_FORMAT = "%Y%m%d%H%M"
FILE_ROTATION = datetime.timedelta(minutes=5)


class NfdumpError(Exception):
    """nfdump konnte nicht ausgeführt werden oder hat einen Fehler gemeldet."""


@dataclass(frozen=True, slots=True)
class NatEvent:
    """Ein NAT-Event (Port-Block-Vergabe oder -Freigabe) aus nfdump."""

    timestamp: datetime.datetime   # aware, UTC
    event: str                     # "ADD" oder "DELETE"
    protocol: str                  # "TCP", "UDP", "ICMP"
    inside_ip: str                 # interne CGNAT-Adresse (100.64.0.0/10)
    outside_ip: str                # öffentliche Adresse
    port_start: int
    port_end: int
    router: str                    # exportierender CGN-Router

    def covers_port(self, port: int) -> bool:
        """Liegt der Port im zugewiesenen Block?"""
        return self.port_start <= port <= self.port_end


def run_nfdump(args: list[str]) -> str:
    """nfdump mit festen Optionen + args ausführen, stdout zurückgeben.

    args: z. B. ["-R", "/var/cache/nfdump/nfcapd.202611151200:nfcapd.202611151215",
                 "src xip 203.0.113.17"]
    """
    cmd = [settings.NFDUMP_BIN, "-q", "-o", OUTPUT_FORMAT, *args]
    logger.debug("nfdump-Aufruf: %s", cmd)

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=settings.NFDUMP_TIMEOUT,
            env=NFDUMP_ENV,
            check=False,   # Exit-Code werten wir selbst aus
        )
    except FileNotFoundError as exc:
        raise NfdumpError(f"nfdump nicht gefunden: {settings.NFDUMP_BIN}") from exc
    except subprocess.TimeoutExpired as exc:
        raise NfdumpError(
            f"nfdump hat das Zeitlimit von {settings.NFDUMP_TIMEOUT} s überschritten"
        ) from exc

    if result.returncode != 0:
        # nfdump 1.6 schreibt Fehler teils nach stdout, teils nach stderr
        detail = (result.stderr or result.stdout).strip()[:500]
        raise NfdumpError(f"nfdump Exit-Code {result.returncode}: {detail}")

    return result.stdout


def parse_line(line: str) -> NatEvent:
    """Eine Zeile der fmt-Ausgabe in ein NatEvent umwandeln.

    Wirft ValueError bei unerwartetem Format.
    """
    parts = [p.strip() for p in line.split("|")]
    if len(parts) != len(FIELDS):
        raise ValueError(f"{len(parts)} statt {len(FIELDS)} Spalten: {line!r}")

    ts_str, event, proto, inside, outside, pb_start, pb_end, router = parts

    timestamp = datetime.datetime.strptime(ts_str, TIMESTAMP_FORMAT).replace(
        tzinfo=datetime.timezone.utc   # nfdump lief mit TZ=UTC
    )

    return NatEvent(
        timestamp=timestamp,
        event=event,
        protocol=proto,
        inside_ip=inside,
        outside_ip=outside,
        port_start=int(pb_start),
        port_end=int(pb_end),
        router=router,
    )
    
@dataclass(frozen=True, slots=True)
class CaptureFile:
    """Eine abgeschlossene nfcapd-Datei und ihr Startzeitpunkt."""

    path: Path
    start: datetime.datetime   # aware, UTC

    @property
    def end(self) -> datetime.datetime:
        return self.start + FILE_ROTATION


def list_capture_files(directory: Path | None = None) -> list[CaptureFile]:
    """Alle abgeschlossenen nfcapd-Dateien, chronologisch sortiert (UTC)."""
    directory = Path(directory or settings.NFDUMP_DIR)
    tz = ZoneInfo(settings.NFDUMP_TIMEZONE)
    files = []

    for path in directory.glob(FILE_PREFIX + "*"):
        stamp = path.name.removeprefix(FILE_PREFIX)
        # nfcapd.current.<pid> (wird gerade geschrieben) und Fremdes ignorieren
        if len(stamp) != 12 or not stamp.isdigit():
            continue
        local = datetime.datetime.strptime(stamp, FILE_TIME_FORMAT)
        files.append(CaptureFile(path=path, start=local.replace(tzinfo=tz).astimezone(datetime.timezone.utc)))

    # Nach UTC sortieren, nicht nach Dateiname -> korrekt auch über die Zeitumstellung
    files.sort(key=lambda f: f.start)
    return files


def select_files(
    start: datetime.datetime,
    end: datetime.datetime,
    directory: Path | None = None,
) -> list[CaptureFile]:
    """Dateien, deren 5-Minuten-Intervall sich mit [start, end] überschneidet."""
    return [f for f in list_capture_files(directory) if f.end > start and f.start <= end]


def range_args(files: list[CaptureFile]) -> list[str]:
    """nfdump-Argument für einen Dateibereich: -R /pfad/erste:letzte"""
    if not files:
        raise ValueError("Keine Dateien im Suchfenster")
    first, last = files[0], files[-1]
    # nfdump erwartet beim zweiten Teil nur den Dateinamen (gleiches Verzeichnis)
    return ["-R", f"{first.path}:{last.path.name}"]


def parse_output(stdout: str) -> list[NatEvent]:
    """Gesamte nfdump-Ausgabe parsen. Kaputte Zeilen werden übersprungen."""
    events = []
    skipped = 0

    for line in stdout.splitlines():
        # 1) Leere Zeilen (auch nur Leerzeichen) überspringen
        if not line.strip():
            continue

        try:
            # 2) Zeile -> NatEvent, an die Liste anhängen
            events.append(parse_line(line))
        except ValueError as exc:
            # 3) Kaputte Zeile: zählen, im Debug-Log festhalten, weitermachen
            skipped += 1
            logger.debug("nfdump-Zeile übersprungen: %s", exc)

    # Eine Zusammenfassung statt einer Warnung pro Zeile
    if skipped:
        logger.warning("%d nfdump-Zeilen konnten nicht geparst werden", skipped)

    return events