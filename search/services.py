"""Fachlogik der Suche: Suchfenster, nfdump-Abfrage, ADD/DELETE-Korrelation."""

import datetime
import ipaddress
from collections import defaultdict
from dataclasses import dataclass, field

from django.conf import settings
from django.utils import timezone

from . import nfdump
from .nfdump import NatEvent

ALLOWED_PROTOCOLS = {"any", "tcp", "udp", "icmp"}

ASSIGNED = "assigned"
FREE = "free"
STATUS_LABELS = {ASSIGNED: "vergeben", FREE: "nicht vergeben"}


@dataclass(frozen=True, slots=True)
class Assignment:
    """Zustand eines Port-Blocks zum gesuchten Zeitpunkt."""

    status: str                                # ASSIGNED oder FREE
    router: str
    protocol: str
    outside_ip: str
    port_start: int
    port_end: int
    inside_ip: str | None = None               # nur bei ASSIGNED (Datenminimierung)
    start: datetime.datetime | None = None     # ASSIGNED: ADD   / FREE: letztes DELETE
    end: datetime.datetime | None = None       # ASSIGNED: DELETE / FREE: nächstes ADD
    near_boundary: bool = False

    @property
    def status_label(self) -> str:
        return STATUS_LABELS[self.status]


@dataclass(slots=True)
class SearchResult:
    """Gesamtergebnis einer Suche inkl. Metadaten für Anzeige und Audit."""

    public_ip: str
    port: int
    protocol: str
    timestamp: datetime.datetime
    window_start: datetime.datetime
    window_end: datetime.datetime
    data_start: datetime.datetime | None = None   # tatsächlich vorhandene Daten
    data_end: datetime.datetime | None = None
    file_count: int = 0
    event_count: int = 0
    assignments: list[Assignment] = field(default_factory=list)

    @property
    def found(self) -> bool:
        return any(a.status == ASSIGNED for a in self.assignments)
    
    @property
    def assigned_inside_ips(self) -> set[str]:
        """Alle internen IPs, denen der Port zum Zeitpunkt zugeordnet war."""
        return {a.inside_ip for a in self.assignments if a.status == ASSIGNED and a.inside_ip}

    @property
    def ambiguous(self) -> bool:
        """Mehr als ein Kunde (z. B. TCP und UDP an verschiedene Kunden)."""
        return len(self.assigned_inside_ips) > 1

    @property
    def has_boundary_case(self) -> bool:
        return any(a.near_boundary for a in self.assignments)

    @property
    def data_incomplete(self) -> bool:
        """Deckt der Datenbestand das Suchfenster nicht vollständig ab?"""
        if self.data_start is None:
            return True
        return self.data_start > self.window_start + nfdump.FILE_ROTATION


def _near(a: datetime.datetime, b: datetime.datetime | None, tolerance: datetime.timedelta) -> bool:
    return b is not None and abs(a - b) <= tolerance


def correlate(
    events: list[NatEvent],
    port: int,
    ts: datetime.datetime,
    tolerance: datetime.timedelta | None = None,
) -> list[Assignment]:
    """Bestimmt für jeden Port-Block, der `port` enthält, den Zustand zum Zeitpunkt `ts`.

    Reine Funktion: kein I/O, keine Settings außer dem Default für tolerance.
    """
    if tolerance is None:
        tolerance = datetime.timedelta(seconds=settings.SEARCH_BOUNDARY_TOLERANCE_SECONDS)

    # 1) Nur Events, deren Block den Port enthält, nach Block gruppieren
    blocks: dict[tuple, list[NatEvent]] = defaultdict(list)
    for e in events:
        if e.covers_port(port):
            blocks[(e.router, e.protocol, e.outside_ip, e.port_start, e.port_end)].append(e)

    results = []
    for (router, proto, outside, pb_start, pb_end), evs in sorted(blocks.items()):
        evs.sort(key=lambda e: e.timestamp)
        before = [e for e in evs if e.timestamp <= ts]
        after = [e for e in evs if e.timestamp > ts]
        last = before[-1] if before else None
        block = dict(router=router, protocol=proto, outside_ip=outside,
                     port_start=pb_start, port_end=pb_end)

        if last is not None and last.event == "ADD":
            # Fall 1: vergeben seit last; Ende = erstes DELETE desselben Kunden danach
            delete = next(
                (e for e in after if e.event == "DELETE" and e.inside_ip == last.inside_ip),
                None,
            )
            end = delete.timestamp if delete else None
            results.append(Assignment(
                status=ASSIGNED, inside_ip=last.inside_ip,
                start=last.timestamp, end=end,
                near_boundary=_near(ts, last.timestamp, tolerance) or _near(ts, end, tolerance),
                **block,
            ))

        elif last is not None:
            # Fall 2: letztes Event vor ts war DELETE -> frei bis zum nächsten ADD
            next_add = next((e for e in after if e.event == "ADD"), None)
            end = next_add.timestamp if next_add else None
            results.append(Assignment(
                status=FREE, start=last.timestamp, end=end,
                near_boundary=_near(ts, last.timestamp, tolerance) or _near(ts, end, tolerance),
                **block,
            ))

        else:
            # Kein Event vor ts im Fenster -> erstes Event danach entscheidet
            first = after[0]   # existiert, sonst gäbe es den Block nicht
            if first.event == "DELETE":
                # Fall 3: vergeben, ADD liegt vor dem Fensterbeginn
                results.append(Assignment(
                    status=ASSIGNED, inside_ip=first.inside_ip,
                    start=None, end=first.timestamp,
                    near_boundary=_near(ts, first.timestamp, tolerance),
                    **block,
                ))
            else:
                # Fall 4: erstes Event ist ADD -> vorher frei
                results.append(Assignment(
                    status=FREE, start=None, end=first.timestamp,
                    near_boundary=_near(ts, first.timestamp, tolerance),
                    **block,
                ))

    return results


def search(public_ip: str, port: int, protocol: str, timestamp: datetime.datetime) -> SearchResult:
    """Komplette Suche: Fenster bestimmen, nfdump abfragen, korrelieren.

    Validiert die Eingaben erneut (Defense in Depth): die Funktion soll auch
    sicher sein, wenn sie später aus einem anderen Kontext aufgerufen wird
    (Management-Command, API) und nicht nur aus dem geprüften Formular.
    """
    ip = ipaddress.IPv4Address(public_ip)   # ValueError bei Unsinn
    if protocol not in ALLOWED_PROTOCOLS:
        raise ValueError(f"Ungültiges Protokoll: {protocol!r}")
    if not 1 <= port <= 65535:
        raise ValueError(f"Ungültiger Port: {port!r}")
    if timestamp.tzinfo is None:
        raise ValueError("timestamp muss timezone-aware sein")

    window_start = timestamp - datetime.timedelta(hours=settings.SEARCH_LOOKBACK_HOURS)
    window_end = min(
        timestamp + datetime.timedelta(hours=settings.SEARCH_LOOKAHEAD_HOURS),
        timezone.now(),
    )

    files = nfdump.select_files(window_start, window_end)
    result = SearchResult(
        public_ip=str(ip), port=port, protocol=protocol, timestamp=timestamp,
        window_start=window_start, window_end=window_end,
        data_start=files[0].start if files else None,
        data_end=files[-1].end if files else None,
        file_count=len(files),
    )
    if not files:
        return result

    # Filter in nfdump: nur die öffentliche IP (und ggf. das Protokoll)
    flt = f"src xip {ip}"
    if protocol != "any":
        flt += f" and proto {protocol}"

    events = nfdump.parse_output(nfdump.run_nfdump([*nfdump.range_args(files), flt]))
    result.event_count = len(events)
    result.assignments = correlate(events, port, timestamp)
    return result