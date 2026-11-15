#!/usr/bin/env python3
"""
nelgen – Generator für CGNAT NAT Event Logging (NEL) mit Port Block Allocation.

Simuliert einen oder mehrere CGN-Router, die Kunden aus 100.64.0.0/10 Port-Blöcke
auf öffentlichen IPs zuweisen (ADD) und wieder freigeben (DELETE), und exportiert
diese Events als NetFlow v9 oder IPFIX an nfcapd. Die Daten sind rein synthetisch.

Öffentliche Pools: Jeder Router bekommt ein Netz aus --pools (Router i -> Netz
i % Anzahl Netze). Teilen sich mehrere Router ein Netz, erhalten sie
überschneidungsfreie Teilmengen. Für das Lab eignen sich nur Adressen, die
nirgends im Internet geroutet werden, z. B. die Dokumentationsnetze aus RFC 5737
(192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) und das Benchmark-Netz aus
RFC 2544 (198.18.0.0/15).

Modi:
  print     Events als Tabelle ausgeben (ohne Netzwerk, zum Prüfen der Logik)
  backfill  Historische Daten erzeugen: pro 5-Minuten-Slot eine temporäre nfcapd-Instanz,
            Ergebnis als nfcapd.YYYYMMDDhhmm im Flow-Verzeichnis
  live      Echtzeitbetrieb gegen den laufenden nfcapd (systemd-Dienst)

Argumente können aus einer Datei gelesen werden (ein Argument pro Zeile,
'#' für Kommentare):  nelgen.py live @/etc/nelgen/nelgen.conf

Der Simulationszustand (offene Port-Blöcke, geplante Events) wird in --state gespeichert,
damit live nahtlos an backfill bzw. an einen vorherigen Lauf anschließt.
"""
import argparse
import glob
import heapq
import ipaddress
import logging
import os
import pickle
import random
import re
import shutil
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time

log = logging.getLogger("nelgen")

TEMPLATE_ID = 260
# (Information Element / v9-Feldtyp, Länge) – Reihenfolge = Reihenfolge im Datensatz
FIELDS = [
    (8, 4),     # sourceIPv4Address           -> src addr (interne CGNAT-IP)
    (225, 4),   # postNATSourceIPv4Address    -> src xlt ip (öffentliche IP)
    (4, 1),     # protocolIdentifier
    (230, 1),   # natEvent: 1 = CREATE/ADD, 2 = DELETE
    (152, 8),   # flowStartMilliseconds       -> first
    (153, 8),   # flowEndMilliseconds         -> last
    (323, 8),   # observationTimeMilliseconds -> Event time
    (361, 2),   # portRangeStart              -> pblock start
    (362, 2),   # portRangeEnd                -> pblock end
    (363, 2),   # portRangeStepSize           -> pblock step
    (364, 2),   # portRangeNumPorts           -> pblock size
]
REC_FMT = "!IIBBQQQHHHH"
REC_LEN = struct.calcsize(REC_FMT)
assert REC_LEN == sum(length for _, length in FIELDS)

RECORDS_PER_PACKET = 25          # 25 * 42 Byte ≈ 1 KB, weit unter MTU
TEMPLATE_EVERY_PACKETS = 20
TEMPLATE_EVERY_SECONDS = 30
SLOT_MS = 300_000                # nfcapd-Rotation: 5 Minuten
PROTO_NAME = {1: "ICMP", 6: "TCP", 17: "UDP"}
EVENT_NAME = {1: "ADD", 2: "DELETE"}

_START_MONO = time.monotonic()


def ip2int(ip):
    return int(ipaddress.IPv4Address(ip))


def int2ip(n):
    return str(ipaddress.IPv4Address(n))


def now_ms():
    return int(time.time() * 1000)


# --------------------------------------------------------------------------- Simulation

def build_router_pools(routers, pools, pool_size):
    """Öffentliche IPs je Router: Router i nutzt Netz i % len(pools).

    Teilen sich mehrere Router ein Netz, bekommen sie verschränkte,
    überschneidungsfreie Teilmengen (Router A: .1 .3 .5 …, Router B: .2 .4 .6 …).
    """
    nets = [ipaddress.ip_network(n) for n in pools]
    sharing = {}
    for i in range(len(routers)):
        sharing.setdefault(i % len(nets), []).append(i)

    result = []
    for i, rip in enumerate(routers):
        ni = i % len(nets)
        members = sharing[ni]
        hosts = [int(ip) for ip in nets[ni].hosts()]
        pool = hosts[members.index(i)::len(members)][:pool_size]
        if not pool:
            raise SystemExit(f"Kein öffentlicher Adressraum für Router {rip} in {nets[ni]}")
        if len(pool) < pool_size:
            log.warning("Router %s: nur %d statt %d IPs in %s verfügbar",
                        rip, len(pool), pool_size, nets[ni])
        result.append((str(nets[ni]), pool))
    return result


class Simulation:
    """Ereignisgesteuerte Simulation der Port-Block-Vergabe (picklebar)."""

    def __init__(self, cfg, t0_ms):
        self.cfg = cfg
        self.rnd = random.Random(cfg["seed"])
        rnd = self.rnd

        router_pools = build_router_pools(cfg["routers"], cfg["pools"], cfg["pool_size"])

        self.routers = []
        for i, rip in enumerate(cfg["routers"]):
            bsize = cfg["block_sizes"][i % len(cfg["block_sizes"])]
            net, pool = router_pools[i]
            self.routers.append({
                "ip": rip,
                "net": net,
                "pool": pool,
                "bsize": bsize,
                "nblocks": (65536 - cfg["port_min"]) // bsize,
            })

        cgn = ipaddress.ip_network("100.64.0.0/10")
        inside = rnd.sample(range(int(cgn.network_address) + 1, int(cgn.broadcast_address)),
                            cfg["subscribers"])
        self.subs = []   # (inside_ip, router_idx, home_public_ip, [protos])
        for n, ip in enumerate(inside):
            r = n % len(self.routers)
            rt = self.routers[r]
            home = rt["pool"][(n // len(self.routers)) % len(rt["pool"])]   # Paired Pooling
            protos = [6]
            if rnd.random() < 0.85:
                protos.append(17)
            if rnd.random() < 0.30:
                protos.append(1)
            self.subs.append((ip, r, home, protos))

        self.used = {}     # (public_ip, proto) -> set(block_index)
        self.active = {}   # (sub_idx, proto)  -> (public_ip, block_index)
        self.heap = []
        self.counter = 0
        self.saved_at = t0_ms

        for si, (_, _, _, protos) in enumerate(self.subs):
            for p in protos:
                self._push(t0_ms + self._idle_ms(p), "add", si, p)

    # Zeitverhalten -------------------------------------------------------------
    def _hold_ms(self, proto):
        r = self.rnd.random()
        if r < 0.55:
            s = self.rnd.uniform(60, 1200)              # kurz: 1–20 min
        elif r < 0.90:
            s = self.rnd.uniform(1200, 3 * 3600)        # mittel: 20 min – 3 h
        else:
            s = self.rnd.uniform(3 * 3600, 12 * 3600)   # lang: 3–12 h
        if proto == 1:
            s /= 4
        return int(s * 1000) + self.rnd.randrange(1000)

    def _idle_ms(self, proto):
        mean = 900 if proto != 1 else 3600
        return int((5 + self.rnd.expovariate(1 / mean)) * 1000) + self.rnd.randrange(1000)

    def _push(self, t, kind, si, proto):
        self.counter += 1
        heapq.heappush(self.heap, (t, self.counter, kind, si, proto))

    def _alloc(self, rt, home, proto):
        candidates = [home] + [ip for ip in rt["pool"] if ip != home]
        for pub in candidates:
            used = self.used.setdefault((pub, proto), set())
            if len(used) >= rt["nblocks"]:
                continue
            while True:
                b = self.rnd.randrange(rt["nblocks"])
                if b not in used:
                    used.add(b)
                    return pub, b
        return None   # Pool erschöpft

    # Öffentliche API -----------------------------------------------------------
    def shift(self, delta_ms):
        """Alle geplanten Events verschieben (nach Pause / Neustart)."""
        self.heap = [(t + delta_ms, c, k, s, p) for (t, c, k, s, p) in self.heap]
        heapq.heapify(self.heap)

    def next_event_ms(self):
        return self.heap[0][0] if self.heap else None

    def step(self, until_ms):
        """Alle Events bis einschließlich until_ms abarbeiten, Records zurückgeben."""
        out = []
        while self.heap and self.heap[0][0] <= until_ms:
            t, _, kind, si, proto = heapq.heappop(self.heap)
            inside, r, home, _ = self.subs[si]
            rt = self.routers[r]
            if kind == "add":
                alloc = self._alloc(rt, home, proto)
                if alloc is None:
                    log.warning("Pool erschöpft (%s, %s) – neuer Versuch in 60 s",
                                rt["ip"], PROTO_NAME[proto])
                    self._push(t + 60_000, "add", si, proto)
                    continue
                pub, b = alloc
                self.active[(si, proto)] = (pub, b)
                out.append(self._record(t, 1, r, inside, pub, proto, b))
                self._push(t + self._hold_ms(proto), "del", si, proto)
            else:
                pub, b = self.active.pop((si, proto))
                self.used[(pub, proto)].discard(b)
                out.append(self._record(t, 2, r, inside, pub, proto, b))
                self._push(t + self._idle_ms(proto), "add", si, proto)
        return out

    def _record(self, t, event, r, inside, pub, proto, b):
        rt = self.routers[r]
        start = self.cfg["port_min"] + b * rt["bsize"]
        return {
            "ts": t, "event": event, "router": r, "inside": inside, "public": pub,
            "proto": proto, "pb_start": start, "pb_end": start + rt["bsize"] - 1,
            "pb_size": rt["bsize"],
        }


# --------------------------------------------------------------------------- Export

class Exporter:
    """Ein simulierter CGN-Router: eigener UDP-Socket mit eigener Quell-IP."""

    def __init__(self, router_ip, source_id, fmt):
        self.router_ip = router_ip
        self.source_id = source_id
        self.fmt = fmt
        self.seq = 0
        self.pkts_since_tpl = TEMPLATE_EVERY_PACKETS
        self.last_tpl = 0.0
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            self.sock.bind((router_ip, 0))
        except OSError as e:
            raise SystemExit(
                f"Kann nicht an Router-IP {router_ip} binden ({e}).\n"
                f"Adresse nicht lokal? -> ip route replace local <netz> dev lo "
                f"oder ip addr add {router_ip}/32 dev lo")

    def send(self, records, collector, force_template=False, pace=0.0):
        for i in range(0, len(records), RECORDS_PER_PACKET):
            chunk = records[i:i + RECORDS_PER_PACKET]
            due = (self.pkts_since_tpl >= TEMPLATE_EVERY_PACKETS
                   or time.monotonic() - self.last_tpl >= TEMPLATE_EVERY_SECONDS)
            with_tpl = force_template or due
            force_template = False
            export_s = max(r["ts"] for r in chunk) // 1000
            pkt = self._packet(chunk, export_s, with_tpl)
            self.sock.sendto(pkt, collector)
            if with_tpl:
                self.pkts_since_tpl = 0
                self.last_tpl = time.monotonic()
            self.pkts_since_tpl += 1
            if pace:
                time.sleep(pace)

    @staticmethod
    def _encode(r):
        return struct.pack(REC_FMT, r["inside"], r["public"], r["proto"], r["event"],
                           r["ts"], r["ts"], r["ts"],
                           r["pb_start"], r["pb_end"], 1, r["pb_size"])

    def _packet(self, recs, export_s, with_tpl):
        tpl_body = struct.pack("!HH", TEMPLATE_ID, len(FIELDS)) + b"".join(
            struct.pack("!HH", t, l) for t, l in FIELDS)
        data = b"".join(self._encode(r) for r in recs)
        pad = (-(4 + len(data))) % 4
        data_set = struct.pack("!HH", TEMPLATE_ID, 4 + len(data) + pad) + data + b"\0" * pad

        if self.fmt == "v9":
            sets, count = b"", len(recs)
            if with_tpl:
                sets += struct.pack("!HH", 0, 4 + len(tpl_body)) + tpl_body
                count += 1
            sets += data_set
            uptime = int((time.monotonic() - _START_MONO) * 1000) & 0xFFFFFFFF
            hdr = struct.pack("!HHIIII", 9, count, uptime, export_s, self.seq, self.source_id)
            self.seq = (self.seq + 1) & 0xFFFFFFFF            # v9: zählt Pakete
        else:  # IPFIX
            sets = b""
            if with_tpl:
                sets += struct.pack("!HH", 2, 4 + len(tpl_body)) + tpl_body
            sets += data_set
            hdr = struct.pack("!HHIII", 10, 16 + len(sets), export_s, self.seq, self.source_id)
            self.seq = (self.seq + len(recs)) & 0xFFFFFFFF    # IPFIX: zählt Datensätze
        return hdr + sets


def send_by_router(records, exporters, collector, **kw):
    by_router = {}
    for r in records:
        by_router.setdefault(r["router"], []).append(r)
    for idx, recs in by_router.items():
        exporters[idx].send(recs, collector, **kw)


# --------------------------------------------------------------------------- State

def load_state(path):
    try:
        with open(path, "rb") as f:
            return pickle.load(f)
    except FileNotFoundError:
        return None


def save_state(sim, path, at_ms):
    sim.saved_at = at_ms
    tmp = path + ".tmp"
    with open(tmp, "wb") as f:
        pickle.dump(sim, f)
    os.replace(tmp, path)


def make_cfg(a):
    return {
        "routers": a.routers, "subscribers": a.subscribers, "pools": a.pools,
        "pool_size": a.pool_size, "block_sizes": a.block_sizes,
        "port_min": a.port_min, "seed": a.seed,
    }


def make_exporters(sim, fmt):
    return [Exporter(rt["ip"], 10 + i, fmt) for i, rt in enumerate(sim.routers)]


def parse_collector(s):
    host, _, port = s.rpartition(":")
    return host or "127.0.0.1", int(port)


def describe_routers(sim):
    """Übersicht Router -> Netz, genutzte IPs, Blockgröße."""
    lines = [f"{'Router':<15} {'Netz':<18} {'IPs':>4} {'erste IP':>15} {'letzte IP':>15} "
             f"{'Block':>6} {'Blöcke/IP':>9}"]
    for rt in sim.routers:
        lines.append(f"{rt['ip']:<15} {rt['net']:<18} {len(rt['pool']):>4} "
                     f"{int2ip(rt['pool'][0]):>15} {int2ip(rt['pool'][-1]):>15} "
                     f"{rt['bsize']:>6} {rt['nblocks']:>9}")
    return "\n".join(lines)


# --------------------------------------------------------------------------- Modi

def cmd_print(a):
    t0 = now_ms() - a.minutes * 60_000
    sim = Simulation(make_cfg(a), t0 - 6 * 3600_000)   # 6 h Vorlauf, damit Blöcke belegt sind
    sim.step(t0)
    recs = sim.step(t0 + a.minutes * 60_000)
    print(describe_routers(sim))
    print()
    print(f"{'Date first seen':<23} {'Event':>6} {'Proto':<5} {'Src IP Addr':>15} "
          f"{'X-late Src IP':>15} {'Pb-Start':>8} {'Pb-End':>7} {'Router IP':>15}")
    for r in recs[: a.limit]:
        ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(r["ts"] / 1000)) + f".{r['ts'] % 1000:03d}"
        print(f"{ts:<23} {EVENT_NAME[r['event']]:>6} {PROTO_NAME[r['proto']]:<5} "
              f"{int2ip(r['inside']):>15} {int2ip(r['public']):>15} {r['pb_start']:>8} "
              f"{r['pb_end']:>7} {sim.routers[r['router']]['ip']:>15}")
    print(f"\n{len(recs)} Events in {a.minutes} min "
          f"(~{len(recs) / a.minutes * 5:.0f} pro 5-Minuten-Datei), aktiv: {len(sim.active)} Blöcke")


def nfcapd_version():
    """(major, minor) aus 'nfcapd -V', z. B. (1, 6) oder (1, 7)."""
    out = subprocess.run(["nfcapd", "-V"], capture_output=True, text=True)
    text = out.stdout + out.stderr
    m = re.search(r"Version:\D*(\d+)\.(\d+)", text)   # auch "Version: NSEL-NEL1.6.22"
    if not m:
        raise SystemExit(f"nfcapd-Version nicht erkennbar:\n{text}")
    return int(m.group(1)), int(m.group(2))


def nfcapd_cmd(version, flowdir, port):
    """Aufruf für eine temporäre nfcapd-Instanz – die Optionen unterscheiden sich je Version."""
    base = ["nfcapd", "-b", "127.0.0.1", "-p", str(port), "-t", "3600"]
    if version >= (1, 7):
        return base + ["-w", flowdir]            # 1.7: -w = Flow-Verzeichnis
    return base + ["-l", flowdir, "-T", "all"]   # 1.6: -l = Verzeichnis, -T all = alle Extensions


def cmd_backfill(a):
    if not shutil.which("nfcapd") or not shutil.which("nfdump"):
        raise SystemExit("nfcapd/nfdump nicht gefunden (apt install nfdump)")
    os.makedirs(a.flowdir, exist_ok=True)
    major_minor = nfcapd_version()
    log.info("nfcapd-Version %d.%d erkannt", *major_minor)

    end = (now_ms() // SLOT_MS) * SLOT_MS          # Beginn des aktuellen Slots (exklusiv)
    start = end - a.hours * 3600_000
    sim = Simulation(make_cfg(a), start - a.warmup * 3600_000)
    for line in describe_routers(sim).splitlines():
        log.info(line)
    sim.step(start - 1)                             # Vorlauf ohne Export: Blöcke sind schon belegt
    exporters = make_exporters(sim, a.format)
    collector = ("127.0.0.1", a.port)

    slots = range(start, end, SLOT_MS)
    total = 0
    t_begin = time.monotonic()
    for n, slot in enumerate(slots, 1):
        name = "nfcapd." + time.strftime("%Y%m%d%H%M", time.localtime(slot / 1000))
        target = os.path.join(a.flowdir, name)
        recs = sim.step(slot + SLOT_MS - 1)
        if os.path.exists(target) and not a.force:
            log.warning("%s existiert – übersprungen (--force zum Überschreiben)", name)
            continue

        tmp = tempfile.mkdtemp(prefix="nelgen-")
        proc = subprocess.Popen(nfcapd_cmd(major_minor, tmp, a.port),
                                stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
        time.sleep(a.settle)
        if proc.poll() is not None:
            raise SystemExit(f"nfcapd beendet sich sofort:\n{proc.stderr.read()}")

        recs.sort(key=lambda r: r["ts"])
        for ex in exporters:
            ex.pkts_since_tpl = TEMPLATE_EVERY_PACKETS      # neue nfcapd-Instanz kennt kein Template
        send_by_router(recs, exporters, collector, force_template=True, pace=0.0005)

        time.sleep(a.settle)
        proc.send_signal(signal.SIGTERM)
        try:
            proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            proc.kill()
            raise SystemExit("nfcapd reagiert nicht auf SIGTERM")

        files = sorted(os.path.basename(f) for f in glob.glob(os.path.join(tmp, "nfcapd.[0-9]*")))
        if not files:
            raise SystemExit(f"nfcapd hat in {tmp} keine Datei geschrieben")
        if len(files) == 1:
            shutil.move(os.path.join(tmp, files[0]), target)
        else:   # Rotation während des Laufs -> zusammenführen
            subprocess.run(["nfdump", "-R", f"{files[0]}:{files[-1]}", "-w", target],
                           cwd=tmp, check=True, stdout=subprocess.DEVNULL)
        shutil.rmtree(tmp, ignore_errors=True)

        total += len(recs)
        elapsed = time.monotonic() - t_begin
        eta = elapsed / n * (len(slots) - n)
        log.info("[%d/%d] %s  %5d Events  (aktiv: %d, Rest ca. %d min)",
                 n, len(slots), name, len(recs), len(sim.active), eta // 60)

    save_state(sim, a.state, end)
    log.info("Fertig: %d Events in %d Dateien, State -> %s", total, len(slots), a.state)


def cmd_live(a):
    sim = load_state(a.state)
    if sim is None:
        sim = Simulation(make_cfg(a), now_ms())
        log.info("Neuer Simulationszustand (%d Kunden, %d Router)", len(sim.subs), len(sim.routers))
    else:
        gap = now_ms() - sim.saved_at
        if gap > 0:
            sim.shift(gap)
        log.info("State geladen (%d aktive Blöcke), Zeitplan um %.0f s verschoben",
                 len(sim.active), gap / 1000)

    exporters = make_exporters(sim, a.format)
    collector = parse_collector(a.collector)
    log.info("Sende %s an %s:%d von %d Routern (%s … %s)", a.format, *collector,
             len(sim.routers), sim.routers[0]["ip"], sim.routers[-1]["ip"])

    stop = {"flag": False}

    def _stop(signum, _frame):
        stop["flag"] = True
    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)

    last_save = time.monotonic()
    sent = 0
    while not stop["flag"]:
        recs = sim.step(now_ms())
        if recs:
            send_by_router(recs, exporters, collector)
            sent += len(recs)
        if time.monotonic() - last_save > 60:
            save_state(sim, a.state, now_ms())
            last_save = time.monotonic()
            log.info("%d Events gesendet, %d Blöcke aktiv", sent, len(sim.active))
        nxt = sim.next_event_ms()
        wait = 1.0 if nxt is None else (nxt - now_ms()) / 1000
        time.sleep(min(1.0, max(0.05, wait)))

    save_state(sim, a.state, now_ms())
    log.info("Beendet, State gespeichert (%d Blöcke aktiv)", len(sim.active))


# --------------------------------------------------------------------------- CLI

class ArgParser(argparse.ArgumentParser):
    """Argumentdatei (@datei): ein Argument pro Zeile, Leerzeilen und #-Kommentare erlaubt."""

    def convert_arg_line_to_args(self, arg_line):
        line = arg_line.strip()
        if not line or line.startswith("#"):
            return []
        return [line]


def csv_list(s):
    return [x.strip() for x in s.split(",") if x.strip()]


def main():
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--routers", type=csv_list, default=["127.0.0.1"],
                        help="Quell-IPs der simulierten CGN-Router, kommagetrennt (müssen lokal sein)")
    common.add_argument("--subscribers", type=int, default=1000)
    common.add_argument("--pools", type=csv_list, default=["203.0.113.0/24"],
                        help="öffentliche NAT-Netze, kommagetrennt; Router i nutzt Netz i %% Anzahl")
    common.add_argument("--pool-size", type=int, default=32,
                        help="Anzahl genutzter öffentlicher IPs pro Router")
    common.add_argument("--block-sizes", type=lambda s: [int(x) for x in csv_list(s)],
                        default=[2048, 1024], help="Port-Blockgröße je Router (zyklisch)")
    common.add_argument("--port-min", type=int, default=1024)
    common.add_argument("--seed", type=int, default=42)
    common.add_argument("--format", choices=["v9", "ipfix"], default="v9")
    common.add_argument("--state", default="/var/lib/nelgen/state.pkl")
    common.add_argument("-v", "--verbose", action="store_true")

    p = ArgParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter,
                  fromfile_prefix_chars="@")
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("print", parents=[common], help="Events als Tabelle ausgeben")
    sp.add_argument("--minutes", type=int, default=5)
    sp.add_argument("--limit", type=int, default=30)
    sp.set_defaults(func=cmd_print)

    sb = sub.add_parser("backfill", parents=[common], help="historische nfcapd-Dateien erzeugen")
    sb.add_argument("--hours", type=int, default=24)
    sb.add_argument("--warmup", type=int, default=12, help="Vorlauf in Stunden (ohne Export)")
    sb.add_argument("--flowdir", default="/var/cache/nfdump")
    sb.add_argument("--port", type=int, default=9996, help="Port der temporären nfcapd-Instanz")
    sb.add_argument("--settle", type=float, default=0.4, help="Wartezeit um nfcapd-Start/-Stopp (s)")
    sb.add_argument("--force", action="store_true", help="vorhandene Dateien überschreiben")
    sb.set_defaults(func=cmd_backfill)

    sl = sub.add_parser("live", parents=[common], help="Echtzeit-Export an nfcapd")
    sl.add_argument("--collector", default="127.0.0.1:2055")
    sl.set_defaults(func=cmd_live)

    a = p.parse_args()
    logging.basicConfig(level=logging.DEBUG if a.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")
    a.func(a)


if __name__ == "__main__":
    main()
