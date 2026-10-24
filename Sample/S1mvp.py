"""
mini_lanscan.py — LanScan-style discovery MVP
Threaded ARP (scapy) or ping-sweep discovery + live CustomTkinter table.

Install:
    pip install customtkinter scapy

Run (ARP mode needs raw sockets):
    Windows:  run as administrator
    Linux:    sudo python mini_lanscan.py
    macOS:    sudo python mini_lanscan.py

If raw sockets aren't available it automatically falls back to a ping sweep
and joins MACs from the OS ARP cache.
"""
from __future__ import annotations

import csv
import ipaddress
import json
import os
import platform
import queue
import re
import shlex
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, replace
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from tkinter import font as tkfont
from tkinter import Menu as tkMenu

import customtkinter as ctk

# ---------------------------------------------------------------------------
# Knowledge tables
# ---------------------------------------------------------------------------

APP_VERSION = "0.3.4"

# Changelog shown in Help → Release Notes. Newest first.
RELEASES: list[dict[str, object]] = [
    {
        "version": "0.3.4",
        "date": "2026-10-24",
        "added": ["Help → Scan diagnostics: which tools the app can find, what "
                  "the neighbour-table reads return, and what the last scan "
                  "collected — made to be copied into a bug report"],
        "fixed": ["MAC addresses and vendor names are back on macOS 27. It stops "
                  "handing link-layer addresses to any process that isn't an "
                  "Apple platform binary, and child processes inherit that, so "
                  "`arp -an` run by the app returns nothing at all. The "
                  "neighbour table is now read through a job handed to launchd, "
                  "which still can — unprivileged, once per sweep, and only "
                  "when the direct read is blocked"],
    },
    {
        "version": "0.3.3",
        "date": "2026-10-24",
        "added": ["MAC resolution from Bonjour TXT records (AirPlay/RAOP "
                  "`deviceid`), and IPv6 resolution by Bonjour hostname — both "
                  "for hosts the OS neighbour table doesn't cover",
                  "A status message when the OS withholds the ARP/neighbour "
                  "table from the app, instead of silently blank MAC/vendor"],
        "fixed": ["IPv6 was missing for most hosts on recent macOS: `ndp -an` no "
                  "longer suffixes global entries with the interface name, and "
                  "the parser skipped every row without one",
                  "The OS placeholder 02:00:00:00:00:00 is no longer shown as a "
                  "host's MAC (it also produced a bogus 'Private MAC "
                  "(randomized)' vendor)",
                  "ARP table now read with `arp -an` — no per-entry reverse DNS, "
                  "so the join no longer stalls right after a sweep"],
    },
    {
        "version": "0.3.2",
        "date": "2026-10-23",
        "added": ["macOS release pipeline now supports Developer ID signing and "
                  "Apple notarization (enabled once Apple credentials are "
                  "configured); current builds remain ad-hoc signed and need "
                  "the one-time Gatekeeper approval described in the README"],
        "fixed": [],
    },
    {
        "version": "0.3.1",
        "date": "2026-09-11",
        "added": ["First-launch instructions for macOS Sequoia (15+): Apple "
                  "removed the Control-click → Open bypass, so the app now "
                  "documents System Settings → Privacy & Security → Open Anyway"],
        "fixed": ["macOS DMG now ships only MyLanScan.app — PyInstaller's extra "
                  "on-dir folder no longer appears on the mounted volume"],
    },
    {
        "version": "0.3.0",
        "date": "2026-08-26",
        "added": ["Linux support (x86_64 + arm64): discovery via iproute2/ip "
                  "neigh, IPv6 via ping -6, OS detection elevation via "
                  "pkexec, nmap from /usr/bin"],
        "fixed": [],
    },
    {
        "version": "0.2.7",
        "date": "2026-08-22",
        "fixed": ["Type column no longer truncated at the default window size — "
                  "column defaults now fit, auto-fit is capped, and the "
                  "horizontal scrollbar only appears when content really "
                  "overflows"],
        "added": [],
    },
    {
        "version": "0.2.6",
        "date": "2026-08-22",
        "added": ["Export results from the Port-scan dialog (CSV) and the "
                  "Deep-scan dialog (full nmap report as text)"],
        "fixed": [],
    },
    {
        "version": "0.2.5",
        "date": "2026-08-22",
        "added": ["Randomized 'Private Wi-Fi' MACs (iOS/Android) are now flagged "
                  "as 'Private MAC (randomized)' instead of showing an empty "
                  "or wrong vendor"],
        "fixed": [],
    },
    {
        "version": "0.2.4",
        "date": "2026-08-22",
        "added": ["Bonjour/mDNS discovery: Apple devices that ignore ping "
                  "(stealth mode) now appear as their own rows",
                  "Device type inferred from announcing service "
                  "(AirPlay, HomeKit, iPhone/iPad, printer, …)",
                  "MAC resolution for Bonjour-only hosts via ARP poke"],
        "fixed": [],
    },
    {
        "version": "0.2.3",
        "date": "2026-08-22",
        "added": ["OS detection in deep scan now prompts for admin via the macOS "
                  "password dialog (no need to run the app as root)",
                  "Deep-scan dialog no longer greys out OS detection for "
                  "unprivileged users"],
        "fixed": [],
    },
    {
        "version": "0.2.2",
        "date": "2026-08-22",
        "added": ["Deep scan (nmap) per device: service versions, default NSE "
                  "scripts, optional OS detection when run as root",
                  "Live nmap report streamed into its own dialog"],
        "fixed": [],
    },
    {
        "version": "0.2.1",
        "date": "2026-08-22",
        "added": ["Release Notes dialog (Help menu)", "Deduped macOS Help menu items"],
        "fixed": [],
    },
    {
        "version": "0.2.0",
        "date": "2026-08-22",
        "added": ["Native macOS menu bar: Help menu + About MyLanScan",
                  "Custom app icon and DMG volume icon",
                  "App version stamped into Info.plist"],
        "fixed": [],
    },
    {
        "version": "0.1.0",
        "date": "2026-08-21",
        "added": ["ARP + ping sweep host discovery",
                  "DNS + mDNS/Bonjour names, IPv6 addresses",
                  "Vendor lookup from full IEEE OUI table",
                  "Per-host port scanning (quick ~100 ports / full 1–65535)",
                  "Sortable, resizeable columns + CSV export",
                  "In-app help and MIT license"],
        "fixed": [],
    },
]

# Small built-in OUI subset — curated short names, kept as fallback and to
# override IEEE's long legal names for common vendors. Full table: run
# `venv/bin/python Sample/fetch_oui.py` once (creates Sample/oui.json,
# ~40k entries from standards-oui.ieee.org); it is loaded automatically.
BUILTIN_OUI_VENDORS = {
    "3C:5A:B4": "Apple",
    "F0:18:98": "Apple",
    "B8:27:EB": "Raspberry Pi",
    "DC:A6:32": "Raspberry Pi",
    "24:0A:C4": "Espressif Systems",
    "2C:3A:E8": "Espressif Systems",
    "A0:20:A0": "Espressif Systems",
    "50:C7:FF": "TP-Link",
    "14:CC:20": "TP-Link",
    "00:E0:4C": "Realtek",
    "44:65:0D": "Amazon",
    "F4:42:83": "Google",
    "3C:A9:F4": "Google",
    "00:50:56": "VMware",
    "00:15:5D": "Microsoft (Hyper-V)",
    "52:54:00": "QEMU / KVM",
    "00:1C:42": "Parallels",
    "68:05:CA": "Intel",
    "4C:72:BA": "Intel",
    "00:1B:21": "Intel",
}

def _load_oui_table() -> dict[str, str]:
    """Full IEEE OUI table from oui.json (see fetch_oui.py).
    In a PyInstaller bundle the data file lives under sys._MEIPASS."""
    meipass = getattr(sys, "_MEIPASS", None)
    base = Path(meipass) if meipass else Path(__file__).resolve().parent
    path = base / "oui.json"
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


OUI_VENDORS = {**_load_oui_table(), **BUILTIN_OUI_VENDORS}


def _norm_mac(raw: str) -> str:
    """Normalize 'aa-bb-cc-dd-ee-ff' / 'aa:bb:...' to 'AA:BB:CC:DD:EE:FF'.
    Handles macOS's zero-stripped form ('e0:98:6:da:33:3f') by padding groups."""
    raw = (raw or "").strip()
    if not raw:
        return ""
    parts = re.split(r"[:\-]", raw)
    if len(parts) == 6 and all(re.fullmatch(r"[0-9a-fA-F]{1,2}", p) for p in parts):
        return ":".join(p.zfill(2) for p in parts).upper()
    hexd = re.sub(r"[^0-9a-fA-F]", "", raw)
    if len(hexd) == 12:
        return ":".join(hexd[i:i + 2] for i in range(0, 12, 2)).upper()
    return ""


def _is_placeholder_mac(mac: str) -> bool:
    """True when the OS handed us a not-a-real-address stand-in rather than a
    hardware address: '02:00:00:00:00:00' (what a restricted process sees from
    `ifconfig`/`arp`/`ndp`) or an all-zero value. Such a MAC has no vendor and
    must never reach the table as if it were real."""
    if not mac:
        return True
    norm = _norm_mac(mac)          # also accepts '2:0:0:0:0:0' and 'aa-bb-..'
    if not norm:
        return True
    return norm == "02:00:00:00:00:00" or not norm.replace(":", "").strip("0")


def _mac_from_mdns(props: dict, service_name: str = "") -> str:
    """Hardware MAC advertised in a Bonjour TXT record, if any.

    AirPlay (_airplay) and RAOP (_raop) devices publish it as `deviceid`, and
    RAOP instance names start with 'AABBCCDDEEFF@'. Independent of the ARP
    cache, so it also covers hosts the neighbour table won't tell us about."""
    for key in ("deviceid", "mac", "macaddress", "hwaddr", "device_id"):
        raw = props.get(key)
        if raw is None:
            continue
        if isinstance(raw, bytes):
            raw = raw.decode("ascii", "ignore")
        mac = _norm_mac(str(raw))
        if mac and not _is_placeholder_mac(mac):
            return mac
    m = re.match(r"^([0-9A-Fa-f]{12})@", service_name or "")
    if m:
        h = m.group(1)
        mac = _norm_mac(":".join(h[i:i + 2] for i in range(0, 12, 2)))
        if not _is_placeholder_mac(mac):
            return mac
    return ""


def _parse_ndp(text: str) -> list[tuple[str, str]]:
    """Parse `ndp -an` into [(ipv6, mac), ...].

    Two column layouts exist: link-local neighbours read
    'fe80::222b:20ff:fe88:c83%en0  20:2b:20:88:c:83  en0  ...', while recent
    macOS lists a global neighbour with no '%iface' suffix and the interface in
    its own column ('2a02:...:a7  38:f7:cd:d3:cc:7f  en0  17h ...'). Both are
    accepted here; the old '%'-only check silently dropped every global entry.
    An incomplete or placeholder ('2:0:0:0:0:0') address comes back as ''."""
    rows: list[tuple[str, str]] = []
    for line in (text or "").splitlines():
        f = line.split()
        if len(f) < 2 or f[0] in ("Neighbor", "Neighbour"):
            continue
        addr = f[0].split("%")[0]
        try:
            v6 = ipaddress.IPv6Address(addr).exploded
        except ValueError:
            continue
        mac = ""
        if f[1] != "(incomplete)":
            mac = _norm_mac(f[1])
            if _is_placeholder_mac(mac):
                mac = ""
        rows.append((v6, mac))
    return rows


def _parse_arp(text: str) -> dict[str, str]:
    """ip -> MAC from `arp -an` output.

    BSD/macOS:  ? (192.168.1.5) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]
    Windows:    192.168.1.1   00-11-22-33-44-55   dynamic
    macOS drops leading zeros in octets, so groups are 1-2 digits; entries still
    resolving ('(incomplete)') simply don't match. Placeholder rows are dropped."""
    out: dict[str, str] = {}
    for m in re.finditer(r"\((\d{1,3}(?:\.\d{1,3}){3})\)\s+at\s+"
                         r"([0-9a-fA-F]{1,2}(?::[0-9a-fA-F]{1,2}){5})", text or ""):
        mac = _norm_mac(m.group(2))
        if mac and not _is_placeholder_mac(mac):
            out[m.group(1)] = mac
    if not out:
        for m in re.finditer(
                r"(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9a-fA-F]{2}(?:[-:][0-9a-fA-F]{2}){5})",
                text or ""):
            mac = _norm_mac(m.group(2))
            if mac and not _is_placeholder_mac(mac):
                out[m.group(1)] = mac
    return out


def _ndp_by_mac(rows: list[tuple[str, str]]) -> dict[str, str]:
    """MAC -> IPv6, preferring a global address over the link-local one."""
    out: dict[str, str] = {}
    for v6, mac in rows:
        if not mac or not v6:
            continue
        cur = out.get(mac)
        if cur is None or (cur.startswith("fe80") and not v6.lower().startswith("fe80")):
            out[mac] = v6
    return out


# ---------------------------------------------------------------------------
# Neighbour table through a launchd helper (macOS 27)
#
# macOS 27 stops handing link-layer addresses to any process that isn't an Apple
# platform binary, and children inherit that: `arp -an` and `ndp -an` started by
# MyLanScan come back empty (`arp`) or as 02:00:00:00:00:00 (`ndp`) — whatever
# the app is signed with, and even when it is started from Terminal. A job handed
# to launchd is spawned by launchd instead, so the same Apple tool runs
# unrestricted and we read the file it writes. Unprivileged, macOS only; when the
# direct read works (older macOS) this never runs.
# ---------------------------------------------------------------------------

_HELPER_LOCK = threading.Lock()
_HELPER_CACHE: dict[str, tuple[float, dict]] = {}
_HELPER_TTL = 2.5            # one launchd round-trip per sweep, not one per host
_HELPER_USED: set[str] = set()   # which tables had to go through the helper


def _helper_output(command: str) -> str:
    """stdout of `command` (an Apple tool such as '/usr/sbin/arp -an') run via
    launchd, or '' if that isn't possible. Never prompts, never elevates."""
    if sys.platform != "darwin":
        return ""
    fd, path = tempfile.mkstemp(prefix="mylanscan_neigh_", suffix=".txt")
    os.close(fd)
    label = f"com.mylanscan.neigh.{os.getpid()}.{int(time.time() * 1000) % 1000000}"
    try:
        subprocess.run(["/bin/launchctl", "submit", "-l", label, "--", "/bin/sh",
                        "-c", f"{command} > {shlex.quote(path)} 2>/dev/null"],
                       capture_output=True, text=True, timeout=5)
        deadline = time.time() + 3.0
        while time.time() < deadline:
            try:
                text = Path(path).read_text(encoding="utf-8", errors="replace")
            except OSError:
                text = ""
            if text.strip():
                return text
            time.sleep(0.1)
        return ""
    except Exception:
        return ""
    finally:
        try:
            subprocess.run(["/bin/launchctl", "remove", label],
                           capture_output=True, timeout=5)
        except Exception:
            pass
        try:
            os.unlink(path)
        except OSError:
            pass


def _helper_table(command: str, parse):
    """Parsed helper output, cached for _HELPER_TTL seconds. The ARP join runs
    once per host right after its ping, and none of those may start a job."""
    with _HELPER_LOCK:                      # one helper run at a time
        at, table = _HELPER_CACHE.get(command, (0.0, {}))
        if table and time.time() - at < _HELPER_TTL:
            return table
        table = parse(_helper_output(command)) or {}
        if table:
            _HELPER_CACHE[command] = (time.time(), table)
    return table


def _helper_arp_table() -> dict[str, str]:
    table = _helper_table("/usr/sbin/arp -an", _parse_arp)
    if table:
        _HELPER_USED.add("arp")
    return table


def _helper_ndp_table() -> dict[str, str]:
    table = _helper_table("/usr/sbin/ndp -an", lambda t: _ndp_by_mac(_parse_ndp(t)))
    if table:
        _HELPER_USED.add("ndp")
    return table


def vendor_for(mac: str) -> str:
    if not mac or _is_placeholder_mac(mac):
        return ""
    # Locally-administered bit (second-least-significant bit of octet 1): set
    # on randomized "private Wi-Fi" MACs (iOS/Android) whose OUI is fake and
    # would otherwise mis-attribute a vendor — flag them instead of guessing.
    if int(mac.split(":")[0], 16) & 0x02:
        return "Private MAC (randomized)"
    return OUI_VENDORS.get(mac[:8], "")


# Keyword rules — IEEE org names are long legal strings ("Raspberry Pi
# Trading Ltd"), so match substrings instead of exact names.
KIND_RULES = (
    ("raspberry", "SBC / maker"),
    ("espressif", "IoT / ESP32"),
    ("apple", "Apple device"),
    ("google", "Google / Chromecast"),
    ("amazon", "Fire TV / Echo"),
    ("tp-link", "Router / AP"),
    ("samsung", "Samsung device"),
    ("vmware", "Virtual machine"),
    ("parallels", "Virtual machine"),
    ("qemu", "Virtual machine"),
    ("sky ", "Router / AP"),
    ("intel", "PC / NIC"),
)


def kind_for(mac: str) -> str:
    if not mac:
        return "Unknown"
    vendor = vendor_for(mac).lower()
    for kw, kind in KIND_RULES:
        if kw in vendor:
            return kind
    return "Other"


def ip_sort_key(ip: str):
    try:
        return tuple(int(x) for x in ip.split("."))
    except ValueError:
        return (999, 999, 999, 999)


MDNS_TYPES = (
    "_device-info._tcp.local.",   # Macs, iPhones, iPads
    "_airplay._tcp.local.",       # Apple TV / AirPlay receivers
    "_raop._tcp.local.",          # AirPlay audio
    "_googlecast._tcp.local.",    # Chromecast / Nest
    "_smb._tcp.local.",           # file sharing (Macs, NAS)
    "_ipp._tcp.local.",           # printers
    "_http._tcp.local.",          # web UIs / IoT
    "_hap._tcp.local.",           # HomeKit
    "_esphomelib._tcp.local.",    # ESPHome nodes
    "_companion-link._tcp.local.",  # iPhone/iPad/Mac Continuity
    "_touch-able._tcp.local.",      # iOS device presence
    "_airport._tcp.local.",         # AirPort / Time Capsule
    "_mediaremotetv._tcp.local.",   # Apple TV remote
    "_apple-mobdev2._tcp.local.",   # iPhones/iPads (USB-ish, LAN)
    "_sleep-proxy._udp.local.",     # Bonjour sleep proxy (Apple TV/Mac)
    "_ssh._tcp.local.",             # SSH hosts
)

# Friendly "Type" for mDNS-found devices, keyed by service type substring.
SVC_KIND = (
    ("_airplay", "AirPlay"),
    ("_raop", "AirPlay audio"),
    ("_hap", "HomeKit"),
    ("_companion-link", "iPhone/iPad"),
    ("_touch-able", "iPhone/iPad"),
    ("_apple-mobdev", "iPhone/iPad"),
    ("_device-info", "Apple device"),
    ("_airport", "AirPort / Time Capsule"),
    ("_mediaremotetv", "Apple TV"),
    ("_sleep-proxy", "Apple sleep proxy"),
    ("_googlecast", "Chromecast"),
    ("_ipp", "Printer"),
    ("_smb", "File share"),
    ("_ssh", "SSH host"),
    ("_http", "Web device"),
    ("_esphomelib", "IoT / ESPHome"),
)


def kind_from_service(service: str) -> str:
    if not service:
        return ""
    for kw, kind in SVC_KIND:
        if kw in service:
            return kind
    return "mDNS device"


@dataclass
class MdnsInfo:
    """What one Bonjour announcement tells us about a host."""
    ip: str = ""
    host: str = ""
    service: str = ""
    ipv6: str = ""
    mac: str = ""


def mdns_discover(browse_secs: float = 3.5) -> dict[str, MdnsInfo]:
    """ip -> MdnsInfo, via zeroconf browse of common types.

    Unprivileged; returns {} if zeroconf isn't installed. First-seen service
    type wins so Type stays stable per host. A second MAC source besides the
    ARP cache: AirPlay/RAOP devices publish their hardware address in the TXT
    record, which also covers hosts whose MAC arp/ndp won't reveal."""
    try:
        from zeroconf import Zeroconf, ServiceBrowser
    except ImportError:
        return {}
    found: dict[str, MdnsInfo] = {}

    class L:
        def add_service(self, zc, type_, name):
            try:
                info = zc.get_service_info(type_, name, timeout=600)
            except Exception:
                return
            if not info:
                return
            ip4 = ip6 = ""
            for packed in info.addresses or []:
                try:
                    if len(packed) == 4:
                        a = socket.inet_ntop(socket.AF_INET, packed)
                        if not a.startswith("127."):
                            ip4 = ip4 or a
                    elif len(packed) == 16:
                        a = socket.inet_ntop(socket.AF_INET6, packed)
                        low = a.lower()
                        if low.startswith("::ffff:") and "." in a:
                            v4 = a.rsplit(":", 1)[-1]
                            if not v4.startswith("127."):
                                ip4 = ip4 or v4
                        elif low in ("::1", "::"):
                            continue
                        elif low.startswith("fe80"):
                            ip6 = ip6 or a
                        else:
                            ip6 = a          # prefer a global/ULA address
                except (OSError, ValueError):
                    pass
            ip = ip4 or ip6
            if not ip or ip in found:
                return
            host = (info.server or name.split(".")[0]).strip(".")
            if host.endswith(".local"):
                host = host[:-len(".local")]
            props = {}
            for k, v in (info.properties or {}).items():
                if isinstance(k, bytes):
                    k = k.decode("ascii", "ignore")
                if isinstance(v, bytes):
                    v = v.decode("ascii", "ignore")
                props[str(k)] = v
            found[ip] = MdnsInfo(ip=ip, host=host, service=type_,
                                 ipv6=ip6, mac=_mac_from_mdns(props, name))

        def update_service(self, *a):
            pass

    zc = None
    try:
        zc = Zeroconf()
        listener = L()
        browsers = [ServiceBrowser(zc, t, listener) for t in MDNS_TYPES]
        time.sleep(browse_secs)
    except Exception:
        pass
    finally:
        try:
            if zc:
                zc.close()
        except Exception:
            pass
    return found


# ---------------------------------------------------------------------------
# Scanner (worker thread) — UI never blocks
# ---------------------------------------------------------------------------

@dataclass
class Device:
    ip: str
    name: str = ""
    ipv6: str = ""
    mac: str = ""
    vendor: str = ""
    kind: str = ""
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    key_id: str = ""   # stable identity, frozen at creation (MAC if known, else IP)
    _enriched: bool = False

    @property
    def key(self) -> str:
        # Dedupe by MAC (stable across DHCP); fall back to IP
        return self.key_id or self.mac or self.ip


class Scanner(threading.Thread):
    """Runs discovery in the background, pushing events onto a queue:
       ("device", Device) | ("status", str) | ("done", int)
    """

    def __init__(self, network: ipaddress.IPv4Network, q: queue.Queue,
                 mode: str = "auto", workers: int = 100, timeout: float = 0.6):
        super().__init__(daemon=True, name="scanner")
        self.network = network
        self.q = q
        self.mode = mode            # "auto" | "arp" | "ping"
        self.workers = workers
        self.timeout = timeout
        self.stop_event = threading.Event()
        self.lock = threading.Lock()
        self.devices: dict[str, Device] = {}
        self.mdns_info: dict[str, MdnsInfo] = {}

    def stop(self):
        self.stop_event.set()

    # ---------------- entry point ----------------
    def run(self):
        hosts = [str(ip) for ip in self.network.hosts()]
        started = time.time()
        self.q.put(("status", f"Scanning {len(hosts)} hosts in {self.network} …"))
        try:
            if self.mode in ("auto", "arp") and self._have_scapy() and self._arp_ok():
                self._scan_arp(hosts)
            else:
                if self.mode == "arp":
                    self.q.put(("status", "ARP unavailable (no scapy / no raw sockets) — using ping sweep."))
                self._scan_ping(hosts)
            self._scan_mdns()
            self._enrich_names()
            self._scan_ipv6()
            if _HELPER_USED:
                self.q.put(("status", "MAC/IPv6 read through a system helper — "
                                      "macOS 27 doesn't give them to apps directly."))
        except Exception as e:  # never let the worker die silently
            self.q.put(("status", f"Scan failed: {e!r}"))
        finally:
            with self.lock:
                n = len(self.devices)
            self.q.put(("done", n))
            self.q.put(("status", f"Finished in {time.time() - started:.1f}s — {n} device(s)."))

    # ---------------- capability checks ----------------
    @staticmethod
    def _have_scapy() -> bool:
        try:
            import scapy.all  # noqa: F401
            return True
        except ImportError:
            return False

    @staticmethod
    def _arp_ok() -> bool:
        """Can we craft/send ARP packets? (root on macOS/Linux, admin on Windows)."""
        try:
            if platform.system() == "Windows":
                s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
                s.close()
                return True
            # scapy sends via BPF/libpcap on macOS (AF_PACKET is Linux-only),
            # and both require root — so root is the real gate here.
            return os.geteuid() == 0
        except Exception:
            return False

    # ---------------- ARP mode ----------------
    def _scan_arp(self, hosts):
        from scapy.all import ARP, Ether, sr1

        def probe(ip: str):
            if self.stop_event.is_set():
                return
            pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, pdst=ip)
            try:
                # NOTE: fine for MVP-scale LANs. For max throughput, use one
                # thread doing sendp() batches + sniff() instead of per-packet
                # sr1() from many threads.
                resp = sr1(pkt, timeout=self.timeout, retry=0, verbose=0)
            except Exception:
                return
            if resp is not None and resp.haslayer(ARP) and resp[ARP].hwsrc:
                self._record(ip, _norm_mac(resp[ARP].hwsrc))

        self._run_pool(hosts, probe)

    # ---------------- Ping-sweep mode (no raw sockets needed) ----------------
    def _scan_ping(self, hosts):
        system = platform.system()

        def probe(ip: str):
            if self.stop_event.is_set():
                return
            if system == "Windows":
                cmd = ["ping", "-n", "1", "-w", "500", ip]
            elif sys.platform == "darwin":
                cmd = ["ping", "-c", "1", "-t", "1", ip]
            else:
                cmd = ["ping", "-c", "1", "-W", "1", ip]
            try:
                ok = subprocess.run(cmd, stdout=subprocess.DEVNULL,
                                    stderr=subprocess.DEVNULL, timeout=2).returncode == 0
            except Exception:
                ok = False
            if ok:
                # Read this host's ARP entry NOW — quiet IoT hosts' kernel
                # entries expire within seconds, long before end-of-sweep.
                self._record(ip, self._arp_for(ip))

        self._run_pool(hosts, probe)

        # One-shot MAC join from the OS ARP cache (all pingers populated it).
        # NOTE: right after a sweep the kernel table is still churning and
        # `arp -an` can exceed its subprocess timeout — retry once after settling.
        table = self._arp_table()
        if not table:
            time.sleep(1.5)
            table = self._arp_table()
        if not table:
            hint = (" — macOS doesn't hand the neighbour table to this process, "
                    "so MAC/vendor stay blank" if sys.platform == "darwin" else "")
            self.q.put(("status", f"No ARP entries available{hint} "
                                  "(see Help → Scan diagnostics)."))
            return
        with self.lock:
            updated = []
            for d in self.devices.values():
                mac = table.get(d.ip)
                if mac and not d.mac:
                    d.mac, d.vendor, d.kind = mac, vendor_for(mac), kind_for(mac)
                    d._enriched = True
                    updated.append(replace(d))
        for d in updated:
            self.q.put(("device", d))

    # ---------------- name resolution (DNS fallback + stored mDNS) ----------------
    def _enrich_names(self):
        """Attach remaining names to discovered devices. mDNS results were
        already merged by _scan_mdns; this only adds DNS PTR lookups."""
        if self.stop_event.is_set():
            return
        self.q.put(("status", "Resolving remaining DNS names …"))
        mdns = self.mdns_info

        def rdns(ip: str) -> str:
            try:
                return socket.gethostbyaddr(ip)[0].rstrip(".")
            except Exception:
                return ""

        with self.lock:
            ips = [d.ip for d in self.devices.values() if not d.name]
        ptr: dict[str, str] = {}
        if ips:
            with ThreadPoolExecutor(max_workers=32, thread_name_prefix="rdns") as pool:
                futs = {pool.submit(rdns, ip): ip for ip in ips}
                for f in as_completed(futs):
                    ptr[futs[f]] = f.result()

        with self.lock:
            updated = []
            for d in self.devices.values():
                info = mdns.get(d.ip)
                name = (info.host if info else "") or ptr.get(d.ip) or ""
                if name.lower() == "unknown":   # macOS resolver junk for unresolvable IPs
                    name = ""
                if name and not d.name:
                    d.name = name
                    updated.append(replace(d))
        for d in updated:
            self.q.put(("device", d))

    # ---------------- IPv6 (link-local discovery + NDP join) ----------------
    @staticmethod
    def _default_iface() -> str:
        if sys.platform.startswith("linux"):
            try:
                out = subprocess.run(["ip", "route", "show", "default"],
                                     capture_output=True, text=True, timeout=3).stdout
                # e.g. "default via 192.168.1.1 dev enp0s3 proto dhcp metric 100"
                m = re.search(r"dev\s+(\S+)", out)
                return m.group(1) if m else ""
            except Exception:
                return ""
        try:
            out = subprocess.run(["route", "-n", "get", "default"],
                                 capture_output=True, text=True, timeout=3).stdout
            m = re.search(r"interface:\s+(\S+)", out)
            return m.group(1) if m else ""
        except Exception:
            return ""

    @staticmethod
    def _ndp_table() -> dict[str, str]:
        """MAC -> IPv6 (global preferred over link-local), from the OS neighbour
        table. NOTE: macOS needs `ndp -an` (plain `ndp -a` hangs resolving names);
        see _parse_ndp for the two column layouts it emits. Falls back to the
        launchd helper when the direct read comes back stripped, and returns {}
        if neither works."""
        out: dict[str, str] = {}
        if sys.platform.startswith("linux"):
            try:
                text = subprocess.run(["ip", "-6", "neigh", "show"],
                                      capture_output=True, text=True,
                                      timeout=5).stdout
            except Exception:
                return out
            # e.g. "fe80::abcd:1234 dev enp0s3 lladdr aa:bb:cc:dd:ee:ff STALE"
            rows: list[tuple[str, str]] = []
            for line in text.splitlines():
                f = line.split()
                if len(f) < 2 or "lladdr" not in f or f[0] == "fe80::1%":
                    continue
                try:
                    v6 = ipaddress.IPv6Address(f[0].split("%")[0]).exploded
                except ValueError:
                    continue
                mac = ""
                for i, tok in enumerate(f):
                    if tok == "lladdr" and i + 1 < len(f):
                        mac = _norm_mac(f[i + 1])
                if not mac or _is_placeholder_mac(mac):
                    continue
                rows.append((v6, mac))
            return _ndp_by_mac(rows)
        try:
            text = subprocess.run(["ndp", "-an"], capture_output=True,
                                  text=True, timeout=5).stdout
        except Exception:
            text = ""
        out = _ndp_by_mac(_parse_ndp(text))
        if not out and sys.platform == "darwin":
            out = _helper_ndp_table()
        return out

    def _scan_ipv6(self):
        """Attach an IPv6 address to every device that doesn't have one yet.

        Multicast-ping ff02::1 first so quiet v6 hosts populate the neighbour
        table, then match it to devices by MAC. MACs aren't always available
        (see _arp_table), so hosts we know a Bonjour name for are resolved
        through the OS resolver as well."""
        if self.stop_event.is_set():
            return
        iface = self._default_iface()
        if iface:
            self.q.put(("status", f"Probing IPv6 neighbors on {iface} …"))
            if sys.platform.startswith("linux"):
                cmd = ["ping", "-6", "-I", iface, "-c", "3", "-i", "0.3", "ff02::1"]
            else:
                cmd = ["ping6", "-n", "-c", "3", "-i", "0.3", f"ff02::1%{iface}"]
            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
            try:
                out, _ = proc.communicate(timeout=4.0)
            except subprocess.TimeoutExpired:
                proc.kill()          # macOS multicast ping6 never exits on its own
                out, _ = proc.communicate()
        ndp = self._ndp_table()

        with self.lock:
            targets = [(d.ip, d.mac, d.name) for d in self.devices.values()
                       if not d.ipv6]
        found: dict[str, str] = {}
        named: list[tuple[str, str]] = []
        for ip, mac, name in targets:
            v6 = ndp.get(mac, "") if mac else ""
            if v6:
                found[ip] = v6
            elif name:
                named.append((ip, name))

        # The neighbour table only helps when we know the MAC. For hosts we have
        # a Bonjour name for, ask the OS resolver for the AAAA record instead.
        # One short-lived subprocess per host, so keep it bounded and off the
        # lock — device updates must keep flowing while this runs.
        if named and sys.platform == "darwin":
            batch = named[:48]
            self.q.put(("status", f"Resolving IPv6 via Bonjour for {len(batch)} host(s) …"))
            with ThreadPoolExecutor(max_workers=8, thread_name_prefix="v6") as pool:
                futs = {pool.submit(self._dns_sd_ipv6, name): ip
                        for ip, name in batch}
                for f in as_completed(futs):
                    v6 = f.result()
                    if v6:
                        found[futs[f]] = v6

        if not found:
            return
        with self.lock:
            updated = []
            for d in self.devices.values():
                v6 = found.get(d.ip, "")
                if v6 and not d.ipv6:
                    d.ipv6 = v6
                    updated.append(replace(d))
        for d in updated:
            self.q.put(("device", d))

    def _run_pool(self, hosts, probe):
        with ThreadPoolExecutor(max_workers=self.workers, thread_name_prefix="probe") as pool:
            futs = [pool.submit(probe, ip) for ip in hosts if not self.stop_event.is_set()]
            for _ in as_completed(futs):
                if self.stop_event.is_set():
                    for f in futs:
                        f.cancel()
                    break

    def _record(self, ip: str, mac: str):
        now = time.time()
        with self.lock:
            dev = self.devices.get(mac or ip)
            if dev is None and mac:
                # A host we first met by IP (e.g. via Bonjour) gains a MAC
                # later — merge into the existing row, don't create a second.
                for d in self.devices.values():
                    if d.ip == ip:
                        dev = d
                        break
            if dev is None:
                dev = Device(ip=ip, mac=mac,
                             vendor=vendor_for(mac), kind=kind_for(mac),
                             key_id=mac or ip)
                dev._enriched = bool(mac)
                self.devices[dev.key] = dev
            else:
                dev.ip = ip
                dev.last_seen = now
                if mac and not dev.mac:
                    dev.mac = mac
                    dev.vendor, dev.kind = vendor_for(mac), kind_for(mac)
            snapshot = replace(dev)
        self.q.put(("device", snapshot))

    @staticmethod
    def _dns_sd_ipv6(host: str) -> str:
        """IPv6 address for a Bonjour hostname, via macOS's own resolver
        (`dns-sd -G v4v6`). Gets a real address even when the neighbour table
        isn't giving us one, e.g. for a host we only know by name."""
        if not host or sys.platform != "darwin":
            return ""
        name = host if host.endswith(".local") else host + ".local"
        try:
            proc = subprocess.Popen(["/usr/bin/dns-sd", "-G", "v4v6", name],
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.DEVNULL, text=True)
            try:
                out, _ = proc.communicate(timeout=2.5)
            except subprocess.TimeoutExpired:
                proc.kill()
                out, _ = proc.communicate()
        except Exception:
            return ""
        best, best_rank = "", 0
        for line in (out or "").splitlines():
            if "Add" not in line or "A/R" in line:
                continue
            for tok in re.findall(r"[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){5,7}", line):
                try:
                    v6 = ipaddress.IPv6Address(tok)
                except ValueError:
                    continue
                if v6.is_loopback or v6.is_unspecified:
                    continue
                # Prefer a globally routable address; a link-local one needs a
                # scope id to be usable, so fall back to it last.
                rank = 1 if v6.is_link_local else (2 if v6.is_private else 3)
                if rank > best_rank:
                    best, best_rank = v6.exploded, rank
        return best

    @staticmethod
    def _arp_for(ip: str) -> str:
        """MAC for a single host, straight from the ARP/neighbour cache ('' if absent)."""
        if sys.platform.startswith("linux"):
            # `ip neigh` is the modern tool; format: 192.168.1.5 dev enp0s3 lladdr aa:bb:cc:dd:ee:ff REACHABLE
            try:
                out = subprocess.run(["ip", "neigh", "show", ip],
                                     capture_output=True, text=True, timeout=3).stdout
            except Exception:
                return ""
            m = re.search(r"lladdr\s+([0-9a-fA-F]{1,2}(?::[0-9a-fA-F]{1,2}){5})", out)
            if m:
                mac = _norm_mac(m.group(1))
                return "" if _is_placeholder_mac(mac) else mac
            # fallback: net-tools `arp -n`
            try:
                out = subprocess.run(["arp", "-n", ip], capture_output=True,
                                     text=True, timeout=3).stdout
            except Exception:
                return ""
            # Linux arp(8): 192.168.1.5   ether   aa:bb:cc:dd:ee:ff  C  enp0s3
            m = re.search(r"ether\s+([0-9a-fA-F]{1,2}(?::[0-9a-fA-F]{1,2}){5})", out)
            mac = _norm_mac(m.group(1)) if m else ""
            return "" if _is_placeholder_mac(mac) else mac
        try:
            out = subprocess.run(["arp", "-n", ip], capture_output=True,
                                 text=True, timeout=3).stdout
        except Exception:
            return ""
        # macOS strips leading zeros: 'e0:98:6:da:33:3f' — accept 1-2 digit groups.
        m = re.search(r"at\s+([0-9a-fA-F]{1,2}(?::[0-9a-fA-F]{1,2}){5})", out)
        mac = _norm_mac(m.group(1)) if m else ""
        if mac and not _is_placeholder_mac(mac):
            return mac
        # Blocked direct read on macOS 27 — the helper has the whole table.
        if sys.platform == "darwin":
            return _helper_arp_table().get(ip, "")
        return ""

    @staticmethod
    def _arp_table() -> dict[str, str]:
        """ip -> MAC, from the OS ARP/neighbour cache."""
        try:
            # -n: never resolve names. `arp -a` does reverse DNS per entry, which
            # is slow (and can exceed the timeout) right after a sweep.
            text = subprocess.run(["arp", "-an"], capture_output=True,
                                  text=True, timeout=10).stdout
        except Exception:
            text = ""
        out = _parse_arp(text)
        if not out and sys.platform == "darwin":
            out = _helper_arp_table()
        if not out and sys.platform.startswith("linux"):
            try:
                with open("/proc/net/arp") as f:
                    for line in f.readlines()[1:]:
                        p = line.split()
                        if len(p) >= 4:
                            mac = _norm_mac(p[3])
                            if mac and not _is_placeholder_mac(mac):
                                out[p[0]] = mac
            except OSError:
                pass
        return out

    # ---------------- Bonjour/mDNS discovery ----------------
    def _scan_mdns(self):
        """Bonjour discovery — catches Apple-style hosts (Macs, iPhones, iPads,
        Apple TVs) that drop ICMP and so are invisible to the ping sweep.
        Announces become brand-new device rows, not just names, and bring their
        own IPv6/MAC when the device advertises them."""
        if self.stop_event.is_set():
            return
        self.q.put(("status", "Browsing Bonjour/mDNS services …"))
        self.mdns_info = mdns_discover()

        with self.lock:
            existing = {d.ip: d for d in self.devices.values()}
        updated, new_ips = [], {}
        for ip, info in self.mdns_info.items():
            dev = existing.get(ip)
            if dev is None:
                new_ips[ip] = info
                continue
            changed = False
            if info.host and not dev.name:
                dev.name = info.host
                changed = True
            if info.ipv6 and not dev.ipv6:
                dev.ipv6 = info.ipv6
                changed = True
            if info.mac and not dev.mac:
                dev.mac = info.mac
                dev.vendor = vendor_for(info.mac)
                dev.kind = kind_from_service(info.service) or kind_for(info.mac)
                changed = True
            if changed:
                updated.append(replace(dev))
        for d in updated:
            self.q.put(("device", d))

        if not new_ips or self.stop_event.is_set():
            return
        self.q.put(("status", f"Joining {len(new_ips)} Bonjour-only device(s) …"))

        def poke(info: MdnsInfo):
            if self.stop_event.is_set():
                return
            # A MAC from the Bonjour TXT record beats the ARP poke (no traffic,
            # and it works for hosts the neighbour table won't tell us about).
            mac = info.mac or self._poke_mac(info.ip)
            with self.lock:
                # Keyed by IP, so a host already listed by its MAC is updated
                # rather than added a second time.
                dev = next((d for d in self.devices.values()
                            if d.ip == info.ip), None)
                if dev is None:
                    dev = Device(ip=info.ip, name=info.host, ipv6=info.ipv6,
                                 mac=mac, vendor=vendor_for(mac),
                                 kind=kind_from_service(info.service) or kind_for(mac),
                                 key_id=mac or info.ip)
                    dev._enriched = bool(mac)
                    self.devices[dev.key] = dev
                else:
                    if mac and not dev.mac:
                        dev.mac = mac
                        dev.vendor = vendor_for(mac)
                        dev.kind = kind_from_service(info.service) or kind_for(mac)
                    elif info.ipv6 and not dev.ipv6:
                        dev.ipv6 = info.ipv6
                    else:
                        return
                snapshot = replace(dev)
            self.q.put(("device", snapshot))

        with ThreadPoolExecutor(max_workers=min(16, len(new_ips)),
                                thread_name_prefix="mdns") as pool:
            for _ in pool.map(poke, new_ips.values()):
                pass

    def _poke_mac(self, ip: str) -> str:
        """Force kernel ARP resolution for `ip` with a quick TCP connect (the
        kernel emits an ARP request even when the port is closed/refused),
        then read the fresh ARP entry. Returns '' if unresolved."""
        for port in (443, 80, 22, 62078, 7000):
            if self.stop_event.is_set():
                break
            try:
                with socket.create_connection((ip, port), timeout=0.3):
                    pass
            except OSError:
                pass
            mac = self._arp_for(ip)
            if mac:
                return mac
        return ""


# ---------------------------------------------------------------------------
# Port scanner (TCP connect — unprivileged) + per-host dialog
# ---------------------------------------------------------------------------

TOP_PORTS = (
    21, 22, 23, 25, 53, 67, 68, 69, 80, 88, 110, 111, 123, 135, 137, 138, 139,
    143, 161, 162, 389, 427, 443, 445, 465, 500, 514, 515, 548, 554, 587, 631,
    636, 873, 993, 995, 1080, 1194, 1433, 1521, 1723, 1883, 2049, 2082, 2083,
    2181, 2375, 2376, 3000, 3128, 3260, 3306, 3389, 3690, 4443, 5000, 5001,
    5060, 5353, 5432, 5555, 5601, 5666, 5900, 5901, 5984, 6379, 6443, 6666,
    7000, 7001, 8000, 8008, 8009, 8080, 8081, 8443, 8888, 9000, 9090, 9100,
    9200, 9999, 11211, 15672, 27017, 32768, 49152, 49153, 49154, 50000, 50001,
)


class PortScanner(threading.Thread):
    """TCP connect() scan of one host; pushes onto q:
       ("open", (port, service)) | ("progress", done) | ("done", open_count)
    """

    def __init__(self, ip: str, ports, q: queue.Queue,
                 workers: int = 512, timeout: float = 0.5):
        super().__init__(daemon=True, name="portscan")
        self.ip = ip
        self.ports = list(ports)
        self.q = q
        self.workers = workers
        self.timeout = timeout
        self.stop_event = threading.Event()

    def stop(self):
        self.stop_event.set()

    def run(self):
        started = time.time()
        self.q.put(("status", f"Scanning {len(self.ports)} ports on {self.ip} …"))
        done = 0
        found = 0

        def probe(port: int):
            if self.stop_event.is_set():
                return
            s = socket.socket()
            s.settimeout(self.timeout)
            try:
                s.connect((self.ip, port))
            except Exception:
                return
            finally:
                s.close()
            try:
                svc = socket.getservbyport(port)
            except OSError:
                svc = ""
            self.q.put(("open", (port, svc)))

        with ThreadPoolExecutor(max_workers=self.workers, thread_name_prefix="pscan") as pool:
            futs = [pool.submit(probe, p) for p in self.ports]
            for _ in as_completed(futs):
                if self.stop_event.is_set():
                    for f in futs:
                        f.cancel()
                    break
                done += 1
                if done % 64 == 0 or done == len(self.ports):
                    self.q.put(("progress", done))
        self.q.put(("done", time.time() - started))


class PortScanDialog(ctk.CTkToplevel):
    """Live per-host port-scan window (quick top-N or full 1-65535)."""

    def __init__(self, master, ip: str):
        super().__init__(master)
        if getattr(master, "_menubar", None):
            self.config(menu=master._menubar)
        self.title(f"Port scan — {ip}")
        self.geometry("520x480")
        self.ip = ip
        self.scanner: PortScanner | None = None
        self.q: queue.Queue = queue.Queue()

        top = ctk.CTkFrame(self)
        top.pack(fill="x", padx=10, pady=(10, 4))
        ctk.CTkLabel(top, text=ip, font=ctk.CTkFont(size=16, weight="bold")).pack(side="left", padx=6)
        self.quick_btn = ctk.CTkButton(top, text=f"Quick ({len(TOP_PORTS)} ports)",
                                       command=self.quick, width=150)
        self.quick_btn.pack(side="right", padx=4, pady=6)
        self.full_btn = ctk.CTkButton(top, text="Full (1–65535)", fg_color="#4a5568",
                                      command=self.full, width=130)
        self.full_btn.pack(side="right", padx=4, pady=6)

        cols = (("port", "Port", 90, "w"), ("service", "Service", 160, "w"),
                ("state", "State", 90, "w"))
        body = ctk.CTkFrame(self)
        body.pack(fill="both", expand=True, padx=10, pady=4)
        self.tree = ttk.Treeview(body, columns=[c[0] for c in cols], show="headings",
                                 style="Mini.Treeview")
        for key, label, width, anchor in cols:
            self.tree.heading(key, text=label)
            self.tree.column(key, width=width, anchor=anchor, stretch=(key == "service"))
        vsb = ttk.Scrollbar(body, orient="vertical", command=self.tree.yview)
        hsb = ttk.Scrollbar(body, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        vsb.pack(side="right", fill="y")
        hsb.pack(side="bottom", fill="x")
        self.tree.pack(side="left", fill="both", expand=True)

        bottom = ctk.CTkFrame(self)
        bottom.pack(fill="x", padx=10, pady=(4, 10))
        self.status_var = ctk.StringVar(value="Choose Quick or Full scan.")
        ctk.CTkLabel(bottom, textvariable=self.status_var, anchor="w").pack(side="left", padx=6, pady=6)
        ctk.CTkButton(bottom, text="Export", fg_color="#4a5568", width=90,
                      command=self.export_csv).pack(side="right", padx=6, pady=6)

        self.after(100, self._poll)

    # ---------------- export ----------------
    def export_csv(self):
        rows = self.tree.get_children()
        if not rows:
            messagebox.showinfo("Nothing to export", "No ports scanned yet.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".csv", filetypes=[("CSV files", "*.csv")],
            initialfile=f"portscan_{self.ip}.csv")
        if not path:
            return
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["IP", "Port", "Service", "State"])
            for iid in rows:
                w.writerow([self.ip, *self.tree.item(iid, "values")])
        self.status_var.set(f"Exported {len(rows)} port(s) to {path}")

    # ---------------- control ----------------
    def quick(self):
        self._start(TOP_PORTS)

    def full(self):
        self._start(range(1, 65536))

    def _start(self, ports):
        if self.scanner and self.scanner.is_alive():
            return
        self.tree.delete(*self.tree.get_children())
        self.quick_btn.configure(state="disabled")
        self.full_btn.configure(state="disabled")
        self.scanner = PortScanner(self.ip, ports, self.q)
        self.scanner.start()

    def _poll(self):
        try:
            while True:
                kind, payload = self.q.get_nowait()
                if kind == "open":
                    port, svc = payload
                    self.tree.insert("", "end",
                                     values=(port, svc or "—", "open"))
                elif kind == "status":
                    self.status_var.set(payload)
                elif kind == "progress":
                    self.status_var.set(f"Scanning {self.ip} … {payload} ports checked")
                elif kind == "done":
                    n = len(self.tree.get_children())
                    self.status_var.set(
                        f"Done in {payload:.1f}s — {n} open port(s).")
                    self.quick_btn.configure(state="normal")
                    self.full_btn.configure(state="normal")
        except queue.Empty:
            pass
        self.after(100, self._poll)

    def destroy(self):
        if self.scanner:
            self.scanner.stop()
        super().destroy()


def diagnostics_report(devices=None) -> str:
    """Plain text describing what this process can actually see on the network:
    which tools it finds, what the neighbour-table reads return both directly and
    through the launchd helper, and what the last scan collected. Help → Scan
    diagnostics shows it so a bug report can carry it."""
    def raw(args) -> str:
        try:
            return subprocess.run(args, capture_output=True, text=True,
                                  timeout=10).stdout
        except Exception as e:
            return f"<{type(e).__name__}: {e}>"

    lines = [
        f"MyLanScan {APP_VERSION}",
        f"macOS    : {platform.mac_ver()[0] or platform.platform()} ({platform.machine()})"
        if sys.platform == "darwin" else f"system   : {platform.platform()}",
        f"python   : {sys.version.split()[0]}  frozen={getattr(sys, 'frozen', False)}"
        f"  euid={os.geteuid()}",
        f"PATH     : {os.environ.get('PATH', '')}",
    ]
    for tool in ("arp", "ndp", "ping", "route", "dns-sd", "launchctl", "nmap"):
        lines.append(f"tool     : {tool} -> {shutil.which(tool) or 'not found'}")

    if sys.platform == "darwin":
        direct = _parse_arp(raw(["/usr/sbin/arp", "-an"]))
        rows = _parse_ndp(raw(["/usr/sbin/ndp", "-an"]))
        via = _helper_arp_table()
        lines += [
            "",
            f"direct arp -an : {len(direct)} entries with a MAC",
            f"helper arp -an : {len(via)} entries with a MAC"
            f"{'  (used)' if _HELPER_USED else ''}",
            f"direct ndp -an : {len([1 for v, m in rows if m])} rows with a MAC,"
            f" {len(rows)} rows total",
            f"helper ndp -an : {len(_helper_ndp_table())} MAC -> IPv6 pairs",
        ]
        if not direct and via:
            lines.append("NOTE     : macOS 27 won't give link-layer addresses to this"
                         " process; the helper path is covering it.")
        elif not direct and not via:
            lines.append("NOTE     : neither path can read the ARP table here.")
    elif sys.platform.startswith("linux"):
        lines.append("")
        lines.append(f"ip -6 neigh    : {len(_ndp_table_rows_linux(raw))} rows")

    if devices:
        with_mac = sum(1 for d in devices.values() if d.mac)
        with_v6 = sum(1 for d in devices.values() if d.ipv6)
        lines += ["", f"last scan      : {len(devices)} device(s) —"
                      f" with MAC {with_mac}, with IPv6 {with_v6}"]
    return "\n".join(lines)


def _ndp_table_rows_linux(raw) -> list:
    text = raw(["ip", "-6", "neigh", "show"])
    return [l for l in text.splitlines() if "lladdr" in l]


# ---------------------------------------------------------------------------
# nmap deep scan (external CLI; unprivileged) + per-host dialog
# ---------------------------------------------------------------------------

def _find_nmap() -> str | None:
    """Locate the nmap binary. GUI launches from Finder/Dock get a minimal
    PATH that omits Homebrew's prefix, so probe the known locations too."""
    found = shutil.which("nmap")
    if found:
        return found
    for cand in ("/opt/homebrew/bin/nmap",     # Apple Silicon Homebrew
                 "/usr/local/bin/nmap",        # Intel Homebrew
                 "/opt/local/bin/nmap",        # MacPorts
                 "/usr/bin/nmap",              # Debian/Ubuntu
                 "/usr/sbin/nmap",             # some distros keep it under sbin
                 "/bin/nmap"):                 # fallback
        if os.path.exists(cand):
            return cand
    return None


NMAP_BIN = _find_nmap()


def build_nmap_args(ip: str, service: bool = True, scripts: bool = True,
                    os_detect: bool = False, ports: str = "") -> list[str]:
    """nmap argv for a deep dive on one known-alive host.
    Unprivileged: TCP connect + version + default NSE scripts.
    OS fingerprinting (root only) is added by the caller."""
    args = ["nmap", "-Pn", "-sT", "-T4", "-v"]
    if service:
        args.append("-sV")
    if scripts:
        args.append("-sC")
    if os_detect:
        args.append("-O")
    if ports:
        args.extend(["-p", ports])
    args.append(ip)
    return args


class NmapScanner(threading.Thread):
    """Runs nmap on one host, streaming its report line-by-line onto q:
       ("line", text) | ("done", rc_or_tag) | ("err", stderr_tail) | ("status", text)
       OS detection needs root. When the app is unprivileged and -O was
       requested, the scan runs elevated via the macOS native admin prompt
       (osascript "do shell script … with administrator privileges").
    """

    def __init__(self, ip: str, service: bool, scripts: bool, os_detect: bool,
                 ports: str, q: queue.Queue):
        super().__init__(daemon=True, name="nmap")
        self.ip = ip
        self.service = service
        self.scripts = scripts
        self.os_detect = os_detect
        self.ports = ports
        self.q = q
        self.bin_path = _find_nmap()
        self.elevate = bool(os_detect and os.geteuid() != 0)
        self.proc: subprocess.Popen | None = None

    def stop(self):
        if self.proc and self.proc.poll() is None:
            try:
                self.proc.terminate()
            except Exception:
                pass

    def run(self):
        if self.elevate:
            self._run_elevated()
        else:
            self._run_plain()

    def _run_plain(self):
        args = build_nmap_args(self.ip, self.service, self.scripts,
                               self.os_detect, self.ports)
        if self.bin_path:
            args[0] = self.bin_path
        try:
            self.proc = subprocess.Popen(args, stdout=subprocess.PIPE,
                                         stderr=subprocess.PIPE, text=True)
        except OSError as e:
            self.q.put(("err", f"Could not run nmap: {e}"))
            self.q.put(("done", -1))
            return
        assert self.proc.stdout is not None
        for line in self.proc.stdout:
            self.q.put(("line", line.rstrip("\n")))
        rc = self.proc.wait()
        if rc != 0:
            assert self.proc.stderr is not None
            tail = "\n".join(self.proc.stderr.read().splitlines()[-8:])
            self.q.put(("err", tail or f"nmap exited with code {rc}"))
        self.q.put(("done", rc))

    def _run_elevated(self):
        """Run nmap as root via the native admin prompt — macOS osascript or
        Linux pkexec. The elevated command writes its output to a temp file we
        tail for live streaming."""
        args = build_nmap_args(self.ip, self.service, self.scripts,
                               True, self.ports)
        if self.bin_path:
            args[0] = self.bin_path
        self.q.put(("status", "Requesting admin rights for OS detection …"))
        fd, out_path = tempfile.mkstemp(prefix="mylanscan_nmap_", suffix=".out")
        os.close(fd)
        try:
            quoted = " ".join(shlex.quote(a) for a in args)
            redir = f"> {shlex.quote(out_path)} 2>&1"
            if sys.platform.startswith("linux"):
                # pkexec shows the graphical PolicyKit password prompt; it
                # doesn't run a shell by default, so wrap the redirect in sh -c.
                cmd = ["pkexec", "sh", "-c", f"{quoted} {redir}"]
            else:
                script = (f"do shell script \"{quoted} {redir}\" "
                          "with administrator privileges")
                cmd = ["osascript", "-e", script]
            try:
                self.proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                             stderr=subprocess.PIPE, text=True)
            except OSError as e:
                self.q.put(("err", f"Could not elevate nmap: {e}"))
                self.q.put(("done", -1))
                return
            seen = 0
            while self.proc.poll() is None:
                try:
                    with open(out_path, encoding="utf-8",
                              errors="replace") as f:
                        f.seek(seen)
                        for line in f:
                            self.q.put(("line", line.rstrip("\n")))
                        seen = f.tell()
                except FileNotFoundError:
                    pass
                time.sleep(0.2)
            try:
                with open(out_path, encoding="utf-8",
                          errors="replace") as f:
                    f.seek(seen)
                    for line in f:
                        self.q.put(("line", line.rstrip("\n")))
            except FileNotFoundError:
                pass
            rc = self.proc.wait()
            err = (self.proc.stderr or "").read()
            if rc != 0:
                tail = err.strip().splitlines()[-1:] or [f"elevation failed (code {rc})"]
                self.q.put(("err", tail[0]))
                self.q.put(("done", "auth-cancel"))
            else:
                self.q.put(("done", 0))
        finally:
            try:
                os.remove(out_path)
            except OSError:
                pass


class NmapDialog(ctk.CTkToplevel):
    """Deep dive on one host: streams the full nmap report live."""

    def __init__(self, master, ip: str):
        super().__init__(master)
        if getattr(master, "_menubar", None):
            self.config(menu=master._menubar)
        self.title(f"Deep scan (nmap) — {ip}")
        self.geometry("640x560")
        self.ip = ip
        self.scanner: NmapScanner | None = None
        self.q: queue.Queue = queue.Queue()

        top = ctk.CTkFrame(self)
        top.pack(fill="x", padx=10, pady=(10, 4))
        ctk.CTkLabel(top, text=ip,
                     font=ctk.CTkFont(size=16, weight="bold")).pack(side="left", padx=6)
        self.start_btn = ctk.CTkButton(top, text="Start",
                                       command=self._start, width=90)
        self.start_btn.pack(side="right", padx=4, pady=6)
        self.stop_btn = ctk.CTkButton(top, text="Stop", fg_color="#c53030",
                                      state="disabled", command=self._stop, width=80)
        self.stop_btn.pack(side="right", padx=4, pady=6)

        opts = ctk.CTkFrame(self)
        opts.pack(fill="x", padx=10, pady=(0, 4))
        self.sv_var = ctk.BooleanVar(value=True)
        self.sc_var = ctk.BooleanVar(value=True)
        self.os_var = ctk.BooleanVar(value=False)
        ctk.CTkCheckBox(opts, text="Service versions", variable=self.sv_var).pack(side="left", padx=8, pady=4)
        ctk.CTkCheckBox(opts, text="Default scripts", variable=self.sc_var).pack(side="left", padx=8, pady=4)
        self.os_box = ctk.CTkCheckBox(opts, text="OS detection", variable=self.os_var)
        self.os_box.pack(side="left", padx=8, pady=4)
        if os.geteuid() != 0:
            self.os_box.configure(text="OS detection (prompts for admin)")

        ctk.CTkLabel(opts, text="Ports:").pack(side="left", padx=(8, 2), pady=4)
        self.ports_var = ctk.StringVar(value="")
        ctk.CTkEntry(opts, textvariable=self.ports_var, width=110,
                     placeholder_text="default 1–1000").pack(side="left", padx=(0, 8), pady=4)

        body = ctk.CTkFrame(self)
        body.pack(fill="both", expand=True, padx=10, pady=4)
        ctk.CTkTextbox(body, wrap="word", font=ctk.CTkFont(family="Menlo", size=12)).pack(
            fill="both", expand=True)
        self.textbox = body.winfo_children()[0]

        bottom = ctk.CTkFrame(self)
        bottom.pack(fill="x", padx=10, pady=(4, 10))
        self.status_var = ctk.StringVar(value="")
        ctk.CTkLabel(bottom, textvariable=self.status_var, anchor="w").pack(side="left", padx=6, pady=6)
        ctk.CTkButton(bottom, text="Export", fg_color="#4a5568", width=90,
                      command=self.export_txt).pack(side="right", padx=6, pady=6)

        if _find_nmap() is None:
            self.status_var.set("nmap not found — install with:  brew install nmap")
            self.start_btn.configure(state="disabled")
        else:
            self.status_var.set("Ready. Start a deep scan.")

        self.after(100, self._poll)

    # ---------------- export ----------------
    def export_txt(self):
        content = self.textbox.get("1.0", "end-1c").strip()
        if not content:
            messagebox.showinfo("Nothing to export", "No scan output yet.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            initialfile=f"nmap_{self.ip}.txt")
        if not path:
            return
        with open(path, "w", encoding="utf-8") as f:
            f.write(content + "\n")
        self.status_var.set(f"Exported report to {path}")

    # ---------------- control ----------------
    def _start(self):
        if self.scanner and self.scanner.is_alive():
            return
        self.textbox.delete("1.0", "end")
        self.start_btn.configure(state="disabled")
        self.stop_btn.configure(state="normal")
        self.status_var.set("Running nmap …")
        self.scanner = NmapScanner(self.ip, self.sv_var.get(), self.sc_var.get(),
                                   self.os_var.get(), self.ports_var.get().strip(),
                                   self.q)
        self.scanner.start()

    def _stop(self):
        if self.scanner:
            self.scanner.stop()
        self.status_var.set("Stopping …")

    def _poll(self):
        try:
            while True:
                kind, payload = self.q.get_nowait()
                if kind == "line":
                    self.textbox.insert("end", payload + "\n")
                    self.textbox.see("end")
                elif kind == "err":
                    self.textbox.insert("end", "\n[error] " + payload + "\n")
                    self.textbox.see("end")
                elif kind == "status":
                    self.status_var.set(payload)
                elif kind == "done":
                    rc = payload
                    self.start_btn.configure(state="normal")
                    self.stop_btn.configure(state="disabled")
                    if rc == 0:
                        self.status_var.set("Done.")
                    elif rc == "auth-cancel":
                        self.status_var.set("Admin prompt cancelled — OS detection skipped.")
                    elif rc == -1:
                        self.status_var.set("Could not run nmap.")
                    else:
                        self.status_var.set(f"nmap finished with exit code {rc}.")
        except queue.Empty:
            pass
        self.after(100, self._poll)

    def destroy(self):
        if self.scanner:
            self.scanner.stop()
        super().destroy()


class HelpDialog(ctk.CTkToplevel):
    """Usage guide + feature list + license notice."""

    TEXT = f"""\
QUICK START
  1. Check the subnet field (prefilled with your local /24).
  2. Press "Start scan" — devices stream in as they answer.
  3. Press "Re-scan" any time: rows update in place, and
     devices no longer on the network are removed.

WHAT YOU GET PER DEVICE
  IP · name (DNS + mDNS/Bonjour) · IPv6 · MAC · vendor
  (full IEEE OUI table) · device type.
  Discovery also browses Bonjour/mDNS, so Apple devices that
  ignore ping (stealth mode) still show up by their services.

PORT SCANNING
  Right-click (or ctrl-click) a device row → "Port scan <ip>".
    Quick — ~100 common ports, seconds.
    Full  — every port 1–65535, about a minute.
  Open ports appear live with their service names.

DEEP SCAN (NMAP)
  Right-click a device row → "Deep scan (nmap) <ip>" runs nmap on
  that host: service versions (-sV) and default NSE scripts (-sC).
  Tick "OS detection" for OS fingerprinting (-O) — it needs admin
  rights, so macOS asks for your password once. The full report
  streams in live. Requires nmap installed:  brew install nmap

TABLE CONTROLS
  Click a column header to sort. Drag header separators to
  resize; double-click a separator to auto-fit that column.
  Horizontal scrollbar appears when columns overflow.

EXPORT
  "Export CSV" writes all listed devices to a spreadsheet file.

ABOUT
  MyLanScan v{APP_VERSION} — LAN discovery for macOS.
  Released under the MIT License.
  Scanning networks you do not own or lack authorization
  for is illegal; this tool defaults to your own subnet.
"""

    def __init__(self, master):
        super().__init__(master)
        if getattr(master, "_menubar", None):
            self.config(menu=master._menubar)
        self.title(f"MyLanScan v{APP_VERSION} — Help")
        self.geometry("560x560")
        ctk.CTkTextbox(self, wrap="word").pack(fill="both", expand=True,
                                               padx=12, pady=(12, 6))
        self.textbox = self.winfo_children()[0]
        self.textbox.insert("1.0", self.TEXT)
        self.textbox.configure(state="disabled")
        ctk.CTkButton(self, text="Close", width=90,
                      command=self.destroy).pack(pady=(0, 12))


class ReleaseNotesDialog(ctk.CTkToplevel):
    """Per-release changelog: versions, features added, fixes."""

    @staticmethod
    def _block(r: dict[str, object]) -> str:
        lines = [f"{r['version']} — {r['date']}"]
        for kind, items in (("Added", r["added"]), ("Fixed", r["fixed"])):
            if items:
                lines.append(f"  {kind}:")
                lines += [f"    · {i}" for i in items]
        return "\n".join(lines)

    def __init__(self, master):
        super().__init__(master)
        if getattr(master, "_menubar", None):
            self.config(menu=master._menubar)
        self.title(f"MyLanScan v{APP_VERSION} — Release Notes")
        self.geometry("560x520")
        ctk.CTkTextbox(self, wrap="word").pack(fill="both", expand=True,
                                               padx=12, pady=(12, 6))
        self.textbox = self.winfo_children()[0]
        self.textbox.insert("1.0", "\n\n".join(self._block(r)
                                               for r in RELEASES))
        self.textbox.configure(state="disabled")
        ctk.CTkButton(self, text="Close", width=90,
                      command=self.destroy).pack(pady=(0, 12))


class DiagnosticsDialog(ctk.CTkToplevel):
    """What this process can actually see on the network — which tools it finds
    and what the neighbour-table reads return. Handy when a column stays empty:
    the text can be copied straight into a bug report."""

    def __init__(self, master, devices=None):
        super().__init__(master)
        if getattr(master, "_menubar", None):
            self.config(menu=master._menubar)
        self.title(f"MyLanScan v{APP_VERSION} — Scan diagnostics")
        self.geometry("640x520")
        ctk.CTkLabel(self, anchor="w", justify="left",
                     text="If MAC or IPv6 stay empty, copy this into a bug report."
                     ).pack(fill="x", padx=12, pady=(10, 4))
        ctk.CTkTextbox(self, wrap="none").pack(fill="both", expand=True,
                                               padx=12, pady=(0, 6))
        self.textbox = self.winfo_children()[-1]
        self.textbox.insert("1.0", diagnostics_report(devices))
        self.status_var = ctk.StringVar(value="")
        bottom = ctk.CTkFrame(self)
        bottom.pack(fill="x", padx=12, pady=(0, 12))
        ctk.CTkButton(bottom, text="Copy", width=90,
                      command=self.copy).pack(side="left")
        ctk.CTkLabel(bottom, text="", textvariable=self.status_var).pack(
            side="left", padx=8)
        ctk.CTkButton(bottom, text="Close", width=90,
                      command=self.destroy).pack(side="right")

    def copy(self):
        self.clipboard_clear()
        self.clipboard_append(self.textbox.get("1.0", "end").strip())
        self.status_var.set("Copied to clipboard")

# ---------------------------------------------------------------------------
# Main window
# ---------------------------------------------------------------------------

COLUMNS = (
    ("ip", "IP Address", 110, "w"),
    ("name", "Name", 150, "w"),
    ("ipv6", "IPv6", 180, "w"),
    ("mac", "MAC", 130, "w"),
    ("vendor", "Vendor", 160, "w"),
    ("kind", "Type", 140, "w"),
)


class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title(f"Mini LanScan v{APP_VERSION}")
        self.geometry("1000x580")
        self.minsize(820, 460)
        ctk.set_appearance_mode("dark")

        self.q: queue.Queue = queue.Queue()
        self.devices: dict[str, Device] = {}   # UI-side copy, updated from queue
        self.scanner: Scanner | None = None
        self._row_by_key: dict[str, str] = {}
        self._scan_keys: set[str] = set()
        self._sort_col, self._sort_rev = "ip", False

        self._build_menubar()
        self._build_topbar()
        self._build_table()
        self._build_statusbar()
        self.after(100, self._poll)

    # ---------------- layout ----------------
    def _build_menubar(self):
        """Application menu (About) + Help menu.
        macOS: the first cascade becomes the app menu next to the  logo;
        other platforms: it's a labelled menu inside the window.
        NOTE: on macOS the Help cascade must NOT use name="help" — Tk/aqua
        auto-fills a menu with that name, duplicating our items."""
        is_mac = sys.platform == "darwin"
        m = tkMenu(self)

        app_menu = tkMenu(m, name="apple" if is_mac else None)
        app_menu.add_command(label="About MyLanScan",
                             command=lambda: HelpDialog(self))
        m.add_cascade(label="" if is_mac else "MyLanScan", menu=app_menu)

        help_menu = tkMenu(m, tearoff=0)
        help_menu.add_command(label="MyLanScan Help",
                              accelerator="Ctrl+?" if not is_mac else "Cmd+?",
                              command=lambda: HelpDialog(self))
        help_menu.add_command(label="Release Notes",
                              command=lambda: ReleaseNotesDialog(self))
        help_menu.add_command(label="Scan diagnostics",
                              command=lambda: DiagnosticsDialog(self, self.devices))
        m.add_cascade(label="Help", menu=help_menu)

        self.config(menu=m)
        self._menubar = m   # reuse on dialogs so they keep the main-page menu
        self.bind_all("<Command-question>", lambda _e: HelpDialog(self))
        if not is_mac:
            self.bind_all("<Control-question>", lambda _e: HelpDialog(self))

    def _build_topbar(self):
        top = ctk.CTkFrame(self)
        top.pack(fill="x", padx=10, pady=(10, 4))

        ctk.CTkLabel(top, text="Network:").pack(side="left", padx=(10, 4), pady=8)
        self.subnet_var = ctk.StringVar(value=self._default_subnet())
        ctk.CTkEntry(top, textvariable=self.subnet_var, width=170).pack(side="left", padx=(0, 10), pady=8)

        ctk.CTkLabel(top, text="Mode:").pack(side="left", padx=(0, 4))
        self.mode_var = ctk.StringVar(value="Auto (ARP, else ping)")
        ctk.CTkOptionMenu(top, variable=self.mode_var, width=190, values=[
            "Auto (ARP, else ping)", "ARP only", "Ping sweep only"]).pack(side="left", padx=(0, 10), pady=8)

        ctk.CTkLabel(top, text="Workers:").pack(side="left", padx=(0, 4))
        self.workers_var = ctk.StringVar(value="100")
        ctk.CTkEntry(top, textvariable=self.workers_var, width=60).pack(side="left", padx=(0, 14), pady=8)

        ctk.CTkButton(top, text="Export CSV", command=self.export_csv,
                      fg_color="#4a5568", width=110).pack(side="right", padx=(4, 10), pady=8)
        self.start_btn = ctk.CTkButton(top, text="Start scan", command=self.start_scan,
                                       fg_color="#2f855a", width=110)
        self.start_btn.pack(side="right", padx=(0, 4), pady=8)

    def _build_table(self):
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("Mini.Treeview", background="#1a1b1e", fieldbackground="#1a1b1e",
                        foreground="#e6e6e6", rowheight=26, borderwidth=0)
        style.configure("Mini.Treeview.Heading", background="#2d2e33",
                        foreground="#ffffff", relief="flat", padding=6)
        style.map("Mini.Treeview.Heading", background=[("active", "#3a3b42")])

        body = ctk.CTkFrame(self)
        body.pack(fill="both", expand=True, padx=10, pady=4)

        self.tree = ttk.Treeview(body, columns=[c[0] for c in COLUMNS], show="headings",
                                 style="Mini.Treeview")
        for key, label, width, anchor in COLUMNS:
            self.tree.heading(key, text=label, command=lambda k=key: self._on_sort(k))
            # only the last column stretches to fill the window — otherwise ttk
            # redistributes every resize across all columns and drags feel wrong
            self.tree.column(key, width=width, anchor=anchor,
                             stretch=(key == COLUMNS[-1][0]))

        vsb = ttk.Scrollbar(body, orient="vertical", command=self.tree.yview)
        hsb = ttk.Scrollbar(body, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        vsb.pack(side="right", fill="y")
        hsb.pack(side="bottom", fill="x")
        self.tree.pack(side="left", fill="both", expand=True)

        # --- dynamic columns: drag separators to resize, double-click to fit ---
        self._resize_col: str | None = None
        self.tree.bind("<Motion>", self._sep_cursor)
        self.tree.bind("<ButtonPress-1>", self._col_press)
        self.tree.bind("<B1-Motion>", self._col_drag)
        self.tree.bind("<ButtonRelease-1>", self._col_release)
        self.tree.bind("<Double-Button-1>", self._col_double)
        self.tree.bind("<Button-2>", self._row_menu)   # macOS right-click
        self.tree.bind("<Button-3>", self._row_menu)   # X11/Windows right-click
        self.tree.bind("<Control-Button-1>", self._row_menu)  # macOS ctrl+click

    # ---------------- dynamic column helpers ----------------
    def _sep_cursor(self, event):
        over = self.tree.identify_region(event.x, event.y) == "separator"
        self.tree.configure(cursor="sb_h_double_arrow" if over else "")

    def _col_press(self, event):
        if self.tree.identify_region(event.x, event.y) == "separator":
            self._resize_col = self.tree.identify_column(event.x)  # column left of the separator
            return "break"

    def _col_drag(self, event):
        if not self._resize_col:
            return
        try:
            idx = int(self._resize_col[1:]) - 1      # identify_column gives '#n'
            cols = self.tree["columns"]
            if idx < 0 or idx >= len(cols):
                return
        except ValueError:
            return
        left = sum(self.tree.column(c, "width") for c in cols[:idx])
        self.tree.column(cols[idx], width=max(40, event.x - left))
        return "break"

    def _col_release(self, event):
        self._resize_col = None

    def _col_double(self, event):
        if self.tree.identify_region(event.x, event.y) == "separator":
            col = self.tree.identify_column(event.x)
            key = COLUMNS[int(col[1:]) - 1][0]
            self._fit_column(key)
            return "break"

    def _fit_column(self, key: str):
        """Widen a column to exactly fit its widest visible value."""
        meta = next(c for c in COLUMNS if c[0] == key)
        f = tkfont.nametofont("TkDefaultFont")
        texts = [meta[1]] + [self.tree.set(iid, key) for iid in self.tree.get_children()]
        width = max((f.measure(t) for t in texts), default=0) + 24
        self.tree.column(key, width=max(60, min(width, 300)))

    def _autofit_all(self):
        """Refit every column — called once when a scan completes, so manual
        resizes stick while results are streaming in."""
        for key, _, _, _ in COLUMNS:
            self._fit_column(key)

    def _build_statusbar(self):
        bottom = ctk.CTkFrame(self)
        bottom.pack(fill="x", padx=10, pady=(4, 10))
        self.status_var = ctk.StringVar(value="Ready.")
        ctk.CTkLabel(bottom, textvariable=self.status_var, anchor="w").pack(side="left", padx=10, pady=6)
        self.count_var = ctk.StringVar(value="0 devices")
        ctk.CTkLabel(bottom, textvariable=self.count_var).pack(side="right", padx=10)

    # ---------------- scan control ----------------
    def start_scan(self):
        if self.scanner and self.scanner.is_alive():
            return
        try:
            net = ipaddress.ip_network(self.subnet_var.get().strip(), strict=False)
        except ValueError:
            messagebox.showerror("Invalid network", "Enter a CIDR, e.g. 192.168.1.0/24")
            return
        mode = "arp" if self.mode_var.get().startswith("ARP") else (
            "ping" if self.mode_var.get().startswith("Ping") else "auto")
        try:
            workers = max(1, min(400, int(self.workers_var.get())))
        except ValueError:
            workers = 100

        # Rescan semantics: keep existing rows — devices update in place as the
        # new scan reports them; anything not seen this scan is pruned on done.
        self._scan_keys = set()
        self._set_running(True)

        self.scanner = Scanner(net, self.q, mode=mode, workers=workers)
        self.scanner.start()

    def _set_running(self, running: bool):
        self.start_btn.configure(state="disabled" if running else "normal")

    # ---------------- queue polling (live UI updates) ----------------
    def _poll(self):
        try:
            while True:
                kind, payload = self.q.get_nowait()
                if kind == "device":
                    self._upsert_device(payload)
                elif kind == "status":
                    self.status_var.set(payload)
                elif kind == "done":
                    self._prune_absent()
                    self._sort_col, self._sort_rev = "ip", False
                    self._apply_sort()
                    self._autofit_all()
                    self._set_running(False)
                    self.start_btn.configure(text="Re-scan")
        except queue.Empty:
            pass
        self.after(100, self._poll)

    def _upsert_device(self, d: Device):
        vals = (d.ip, d.name or "—", d.ipv6 or "—", d.mac or "—", d.vendor or "—",
                d.kind or "—")
        iid = self._row_by_key.get(d.key)
        if iid is None or not self.tree.exists(iid):
            iid = self.tree.insert("", "end", values=vals)
            self._row_by_key[d.key] = iid
        else:
            self.tree.item(iid, values=vals)
        self.devices[d.key] = d
        self._scan_keys.add(d.key)
        self.count_var.set(f"{len(self.devices)} device(s)")

    def _prune_absent(self):
        """After a scan completes, drop devices that weren't seen in it."""
        gone = [k for k in self.devices if k not in self._scan_keys]
        for k in gone:
            iid = self._row_by_key.pop(k, None)
            if iid and self.tree.exists(iid):
                self.tree.delete(iid)
            self.devices.pop(k, None)
        if gone:
            self.count_var.set(f"{len(self.devices)} device(s)")
            self.status_var.set(f"Rescan: {len(gone)} device(s) no longer present.")

    # ---------------- per-device actions ----------------
    def _row_menu(self, event):
        iid = self.tree.identify_row(event.y)
        if not iid:
            return
        self.tree.selection_set(iid)
        ip = self.tree.item(iid, "values")[0]
        menu = tkMenu(self, tearoff=0)
        menu.add_command(label=f"Port scan {ip}",
                         command=lambda: PortScanDialog(self, ip))
        menu.add_command(label=f"Deep scan (nmap) {ip}",
                         command=lambda: NmapDialog(self, ip))
        menu.tk_popup(event.x_root, event.y_root)

    # ---------------- sorting ----------------
    def _on_sort(self, key: str):
        if self._sort_col == key:
            self._sort_rev = not self._sort_rev
        else:
            self._sort_col, self._sort_rev = key, False
        self._apply_sort()

    def _apply_sort(self):
        key = self._sort_col
        def val(t):
            return (ip_sort_key(t) if key == "ip" else t)
        items = sorted(((val(self.tree.set(iid, key)), iid)
                        for iid in self.tree.get_children()), reverse=self._sort_rev)
        for i, (_, iid) in enumerate(items):
            self.tree.move(iid, "", i)

    # ---------------- export ----------------
    def export_csv(self):
        if not self.devices:
            messagebox.showinfo("Nothing to export", "No devices found yet.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".csv",
                                            filetypes=[("CSV files", "*.csv")],
                                            initialfile="lan_scan.csv")
        if not path:
            return
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["ip", "name", "ipv6", "mac", "vendor", "type"])
            for d in sorted(self.devices.values(), key=lambda d: ip_sort_key(d.ip)):
                w.writerow([d.ip, d.name, d.ipv6, d.mac, d.vendor, d.kind])
        self.status_var.set(f"Exported {len(self.devices)} rows → {path}")

    @staticmethod
    def _default_subnet() -> str:
        # MVP: first local IPv4, assumed /24. For multi-NIC accuracy use psutil
        # and pick the interface with a gateway.
        try:
            ip = socket.gethostbyname(socket.gethostname())
        except OSError:
            ip = "192.168.1.1"
        try:
            return str(ipaddress.ip_network(ip + "/24", strict=False))
        except ValueError:
            return "192.168.1.0/24"


def main():
    App().mainloop()


if __name__ == "__main__":
    main()
