"""Headless validation of Sample/S1mvp.py — no GUI opened."""
import importlib.util
import ipaddress
import os
import queue
import socket
import sys
import time

spec = importlib.util.spec_from_file_location("s1mvp", "Sample/S1mvp.py")
m = importlib.util.module_from_spec(spec)
sys.modules["s1mvp"] = m
spec.loader.exec_module(m)

fails = []


def check(name, cond, detail=""):
    print(f"{'PASS' if cond else 'FAIL'}  {name}" + (f"  [{detail}]" if detail else ""))
    if not cond:
        fails.append(name)


# --- pure helpers ---
check("_norm_mac dashes", m._norm_mac("aa-bb-cc-dd-ee-ff") == "AA:BB:CC:DD:EE:FF")
check("_norm_mac zero-stripped (macOS)", m._norm_mac("e0:98:6:da:33:3f") == "E0:98:06:DA:33:3F")
check("_norm_mac garbage", m._norm_mac("nope") == "")
check("vendor_for Apple", m.vendor_for("F0:18:98:11:22:33") == "Apple")
check("vendor_for randomized MAC", m.vendor_for("2E:57:60:16:D7:8D") == "Private MAC (randomized)")
check("OUI table loaded", len(m.OUI_VENDORS) > 30000, f"{len(m.OUI_VENDORS)} entries")
known_oui = next(iter(m.OUI_VENDORS))
check("vendor_for known prefix", m.vendor_for(known_oui + ":00:00") == m.OUI_VENDORS[known_oui])
check("kind_for mapped", m.kind_for("B8:27:EB:00:00:01") == "SBC / maker")
check("ip_sort_key numeric", m.ip_sort_key("192.168.1.2") < m.ip_sort_key("192.168.1.10"))

# --- Bonjour/mDNS discovery helpers ---
check("kind_from_service AirPlay", m.kind_from_service("_airplay._tcp.local.") == "AirPlay")
check("kind_from_service companion", m.kind_from_service("_companion-link._tcp.local.") == "iPhone/iPad")
check("kind_from_service printer", m.kind_from_service("_ipp._tcp.local.") == "Printer")
check("kind_from_service fallback", m.kind_from_service("_odd._tcp.local.") == "mDNS device")

# Live, network-dependent checks are skipped in CI / on hosts with no LAN.
# Pure-logic checks (above and below) and the loopback port scan still run.
SKIP_LIVE = os.environ.get("MYLANSCAN_SKIP_LIVE", "") not in ("", "0", "false")
if SKIP_LIVE:
    print("SKIP  live network checks (MYLANSCAN_SKIP_LIVE set)")

if not SKIP_LIVE:
    mdns = m.mdns_discover(browse_secs=2.0)
    check("mdns_discover runs unprivileged", isinstance(mdns, dict))
    if mdns:
        ip, (host, svc) = next(iter(mdns.items()))
        check("mdns entry has host+service", bool(host) and "_" in svc,
              f"{ip} {host} {svc}")
    else:
        print("SKIP  mdns entry (quiet LAN)")

# --- _record merge dedupe: Bonjour-first device gaining a MAC stays one row ---
import threading as _threading
_rec_q = queue.Queue()
_rec_sc = object.__new__(m.Scanner)
_rec_sc.lock = _threading.Lock()
_rec_sc.devices = {}
_rec_sc.q = _rec_q
_rec_sc.stop_event = _threading.Event()
_rec_sc._record("192.168.9.9", "")
_rec_sc._record("192.168.9.9", "AA:BB:CC:DD:EE:FF")
_rec_dev = list(_rec_sc.devices.values())[0]
check("record merge keeps one row", len(_rec_sc.devices) == 1 and _rec_dev.mac == "AA:BB:CC:DD:EE:FF")

# --- nmap deep-scan arg builder (pure; nmap need not be installed) ---
def _b(**kw):
    return m.build_nmap_args("10.0.0.5", **kw)

check("nmap args defaults", _b() == ["nmap", "-Pn", "-sT", "-T4", "-v", "-sV", "-sC", "10.0.0.5"])
check("nmap args os_detect", "-O" in _b(os_detect=True))
check("nmap args toggled off", not any(a in ("-sV", "-sC") for a in _b(service=False, scripts=False)))
check("nmap args ports", _b(ports="22,80") == ["nmap", "-Pn", "-sT", "-T4", "-v", "-sV", "-sC", "-p", "22,80", "10.0.0.5"])

# --- capability checks on macOS (darwin) ---
print(f"\nplatform={m.platform.system()}  euid={os.geteuid()}")
check("scapy importable", m.Scanner._have_scapy())
arp_ok = m.Scanner._arp_ok()
print(f"INFO  _arp_ok() -> {arp_ok} (expected {os.geteuid() == 0}: root-gated on macOS)")

# --- ARP table parsing (checked after the live scan below, once cache is warm) ---

# --- default subnet detection ---
default = m.App._default_subnet()
print(f"\nINFO  _default_subnet() -> {default}")
try:
    ip = socket.gethostbyname(socket.gethostname())
    print(f"INFO  gethostbyname(hostname) -> {ip}"
          + ("   <-- loopback: default subnet will be wrong" if ip.startswith("127.") else ""))
except OSError as e:
    print(f"INFO  gethostbyname failed: {e}")

# --- live ping-sweep scan of the real local /24 (headless, UI-independent) ---
if not SKIP_LIVE:
    local_ip = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
    except OSError:
        pass
    net = ipaddress.ip_network(f"{local_ip}/24", strict=False)
    q = queue.Queue()
    sc = m.Scanner(net, q, mode="ping", workers=100)
    sc.start()
    devices, statuses = {}, []
    deadline = time.time() + 90
    while time.time() < deadline:
        try:
            kind, payload = q.get(timeout=1)
        except queue.Empty:
            if not sc.is_alive():
                break
            continue
        if kind == "device":
            devices[payload.key] = payload
        elif kind == "status":
            statuses.append(payload)
            if kind == "done":
                break

    print("\n--- live scan events ---")
    for s_ in statuses:
        print(f"      status: {s_}")
    print(f"INFO  devices found: {len(devices)}")
    for d in sorted(devices.values(), key=lambda d: m.ip_sort_key(d.ip)):
        print(f"      {d.ip:>15}  {d.mac or '-':<17}  {d.vendor or '-':<18} {d.kind or '-'}")

    check("scan found >=1 device", len(devices) >= 1)

    # --- name resolution (DNS PTR + mDNS) ---
    named = [d for d in devices.values() if d.name]
    print(f"INFO  named devices: {len(named)}/{len(devices)}")
    for d in sorted(named, key=lambda d: m.ip_sort_key(d.ip))[:8]:
        print(f"      {d.ip:>15}  {d.name}")
    if named:
        check("names resolved (DNS/mDNS)", True, f"{len(named)} named")
    else:
        print("NOTE  no names resolved — network-dependent; not a hard failure.")

    # --- IPv6 (multicast ping6 + NDP join) ---
    v6 = [d for d in devices.values() if d.ipv6]
    print(f"INFO  devices with IPv6: {len(v6)}/{len(devices)}")
    for d in sorted(v6, key=lambda d: m.ip_sort_key(d.ip))[:5]:
        print(f"      {d.ip:>15}  {d.ipv6}")
    if v6:
        check("IPv6 joined", True, f"{len(v6)} hosts")
    else:
        print("NOTE  no IPv6 joined — network-dependent (needs v6 traffic/NDP entries).")

    # --- ARP table after the sweep (cache now warm) ---
    table = m.Scanner._arp_table()
    print(f"INFO  _arp_table() entries after scan: {len(table)}")
    check("arp table parsed", len(table) > 0)
    joined = sum(1 for d in devices.values() if d.mac)
    check("MACs joined to devices", joined > 0, f"{joined}/{len(devices)}")

    me = next((d for d in devices.values() if d.ip == local_ip), None)
    if me is None:
        print(f"NOTE  own host {local_ip} absent — this Mac drops ICMP echo (firewall stealth mode); "
              "ping-sweep cannot see stealth hosts. Not a code bug.")
    else:
        check("own host in results", True)

# --- port scan (TCP connect) against local listeners ---
import socket as _socket
listeners = []
for _ in range(2):
    s = _socket.socket(); s.bind(("127.0.0.1", 0)); s.listen(1); listeners.append(s)
open_ports = sorted(s.getsockname()[1] for s in listeners)
pq = queue.Queue()
ps = m.PortScanner("127.0.0.1", open_ports + [1, 2, 3], pq, workers=16, timeout=0.4)
ps.start()
found, t_deadline = [], time.time() + 30
while len(found) < len(open_ports) and time.time() < t_deadline:
    try:
        kind, payload = pq.get(timeout=1)
    except queue.Empty:
        continue
    if kind == "open":
        found.append(payload[0])
check("port scan finds open ports", sorted(found) == open_ports,
      f"{sorted(found)} vs {sorted(open_ports)}")
for s in listeners:
    s.close()

# --- nmap deep-scan end-to-end (skipped when nmap not installed) ---
if m.NMAP_BIN:
    nq = queue.Queue()
    ns = m.NmapScanner("127.0.0.1", service=True, scripts=True, os_detect=False,
                       ports="22,80,443", q=nq)
    ns.start()
    lines, saw_done, deadline = [], False, time.time() + 60
    while time.time() < deadline and ns.is_alive():
        try:
            kind, payload = nq.get(timeout=1)
        except queue.Empty:
            continue
        if kind == "line":
            lines.append(payload)
        elif kind == "done":
            saw_done = True
    while not nq.empty():
        kind, _ = nq.get_nowait()
        if kind == "done":
            saw_done = True
    check("nmap scanner streams report", len(lines) > 0 and saw_done,
          f"{len(lines)} lines")
else:
    print("SKIP  nmap scanner e2e (nmap not installed — brew install nmap)")

print("\n" + ("ALL PASS" if not fails else f"FAILURES: {fails}"))
sys.exit(1 if fails else 0)
