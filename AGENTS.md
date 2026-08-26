# AGENTS.md

## Status

Scaffold + first validated sample (`Sample/S1mvp.py`, customtkinter MVP) as of 2026-08.
No package layout/lint config yet. When tooling lands, replace this section with verified
commands and delete anything stale below.

Verified so far: `venv/bin/python Sample/S1mvp_test.py` (headless logic + live /24 sweep)
and a GUI smoke test both pass on this Mac.

## Distribution (Apple Silicon, unsigned)

Build: `./build_package.sh` → `MyLanScan-macos-arm64.dmg` (~28 MB).
Uses a throwaway `.build-venv` with only shipping deps (customtkinter, zeroconf,
pyinstaller — no scapy/PySide6). Verified: bundled app launches, oui.json lands in
Contents/Frameworks and loads via sys._MEIPASS.

**Code signing**: PyInstaller ad-hoc signs the bundle, but stamping Info.plist after
the build invalidates that signature — the build script therefore re-runs
`codesign --force --deep --sign -` and verifies. This fixes the Gatekeeper "app is
damaged" error on downloads. Ad-hoc (no Developer ID) still means recipients need
right-click → Open once; fallback `xattr -dr com.apple.quarantine <app>`. Rebuild
after any S1mvp.py change.

## Scope (feature baseline)

`MyLanScan` — macOS desktop app (Python + PySide6 GUI, not a CLI), feature parity with LanScan:

1. ARP-based discovery on the local subnet → IP, hostname, MAC, vendor (OUI lookup), status
2. Port scanning of selected hosts: top-N common ports first, then full 1–65535 ranges
3. Service identification: banner grabbing / nmap-style service match
4. OS fingerprinting: heuristics or nmap-based
5. Two modes: fast ping sweep vs. deep scan (ports + services + OS)
6. CSV export, refresh/rescan, filter/sort

Discovery note: as well as ping/ARP, every scan browses Bonjour/mDNS
(`Scanner._scan_mdns` → `mdns_discover`) to catch stealth Apple devices that drop
ICMP; announcements become new device rows (Type inferred from service via
`SVC_KIND`/`kind_from_service`) and MAC is filled by an ARP poke (quick TCP connect
then `arp -n`). `_record` merges by IP so a Bonjour-first host that later gains a
MAC stays a single row.

Nmap note: the per-host "Deep scan" shells out to the `nmap` CLI (never bundled — GPL
+ size; recipients install `brew install nmap` / `sudo apt install nmap`). Deep scan
runs unprivileged (`-sT -sV -sC`). OS detection (`-O`) needs root: when the app is
unprivileged it's elevated per-run — macOS via osascript `do shell script … with
administrator privileges`, Linux via `pkexec sh -c` — writing to a tailed temp file;
if the app sees euid 0 it runs directly. Never prompt for app-wide sudo.

Linux (added 2026-08, branch `linux-port`, v0.3.0): platform branches live alongside
the macOS ones — `ip neigh show`/`ip route`/`ip -6 neigh` (`_arp_for`, `_default_iface`,
`_ndp_table`), `ping -6 -I` for IPv6, `/usr/bin|/usr/sbin/nmap` in `_find_nmap`,
`pkexec` elevation, and a labelled app-menu in `_build_menubar` (non-macOS). Build:
`./build_package_linux.sh` (Docker buildx, Debian base for tkinter) → one-file
binaries in `dist-linux/`. macOS behavior is unchanged — regression-check with
`venv/bin/python Sample/S1mvp_test.py` on the Mac after touching shared code.

Privilege note: discovery (1) works unprivileged-ish; SYN scanning and OS fingerprinting
need raw sockets/root, plain TCP connect() does not — make elevation optional and degrade
gracefully rather than requiring sudo for basic use. A GUI app can't just be `sudo`-run;
plan for an elevated helper or graceful fallback to connect()-based scanning.

Architecture note: keep the scanning engine a plain-Python package independent of Qt.
Scans must run off the UI thread (QThread/worker + signals) — blocking the Qt main loop
freezes the window.

## Environment

- Virtualenv at `venv/` (note: not `.venv`), Python 3.14. Install/run via
  `venv/bin/pip install ...` and `venv/bin/python ...` — don't use system Python or recreate the venv.
- Homebrew Python has no tkinter by default — only matters for the legacy customtkinter
  sample; if needed: `brew install python-tk@3.14` (done on this machine). PySide6 needs nothing extra.
- Dependencies: `venv/bin/pip install -r requirements.txt` (PySide6, scapy, zeroconf;
  customtkinter kept only until `Sample/S1mvp.py` is ported to PySide6).
- UI framework decision (2026-08): **PySide6** — S1mvp's customtkinter was validated but
  is being replaced; don't extend the tkinter code.
- **macOS is the primary target; Linux added 2026-08 (v0.3.0, branch `linux-port`)**
  — dev machine is a Mac. Write platform branches alongside the macOS ones (`ip neigh`
  on Linux vs `arp -n` on macOS); don't carry Windows/BSD branches unless requested.
  - ICMP echo requires root/setuid unless using unprivileged techniques
    (e.g. UDP datagram trick) — prefer stdlib/subprocess over scapy to avoid the dependency
    unless packet crafting becomes necessary.
- Vendor (OUI) lookup: full IEEE table lives in `Sample/oui.json` (~40k entries, 1.5 MB,
  loaded at startup; built-in 20-entry subset overrides common vendors with short names).
  Refresh with `venv/bin/python Sample/fetch_oui.py` (downloads standards-oui.ieee.org
  once — needs a User-Agent header or the server returns HTTP 418). No network calls per device.
- Scanning other people's networks without authorization is illegal; default scope is the
  dev machine's own subnet and keep it that way — full-range port scanning makes this doubly
  important.

## Conventions

None established yet. First implementation should pick: package layout (`src/mylanscan/`),
formatter/linter (suggest ruff), and test runner (pytest) — then record them here with exact commands.

Releases: app version lives in `APP_VERSION` at the top of `Sample/S1mvp.py` (shown in
window title + Help dialog). Bump it, rerun tests, rebuild the DMG. `build_package.sh`
stamps the version into Info.plist automatically and bundles the app + volume icons
from `Sample/assets/MyLanScan.icns` (regenerate with `Sample/assets/make_icon.py`,
needs pillow in the main venv — dev-only).

Testing approach (user-directed): build small sample code to exercise each base feature as
it lands — verify discovery, port scan, service ID, etc. incrementally rather than testing
only at the end. Samples live in `Sample/` (`S1mvp.py` = discovery MVP,
`S1mvp_test.py` = headless validation incl. live /24 sweep; run with venv python).

Gotchas proven on this network/Mac:
- This Mac drops ICMP echo (firewall stealth mode) → ping sweep never sees it; ARP-based
  discovery is required to catch such hosts.
- Right after a /24 ping sweep, `arp -a` can exceed a short subprocess timeout while the
  kernel table settles — retry once (S1mvp does) or MAC joins silently fail.
- **macOS strips leading zeros in ARP MAC octets** (`e0:98:6:da:33:3f`, 15 chars, not 17).
  Any regex/parser assuming fixed-width colon-separated pairs silently drops those entries;
  normalize per-group (`zfill(2)`), don't strip-and-count hex digits. Quiet IoT hosts also
  expire their kernel ARP entries within seconds — read each host's entry right after its
  ping succeeds (`arp -n <ip>`), not once at end of sweep.
- macOS has no `AF_PACKET`; raw packet send goes through BPF/libpcap (scapy), root only.
- iOS/Android **Private Wi-Fi Addresses** are randomized: the MAC's locally-administered
  bit (octet-1 `& 0x02`) is set and the OUI is fake, so the IEEE table has no vendor.
  `vendor_for` flags these as "Private MAC (randomized)" rather than mis-attributing a
  vendor; the real device type still shows from mDNS (`kind_from_service`).
