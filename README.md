# MyLanScan

LAN scanner for **macOS and Linux** — feature parity with LanScan. Python + customtkinter desktop app.

## Download

Prebuilt, self-contained releases are on the
[Releases page](https://github.com/obridle/MyLanScan/releases/latest) — no Python required.

| Platform | Artifact | Install |
|---|---|---|
| macOS (Apple Silicon) | `MyLanScan-macos-arm64.dmg` | Open the DMG, drag **MyLanScan** to **Applications** — then see [macOS install notes](#macos-dmg) for the one-time Gatekeeper step (unsigned build). |
| Linux x86_64 | `MyLanScan-linux-x86_64` | `chmod +x MyLanScan-linux-x86_64 && ./MyLanScan-linux-x86_64` |
| Linux arm64 | `MyLanScan-linux-aarch64` | Raspberry Pi OS, arm64 VMs — same as above. |

Verify your download against `SHA256SUMS.txt` (also on the Releases page). Deep scan needs
nmap installed (`brew install nmap` / `sudo apt install nmap`). The macOS build is Apple
Silicon only; the Linux binaries need Debian 12+ / Ubuntu 22.04+ or newer.

## Features (current)

- **Host discovery** on the local subnet: ping sweep + per-host ARP lookup, plus
  **Bonjour/mDNS browsing** so Apple devices that ignore ping (stealth mode) still show up
  → IP, hostname (DNS PTR), mDNS name, IPv6, MAC, vendor (full IEEE OUI table), device type
  (AirPlay, HomeKit, iPhone/iPad, printer, … inferred from the announcing service)
- **Port scanning** per host: right-click a row → *Port scan* → quick (~100 common ports)
  or full 1–65535 TCP connect scan, live results with service names
- **Deep scan (nmap)** per host: right-click a row → *Deep scan (nmap)* — service
  versions (`-sV`), default NSE scripts (`-sC`), and OS detection (`-O`) when run with
  admin rights; the full nmap report streams live
- **Rescan in place**: re-scans update existing rows; devices absent from the latest scan are pruned
- **CSV export**, sortable columns, drag-to-resize columns, horizontal scrolling
- Unprivileged: no sudo needed for everyday use (ICMP/ARP/TCP-connect only)

## Requirements (running from source)

**macOS**
- Homebrew Python 3.14 + `brew install python-tk@3.14` (tkinter bindings)
- `python3.14 -m venv venv && venv/bin/pip install -r requirements.txt`
- `venv/bin/python Sample/fetch_oui.py` once (downloads the IEEE OUI table → `Sample/oui.json`)

**Linux (Debian/Ubuntu)**
- `sudo apt install python3 python3-tk python3-pip`
- `python3 -m venv venv && venv/bin/pip install -r requirements.txt`
- `venv/bin/python Sample/fetch_oui.py` once

Run: `venv/bin/python Sample/S1mvp.py`

Optional (deep scan): `brew install nmap` (macOS) / `sudo apt install nmap` (Linux)

Tests: `venv/bin/python Sample/S1mvp_test.py` (headless logic checks + live /24 sweep)

## Build & release

Two build scripts, one per platform — both produce self-contained artifacts with no
Python required on the recipient's machine. Rebuild after every source change; the
artifacts are snapshots, not live links.

### Cutting a release (CI)

Releases are built and published by [`.github/workflows/release.yml`](.github/workflows/release.yml).
Pushing a version tag is all it takes:

1. Bump `APP_VERSION` and add a matching entry to the `RELEASES` changelog in `Sample/S1mvp.py`
2. Run the tests locally: `venv/bin/python Sample/S1mvp_test.py`
3. Commit, then tag and push:

   ```sh
   git tag -a v0.3.0 -m "v0.3.0"
   git push origin v0.3.0
   ```

4. CI runs the test job, builds the macOS DMG and both Linux binaries, and publishes a
   Release with `SHA256SUMS.txt` attached. The test job fails if the tag doesn't match
   `APP_VERSION`, so the two can never drift.

The per-platform sections below describe the same builds run locally (useful for a
pre-release smoke test or when CI is unavailable).

### macOS (DMG)

```sh
./build_package.sh
```

Produces **`MyLanScan-macos-arm64.dmg`** (~28 MB) — a self-contained Apple Silicon app.
The script uses a throwaway `.build-venv` with shipping deps only
(customtkinter, zeroconf, pyinstaller — no scapy/PySide6), so the bundle stays small.

**Release checklist:**
1. Make your changes to `Sample/S1mvp.py`
2. Run the test suite: `venv/bin/python Sample/S1mvp_test.py`
3. Rebuild: `./build_package.sh`
4. Smoke-test the artifact: mount the DMG, copy the app out, launch it,
   run one scan + one port scan (vendors must resolve — proves `oui.json` bundled)
5. Send `MyLanScan-macos-arm64.dmg` to recipients

The app icon and mounted-volume icon come from `Sample/assets/MyLanScan.icns`.
To redesign it: edit `Sample/assets/make_icon.py` (Pillow, radar theme) then run
`venv/bin/python Sample/assets/make_icon.py` to regenerate the `.icns` before rebuilding.

**Installing (recipients):**
1. Open the `.dmg`, drag **MyLanScan** onto the **Applications** shortcut, eject.
2. First launch — **macOS Sequoia (15) and later**:
   1. Double-click **MyLanScan**. macOS blocks it and offers to move it to the Bin —
      click **Done** / **Cancel**, do *not* move it to the Bin.
   2. Open **System Settings → Privacy & Security** and scroll to the **Security**
      section. Click **Open Anyway** next to the message that MyLanScan was blocked.
   3. Enter your login password, then click **Open**. You only do this once.
3. First launch — **macOS Sonoma (14) and earlier**: Control-click (or right-click)
   the app → **Open** → **Open**.
4. After the first successful launch it opens like any other app. No Python or other
   dependencies needed.

> **Why this is needed / Sequoia changed the steps.** MyLanScan is **ad-hoc signed**
> (which avoids the "app is damaged" error) but *not notarized* — that needs a paid
> Apple Developer account. Since **macOS Sequoia (15)**, the old
> Control-click → **Open** shortcut **no longer bypasses Gatekeeper**, and on
> **macOS 15.1** the **Open Anyway** button may not even appear. If you're stuck:
>
> - Remove the download quarantine flag, then launch again:
>
>   ```sh
>   xattr -dr com.apple.quarantine /Applications/MyLanScan.app
>   ```
>
> - Or re-try the System Settings route: attempt to open the app once, then go to
>   **Privacy & Security → Security → Open Anyway** (the button is available for about
>   an hour after the attempt).
>
> The reliable long-term fix is an Apple **Developer ID** (paid) plus notarization,
> which removes all of these prompts.

Apple Silicon Macs only (the build is `arm64`).

### Linux (Docker)

```sh
./build_package_linux.sh
```

Produces self-contained single executables via Docker (Debian-based; needs Docker
Desktop or any Docker with buildx). Builds both architectures:

```
dist-linux/MyLanScan-linux-x86_64     # x86_64 desktops
dist-linux/MyLanScan-linux-aarch64    # ARM (Raspberry Pi OS, Apple-silicon VMs…)
```

**Release checklist:**
1. Make your changes to `Sample/S1mvp.py`
2. Run the test suite on a Linux container:
   `docker run --rm -v "$PWD":/src debian:bookworm-slim bash -c "apt-get update && apt-get install -y python3 python3-tk python3-pip nmap && pip install --break-system-packages customtkinter zeroconf scapy && cd /src && python3 Sample/S1mvp_test.py"`
   > All pure-logic checks must PASS. `scan found >=1 device` and `MACs joined`
   > are network-dependent and legitimately FAIL inside an isolated container —
   > they need to reach your LAN, so run those on a real machine.
3. Rebuild: `./build_package_linux.sh`
4. Smoke-test: launch the binary under X (`xvfb-run -a ./dist-linux/MyLanScan-linux-aarch64`)
5. Zip/tar the binary and send to recipients

**Installing (recipients):** download the right binary for their machine and run it
(no Python needed). Deep scan needs `sudo apt install nmap`; OS detection uses the
graphical PolicyKit prompt (`pkexec`).

## Usage

Launch the app (`venv/bin/python Sample/S1mvp.py` from source, or the installed
MyLanScan from the DMG build):

1. **Subnet** — prefilled with your local /24 (e.g. `192.168.0.0/24`); edit if needed
2. **Mode** — *Auto* picks ARP scanning when raw-socket access is available (root),
   otherwise a ping sweep; you can force either
3. **Workers** — parallel probe count; 100 suits most home LANs
4. **Start scan** — results stream in live: IP, name (DNS/mDNS), IPv6, MAC, vendor, type.
   The button becomes **Re-scan**: subsequent scans update existing rows in place and
   prune devices that disappeared; nothing flickers away mid-scan
5. **Port scan** — right-click (or ctrl-click) any row → *Port scan <ip>*:
   - *Quick*: ~100 common ports, done in seconds
   - *Full*: all 1–65535, about a minute per host
   Open ports appear live with service names (http, afp, ssh …); **Export** saves the
   results as CSV
6. **Deep scan** — right-click any row → *Deep scan (nmap) <ip>* for the full nmap
   deep dive (service versions + NSE scripts; tick **OS detection** for fingerprinting —
   macOS asks for your admin password once, Linux via a PolicyKit prompt; the app itself
   never needs to run as root). **Export** saves the full report as text. Requires nmap
   installed: `brew install nmap` (macOS) / `sudo apt install nmap` (Linux)
7. **Table controls** — click a header to sort, drag header separators to resize,
   double-click a separator to auto-fit that column, horizontal scrollbar for overflow
8. **Export CSV** — writes every listed device to a spreadsheet-friendly file
9. **Help** — the **Help** menu in the macOS menu bar (⌘?) opens the in-app guide;
   **Release Notes** shows the changelog per version; **About MyLanScan** lives in the
   app menu next to the Apple logo

## License

Released under the [MIT License](LICENSE) — Copyright (c) 2026 MyLanScan contributors.

## Repo layout

| path | purpose |
|---|---|
| `Sample/S1mvp.py` | the app (single-file MVP) |
| `Sample/S1mvp_test.py` | headless validation incl. live /24 sweep |
| `Sample/fetch_oui.py` | refreshes `Sample/oui.json` from IEEE |
| `Sample/oui.json` | ~40k IEEE OUI entries (generated, do not edit) |
| `build_package.sh` | builds the macOS release DMG |
| `build_package_linux.sh` | builds the Linux binaries (x86_64 + aarch64) via Docker |
| `Dockerfile` | Debian-based Linux build image (system Python for tkinter) |
| `Sample/assets/make_icon.py` | regenerates `Sample/assets/MyLanScan.icns` (dev-only, Pillow) |
| `AGENTS.md` | instructions for AI coding agents |

## Legal note

Scanning networks you don't own or lack authorization for is illegal.
This tool defaults to your own subnet — keep it that way.
