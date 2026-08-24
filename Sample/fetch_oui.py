"""Fetch the IEEE OUI list once and convert it to Sample/oui.json.

Run:  venv/bin/python Sample/fetch_oui.py
Re-run any time to refresh (IEEE updates the file continuously).
"""
import csv
import json
import sys
import urllib.request
from pathlib import Path

URL = "https://standards-oui.ieee.org/oui/oui.csv"
HERE = Path(__file__).resolve().parent
DEST = HERE / "oui.json"


def main() -> int:
    print(f"downloading {URL} …")
    req = urllib.request.Request(URL, headers={"User-Agent": "Mozilla/5.0 (fetch_oui)"})
    raw = urllib.request.urlopen(req, timeout=60).read()
    entries: dict[str, str] = {}
    for row in csv.reader(raw.decode("utf-8", "replace").splitlines()):
        if len(row) < 3 or row[0] == "Registry":
            continue
        prefix = row[1].strip().upper()
        org = " ".join(row[2].split())          # collapse whitespace
        if len(prefix) == 6 and all(c in "0123456789ABCDEF" for c in prefix):
            oui = ":".join(prefix[i:i + 2] for i in range(0, 6, 2))
            entries.setdefault(oui, org)         # first registration wins
    DEST.write_text(json.dumps(entries, ensure_ascii=False), encoding="utf-8")
    print(f"wrote {len(entries)} OUIs -> {DEST}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
