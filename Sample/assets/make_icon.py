#!/usr/bin/env python3
"""Generate the MyLanScan app icon (radar/network theme) and build MyLanScan.icns.

Dev-only tool — not part of the app or bundle. Needs Pillow + macOS sips/iconutil:
    venv/bin/pip install pillow
    venv/bin/python Sample/assets/make_icon.py
"""
from __future__ import annotations

import subprocess
from pathlib import Path

from PIL import Image, ImageDraw

HERE = Path(__file__).resolve().parent
OUT = HERE / "MyLanScan.icns"
S = 1024

GRAD_TOP = (35, 48, 71)
GRAD_BOT = (15, 22, 38)
ACCENT = (72, 187, 120)      # green
ACCENT_BRIGHT = (154, 230, 180)
DOT = (236, 246, 240)
RING = (200, 215, 230)


def _bg_gradient(img, d):
    for y in range(S):
        t = y / (S - 1)
        col = tuple(int(a + (b - a) * t) for a, b in zip(GRAD_TOP, GRAD_BOT))
        d.line([(0, y), (S, y)], fill=col)
    d.rounded_rectangle([0, 0, S - 1, S - 1], radius=180, outline=(0, 0, 0, 60), width=4)


def _radar(img, d):
    cx, cy = S / 2, S / 2 - 20
    for r in (130, 235, 340, 445):
        d.ellipse([cx - r, cy - r, cx + r, cy + r], outline=RING + (70,), width=8)
    d.line([(cx, cy), (cx + 445, cy)], fill=RING + (50,), width=6)
    d.line([(cx, cy), (cx, cy - 445)], fill=RING + (50,), width=6)

    # sweep wedge
    d.pieslice([cx - 445, cy - 445, cx + 445, cy + 445],
               315, 375, fill=ACCENT + (80,))
    d.pieslice([cx - 445, cy - 445, cx + 445, cy + 445],
               358, 362, fill=ACCENT_BRIGHT + (200,))

    # device blips: (angle deg from +x axis, radius, size) — inside the sweep
    for ang, r, size in ((355, 260, 30), (345, 150, 22), (5, 380, 26),
                         (330, 330, 20), (20, 120, 18)):
        import math
        rad = math.radians(ang)
        x, y = cx + r * math.cos(rad), cy - r * math.sin(rad)
        d.ellipse([x - size * 1.6, y - size * 1.6, x + size * 1.6, y + size * 1.6],
                  fill=DOT + (60,))
        d.ellipse([x - size / 2, y - size / 2, x + size / 2, y + size / 2], fill=DOT)


def _center_dot(img, d):
    d.ellipse([S / 2 - 18, S / 2 - 38, S / 2 + 18, S / 2 - 2], fill=ACCENT_BRIGHT)


def build_icns():
    img = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    _bg_gradient(img, d)
    _radar(img, d)
    _center_dot(img, d)

    iconset = HERE / "MyLanScan.iconset"
    iconset.mkdir(exist_ok=True)
    sizes = [(16, "16x16"), (32, "16x16@2x"), (32, "32x32"), (64, "32x32@2x"),
             (128, "128x128"), (256, "128x128@2x"), (256, "256x256"),
             (512, "256x256@2x"), (512, "512x512"), (1024, "512x512@2x")]
    png = HERE / "MyLanScan_1024.png"
    img.save(png)
    for size, name in sizes:
        img.resize((size, size), Image.LANCZOS).save(iconset / f"icon_{name}.png")
    subprocess.run(["iconutil", "-c", "icns", str(iconset), "-o", str(OUT)],
                   check=True)
    for f in iconset.iterdir():
        f.unlink()
    iconset.rmdir()
    png.unlink()
    print(f"wrote {OUT} ({OUT.stat().st_size} bytes)")


if __name__ == "__main__":
    build_icns()
