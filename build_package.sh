#!/bin/bash
# Build MyLanScan.app + DMG for Apple Silicon Macs (unsigned distribution).
# Recipients: unzip/mount, drag to Applications, right-click -> Open on first launch.
#
# Usage:  ./build_package.sh
set -euo pipefail
cd "$(dirname "$0")"

APP_NAME=MyLanScan
BUILD_VENV=.build-venv
DMG="$APP_NAME-macos-arm64.dmg"
ICON=Sample/assets/MyLanScan.icns
APP_VERSION="$(sed -n 's/^APP_VERSION = "\(.*\)"/\1/p' Sample/S1mvp.py | head -1)"

echo "== cleaning previous artifacts =="
rm -rf "$BUILD_VENV" build dist "$DMG"

echo "== creating throwaway build venv (shipping deps only: no scapy/PySide6) =="
venv/bin/python -m venv "$BUILD_VENV"
"$BUILD_VENV/bin/pip" install --quiet --upgrade pip
"$BUILD_VENV/bin/pip" install --quiet customtkinter zeroconf pyinstaller

echo "== building $APP_NAME.app =="
"$BUILD_VENV/bin/pyinstaller" \
    --windowed \
    --name "$APP_NAME" \
    --icon "$ICON" \
    --osx-bundle-identifier com.mylanscan.app \
    --add-data "Sample/oui.json:." \
    --collect-all customtkinter \
    --noconfirm \
    Sample/S1mvp.py

test -d "dist/$APP_NAME.app"
test -f "dist/$APP_NAME.app/Contents/Frameworks/oui.json"

echo "== stamping version into Info.plist =="
PLIST="dist/$APP_NAME.app/Contents/Info.plist"
/usr/libexec/PlistBuddy -c "Set :CFBundleShortVersionString $APP_VERSION" "$PLIST"
/usr/libexec/PlistBuddy -c "Add :CFBundleVersion string $APP_VERSION" "$PLIST" 2>/dev/null \
    || /usr/libexec/PlistBuddy -c "Set :CFBundleVersion $APP_VERSION" "$PLIST"

echo "== ad-hoc signing (fixes Gatekeeper 'app is damaged') =="
# PyInstaller signs the bundle, but stamping Info.plist above invalidates that
# signature. Re-sign so the signature matches the plist again. Ad-hoc ("-")
# needs no Apple Developer account; recipients still right-click -> Open once.
codesign --force --deep --sign - "dist/$APP_NAME.app"
codesign --verify --deep --strict "dist/$APP_NAME.app"

echo "== creating DMG =="
if command -v create-dmg >/dev/null 2>&1; then
    # create-dmg can exit non-zero on harmless Finder AppleScript hiccups
    create-dmg \
        --volname "$APP_NAME" \
        --icon "$APP_NAME.app" 180 170 \
        --app-drop-link 420 170 \
        --volicon "$ICON" \
        --window-size 620 360 \
        "$DMG" dist/ || test -f "$DMG"
else
    echo "(create-dmg not found — using plain hdiutil layout)"
    hdiutil create -volname "$APP_NAME" -srcfolder dist -format UDZO -ov "$DMG"
fi

echo "== done =="
ls -lh "dist/$APP_NAME.app" "$DMG"
echo "Ship:  $DMG   (recipients: mount, drag to Applications, right-click -> Open once)"
