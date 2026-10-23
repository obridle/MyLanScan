#!/bin/bash
# Build MyLanScan.app + DMG for Apple Silicon Macs.
# Recipients: mount, drag to Applications, then open (see the README's macOS install notes).
#
# Usage:  ./build_package.sh
#
# Signing/notarization (optional, via environment):
#   SIGN_IDENTITY   codesign identity, e.g. "Developer ID Application: Name (TEAMID)".
#                   Default "-" = ad-hoc, which Gatekeeper warns about on first launch.
#   ENTITLEMENTS    hardened-runtime entitlements plist (default: Sample/assets path below).
#   NOTARY_PROFILE  notarytool keychain profile name, OR supply all of
#   NOTARY_APPLE_ID / NOTARY_PASSWORD / NOTARY_TEAM_ID
#                   (NOTARY_PASSWORD = an app-specific password). With a real
#                   SIGN_IDENTITY the DMG is notarized and the ticket stapled.
set -euo pipefail
cd "$(dirname "$0")"

APP_NAME=MyLanScan
BUILD_VENV=.build-venv
STAGE=.dmg-stage
DMG="$APP_NAME-macos-arm64.dmg"
ICON=Sample/assets/MyLanScan.icns
ENTITLEMENTS="${ENTITLEMENTS:-Sample/assets/entitlements.plist}"
SIGN_IDENTITY="${SIGN_IDENTITY:--}"
APP_VERSION="$(sed -n 's/^APP_VERSION = "\(.*\)"/\1/p' Sample/S1mvp.py | head -1)"

echo "== cleaning previous artifacts =="
rm -rf "$BUILD_VENV" build dist "$STAGE" "$DMG"

echo "== creating throwaway build venv (shipping deps only: no scapy/PySide6) =="
venv/bin/python -m venv "$BUILD_VENV"
"$BUILD_VENV/bin/pip" install --quiet --upgrade pip
"$BUILD_VENV/bin/pip" install --quiet customtkinter zeroconf pyinstaller

echo "== building $APP_NAME.app =="
# With a Developer ID, let PyInstaller sign every nested binary as it builds
# (inside-out). We re-sign the outer bundle after stamping Info.plist below.
PYINSTALLER_SIGN=()
if [ "$SIGN_IDENTITY" != "-" ]; then
    PYINSTALLER_SIGN=(--codesign-identity "$SIGN_IDENTITY")
    [ -f "$ENTITLEMENTS" ] && PYINSTALLER_SIGN+=(--osx-entitlements-file "$ENTITLEMENTS")
fi
"$BUILD_VENV/bin/pyinstaller" \
    --windowed \
    --name "$APP_NAME" \
    --icon "$ICON" \
    --osx-bundle-identifier com.mylanscan.app \
    --add-data "Sample/oui.json:." \
    --collect-all customtkinter \
    --noconfirm \
    ${PYINSTALLER_SIGN[@]+"${PYINSTALLER_SIGN[@]}"} \
    Sample/S1mvp.py

test -d "dist/$APP_NAME.app"
test -f "dist/$APP_NAME.app/Contents/Frameworks/oui.json"

echo "== stamping version into Info.plist =="
PLIST="dist/$APP_NAME.app/Contents/Info.plist"
/usr/libexec/PlistBuddy -c "Set :CFBundleShortVersionString $APP_VERSION" "$PLIST"
/usr/libexec/PlistBuddy -c "Add :CFBundleVersion string $APP_VERSION" "$PLIST" 2>/dev/null \
    || /usr/libexec/PlistBuddy -c "Set :CFBundleVersion $APP_VERSION" "$PLIST"

if [ "$SIGN_IDENTITY" = "-" ]; then
    echo "== ad-hoc signing (fixes Gatekeeper 'app is damaged') =="
    # PyInstaller signs the bundle, but stamping Info.plist above invalidates that
    # signature. Re-sign so the signature matches the plist again. Ad-hoc ("-")
    # needs no Apple Developer account; recipients still must approve first launch.
    codesign --force --deep --sign - "dist/$APP_NAME.app"
    codesign --verify --deep --strict "dist/$APP_NAME.app"
else
    echo "== signing with Developer ID: $SIGN_IDENTITY =="
    # PyInstaller signed the nested binaries; re-sign the outer bundle (hardened
    # runtime + entitlements + secure timestamp, all required for notarization)
    # so it matches the freshly stamped Info.plist.
    codesign --force --options runtime --timestamp \
        --entitlements "$ENTITLEMENTS" --sign "$SIGN_IDENTITY" "dist/$APP_NAME.app"
    codesign --verify --deep --strict --verbose=2 "dist/$APP_NAME.app"
fi

# PyInstaller's onedir output also leaves dist/MyLanScan/ next to the .app.
# Stage only the .app so the mounted DMG shows just the app + Applications link.
echo "== staging the app for the DMG =="
rm -rf "$STAGE"
mkdir -p "$STAGE"
cp -R "dist/$APP_NAME.app" "$STAGE/"

echo "== creating DMG =="
if command -v create-dmg >/dev/null 2>&1; then
    # create-dmg can exit non-zero on harmless Finder AppleScript hiccups
    create-dmg \
        --volname "$APP_NAME" \
        --icon "$APP_NAME.app" 180 170 \
        --app-drop-link 420 170 \
        --volicon "$ICON" \
        --window-size 620 360 \
        "$DMG" "$STAGE" || test -f "$DMG"
else
    echo "(create-dmg not found — using plain hdiutil layout)"
    hdiutil create -volname "$APP_NAME" -srcfolder "$STAGE" -format UDZO -ov "$DMG"
fi
rm -rf "$STAGE"

# Notarize the DMG so Gatekeeper accepts it on a normal double-click. That needs
# a real Developer ID plus Apple credentials (see the header). Without them we
# keep the ad-hoc build so local/dev builds still work.
if [ "$SIGN_IDENTITY" != "-" ]; then
    NOTARY_ARGS=()
    if [ -n "${NOTARY_PROFILE:-}" ]; then
        NOTARY_ARGS=(--keychain-profile "$NOTARY_PROFILE")
    elif [ -n "${NOTARY_APPLE_ID:-}" ] && [ -n "${NOTARY_PASSWORD:-}" ] && [ -n "${NOTARY_TEAM_ID:-}" ]; then
        NOTARY_ARGS=(--apple-id "$NOTARY_APPLE_ID" --password "$NOTARY_PASSWORD" --team-id "$NOTARY_TEAM_ID")
    fi

    if [ ${#NOTARY_ARGS[@]} -gt 0 ]; then
        echo "== notarizing the DMG with Apple (can take a few minutes) =="
        xcrun notarytool submit "$DMG" ${NOTARY_ARGS[@]+"${NOTARY_ARGS[@]}"} --wait
        echo "== stapling the notarization ticket =="
        xcrun stapler staple "$DMG"
        xcrun stapler validate "$DMG"
        echo "== Gatekeeper assessment =="
        spctl -a -vvv -t open --context context:primary-signature "$DMG"
    else
        echo "!! Developer ID signing requested but no notarization credentials set."
        echo "   Set NOTARY_PROFILE or NOTARY_APPLE_ID/NOTARY_PASSWORD/NOTARY_TEAM_ID"
        echo "   — skipping notarization (Gatekeeper will still warn on first launch)."
    fi
fi

echo "== done =="
ls -lh "dist/$APP_NAME.app" "$DMG"
if [ "$SIGN_IDENTITY" = "-" ]; then
    echo "Ship:  $DMG   (unsigned/ad-hoc; see the README's macOS install notes)"
else
    echo "Ship:  $DMG   (Developer ID signed; notarized if credentials were provided)"
fi
