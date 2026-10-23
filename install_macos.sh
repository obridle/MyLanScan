#!/usr/bin/env bash
# install_macos.sh — download the latest MyLanScan DMG, install it to
# /Applications, clear the download-quarantine flag, and launch it.
#
# Usage:
#   bash install_macos.sh              # latest release
#   bash install_macos.sh v0.3.2       # a specific tag
#
# Or straight from the repo:
#   curl -fsSL https://raw.githubusercontent.com/obridle/MyLanScan/main/install_macos.sh | bash
#
# Why this exists: release builds are ad-hoc signed (not notarized yet), so
# macOS Sequoia 15.1+ can block the first launch and offer only "Move to Bin",
# with no "Open Anyway" button in System Settings. Clearing the quarantine flag
# removes the block.
set -euo pipefail

REPO="obridle/MyLanScan"
APP_NAME="MyLanScan"
DMG_NAME="MyLanScan-macos-arm64.dmg"
TAG="${1:-latest}"

if [ "$TAG" = "latest" ]; then
    BASE="https://github.com/$REPO/releases/latest/download"
else
    BASE="https://github.com/$REPO/releases/download/$TAG"
fi

DEST="${DEST:-/Applications/$APP_NAME.app}"
TMP="$(mktemp -d)"
MOUNT="$TMP/mnt"
MOUNTED=0

cleanup() {
    if [ "$MOUNTED" = 1 ]; then
        hdiutil detach "$MOUNT" -quiet >/dev/null 2>&1 || true
    fi
    rm -rf "$TMP"
}
trap cleanup EXIT

if [ "$(uname -s)" != "Darwin" ]; then
    echo "error: this installer is for macOS only." >&2
    exit 1
fi
if [ "$(uname -m)" != "arm64" ]; then
    echo "error: the MyLanScan macOS build is Apple Silicon (arm64) only." >&2
    exit 1
fi

echo "== Downloading MyLanScan ($TAG) =="
curl -fL --progress-bar "$BASE/$DMG_NAME" -o "$TMP/$DMG_NAME"

# Best-effort checksum check against the release's SHA256SUMS.txt.
if curl -fsSL "$BASE/SHA256SUMS.txt" -o "$TMP/SHA256SUMS.txt" 2>/dev/null; then
    SUM_LINE="$(grep "  $DMG_NAME\$" "$TMP/SHA256SUMS.txt" || true)"
    if [ -n "$SUM_LINE" ]; then
        printf '%s\n' "$SUM_LINE" | ( cd "$TMP" && shasum -a 256 -c - >/dev/null )
        echo "   checksum OK"
    fi
fi

echo "== Mounting =="
mkdir -p "$MOUNT"
hdiutil attach -nobrowse -readonly -mountpoint "$MOUNT" "$TMP/$DMG_NAME" >/dev/null
MOUNTED=1

if [ ! -d "$MOUNT/$APP_NAME.app" ]; then
    echo "error: $APP_NAME.app was not found in the DMG." >&2
    exit 1
fi

echo "== Installing to $DEST =="
# Quit a running copy so the bundle can be replaced.
osascript -e "tell application \"$APP_NAME\" to quit" >/dev/null 2>&1 || true
if [ -e "$DEST" ]; then
    rm -rf "$DEST" 2>/dev/null || sudo rm -rf "$DEST"
fi
cp -R "$MOUNT/$APP_NAME.app" "$DEST" 2>/dev/null || sudo cp -R "$MOUNT/$APP_NAME.app" "$DEST"

echo "== Clearing quarantine =="
xattr -dr com.apple.quarantine "$DEST" 2>/dev/null || sudo xattr -dr com.apple.quarantine "$DEST"

echo "== Done =="
echo "$APP_NAME installed at $DEST"
if ! open "$DEST" 2>/dev/null; then
    echo "Installed, but macOS did not launch it automatically."
    echo "Double-click it in /Applications, or run:"
    echo "  xattr -dr com.apple.quarantine \"$DEST\""
fi
