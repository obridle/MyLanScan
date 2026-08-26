#!/bin/bash
# Build MyLanScan for Linux (x86_64 + arm64) via Docker buildx.
# Output: dist-linux/MyLanScan-linux-x86_64 and MyLanScan-linux-aarch64
# (self-contained single executables; friends just run them).
#
# Usage:  ./build_package_linux.sh
set -euo pipefail
cd "$(dirname "$0")"

OUT_DIR=dist-linux
rm -rf "$OUT_DIR"

echo "== checking docker / buildx =="
command -v docker >/dev/null 2>&1 || { echo "ERROR: docker not found"; exit 1; }
docker buildx version >/dev/null 2>&1 || { echo "ERROR: docker buildx not available"; exit 1; }

echo "== registering QEMU for multi-arch (linux/amd64 + linux/arm64) =="
docker run --privileged --rm tonistiigi/binfmt --install all >/dev/null 2>&1 || true

echo "== building Linux binaries (one arch at a time; first run is slow) =="
mkdir -p "$OUT_DIR"
for platform in "linux/amd64:linux_amd64:MyLanScan-linux-x86_64" \
                "linux/arm64:linux_arm64:MyLanScan-linux-aarch64"; do
    plat="${platform%%:*}"; rest="${platform#*:}"
    src="${rest%%:*}"; dst="${rest##*:}"
    docker buildx build \
        --platform "$plat" \
        --output type=local,dest="$OUT_DIR/$src" \
        .
    # type=local exports the whole container FS; the binary lives under /build/dist
    if [ -f "$OUT_DIR/$src/build/dist/MyLanScan" ]; then
        mv "$OUT_DIR/$src/build/dist/MyLanScan" "$OUT_DIR/$dst"
        rm -rf "$OUT_DIR/$src"
    fi
done

echo "== done =="
ls -lh "$OUT_DIR"
for f in "$OUT_DIR"/*; do
    [ -f "$f" ] && echo "Check arch: $(file -b "$f" | cut -d, -f1-2)"
done
echo "Ship to Linux friends:  dist-linux/MyLanScan-linux-x86_64  (or -aarch64)"
echo "Note: deep scan needs nmap installed:  sudo apt install nmap"