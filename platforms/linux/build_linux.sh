#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
LINUX_DIR="$ROOT_DIR/platforms/linux"
LINUX_LIB_DIR="$LINUX_DIR/lib"

cd "$ROOT_DIR"

echo "[1/3] Compiling VNB Security Assistant for Linux..."
export RUSTFLAGS="--remap-path-prefix=$ROOT_DIR=. --remap-path-prefix=$HOME/.cargo=/cargo --remap-path-prefix=$HOME=~ ${RUSTFLAGS:-}"
cargo build --release

echo "[2/3] Staging Linux executable and shared library (.so) into platforms/linux/..."
mkdir -p "$LINUX_LIB_DIR"
cp -f target/release/vnb-security-assistant "$LINUX_DIR/vnb-security-assistant"
cp -f target/release/libvnb_edr_gpui.so "$LINUX_LIB_DIR/libvnb_edr_gpui.so"
strip --strip-unneeded "$LINUX_DIR/vnb-security-assistant" "$LINUX_LIB_DIR/libvnb_edr_gpui.so" || true
chmod +x "$LINUX_DIR/vnb-security-assistant" "$LINUX_DIR/start_linux_edr.sh"

echo "[3/3] Verifying ABI info..."
"$LINUX_DIR/vnb-security-assistant" --abi-info
echo "Build complete: $LINUX_DIR"
