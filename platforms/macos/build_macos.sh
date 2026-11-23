#!/usr/bin/env zsh
set -euo pipefail

# Resolve repository root whether invoked from scripts/ or platforms/macos/
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
if [[ "$SCRIPT_DIR" == */platforms/macos ]]; then
    ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
else
    ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
fi
MAC_DIR="$ROOT_DIR/platforms/macos"
MAC_LIB_DIR="$MAC_DIR/lib"
export VNB_ROOT_DIR="$ROOT_DIR"
export VNB_MAC_DIR="$MAC_DIR"
cd "$ROOT_DIR"

# 1. 编译共享动态库与极简宿主启动器（编译前必须先移除 target/debug 下的动态库软链接，防止链接器覆写已签名 inode）
rm -f target/debug/libvnb_edr_gpui.dylib
export RUSTFLAGS="--remap-path-prefix=$ROOT_DIR=. --remap-path-prefix=$HOME/.cargo=/cargo --remap-path-prefix=$HOME=~ ${RUSTFLAGS:-}"
cargo build --offline

# 2. 部署并对齐 GPUI+EDR 核心动态库到 platforms/macos/lib/（使用 rm -f 先解除旧 inode 映射，防止 macOS AMFI vnode 签名缓存触发 SIGKILL 137）
mkdir -p "$MAC_LIB_DIR"
rm -f "$MAC_LIB_DIR/libvnb_edr_gpui.dylib"
cp -f target/debug/libvnb_edr_gpui.dylib "$MAC_LIB_DIR/libvnb_edr_gpui.dylib"
install_name_tool -id "@loader_path/libvnb_edr_gpui.dylib" "$MAC_LIB_DIR/libvnb_edr_gpui.dylib"
strip -x "$MAC_LIB_DIR/libvnb_edr_gpui.dylib"
codesign --remove-signature "$MAC_LIB_DIR/libvnb_edr_gpui.dylib"

python3 -c '
import struct, os
p = os.path.join(os.environ["VNB_MAC_DIR"], "lib", "libvnb_edr_gpui.dylib")
with open(p, "rb") as f:
    data = bytearray(f.read())
ncmds = struct.unpack_from("<I", data, 16)[0]
off = 32
symtab_cmd_off = None
linkedit_cmd_off = None
for _ in range(ncmds):
    cmd, cmdsize = struct.unpack_from("<II", data, off)
    if cmd == 0x19 and data[off+8:off+24].rstrip(b"\x00") == b"__LINKEDIT":
        linkedit_cmd_off = off
    elif cmd == 0x2:
        symtab_cmd_off = off
    off += cmdsize
stroff, strsize = struct.unpack_from("<II", data, symtab_cmd_off + 16)
if stroff % 8 != 0:
    pad = 8 - (stroff % 8)
    data[stroff:stroff] = b"\x00" * pad
    struct.pack_into("<I", data, symtab_cmd_off + 16, stroff + pad)
    vmsize, fileoff, filesize = struct.unpack_from("<QQQ", data, linkedit_cmd_off + 32)
    struct.pack_into("<Q", data, linkedit_cmd_off + 48, filesize + pad)
    os.remove(p)
    with open(p, "wb") as f:
        f.write(data)
    os.chmod(p, 0o755)
'
codesign -s - -f "$MAC_LIB_DIR/libvnb_edr_gpui.dylib"
if [ -n "${VNB_MODEL_SERVICE_LIB:-}" ] && [ -d "$VNB_MODEL_SERVICE_LIB" ]; then
  rm -f "$VNB_MODEL_SERVICE_LIB/libvnb_edr_gpui.dylib"
  cp -f "$MAC_LIB_DIR/libvnb_edr_gpui.dylib" "$VNB_MODEL_SERVICE_LIB/libvnb_edr_gpui.dylib"
fi

# 3. 裁剪宿主启动器符号并封装到 platforms/macos/
strip -x target/debug/vnb-security-assistant
codesign -s - -f target/debug/vnb-security-assistant
rm -f "$MAC_DIR/vnb-security-assistant"
cp -f target/debug/vnb-security-assistant "$MAC_DIR/vnb-security-assistant"
codesign -s - -f "$MAC_DIR/vnb-security-assistant"

APP_DIR="$MAC_DIR/VNB终端安全助手.app"
mkdir -p "$APP_DIR/Contents/MacOS" "$APP_DIR/Contents/Resources"
rm -f "$APP_DIR/Contents/MacOS/vnb-security-assistant"
cp -f target/debug/vnb-security-assistant "$APP_DIR/Contents/MacOS/vnb-security-assistant"
ln -sfn "../../../lib" "$APP_DIR/Contents/Resources/lib"
ln -sfn "../../../../../models" "$APP_DIR/Contents/Resources/models"
cat > "$APP_DIR/Contents/Info.plist" <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleDisplayName</key>
    <string>VNB终端安全助手</string>
    <key>CFBundleExecutable</key>
    <string>vnb-security-assistant</string>
    <key>CFBundleIdentifier</key>
    <string>com.vnb.edr.security-assistant</string>
    <key>CFBundleInfoDictionaryVersion</key>
    <string>6.0</string>
    <key>CFBundleName</key>
    <string>VNB终端安全助手</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>CFBundleShortVersionString</key>
    <string>2.1.0</string>
    <key>CFBundleVersion</key>
    <string>210</string>
    <key>LSMinimumSystemVersion</key>
    <string>13.0</string>
    <key>NSHighResolutionCapable</key>
    <true/>
</dict>
</plist>
EOF
codesign -s - -f --deep "$APP_DIR"

cat > "$MAC_DIR/启动终端安全.command" <<'EOF'
#!/usr/bin/env zsh
DIR="$(cd "$(dirname "$0")" && pwd)"
open "$DIR/VNB终端安全助手.app"
EOF
chmod +x "$MAC_DIR/启动终端安全.command"

python3 -c '
import os
for root, dirs, files in os.walk(os.path.join(os.environ["VNB_ROOT_DIR"], "target"), topdown=False):
    for f in files:
        fp = os.path.join(root, f)
        if fp != os.path.join(os.environ["VNB_ROOT_DIR"], "target/debug/vnb-security-assistant") and not os.path.islink(fp):
            os.remove(fp)
    for d in dirs:
        dp = os.path.join(root, d)
        if dp != os.path.join(os.environ["VNB_ROOT_DIR"], "target/debug"):
            try: os.rmdir(dp)
            except OSError: pass
local_dylib = os.path.join(os.environ["VNB_ROOT_DIR"], "target/debug/libvnb_edr_gpui.dylib")
if os.path.islink(local_dylib) or os.path.exists(local_dylib):
    os.remove(local_dylib)
os.symlink("../../platforms/macos/lib/libvnb_edr_gpui.dylib", local_dylib)
'
du -sh "$ROOT_DIR" "$MAC_DIR" "$MAC_LIB_DIR"
