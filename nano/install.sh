#!/bin/sh
# Checked first install only. Does not initialize a vault or alter USB/SSH/boot.
set -eu
[ "$(id -u)" = 0 ] || { echo 'Root required' >&2; exit 1; }
[ "$#" -eq 2 ] || { echo 'Usage: install.sh VERIFIED_RISCV_BINARY EXPECTED_SHA256' >&2; exit 1; }
BINARY=$1
EXPECTED=$2
SRC=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
DEST=/opt/nano-fido
[ "${#EXPECTED}" -eq 64 ] || exit 1
case "$EXPECTED" in *[!0-9a-f]*) exit 1;; esac
actual=$(sha256sum "$BINARY" | awk '{print $1}')
[ "$actual" = "$EXPECTED" ] || { echo 'Binary hash mismatch' >&2; exit 1; }
[ ! -e "$DEST/nano-fido" ] && [ ! -L "$DEST" ] || { echo 'Installation exists; inspect it rather than overwrite.' >&2; exit 1; }
for name in configure.sh service.sh usb-gadget.sh; do
    [ -f "$SRC/$name" ] || exit 1
    sh -n "$SRC/$name"
done
umask 077
mkdir -p "$DEST"
chmod 700 "$DEST"
cp "$BINARY" "$DEST/nano-fido"
chmod 700 "$DEST/nano-fido"
for name in configure.sh service.sh usb-gadget.sh; do
    cp "$SRC/$name" "$DEST/$name"
    chmod 700 "$DEST/$name"
done
echo 'Installed. No vault/PIN was chosen and no USB/SSH/boot change was made.'
echo 'From a trusted independent SSH connection, run: /opt/nano-fido/configure.sh'
