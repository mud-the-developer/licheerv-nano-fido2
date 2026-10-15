#!/bin/sh
# Managed HID only; never reads/removes vaults or changes existing network links.
set -eu
[ "$(id -u)" = 0 ] || exit 1
G=/sys/kernel/config/usb_gadget/g0
CFG=$G/configs/c.1
FUNC=$G/functions/hid.usb0
LINK=$CFG/hid.usb0
RUN=/run/nano-fido
[ -d "$CFG" ] || { echo 'Official g0/c.1 configuration missing' >&2; exit 1; }
umask 077
mkdir -p "$RUN"
chmod 700 "$RUN"

restore() {
    [ -f "$RUN/usb.udc" ] || return 0
    IFS= read -r udc < "$RUN/usb.udc"
    [ -d "/sys/class/udc/$udc" ] || exit 1
    if [ -L "$LINK" ]; then
        [ "$(readlink -f "$LINK")" = "$FUNC" ] || { echo 'Unexpected HID link' >&2; exit 1; }
    fi
    current=$(cat "$G/UDC")
    if [ -n "$current" ]; then
        [ "$current" = "$udc" ] || exit 1
        printf '\n' > "$G/UDC"
    fi
    [ ! -L "$LINK" ] || rm "$LINK"
    printf '%s\n' "$udc" > "$G/UDC"
    [ ! -e /proc/cviusb/otg_role ] || printf 'device\n' >/proc/cviusb/otg_role
    sleep 2
    [ "$(cat "$G/UDC")" = "$udc" ] || { echo 'USB restoration not confirmed' >&2; exit 1; }
    rm "$RUN/usb.udc"
    echo 'Original network-only USB configuration restored.'
}

case "${1:-}" in
add)
    [ -L "$CFG/ncm.usb0" ] || [ -L "$CFG/rndis.usb0" ] || { echo 'Expected USB network function missing' >&2; exit 1; }
    [ ! -L "$LINK" ] || { echo 'HID is already linked; refuse to take ownership' >&2; exit 1; }
    [ ! -e "$RUN/usb.udc" ] || { echo 'Prior managed USB state exists; inspect first' >&2; exit 1; }
    for existing in "$G"/functions/hid.*; do
        [ ! -d "$existing" ] || [ "$existing" = "$FUNC" ] || { echo 'Another HID function exists; stop' >&2; exit 1; }
    done
    printf '%b' '\006\320\361\011\001\241\001\011\040\025\000\046' \
        '\377\000\165\010\225\100\201\002\011\041\025\000' \
        '\046\377\000\165\010\225\100\221\002\300' > "$RUN/expected.desc"
    if [ ! -d "$FUNC" ]; then
        mkdir "$FUNC"
        printf '0\n' > "$FUNC/subclass"
        printf '0\n' > "$FUNC/protocol"
        printf '64\n' > "$FUNC/report_length"
        cp "$RUN/expected.desc" "$FUNC/report_desc"
    fi
    [ "$(cat "$FUNC/subclass")" = 0 ] && [ "$(cat "$FUNC/protocol")" = 0 ] && [ "$(cat "$FUNC/report_length")" = 64 ]
    cmp -s "$RUN/expected.desc" "$FUNC/report_desc" || { echo 'Existing HID descriptor differs; no overwrite' >&2; exit 1; }
    rm "$RUN/expected.desc"
    udc=$(cat "$G/UDC")
    [ -n "$udc" ] && [ -d "/sys/class/udc/$udc" ] || { echo 'USB not bound; inspect first' >&2; exit 1; }
    printf '%s\n' "$udc" > "$RUN/usb.udc"
    trap 'rc=$?; if [ "$rc" -ne 0 ]; then restore; fi' EXIT
    printf '\n' > "$G/UDC"
    ln -s "$FUNC" "$LINK"
    printf '%s\n' "$udc" > "$G/UDC"
    [ ! -e /proc/cviusb/otg_role ] || printf 'device\n' >/proc/cviusb/otg_role
    sleep 2
    [ "$(cat "$G/UDC")" = "$udc" ]
    echo 'Managed FIDO HID enabled.'
    ;;
remove) restore ;;
device)
    [ -L "$LINK" ] && [ "$(readlink -f "$LINK")" = "$FUNC" ]
    expected=$(cat "$FUNC/dev")
    found=''
    for attr in /sys/class/hidg/*/dev; do
        [ -f "$attr" ] || continue
        if [ "$(cat "$attr")" = "$expected" ]; then
            d=${attr%/dev}; node=/dev/${d##*/}
            [ -z "$found" ] && [ -c "$node" ] || exit 1
            found=$node
        fi
    done
    [ -n "$found" ] || exit 1
    printf '%s\n' "$found"
    ;;
status) printf 'UDC: '; cat "$G/UDC"; if [ -L "$LINK" ]; then echo 'FIDO HID linked'; else echo 'FIDO HID not linked'; fi ;;
*) echo 'Usage: usb-gadget.sh add|remove|device|status' >&2; exit 1 ;;
esac
