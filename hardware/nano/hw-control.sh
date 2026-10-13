#!/bin/sh
# Disposable physical test only. Does not access the live authenticator vault.
set -eu
RUN=/run/nano-fido-hwtest
STATE=/var/lib/nano-fido-hwtest
APP=/opt/nano-fido-hwtest/nano-fido
SELF=/opt/nano-fido-hwtest/hw-control.sh
G=/sys/kernel/config/usb_gadget/g0
FUNC=$G/functions/hid.usb0
LINK=$G/configs/c.1/hid.usb0
[ "$(id -u)" = 0 ] || exit 1

stop_app() {
    [ -r "$RUN/app.pid" ] || return 0
    IFS= read -r pid < "$RUN/app.pid"
    case "$pid" in ''|*[!0-9]*) echo 'Invalid application PID' >&2; return 1 ;; esac
    if kill -0 "$pid" 2>/dev/null; then
        [ "$(readlink "/proc/$pid/exe")" = "$APP" ] || { echo 'PID identity mismatch' >&2; return 1; }
        kill -TERM "$pid"
        for i in 1 2 3 4 5 6 7 8 9 10; do
            kill -0 "$pid" 2>/dev/null || break
            sleep 1
        done
        kill -0 "$pid" 2>/dev/null && return 1
    fi
    rm -f "$RUN/app.pid"
}

restore() {
    stop_app
    [ -e "$RUN/active" ] || return 0
    IFS= read -r udc < "$RUN/original.udc"
    [ "$udc" = 4340000.usb ] || { echo 'Unexpected saved UDC' >&2; return 1; }
    # configfs presents even an absolute ln -s target as a relative link.
    # Resolve and validate before unbinding, so a mismatch leaves USB untouched.
    if [ -L "$LINK" ]; then
        [ "$(readlink -f "$LINK")" = "$FUNC" ] || { echo 'Unexpected HID link; stop' >&2; return 1; }
    fi
    current=$(cat "$G/UDC")
    if [ -n "$current" ]; then
        [ "$current" = "$udc" ] || { echo 'Unexpected active UDC; stop' >&2; return 1; }
        # This kernel returns an error when asked to unbind an already-unbound gadget.
        printf '\n' > "$G/UDC"
    fi
    [ ! -L "$LINK" ] || rm "$LINK"
    printf '%s\n' "$udc" > "$G/UDC"
    if [ -e /proc/cviusb/otg_role ]; then
        printf 'device\n' > /proc/cviusb/otg_role
    fi
    sleep 2
    [ "$(cat "$G/UDC")" = "$udc" ] || { echo 'USB binding not restored; marker retained' >&2; return 1; }
    rm -f "$RUN/active"
    echo 'Original USB network configuration restored.'
}

case "${1:-}" in
activate)
    [ -d "$RUN" ] && [ -d "$STATE" ]
    awk '$2=="/run" && $3=="tmpfs" {ok=1} END {exit !ok}' /proc/mounts
    [ ! -e "$RUN/active" ] && [ ! -e "$LINK" ]
    [ "$(cat "$FUNC/report_length")" = 64 ]
    [ "$(wc -c < "$FUNC/report_desc")" -eq 34 ]
    [ "$(cat "$G/UDC")" = 4340000.usb ]
    [ -L "$G/configs/c.1/ncm.usb0" ] && [ -L "$G/configs/c.1/rndis.usb0" ]
    umask 077
    printf '4340000.usb\n' > "$RUN/original.udc"
    session="$(date -u +%s)-$$"
    printf '%s\n' "$session" > "$RUN/active"
    nohup sh "$SELF" watchdog "$session" > "$RUN/rollback.log" 2>&1 </dev/null &
    printf '%s\n' "$!" > "$RUN/watchdog.pid"
    trap 'rc=$?; if [ "$rc" -ne 0 ]; then restore; fi' EXIT
    printf '\n' > "$G/UDC"
    ln -s "$FUNC" "$LINK"
    printf '4340000.usb\n' > "$G/UDC"
    if [ -e /proc/cviusb/otg_role ]; then
        printf 'device\n' > /proc/cviusb/otg_role
    fi
    sleep 2
    [ -c /dev/hidg0 ]
    [ "$(cat /sys/class/hidg/hidg0/dev)" = "$(cat "$FUNC/dev")" ]
    echo 'Temporary FIDO HID active; mapped /dev/hidg0. Automatic rollback in 15 minutes.'
    ;;
run)
    [ -t 0 ] || { echo 'Interactive SSH PTY required' >&2; exit 1; }
    [ -e "$RUN/active" ] && [ -c /dev/hidg0 ]
    [ "$(cat /sys/class/hidg/hidg0/dev)" = "$(cat "$FUNC/dev")" ]
    stop_app
    umask 077
    if [ ! -e "$RUN/lab-passphrase" ]; then
        openssl rand -hex 32 > "$RUN/lab-passphrase"
        chmod 600 "$RUN/lab-passphrase"
    fi
    cp "$RUN/lab-passphrase" "$RUN/pass.once"
    chmod 600 "$RUN/pass.once"
    printf '%s\n' "$$" > "$RUN/app.pid"
    exec env GOMEMLIMIT=40MiB GOGC=50 "$APP" --hid /dev/hidg0 \
        --vault "$STATE/vault.enc" --pass-file "$RUN/pass.once" --terminal-approval
    ;;
stop) stop_app ;;
restore) restore ;;
watchdog)
    expected=${2:?Missing watchdog session ID}
    sleep 900
    [ -r "$RUN/active" ] || exit 0
    [ "$(cat "$RUN/active")" = "$expected" ] || exit 0
    restore
    ;;
cleanup)
    restore
    # Only the disposable, explicitly named lab vault is removed, never /var/lib/nano-fido.
    rm -f "$RUN/lab-passphrase" "$RUN/pass.once" "$STATE/vault.enc"
    echo 'Disposable lab vault and RAM-only lab secret removed.'
    ;;
*) echo 'Usage: hw-control.sh activate|run|stop|restore|cleanup' >&2; exit 1 ;;
esac
