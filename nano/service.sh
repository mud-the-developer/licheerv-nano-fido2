#!/bin/sh
# Own daemon only. No reset, PIN change, vault deletion or automatic unlock.
set -eu
APP=/opt/nano-fido/nano-fido
USB=/opt/nano-fido/usb-gadget.sh
SELF=/opt/nano-fido/service.sh
VAULT=/var/lib/nano-fido/vault.enc
RUN=/run/nano-fido
PIDFILE=$RUN/app.pid
READY=$RUN/ready

read_pid() {
    [ -r "$PIDFILE" ] || return 1
    IFS= read -r pid < "$PIDFILE" || return 1
    case "$pid" in ''|*[!0-9]*) return 1 ;; esac
    [ "$pid" -gt 1 ]
}
pid_alive() {
    kill -0 "$pid" 2>/dev/null && ! grep -q '^State:.*Z' "/proc/$pid/status" 2>/dev/null
}
ours_running() {
    read_pid && pid_alive && [ "$(readlink "/proc/$pid/exe" 2>/dev/null)" = "$APP" ]
}
private_runtime() {
    [ "$(id -u)" = 0 ] || exit 1
    awk '$2=="/run" && $3=="tmpfs" {ok=1} END {exit !ok}' /proc/mounts || { echo '/run must be tmpfs' >&2; exit 1; }
    umask 077
    mkdir -p "$RUN"
    chmod 700 "$RUN"
}
independent_console() {
    [ -n "${SSH_CONNECTION:-}" ] || return 0
    local_ip=$(printf '%s\n' "$SSH_CONNECTION" | awk '{print $3}')
    for iface in /sys/class/net/usb*; do
        [ -d "$iface" ] || continue
        for address in $(ip addr show "${iface##*/}" | awk '/inet / || /inet6 / {print $2}'); do
            [ "${address%/*}" != "$local_ip" ] || { echo 'Use Wi-Fi/VPN or a local UART console before USB reconfiguration.' >&2; return 1; }
        done
    done
}
stop() {
    if read_pid && pid_alive; then
        ours_running || { echo 'PID belongs to a different process; refusing to stop it' >&2; return 1; }
        kill -TERM "$pid"
        for _attempt in 1 2 3 4 5 6 7 8 9 10; do
            pid_alive || break
            sleep 1
        done
        if pid_alive; then echo 'Stop not confirmed; no force kill attempted' >&2; return 1; fi
    fi
    rm -f "$PIDFILE" "$READY" "$RUN/pending"
    sh "$USB" remove
    echo 'Locked/stopped. Encrypted vault retained.'
}

case "${1:-}" in
start)
    private_runtime
    if ours_running; then echo 'Authenticator already unlocked/running.'; exit 0; fi
    if read_pid && pid_alive; then echo 'Unexpected live PID; inspect first' >&2; exit 1; fi
    [ -f "$VAULT" ] && [ ! -L "$VAULT" ] || { echo 'No regular owner vault; initialize separately' >&2; exit 1; }
    passfile=${2:?Missing RAM-only pass file}
    event=${3:?Missing verified USER input node}
    case "$passfile" in /run/nano-fido-ui.*/pass) ;; *) echo 'Pass file must come from the private TUI runtime' >&2; exit 1 ;; esac
    [ -f "$passfile" ] && [ -c "$event" ]
    independent_console
    rm -f "$READY" "$PIDFILE"
    session="$(date -u +%s)-$$"
    printf '%s\n' "$session" > "$RUN/pending"
    nohup setsid sh "$SELF" rollback "$session" >/dev/null 2>&1 </dev/null &
    if ! sh "$USB" add; then rm -f "$RUN/pending"; exit 1; fi
    hid=$(sh "$USB" device) || { stop; exit 1; }
    nohup setsid env GOMEMLIMIT=40MiB GOGC=50 "$APP" --hid "$hid" --vault "$VAULT" \
        --pass-file "$passfile" --button-event "$event" --ready-file "$READY" \
        >/dev/null 2>&1 </dev/null &
    pid=$!
    printf '%s\n' "$pid" > "$PIDFILE"
    for _attempt in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
        if ! pid_alive; then wait "$pid" 2>/dev/null || true; break; fi
        if ours_running && [ -f "$READY" ] && [ "$(cat "$READY")" = "$pid" ]; then
            rm -f "$RUN/pending"
            echo 'Unlocked. Approve browser requests using the on-board USER button.'
            exit 0
        fi
        sleep 1
    done
    echo 'Unlock/start failed. Vault retained; restoring original USB.' >&2
    stop
    exit 1
    ;;
stop) private_runtime; independent_console; stop ;;
rollback)
    expected=${2:?Missing startup session}
    sleep 75
    [ -r "$RUN/pending" ] || exit 0
    [ "$(cat "$RUN/pending")" = "$expected" ] || exit 0
    stop
    ;;
status)
    if ours_running && [ -f "$READY" ] && [ "$(cat "$READY")" = "$pid" ]; then
        echo 'Authenticator: UNLOCKED / running'
    else
        echo 'Authenticator: LOCKED / stopped (or startup unconfirmed)'
    fi
    if [ -e "$VAULT" ]; then echo 'Encrypted vault: present (contents not read)'; else echo 'Encrypted vault: not initialized'; fi
    sh "$USB" status
    ;;
*) echo 'Usage: service.sh status|start RAM_PASS_FILE USER_EVENT|stop' >&2; exit 1 ;;
esac
