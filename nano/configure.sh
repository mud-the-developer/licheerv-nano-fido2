#!/bin/sh
# Lightweight English ANSI console. Never stores plaintext secrets on SD.
set -u
APP=/opt/nano-fido/nano-fido
SERVICE=/opt/nano-fido/service.sh
VAULT=/var/lib/nano-fido/vault.enc
TMP=''
TTY_STATE=''
LOCK=/run/nano-fido-config.lock
LAST_SETUP=''
NOTICE=''
FX=0
ANIMATE=0
RESET=''; BOLD=''; DIM=''; CYAN=''; GREEN=''; AMBER=''; RED=''

help_text() {
    cat <<'HELP'
NANO FIDO2 / OPERATOR GUIDE

  FIRST SETUP  Create a NEW encrypted vault and initial FIDO PIN.
  UNLOCK      Enter the vault passphrase, then approve requests with USER.
  LOCK        Stop the managed process and remove managed HID. Keep the vault.

Three different credentials:
  SSH authentication  -> administer Linux
  Vault passphrase    -> decrypt the SD vault; at least 16 bytes
  FIDO PIN            -> browser user verification; separate from the vault

After power loss, reconnect over independent Wi-Fi/VPN and unlock again.
Plaintext auto-unlock is not offered. Never send secrets to chat or Git.
Use USER after normal boot. RESET is not an approval button.

Exit closes only this menu. An already unlocked authenticator keeps running.
Choose [4] LOCK before leaving if you want it stopped.

EXPERIMENTAL: secure your SSH/root administration first. Use a disposable
account with an independent login method. Browser compatibility, key
extraction resistance and production certification remain unverified.
No vault overwrite, reset, deletion, or existing-PIN removal is offered.
HELP
}

case "${1:-}" in --help|-h) help_text; exit 0;; esac
[ "$(id -u)" = 0 ] || { echo 'Root required.' >&2; exit 1; }
[ -x "$APP" ] && [ -f "$SERVICE" ] || { echo 'Install the checked bundle into /opt/nano-fido first.' >&2; exit 1; }
case "${1:-}" in --status) sh "$SERVICE" status; exit $?;; esac
[ -t 0 ] && [ -t 1 ] || { echo 'Interactive TTY required: use ssh -t.' >&2; exit 1; }
awk '$2=="/run" && $3=="tmpfs" {ok=1} END {exit !ok}' /proc/mounts || { echo '/run must be RAM-backed tmpfs.' >&2; exit 1; }
umask 077
TTY_STATE=$(stty -g) || exit 1
mkdir "$LOCK" 2>/dev/null || { echo 'Another menu or a stale lock exists; inspect it first.' >&2; exit 1; }

if [ "${TERM:-dumb}" != dumb ] && [ -z "${NO_COLOR:-}" ]; then
    FX=1
    RESET=$(printf '\033[0m'); BOLD=$(printf '\033[1m'); DIM=$(printf '\033[2m')
    CYAN=$(printf '\033[36m'); GREEN=$(printf '\033[32m')
    AMBER=$(printf '\033[33m'); RED=$(printf '\033[31m')
    if [ "${NANO_UI_NO_ANIMATION:-0}" != 1 ] && sleep 0.05 2>/dev/null; then ANIMATE=1; fi
fi
cleanup_secrets() {
    [ -z "$TTY_STATE" ] || stty "$TTY_STATE" 2>/dev/null || true
    if [ -n "$TMP" ]; then
        rm -f "$TMP/pass" "$TMP/pin"
        rmdir "$TMP" 2>/dev/null || true
        TMP=''
    fi
    unset secret pass confirm pin 2>/dev/null || true
}
finish() {
    cleanup_secrets
    [ "$FX" = 0 ] || printf '\033[0m\033[?25h'
    rmdir "$LOCK" 2>/dev/null || true
}
trap finish EXIT
trap 'exit 1' HUP INT TERM

rule() { printf '%s  --------------------------------------------------------------------%s\n' "$DIM" "$RESET"; }
step() {
    printf '\n%s%s  STEP %s / 4  %s%s\n' "$BOLD" "$CYAN" "$1" "$2" "$RESET"
    rule
}
intro() {
    [ "$ANIMATE" = 1 ] || return 0
    printf '\033[?25l'
    for frame in '.' '..' '...' '....'; do
        printf '\r%s  Opening the operator console %-4s%s' "$CYAN" "$frame" "$RESET"
        sleep 0.05
    done
    printf '\r\033[2K\033[?25h'
}
read_secret() {
    # Echo is disabled before the prompt, so fast/pasted input cannot race it.
    stty -echo || return 1
    printf '%s' "$1"
    unset secret 2>/dev/null || true
    IFS= read -r secret
    r=$?
    stty "$TTY_STATE"
    printf '\n'
    return "$r"
}
new_runtime() {
    TMP=$(mktemp -d /run/nano-fido-ui.XXXXXX) || return 1
    chmod 700 "$TMP" || return 1
}
find_user() {
    event=''
    for node in /sys/class/input/event*; do
        [ -d "$node" ] || continue
        [ "$(cat "$node/device/name" 2>/dev/null)" = gpio-keys ] || continue
        [ -z "$event" ] || { echo 'Multiple gpio-keys devices; inspect before starting.' >&2; return 1; }
        event=/dev/input/${node##*/}
    done
    [ -n "$event" ] && [ -c "$event" ] || { echo 'USER input device not found.' >&2; return 1; }
}
setup_new() {
    LAST_SETUP='Setup did not finish. Check for cancelled input or a closed connection.'
    [ ! -e "$VAULT" ] && [ ! -L "$VAULT" ] || { LAST_SETUP='Vault exists. Initialization will not overwrite it; choose [3] UNLOCK.'; echo "$LAST_SETUP"; return 1; }
    step 1 'CONFIRM NEW OWNER VAULT'
    echo 'This creates new keys and an initial PIN. It does not change USB.'
    echo 'Enter SETUP or y to continue. Empty or other input cancels.'
    printf 'Create a new owner vault and initial FIDO PIN? Type SETUP: '
    IFS= read -r answer || return 1
    case "$answer" in SETUP|y|Y|yes|YES) ;; *) LAST_SETUP='Setup cancelled at confirmation. Enter SETUP or y to proceed.'; echo "$LAST_SETUP"; return 1;; esac
    new_runtime || { LAST_SETUP='Could not create the private RAM directory. Check [6] DIAGNOSTICS.'; return 1; }
    step 2 'PROTECT THE SD VAULT'
    echo 'Use a long, unique passphrase. It is not your SSH password or FIDO PIN.'
    echo 'At least 16 bytes are required. Input is hidden; blank cancels.'
    while :; do
        read_secret 'New vault passphrase (>=16 bytes, blank cancels): ' || return 1
        pass=$secret; unset secret
        [ -n "$pass" ] || { LAST_SETUP='Setup cancelled: empty vault passphrase.'; return 1; }
        bytes=$(printf '%s' "$pass" | wc -c)
        if [ "$bytes" -lt 16 ]; then
            LAST_SETUP='Passphrase too short: at least 16 bytes required. Please retry.'
            printf '%s  ! %s%s\n' "$AMBER" "$LAST_SETUP" "$RESET"
            unset pass
            continue
        fi
        read_secret 'Repeat vault passphrase: ' || return 1
        if [ "$pass" != "$secret" ]; then
            LAST_SETUP='Vault passphrases do not match. Please retry.'
            printf '%s  ! %s%s\n' "$AMBER" "$LAST_SETUP" "$RESET"
            unset pass secret
            continue
        fi
        unset secret
        break
    done
    step 3 'CHOOSE YOUR FIDO PIN'
    echo 'Use a different secret: at least 4 UTF-8 characters, at most 63 bytes.'
    read_secret 'New FIDO PIN (>=4 characters, <=63 bytes): ' || return 1
    pin=$secret; unset secret
    [ "$pin" != "$pass" ] || { LAST_SETUP='Use different values for the vault passphrase and FIDO PIN.'; echo "$LAST_SETUP"; return 1; }
    read_secret 'Repeat FIDO PIN: ' || return 1
    [ "$pin" = "$secret" ] || { LAST_SETUP='FIDO PINs do not match. Restart [2] FIRST SETUP.'; echo "$LAST_SETUP"; return 1; }
    unset secret
    printf '%s' "$pass" > "$TMP/pass" || return 1
    printf '%s' "$pin" > "$TMP/pin" || return 1
    unset pass pin
    step 4 'CREATE ENCRYPTED STATE'
    echo 'Applying the existing scrypt policy. No plaintext secret is saved to SD.'
    if ! "$APP" --initialize --vault "$VAULT" --pass-file "$TMP/pass" --initial-pin-file "$TMP/pin"; then
        LAST_SETUP='Initialization refused. See the error above; verify PIN length/encoding. Existing ciphertext is retained.'
        echo "$LAST_SETUP"
        return 1
    fi
    [ -f "$VAULT" ] && [ ! -L "$VAULT" ] || { LAST_SETUP='Vault creation could not be confirmed. Check [6] DIAGNOSTICS.'; echo "$LAST_SETUP"; return 1; }
    LAST_SETUP='SETUP COMPLETE: vault and initial PIN saved. Choose [3] and enter the same vault passphrase.'
    printf '%s%s  + %s%s\n' "$BOLD" "$GREEN" "$LAST_SETUP" "$RESET"
    echo 'Initial setup complete. Choose unlock/start next.'
}
diagnose() {
    printf '\n%s%s  DIAGNOSTICS / METADATA ONLY%s\n' "$BOLD" "$CYAN" "$RESET"
    rule
    printf 'Runtime mount: '; awk '$2=="/run" {print $2,$3}' /proc/mounts
    free -m
    printf 'Binary SHA256: '; sha256sum "$APP"
    if find_user; then printf 'USER input node: %s (GPIO direction unchanged)\n' "$event"; fi
    if [ -e "$VAULT" ]; then ls -l "$VAULT"; fi
    echo 'No key, PIN, passphrase, account list or raw request log is displayed.'
}
unlock() {
    [ -f "$VAULT" ] && [ ! -L "$VAULT" ] || { echo 'No regular owner vault. Complete first setup.'; NOTICE='No vault: complete [2] until SETUP COMPLETE and vault CONFIGURED are shown.'; echo "$NOTICE"; return 1; }
    find_user || return 1
    new_runtime || return 1
    printf '\n%s%s  UNLOCK / START%s\n' "$BOLD" "$CYAN" "$RESET"
    echo 'Enter the vault passphrase, NOT the FIDO PIN. Nothing is echoed.'
    read_secret 'Vault passphrase (not FIDO PIN; blank cancels): ' || return 1
    [ -n "$secret" ] || return 1
    printf '%s' "$secret" > "$TMP/pass" || return 1
    unset secret
    if sh "$SERVICE" start "$TMP/pass" "$event"; then
        NOTICE='Authenticator unlocked. Approve requests with USER. Exit does not lock it.'
    else
        NOTICE='Unlock failed or was refused. Vault retained; check the messages and status.'
        return 1
    fi
}
pause_view() {
    [ "$FX" = 1 ] || return 0
    printf '\n%sPress Enter to return to the dashboard...%s' "$DIM" "$RESET"
    IFS= read -r _answer || true
}
dashboard() {
    status_text=$(sh "$SERVICE" status 2>&1)
    state='LOCKED'; state_color=$AMBER
    case "$status_text" in *'UNLOCKED / running'*) state='UNLOCKED'; state_color=$GREEN;; esac
    vault_state='NOT SET UP'
    case "$status_text" in *'Encrypted vault: present'*) vault_state='CONFIGURED';; esac
    usb_state='NETWORK ONLY'
    case "$status_text" in *'FIDO HID linked'*) usb_state='FIDO HID LINKED';; esac
    [ "$FX" = 0 ] || printf '\033[2J\033[H'
    printf '\n%s%s  N A N O  / /  F I D O 2%s\n' "$BOLD" "$CYAN" "$RESET"
    printf '%s  OPERATOR CONSOLE                         EXPERIMENTAL%s\n' "$DIM" "$RESET"
    rule
    printf '  AUTHENTICATOR  %s%s%-16s%s  VAULT  %s\n' "$BOLD" "$state_color" "$state" "$RESET" "$vault_state"
    printf '  TRANSPORT      %-20s  APPROVAL  USER button\n' "$usb_state"
    rule
    printf '\n%s  SETUP%s\n' "$DIM" "$RESET"
    printf '  %s[2]%s FIRST SETUP       New vault + initial FIDO PIN\n' "$CYAN" "$RESET"
    printf '\n%s  CONTROL%s\n' "$DIM" "$RESET"
    printf '  %s[3]%s UNLOCK / START    Enter vault passphrase; enable USER approval\n' "$GREEN" "$RESET"
    printf '  %s[4]%s LOCK / STOP       Remove managed HID; retain encrypted keys\n' "$AMBER" "$RESET"
    printf '\n%s  INSPECT%s\n' "$DIM" "$RESET"
    printf '  %s[1]%s STATUS            Detailed read-only service status\n' "$CYAN" "$RESET"
    printf '  %s[5]%s GUIDE             Credentials, workflow and safety\n' "$CYAN" "$RESET"
    printf '  %s[6]%s DIAGNOSTICS       Runtime, binary hash and USER device\n' "$CYAN" "$RESET"
    rule
    printf '  %s[0]%s EXIT MENU         Running authenticator stays UNLOCKED\n' "$RED" "$RESET"
    printf '%s  Manual unlock is required after power loss. RESET is not approval.%s\n' "$DIM" "$RESET"
    if [ -n "$LAST_SETUP" ]; then printf '\n%sLast setup result:%s %s\n' "$AMBER" "$RESET" "$LAST_SETUP"; fi
    if [ -n "$NOTICE" ]; then printf '\n%s  > %s%s\n' "$CYAN" "$NOTICE" "$RESET"; fi
    printf '\n%sSelect: %s' "$BOLD" "$RESET"
}

intro
while :; do
    cleanup_secrets
    dashboard
    IFS= read -r choice || break
    NOTICE=''
    case "$choice" in
        1) sh "$SERVICE" status || true; pause_view ;;
        2) setup_new || echo 'Setup cancelled or refused.' ;;
        3) unlock || echo 'Unlock cancelled or failed; vault retained.' ;;
        4) if sh "$SERVICE" stop; then NOTICE='Locked/stopped. Encrypted vault retained.'; else NOTICE='Stop failed; inspect status before disconnecting.'; fi ;;
        5) help_text; pause_view ;;
        6) diagnose; pause_view ;;
        0) printf '\n%sMenu closed. Use LOCK / STOP to stop an unlocked authenticator.%s\n' "$DIM" "$RESET"; break ;;
        *) NOTICE='Unknown choice. Select a number from 0 to 6.' ;;
    esac
done
