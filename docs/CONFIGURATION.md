# Interactive configuration console

For the full day-to-day handbook, start with [USER-GUIDE.md](USER-GUIDE.md). For exact errors and safe recovery, use [TROUBLESHOOTING.md](TROUBLESHOOTING.md). This page is the shorter menu/configuration reference.

The console is a lightweight BusyBox/POSIX-shell TUI. All prompts, help and errors are English. ANSI terminals get a colored status dashboard, grouped controls, a four-step setup wizard and a short opening animation. No extra framework is installed on the Nano.

**This is not automatic unlock. After power loss, enter the vault passphrase again through a trusted SSH/local console.** No plaintext passphrase is stored on SD.

## Open the installed console

```text
ssh -t root@<NANO_HOST> /opt/nano-fido/configure.sh
```

Use your own verified Wi-Fi/VPN management address and trusted SSH host key. Do not disable host-key checking. USB SSH can inspect status or perform first setup, but unlocking/stopping changes USB configuration: use independent Wi-Fi/VPN or UART for those operations. The helper refuses direct USB SSH reconfiguration.

## Dashboard and controls

```text
N A N O  / /  F I D O 2
OPERATOR CONSOLE                                  EXPERIMENTAL
AUTHENTICATOR  LOCKED / UNLOCKED     VAULT  CONFIGURED / NOT SET UP
TRANSPORT      NETWORK ONLY / FIDO HID LINKED       APPROVAL USER

[2] FIRST SETUP       New vault + initial FIDO PIN
[3] UNLOCK / START    Enter vault passphrase; enable USER approval
[4] LOCK / STOP       Remove managed HID; retain encrypted keys
[1] STATUS           Detailed read-only service status
[5] GUIDE            Credentials, workflow and safety
[6] DIAGNOSTICS      Runtime, binary hash and USER device
[0] EXIT MENU        Running authenticator stays UNLOCKED
```

The dashboard never shows keys, PINs, passphrases, account lists or raw request logs. The last setup result remains visible after cancellation/failure. In ANSI mode, detailed views pause until Enter so the next redraw does not hide them. Secret entry never animates, echoes or displays a character count.

Color/animation require an interactive ANSI terminal. `TERM=dumb` or non-empty `NO_COLOR` selects a plain transcript-friendly fallback. Set `NANO_UI_NO_ANIMATION=1` to keep the colored dashboard without animation:

```text
NANO_UI_NO_ANIMATION=1 /opt/nano-fido/configure.sh
NO_COLOR=1 /opt/nano-fido/configure.sh
```

## First use: [2] FIRST SETUP

Secure Linux/SSH administration before provisioning anything important. Do not leave default management credentials in place.

1. Select `2`. Confirm with `SETUP` or `y`; Enter or other input cancels.
2. Enter a long, unique **vault passphrase** twice. At least 16 bytes are required. Short/mismatched entries retry the same step.
3. Enter a separate **FIDO PIN** twice: at least four UTF-8 characters, at most 63 bytes. Do not reuse the vault passphrase.
4. Input is hidden. Root-only secret files exist only on verified RAM tmpfs and are consumed by the initializer.
5. One atomic initial save writes the new keys and initial PIN to `/var/lib/nano-fido/vault.enc`. This step does not change USB.

Wait for `SETUP COMPLETE` and vault `CONFIGURED` before choosing `3`. An existing path is refused by both the menu and the binary: no overwrite, Reset, deletion or existing-PIN removal is offered. If setup fails, share only the error wording, never a secret.

### The three credentials are different

- SSH authentication: administer Linux.
- Vault passphrase: unlock the encrypted SD state after startup.
- FIDO PIN: answer browser/Windows security-key user-verification prompts.

Never send them to chat, put their values in command arguments, or commit them to Git.

## Unlock and use: [3]

Enter the **vault passphrase**, not the FIDO PIN. The helper discovers the existing gpio-keys input and does not export or reconfigure its GPIO. It adds only a validated FIDO HID while preserving the official network functions, loads the encrypted vault and starts the USER-event approval mode.

Startup is confirmed only when the managed PID and exclusive readiness marker agree. A wrong passphrase or failed startup retains ciphertext and restores USB; a generation-scoped 75-second rollback also protects incomplete startup. Account/request output is discarded instead of kept as a disk log.

When the browser asks, enter the **FIDO PIN** and press/release on-board **USER**. RESET is not approval. The operator reported the Token2 demo working; the broader browser/version/option matrix still needs separate verification. Use a disposable account with an independent login method first.

## Lock: [4]

The helper checks its PID/executable, stops only the managed authenticator and removes only its managed HID link. It retains the encrypted vault and does not force-kill an unknown process or Reset credentials.

`0` closes only the menu. **An unlocked authenticator continues running.** Use `4` first if you want it stopped. Process termination does not guarantee secure erasure of all Go/RAM copies.

## After power loss

Wait for independent management networking, reconnect and choose `3`. This bundle does not install a boot service that automatically unlocks FIDO. Plug-and-use operation with only PIN/USER would require a separate review of the manual vault-unlock design and key-protection boundary.

## Install on another board

Build and verify the RISC-V binary. Copy it and the four `nano/` shell scripts into a new root-only staging directory, then run:

```text
sh <STAGING>/install.sh <STAGING>/nano-fido <EXPECTED_SHA256>
```

Use your own build's `out/SHA256SUMS.txt`. The first-install script refuses an existing binary and does not choose a vault/PIN or change USB, SSH authentication or boot settings. Treat upgrades separately: stop, back up and verify first.

## Validation and limits

The configuration workflow was exercised through an SSH PTY against a separate synthetic vault: no secret echo, independent initial-PIN verification, existing-ciphertext refusal, wrong-passphrase fail-closed behavior, normal supervised unlock/stop and USB recovery. No owner credentials were selected by the test.

The visual redesign is tested with mock app/service/vault/lock paths, including ANSI/plain output, four-step setup, short/mismatched input, cancellation, paused detail views and cursor restoration. It does not initialize, decrypt, stop or modify the operator's live vault/service.

Remaining limitations include real browser compatibility, cancellation/concurrent-channel handling, power loss/cold boot, secure RAM erasure and key-extraction resistance. See SECURITY.md. A prettier interface does not make this prototype a certified commercial security key.
