# Complete operator guide

> Experimental Linux USB authenticator, not a certified commercial security key.
> Keep an independent login method. Never troubleshoot by deleting your vault.

This is the detailed day-to-day handbook. [CONFIGURATION.md](CONFIGURATION.md) is the shorter console reference, [TROUBLESHOOTING.md](TROUBLESHOOTING.md) explains failure messages, and [SECURITY.md](SECURITY.md) describes the security boundary and unresolved gaps.

## Contents

1. [What is ready](#1-what-is-ready)
2. [The three credentials](#2-the-three-credentials)
3. [Equipment and safe management access](#3-equipment-and-safe-management-access)
4. [Open an already-installed console](#4-open-an-already-installed-console)
5. [Understand the dashboard](#5-understand-the-dashboard)
6. [First setup](#6-first-setup--2)
7. [Unlock and start](#7-unlock-and-start--3)
8. [Register and sign in through a browser](#8-register-and-sign-in-through-a-browser)
9. [Lock, exit and disconnect](#9-lock-exit-and-disconnect)
10. [After reboot or power loss](#10-after-reboot-or-power-loss)
11. [Console appearance and diagnostics](#11-console-appearance-and-diagnostics)
12. [Build and first installation](#12-build-and-first-installation)
13. [Backups, forgotten credentials and recovery](#13-backups-forgotten-credentials-and-recovery)
14. [Maintenance and upgrades](#14-maintenance-and-upgrades)
15. [CLI reference](#15-cli-reference)
16. [Test evidence and support checklist](#16-test-evidence-and-support-checklist)

## 1. What is ready

The Nano itself implements USB FIDO2. It stores encrypted authenticator state on its SD card and signs requests on the device. On-board USER approval, PIN protocol 1, credential registration/authentication, process-restart persistence and monotonic signature-counter behavior passed physical USB tests. A lightweight English terminal console handles initial provisioning, unlock/start, stop/lock and diagnostics.

The operator also reported that the [Token2 FIDO2 demo](https://www.token2.com/tools/fido2-demo) worked. This is useful real-browser evidence, but it is an operator report: the exact browser/version, options, individual ceremonies and artifacts were not independently captured by the agent. Broader browser compatibility and production security are not implied.

**Not plug-and-use after power loss:** the current design requires a management terminal to enter the vault passphrase again. The browser's FIDO PIN does not automatically decrypt the vault. Do not remove that requirement by putting the passphrase on SD.

![First setup and daily operation](diagrams/daily-usage.svg)

## 2. The three credentials

| Credential | Where you enter it | What it does | Not interchangeable with |
|---|---|---|---|
| SSH authentication | Your SSH client or SSH key agent | Administers Linux | Vault passphrase / FIDO PIN |
| Vault passphrase | Nano console, first setup and unlock | Encrypts/unlocks SD authenticator state | SSH password / FIDO PIN |
| FIDO PIN | Initial setup; later browser/Windows security-key prompt | FIDO user verification and PIN-token authorization | Vault passphrase |

### Vault passphrase

- At least **16 bytes** are required; use a long, unique secret, not merely a string that barely meets the minimum.
- UTF-8 byte count is not character count. For example, some non-ASCII characters occupy multiple bytes. The menu checks minimum bytes; the program also bounds its private input file.
- Remember it or keep it in an appropriate private password manager. Losing it is not solved by remembering the FIDO PIN.
- Input is hidden. No dots or asterisks appear; that does not mean the terminal is frozen.

### FIDO PIN

- At least **four UTF-8 characters**, at most **63 bytes**.
- Choose a separate secret. For a simple initial Windows compatibility trial, a suitable numeric PIN is easier than relying on every platform's Unicode behavior.
- Do not use the synthetic PINs in unit tests as deployment suggestions.
- Incorrect PINs consume persisted retries. Do not repeatedly guess.

Never send either value to chat, put its actual value into CLI arguments/environment examples, take an unredacted screenshot of it, or commit it. The examples in this guide contain host/path placeholders only, not example passwords.

## 3. Equipment and safe management access

You need:

- A supported LicheeRV Nano image with working USB device mode/configfs and HID support.
- A data-capable USB cable, not a power-only cable.
- A host with a FIDO2-capable browser. Windows was used for the physical tests.
- The built-in USER button accessible after normal boot.
- An independent management path: verified Wi-Fi/VPN, UART, or a separately functioning Ethernet route.

The official USB NCM and RNDIS interfaces share one cable/controller. They are not independent recovery paths. Enabling or removing HID briefly disconnects/re-enumerates that USB gadget and can interrupt USB SSH. Use a Wi-Fi/VPN address for menu actions that reconfigure USB. The service helper rejects direct USB SSH for start/stop.

Management traffic must actually use the independent path. Merely installing a VPN does not help if its underlying internet path is the USB network you are changing. Confirm the peer/return route during initial installation.

Before important use, replace default management authentication, establish verified SSH key access as appropriate, and restrict management-network exposure. This console does not silently change SSH credentials or firewall policy.

Do not hold USER while applying power or pressing RESET during normal approval tests. USER also has a BOOT role. RESET restarts the board; it is never approval.

## 4. Open an already-installed console

Replace the sample hostname with your own verified Nano management hostname/address. Do not paste literal angle-bracket placeholders into a shell.

PowerShell:

```powershell
$NanoHost = 'your-nano-management-host'
ssh -t "root@$NanoHost" /opt/nano-fido/configure.sh
```

Linux/macOS management terminal:

```sh
NANO_HOST='your-nano-management-host'
ssh -t "root@$NANO_HOST" /opt/nano-fido/configure.sh
```

The `-t` allocates a terminal for hidden input. Use the management account supported by your image; the current adapter requires root. The SSH prompt, if any, is for **Linux administration**, not the vault or FIDO PIN.

If the same board already has a trusted SSH host-key entry under another address, you may supply your verified alias:

```text
ssh -t -o HostKeyAlias=<YOUR_EXISTING_VERIFIED_ENTRY> root@<NANO_HOST> /opt/nano-fido/configure.sh
```

Only do this for the same physically verified board. Never solve host-key warnings with StrictHostKeyChecking=no or automatic deletion of known_hosts.

If another menu is open, close it with `0` before starting another. A lock is intentional; do not remove an active menu's lock directory.

## 5. Understand the dashboard

```text
N A N O  / /  F I D O 2
OPERATOR CONSOLE                                  EXPERIMENTAL
AUTHENTICATOR  LOCKED / UNLOCKED     VAULT  CONFIGURED / NOT SET UP
TRANSPORT      NETWORK ONLY / FIDO HID LINKED       APPROVAL USER
```

| What you see | Meaning | Normal next action |
|---|---|---|
| LOCKED + NOT SET UP | No owner vault was found | Use [2] once, then [3] |
| LOCKED + CONFIGURED | State file exists, but managed readiness is unconfirmed | Use [3] with the existing vault passphrase |
| UNLOCKED + CONFIGURED + FIDO HID LINKED | Managed PID and ready marker agree; key is available | Use browser / USER; do not initialize again |
| Unexpected combination | Partial startup, external state or management failure is possible | Inspect [1]/[6]; do not delete or reinitialize |

`CONFIGURED` is a **file-presence indication**, not a proof that its ciphertext is healthy or that you remember the passphrase. Successful unlock is a separate check. `LOCKED` means the managed running/ready state is absent or unconfirmed; it does not promise physical RAM erasure.

The grouped controls are:

| Choice | Operation |
|---|---|
| 1 STATUS | Detailed read-only process/vault-presence/USB status |
| 2 FIRST SETUP | New keys, encrypted vault and initial PIN; refuses an existing path |
| 3 UNLOCK / START | Opens the existing vault and enables USER-based FIDO |
| 4 LOCK / STOP | Stops only the managed process and removes managed HID; retains vault |
| 5 GUIDE | Credential distinctions, workflow and safety |
| 6 DIAGNOSTICS | Runtime/memory, binary hash, input node and file metadata only |
| 0 EXIT MENU | Closes only the console; an unlocked authenticator stays running |

## 6. First setup — [2]

Do this once only when there is no existing owner vault.

### Step 1 / 4: confirm

1. Select `2`.
2. Read the warning that new keys and an initial PIN will be created.
3. Type `SETUP` or `y` and press Enter. Empty input or another answer cancels.

If the vault already exists, the menu and binary refuse initialization. This is protection, not an instruction to delete the file.

### Step 2 / 4: protect the SD vault

1. Enter your new vault passphrase. The terminal displays no characters.
2. A short value is rejected immediately and retried in the same step.
3. Enter the same value at `Repeat vault passphrase:`.
4. A mismatch also retries. Blank initial input cancels.

Hidden input and secret handling are deliberately not animated. The new secret is held in the shell briefly and then in root-only files on verified `/run` tmpfs, not SD. Memory/file cleanup is not a guarantee against a privileged memory attacker.

### Step 3 / 4: choose the initial FIDO PIN

1. Enter a separate FIDO PIN.
2. Repeat it exactly.
3. The PIN must differ from the vault passphrase. Backend validation checks UTF-8 and the four-character/63-byte limits.

The console does not offer existing-PIN removal or a shortcut around retry state. Subsequent PIN management has different security requirements; do not treat first setup as a PIN-reset tool.

### Step 4 / 4: create encrypted state

The initializer checks that the vault path does not already exist. It saves the new identity and initial PIN together, using the current encrypted format and filesystem protections. It does **not** enable HID or change USB at this step.

Wait for both:

```text
SETUP COMPLETE
VAULT CONFIGURED
```

The exact success sentence also tells you to choose [3]. If setup cancels/fails, `Last setup result` stays visible. Read that message before trying unlock. Sharing the error wording is enough; never share the input values.

### If you selected [2] but [3] says no vault

The initial operation did not finish successfully. Common checks are: confirmation was SETUP/y rather than Enter, passphrase was at least 16 bytes, repeated entries matched, and PIN policy passed. The message itself does not identify which check failed. Use the retained result/preceding error, not guesses or deletion. See [troubleshooting](TROUBLESHOOTING.md#setup-does-not-create-a-vault).

## 7. Unlock and start — [3]

Use the **same existing vault passphrase**. Do not enter the FIDO PIN here. If already UNLOCKED, you normally do not need to select [3] again.

The service:

1. Confirms the managed process state, regular owner vault and independent management connection.
2. Finds gpio-keys USER input; it does not export/change GPIO direction.
3. Validates the existing HID function or creates the expected one when absent; unrelated/mismatched HID state is refused.
4. Preserves official NCM/RNDIS links, records its own USB ownership state and rebinds the gadget.
5. Loads the encrypted vault and starts the USER-event approval mode.
6. Confirms the managed PID and exclusive ready marker before reporting success.

The supervisor uses bounded Go memory settings. Root-only runtime markers live under `/run/nano-fido`. Account/request output is discarded rather than kept in a disk log. An incomplete start has a generation-scoped 75-second rollback; this is a safety measure, not a reason to skip independent recovery.

A wrong passphrase does not become a new vault. Startup fails closed and retains ciphertext. USB restoration/re-enumeration/DHCP can take additional time; do not start parallel controllers while it settles.

## 8. Register and sign in through a browser

### Before the first browser trial

- Confirm UNLOCKED, CONFIGURED and FIDO HID LINKED.
- Keep another working login/recovery method.
- Use a disposable demo/account first, not an important account's sole factor.
- Disconnect other security keys if you cannot confidently identify the intended key.
- Select the USB security-key path, not a phone/hybrid flow or Windows Hello/platform passkey when testing this board.
- Keep USER accessible. Do not press RESET or hold USER in advance.

### Token2 demo

The operator reported success at:

https://www.token2.com/tools/fido2-demo

The site presents **Register** followed by **Log in** and adjustable user-verification/authenticator/discoverable-credential options. It describes the demo as session-only on the server side. A credential created on the authenticator can still remain in its SD vault after the page/session is gone; do not Reset/delete your whole vault to clean up a demo.

Suggested reproducible sequence:

1. Open the HTTPS demo in the browser you want to evaluate.
2. Choose physical/roaming/cross-platform USB security key when offered.
3. For a PIN+USER trial, choose user verification required when that option is available.
4. Click **Register**. In Windows/browser security UI, enter the **FIDO PIN** when asked.
5. When asked to touch the key, press and release Nano **USER**.
6. Confirm registration succeeded in the page.
7. In the same demo session, click **Log in** and repeat PIN/USER as requested.
8. Confirm login succeeded. Record only non-sensitive details: browser/OS versions, relevant option names, success/failure and sanitized error wording.

Do not assume every advanced option works. Exclusion tests intentionally return an error for an already-registered key. Usernameless/discoverable modes exercise different paths. Metadata/certification results are not proof this custom device is certified. Do not copy another vendor's identity to bypass a relying party's trust policy.

The current Token2 result is **operator-reported working**. The exact browser/version and individual operations were not independently captured. The automated physical evidence remains separately described in TEST-STATUS.md.

### Existing real services

Follow that site's security-key/passkey enrollment UI only after the disposable test works. Some sites require a supported protocol version, attestation policy or certified model that this prototype does not satisfy. Keep alternative access. No compatibility claim is made for Windows account sign-in, enterprise policy, every browser or every RP.

## 9. Lock, exit and disconnect

### [4] LOCK / STOP

Use the independent management route. The helper verifies its PID and executable, requests termination, and removes only its managed HID link. It preserves `/var/lib/nano-fido/vault.enc` and unrelated USB network functions. It refuses a PID belonging to another live process and does not force-kill it.

After success expect LOCKED and network-only USB. Enumeration/network recovery can lag the script by a few seconds. This stops the key service but does not guarantee forensic erasure of RAM.

### [0] EXIT MENU

This closes the UI/its SSH command only. **It is not a lock button.** If you were UNLOCKED, the detached authenticator continues running. This allows normal key use without keeping the menu open. If you want it stopped, choose [4] before [0].

### Unplugging USB

Treat cable removal as possible power loss, not as a tested transactional shutdown. Prefer stopping cleanly first, especially before removing the SD card. Unplug/replug/cold-boot and interrupted-write testing are not comprehensive. Do not remove SD while Linux is running.

## 10. After reboot or power loss

Persistent: installed files and encrypted vault, including identity, credentials, PIN hash and persisted retry/counter state.

Not persistent as an unlocked session: RAM passphrase, wrapping-key cache, daemon/ready marker and managed temporary runtime state. The console does not install an automatic FIDO-unlock boot service.

1. Restore normal board power and wait for boot.
2. Ensure the chosen Wi-Fi/Ethernet/VPN path works; a VPN needs an underlying independent internet connection.
3. Ensure system time is sane and NTP has a route. A 1970 clock can break TLS; a captive portal can return the wrong server certificate. Do not disable TLS checks to work around either.
4. Open the console and confirm the existing vault is CONFIGURED.
5. Choose [3] with the existing vault passphrase.
6. Validate with an account that has independent recovery before relying on it.

If the vault appears missing, stop and investigate paths/storage. Do not run [2] as a repair action. A fresh vault is a different authenticator and will not restore old registrations.

## 11. Console appearance and diagnostics

The English ANSI dashboard groups SETUP, CONTROL and INSPECT. Detail views pause for Enter. A short startup animation is cosmetic; it does not weaken validation or show secret length.

```text
NANO_UI_NO_ANIMATION=1 /opt/nano-fido/configure.sh
NO_COLOR=1 /opt/nano-fido/configure.sh
TERM=dumb /opt/nano-fido/configure.sh
```

These preferences are process-local. Color needs an interactive ANSI terminal. Maximize a small terminal if the dashboard scrolls. Plain mode is better for simple transcript-based testing. Never record a session while entering real secrets.

Menu [1]/[6] and the following command are passive:

```sh
/opt/nano-fido/configure.sh --status
```

Diagnostics show memory/runtime mount, binary SHA256, USER input-node identity and file metadata only. Do not post raw tailnet status, configuration files, vaults, screenshots with real identifiers or account/request logs in public issues.

## 12. Build and first installation

This is installation of an authenticator bundle on an already functioning supported image, not an SD-flashing guide. Preserve your recovery path and any existing vault. Official board/image references are in README.md.

### Build on Windows

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\build-nano.ps1
```

The execution-policy option affects only that process. The script verifies modules, runs uncached host tests and host/target vet, builds Linux/riscv64 with conservative rva20u64 and CGO disabled, and compiles target test binaries. It does not contact or modify a board. Build artifacts and test logs stay under ignored `out/`.

The setup-feature suite passed 72 host cases including subtests. UI styling has separate mock-only tests. Do not confuse cross-compilation with actual target execution.

### Copy a checked first-install bundle

Set your own non-secret management hostname. This example intentionally uses no operational address.

```powershell
$NanoHost = 'your-nano-management-host'
ssh "root@$NanoHost" 'umask 077; test ! -e /opt/nano-fido-install; mkdir /opt/nano-fido-install'
scp -O .\out\nano-fido .\nano\configure.sh .\nano\service.sh .\nano\usb-gadget.sh .\nano\install.sh "root@${NanoHost}:/opt/nano-fido-install/"
$Digest = (Get-Content .\out\SHA256SUMS.txt).Split(' ')[0]
ssh "root@$NanoHost" "sh /opt/nano-fido-install/install.sh /opt/nano-fido-install/nano-fido $Digest"
```

`scp -O` uses legacy SCP for images without SFTP support. Use a client that supports it. Do not disable host-key checks or substitute an unverified digest. No shared/static key or password helper is included in the repository.

The installer checks the binary hash and script syntax, refuses an existing binary/symlink destination, and installs under `/opt/nano-fido`. It does not initialize the vault/PIN, modify SSH, enable HID or add a boot auto-unlock service.

## 13. Backups, forgotten credentials and recovery

### Backup

Before valuable registrations, establish a private backup/recovery plan; that plan is not comprehensively verified by this prototype.

1. Use independent management and stop through [4].
2. Preserve the encrypted vault and its owner-only permissions in a trusted, access-controlled backup location, preferably encrypted at rest.
3. Keep the vault passphrase separately in an appropriate private manager.
4. Never store a backup, full SD image, PIN or management/VPN identity inside this repository or a public cloud link.
5. Do not overwrite an existing live vault during an upgrade or troubleshooting.

A whole-card image can contain Wi-Fi/SSH/VPN secrets in addition to FIDO state. Encrypt and protect it accordingly. The repository's ignore rules are only a safety net, not permission to place private files in the tree.

Restoring an old snapshot can roll back counters and PIN retry state. This is one reason SD/root access is not a hardware security boundary. Restoration is not a normal way to replenish PIN guesses, and relying parties may react to counter rollback. No safe one-click restore/reset feature is claimed.

### Forgotten vault passphrase

The FIDO PIN is not a substitute. Do not delete/reinitialize the vault expecting old logins to recover. Use another RP login method and a planned private recovery process. The project provides no passphrase recovery or hidden key escrow.

### Forgotten or blocked FIDO PIN

Do not repeatedly guess: eight total retries persist, including zero. Three consecutive errors additionally block the process/session; restarting does not restore the total. Reset is rejected. Use independent account access and obtain a deliberate recovery review rather than deleting state.

### Corrupt/missing storage

Preserve the affected card/state privately and stop writes if failure is suspected. Do not repeatedly initialize, run destructive filesystem commands or post the file publicly. No guide step instructs deleting an owner vault.

## 14. Maintenance and upgrades

`nano/install.sh` is a checked **first-install** helper, not an updater. Its existing-binary refusal is intentional.

For an upgrade: identify the version, stop cleanly through independent management, make a protected backup, verify the candidate binary/scripts and compatibility, inspect actual target/runtime state, and perform a reviewed replacement while preserving `/var/lib/nano-fido`. Do not overwrite a running executable or blindly rerun lab scripts. Keep a private rollback plan. This project does not yet provide a production-safe automatic update workflow.

The upstream module path is retained for imports in this specialized downstream. Desktop/USB-IP demos and vendor drivers/certificates are not needed. Do not install a random Windows driver just because a browser flow fails; the intended interface is standard FIDO HID.

The physical-lab controller and synthetic-vault helpers are for deliberate experiments only. They are not the owner console and must not be pointed at real state. Never run broad external Reset/destructive suites with other keys attached.

## 15. CLI reference

Prefer the console for normal use. The adapter is root-only and expects controlled paths.

| Flag | Meaning / restriction |
|---|---|
| --vault | Encrypted state path; console fixes the owner path |
| --pass-file | Regular 0600 one-time secret file on operator-verified RAM storage, consumed on read |
| --initialize | New-path-only initialization; refuses an existing path |
| --initial-pin-file | Regular 0600 one-time initial PIN file; initialization only |
| --button-event | Verified gpio-keys USER evdev node |
| --button-value | Alternative verified active-low GPIO value path; do not re-export USER |
| --terminal-approval | Test-only human token mode, not physical presence |
| --hid | Confirmed gadget node, not an assumed hidg index |
| --ready-file | Exclusive private runtime marker for supervised startup |

Normal operation requires exactly one approval mode. Initialization is separate and must not include a running approval mode or readiness flag. Real passphrase/PIN values never belong in these arguments. Go/OS RAM erasure is not guaranteed.

Installed helpers:

```sh
/opt/nano-fido/configure.sh --help
/opt/nano-fido/configure.sh --status
/opt/nano-fido/service.sh status
```

Direct service start requires a console-generated private RAM pass-file path and verified input node; it is not a recommended hand-written password command. Direct USB helper mutations require the same recovery care as the console. These helpers contain no Reset or owner-vault deletion operation.

## 16. Test evidence and support checklist

Keep the evidence categories distinct:

- Automated host/target software tests: specific code paths and filesystem helpers.
- Physical USB/RP-verifier tests: actual Nano transport and independently verified operations, with three real USER approvals in the later run.
- Mock UI tests: presentation/hidden input/English/ANSI behavior, not live cryptography or owner state.
- Token2 demo: operator-reported browser success, not an independently captured multi-browser matrix.
- Outstanding: production security, broader browser/options, cancellation/concurrent channels, physical negative-button cases, cold boot and power loss.

For support, share only:

- Software version/commit and build tool versions.
- Board/image/kernel family, without unique serial/account identifiers.
- The exact non-secret error wording and selected menu number.
- Whether status says CONFIGURED, LOCKED/UNLOCKED and HID linked.
- Browser/OS versions and relevant test options.

Do not share secret inputs, vault data, private keys, login/enrollment URLs, actual network identifiers, private helpers, raw account lists or full console recordings. See [troubleshooting](TROUBLESHOOTING.md) for message-specific next steps.
