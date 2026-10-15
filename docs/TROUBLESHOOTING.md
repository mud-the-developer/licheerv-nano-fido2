# Troubleshooting without losing credentials

> Preserve the encrypted vault. Never delete it, reinitialize it, exhaust PIN guesses, disable certificate checks or run a generic Reset suite as a troubleshooting shortcut.

Start with [USER-GUIDE.md](USER-GUIDE.md). Status and diagnostics are metadata-only; they do not prove the vault can be decrypted or that the device is production-secure.

## Safe first checks

1. Confirm you are administering the intended Nano over a verified independent connection.
2. Run `/opt/nano-fido/configure.sh --status`, or use menu [1].
3. Use [6] for memory, runtime mount, binary hash, input-node identity and permissions metadata.
4. Record the exact non-secret message and what menu operation produced it.
5. If state is unexpected, stop before changing files or starting parallel controllers.

Do not attach a vault, passphrase, PIN, Wi-Fi config, tailnet state, private SSH material, enrollment URL or raw account/request logs to a public issue.

## Opening the console

| Symptom/message | Meaning | Safe next step |
|---|---|---|
| Root required | Current adapter/management bundle expects root | Use the verified administration account; do not weaken file modes |
| Install the checked bundle... | Expected binary or helper is absent | Verify deployment and its checksum; do not assume an arbitrary binary is equivalent |
| Interactive TTY required | SSH session did not allocate a terminal | Reconnect using `ssh -t` |
| /run must be RAM-backed tmpfs | Secret-file location is not the expected RAM mount | Stop; verify the supported image/runtime instead of putting secrets on SD |
| Another menu or a stale lock exists | Exclusive console lock is present | Close the other menu with [0]; if crashed, have the administrator verify ownership before touching the lock |
| No color/animation | Plain/no-color mode or limited terminal | Inspect TERM/NO_COLOR; set a normal ANSI terminal or keep the plain fallback |
| Detail output disappears too quickly | ANSI detail views require Enter; plain transcripts differ | Use the pause prompt or `NO_COLOR=1` for a plain view |
| Menu says UNLOCKED even after closing a window | [0] closes only the UI | Reopen through independent management and use [4] if you intend to stop |

Never remove an active lock directory to run a second setup session. If unsure whether the first is active, investigate from a separate trusted terminal; do not guess.

## Setup does not create a vault

`No regular owner vault. Complete first setup.` means unlock cannot find a regular owner file. It does **not** tell you why the earlier setup did not finish.

Check the retained `Last setup result` and preceding initializer error:

- Confirmation must be `SETUP` or `y`. Enter/another answer cancels; selecting [2] alone does not create anything.
- Vault passphrase must be at least 16 bytes. Short input retries the same step.
- Repeated vault inputs must match exactly. Input is hidden, including spaces.
- PIN inputs must match, differ from the vault passphrase and satisfy at least four UTF-8 characters / at most 63 bytes.
- The backend must accept the state directory's owner/mode and complete its atomic save.

Only choose [3] after `SETUP COMPLETE` and vault `CONFIGURED`. If no clear error is visible, share only the message wording and software version. Do not send the values to prove they meet the rules.

### Existing vault refusal

`Vault exists. Initialization will not overwrite it` or the equivalent CLI refusal is intentional. Choose [3] with the existing passphrase. Do not remove/rename the file merely to get setup to proceed. A fresh identity cannot authenticate an old RP registration.

### Permission/owner errors

The vault must be a real owned regular 0600 file; its immediate directory must be a real owned 0700 directory. The root-only deployed adapter therefore expects root ownership. Symlinks and unexpected modes are refused.

Inspect metadata before any permission change. Do not run blanket recursive chmod/chown or follow an unexpected symlink. On a new supported installation the helper creates the correct private paths. Existing unexpected state deserves review, not an automatic repair.

## Unlock/start problems

| Symptom/message | Meaning | Safe next step |
|---|---|---|
| No regular owner vault | State absent, non-regular or unexpected | Check [2] completion and storage/path; do not initialize if an older vault should exist |
| Empty passphrase / cancel | No unlock attempted | Re-run [3] when ready |
| Wrong passphrase / state failure | Decryption or restored-state validation failed | Stop guessing; use the exact existing passphrase; preserve ciphertext |
| Use Wi-Fi/VPN or local UART... | Current start/stop path is USB SSH | Reconnect through a tested independent path |
| Unexpected live PID / different process | Runtime PID cannot be safely attributed | Inspect process identity; do not force-kill or replace its marker blindly |
| Authenticator already unlocked/running | Managed instance is already active | Use it; do not start another instance |
| Unlock/start failed; restoring original USB | Ready PID was not confirmed or process exited | Allow rollback/enumeration to settle, inspect status and retain vault |
| Prior managed USB state exists | A previous controller state remains | Do not overwrite it; inspect known ownership and recover through the managed service |

Readiness requires both the expected process and matching exclusive marker. Merely seeing a PID, HID link or encrypted file is not proof of a healthy unlocked instance. A wrong passphrase never authorizes creation of an empty replacement vault.

## USB enumeration and restoration

Expected hardware/software state is the official configfs gadget `g0/c.1`, existing network function(s), and one matching FIDO HID. The helper refuses unrelated HID functions, an already-owned link, mismatched descriptors and an unexpected UDC.

| Symptom/message | Meaning | Safe next step |
|---|---|---|
| Official g0/c.1 configuration missing | Unsupported/different base USB setup | Inspect image/official setup; do not create a guessed gadget over existing state |
| Another HID function exists | Device-node mapping is ambiguous | Identify the existing function and owner; do not overwrite it |
| Existing HID descriptor differs | Existing function is not the expected FIDO format | Preserve it and review; do not force-write the descriptor |
| HID already linked; refuse ownership | Another/previous controller may own it | Inspect ownership and managed runtime state |
| USB not bound | Base gadget is unbound or failed | Use independent recovery and known-good configuration; do not blindly assign controller names |
| USB restoration not confirmed | Rebinding did not meet expected state | Keep independent access; inspect UDC/role/host enumeration before another mutation |
| USB SSH disappeared briefly | Re-enumeration or DHCP can lag | Continue through Wi-Fi/VPN; allow settling before a single checked reconnect |

Known issues discovered during development included configfs rewriting absolute symlink targets as relative, the kernel rejecting a second unbind of an already-unbound gadget, device-role application and host/DHCP settling time. The managed controller handles these observed cases; that is not exhaustive reconnect/power-loss validation.

Do not repeatedly bounce UDC while an operation is active. Do not reset a whole USB host controller or change GPIO/OTG power roles as a blind workaround. If recovery needs physical intervention, make that a deliberate administrator action with the encrypted state preserved.

## PIN and USER problems

| Symptom | Check / limitation |
|---|---|
| Vault passphrase entered into Windows security-key PIN prompt | These are different credentials; use the FIDO PIN |
| FIDO PIN entered into [3] | Use the vault passphrase there |
| Wrong PIN | One failure consumes persisted total retries; do not repeatedly guess |
| PIN auth blocked after three consecutive failures | Current session limit; restarting does not restore the total retry budget |
| Total retries reach zero | Persisted block. Reset/recovery is not implemented; use independent account access and deliberate review |
| USER device not found | Check gpio-keys device identity/capability and image mapping; do not assume an event index on every image |
| No approval while key already held | Release it, then make a fresh press after the request |
| Repeat/wrong-key/lost input | Repeats/unrelated keys are ignored; dropped/error state fails closed |
| Timeout | No accepted fresh USER event arrived within the request deadline; do not replace it with automatic approval |
| RESET was pressed | Board/operation may have restarted. It is not approval; wait for normal boot/clock/network and inspect state |

The documented USER circuit is GPIOA30 active-low and the tested input code is 431. The kernel owns the GPIO through gpio-keys. Do not re-export it or change its direction. Real negative held/repeat/timeout/removal tests still need expansion beyond the existing state-machine tests.

## Browser and Token2 demo

The operator reported that the Token2 demo worked. Exact ceremonies, options and browser/version were not independently captured. Do not generalize this to enterprise attestation, every browser or OS sign-in policy.

- Confirm UNLOCKED / CONFIGURED / FIDO HID LINKED before the browser request.
- Choose USB security key, not Windows Hello or a phone/hybrid passkey, for the intended trial.
- In the demo, complete Register before Log in and keep the same session.
- Select appropriate user-verification/roaming-key options if needed; exact UI labels vary.
- An exclusion-error option is supposed to reject an already-registered key. That is different from a broken authenticator.
- A DOM `NotAllowedError` is ambiguous: cancellation, timeout, user gesture, origin/policy or unavailable transport can all be involved. It does not alone prove a wrong PIN or successful signing.
- Unknown or absent certification metadata is expected for an uncertified custom prototype. Do not impersonate a certified model.
- If an advanced option fails, record sanitized options and error wording rather than weakening the authenticator's PIN/approval requirements.

Do not publish full attestation/credential dumps, raw HID traffic or account identifiers simply because a demo labels them logs. Do not Reset the Nano or delete the whole vault to remove a demo credential.

## Network/TLS/clock problems

A working Wi-Fi association does not prove internet access. A captive portal can return a network controller's certificate instead of the requested server's certificate. A 1970 clock can also break TLS.

Use a trusted supported network and verify normal certificate validation. Do not add an unverified interception CA, use curl -k or disable SSH host-key checking. A VPN still needs independent underlying connectivity. Keep its private state out of Git; deleting it can change the registered device identity/address.

Actual boot behavior of networking, NTP and the FIDO unlock model remains a separate test. The installed FIDO console does not automatically unlock after boot.

## Memory and power loss

The tested image gives Linux approximately 128MiB. Large additional services can exhaust it even though the board has more physical DDR reserved for other uses. A historical OOM was fixed without reducing scrypt strength by reclaiming workspace and caching only the session wrapping key.

Go memory limits are soft heap limits, not total RSS caps. Do not add SD swap for unlocked-key memory as a quick fix. If the kernel kills a process, preserve state and inspect non-secret OOM metadata; do not loop-start it or reset the vault. A lower memory footprint does not imply key-extraction protection.

File/dir fsync tests passed, but interrupted SD writes and power-loss recovery are not comprehensively proven. Avoid pulling power during writes, do not remove SD while Linux runs, and keep an independent RP login method.

## What to share for help

Share software commit, board/image family, browser/OS versions, menu choice, sanitized exact error, and the high-level dashboard state. Do not share PIN/passphrase/private keys, real network/account/device identifiers, enrollment URLs, raw logs or state files. A photo of board labels should be reviewed for unique identifiers before posting publicly.
