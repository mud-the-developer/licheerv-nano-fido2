# Security model and limitations

## What is and is not protected

The authenticator stores credentials on SD in a passphrase-encrypted vault. It validates RP binding and PIN authentication and requires an explicit approval path. Files are owner-only and updates use atomic replacement and fsync. These are functional software protections, not a tamper-resistant hardware boundary.

An attacker with Linux root, a compromised boot image, privileged memory access, or access to an unlocked device can potentially extract keys or the unlocked wrapping key. Secure boot, secure element/TPM-backed FIDO private keys and reliable memory erasure are not implemented. Development SSH and VPN are additional attack surfaces, not key protection. Remove default administration credentials before any real-account trial.

## Current gaps

- USER evdev approval is not implemented or physically pressed in a verified credential operation. Terminal approval is test-only.
- Synchronous approval can block CANCEL. Concurrent channel isolation, partial-message timeouts and in-flight resynchronization require work.
- Three consecutive incorrect PINs block the current process/session; process restart clears that session block. The persisted total of eight retries is separate and survives restart, including zero.
- Reset is rejected, not implemented. Do not advertise commercial reset/recovery behavior.
- U2F inherits upstream behavior and has not received a separate comprehensive hardware review.
- Browser WebAuthn API, cold boot, interrupted SD writes, reconnect cycles and backup/recovery are not comprehensively tested.
- No independent penetration test, dependency vulnerability review, race-detector run or FIDO certification has been completed.

## Memory fix

The 128 MiB target exposed consecutive 32 MiB scrypt workspaces that caused OOM. The client caches a session wrapping key and explicitly reclaims the temporary KDF workspace. scrypt parameters remain N=32768, r=8, p=1. Every save generates a fresh data key and AES-GCM nonces. Tests check old-format interoperability and malformed ciphertext rejection. The cache is a secret in RAM; it is not secure hardware storage.

## Operational rules

Use only disposable accounts with an independent login method. Never run generic Reset/destructive suites against attached keys. Select the intended device explicitly. Preserve a known-working USB-independent management route before changing UDC/configfs. Do not re-export the USER GPIO that is already owned by gpio-keys. Do not hold USER during power-on/reset while testing approvals.

Never put vault passphrases, FIDO PINs, Wi-Fi credentials, SSH private keys, tailnet state, authentication URLs, raw HID traces, or live credential material in Git or public issue attachments. Use private communication for sensitive incidents and rotate/revoke leaked credentials first. A secret scan is not proof of security.
