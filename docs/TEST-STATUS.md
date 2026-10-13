# Test evidence — scope matters

Snapshot: 2026-10-13. No live account or live authenticator vault was used.

## Before publication

The full development workspace passed 56 host test cases including subtests, host and target go vet, and a Linux/riscv64 rva20u64 static cross-build. The publication tree removes unrelated desktop/USB/IP packages. Its own Windows host build passed **50 cases including subtests**, host/target vet and the RISC-V cross-build; that count is recorded separately rather than assumed to be 56.

Actual Nano Linux/SD execution passed all 11 report/storage helper tests: full/short report I/O, missing/empty vault cases, private modes/owner, atomic replacement, fsync and symlink rejection. Three selected target core tests passed: registration/authentication/reload, PIN changes and token invalidation, and persisted total retries including blocked zero. The core tests use synthetic in-memory support, not live HID credentials.

## Actual Windows USB HID experiment

The client selected only the intended Nano VID/PID. It never called Reset or changed another authenticator. A separate SD test vault and a RAM-only random passphrase were used. The PIN existed only in test-process memory. Three explicit human terminal approval dialogs were accepted; no automatic approval was used.

| Check | Result |
|---|---|
| CTAPHID INIT, empty and non-empty PING | Passed |
| GetInfo and strict canonical CBOR | Passed |
| PIN protocol 1 setup | Passed |
| MakeCredential | Passed |
| Independent RP/UP/UV and packed-attestation validation | Passed |
| GetAssertion and independent signature verification | Passed |
| One incorrect PIN / retries reduced to seven | Passed |
| Authenticator process restart / PIN, retries and SD credential retained | Passed |
| Old credential authenticates after restart / counter 1 to 2 | Passed |
| Correct PIN restores eight retries | Passed |

This is a host-library/RP-verifier experiment over physical USB, **not** proof that a real browser account or all Windows WebAuthn UI paths work.

## Failures were retained and investigated

1. Root's 0077 umask made an intended unsafe-permission fixture private. The test now explicitly chmods its disposable file to 0644. The actual access check was not weakened.
2. An initial target core process was OOM-killed at about 65 MiB anonymous RSS. Session key caching and immediate scrypt workspace reclamation fixed the repeated-allocation pattern without changing the work factor or encrypted vault format.
3. All physical protocol checks passed, but the original runner ended in `needs_review` because its restoration failed. Canonical configfs link checks, idempotent handling of an already-unbound UDC, device-role application and generation-scoped watchdogs were corrected. Manual recovery and a separate activation/restoration cycle were verified. USB enumeration/DHCP required settling before SSH reconnected.

The public record omits raw logs, actual addresses, SSIDs, unique device identifiers, login links and private state. It does not relabel the original runner as having succeeded automatically.

## Final device state after the experiment

The test authenticator was stopped, its temporary HID link removed, original network-only USB configuration restored, and both USB and independent management SSH reverified. The synthetic SD vault and RAM secret were removed. A live vault/PIN and always-on key service were **not** provisioned.

## Not yet verified

Real USER press/release approvals, real browser WebAuthn, hardware-enforced power-cycle limits, CANCEL, concurrent channels, cold boot, power loss, exhaustive reconnect/recovery, secure key storage and production security remain outstanding. USER hardware/input metadata was inspected read-only, but the operator could not press it during that investigation.
