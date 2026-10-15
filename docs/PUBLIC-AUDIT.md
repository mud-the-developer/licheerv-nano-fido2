# Public publication hygiene review

This repository was exported into a **new, separate Git history** from a larger local development workspace. The workspace itself was not added to Git or pushed. This review is about avoiding accidental disclosure, not a cryptographic/security certification.

## File-by-file process

1. Use an explicit source allowlist: Nano-relevant Go packages, synthetic tests, dependency manifests, hardware test/controller source, a generic service, authored documentation, authored MCP diagrams and the upstream MIT license.
2. Read every public candidate file in full as bytes, reject binary/non-UTF8/private file types, scan private-key blocks, credential/token formats, authentication URLs, personal Windows paths, SSH-key paths, real IPv4 addresses and active/external SVG content. `scripts/audit-public.py` performs this offline pass without printing matched values.
3. Review the meaningful findings/contexts: key/PIN/vault field names in source are code/schema; synthetic unit-test PINs/passphrases are labeled test-only and are not operator credentials; go.sum values are public dependency checksums; hardware VID/PID, USER circuitry and input codes are public board facts.
4. Perform an independent **Gitleaks 8.30.1** scan with redaction and built-in rules. The scanner's official release checksum was checked before execution. No hosted scanner or external source upload is used.
5. Inspect Git's exact non-ignored candidate/staged paths, run tests/vet/cross-build, validate SVGs and look at raster previews, then repeat the scan over the new commit history before any public push.

The local exact-match check against known private Wi-Fi/network/device/path values returned no matching public candidate paths. Those values and that private input were not saved in this repository. Independent directory scanning also returned zero findings before publication.

The per-file inventory is [PUBLIC-FILE-AUDIT.csv](PUBLIC-FILE-AUDIT.csv), with each file's size, SHA256 and whole-file check result. It excludes its own digest because a file cannot contain its own stable hash. Git's staged tree and final independent scan cover the inventory file too. This is not a claim that every code path has received an independent security audit.

## Excluded or generalized

| Category | Treatment |
|---|---|
| Real Wi-Fi SSID/password/configuration | No operational configuration copied; never written into diagrams/docs |
| Actual LAN/VPN addresses, hardware serial, local hostname or account/peer list | Omitted; hardware client requires the operator's target and trusted-host alias |
| SSH password helper/private keys/known_hosts | Not copied; optional private helper must remain outside the repo |
| VPN state, private node keys, browser enrollment link | Never copied or read for publication |
| FIDO vault, passphrase, PIN and live credential material | Not copied; tests use newly generated or explicitly synthetic values |
| Raw local result/log files | Replaced by a written, scope-limited test summary; original local records remain private |
| Upstream Windows driver PFX/test certificate and compiled libraries | Entire unrelated driver/macOS/desktop tree excluded, even where publicly supplied upstream |
| .venv, caches, npm tools, compiled authenticator/test binaries, downloaded archives | Excluded and ignored |
| Manufacturer PDFs/crops | Not redistributed; official links and newly authored explanatory diagrams are used |
| Local Git history and machine's personal Git email | Not reused; new history with public GitHub noreply identity |

The repository retains the old Go module path for source import compatibility; that is upstream attribution, not a credential. Runtime device file paths such as `/dev/hidg0` and root-only state-directory names describe the design and do not contain actual state.

## Diagram review

Four diagrams were produced through actual **Excalimate MCP 0.5.0**, local stdio, using read_me/create_scene/managed-animation/validation/checkpoint tools. The server process used a task-local home/temp environment rather than credential-bearing configuration. No external share tool or hosted model was called. SVG snapshots contain no scripts, foreignObject, event handlers, remote images or private data. Editable V2 checkpoints and tool provenance are included.

## Operator-guide update review

The detailed operator handbook, troubleshooting matrix and documentation index were added with generic host/path placeholders only. The Token2 URL is a public demo reference; its reported success is attributed to the operator rather than presented as an independently captured browser matrix. The new daily-use diagram contains only generic credential roles and menu choices. No owner device was accessed, stopped or reconfigured to publish these documents.

This update also publishes the previously local USER approval, checked initializer, English TUI and isolated mock-UI test source. It does not publish private test output, a live vault, secret input, operational network data, compiler binaries or the task-local MCP/npm/scanner environment.

## Repeat locally

```text
python scripts/audit-public.py --manifest docs/PUBLIC-FILE-AUDIT.csv
gitleaks dir . --redact --ignore-gitleaks-allow --no-banner
gitleaks git . --redact --ignore-gitleaks-allow --no-banner
```

Python environment setup should use uv. An optional file of known-private literals can be passed to the offline audit tool, but that file must be outside the repository and must never be committed. Do not print it or attach it to issues.

Even a zero-finding scan can miss credentials, indirect identifiers or vulnerable logic. Review future changes before publication, keep private state out of the tree, and revoke/rotate any real material accidentally exposed. Functional test success does not change the unresolved limitations in SECURITY.md.
