# Documentation index

## Operate the device

1. **[Complete user guide](USER-GUIDE.md)** — equipment, verified management access, first setup, passphrase versus PIN, dashboard states, daily unlock, USER, browser tests, lock/exit, power cycles, install, backups, maintenance and CLI reference.
2. **[Troubleshooting](TROUBLESHOOTING.md)** — setup failure, existing vault, wrong credential, USB/UDC, input events, browser/Token2, clock/TLS, memory and safe support information.
3. **[Configuration reference](CONFIGURATION.md)** — shorter menu instructions, English ANSI/plain behavior and installation overview.

## Understand evidence and risk

- [Test status](TEST-STATUS.md) separates automated software, target/SD, physical USB/USER, mock UI and operator-reported Token2 evidence.
- [Security model](SECURITY.md) explains root/SD/RAM/boot limitations, PIN limits and unfinished protocol paths.
- [Public audit](PUBLIC-AUDIT.md) and [per-file inventory](PUBLIC-FILE-AUDIT.csv) describe publication hygiene, not certification.

## Diagrams

Created/checkpointed through local Excalimate MCP; editable V2 projects accompany the static SVG snapshots.

- [Architecture](diagrams/architecture.svg) / [editable source](diagrams/architecture.excalimate.json)
- [Approval and encrypted state](diagrams/approval-vault-flow.svg) / [editable source](diagrams/approval-vault-flow.excalimate.json)
- [Built-in buttons and remaining work](diagrams/buttons-and-status.svg) / [editable source](diagrams/buttons-and-status.excalimate.json)
- [First setup and daily use](diagrams/daily-usage.svg) / [editable source](diagrams/daily-usage.excalimate.json)
- [Tool provenance](diagrams/provenance.json)

No document contains an operator password, operational host address, enrollment link, unique device serial or private state file. Supply your own verified environment values; never turn placeholders into shared credentials.
