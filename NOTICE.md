# Attribution and scope

This is a specialized Nano integration derived from BulwarkID's MIT-licensed Virtual FIDO, base commit `512d8a3fef0e073171a7ef3261f300e8a5e48694`.

The original copyright and MIT permission notice are preserved in LICENSE. Nano-specific integration changes and documentation are published by the repository maintainers under the same MIT terms.

The original Go module path is retained for internal import compatibility. This repository intentionally excludes the USB/IP demo, macOS/Windows driver trees, vendor test certificates and binary libraries. It targets the Linux USB HID gadget adapter and its tests, not the upstream desktop product.

Manufacturers' schematics are linked, not redistributed. The explanatory diagrams are generated for this project using Excalimate MCP. Dependency source/binaries, Python environments, device identity files, credentials, raw local logs and privately generated keys are not distributed here.

This is not an official release of Sipeed, BulwarkID, Yubico, FIDO Alliance or Excalimate. No FIDO certification, hardware-backed private-key protection, compatibility certification or production-readiness claim is made.
