"""Offline, whole-file publication hygiene checks; not a security certification.

Works on tracked and non-ignored candidate files. Never prints matched values.
Optional known-private literals must be supplied through a file outside the repo.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import ipaddress
import re
import subprocess
import sys
from pathlib import Path

RULES = {
    "private-key-material": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----"),
    "access-token": re.compile(r"(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{30,}|AKIA[A-Z0-9]{16}|sk-[A-Za-z0-9]{30,})"),
    "authentication-url": re.compile(r"https://login\.tailscale\.com/a/[A-Za-z0-9_-]+"),
    "personal-windows-path": re.compile(r"[A-Za-z]:[\\/]Users[\\/][^\\/\s]+"),
    "private-ssh-path": re.compile(r"(?:\.ssh[\\/](?:id_rsa|id_ed25519)|known_hosts[^\n]*[A-Za-z]:)"),
}
FORBIDDEN_SUFFIXES = {".enc", ".state", ".pfx", ".p12", ".pem", ".key", ".exe", ".dll", ".a", ".pyc", ".test", ".tgz", ".zip", ".log"}
IPV4 = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
# Exact reviewed raster only; a new/replaced image requires fresh visual review.
SCREENSHOT_SHA256 = "fbe238e193c6294967c1924f571a07f1f4c6b99e98a89dc6a748f6e8d667b82f"
REVIEWED_PNGS = {
    "docs/images/token2-demo-success.png": SCREENSHOT_SHA256,
}


def reviewed_image_issues(name: str, raw: bytes):
    expected = REVIEWED_PNGS.get(name)
    if expected is None:
        return None
    issues = []
    if hashlib.sha256(raw).hexdigest() != expected:
        issues.append("reviewed-image-digest-changed")
    if not raw.startswith(b"\x89PNG\r\n\x1a\n"):
        issues.append("reviewed-image-invalid-format")
    return issues


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--known-private-file", type=Path)
    args = parser.parse_args()
    root = args.root.resolve()
    if args.known_private_file:
        private = args.known_private_file.resolve()
        if private.is_relative_to(root):
            parser.error("private literal source must remain outside the repository")
        literals = [line for line in private.read_text(encoding="utf-8").splitlines() if line]
    else:
        literals = []
    candidates = subprocess.check_output(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"], cwd=root
    ).decode("utf-8").split("\0")
    rows, failures = [], []
    manifest = args.manifest.resolve() if args.manifest else None
    for name in sorted(set(filter(None, candidates))):
        path = root / name
        if path.is_symlink() or not path.resolve().is_relative_to(root):
            failures.append((name, "unsafe-path"))
            continue
        if path == manifest:
            continue  # The output cannot contain its own stable digest.
        raw = path.read_bytes()  # Inspect every byte of each public candidate.
        image_issues = reviewed_image_issues(name, raw)
        if image_issues is not None:
            rows.append((name, len(raw), hashlib.sha256(raw).hexdigest(), "pass" if not image_issues else "review:" + ";".join(image_issues)))
            failures.extend((name, issue) for issue in image_issues)
            continue
        issues = []
        if path.suffix.lower() in FORBIDDEN_SUFFIXES:
            issues.append("forbidden-file-type")
        if b"\0" in raw:
            issues.append("binary-content")
        try:
            text = raw.decode("utf-8-sig")
        except UnicodeDecodeError:
            text = ""
            issues.append("non-utf8-content")
        for rule, pattern in RULES.items():
            if pattern.search(text):
                issues.append(rule)
        for match in IPV4.finditer(text):
            try:
                address = ipaddress.ip_address(match.group())
            except ValueError:
                continue
            if not address.is_loopback and not address.is_unspecified:
                issues.append("non-placeholder-ipv4")
                break
        if any(value in text for value in literals):
            issues.append("known-private-literal")
        if path.suffix == ".svg" and re.search(r"<script|<foreignObject|\bon\w+\s*=|(?:href|src)\s*=\s*[\"'](?:file:|https?:|data:)", text, re.I):
            issues.append("active-or-external-svg-content")
        rows.append((name, len(raw), hashlib.sha256(raw).hexdigest(), "pass" if not issues else "review:" + ";".join(sorted(set(issues)))))
        failures.extend((name, issue) for issue in sorted(set(issues)))
    if manifest:
        manifest.parent.mkdir(parents=True, exist_ok=True)
        with manifest.open("w", encoding="utf-8", newline="") as stream:
            writer = csv.writer(stream, lineterminator="\n")
            writer.writerow(("path", "bytes", "sha256", "whole_file_scan"))
            writer.writerows(rows)
    for name, issue in failures:
        print(f"REVIEW {name}: {issue}")  # Never disclose a matched value.
    print(f"Inspected {len(rows)} complete candidate files; findings={len(failures)}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
