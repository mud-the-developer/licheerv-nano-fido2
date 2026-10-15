"""English/ANSI UI regression with mock app/service; never touches owner state."""

from __future__ import annotations

import argparse
import json
import os
import queue
import secrets
import subprocess
import tempfile
import threading
import time
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    for name in (
        "ssh",
        "scp",
        "askpass",
        "target",
        "host-key-alias",
        "source",
        "result",
    ):
        parser.add_argument("--" + name, required=True)
    a = parser.parse_args()
    fixture = "/run/nano-fido-ui-style-fixture"
    options = [
        "-o",
        "HostKeyAlias=" + a.host_key_alias,
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        "ConnectTimeout=8",
        "-o",
        "NumberOfPasswordPrompts=1",
        "-o",
        "PreferredAuthentications=password",
        "-o",
        "PubkeyAuthentication=no",
        "-o",
        "KbdInteractiveAuthentication=no",
    ]
    target = "root@" + a.target
    env = os.environ.copy()
    env.update(
        SSH_ASKPASS=str(Path(a.askpass).resolve()),
        SSH_ASKPASS_REQUIRE="force",
        DISPLAY="nano-ssh",
    )
    result = {
        "status": "running",
        "mock_only": True,
        "owner_vault_touched": False,
        "checks": [],
    }
    master, pin = secrets.token_urlsafe(32), str(secrets.randbelow(90000000) + 10000000)

    def command(text: str, check=True):
        run = subprocess.run(
            [a.ssh] + options + [target, text],
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=25,
            check=False,
        )
        if check and run.returncode:
            raise RuntimeError("mock fixture command failed: " + str(run.returncode))
        return run

    def session(steps, fancy: bool):
        setting = (
            "TERM=xterm-256color NO_COLOR='' NANO_UI_NO_ANIMATION=0"
            if fancy
            else "TERM=dumb NO_COLOR=1 NANO_UI_NO_ANIMATION=1"
        )
        proc = subprocess.Popen(
            [a.ssh, "-tt"]
            + options
            + [target, f"{setting} sh {fixture}/configure-test.sh"],
            env=env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            bufsize=0,
        )
        output, incoming = proc.stdout, proc.stdin
        if output is None or incoming is None:
            raise RuntimeError("missing mock UI pipes")
        messages = queue.Queue()

        def read():
            while True:
                part = output.read(1)
                if not part:
                    break
                messages.put(part)
            messages.put(None)

        threading.Thread(target=read, daemon=True).start()
        transcript, cursor, sent = b"", 0, 0
        deadline = time.monotonic() + 60
        try:
            while time.monotonic() < deadline:
                try:
                    part = messages.get(timeout=0.2)
                except queue.Empty:
                    continue
                if part is None:
                    break
                transcript += part
                if sent < len(steps):
                    prompt, answer = steps[sent]
                    found = transcript.find(prompt.encode(), cursor)
                    if found >= 0:
                        cursor = found + len(prompt.encode())
                        incoming.write((answer + "\n").encode())
                        incoming.flush()
                        sent += 1
            proc.wait(timeout=8)
            if proc.returncode or sent != len(steps):
                raise RuntimeError("mock UI did not finish expected prompts")
            if master.encode() in transcript or pin.encode() in transcript:
                raise RuntimeError("synthetic secret was echoed")
            if any(c > 127 for c in transcript):
                raise RuntimeError("non-English/non-ASCII UI output observed")
            if fancy and (
                b"\x1b[2J" not in transcript
                or b"\x1b[?25l" not in transcript
                or b"\x1b[?25h" not in transcript
            ):
                raise RuntimeError("dashboard/animation/cursor restoration missing")
            if not fancy and b"\x1b[" in transcript:
                raise RuntimeError("plain fallback emitted ANSI control codes")
            return transcript.decode("ascii")
        finally:
            if proc.poll() is None:
                proc.terminate()
                proc.wait(timeout=5)

    with tempfile.TemporaryDirectory(prefix="nano-ui-style-") as temporary:
        temp = Path(temporary)
        fixture_owned = False
        try:
            command(f"set -e; [ ! -e {fixture} ]; umask 077; mkdir {fixture}")
            fixture_owned = True
            source = Path(a.source).read_text(encoding="utf-8")
            for old, new in [
                ("APP=/opt/nano-fido/nano-fido", f"APP={fixture}/mock-app.sh"),
                (
                    "SERVICE=/opt/nano-fido/service.sh",
                    f"SERVICE={fixture}/mock-service.sh",
                ),
                (
                    "VAULT=/var/lib/nano-fido/vault.enc",
                    f"VAULT={fixture}/vault.fixture",
                ),
                ("LOCK=/run/nano-fido-config.lock", f"LOCK={fixture}/menu.lock"),
            ]:
                if source.count(old) != 1:
                    raise RuntimeError(
                        "mock source remapping did not match exactly once"
                    )
                source = source.replace(old, new)
            (temp / "configure-test.sh").write_text(
                source, encoding="utf-8", newline="\n"
            )
            (temp / "mock-app.sh").write_text(
                """#!/bin/sh
set -eu
vault=''; passfile=''; pinfile=''
while [ "$#" -gt 0 ]; do
 case "$1" in
 --initialize) shift ;;
 --vault) vault=$2; shift 2 ;;
 --pass-file) passfile=$2; shift 2 ;;
 --initial-pin-file) pinfile=$2; shift 2 ;;
 *) exit 1 ;;
 esac
done
[ "$vault" = /run/nano-fido-ui-style-fixture/vault.fixture ]
[ ! -e "$vault" ] && [ -s "$passfile" ] && [ -s "$pinfile" ]
printf 'SYNTHETIC MOCK STATE ONLY' > "$vault"
echo 'Mock initializer complete; no real cryptography or hardware used.'
""",
                encoding="utf-8",
                newline="\n",
            )
            (temp / "mock-service.sh").write_text(
                """#!/bin/sh
case "$1" in
status)
 echo 'Authenticator: LOCKED / stopped (or startup unconfirmed)'
 if [ -f /run/nano-fido-ui-style-fixture/vault.fixture ]; then echo 'Encrypted vault: present (contents not read)'; else echo 'Encrypted vault: not initialized'; fi
 echo 'UDC: mock-controller'; echo 'FIDO HID not linked' ;;
*) echo 'Mock service never starts or stops real hardware.' ;;
esac
""",
                encoding="utf-8",
                newline="\n",
            )
            for path in temp.iterdir():
                subprocess.run(
                    [a.scp, "-O"]
                    + options
                    + [str(path), target + ":" + fixture + "/" + path.name],
                    env=env,
                    stdin=subprocess.DEVNULL,
                    capture_output=True,
                    timeout=25,
                    check=True,
                )
            command(f"chmod 700 {fixture}/*.sh; sh -n {fixture}/configure-test.sh")
            session(
                [
                    ("Select: ", "1"),
                    ("Select: ", "5"),
                    ("Select: ", "6"),
                    ("Select: ", "0"),
                ],
                False,
            )
            result["checks"].append(
                "English plain fallback, metadata/help/diagnostics, no ANSI"
            )
            text = session(
                [
                    ("Select: ", "2"),
                    ("Type SETUP: ", "no"),
                    ("Select: ", "2"),
                    ("Type SETUP: ", "y"),
                    ("blank cancels): ", "short"),
                    ("blank cancels): ", master),
                    ("Repeat vault passphrase: ", "synthetic-mismatch"),
                    ("blank cancels): ", master),
                    ("Repeat vault passphrase: ", master),
                    ("<=63 bytes): ", pin),
                    ("Repeat FIDO PIN: ", pin),
                    ("Select: ", "1"),
                    ("Press Enter to return", ""),
                    ("Select: ", "5"),
                    ("Press Enter to return", ""),
                    ("Select: ", "6"),
                    ("Press Enter to return", ""),
                    ("Select: ", "0"),
                ],
                True,
            )
            for expected in (
                "Last setup result:",
                "at least 16 bytes required",
                "Vault passphrases do not match",
                "Initial setup complete",
                "STEP 4 / 4",
            ):
                if expected not in text:
                    raise RuntimeError("missing English setup/feedback stage")
            result["checks"].append(
                "ANSI dashboard, short animation, cursor restoration and paused detail views"
            )
            result["checks"].append(
                "English setup, cancel/short/mismatch feedback, four steps, no secret echo"
            )
            command(f"test ! -e {fixture}/menu.lock")
            result["checks"].append(
                "mock lock cleanup; real app/service/vault paths were never invoked"
            )
            result["status"] = "passed"
        except (RuntimeError, OSError, ValueError, subprocess.SubprocessError) as error:
            result["status"] = "failed"
            result["error_type"] = type(error).__name__
            if isinstance(error, RuntimeError):
                result["error"] = str(error)
        finally:
            if fixture_owned:
                try:
                    cleanup = command(
                        f"rm -f {fixture}/configure-test.sh {fixture}/mock-app.sh {fixture}/mock-service.sh {fixture}/vault.fixture; rmdir {fixture}",
                        False,
                    )
                    result["fixture_cleanup_exit"] = cleanup.returncode
                    if cleanup.returncode:
                        result["status"] = "needs_review"
                except (OSError, subprocess.SubprocessError) as error:
                    result["status"] = "needs_review"
                    result["cleanup_error_type"] = type(error).__name__
            else:
                result["fixture_cleanup_skipped"] = "No confirmed ownership; existing or unknown fixture preserved."
            destination = Path(a.result)
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print("UI style smoke:", result["status"], "checks:", len(result["checks"]))
    return 0 if result["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
