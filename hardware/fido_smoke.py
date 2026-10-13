"""Real Nano HID tests using disposable credentials and explicit human approvals.

No Reset or credential-management deletion; no live account/vault or auto-approval.
The disposable lab vault is removed after testing. Run elevated on Windows.
PINs, private keys and approval nonces are never logged.
"""
from __future__ import annotations

import argparse
import ctypes
import json
import logging
import os
import re
import secrets
import subprocess
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from fido2.attestation.packed import PackedAttestation
from fido2.ctap import CtapError
from fido2.ctap2.base import Ctap2
from fido2.ctap2.pin import ClientPin, PinProtocolV1
from fido2.hid import CtapHidDevice, list_descriptors, open_connection
from fido2.server import Fido2Server
from fido2.webauthn import (
    AttestationConveyancePreference,
    AttestationObject,
    AuthenticationResponse,
    AuthenticatorAssertionResponse,
    AuthenticatorAttestationResponse,
    CollectedClientData,
    PublicKeyCredentialRpEntity,
    PublicKeyCredentialUserEntity,
    RegistrationResponse,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

RP_ID = "nano-hardware-test.invalid"
ORIGIN = "https://" + RP_ID
CONTROL = "/opt/nano-fido-hwtest/hw-control.sh"
VID, PID = 0x359F, 0x2120
logging.getLogger().setLevel(logging.CRITICAL)


def progress(text: str) -> None:
    print(text, flush=True)


@contextmanager
def Timeout(seconds: float):
    event = threading.Event()
    timer = threading.Timer(seconds, event.set)
    timer.daemon = True
    timer.start()
    try:
        yield event
    finally:
        timer.cancel()


def verify_attestation(obj: AttestationObject, digest: bytes) -> None:
    PackedAttestation().verify(obj.att_stmt, obj.auth_data, digest)


class Nano:
    def __init__(self, args):
        self.env = os.environ.copy()
        self.base = [args.ssh, "-o", "HostKeyAlias=" + (args.host_key_alias or args.target),
                     "-o", "StrictHostKeyChecking=yes", "-o", "ConnectTimeout=8"]
        if args.askpass:
            # Optional, user-provided helper remains outside the repository.
            self.env.update(SSH_ASKPASS=str(Path(args.askpass).resolve()),
                            SSH_ASKPASS_REQUIRE="force", DISPLAY="nano-ssh")
            self.base += ["-o", "NumberOfPasswordPrompts=1", "-o", "PreferredAuthentications=password",
                          "-o", "PubkeyAuthentication=no", "-o", "KbdInteractiveAuthentication=no"]
        else:
            self.base += ["-o", "BatchMode=yes"]
        self.target = "root@" + args.target
        self.proc = None
        self.reader = None
        self.ready = threading.Event()
        self.approvals = 0
        self.denials = 0
        self.error = None

    def control(self, mode: str) -> str:
        if mode not in {"activate", "stop", "restore", "cleanup"}:
            raise ValueError("invalid control operation")
        result = subprocess.run(self.base + [self.target, f"sh {CONTROL} {mode}"],
                                env=self.env, stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                timeout=35, check=False)
        if result.returncode:
            raise RuntimeError(f"board control {mode} failed (exit {result.returncode})")
        return result.stdout.decode("utf-8", "replace")

    def start(self):
        self.ready.clear()
        self.error = None
        self.proc = subprocess.Popen(self.base + ["-tt", self.target, f"sh {CONTROL} run"],
                                     env=self.env, stdin=subprocess.PIPE,
                                     stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                     bufsize=0)
        self.reader = threading.Thread(target=self._read, daemon=True)
        self.reader.start()
        if not self.ready.wait(30):
            raise RuntimeError("authenticator did not become ready within 30 seconds")
        if self.error:
            raise RuntimeError(self.error)

    def _read(self):
        # Keep a bounded, in-memory transcript. Never write raw terminal output.
        text = ""
        request = ""
        process = self.proc
        if process is None or process.stdout is None:
            self.error = "missing SSH output stream"
            self.ready.set()
            return
        while True:
            raw = process.stdout.read(1)
            if not raw:
                break
            text = (text + raw.decode("utf-8", "replace"))[-8192:]
            if "Experimental Nano FIDO adapter ready" in text:
                self.ready.set()
            if "Stopped after an upstream/state error" in text or "HID write failed" in text:
                self.error = "board authenticator reported a state/transport failure"
            found = re.search(r'Request (\d+): RP="([^"\r\n]*)" user="([^"\r\n]*)"', text)
            if found:
                request = f"action={found.group(1)}, RP={found.group(2)}"
            match = re.search(r"TEST ONLY: type ([0-9a-f]{8}) within 30 seconds:", text)
            if not match:
                continue
            nonce = match.group(1)
            allowed_rp = found is not None and found.group(2) == RP_ID
            accepted = False
            if allowed_rp:
                message = (
                    "Nano FIDO2 실물 시험 요청입니다.\n\n" + request +
                    "\n\n등록/인증 요청이 맞으면 예를 눌러 주세요.\n"
                    "30초 안에 승인해야 합니다.\n"
                    "이것은 시험용 터미널 승인이고 물리 버튼 검증은 아닙니다."
                )
                # No is the default; there is no automated approval path.
                accepted = ctypes.windll.user32.MessageBoxW(
                    None, message, "Nano FIDO2 시험 승인", 0x4 | 0x20 | 0x100 | 0x10000 | 0x40000
                ) == 6
            if accepted:
                if process.stdin is None:
                    self.error = "missing SSH input stream"
                    break
                self.approvals += 1
                process.stdin.write((nonce + "\n").encode())
                process.stdin.flush()
            else:
                self.denials += 1
                # Do not send a matching token; the board denies after its deadline.
            text = ""
        if not self.ready.is_set():
            self.error = "SSH PTY or board authenticator exited before ready"
            self.ready.set()

    def stop(self):
        if self.proc:
            try:
                self.control("stop")
            finally:
                try:
                    self.proc.wait(timeout=8)
                except subprocess.TimeoutExpired:
                    self.proc.terminate()
                    self.proc.wait(timeout=5)
                self.proc = None
        if self.reader:
            self.reader.join(timeout=1)
            self.reader = None


def selected_device() -> CtapHidDevice:
    matches = [d for d in list_descriptors() if d.vid == VID and d.pid == PID]
    if len(matches) != 1:
        raise RuntimeError(f"expected exactly one Nano FIDO interface, found {len(matches)}")
    d = matches[0]
    if d.report_size_in != 64 or d.report_size_out != 64:
        raise RuntimeError("Nano FIDO report sizes are not 64 bytes")
    return CtapHidDevice(d, open_connection(d))


def register(server, ctap, client_pin, pin: str):
    user = PublicKeyCredentialUserEntity(id=b"disposable-nano-user", name="synthetic", display_name="Synthetic Nano test")
    options, state = server.register_begin(user, resident_key_requirement=ResidentKeyRequirement.REQUIRED,
                                           user_verification=UserVerificationRequirement.REQUIRED)
    client_data = CollectedClientData.create(CollectedClientData.TYPE.CREATE,
                                             options.public_key.challenge, ORIGIN)
    token = client_pin.get_pin_token(pin)
    with Timeout(50) as event:
        response = ctap.make_credential(client_data.hash, {"id": RP_ID, "name": "Nano disposable test"},
                    {"id": user.id, "name": user.name, "displayName": user.display_name},
                    [{"type": "public-key", "alg": -7}], options={"rk": True},
                    pin_uv_param=client_pin.protocol.authenticate(token, client_data.hash),
                    pin_uv_protocol=client_pin.protocol.VERSION, event=event)
    attestation = AttestationObject.create(response.fmt, response.auth_data, response.att_stmt)
    created = response.auth_data.credential_data
    if created is None:
        raise RuntimeError("registration did not return attested credential data")
    result = RegistrationResponse(raw_id=created.credential_id,
              response=AuthenticatorAttestationResponse(client_data=client_data, attestation_object=attestation))
    auth_data = server.register_complete(state, result)
    if auth_data.credential_data is None:
        raise RuntimeError("server verification did not retain a credential")
    return auth_data.credential_data


def authenticate(server, ctap, client_pin, pin: str, credential):
    options, state = server.authenticate_begin([credential], user_verification=UserVerificationRequirement.REQUIRED)
    data = CollectedClientData.create(CollectedClientData.TYPE.GET, options.public_key.challenge, ORIGIN)
    token = client_pin.get_pin_token(pin)
    with Timeout(50) as event:
        response = ctap.get_assertion(RP_ID, data.hash,
                   allow_list=[{"type": "public-key", "id": credential.credential_id}],
                   pin_uv_param=client_pin.protocol.authenticate(token, data.hash),
                   pin_uv_protocol=client_pin.protocol.VERSION, event=event)
    result = AuthenticationResponse(raw_id=response.credential["id"],
              response=AuthenticatorAssertionResponse(client_data=data, authenticator_data=response.auth_data,
                         signature=response.signature, user_handle=(response.user or {}).get("id")))
    verified = server.authenticate_complete(state, [credential], result)
    if verified.credential_id != credential.credential_id:
        raise RuntimeError("wrong credential authenticated")
    return response.auth_data.counter


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--ssh", required=True)
    parser.add_argument("--askpass", help="Optional private SSH password helper; never commit it")
    parser.add_argument("--target", required=True, help="Your Nano's verified SSH hostname or address")
    parser.add_argument("--host-key-alias", help="Existing trusted known_hosts entry for this same board")
    parser.add_argument("--result", required=True)
    args = parser.parse_args()
    result: dict[str, Any] = {"mode": "physical USB HID with disposable SD vault and explicit human terminal approvals",
              "physical_button_tested": False, "reset_called": False, "live_account_used": False,
              "checks": [], "status": "running"}
    destination = Path(args.result)
    destination.parent.mkdir(parents=True, exist_ok=True)
    nano, device = Nano(args), None
    active = False

    def write_result():
        destination.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")

    def emergency():
        result["status"] = "timeout"
        result["error"] = "overall 240-second deadline; detached board rollback remains scheduled"
        write_result()
        os._exit(124)

    timer = threading.Timer(240, emergency)
    timer.daemon = True
    timer.start()
    try:
        if os.name != "nt" or not ctypes.windll.shell32.IsUserAnAdmin():
            raise RuntimeError("Windows administrator approval is required for direct FIDO HID access")
        progress("Activating temporary Nano FIDO HID; detached rollback is armed.")
        nano.control("activate")
        active = True
        nano.start()
        device = selected_device()
        if device.ping(b"nano-physical-test") != b"nano-physical-test" or device.ping(b"") != b"":
            raise RuntimeError("physical PING mismatch")
        result["checks"].append("physical INIT and non-empty/empty PING")
        ctap = Ctap2(device, strict_cbor=True)
        info = ctap.info
        if "FIDO_2_0" not in info.versions or 1 not in info.pin_uv_protocols or info.options.get("clientPin") is not False:
            raise RuntimeError("unexpected fresh-lab GetInfo capabilities or existing PIN")
        result["get_info"] = {"versions": info.versions, "options": info.options, "pin_protocols": info.pin_uv_protocols}
        result["checks"].append("physical GetInfo with canonical CBOR")
        pin = str(secrets.randbelow(90000000) + 10000000)
        client_pin = ClientPin(ctap, PinProtocolV1())
        client_pin.set_pin(pin)
        result["checks"].append("physical PIN protocol 1 setup")
        server = Fido2Server(PublicKeyCredentialRpEntity(id=RP_ID, name="Nano disposable test"),
                             attestation=AttestationConveyancePreference.DIRECT,
                             verify_attestation=verify_attestation)
        progress("Approve the disposable registration request in the Windows approval dialog.")
        credential = register(server, ctap, client_pin, pin)
        result["checks"].append("physical MakeCredential; independent RP/UP/UV/packed-attestation validation")
        progress("Approve the disposable authentication request in the Windows approval dialog.")
        first_counter = authenticate(server, ctap, client_pin, pin, credential)
        result["checks"].append("physical GetAssertion; independent RP/UP/UV/signature validation")
        wrong = "0" + pin if len(pin) < 63 else "incorrect-test-pin"
        try:
            client_pin.get_pin_token(wrong)
            raise RuntimeError("wrong PIN unexpectedly accepted")
        except CtapError as exc:
            if exc.code != CtapError.ERR.PIN_INVALID:
                raise
        if client_pin.get_pin_retries()[0] != 7:
            raise RuntimeError("wrong PIN did not decrement to seven retries")
        result["checks"].append("one wrong PIN rejected; retries decrement to seven")
        device.close()
        device = None
        nano.stop()
        nano.start()
        device = selected_device()
        ctap = Ctap2(device, strict_cbor=True)
        client_pin = ClientPin(ctap, PinProtocolV1())
        if not ctap.info.options.get("clientPin") or client_pin.get_pin_retries()[0] != 7:
            raise RuntimeError("PIN or retry count lost across authenticator process restart")
        result["checks"].append("same SD vault reload; PIN and seven retries persist across process restart")
        progress("Approve authentication after restart in the Windows approval dialog.")
        second_counter = authenticate(server, ctap, client_pin, pin, credential)
        if second_counter <= first_counter or client_pin.get_pin_retries()[0] != 8:
            raise RuntimeError("counter persistence or successful-PIN retry reset failed")
        result["signature_counters"] = [first_counter, second_counter]
        result["checks"].append("old credential authenticates after restart; monotonic counter and retry reset verified")
        result["status"] = "passed"
        progress("Physical protocol checks passed. Restoring USB and disposing of the test-only vault.")
    except BaseException as exc:
        result["status"] = "failed"
        result["error_type"] = type(exc).__name__
        # No raw HID/CBOR frames or credential material are included in errors.
        if isinstance(exc, CtapError):
            result["ctap_error"] = str(exc.code)
        elif isinstance(exc, RuntimeError):
            result["error"] = str(exc)
        progress(f"Physical test failed: {type(exc).__name__}. See the sanitized result file.")
    finally:
        timer.cancel()
        if device:
            device.close()
        try:
            nano.stop()
            if active:
                nano.control("cleanup")
            result["usb_restored_and_lab_vault_disposed"] = bool(active)
        except BaseException as exc:
            result["cleanup_error_type"] = type(exc).__name__
            result["usb_restored_and_lab_vault_disposed"] = False
            result["status"] = "needs_review"
        result["human_approvals"] = nano.approvals
        result["human_denials"] = nano.denials
        write_result()
    return 0 if result["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
