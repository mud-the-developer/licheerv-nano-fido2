# LicheeRV Nano FIDO2 — 실험용 USB 인증기

> **실제 USB 등록·인증 시험은 통과했습니다. 하지만 실사용 가능한 보안키의 설정·검증은 아직 끝나지 않았습니다.**
> 중요한 계정이나 유일한 로그인 수단에 사용하지 마세요. FIDO 인증, 보안 감사, 내구성·키 추출 방어를 보장하지 않습니다.

LicheeRV Nano 자체를 PC에 꽂는 FIDO2 인증기로 만드는 개발 프로젝트입니다. Nano에 다른 보안키를 연결하는 프로젝트가 아닙니다. Linux USB gadget의 HID 기능에 Go 인증기 엔진을 연결하며, 상용 키와 같은 보안 경계라고 주장하지 않습니다.

**기준:** 2026-10-13에 수행한 실험. 실제 환경은 SG2002 / RISC-V C906, Buildroot, Linux 5.10 계열, Windows 11이었습니다. 보드 사양의 물리 DDR은 256MB이지만, 실험 이미지에서 Linux가 사용할 수 있는 메모리는 약 128MiB였습니다.

## 현재 결론

| 구분 | 상태 |
|---|---|
| 실제 USB INIT / 빈·일반 PING / GetInfo | 통과 |
| PIN 프로토콜 1 설정·잘못된 PIN 거부 | 통과 |
| 시험용 자격증명 등록·인증 | 통과 |
| 독립 검증기의 RP·UP·UV·packed attestation·서명 검증 | 통과 |
| 인증기 프로세스 재시작 후 SD 자격증명·PIN·실패 횟수 유지 | 통과 |
| 기존 자격증명 재인증·서명 카운터 `1 → 2` | 통과 |
| Linux/SD 저장·권한·rename·fsync 도우미 11개 | 통과 |
| 내장 USER의 회로·Linux 입력 장치 확인 | 완료 — 실제 누름/승인 미시험 |
| USER 버튼으로 승인하는 코드 | **미구현** |
| 실제 브라우저 `navigator.credentials` 흐름 | **미시험** |
| 실사용 vault·PIN·상시 HID 서비스 | **미설정** |
| CANCEL, 동시 채널, 전원 차단, 콜드 부팅, 독립 보안 검토 | **남음** |

시험은 별도 SD vault와 RAM에만 둔 임시 암호, 합성 자격증명으로 수행했습니다. 사람이 Windows 승인 창에서 **3회 직접 승인**했고 자동 승인은 없었습니다. 이 터미널 승인을 보드의 물리 버튼 검증으로 세지 않습니다. 실제 계정, 실사용 vault, 다른 보안키에는 Reset이나 PIN 변경을 하지 않았습니다.

시험 종료 후 인증기 프로세스를 멈추고 임시 HID를 제거했으며, 합성 vault와 RAM 암호를 폐기했습니다. **현재 장치를 곧바로 로그인 키로 쓸 수 있다는 뜻이 아닙니다.**

## 1. 전체 구조

![전체 구조](docs/diagrams/architecture.svg)

```text
RP / 검증기 → 호스트 FIDO2 클라이언트 → USB HID → Nano Go 어댑터
                                                    ├─ CTAP / ES256 / PIN / 카운터
                                                    ├─ 사용자 승인
                                                    └─ 암호화 SD vault
```

- **USB:** `configfs`의 HID gadget, FIDO usage page `0xF1D0`, report ID 없이 64바이트 IN/OUT 보고서를 사용합니다.
- **전송:** CTAPHID INIT/PING/CBOR와 continuation 프레임을 처리합니다. 최대 메시지는 7609바이트입니다.
- **어댑터:** 실제 HID 노드를 확인한 뒤 읽고 쓰며, 암호를 소비하고 승인·저장 인터페이스를 연결합니다.
- **인증기:** ES256 자격증명, RP별 조회, 서명 카운터, PIN 프로토콜 1, 발견 가능한 자격증명과 GetNextAssertion을 제공합니다.
- **저장:** 인증기 키·자격증명·PIN hash·재시도 수를 암호화해서 SD에 저장합니다.
- **복구:** USB와 독립된 Wi-Fi/VPN 또는 UART/Ethernet 연결을 확보한 뒤 USB 구성을 변경합니다. 같은 케이블의 NCM과 RNDIS는 독립 복구 경로가 아닙니다.

네트워크 관리 경로는 개발 편의를 위한 것입니다. 키 추출을 막는 보안 경계가 아니며, 실사용 시 SSH·네트워크 노출을 별도로 제한해야 합니다.

## 2. 승인·PIN·암호화 저장

![승인과 저장 흐름](docs/diagrams/approval-vault-flow.svg)

### 서로 다른 세 가지 입력

| 입력 | 용도 |
|---|---|
| SSH 로그인 인증 | 운영체제 관리 |
| vault 해제 암호 | SD에 저장된 인증기 상태 복호화 |
| FIDO PIN | 호스트의 사용자 검증 및 PIN 토큰 발급 |

서로 같은 암호를 쓰도록 설계하지 않았습니다. 어떠한 실사용 암호·PIN도 저장소에 넣지 않습니다.

### 요청 처리

1. CBOR·필수 필드·RP·PIN 인증 매개변수를 검증합니다.
2. 요청에 필요한 사용자 승인을 기다립니다.
3. 자격증명을 생성하거나 서명하고 카운터·PIN 상태를 갱신합니다.
4. 필요한 상태를 SD에 저장한 뒤 결과를 반환합니다.

현재 시험용 터미널 모드는 요청마다 새 확인 문자열을 표시하고 제한 시간 안에 사람이 입력하도록 합니다. 항상 승인하는 배포 모드는 없습니다. 물리 버튼 경로에는 새 요청 뒤의 **release → press**가 필요하며, 이전 누름이나 autorepeat를 승인으로 세면 안 됩니다.

### PIN

- PIN 프로토콜 1의 P-256 ECDH / AES-CBC / HMAC 처리를 검증했습니다.
- 곡선 식별자와 32바이트 좌표·공유 비밀의 선행 0 처리를 수정했습니다.
- 총 재시도 수 8회와 차단 값 **0**을 vault에 저장합니다.
- 연속 3회 실패는 현재 프로세스/세션에서 PIN 인증을 차단합니다. 프로세스 재시작으로 이 세션 제한은 해제되지만 총 실패 수는 유지됩니다.
- PIN 변경 시 기존 인증 토큰은 무효화합니다.

**세션 제한은 하드웨어 전원 재연결을 강제하는 보안 경계가 아닙니다.** Reset 명령은 의도적으로 거부하므로, 상용 키와 같은 복구·초기화 기능을 제공한다고 주장하지 않습니다.

### vault

- scrypt: `N=32768, r=8, p=1`, 32바이트 래핑 키.
- 저장마다 새 랜덤 데이터 키와 AES-GCM nonce를 사용합니다.
- 디렉터리 0700, 파일 0600, 현재 실행 사용자 소유권을 검사합니다. 어댑터는 root 실행을 요구하므로 보드에서는 root 소유여야 합니다.
- 임시 파일 → 파일 fsync → rename → 디렉터리 fsync 순서로 저장합니다.
- 손상, 잘못된 암호, 잘못된 저장 상태는 중단시키며 자동으로 새 vault를 만들거나 기존 vault를 삭제하지 않습니다.
- 원래 vault 포맷을 읽을 수 있고, PIN 재시도 필드가 없는 구형 상태는 명시적으로 이전합니다.

### 128MiB 환경에서 발견한 OOM과 수정

초기 보드 시험에서 연속 scrypt 작업 공간이 남아 약 65MiB의 anonymous RSS를 차지한 코어 시험이 OOM으로 종료됐습니다. 암호화 강도를 낮추거나 비밀이 SD swap에 기록되게 하지 않았습니다.

대신 한 해제 세션의 **32바이트 래핑 키만 재사용**하고, KDF 완료 후 큰 임시 작업 공간을 즉시 회수하도록 수정했습니다. 기존 포맷·KDF 강도·저장별 새 데이터 키와 nonce는 유지합니다. 수정 후 보드의 등록/재로드·PIN/토큰·실패 횟수 시험과 실제 USB 시험이 통과했습니다.

그러나 실행 중인 개인키·해제 암호·캐시 키는 RAM에 있습니다. Go 문자열의 확실한 소거, root/SD 접근, 부팅 체인, 물리 키 추출 방어는 해결하지 않았습니다.

## 3. 내장 USER 버튼

![내장 버튼과 상태](docs/diagrams/buttons-and-status.svg)

외부 스위치를 추가할 필요는 없습니다. 공식 회로도와 실제 장치 트리를 대조했습니다.

| 버튼 | 회로 | 승인용 적합성 |
|---|---|---|
| USER / BOOT, SW1 | `BOOT_KEY → GPIOA30`, 3.3V / 10kΩ pull-up, 누르면 LOW | 사용 가능, 코드 연결·실제 누름 시험 필요 |
| RESET, SW2 | `SYS_RSTN`, 하드웨어 재설정 | 사용하지 않음 |

확인한 이미지에서 USER는 `gpio-keys`가 관리하며, `EV_KEY` 코드 `0x1af`(431)로 보고됩니다. 해당 입력 노드는 `/dev/input/event0`이었지만, 다른 입력 장치를 붙이면 번호가 달라질 수 있으므로 이름·capability로 식별해야 합니다. GPIO bank의 전역 번호 역시 이미지에 따라 바뀔 수 있습니다.

현재 어댑터의 `--button-value`는 GPIO value 파일을 읽습니다. **기존 gpio-keys를 재-export하거나 방향을 바꾸면 안 됩니다.** 다음 구현은 별도의 evdev 승인 모드로 USER 이벤트를 읽고, fresh release/press·timeout·repeat 무시를 검증하는 것입니다. 사용자가 지금 누를 수 없는 상태라 이 시험은 보류했습니다.

USER는 BOOT 역할도 있으므로 정상 부팅 후 짧게 눌러 시험합니다. 전원을 넣거나 RESET을 누르는 동안 길게 누르지 마세요.

## 4. 재현 가능한 소프트웨어 빌드

Go 1.23 이상과 Git을 준비합니다. 개발·검증에 사용한 버전은 Go 1.27.2입니다.

Windows PowerShell:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\build-nano.ps1
```

Linux에서:

```sh
go mod verify
go test -count=1 ./...
go vet ./...
CGO_ENABLED=0 GOOS=linux GOARCH=riscv64 GORISCV64=rva20u64 \
  go build -trimpath -o out/nano-fido ./cmd/nano-fido
```

PowerShell의 ExecutionPolicy 옵션은 해당 프로세스에만 적용합니다. 빌드 스크립트는 보드에 접속하거나 USB·vault·SSH를 변경하지 않습니다. 결과 바이너리는 인증기이며 INIT/PING-only 진단기와 다릅니다.

이 저장소는 [Virtual FIDO](https://github.com/bulwarkid/virtual-fido)의 커밋 `512d8a3fef0e073171a7ef3261f300e8a5e48694`에서 Nano에 필요한 패키지만 가져온 specialized downstream입니다. import 호환성을 위해 원래 Go module path를 유지합니다. USB/IP 데모, macOS 드라이버, Windows 드라이버/인증서 바이너리는 포함하지 않습니다. upstream 라이선스는 보존했습니다.

## 5. 실물 시험 도구와 증거

- [설계·한계](docs/SECURITY.md)
- [실물 시험 결과와 최초 복구 실패 기록의 요약](docs/TEST-STATUS.md)
- [공개 전 민감 정보 검토](docs/PUBLIC-AUDIT.md)
- [다이어그램 원본·생성 이력](docs/diagrams/provenance.json)

Python은 프로젝트별 환경을 사용합니다:

```sh
uv venv .venv --python 3.14
uv pip install --python .venv/Scripts/python.exe -r hardware/requirements.lock
```

`hardware/fido_smoke.py`는 Windows 관리자 권한이 필요하며, 해당 Nano의 VID/PID만 선택합니다. 실제 주소와 개인 SSH 인증 자료는 사용자가 별도로 제공해야 합니다. 저장소에는 기본 관리 주소나 비밀번호가 없습니다. 기본 경로는 SSH 키 인증이며, 필요하면 저장소 밖의 private askpass helper를 지정할 수 있습니다. 기존 호스트 키 검증은 끄지 않습니다.

예시의 `<...>`는 개인 환경 값으로 바꿔야 합니다:

```text
python hardware/fido_smoke.py --ssh <SSH_EXECUTABLE> --target <NANO_HOST> \
  --host-key-alias <VERIFIED_KNOWN_HOST> --result <LOCAL_RESULT_FILE>
```

**먼저** `hardware/nano/hw-control.sh`의 장치·디렉터리 가드, 보드에 배치한 바이너리, independent recovery를 직접 확인해야 합니다. 무작정 실행하는 설치 스크립트가 아닙니다. Windows UAC 및 별도 승인 창에 사람이 직접 응답해야 합니다.

첫 물리 시험에서 모든 프로토콜 검증은 통과했지만, 종료 복구가 실패해 원본 runner 상태는 `needs_review`였습니다. configfs가 절대 경로도 상대 경로로 표시하는 점, 이미 unbind된 UDC의 오류, device-role 적용과 재열거/DHCP 지연을 처리했습니다. 별도 활성화/복구 주기와 실제 USB/VPN SSH 재접속으로 복구를 확인했습니다. 이를 숨기지 않고 [시험 기록](docs/TEST-STATUS.md)에 구분해 적었습니다.

원시 실험 로그·실제 주소·계정·기기 식별자·vault·PIN·인증 링크는 공개하지 않습니다. 공개한 결과는 검증 항목과 제한 사항만 남긴 요약입니다.

## 6. 남은 작업 — 우선순위

1. **USER evdev 승인:** 요청 이후의 release/press, 눌린 채 시작, repeat·timeout·취소를 구현하고 실제 버튼으로 검증.
2. **실사용 provisioning:** 사용자 vault 암호·PIN, 상시 HID·실행·잠금 해제 설계. 실사용 비밀번호를 채팅이나 Git에 올리지 않음.
3. **실제 브라우저 호환성:** Windows WebAuthn API와 `navigator.credentials`로 별도 로그인 수단이 있는 시험 계정에서 확인.
4. **CANCEL/채널:** 동기 승인 중 CANCEL, 동시 채널, 부분 메시지 timeout, 진행 중 INIT 재동기화와 명령 상태 격리.
5. **수명·복구:** USB 재연결, 콜드 부팅, NTP, 같은 vault 유지, SD 전원 차단, 백업·복원 및 reset 정책.
6. **보안:** 기본 관리 인증 제거, 개발 네트워크 노출 제한, SD/부팅 체인·key extraction·RAM 비밀 보호, 의존성 취약점과 독립 리뷰.

## 7. 공개 저장소 정책

코드·문서·합성 테스트·본 프로젝트가 생성한 그림만 포함합니다. `.venv`, npm 캐시, 바이너리, 개인 설정, private helper, 원시 로그, vendor PFX/라이브러리, 제조사 PDF는 포함하지 않습니다. 회로도는 원본 링크로 안내합니다. 새 Git history와 공개 GitHub noreply 작성자 정보만 사용했습니다.

그림은 **Excalimate MCP 0.5.0의 local stdio**로 scene·managed animation·checkpoint를 실제 생성했습니다. SVG는 MCP가 반환한 scene의 정적 snapshot을 로컬에서 렌더링했습니다. 외부 share 기능이나 호스팅 모델은 호출하지 않았으며, 입력에 개인 네트워크 정보는 없었습니다. 편집 가능한 `.excalimate.json`도 제공합니다.

자동 검사·파일별 검토는 보안 인증이 아닙니다. 민감한 자료를 발견하면 새 issue에 값이나 원시 파일을 올리지 말고 삭제·회수와 private 연락을 먼저 진행하세요.

## 자료와 라이선스

- [Sipeed 소개·하드웨어 자료](https://wiki.sipeed.com/hardware/en/lichee/RV_Nano/1_intro.html)
- [Sipeed USER 입력 문서](https://wiki.sipeed.com/hardware/en/lichee/RV_Nano/5_peripheral.html)
- [공식 70418 회로도](https://dl.sipeed.com/fileList/LICHEE/LicheeRV_Nano/02_Schematic/LicheeRV_Nano-70418_Schematic.pdf)
- [FIDO CTAP 규격](https://fidoalliance.org/specifications/)
- [Yubico python-fido2](https://github.com/Yubico/python-fido2)
- [Excalimate](https://github.com/excalimate/excalimate)
- [Virtual FIDO](https://github.com/bulwarkid/virtual-fido)

MIT. Original Virtual FIDO copyright: BulwarkID. 수정·통합 코드는 동일한 MIT 조건으로 공개하며, Sipeed·Yubico·FIDO Alliance·Bulwark·Excalimate의 공식 제품이나 인증을 뜻하지 않습니다.
