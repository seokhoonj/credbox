# credbox

[![check](https://github.com/seokhoonj/credbox/actions/workflows/check.yml/badge.svg)](https://github.com/seokhoonj/credbox/actions/workflows/check.yml)
[![PyPI](https://img.shields.io/pypi/v/credbox)](https://pypi.org/project/credbox/)
[![Python](https://img.shields.io/pypi/pyversions/credbox)](https://pypi.org/project/credbox/)
[![License](https://img.shields.io/pypi/l/credbox)](https://github.com/seokhoonj/credbox/blob/main/LICENSE)

[English](README.md) | **한국어**

Python 앱·CLI용 시크릿 저장소. 경로는 기본 XDG, 요청 시 OS 네이티브(Linux/macOS/Windows). 시크릿은
로그·예외·트레이스백으로 새지 않도록 설계했습니다.

- **누출 방지** — 시크릿은 `Secret`으로 반환, 자동 마스킹, 실제 값은 `.reveal()`로만. 손상·실패·오류에도
  예외·트레이스백에 값 없음.
- **정직한 기본값** — 0700 디렉터리 안 0600 평문 `credentials.json`. 키링·암호화는 opt-in.
- **의존성 0** — `keyring`·`cryptography`는 필요 시 extra.
- **공유·통합** — 한 키를 여러 앱이 공유하거나, 여러 도구의 시크릿을 한 파일로 통합(§3의 공유 저장소·namespace).

원자적 쓰기·권한·프로세스 간 잠금·XDG 경로·로그 마스킹을 한 단위로 묶어 테스트했습니다. 새로운 볼트가
아니라, 검증된 표준 기법을 조합할 뿐 새 암호를 발명하지 않습니다. 디렉터리는
[XDG Base Directory Specification](https://specifications.freedesktop.org/basedir/latest/)을 따릅니다.

## 1. 설치

```sh
pip install credbox              # 파일 저장소, 의존성 0
pip install "credbox[keyring]"   # OS 키링 백엔드
pip install "credbox[crypto]"    # 암호화 파일 백엔드 (Argon2id + AES-GCM)
pip install "credbox[all]"       # keyring + crypto 모두
```

설치 확인은 `credbox --version`. Python 3.11 이상.

## 2. 빠른 시작

시크릿을 한 번 저장합니다(입력값은 화면에 표시되지 않습니다):

```sh
credbox set myapp API_KEY
```

코드에서 다시 읽습니다. `require`는 값을 찾고(`$API_KEY` → `myapp` 저장소 순), 없으면 예외를 냅니다.
반환값은 `Secret`이라 실수로 로그에 남지 않습니다:

```python
from credbox import Credentials

secret = Credentials("myapp").require("API_KEY")   # str이 아니라 Secret
secret.reveal()                                    # 실제 값 — 쓰는 자리에서만
print(secret)                                      # 'API_...cdef' — 마스킹되어 로그에 안전
```

## 3. 시크릿

시크릿(비밀번호·토큰·API 키)은 앱마다 하나인 `credentials.json`에 담깁니다 — 예: `myapp` →
`~/.config/myapp/credentials.json`. 이 파일이 앱의 **저장소(store)** 입니다. 읽을 저장소는 앱 이름으로
정해지므로, 한 앱이 다른 앱의 저장소를 이름으로 지목해 함께 읽을 수도 있습니다(아래 **공유 저장소**).

```python
from credbox import Credentials, Secret

# 해석 순서: override > 환경변수 > 공유 저장소 > 이 앱의 저장소
creds = Credentials("myapp", shared=["auth"])
key   = creds.require("API_KEY")          # $API_KEY, 그다음 auth 저장소, 그다음 myapp; 없으면 예외
maybe = creds.secret("API_KEY")           # 같지만 없으면 예외 대신 None
creds.set("API_KEY", value="sk-...")      # myapp 저장소에 저장 (str 또는 Secret; 키워드 전용)
creds.unset("API_KEY")                    # myapp 저장소에서 제거 (없으면 무시)
creds.names()                             # ["API_KEY", ...] — 이름만, 값은 아님

key.reveal()                              # -> "sk-..."  HTTP 클라이언트에 넘길 실제 문자열
```

`secret`·`require`는 `Secret`을 반환합니다. 실제 문자열은 `.reveal()`로 꺼냅니다. `Secret`은 `str`·`repr`
에서 마스킹되고, 비교는 상수 시간이며, 해시할 수 없어 로그 한 줄이나 dict 키에 실수로 끼지 않습니다.
`set`은 `str`·`Secret`을 받고, 빈 값을 거부하며, 앞뒤 공백을 떼어 저장값과 조회값이 어긋나지 않게 합니다.

`Secret` 함정 두 가지: 문자열이 필요한 자리(f-string, 헤더 값 `f"Bearer {secret}"`)에 그대로 쓰면
실제 키가 아니라 **마스크**가 들어가고 오류도 안 나므로 경계에서 반드시 `.reveal()` 하세요. 그리고
`secret == "문자열"`은 항상 `False`입니다(동등 비교는 `Secret`끼리만) — `secret.reveal() == other`로
비교하거나 상대를 `Secret(...)`으로 감싸세요.

**공유 저장소**는 여러 앱이 함께 쓰는 키를 한 번만 두는 방법입니다 — 공유 앱(예: `"auth"`)에 저장하고, 각
앱이 `shared=["auth"]`로 함께 읽습니다. 한 앱에만 필요한 키는 그 앱 저장소에 둡니다.

**namespace(네임스페이스)**는 반대 방향입니다 — 한 앱의 저장소 안에서 여러 도구의 시크릿을 *같은* 파일의
별도 구획에 키 이름 충돌 없이 담게 해줍니다. 한 앱을 컨테이너로 삼고 각 도구에 자기 namespace를 주면 됩니다
— 도구마다 앱·파일을 따로 둘 필요가 없습니다. `Credentials(app, namespace="chat")`는 `chat` 구획만
읽고 씁니다. `namespace=None`(기본값)은 기존 flat 저장소 그대로입니다.

**여러 도구, 한 파일.** 각 도구의 키를 호스트 앱 하나의 자기 namespace 아래 둡니다 — CLI(`--namespace`, 또는
`-n`) 또는 코드로:

```sh
credbox set yourapp GEMINI_API_KEY -n chat  # 화면 표시 없이 입력
credbox set yourapp SMTP_PASSWORD  -n mailer
credbox list yourapp -n chat                # 한 구획만 조회
```

```python
from credbox import Credentials
key = Credentials("yourapp", namespace="chat").require("GEMINI_API_KEY")   # 다시 읽기
```

전부 한 파일 `~/.config/yourapp/credentials.json`에 들어갑니다:

```json
{ "chat": {"GEMINI_API_KEY": "…"}, "mailer": {"SMTP_PASSWORD": "…"} }
```

한 앱의 자격증명 **파일**은 flat이거나 namespaced 중 하나입니다 — namespace가 생기면 flat 접근(namespace
없이)은 손상 대신 예외가 나고 그 반대도 마찬가지 — 그러니 namespaced 저장소엔 새 앱 이름을 주거나, 기존
flat 저장소를 마이그레이션(아래)하세요. namespace는 공유·앱 저장소 단계만 구획합니다. 환경변수·override
단계는 이름만으로 해석되므로 같은 `name`은 namespace와 무관하게 같은 환경변수를 읽습니다. CLI에서는
`--namespace/-n` 또는 `CREDBOX_NAMESPACE` 환경변수로 namespace를 고릅니다. git 자격증명 헬퍼는 flat 전용입니다.

**flat 저장소를 namespace로 마이그레이션.** flat과 namespaced는 한 파일에 공존할 수 없으니 중간에 비웁니다:
각 flat 키를 읽고(`credbox get app K --reveal`), 전부 제거한 뒤(`credbox unset app K` — 마지막 키가 사라지면
저장소는 빈 상태), 각각을 namespace 아래 다시 저장합니다(`credbox set app K -n ns`).

여러 도구가 한 저장소를 공유할 때 주의 두 가지. 환경변수 단계는 namespace를 무시하므로, 두 도구가 *같은*
일반 이름(`API_KEY`)을 `$API_KEY`에서 각자 해석하면 *같은* 값을 받습니다 — 각자 다른 env 이름(예제의
`GEMINI_API_KEY`·`SMTP_PASSWORD`처럼)을 주어 분리하세요. 그리고 통합 저장소를 **여러 머신**에서 동기화 폴더(Dropbox, NFS)를
통해 쓰면, 크로스-프로세스 lock이 머신 간에는 미치지 않아 한 namespace의 갱신이 동기화 충돌로 유실될 수
있습니다 — 공유 저장소는 한 머신에서만 쓰거나, 도구를 별도 저장소로 두세요.

## 4. `credbox` 명령

어느 앱의 시크릿이든 한 곳에서 같은 방식으로 다룹니다:

```sh
credbox set myapp API_KEY               # 화면에 표시하지 않고 입력받아 저장 (0600)
credbox set myapp API_KEY --value sk-…  # 값 직접 전달 (argv에 노출; 프롬프트 권장)
credbox list myapp                      # 이름만
credbox get myapp API_KEY               # 마스킹 출력 (API_...cdef); 저장값만
credbox get myapp API_KEY --reveal      # 전체 출력 (실제 값이 화면에 나가는 유일한 경로)
credbox get myapp API_KEY --resolve     # 환경변수까지 함께 참조
credbox unset myapp API_KEY
credbox set myapp API_KEY -n chat       # -n/--namespace: 저장소의 한 구획 안에서 동작
credbox path myapp                      # credentials.json 경로
credbox dirs myapp                      # 디렉터리 다섯 개
credbox doctor                          # 모든 앱의 권한 점검
```

`set`은 터미널에선 (에코 없이) 입력받고, 스크립트·CI에선 값을 stdin으로 파이프하세요
(`printf %s "$TOKEN" | credbox set myapp API_KEY`) — `--value`와 달리 시크릿이 프로세스 인자
목록에 안 남는 argv-안전 경로입니다. `set`·`get`·`list`·`unset`은 `--namespace/-n`(또는
`CREDBOX_NAMESPACE` 환경변수, 플래그가 우선)으로 namespaced 저장소의 한 구획 안에서 동작합니다 — §3의
"여러 도구, 한 파일" 레시피 참조. `--keyring`을 붙이면 OS 키링 백엔드(`credbox[keyring]` 필요; 런타임에
키링을 못 쓰면 파일 저장소 사용)를 씁니다. CLI는 트레이스백을 찍지 않고, 오류는 stderr에 값
없는 한 줄로 냅니다. 종료 코드는 성공 `0`, 명령 실패 `1`(`doctor`가 소유자 외 접근 가능한 파일·디렉터리를
찾은 경우 포함), 사용법 오류 `2`.

## 5. 백엔드

시크릿이 실제로 어디 저장되는지는 `SecretBackend`가 정합니다. `Credentials`는 기본 `FileBackend`를 쓰고,
`backend=`로 교체합니다:

```python
from credbox import Credentials, Secret
from credbox import default_backend, file_backend, keyring_backend, encrypted_backend

Credentials("myapp")                                                    # 파일 저장소 (기본)
Credentials("myapp", backend=default_backend(use_keyring=True))         # 파일 위에 키링
Credentials("myapp", backend=keyring_backend(fallback=file_backend()))  # 같은 것, 명시적으로
Credentials("myapp", backend=encrypted_backend(passphrase=Secret("…"))) # 암호화 파일 [crypto]
```

- **파일 저장소** (기본, 의존성 0) — 앱 폴더의 `credentials.json`. 어디서나 동작, `0600`(소유자만
  읽고 쓰기 — 리눅스·macOS의 파일 권한) 평문 저장.
- **OS 키링** (`[keyring]`) — OS 볼트(macOS Keychain, GNOME Keyring 등). 쓸 수 있으면 키링이 우선이고,
  `set`·`unset` 성공 시 폴백 파일의 예전 평문 사본도 지웁니다. 키링이 **아예 없으면**(서버·cron·컨테이너)
  파일 저장소로 넘어가며 경고를 한 번 냅니다 — 사용자 모르게 평문으로 바꾸지 않습니다. **있는데 실패하면**
  (잠김·일시 오류) 평문을 쓰거나 예전 값을 주는 대신 예외를 냅니다(fail-closed). 파일 폴백은 키링이 아예
  없을 때만 씁니다. (정리는 *키링 → 파일* 한 방향뿐 — 키링을 못 쓰는 동안 파일에 쓴 값은 키링 복구 후
  자동으로 옮겨지지 않으니, 그때 키를 다시 `set` 하세요.)
- **암호화 파일** (`[crypto]`) — passphrase의 Argon2id 해시로 키를 만든 단일 AES-GCM 블롭. 폴백 없음: 암호
  오류·변조는 값 없는 `DecryptionError`로 실패하며 평문으로 물러서지 않습니다. 헤더 전체 인증(AAD —
  암호화하진 않지만 변조 검사에 포함되어, 헤더가 바뀌면 복호화가 실패하는 데이터), 쓸 때마다 새
  nonce(암호화마다 한 번만 쓰는 난수), 의도적으로 무거운 KDF(key-derivation function — passphrase로
  키를 만드는 함수, 여기선 Argon2id)가 저장소를 열 때마다 ~100ms를 더합니다 — 버그가 아닙니다.
  **복구 경로가 없습니다**: passphrase를 잃으면 아무도 저장소를 복호화할 수 없으니, passphrase는 따로
  백업하세요.

팩토리가 선택 import를 걸러 줍니다: extra가 없으면 `keyring_backend()`·`encrypted_backend()`는
`MissingExtraError`와 `pip install credbox[…]` 안내를 냅니다.

`credbox` CLI는 파일·키링 저장소만 다룹니다 — **암호화 저장소는 코드에서** 같은 `Credentials`로 채웁니다:

```python
from getpass import getpass
from credbox import Credentials, Secret, encrypted_backend

creds = Credentials("myapp", backend=encrypted_backend(passphrase=Secret(getpass("passphrase: "))))
creds.set("API_KEY", value="sk-...")     # credentials.enc(암호화)에 씀
creds.require("API_KEY")                 # 같은 passphrase로 다시 읽음
```

## 6. git 자격증명 헬퍼

credbox는 git에 자격증명을 넘길 수 있습니다. 헬퍼를 git에 지정합니다:

```sh
git config --global credential.helper credbox
```

git이 `get`·`store`·`erase`마다 `git-credential-credbox`를 부르고, git `host`를 credbox 앱 이름에,
`username`을 시크릿 이름에 대응시킵니다. `get`에서 헬퍼는 자격증명 응답만 stdout에 쓰고, 오류가 나면
stdout에는 아무것도 쓰지 않고(git이 직접 묻습니다) stderr에 값 없는 짧은 안내만 냅니다 — 시크릿도
트레이스백도 없습니다.

저장소는 호스트 이름만으로 자격증명을 구분하고 프로토콜은 기록하지 않으므로, 평문 `http://` 요청에는
아무것도 제공하지 않습니다(http 저장분과 https 저장분을 구분할 수 없어, 어느 쪽이든 git에 평문으로
넘기면 다운그레이드가 됩니다). 포트가 붙은 host
(`example.com:8443`)나 IPv6 리터럴도 처리합니다. 헬퍼는 OS 키링이 아니라 파일 저장소를 읽습니다.

## 7. 디렉터리

```python
from credbox import config_dir, data_dir, state_dir, cache_dir, runtime_dir

config_dir("myapp")   # ~/.config/myapp        (또는 $XDG_CONFIG_HOME/...)
data_dir("myapp")     # ~/.local/share/myapp   (또는 $XDG_DATA_HOME/...)
state_dir("myapp")    # ~/.local/state/myapp   (또는 $XDG_STATE_HOME/...)
cache_dir("myapp")    # ~/.cache/myapp         (또는 $XDG_CACHE_HOME/...)
runtime_dir("myapp")  # $XDG_RUNTIME_DIR/myapp, 없으면 소유자만 접근하는 0700 임시 디렉터리
```

앱 이름은 경로 세그먼트 하나로 검증되어, 조작한 이름으로 기준 디렉터리를 벗어날 수 없습니다.
`data_dir`·`state_dir`은 앱별 `<PREFIX>_DATA_DIR`·`<PREFIX>_STATE_DIR` 오버라이드(지정한 절대경로를 그대로
사용)를 따르며, `<PREFIX>`는 `env_var_prefix(app)`가 만듭니다. 기본은 모든 OS에서 XDG `~/.config`이고,
`layout="native"`를 주면 OS 네이티브(Linux `~/.config`, macOS `~/Library/Application Support`, Windows
`%LOCALAPPDATA%`)를 쓰거나 `CREDBOX_LAYOUT`으로 지정합니다. layout은 **저장 위치**를 정하므로, 바꾸면
다른 위치를 가리킬 뿐 마이그레이션이 아닙니다 — 바꾸려면 기존 저장소를 직접 옮기세요(예: `relocate_once`).

**Windows 참고:** `0600`·`0700`은 리눅스·macOS(POSIX)의 파일 권한 표기입니다 — credbox는 시크릿
**파일**은 `0600`(소유자만 읽고 쓰기), 그 파일이 든 **폴더**는 `0700`(소유자만 접근 가능)으로 설정해,
같은 컴퓨터의 다른 사용자가 시크릿에 닿지 못하게 합니다. Windows엔 이 유닉스식 권한 비트가 없고, 대신
**ACL**(Access Control List — 계정·그룹별로 허용/거부를 적어둔 접근 제어 목록)로 접근을 통제합니다.
credbox는 Windows에서 `0600`·`0700`을 직접 설정할 수 없어, 시크릿을 사용자별 `%LOCALAPPDATA%` 폴더에
저장합니다 — Windows가 이 폴더를 만들 때부터 그 계정에게만 접근을 허용하는 ACL을 설정해두고, 그 안에
만든 파일도 이 ACL을 물려받아 자동으로 그 계정 전용이 됩니다. 그래서 credbox는 Windows에서 직접 설정할 수
없는 `0600`·`0700`을 보장한다고 주장하지 않고, OS가 이미 설정해둔 ACL 보호에 의존합니다.

## 8. 로그에서 시크릿 마스킹

API가 오류 메시지나 요청 URL에 키를 되비추는 일이 잦아, 손보지 않은 예외를 그대로 로깅하면 실패의 원인이
된 시크릿이 샐 수 있습니다. 아래 헬퍼는 알려진 시크릿 값과 그 URL 인코딩 형태를 로깅 전에 `***`로
바꿉니다:

```python
from credbox import scrub_secrets, scrub_exception

scrub_secrets("failed with sk-abc123", [key])   # "failed with ***"
raise scrub_exception(err, [key])               # 예외 체인 전체(연결된 하위 예외) 마스킹
```

두 헬퍼가 받는 시크릿 값은 raw `str`이거나 `Secret`이면 됩니다 — 위 `key`는 `Secret`이고 그대로
마스킹됩니다. `scrub_exception`은 예외를 내지 않으며, 예외를 처리하다 난 또 다른 예외는 Python이
`__cause__`·`__context__`로 엮습니다(예외 체인). 시크릿이 그 밑단 예외에 박혀 있을 수 있으므로 **체인
전체를 따라가** 각 예외의 `args`와 전송 URL(`url`·`request.url`·`response.url`), PEP 678 `__notes__`를
다시 씁니다. `__str__`을 따로 정의한 예외라면 만들어진 로그 줄도 `scrub_secrets`에 한 번 통과시키세요.

## 9. 중복 실행 방지 (단일 인스턴스 잠금)

같은 작업이 두 번 겹쳐 도는 것을 막습니다 — cron 두 개, 또는 cron과 수동 실행. 이런 중복은 같은 일을 다시
하고, 결과를 두 번 내보내고, 공유 상태에서 경합합니다:

```python
from credbox import single_instance, FileLock

with single_instance("myapp", name="poll") as acquired:
    if not acquired:
        return   # 이미 실행 중인 인스턴스가 있음 — 건너뜁니다
    ...
```

잠금 파일은 `runtime_dir`에 있고, 크래시로 죽어도 종료 시 OS가 풉니다. 잠금을 지원하지 않는 파일시스템
(`ENOLCK`을 내는 일부 NFS 마운트)에서는 기본적으로 **fail-open** — 크로스-프로세스 보호 없이 작업을
실행하고 `UserWarning`을 한 번 내며(`lock_unavailable`이 `True`), 영원히 건너뛰지 않습니다.
`require_lock=True`(`single_instance`·`FileLock`에)를 주면 대신 fail-closed — `LockUnavailableError`를 냅니다.

## 10. 공개 API 레퍼런스

### 자주 쓰는 API

| Import | 설명 |
|--------|------|
| `Credentials(app, *, namespace=None, shared=(), backend=None)` | 네 단계 시크릿 리졸버: `.secret` / `.require` / `.set` / `.unset` / `.names`. `namespace`는 한 앱 저장소 안의 컴포넌트별 구획으로 저장을 한정합니다. |
| `Secret` / `mask_secret` | 로그에 새지 않는 값 타입(`.reveal()`로 실제 문자열)과 표준 마스크. |
| `config_dir` / `data_dir` / `state_dir` / `cache_dir` / `runtime_dir` | 앱의 XDG 디렉터리. |
| `default_backend` / `file_backend` / `keyring_backend` / `encrypted_backend` | 백엔드 선택기와 팩토리. |
| `SecretBackend` / `FileBackend` | 백엔드 프로토콜과 의존성 0 파일 백엔드. |
| `scrub_secrets` / `scrub_exception` | 텍스트와 예외 체인에서 시크릿 값 마스킹. |
| `single_instance` / `FileLock` | `runtime_dir`의 단일 인스턴스 잠금. |
| `CredBoxError` / `CredentialsError` / `NoKeyringError` / `InsecureStorageError` / `InvalidAppNameError` / `InvalidLayoutError` / `BlankSecretError` / `LockHeldError` / `LockUnavailableError` / `DecryptionError` / `MissingExtraError` | 예외 계층. |
| `__version__` | 설치된 패키지 버전 문자열. |

### 빌딩 블록 (라이브러리 작성자용)

| Import | 설명 |
|--------|------|
| `ensure_dir` / `ensure_private_dir` / `restrict_dir_to_owner` / `warn_if_group_or_world_readable` / `warn_if_group_or_world_accessible` | 디렉터리·파일 권한 보장과 점검(뒤 둘은 credentials 파일이나 그 디렉터리가 소유자 밖에서 접근 가능하면 경고). |
| `write_bytes_atomic` / `write_text_atomic` | 원자적 0600 쓰기. |
| `read_json` / `relocate_once` | 손상에 안전한 비-시크릿 상태 읽기; 여러 번 호출해도 안전한 재배치. |
| `env_var_prefix` / `colliding_env_var_prefixes` / `read_absolute_path_override` | 앱 이름을 환경변수 접두어로 변환·충돌 검사; 절대경로 오버라이드 읽기. |
| `app_dir_segment` / `Layout` / `default_layout` / `set_default_layout` | 앱 이름 검증; 경로 레이아웃 선택. |

## 11. 라이브러리 작성자를 위해

credbox는 바닥 계층만 제공합니다 — 디렉터리·시크릿 해석·권한·원자적 쓰기·잠금·마스킹. 작성자의 패키지는
자기 도메인 설정(계정·라우트·토픽)은 그대로 두고, 그 아래에서 저장 위치와 시크릿만 credbox에 맡깁니다:

```python
from credbox import Credentials, config_dir

settings = config_dir("myapp") / "settings.toml"     # 설정 파일은 직접 관리
token    = Credentials("myapp").secret("API_TOKEN")  # 저장 위치와 시크릿만 credbox에
```

## 12. 라이선스

[MIT](LICENSE)
