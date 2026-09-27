# Secretary 코드베이스 안내

이 문서는 Secretary의 금고 암호화, 저장, 백업 및 복구 흐름을 코드와 함께 읽기 위한 안내서다.

## 주요 파일

- `src-tauri/src/lib.rs`: 암호화, 금고 저장, TOTP 계산, 생체 인증, 백업 및 복구 명령
- `src/main.ts`: 화면 생성과 Tauri `invoke` 호출
- `src/style.css`: 앱과 복구 미리보기 UI 스타일
- `src-tauri/tauri.conf.json`: 창, CSP, 업데이트 및 번들 설정
- `src-tauri/capabilities/main.json`: 프런트엔드에 허용된 Tauri 권한

## Vault v2 암호화 구조

마스터 비밀번호는 OTP 데이터를 직접 암호화하지 않는다.

1. `new_kdf_config`가 무작위 salt와 Argon2id 파라미터를 만든다.
2. `derive_key`가 마스터 비밀번호로 256비트 KEK(Key Encryption Key)를 만든다.
3. `create_v2_envelope`가 운영체제 난수 생성기로 256비트 DEK(Data Encryption Key)를 만든다.
4. `wrap_data_key`가 KEK와 AES-256-GCM으로 DEK를 암호화한다.
5. `encrypt_vault_v2`가 DEK와 별도 nonce로 전체 `Vault`를 암호화한다.
6. 세션에는 KEK나 마스터 비밀번호가 아니라 DEK만 `Zeroizing<[u8; 32]>` 형태로 남는다.

암호화 파일의 개념적인 구조는 다음과 같다.

```json
{
  "version": 2,
  "kind": "vault 또는 backup",
  "kdf": {
    "algorithm": "argon2id",
    "memory_kib": 65536,
    "iterations": 3,
    "parallelism": 1,
    "salt": "base64"
  },
  "key_nonce": "base64",
  "wrapped_key": "base64로 인코딩된 암호화 DEK",
  "nonce": "base64",
  "ciphertext": "base64로 인코딩된 암호화 Vault"
}
```

`key_nonce`와 `nonce`는 서로 다른 값이다. 하나는 DEK를 감쌀 때 사용하고 다른 하나는 실제 금고를 암호화할 때 사용한다.

## 잠금 해제 흐름

비밀번호 잠금 해제는 `unlock_vault`에서 시작한다.

1. `unlock_local_with_password`가 `vault.dat`을 읽는다.
2. 파일이 손상됐다면 `vault.dat.bak`을 검사하고 정상 파일을 자동 복원한다.
3. v2 파일이면 `derive_key`로 KEK를 만들고 `unwrap_data_key`로 DEK를 복호화한다.
4. DEK로 금고를 복호화하고 `validate_vault`로 내부 구조를 검증한다.
5. DEK만 `SessionKey`에 저장한다.

구형 v1 금고는 같은 함수에서 읽을 수 있다. 사용자가 비밀번호로 처음 잠금을 해제하면 무작위 DEK를 사용하는 v2 파일로 즉시 마이그레이션된다. 기존 생체 인증 저장소에는 v1 키가 들어 있으므로 마이그레이션 시 생체 인증 설정만 해제되며, 사용자가 설정에서 다시 활성화할 수 있다.

Windows Hello와 Touch ID 잠금 해제는 OS 보안 저장소가 보호하는 DEK를 가져온 뒤 `load_local`로 금고를 검증한다. 마스터 비밀번호는 OS 저장소에 저장하지 않는다.

## 저장과 원자적 교체

모든 금고 변경은 `save_local`로 모인다.

1. `revision`을 증가시킨다.
2. `validate_vault`로 UUID 중복, 항목 수, OTP secret 및 백업 설정을 검사한다.
3. 자동 백업이 설정돼 있으면 먼저 암호화 백업을 생성하고 다시 복호화해 검증한다.
4. 본 금고용 새 nonce를 만들고 AES-256-GCM으로 암호화한다.
5. `atomic_write_verified`가 같은 폴더에 임시 파일을 생성한다.
6. 임시 파일을 `sync_all`로 디스크에 반영한다.
7. 임시 파일을 다시 읽고 복호화하여 `vault_id`, `revision`, OTP 개수를 원본과 비교한다.
8. 검증이 끝난 파일만 본 파일과 교체한다.

Windows에서는 `ReplaceFileW`로 `vault.dat`을 원자적으로 교체하면서 이전 세대를 `vault.dat.bak`에 남긴다. Unix 계열에서는 이전 파일을 동기화한 복구 파일로 만든 뒤 같은 파일시스템 내 `rename`으로 교체하고 폴더까지 동기화한다.

따라서 임시 파일 쓰기, 검증 또는 교체가 실패하면 기존 `vault.dat`은 그대로 유지된다.

## 백업

### 자동 파일 백업

`write_automatic_file_backup`이 현재 금고의 DEK와 암호화된 DEK 정보를 재사용한다. 따라서 백업에는 평문 키가 없지만 현재 마스터 비밀번호로 다른 PC에서도 복구할 수 있다. 파일을 쓴 직후 다시 복호화하여 금고 ID, revision과 항목 수를 확인한 파일만 정상 백업으로 인정한다.

`get_backup_status`는 가장 최근 백업을 실제로 복호화하여 다음 정보를 UI에 전달한다.

- 검증된 OTP 개수
- 파일 크기
- 수정 시각
- SHA-256
- 보관 중인 자동 백업 개수

### 수동 백업

`export_backup`은 사용자가 입력한 백업 전용 비밀번호로 새 KEK와 새 무작위 DEK를 만든다. 로컬 금고와 독립된 암호화 컨텍스트이므로 백업 비밀번호가 로컬 마스터 비밀번호와 달라도 된다. 파일 저장 후 동일한 쓰기 후 복호화 검증을 수행한다.

## 2단계 복구

복구는 `preview_backup_restore`와 `apply_backup_restore` 두 명령으로 분리되어 있다.

### 1단계: 미리보기

1. 사용자가 `.enc` 파일과 백업 비밀번호를 선택한다.
2. Rust가 백업을 복호화하고 전체 금고를 검증한다.
3. 현재 금고와 비교해 새 항목, 완전 중복, 같은 이름의 충돌을 분류한다.
4. 프런트엔드에는 서비스명, 계정명, 분류 결과만 전달한다.
5. secret과 현재 OTP 코드는 Rust 메모리를 벗어나지 않는다.
6. 복호화된 백업은 임의의 토큰과 함께 최대 10분 동안 `PendingRestore`에 보관된 후 자동으로 zeroize된다.

### 2단계: 적용

사용자는 다음 중 하나를 선택한다.

- `merge`: 완전히 같은 OTP는 건너뛰고 나머지를 현재 금고에 추가한다. UUID 충돌은 새 UUID를 부여한다.
- `replace`: 백업의 OTP 목록으로 교체하지만 현재 PC의 자동 백업 설정과 금고 ID는 유지한다.

적용 직전에 현재 금고를 `vault.pre-restore.dat`에 검증된 암호화 상태로 보존한다. 이후 일반 `save_local` 경로로 저장하므로 복구 도중 실패해도 기존 금고가 유지된다.

## 프런트엔드 보안 경계

`src/main.ts`는 암호화나 OTP secret 처리를 하지 않는다. 비밀번호 입력값은 `invoke` 인자로 Rust에 전달되고, 복구 미리보기에는 비밀이 아닌 메타데이터만 돌아온다. 실제 복호화된 `Vault`는 Rust의 `PendingRestore` 안에만 존재한다.

## 추천 코드 읽기 순서

1. `KdfConfig`, `EncryptedEnvelope`, `Vault`, `SessionKey`
2. `derive_key`
3. `wrap_data_key`와 `unwrap_data_key`
4. `create_v2_envelope`와 `encrypt_vault_v2`
5. `decrypt_vault`와 `unlock_envelope`
6. `atomic_write_verified`와 `replace_file_atomically`
7. `load_local`과 `save_local`
8. `export_backup`
9. `preview_backup_restore`와 `apply_backup_restore`
10. `src/main.ts`의 `backupCenterDialog`, `backupDialog`, `restorePreviewDialog`

## 테스트

`src-tauri/src/lib.rs` 하단 테스트 모듈은 다음을 확인한다.

- RFC 6238 TOTP 벡터
- AES-GCM 변조 탐지
- v2 DEK 래핑과 잘못된 비밀번호 거부
- v1 암호화 파일 호환
- 원자적 저장과 이전 세대 보존
- 복구 시 로컬 백업 설정 유지
- 복구 미리보기의 중복 및 충돌 분류
- 과도한 Argon2 비용 거부
- QR 및 Google Authenticator migration 파싱

실행 명령:

```powershell
cd src-tauri
cargo test --locked --offline
```

프런트엔드 검증:

```powershell
npm run build
```
