use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use argon2::{Algorithm as ArgonAlgorithm, Argon2, Params, Version};
use base64::{
    engine::general_purpose::{STANDARD as B64, STANDARD_NO_PAD as B64_NO_PAD},
    Engine,
};
use data_encoding::BASE32_NOPAD;
use hmac::{Hmac, Mac};
use prost::Message;
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use std::{
    collections::{HashMap, HashSet},
    fs,
    io::Cursor,
    path::{Path, PathBuf},
    sync::Mutex,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use subtle::ConstantTimeEq;
use tauri::{AppHandle, Emitter, Manager, State, WebviewUrl, WebviewWindow, WebviewWindowBuilder};
use tauri_plugin_clipboard_manager::ClipboardExt;
use tauri_plugin_dialog::DialogExt;
use url::Url;
use uuid::Uuid;
use xcap::Monitor;
use zeroize::{Zeroize, Zeroizing};

const VAULT_FILE: &str = "vault.dat";
const BIOMETRIC_MARKER_FILE: &str = "biometric.enabled";
const BIOMETRIC_SERVICE: &str = "dev.sentinel.totp";
const BIOMETRIC_ACCOUNT: &str = "vault-key";
const AAD: &[u8] = b"sentinel-totp:v1:vault";
const BACKUP_AAD: &[u8] = b"sentinel-totp:v1:backup";
const KDF_MEMORY_KIB: u32 = 65_536;
const KDF_ITERATIONS: u32 = 3;
const KDF_PARALLELISM: u32 = 1;
const SESSION_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const CLIPBOARD_CLEAR_DELAY: Duration = Duration::from_secs(30);
const MAX_FILE_BYTES: u64 = 16 * 1024 * 1024;

type CommandResult<T> = Result<T, String>;

#[derive(Default)]
struct AppState {
    session: Mutex<Option<SessionKey>>,
}

struct SessionKey {
    key: Zeroizing<[u8; 32]>,
    last_used: Instant,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct KdfConfig {
    algorithm: String,
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
    salt: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct EncryptedEnvelope {
    version: u8,
    kind: String,
    kdf: KdfConfig,
    nonce: String,
    ciphertext: String,
}

#[derive(Default, Serialize, Deserialize, Zeroize)]
#[zeroize(drop)]
struct Vault {
    entries: Vec<OtpEntry>,
    #[serde(default)]
    backup: BackupSettings,
}

#[derive(Serialize, Deserialize, Zeroize)]
#[zeroize(drop)]
struct BackupSettings {
    automatic_file: bool,
    directory: String,
    retention: u32,
}

impl Default for BackupSettings {
    fn default() -> Self {
        Self {
            automatic_file: false,
            directory: String::new(),
            retention: 10,
        }
    }
}

#[derive(Serialize, Deserialize, Zeroize)]
#[zeroize(drop)]
struct OtpEntry {
    #[zeroize(skip)]
    id: Uuid,
    issuer: String,
    account: String,
    secret: String,
    algorithm: TotpAlgorithm,
    digits: u32,
    period: u64,
    #[serde(default)]
    icon: Option<String>,
    #[serde(default)]
    brand_icon: Option<String>,
    #[serde(default)]
    favorite: bool,
}

#[derive(Copy, Clone, Serialize, Deserialize, Zeroize)]
#[serde(rename_all = "UPPERCASE")]
enum TotpAlgorithm {
    Sha1,
    Sha256,
    Sha512,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct VaultStatus {
    initialized: bool,
    unlocked: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct BiometricStatus {
    supported: bool,
    enabled: bool,
    method: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct BackupSettingsView {
    automatic_file: bool,
    directory: String,
    retention: u32,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct BackupStatusView {
    configured: bool,
    healthy: bool,
    file_count: usize,
    last_backup_at: Option<u64>,
    message: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CodeView {
    id: Uuid,
    issuer: String,
    account: String,
    code: String,
    period: u64,
    remaining: u64,
    icon: Option<String>,
    brand_icon: Option<String>,
    favorite: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EntryView {
    id: Uuid,
    issuer: String,
    account: String,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ImportSummary {
    added: usize,
    skipped: usize,
    weak_secrets: usize,
    batch_index: u32,
    batch_size: u32,
}

#[derive(Clone, PartialEq, Message)]
struct MigrationPayload {
    #[prost(message, repeated, tag = "1")]
    otp_parameters: Vec<MigrationOtpParameters>,
    #[prost(int32, tag = "2")]
    version: i32,
    #[prost(int32, tag = "3")]
    batch_size: i32,
    #[prost(int32, tag = "4")]
    batch_index: i32,
    #[prost(int32, tag = "5")]
    batch_id: i32,
}

#[derive(Clone, PartialEq, Message, Zeroize)]
#[zeroize(drop)]
struct MigrationOtpParameters {
    #[prost(bytes = "vec", tag = "1")]
    secret: Vec<u8>,
    #[prost(string, tag = "2")]
    name: String,
    #[prost(string, tag = "3")]
    issuer: String,
    #[prost(int32, tag = "4")]
    algorithm: i32,
    #[prost(int32, tag = "5")]
    digits: i32,
    #[prost(int32, tag = "6")]
    otp_type: i32,
    #[prost(int64, tag = "7")]
    counter: i64,
}

struct ParsedOtp {
    issuer: String,
    account: String,
    secret: Zeroizing<String>,
    algorithm: TotpAlgorithm,
    digits: u32,
    period: u64,
}

struct ParsedQr {
    entries: Vec<ParsedOtp>,
    weak_secrets: usize,
    batch_index: u32,
    batch_size: u32,
}

fn error<E: std::fmt::Display>(context: &str, err: E) -> String {
    format!("{context}: {err}")
}

fn require_window(window: &WebviewWindow, expected: &str) -> CommandResult<()> {
    if window.label() == expected {
        Ok(())
    } else {
        Err("허용되지 않은 창에서 호출했습니다.".into())
    }
}

fn vault_path(app: &AppHandle) -> CommandResult<PathBuf> {
    let directory = app
        .path()
        .app_data_dir()
        .map_err(|e| error("앱 데이터 경로를 찾을 수 없습니다", e))?;
    fs::create_dir_all(&directory).map_err(|e| error("앱 데이터 폴더를 만들 수 없습니다", e))?;
    Ok(directory.join(VAULT_FILE))
}

fn biometric_marker_path(app: &AppHandle) -> CommandResult<PathBuf> {
    let vault = vault_path(app)?;
    Ok(vault.with_file_name(BIOMETRIC_MARKER_FILE))
}

#[cfg(windows)]
mod platform_biometric {
    use super::*;
    use keyring::Entry;
    use windows::{
        core::{factory, HSTRING},
        Security::Credentials::UI::{
            UserConsentVerificationResult, UserConsentVerifier, UserConsentVerifierAvailability,
        },
        Win32::System::WinRT::IUserConsentVerifierInterop,
    };
    use windows_future::IAsyncOperation;

    pub fn available() -> bool {
        match UserConsentVerifier::CheckAvailabilityAsync() {
            Ok(operation) => {
                operation.join().ok() == Some(UserConsentVerifierAvailability::Available)
            }
            Err(_) => false,
        }
    }

    fn verify(window: &WebviewWindow, message: &str) -> CommandResult<()> {
        let hwnd = window
            .hwnd()
            .map_err(|e| error("Windows 창 핸들 확인 실패", e))?;
        let verifier: IUserConsentVerifierInterop =
            factory::<UserConsentVerifier, IUserConsentVerifierInterop>()
                .map_err(|e| error("Windows Hello 초기화 실패", e))?;
        let operation: IAsyncOperation<UserConsentVerificationResult> =
            unsafe { verifier.RequestVerificationForWindowAsync(hwnd, &HSTRING::from(message)) }
                .map_err(|e| error("Windows Hello 요청 실패", e))?;
        let result = operation
            .join()
            .map_err(|e| error("Windows Hello 인증 실패", e))?;
        if result == UserConsentVerificationResult::Verified {
            Ok(())
        } else if result == UserConsentVerificationResult::Canceled {
            Err("Windows Hello 인증을 취소했습니다.".into())
        } else {
            Err("Windows Hello 인증을 완료하지 못했습니다.".into())
        }
    }

    fn entry() -> CommandResult<Entry> {
        Entry::new(BIOMETRIC_SERVICE, BIOMETRIC_ACCOUNT)
            .map_err(|e| error("Windows 자격 증명 저장소 열기 실패", e))
    }

    pub fn store(window: &WebviewWindow, key: &[u8; 32]) -> CommandResult<()> {
        verify(window, "Secretary 생체 인증을 설정합니다.")?;
        entry()?
            .set_password(&B64.encode(key))
            .map_err(|e| error("Windows 보호 저장소 쓰기 실패", e))
    }

    pub fn load(window: &WebviewWindow) -> CommandResult<Zeroizing<Vec<u8>>> {
        verify(window, "Secretary 잠금을 해제합니다.")?;
        let encoded = Zeroizing::new(
            entry()?
                .get_password()
                .map_err(|e| error("Windows 보호 키 읽기 실패", e))?,
        );
        Ok(Zeroizing::new(B64.decode(encoded.as_bytes()).map_err(
            |_| "저장된 Windows 보호 키가 손상되었습니다.".to_string(),
        )?))
    }

    pub fn delete() -> CommandResult<()> {
        match entry()?.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(error("Windows 보호 키 삭제 실패", e)),
        }
    }

    pub const fn method() -> &'static str {
        "Windows Hello"
    }
}

#[cfg(target_os = "macos")]
mod platform_biometric {
    use super::*;
    use localauthentication::{LAContext, LAPolicy};
    use security::{
        AccessControl, AccessControlFlags, AccessControlProtection, Keychain, KeychainOptions,
    };

    pub fn available() -> bool {
        LAContext::new()
            .and_then(|context| {
                context.can_evaluate_policy(LAPolicy::DeviceOwnerAuthenticationWithBiometrics)
            })
            .unwrap_or(false)
    }

    fn context() -> CommandResult<LAContext> {
        let context = LAContext::new().map_err(|e| error("Touch ID 초기화 실패", e))?;
        context
            .set_localized_reason("Secretary 잠금을 해제합니다.")
            .map_err(|e| error("Touch ID 안내 설정 실패", e))?;
        context
            .set_localized_fallback_title(None)
            .map_err(|e| error("Touch ID 설정 실패", e))?;
        Ok(context)
    }

    pub fn store(_window: &WebviewWindow, key: &[u8; 32]) -> CommandResult<()> {
        let context = context()?;
        if !context
            .evaluate_policy(
                LAPolicy::DeviceOwnerAuthenticationWithBiometrics,
                "Secretary 생체 인증을 설정합니다.",
            )
            .map_err(|e| error("Touch ID 인증 실패", e))?
        {
            return Err("Touch ID 인증을 완료하지 못했습니다.".into());
        }
        let access = AccessControl::create(
            AccessControlProtection::WhenUnlockedThisDeviceOnly,
            AccessControlFlags::BIOMETRY_CURRENT_SET,
        )
        .map_err(|e| error("Touch ID 접근 제어 생성 실패", e))?;
        let options = unsafe {
            KeychainOptions::default()
                .access_control(access)
                .data_protection_keychain(true)
                .authentication_context(context.as_raw_la_context())
        }
        .map_err(|e| error("Touch ID 인증 컨텍스트 연결 실패", e))?;
        Keychain::set_with_options(BIOMETRIC_ACCOUNT, BIOMETRIC_SERVICE, key, &options)
            .map_err(|e| error("Touch ID Keychain 저장 실패", e))
    }

    pub fn load(_window: &WebviewWindow) -> CommandResult<Zeroizing<Vec<u8>>> {
        let context = context()?;
        let options = unsafe {
            KeychainOptions::default()
                .data_protection_keychain(true)
                .authentication_context(context.as_raw_la_context())
        }
        .map_err(|e| error("Touch ID 인증 컨텍스트 연결 실패", e))?;
        let secret = Keychain::get_with_options(BIOMETRIC_ACCOUNT, BIOMETRIC_SERVICE, &options)
            .map_err(|e| error("Touch ID Keychain 읽기 실패", e))?;
        Ok(Zeroizing::new(secret.as_bytes().to_vec()))
    }

    pub fn delete() -> CommandResult<()> {
        Keychain::delete(BIOMETRIC_ACCOUNT, BIOMETRIC_SERVICE)
            .map_err(|e| error("Touch ID Keychain 삭제 실패", e))
    }

    pub const fn method() -> &'static str {
        "Touch ID"
    }
}

#[cfg(not(any(windows, target_os = "macos")))]
mod platform_biometric {
    use super::*;
    pub fn available() -> bool {
        false
    }
    pub fn store(_window: &WebviewWindow, _key: &[u8; 32]) -> CommandResult<()> {
        Err("이 운영체제에서는 생체 인증을 지원하지 않습니다.".into())
    }
    pub fn load(_window: &WebviewWindow) -> CommandResult<Zeroizing<Vec<u8>>> {
        Err("이 운영체제에서는 생체 인증을 지원하지 않습니다.".into())
    }
    pub fn delete() -> CommandResult<()> {
        Ok(())
    }
    pub const fn method() -> &'static str {
        "생체 인증"
    }
}

fn random_bytes<const N: usize>() -> CommandResult<[u8; N]> {
    let mut bytes = [0_u8; N];
    getrandom::fill(&mut bytes).map_err(|e| error("운영체제 난수 생성 실패", e))?;
    Ok(bytes)
}

fn new_kdf_config() -> CommandResult<KdfConfig> {
    let salt = random_bytes::<16>()?;
    Ok(KdfConfig {
        algorithm: "argon2id".into(),
        memory_kib: KDF_MEMORY_KIB,
        iterations: KDF_ITERATIONS,
        parallelism: KDF_PARALLELISM,
        salt: B64.encode(salt),
    })
}

fn validate_password(password: &str) -> CommandResult<()> {
    if password.chars().count() < 12 {
        return Err("마스터/백업 암호는 최소 12자여야 합니다.".into());
    }
    if password.len() > 1024 {
        return Err("암호가 너무 깁니다.".into());
    }
    Ok(())
}

fn derive_key(password: &[u8], config: &KdfConfig) -> CommandResult<Zeroizing<[u8; 32]>> {
    if config.algorithm != "argon2id"
        || config.memory_kib < KDF_MEMORY_KIB
        || config.memory_kib > 1_048_576
        || config.iterations < KDF_ITERATIONS
        || config.iterations > 10
        || config.parallelism == 0
        || config.parallelism > 8
    {
        return Err("지원하지 않거나 안전하지 않은 KDF 매개변수입니다.".into());
    }
    let salt = Zeroizing::new(
        B64.decode(&config.salt)
            .map_err(|_| "KDF salt가 손상되었습니다.".to_string())?,
    );
    if salt.len() != 16 {
        return Err("KDF salt 길이가 올바르지 않습니다.".into());
    }
    let params = Params::new(
        config.memory_kib,
        config.iterations,
        config.parallelism,
        Some(32),
    )
    .map_err(|e| error("KDF 설정 오류", e))?;
    let argon = Argon2::new(ArgonAlgorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0_u8; 32]);
    argon
        .hash_password_into(password, &salt, key.as_mut())
        .map_err(|e| error("키 파생 실패", e))?;
    Ok(key)
}

fn encrypt_vault(
    vault: &Vault,
    key: &[u8; 32],
    kdf: KdfConfig,
    kind: &str,
) -> CommandResult<EncryptedEnvelope> {
    let aad = if kind == "backup" { BACKUP_AAD } else { AAD };
    let plaintext =
        Zeroizing::new(serde_json::to_vec(vault).map_err(|e| error("금고 직렬화 실패", e))?);
    let nonce_bytes = random_bytes::<12>()?;
    let cipher =
        Aes256Gcm::new_from_slice(key).map_err(|_| "암호화 키가 올바르지 않습니다.".to_string())?;
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce_bytes),
            Payload {
                msg: &plaintext,
                aad,
            },
        )
        .map_err(|_| "금고 암호화 실패".to_string())?;
    Ok(EncryptedEnvelope {
        version: 1,
        kind: kind.into(),
        kdf,
        nonce: B64.encode(nonce_bytes),
        ciphertext: B64.encode(ciphertext),
    })
}

fn decrypt_vault(
    envelope: &EncryptedEnvelope,
    key: &[u8; 32],
    expected_kind: &str,
) -> CommandResult<Vault> {
    if envelope.version != 1 || envelope.kind != expected_kind {
        return Err("지원하지 않는 금고 형식입니다.".into());
    }
    let nonce = B64
        .decode(&envelope.nonce)
        .map_err(|_| "nonce가 손상되었습니다.".to_string())?;
    if nonce.len() != 12 {
        return Err("nonce 길이가 올바르지 않습니다.".into());
    }
    let ciphertext = Zeroizing::new(
        B64.decode(&envelope.ciphertext)
            .map_err(|_| "암호문이 손상되었습니다.".to_string())?,
    );
    let aad = if expected_kind == "backup" {
        BACKUP_AAD
    } else {
        AAD
    };
    let cipher =
        Aes256Gcm::new_from_slice(key).map_err(|_| "복호화 키가 올바르지 않습니다.".to_string())?;
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &ciphertext,
                    aad,
                },
            )
            .map_err(|_| "암호가 틀렸거나 파일이 변조되었습니다.".to_string())?,
    );
    serde_json::from_slice(&plaintext).map_err(|e| error("복호화 데이터 형식 오류", e))
}

fn read_envelope(path: &Path) -> CommandResult<EncryptedEnvelope> {
    let metadata = fs::metadata(path).map_err(|e| error("암호화 파일을 읽을 수 없습니다", e))?;
    if metadata.len() > MAX_FILE_BYTES {
        return Err("암호화 파일이 허용 크기를 초과합니다.".into());
    }
    let bytes = fs::read(path).map_err(|e| error("암호화 파일을 읽을 수 없습니다", e))?;
    serde_json::from_slice(&bytes).map_err(|e| error("암호화 파일 형식 오류", e))
}

fn atomic_write(path: &Path, envelope: &EncryptedEnvelope) -> CommandResult<()> {
    let bytes = serde_json::to_vec(envelope).map_err(|e| error("암호화 파일 직렬화 실패", e))?;
    let parent = path
        .parent()
        .ok_or_else(|| "저장 폴더가 올바르지 않습니다.".to_string())?;
    fs::create_dir_all(parent).map_err(|e| error("저장 폴더 생성 실패", e))?;
    let temp = parent.join(format!(".secretary-{}.tmp", Uuid::new_v4()));

    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temp)
            .map_err(|e| error("임시 파일 생성 실패", e))?;
        file.write_all(&bytes)
            .map_err(|e| error("임시 파일 쓰기 실패", e))?;
        file.sync_all()
            .map_err(|e| error("임시 파일 동기화 실패", e))?;
    }
    #[cfg(not(unix))]
    {
        use std::io::Write;
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp)
            .map_err(|e| error("임시 파일 생성 실패", e))?;
        file.write_all(&bytes)
            .map_err(|e| error("임시 파일 쓰기 실패", e))?;
        file.sync_all()
            .map_err(|e| error("임시 파일 동기화 실패", e))?;
    }

    if path.exists() {
        fs::remove_file(path).map_err(|e| {
            let _ = fs::remove_file(&temp);
            error("기존 암호화 파일 교체 실패", e)
        })?;
    }
    fs::rename(&temp, path).map_err(|e| {
        let _ = fs::remove_file(&temp);
        error("암호화 파일 저장 실패", e)
    })?;
    Ok(())
}

fn with_session<T>(
    state: &State<'_, AppState>,
    action: impl FnOnce(&[u8; 32]) -> CommandResult<T>,
) -> CommandResult<T> {
    let mut guard = state
        .session
        .lock()
        .map_err(|_| "보안 상태 잠금 오류".to_string())?;
    let expired = guard
        .as_ref()
        .map(|session| session.last_used.elapsed() >= SESSION_TIMEOUT)
        .unwrap_or(false);
    if expired {
        *guard = None;
    }
    let session = guard
        .as_ref()
        .ok_or_else(|| "금고가 잠겼습니다.".to_string())?;
    action(&session.key)
}

fn schedule_clipboard_clear(app: AppHandle, copied: Zeroizing<String>) {
    tauri::async_runtime::spawn(async move {
        tokio::time::sleep(CLIPBOARD_CLEAR_DELAY).await;
        if app.clipboard().read_text().ok().as_deref() == Some(copied.as_str()) {
            let _ = app.clipboard().write_text(String::new());
        }
    });
}

fn load_local(app: &AppHandle, key: &[u8; 32]) -> CommandResult<(Vault, KdfConfig)> {
    let envelope = read_envelope(&vault_path(app)?)?;
    let vault = decrypt_vault(&envelope, key, "vault")?;
    Ok((vault, envelope.kdf))
}

fn save_local(app: &AppHandle, key: &[u8; 32], kdf: KdfConfig, vault: &Vault) -> CommandResult<()> {
    let envelope = encrypt_vault(vault, key, kdf.clone(), "vault")?;
    atomic_write(&vault_path(app)?, &envelope)?;
    if vault.backup.automatic_file {
        write_automatic_file_backup(vault, key, kdf)?;
    }
    Ok(())
}

fn write_automatic_file_backup(vault: &Vault, key: &[u8; 32], kdf: KdfConfig) -> CommandResult<()> {
    let directory = PathBuf::from(&vault.backup.directory);
    if !directory.is_dir() {
        return Err("자동 백업 폴더를 찾을 수 없습니다.".into());
    }
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "시스템 시간이 올바르지 않습니다.".to_string())?
        .as_millis();
    let envelope = encrypt_vault(vault, key, kdf, "backup")?;
    let path = directory.join(format!("secretary-auto-{timestamp}.enc"));
    atomic_write(&path, &envelope)?;

    let mut backups = fs::read_dir(&directory)
        .map_err(|e| error("자동 백업 폴더 읽기 실패", e))?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("secretary-auto-") && name.ends_with(".enc"))
        })
        .collect::<Vec<_>>();
    backups.sort();
    let excess = backups
        .len()
        .saturating_sub(vault.backup.retention as usize);
    for old in backups.into_iter().take(excess) {
        fs::remove_file(&old).map_err(|e| error("오래된 자동 백업 삭제 실패", e))?;
    }
    Ok(())
}

fn normalize_secret(input: &str) -> CommandResult<Zeroizing<String>> {
    let normalized = Zeroizing::new(
        input
            .chars()
            .filter(|c| !c.is_ascii_whitespace() && *c != '-')
            .flat_map(char::to_uppercase)
            .collect::<String>(),
    );
    let decoded = Zeroizing::new(
        BASE32_NOPAD
            .decode(normalized.as_bytes())
            .map_err(|_| "Secret은 올바른 Base32여야 합니다.".to_string())?,
    );
    if decoded.is_empty() {
        return Err("Secret이 비어 있습니다.".into());
    }
    Ok(normalized)
}

fn parse_otpauth(input: &str) -> CommandResult<ParsedOtp> {
    if input.len() > 8192 {
        return Err("otpauth URI가 너무 깁니다.".into());
    }
    let url = Url::parse(input).map_err(|_| "올바른 otpauth URI가 아닙니다.".to_string())?;
    if url.scheme() != "otpauth" || url.host_str() != Some("totp") {
        return Err("TOTP 형식의 otpauth URI만 지원합니다.".into());
    }
    let label = url.path().trim_start_matches('/');
    if label.is_empty() {
        return Err("계정 라벨이 없습니다.".into());
    }
    let label = percent_decode(label)?;
    let mut secret = None;
    let mut issuer_query = None;
    let mut algorithm = TotpAlgorithm::Sha1;
    let mut digits = 6_u32;
    let mut period = 30_u64;
    for (name, value) in url.query_pairs() {
        match name.as_ref() {
            "secret" => secret = Some(normalize_secret(&value)?),
            "issuer" => issuer_query = Some(value.into_owned()),
            "algorithm" => {
                algorithm = match value.to_ascii_uppercase().as_str() {
                    "SHA1" => TotpAlgorithm::Sha1,
                    "SHA256" => TotpAlgorithm::Sha256,
                    "SHA512" => TotpAlgorithm::Sha512,
                    _ => return Err("지원하지 않는 TOTP 해시 알고리즘입니다.".into()),
                }
            }
            "digits" => {
                digits = value
                    .parse()
                    .map_err(|_| "digits 값이 올바르지 않습니다.".to_string())?;
                if digits != 6 && digits != 8 {
                    return Err("6자리 또는 8자리 TOTP만 지원합니다.".into());
                }
            }
            "period" => {
                period = value
                    .parse()
                    .map_err(|_| "period 값이 올바르지 않습니다.".to_string())?;
                if !(15..=120).contains(&period) {
                    return Err("TOTP period는 15~120초여야 합니다.".into());
                }
            }
            _ => {}
        }
    }
    let (label_issuer, account) = label
        .split_once(':')
        .map(|(a, b)| (a.trim().to_string(), b.trim().to_string()))
        .unwrap_or_else(|| (String::new(), label.trim().to_string()));
    let issuer = issuer_query.unwrap_or(label_issuer);
    if account.is_empty() || issuer.len() > 256 || account.len() > 512 {
        return Err("서비스명 또는 계정명이 올바르지 않습니다.".into());
    }
    Ok(ParsedOtp {
        issuer,
        account,
        secret: secret.ok_or_else(|| "otpauth URI에 secret이 없습니다.".to_string())?,
        algorithm,
        digits,
        period,
    })
}

fn parse_qr_content(input: &str) -> CommandResult<ParsedQr> {
    if input.starts_with("otpauth-migration://") {
        parse_google_migration(input)
    } else {
        Ok(ParsedQr {
            entries: vec![parse_otpauth(input)?],
            weak_secrets: 0,
            batch_index: 0,
            batch_size: 1,
        })
    }
}

fn parse_google_migration(input: &str) -> CommandResult<ParsedQr> {
    if input.len() > 65_536 {
        return Err("Google Authenticator 내보내기 데이터가 너무 큽니다.".into());
    }
    let url = Url::parse(input)
        .map_err(|_| "올바른 Google Authenticator 내보내기 QR이 아닙니다.".to_string())?;
    if url.scheme() != "otpauth-migration" || url.host_str() != Some("offline") {
        return Err("지원하지 않는 Google Authenticator 마이그레이션 URI입니다.".into());
    }
    let encoded = url
        .query_pairs()
        .find(|(name, _)| name == "data")
        .map(|(_, value)| value.into_owned())
        .ok_or_else(|| "마이그레이션 QR에 data가 없습니다.".to_string())?
        .replace(' ', "+");
    let raw = Zeroizing::new(
        B64.decode(encoded.as_bytes())
            .or_else(|_| B64_NO_PAD.decode(encoded.as_bytes()))
            .map_err(|_| "마이그레이션 데이터의 Base64 형식이 손상되었습니다.".to_string())?,
    );
    if raw.len() > 1024 * 1024 {
        return Err("마이그레이션 payload가 허용 크기를 초과합니다.".into());
    }
    let mut payload = MigrationPayload::decode(raw.as_slice())
        .map_err(|e| error("Google Authenticator payload 해석 실패", e))?;
    if payload.otp_parameters.is_empty() {
        return Err("마이그레이션 QR에 인증 계정이 없습니다.".into());
    }
    if payload.otp_parameters.len() > 256 {
        return Err("한 QR에서 가져올 수 있는 계정 수를 초과했습니다.".into());
    }

    let batch_size = payload.batch_size.max(1) as u32;
    let batch_index = payload.batch_index.max(0) as u32;
    if batch_size > 100 || batch_index >= batch_size {
        return Err("Google 내보내기 QR의 배치 정보가 올바르지 않습니다.".into());
    }
    let mut parsed = Vec::with_capacity(payload.otp_parameters.len());
    let mut weak_secrets = 0_usize;
    for parameter in payload.otp_parameters.drain(..) {
        if parameter.otp_type != 2 {
            return Err(
                "Google 내보내기의 HOTP 계정은 지원하지 않습니다. TOTP 계정만 가져올 수 있습니다."
                    .into(),
            );
        }
        if parameter.secret.is_empty() {
            return Err("Google 내보내기에 비어 있는 Secret이 포함되어 있습니다.".into());
        }
        if parameter.secret.len() < 16 {
            weak_secrets += 1;
        }
        let algorithm = match parameter.algorithm {
            0 | 1 => TotpAlgorithm::Sha1,
            2 => TotpAlgorithm::Sha256,
            3 => TotpAlgorithm::Sha512,
            _ => return Err("Google 내보내기에 지원하지 않는 해시 알고리즘이 있습니다.".into()),
        };
        let digits = match parameter.digits {
            0 | 1 => 6,
            2 => 8,
            _ => return Err("Google 내보내기에 지원하지 않는 OTP 자릿수가 있습니다.".into()),
        };
        let mut issuer = parameter.issuer.trim().to_string();
        let mut account = parameter.name.trim().to_string();
        if let Some(separator) = account.find(':') {
            let label_issuer = account[..separator].trim().to_string();
            let label_account = account[separator + 1..].trim().to_string();
            if issuer.is_empty() {
                issuer = label_issuer;
            }
            account = label_account;
        }
        if account.is_empty() || issuer.len() > 256 || account.len() > 512 {
            return Err("Google 내보내기의 서비스명 또는 계정명이 올바르지 않습니다.".into());
        }
        parsed.push(ParsedOtp {
            issuer,
            account,
            secret: Zeroizing::new(BASE32_NOPAD.encode(&parameter.secret)),
            algorithm,
            digits,
            period: 30,
        });
    }
    Ok(ParsedQr {
        entries: parsed,
        weak_secrets,
        batch_index,
        batch_size,
    })
}

fn percent_decode(value: &str) -> CommandResult<String> {
    let decoded = percent_encoding::percent_decode_str(value)
        .decode_utf8()
        .map_err(|_| "계정 라벨 인코딩이 올바르지 않습니다.".to_string())?;
    Ok(decoded.into_owned())
}

fn add_parsed(
    app: &AppHandle,
    state: &State<'_, AppState>,
    parsed: ParsedOtp,
) -> CommandResult<EntryView> {
    with_session(state, |key| {
        let (mut vault, kdf) = load_local(app, key)?;
        let candidate = BASE32_NOPAD
            .decode(parsed.secret.as_bytes())
            .map_err(|_| "Secret 디코딩 실패".to_string())?;
        let duplicate = vault.entries.iter().any(|entry| {
            BASE32_NOPAD
                .decode(entry.secret.as_bytes())
                .map(|existing| existing.ct_eq(&candidate).into())
                .unwrap_or(false)
        });
        let mut candidate = Zeroizing::new(candidate);
        if duplicate {
            candidate.zeroize();
            return Err("이미 등록된 Secret입니다.".into());
        }
        let id = Uuid::new_v4();
        let view = EntryView {
            id,
            issuer: parsed.issuer.clone(),
            account: parsed.account.clone(),
        };
        vault.entries.push(OtpEntry {
            id,
            issuer: parsed.issuer,
            account: parsed.account,
            secret: parsed.secret.to_string(),
            algorithm: parsed.algorithm,
            digits: parsed.digits,
            period: parsed.period,
            icon: None,
            brand_icon: None,
            favorite: false,
        });
        save_local(app, key, kdf, &vault)?;
        Ok(view)
    })
}

fn add_many(
    app: &AppHandle,
    state: &State<'_, AppState>,
    parsed: ParsedQr,
) -> CommandResult<ImportSummary> {
    with_session(state, |key| {
        let (mut vault, kdf) = load_local(app, key)?;
        let mut added = 0_usize;
        let mut skipped = 0_usize;
        for item in parsed.entries {
            let candidate = Zeroizing::new(
                BASE32_NOPAD
                    .decode(item.secret.as_bytes())
                    .map_err(|_| "Secret 디코딩 실패".to_string())?,
            );
            let duplicate = vault.entries.iter().any(|entry| {
                BASE32_NOPAD
                    .decode(entry.secret.as_bytes())
                    .map(|existing| {
                        let existing = Zeroizing::new(existing);
                        bool::from(existing.ct_eq(&candidate))
                    })
                    .unwrap_or(false)
            });
            if duplicate {
                skipped += 1;
                continue;
            }
            vault.entries.push(OtpEntry {
                id: Uuid::new_v4(),
                issuer: item.issuer,
                account: item.account,
                secret: item.secret.to_string(),
                algorithm: item.algorithm,
                digits: item.digits,
                period: item.period,
                icon: None,
                brand_icon: None,
                favorite: false,
            });
            added += 1;
        }
        if added == 0 {
            return Err("QR의 모든 인증키가 이미 등록되어 있습니다.".into());
        }
        save_local(app, key, kdf, &vault)?;
        Ok(ImportSummary {
            added,
            skipped,
            weak_secrets: parsed.weak_secrets,
            batch_index: parsed.batch_index,
            batch_size: parsed.batch_size,
        })
    })
}

fn totp(entry: &OtpEntry, unix_seconds: u64) -> CommandResult<String> {
    let secret = Zeroizing::new(
        BASE32_NOPAD
            .decode(entry.secret.as_bytes())
            .map_err(|_| "저장된 Secret이 손상되었습니다.".to_string())?,
    );
    let counter = unix_seconds / entry.period;
    let message = counter.to_be_bytes();
    let digest = match entry.algorithm {
        TotpAlgorithm::Sha1 => {
            let mut mac = <Hmac<Sha1> as Mac>::new_from_slice(&secret)
                .map_err(|_| "HMAC 키 오류".to_string())?;
            mac.update(&message);
            Zeroizing::new(mac.finalize().into_bytes().to_vec())
        }
        TotpAlgorithm::Sha256 => {
            let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&secret)
                .map_err(|_| "HMAC 키 오류".to_string())?;
            mac.update(&message);
            Zeroizing::new(mac.finalize().into_bytes().to_vec())
        }
        TotpAlgorithm::Sha512 => {
            let mut mac = <Hmac<Sha512> as Mac>::new_from_slice(&secret)
                .map_err(|_| "HMAC 키 오류".to_string())?;
            mac.update(&message);
            Zeroizing::new(mac.finalize().into_bytes().to_vec())
        }
    };
    let offset = (digest[digest.len() - 1] & 0x0f) as usize;
    let binary = (u32::from(digest[offset] & 0x7f) << 24)
        | (u32::from(digest[offset + 1]) << 16)
        | (u32::from(digest[offset + 2]) << 8)
        | u32::from(digest[offset + 3]);
    let modulus = 10_u32.pow(entry.digits);
    Ok(format!(
        "{:0width$}",
        binary % modulus,
        width = entry.digits as usize
    ))
}

fn now_seconds() -> CommandResult<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| "시스템 시간이 올바르지 않습니다.".to_string())
}

fn secure_index(upper_bound: usize) -> CommandResult<usize> {
    if upper_bound == 0 || upper_bound > 256 {
        return Err("암호 문자 집합 크기가 올바르지 않습니다.".into());
    }
    let limit = 256 - (256 % upper_bound);
    loop {
        let byte = random_bytes::<1>()?[0] as usize;
        if byte < limit {
            return Ok(byte % upper_bound);
        }
    }
}

#[tauri::command]
fn generate_password(
    window: WebviewWindow,
    length: usize,
    lowercase: bool,
    uppercase: bool,
    digits: bool,
    symbols: bool,
) -> CommandResult<String> {
    require_window(&window, "main")?;
    if !(12..=128).contains(&length) {
        return Err("암호 길이는 12~128자여야 합니다.".into());
    }
    let groups = [
        (lowercase, b"abcdefghijklmnopqrstuvwxyz".as_slice()),
        (uppercase, b"ABCDEFGHIJKLMNOPQRSTUVWXYZ".as_slice()),
        (digits, b"0123456789".as_slice()),
        (symbols, b"!@#$%^&*()-_=+[]{}:,.?".as_slice()),
    ];
    let selected = groups
        .iter()
        .filter(|(enabled, _)| *enabled)
        .map(|(_, chars)| *chars)
        .collect::<Vec<_>>();
    if selected.is_empty() {
        return Err("하나 이상의 문자 종류를 선택하세요.".into());
    }
    let alphabet = selected
        .iter()
        .flat_map(|group| group.iter().copied())
        .collect::<Vec<_>>();
    let mut password = Zeroizing::new(Vec::with_capacity(length));
    for group in &selected {
        password.push(group[secure_index(group.len())?]);
    }
    while password.len() < length {
        password.push(alphabet[secure_index(alphabet.len())?]);
    }
    for index in (1..password.len()).rev() {
        let swap = secure_index(index + 1)?;
        password.swap(index, swap);
    }
    let password = Zeroizing::new(
        String::from_utf8(password.to_vec()).map_err(|_| "암호 생성 실패".to_string())?,
    );
    Ok(password.to_string())
}

#[tauri::command]
fn copy_generated_password(
    app: AppHandle,
    window: WebviewWindow,
    password: String,
) -> CommandResult<()> {
    require_window(&window, "main")?;
    let password = Zeroizing::new(password);
    if password.len() > 512 || password.is_empty() {
        return Err("복사할 암호가 올바르지 않습니다.".into());
    }
    app.clipboard()
        .write_text(password.to_string())
        .map_err(|e| error("클립보드 쓰기 실패", e))?;
    schedule_clipboard_clear(app, password);
    Ok(())
}

#[tauri::command]
fn vault_status(
    app: AppHandle,
    window: WebviewWindow,
    state: State<'_, AppState>,
) -> CommandResult<VaultStatus> {
    require_window(&window, "main")?;
    let initialized = vault_path(&app)?.exists();
    let unlocked = {
        let mut guard = state
            .session
            .lock()
            .map_err(|_| "보안 상태 잠금 오류".to_string())?;
        if guard
            .as_ref()
            .is_some_and(|s| s.last_used.elapsed() >= SESSION_TIMEOUT)
        {
            *guard = None;
        }
        guard.is_some()
    };
    Ok(VaultStatus {
        initialized,
        unlocked,
    })
}

#[tauri::command]
fn biometric_status(app: AppHandle, window: WebviewWindow) -> CommandResult<BiometricStatus> {
    require_window(&window, "main")?;
    Ok(BiometricStatus {
        supported: platform_biometric::available(),
        enabled: biometric_marker_path(&app)?.exists(),
        method: platform_biometric::method().into(),
    })
}

#[tauri::command]
fn enable_biometric(
    app: AppHandle,
    window: WebviewWindow,
    state: State<'_, AppState>,
) -> CommandResult<()> {
    require_window(&window, "main")?;
    if !platform_biometric::available() {
        return Err(format!(
            "{}을 사용할 수 없습니다.",
            platform_biometric::method()
        ));
    }
    let key = with_session(&state, |key| Ok(Zeroizing::new(*key)))?;
    platform_biometric::store(&window, &key)?;
    fs::write(biometric_marker_path(&app)?, b"1").map_err(|e| error("생체 인증 설정 저장 실패", e))
}

#[tauri::command]
fn unlock_with_biometric(
    app: AppHandle,
    window: WebviewWindow,
    state: State<'_, AppState>,
) -> CommandResult<()> {
    require_window(&window, "main")?;
    if !biometric_marker_path(&app)?.exists() {
        return Err("생체 인증이 설정되어 있지 않습니다.".into());
    }
    let stored = platform_biometric::load(&window)?;
    let key_bytes: [u8; 32] = stored
        .as_slice()
        .try_into()
        .map_err(|_| "OS 보호 저장소의 금고 키가 손상되었습니다.".to_string())?;
    let key = Zeroizing::new(key_bytes);
    let envelope = read_envelope(&vault_path(&app)?)?;
    let _verified = decrypt_vault(&envelope, &key, "vault")?;
    let mut guard = state
        .session
        .lock()
        .map_err(|_| "보안 상태 잠금 오류".to_string())?;
    *guard = Some(SessionKey {
        key,
        last_used: Instant::now(),
    });
    Ok(())
}

#[tauri::command]
fn disable_biometric(
    app: AppHandle,
    window: WebviewWindow,
    state: State<'_, AppState>,
) -> CommandResult<()> {
    require_window(&window, "main")?;
    with_session(&state, |_| Ok(()))?;
    platform_biometric::delete()?;
    let marker = biometric_marker_path(&app)?;
    if marker.exists() {
        fs::remove_file(marker).map_err(|e| error("생체 인증 설정 삭제 실패", e))?;
    }
    Ok(())
}

#[tauri::command]
fn initialize_vault(
    app: AppHandle,
    window: WebviewWindow,
    state: State<'_, AppState>,
    password: String,
) -> CommandResult<()> {
    require_window(&window, "main")?;
    let password = Zeroizing::new(password);
    validate_password(&password)?;
    let path = vault_path(&app)?;
    if path.exists() {
        return Err("이미 금고가 존재합니다.".into());
    }
    let kdf = new_kdf_config()?;
    let key = derive_key(password.as_bytes(), &kdf)?;
    let envelope = encrypt_vault(&Vault::default(), &key, kdf, "vault")?;
    atomic_write(&path, &envelope)?;
    let mut guard = state
        .session
        .lock()
        .map_err(|_| "보안 상태 잠금 오류".to_string())?;
    *guard = Some(SessionKey {
        key,
        last_used: Instant::now(),
    });
    Ok(())
}

#[tauri::command]
fn unlock_vault(
    app: AppHandle,
    window: WebviewWindow,
    state: State<'_, AppState>,
    password: String,
) -> CommandResult<()> {
    require_window(&window, "main")?;
    let password = Zeroizing::new(password);
    let envelope = read_envelope(&vault_path(&app)?)?;
    let key = derive_key(password.as_bytes(), &envelope.kdf)?;
    let _verified = decrypt_vault(&envelope, &key, "vault")?;
    let mut guard = state
        .session
        .lock()
        .map_err(|_| "보안 상태 잠금 오류".to_string())?;
    *guard = Some(SessionKey {
        key,
        last_used: Instant::now(),
    });
    Ok(())
}

#[tauri::command]
fn lock_vault(window: WebviewWindow, state: State<'_, AppState>) -> CommandResult<()> {
    require_window(&window, "main")?;
    *state
        .session
        .lock()
        .map_err(|_| "보안 상태 잠금 오류".to_string())? = None;
    Ok(())
}

#[tauri::command]
fn touch_session(window: WebviewWindow, state: State<'_, AppState>) -> CommandResult<()> {
    require_window(&window, "main")?;
    let mut guard = state
        .session
        .lock()
        .map_err(|_| "보안 상태 잠금 오류".to_string())?;
    let session = guard
        .as_mut()
        .ok_or_else(|| "금고가 잠겼습니다.".to_string())?;
    if session.last_used.elapsed() >= SESSION_TIMEOUT {
        *guard = None;
        return Err("금고가 잠겼습니다.".into());
    }
    session.last_used = Instant::now();
    Ok(())
}

#[tauri::command]
fn list_codes(
    app: AppHandle,
    window: WebviewWindow,
    state: State<'_, AppState>,
) -> CommandResult<Vec<CodeView>> {
    require_window(&window, "main")?;
    with_session(&state, |key| {
        let (vault, _) = load_local(&app, key)?;
        let now = now_seconds()?;
        vault
            .entries
            .iter()
            .map(|entry| {
                Ok(CodeView {
                    id: entry.id,
                    issuer: entry.issuer.clone(),
                    account: entry.account.clone(),
                    code: totp(entry, now)?,
                    period: entry.period,
                    remaining: entry.period - (now % entry.period),
                    icon: entry.icon.clone(),
                    brand_icon: entry.brand_icon.clone(),
                    favorite: entry.favorite,
                })
            })
            .collect()
    })
}

#[tauri::command]
fn list_favorite_codes(
    app: AppHandle,
    window: WebviewWindow,
    state: State<'_, AppState>,
) -> CommandResult<Vec<CodeView>> {
    require_window(&window, "mini")?;
    with_session(&state, |key| {
        let (vault, _) = load_local(&app, key)?;
        let now = now_seconds()?;
        vault
            .entries
            .iter()
            .filter(|entry| entry.favorite)
            .map(|entry| {
                Ok(CodeView {
                    id: entry.id,
                    issuer: entry.issuer.clone(),
                    account: entry.account.clone(),
                    code: totp(entry, now)?,
                    period: entry.period,
                    remaining: entry.period - (now % entry.period),
                    icon: entry.icon.clone(),
                    brand_icon: entry.brand_icon.clone(),
                    favorite: true,
                })
            })
            .collect()
    })
}

#[tauri::command]
fn add_otpauth_uri(
    app: AppHandle,
    window: WebviewWindow,
    state: State<'_, AppState>,
    uri: String,
) -> CommandResult<EntryView> {
    require_window(&window, "main")?;
    let uri = Zeroizing::new(uri);
    let parsed = parse_otpauth(&uri)?;
    add_parsed(&app, &state, parsed)
}

#[tauri::command]
fn delete_entry(
    app: AppHandle,
    window: WebviewWindow,
    state: State<'_, AppState>,
    id: Uuid,
) -> CommandResult<()> {
    require_window(&window, "main")?;
    with_session(&state, |key| {
        let (mut vault, kdf) = load_local(&app, key)?;
        let before = vault.entries.len();
        vault.entries.retain(|entry| entry.id != id);
        if vault.entries.len() == before {
            return Err("삭제할 항목을 찾지 못했습니다.".into());
        }
        save_local(&app, key, kdf, &vault)
    })
}

#[tauri::command]
fn set_entry_favorite(
    app: AppHandle,
    window: WebviewWindow,
    state: State<'_, AppState>,
    id: Uuid,
    favorite: bool,
) -> CommandResult<()> {
    require_window(&window, "main")?;
    with_session(&state, |key| {
        let (mut vault, kdf) = load_local(&app, key)?;
        let entry = vault
            .entries
            .iter_mut()
            .find(|entry| entry.id == id)
            .ok_or_else(|| "수정할 항목을 찾지 못했습니다.".to_string())?;
        entry.favorite = favorite;
        save_local(&app, key, kdf, &vault)
    })
}

#[tauri::command]
fn reorder_entries(
    app: AppHandle,
    window: WebviewWindow,
    state: State<'_, AppState>,
    ordered_ids: Vec<Uuid>,
) -> CommandResult<()> {
    require_window(&window, "main")?;
    if ordered_ids.len() < 2 {
        return Ok(());
    }
    let selected = ordered_ids.iter().copied().collect::<HashSet<_>>();
    if selected.len() != ordered_ids.len() {
        return Err("중복된 인증키 순서 정보입니다.".into());
    }
    with_session(&state, |key| {
        let (mut vault, kdf) = load_local(&app, key)?;
        if !selected
            .iter()
            .all(|id| vault.entries.iter().any(|entry| entry.id == *id))
        {
            return Err("순서를 변경할 인증키를 찾을 수 없습니다.".into());
        }
        let original = std::mem::take(&mut vault.entries);
        let mut owned = HashMap::with_capacity(selected.len());
        let mut slots = Vec::with_capacity(original.len());
        for entry in original {
            if selected.contains(&entry.id) {
                owned.insert(entry.id, entry);
                slots.push(None);
            } else {
                slots.push(Some(entry));
            }
        }
        let mut reordered = ordered_ids
            .iter()
            .map(|id| {
                owned
                    .remove(id)
                    .ok_or_else(|| "인증키 순서 정보가 올바르지 않습니다.".to_string())
            })
            .collect::<CommandResult<Vec<_>>>()?
            .into_iter();
        vault.entries = slots
            .into_iter()
            .map(|slot| slot.unwrap_or_else(|| reordered.next().expect("validated reorder slots")))
            .collect();
        save_local(&app, key, kdf, &vault)
    })
}

#[tauri::command]
fn update_entry(
    app: AppHandle,
    window: WebviewWindow,
    state: State<'_, AppState>,
    id: Uuid,
    issuer: String,
    account: String,
    brand_icon: Option<String>,
    icon: Option<String>,
) -> CommandResult<()> {
    require_window(&window, "main")?;
    let issuer = issuer.trim().to_string();
    let account = account.trim().to_string();
    if account.is_empty() || issuer.len() > 256 || account.len() > 512 {
        return Err("서비스명 또는 계정명이 올바르지 않습니다.".into());
    }
    let brand_icon = brand_icon
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    if brand_icon.as_ref().is_some_and(|value| {
        value.len() > 64
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    }) {
        return Err("올바르지 않은 아이콘 식별자입니다.".into());
    }
    if brand_icon.is_some() && icon.is_some() {
        return Err("브랜드 아이콘과 사용자 이미지를 동시에 저장할 수 없습니다.".into());
    }
    if let Some(value) = &icon {
        let encoded = value
            .strip_prefix("data:image/png;base64,")
            .ok_or_else(|| "사용자 아이콘 형식이 올바르지 않습니다.".to_string())?;
        if encoded.len() > 2 * 1024 * 1024 {
            return Err("사용자 아이콘 데이터가 너무 큽니다.".into());
        }
        let decoded = B64
            .decode(encoded)
            .map_err(|_| "사용자 아이콘 데이터가 손상되었습니다.".to_string())?;
        let decoded_image = image::load_from_memory(&decoded)
            .map_err(|_| "사용자 아이콘을 읽을 수 없습니다.".to_string())?;
        if decoded_image.width() > 128 || decoded_image.height() > 128 {
            return Err("사용자 아이콘 크기가 올바르지 않습니다.".into());
        }
    }
    with_session(&state, |key| {
        let (mut vault, kdf) = load_local(&app, key)?;
        let entry = vault
            .entries
            .iter_mut()
            .find(|entry| entry.id == id)
            .ok_or_else(|| "수정할 항목을 찾지 못했습니다.".to_string())?;
        entry.issuer = issuer;
        entry.account = account;
        entry.brand_icon = brand_icon;
        entry.icon = icon;
        save_local(&app, key, kdf, &vault)
    })
}

#[tauri::command]
fn choose_entry_icon(app: AppHandle, window: WebviewWindow) -> CommandResult<Option<String>> {
    require_window(&window, "main")?;
    let selected = app
        .dialog()
        .file()
        .add_filter("Raster image", &["png", "jpg", "jpeg", "webp"])
        .blocking_pick_file();
    let Some(path) = selected else {
        return Ok(None);
    };
    let path = path
        .into_path()
        .map_err(|_| "선택한 이미지 경로를 사용할 수 없습니다.".to_string())?;
    let metadata = fs::metadata(&path).map_err(|e| error("아이콘 파일을 읽을 수 없습니다", e))?;
    if metadata.len() > 5 * 1024 * 1024 {
        return Err("아이콘 이미지는 5MB 이하여야 합니다.".into());
    }
    let source = fs::read(&path).map_err(|e| error("아이콘 파일을 읽을 수 없습니다", e))?;
    let image =
        image::load_from_memory(&source).map_err(|e| error("지원하지 않거나 손상된 이미지", e))?;
    if image.width() > 4096 || image.height() > 4096 {
        return Err("아이콘 이미지 해상도는 4096×4096 이하여야 합니다.".into());
    }
    let icon = image.thumbnail(128, 128);
    let mut encoded = Zeroizing::new(Vec::new());
    icon.write_to(&mut Cursor::new(&mut *encoded), image::ImageFormat::Png)
        .map_err(|e| error("안전한 PNG 아이콘 변환 실패", e))?;
    let data_url = Zeroizing::new(format!("data:image/png;base64,{}", B64.encode(&encoded)));

    Ok(Some(data_url.to_string()))
}

#[tauri::command]
fn minimize_main_window(app: AppHandle, window: WebviewWindow) -> CommandResult<()> {
    require_window(&window, "main")?;
    let mini = app
        .get_webview_window("mini")
        .ok_or_else(|| "미니 창을 찾을 수 없습니다.".to_string())?;
    let monitor = window
        .current_monitor()
        .map_err(|e| error("현재 모니터 확인 실패", e))?
        .ok_or_else(|| "현재 모니터를 찾을 수 없습니다.".to_string())?;
    let work_area = monitor.work_area();
    mini.set_size(tauri::LogicalSize::new(6.0, 6.0))
        .map_err(|e| error("미니 창 크기 설정 실패", e))?;
    let mini_size = mini
        .outer_size()
        .map_err(|e| error("미니 창 크기 확인 실패", e))?;
    let x = work_area.position.x + work_area.size.width as i32 - mini_size.width as i32;
    let y = work_area.position.y;
    mini.set_position(tauri::PhysicalPosition::new(x, y))
        .map_err(|e| error("미니 창 위치 설정 실패", e))?;
    mini.show().map_err(|e| error("미니 창 표시 실패", e))?;
    window.hide().map_err(|e| {
        let _ = mini.hide();
        error("메인 창 숨기기 실패", e)
    })?;
    Ok(())
}

#[tauri::command]
fn set_mini_revealed(
    window: WebviewWindow,
    revealed: bool,
    item_count: Option<u32>,
) -> CommandResult<()> {
    require_window(&window, "mini")?;
    let monitor = window
        .current_monitor()
        .map_err(|e| error("현재 모니터 확인 실패", e))?
        .ok_or_else(|| "현재 모니터를 찾을 수 없습니다.".to_string())?;
    let work_area = monitor.work_area();
    let (width, height) = if revealed {
        let count = item_count.unwrap_or(0).min(6) as f64;
        (
            320.0,
            if count == 0.0 {
                104.0
            } else {
                18.0 + count * 62.0
            },
        )
    } else {
        (6.0, 6.0)
    };
    window
        .set_size(tauri::LogicalSize::new(width, height))
        .map_err(|e| error("미니 창 크기 설정 실패", e))?;
    let size = window
        .outer_size()
        .map_err(|e| error("미니 창 크기 확인 실패", e))?;
    let x = work_area.position.x + work_area.size.width as i32 - size.width as i32;
    window
        .set_position(tauri::PhysicalPosition::new(x, work_area.position.y))
        .map_err(|e| error("미니 창 위치 설정 실패", e))
}

#[tauri::command]
fn restore_main_window(app: AppHandle, window: WebviewWindow) -> CommandResult<()> {
    require_window(&window, "mini")?;
    let main = app
        .get_webview_window("main")
        .ok_or_else(|| "메인 창을 찾을 수 없습니다.".to_string())?;
    main.show().map_err(|e| error("메인 창 표시 실패", e))?;
    main.set_focus()
        .map_err(|e| error("메인 창 포커스 실패", e))?;
    window.hide().map_err(|e| error("미니 창 숨기기 실패", e))
}

#[tauri::command]
fn close_main_window(window: WebviewWindow) -> CommandResult<()> {
    require_window(&window, "main")?;
    window.close().map_err(|e| error("앱 창 닫기 실패", e))
}

#[tauri::command]
fn copy_code(
    app: AppHandle,
    window: WebviewWindow,
    state: State<'_, AppState>,
    id: Uuid,
) -> CommandResult<()> {
    if window.label() != "main" && window.label() != "mini" {
        return Err("허용되지 않은 창에서 호출했습니다.".into());
    }
    let code = with_session(&state, |key| {
        let (vault, _) = load_local(&app, key)?;
        let entry = vault
            .entries
            .iter()
            .find(|entry| entry.id == id)
            .ok_or_else(|| "항목을 찾지 못했습니다.".to_string())?;
        totp(entry, now_seconds()?)
    })?;
    let code = Zeroizing::new(code);
    app.clipboard()
        .write_text(code.to_string())
        .map_err(|e| error("클립보드 쓰기 실패", e))?;
    schedule_clipboard_clear(app, code);
    Ok(())
}

#[tauri::command]
fn get_backup_settings(
    app: AppHandle,
    window: WebviewWindow,
    state: State<'_, AppState>,
) -> CommandResult<BackupSettingsView> {
    require_window(&window, "main")?;
    with_session(&state, |key| {
        let (vault, _) = load_local(&app, key)?;
        Ok(BackupSettingsView {
            automatic_file: vault.backup.automatic_file,
            directory: vault.backup.directory.clone(),
            retention: vault.backup.retention,
        })
    })
}

#[tauri::command]
fn get_backup_status(
    app: AppHandle,
    window: WebviewWindow,
    state: State<'_, AppState>,
) -> CommandResult<BackupStatusView> {
    require_window(&window, "main")?;
    with_session(&state, |key| {
        let (vault, _) = load_local(&app, key)?;
        if !vault.backup.automatic_file {
            return Ok(BackupStatusView {
                configured: false,
                healthy: false,
                file_count: 0,
                last_backup_at: None,
                message: "자동 백업이 꺼져 있습니다.".into(),
            });
        }
        let directory = PathBuf::from(&vault.backup.directory);
        if !directory.is_dir() {
            return Ok(BackupStatusView {
                configured: true,
                healthy: false,
                file_count: 0,
                last_backup_at: None,
                message: "백업 폴더를 찾을 수 없습니다.".into(),
            });
        }
        let mut backups = fs::read_dir(&directory)
            .map_err(|e| error("백업 상태 확인 실패", e))?
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| {
                path.file_name()
                    .and_then(|v| v.to_str())
                    .is_some_and(|name| {
                        name.starts_with("secretary-auto-") && name.ends_with(".enc")
                    })
            })
            .collect::<Vec<_>>();
        backups.sort();
        let Some(latest) = backups.last() else {
            return Ok(BackupStatusView {
                configured: true,
                healthy: false,
                file_count: 0,
                last_backup_at: None,
                message: "아직 생성된 자동 백업이 없습니다.".into(),
            });
        };
        let envelope = read_envelope(latest)?;
        decrypt_vault(&envelope, key, "backup")?;
        let last_backup_at = latest
            .metadata()
            .ok()
            .and_then(|metadata| metadata.modified().ok())
            .and_then(|modified| modified.duration_since(UNIX_EPOCH).ok())
            .map(|duration| duration.as_secs());
        Ok(BackupStatusView {
            configured: true,
            healthy: true,
            file_count: backups.len(),
            last_backup_at,
            message: "최근 백업의 무결성을 확인했습니다.".into(),
        })
    })
}

#[tauri::command]
fn choose_backup_directory(app: AppHandle, window: WebviewWindow) -> CommandResult<Option<String>> {
    require_window(&window, "main")?;
    let selected = app.dialog().file().blocking_pick_folder();
    let Some(path) = selected else {
        return Ok(None);
    };
    let path = path
        .into_path()
        .map_err(|_| "선택한 백업 폴더 경로를 사용할 수 없습니다.".to_string())?;
    Ok(Some(path.to_string_lossy().into_owned()))
}

#[tauri::command]
fn save_backup_settings(
    app: AppHandle,
    window: WebviewWindow,
    state: State<'_, AppState>,
    automatic_file: bool,
    directory: String,
    retention: u32,
) -> CommandResult<()> {
    require_window(&window, "main")?;
    if !(1..=100).contains(&retention) {
        return Err("자동 백업 보관 개수는 1~100개여야 합니다.".into());
    }
    let directory = directory.trim().to_string();
    if automatic_file && !Path::new(&directory).is_dir() {
        return Err("유효한 자동 백업 폴더를 선택하세요.".into());
    }
    with_session(&state, |key| {
        let (mut vault, kdf) = load_local(&app, key)?;
        vault.backup.automatic_file = automatic_file;
        vault.backup.directory = directory;
        vault.backup.retention = retention;
        save_local(&app, key, kdf, &vault)
    })
}

#[tauri::command]
fn export_backup(
    app: AppHandle,
    window: WebviewWindow,
    state: State<'_, AppState>,
    password: String,
) -> CommandResult<bool> {
    require_window(&window, "main")?;
    let password = Zeroizing::new(password);
    validate_password(&password)?;
    let envelope = with_session(&state, |key| {
        let (vault, _) = load_local(&app, key)?;
        let kdf = new_kdf_config()?;
        let backup_key = derive_key(password.as_bytes(), &kdf)?;
        encrypt_vault(&vault, &backup_key, kdf, "backup")
    })?;
    let selected = app
        .dialog()
        .file()
        .add_filter("Secretary encrypted backup", &["enc"])
        .set_file_name("secretary-backup.enc")
        .blocking_save_file();
    let Some(path) = selected else {
        return Ok(false);
    };
    let path = path
        .into_path()
        .map_err(|_| "선택한 경로를 사용할 수 없습니다.".to_string())?;
    atomic_write(&path, &envelope)?;
    Ok(true)
}

#[tauri::command]
fn import_backup(
    app: AppHandle,
    window: WebviewWindow,
    state: State<'_, AppState>,
    password: String,
) -> CommandResult<bool> {
    require_window(&window, "main")?;
    let password = Zeroizing::new(password);
    let selected = app
        .dialog()
        .file()
        .add_filter("Secretary encrypted backup", &["enc"])
        .blocking_pick_file();
    let Some(path) = selected else {
        return Ok(false);
    };
    let path = path
        .into_path()
        .map_err(|_| "선택한 경로를 사용할 수 없습니다.".to_string())?;
    let backup = read_envelope(&path)?;
    let backup_key = derive_key(password.as_bytes(), &backup.kdf)?;
    let imported = decrypt_vault(&backup, &backup_key, "backup")?;
    with_session(&state, |current_key| {
        let local = read_envelope(&vault_path(&app)?)?;
        save_local(&app, current_key, local.kdf, &imported)
    })?;
    Ok(true)
}

#[tauri::command]
async fn open_scanner(
    app: AppHandle,
    window: WebviewWindow,
    state: State<'_, AppState>,
) -> CommandResult<()> {
    require_window(&window, "main")?;
    with_session(&state, |_| Ok(()))?;
    if let Some(scanner) = app.get_webview_window("scanner") {
        scanner
            .close()
            .map_err(|e| error("기존 스캐너 닫기 실패", e))?;
    }
    let monitor = window
        .current_monitor()
        .map_err(|e| error("현재 모니터 확인 실패", e))?
        .ok_or_else(|| "현재 모니터를 찾을 수 없습니다.".to_string())?;
    let position = monitor.position();
    let scanner = WebviewWindowBuilder::new(&app, "scanner", WebviewUrl::App("index.html".into()))
        .title("QR 영역 선택")
        .decorations(false)
        .transparent(true)
        .background_color(tauri::utils::config::Color(0, 0, 0, 0))
        .always_on_top(true)
        .skip_taskbar(true)
        .resizable(false)
        .visible(false)
        .build()
        .map_err(|e| error("QR 스캐너 창 생성 실패", e))?;
    scanner
        .set_position(tauri::PhysicalPosition::new(position.x, position.y))
        .map_err(|e| error("QR 스캐너 위치 설정 실패", e))?;
    scanner
        .set_fullscreen(true)
        .map_err(|e| error("QR 스캐너 전체화면 설정 실패", e))?;
    scanner
        .show()
        .map_err(|e| error("QR 스캐너 표시 실패", e))?;
    scanner
        .set_focus()
        .map_err(|e| error("QR 스캐너 포커스 실패", e))?;
    Ok(())
}

#[tauri::command]
fn close_scanner(window: WebviewWindow) -> CommandResult<()> {
    require_window(&window, "scanner")?;
    window.close().map_err(|e| error("QR 스캐너 닫기 실패", e))
}

#[tauri::command]
fn scan_screen_region(
    app: AppHandle,
    window: WebviewWindow,
    state: State<'_, AppState>,
    x: u32,
    y: u32,
    width: u32,
    height: u32,
) -> CommandResult<ImportSummary> {
    require_window(&window, "scanner")?;
    if width < 24 || height < 24 || width > 8192 || height > 8192 {
        return Err("선택 영역 크기가 올바르지 않습니다.".into());
    }
    let tauri_monitor = window
        .current_monitor()
        .map_err(|e| error("현재 모니터 확인 실패", e))?
        .ok_or_else(|| "현재 모니터를 찾을 수 없습니다.".to_string())?;
    let origin = *tauri_monitor.position();
    window.hide().map_err(|e| error("스캐너 숨기기 실패", e))?;
    std::thread::sleep(Duration::from_millis(180));
    let result = (|| {
        let global_x = i64::from(origin.x) + i64::from(x);
        let global_y = i64::from(origin.y) + i64::from(y);
        let monitor = Monitor::from_point(global_x as i32, global_y as i32)
            .map_err(|e| error("캡처 모니터 확인 실패", e))?;
        let mx = monitor.x().map_err(|e| error("모니터 좌표 확인 실패", e))?;
        let my = monitor.y().map_err(|e| error("모니터 좌표 확인 실패", e))?;
        let local_x = global_x - i64::from(mx);
        let local_y = global_y - i64::from(my);
        if local_x < 0 || local_y < 0 {
            return Err("선택 영역이 모니터 밖에 있습니다.".into());
        }
        let image = monitor
            .capture_region(local_x as u32, local_y as u32, width, height)
            .map_err(|e| error("화면 캡처 실패", e))?;
        let gray = image::DynamicImage::ImageRgba8(image).to_luma8();
        let mut prepared = rqrr::PreparedImage::prepare(gray);
        let grids = prepared.detect_grids();
        let (_, content) = grids
            .first()
            .ok_or_else(|| "선택 영역에서 QR 코드를 찾지 못했습니다.".to_string())?
            .decode()
            .map_err(|e| error("QR 디코딩 실패", e))?;
        let content = Zeroizing::new(content);
        let parsed = parse_qr_content(&content)?;
        add_many(&app, &state, parsed)
    })();
    match result {
        Ok(summary) => {
            app.emit_to("main", "vault-changed", summary.clone())
                .map_err(|e| error("화면 갱신 이벤트 실패", e))?;
            window.close().map_err(|e| error("스캐너 닫기 실패", e))?;
            Ok(summary)
        }
        Err(err) => {
            let _ = window.show();
            Err(err)
        }
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.show();
                let _ = window.unminimize();
                let _ = window.set_focus();
            }
            if let Some(mini) = app.get_webview_window("mini") {
                let _ = mini.hide();
            }
        }))
        .plugin(tauri_plugin_process::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .manage(AppState::default())
        .plugin(tauri_plugin_clipboard_manager::init())
        .plugin(tauri_plugin_dialog::init())
        .invoke_handler(tauri::generate_handler![
            vault_status,
            biometric_status,
            enable_biometric,
            unlock_with_biometric,
            disable_biometric,
            generate_password,
            copy_generated_password,
            initialize_vault,
            unlock_vault,
            lock_vault,
            touch_session,
            list_codes,
            list_favorite_codes,
            add_otpauth_uri,
            delete_entry,
            set_entry_favorite,
            reorder_entries,
            update_entry,
            choose_entry_icon,
            minimize_main_window,
            set_mini_revealed,
            restore_main_window,
            close_main_window,
            copy_code,
            get_backup_settings,
            get_backup_status,
            choose_backup_directory,
            save_backup_settings,
            export_backup,
            import_backup,
            open_scanner,
            close_scanner,
            scan_screen_region
        ])
        .run(tauri::generate_context!())
        .expect("fatal Tauri runtime error");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc_6238_sha1_vector() {
        let entry = OtpEntry {
            id: Uuid::nil(),
            issuer: "RFC".into(),
            account: "test".into(),
            secret: BASE32_NOPAD.encode(b"12345678901234567890"),
            algorithm: TotpAlgorithm::Sha1,
            digits: 8,
            period: 30,
            icon: None,
            brand_icon: None,
            favorite: false,
        };
        assert_eq!(totp(&entry, 59).unwrap(), "94287082");
    }

    #[test]
    fn encryption_round_trip_and_tamper_detection() {
        let kdf = new_kdf_config().unwrap();
        let key = derive_key(b"correct horse battery staple", &kdf).unwrap();
        let vault = Vault {
            entries: vec![],
            backup: BackupSettings::default(),
        };
        let mut envelope = encrypt_vault(&vault, &key, kdf, "vault").unwrap();
        assert!(decrypt_vault(&envelope, &key, "vault").is_ok());
        envelope.ciphertext.push('A');
        assert!(decrypt_vault(&envelope, &key, "vault").is_err());
    }

    #[test]
    fn parses_standard_uri() {
        let parsed = parse_otpauth("otpauth://totp/Example:alice%40example.com?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&issuer=Example").unwrap();
        assert_eq!(parsed.issuer, "Example");
        assert_eq!(parsed.account, "alice@example.com");
    }

    #[test]
    fn accepts_legacy_80_bit_secret() {
        let parsed =
            parse_otpauth("otpauth://totp/GitHub:octocat?secret=JBSWY3DPEHPK3PXP&issuer=GitHub")
                .unwrap();
        assert_eq!(parsed.issuer, "GitHub");
        assert_eq!(
            BASE32_NOPAD.decode(parsed.secret.as_bytes()).unwrap().len(),
            10
        );
    }

    #[test]
    fn parses_google_authenticator_migration_qr() {
        let payload = MigrationPayload {
            otp_parameters: vec![MigrationOtpParameters {
                secret: b"12345678901234567890".to_vec(),
                name: "Example:alice@example.com".into(),
                issuer: "Example".into(),
                algorithm: 1,
                digits: 1,
                otp_type: 2,
                counter: 0,
            }],
            version: 1,
            batch_size: 2,
            batch_index: 0,
            batch_id: 42,
        };
        let uri = format!(
            "otpauth-migration://offline?data={}",
            B64.encode(payload.encode_to_vec())
        );
        let parsed = parse_google_migration(&uri).unwrap();
        assert_eq!(parsed.entries.len(), 1);
        assert_eq!(parsed.entries[0].issuer, "Example");
        assert_eq!(parsed.entries[0].account, "alice@example.com");
        assert_eq!(parsed.batch_size, 2);
    }
}
