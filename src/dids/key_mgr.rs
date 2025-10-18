use aes_gcm::aead::OsRng;
use argon2::Argon2;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use directories_next::BaseDirs;
use ed25519_dalek::SigningKey;
use pkcs8::{
    EncryptedPrivateKeyInfo, LineEnding, ObjectIdentifier, PrivateKeyInfo, SecretDocument,
};
use rand::RngCore;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use tracing::{debug, info};

use crate::dids::{self, utils};
use crate::utils::error::TokenError;

const ALGORITHM_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.112");
/// Ed25519 Algorithm Identifier.
const ALGORITHM_ID: pkcs8::AlgorithmIdentifierRef<'static> = pkcs8::AlgorithmIdentifierRef {
    oid: ALGORITHM_OID,
    parameters: None,
};

static SYSTEM_KEYS_INSTANCE: OnceLock<Arc<Mutex<SystemKeys>>> = OnceLock::new();

#[derive(Clone, Debug)]
pub(crate) struct SystemKeys {
    system_key: [u8; 32],
    device_key: [u8; 32],
    file_crypt_key: [u8; 32],
    regenerated: bool,
}
impl SystemKeys {
    fn new() -> Self {
        debug!("Init SystemKeys");
        let mut regenerated = false;

        // 无缓存的key读取或生成
        let mut device_key = Self::get_device_key_from_file(false);
        if device_key == [0u8; 32] {
            println!("{} [SimpBase] Device key is invalid, it will be regenerate for your device, then the system will restore default.", utils::now_string());
            device_key = Self::get_device_key_from_file(true);
            if device_key == [0u8; 32] {
                panic!("Failed to generate valid device key after regeneration");
            }
            regenerated = true;
        }
        println!("Loaded device key");

        let mut system_key = Self::get_system_key_from_file(&device_key, false);
        if system_key == [0u8; 32] {
            println!("{} [SimpBase] System key is invalid, it will be regenerate for your system, then the system will restore default.", utils::now_string());
            system_key = Self::get_system_key_from_file(&device_key, true);
            if system_key == [0u8; 32] {
                panic!("Failed to generate valid system key after regeneration");
            }
            regenerated = true;
        }
        println!("Loaded system key");

        let device_key_hash = utils::calc_sha256(&device_key);
        let local_key_hash = utils::calc_sha256(&system_key);
        let mut com_hash = [0u8; 64];
        com_hash[..32].copy_from_slice(&device_key_hash);
        com_hash[32..].copy_from_slice(&local_key_hash);
        let file_crypt_key = utils::calc_sha256(com_hash.as_ref());

        let (device_name, system_name, guest_name) = dids::get_system_key_name();
        let device_symbol_hash = dids::get_key_symbol_hash("Device");
        let (dev_hash_id, _device_phrase) =
            Self::get_key_hash_id_and_phrase_inner(&device_symbol_hash.to_vec(), 0);
        let system_symbol_hash = dids::get_key_symbol_hash("System");
        let (sys_hash_id, system_phrase) =
            Self::get_key_hash_id_and_phrase_inner(&system_symbol_hash.to_vec(), 0);

        println!("{} [SimpBase] SystemKeys has loaded: system({system_name}, {sys_hash_id}), device({device_name}, {dev_hash_id}).", utils::now_string());
        Self {
            system_key,
            device_key,
            file_crypt_key,
            regenerated,
        }
    }

    pub(crate) fn instance() -> Arc<Mutex<SystemKeys>> {
        SYSTEM_KEYS_INSTANCE
            .get_or_init(|| Arc::new(Mutex::new(Self::new())))
            .clone()
    }

    pub(crate) fn get_file_crypt_key(&self) -> [u8; 32] {
        self.file_crypt_key
    }

    pub(crate) fn get_device_key(&self) -> [u8; 32] {
        self.device_key
    }

    pub(crate) fn get_system_key(&self) -> [u8; 32] {
        self.system_key
    }

    pub(crate) fn was_regenerated(&self) -> bool {
        self.regenerated
    }

    /// 用户密钥读取/生成入口方法
    ///
    /// # Parameters
    /// - `symbol_hash`: Symbol hash for the key
    /// - `phrase`: Phrase for user key generation
    /// - `regen`: Whether to regenerate if read fails
    pub(crate) fn read_user_key_or_generate(
        &self,
        symbol_hash: &[u8; 32],
        phrase: &str,
        regen: bool,
    ) -> [u8; 32] {
        // 获取设备密钥作为依赖
        let device_key = self.get_device_key();
        self.get_user_key_from_file(phrase, symbol_hash, regen)
    }

    fn get_device_key_from_file(regen: bool) -> [u8; 32] {
        let sysinfo = &utils::SYSTEM_BASE_INFO;
        let symbol_hash = dids::get_key_symbol_hash("Device");
        let (device_hash_id, _device_phrase) =
            Self::get_key_hash_id_and_phrase_inner(&symbol_hash.to_vec(), 0);
        let device_key_file =
            Self::get_path_in_sys_key_dir(&format!(".token_device_{}.pem", device_hash_id));
        let device_phrase = format!(
            "{}/{}/{}/{}/{}/{}/{}/{}",
            sysinfo.host_name,
            sysinfo.disk_uuid,
            sysinfo.os_name,
            sysinfo.os_type,
            sysinfo.cpu_brand,
            sysinfo.cpu_cores,
            sysinfo.ram_total + sysinfo.gpu_memory,
            sysinfo.gpu_name
        );

        Self::read_key_or_generate_key_inner(device_key_file.as_path(), &device_phrase, regen)
    }

    fn get_system_key_from_file(device_key: &[u8; 32], regen: bool) -> [u8; 32] {
        let sysinfo = &utils::SYSTEM_BASE_INFO;
        let symbol_hash = dids::get_key_symbol_hash("System");
        let (sys_hash_id, sys_phrase) =
            Self::get_key_hash_id_and_phrase_inner(&symbol_hash.to_vec(), 0);
        let system_key_file =
            Self::get_path_in_sys_key_dir(&format!(".token_system_{}.pem", sys_hash_id));
        let local_phrase = format!(
            "{}@{}:{}/{}/{}/{}/{}/{}/{}",
            sysinfo.root_dir,
            sysinfo.host_name,
            sysinfo.os_name,
            sysinfo.os_type,
            sysinfo.cpu_brand,
            sysinfo.cpu_cores,
            sysinfo.ram_total + sysinfo.gpu_memory,
            sysinfo.gpu_name,
            sysinfo.disk_uuid
        );
        let phrase_text = format!(
            "{}|{}|{}",
            URL_SAFE_NO_PAD.encode(device_key),
            local_phrase,
            sys_phrase
        );

        Self::read_key_or_generate_key_inner(system_key_file.as_path(), &phrase_text, regen)
    }

    fn get_user_key_from_file(
        &self,
        phrase: &str,
        symbol_hash: &[u8; 32],
        regen: bool,
    ) -> [u8; 32] {
        let (user_hash_id, user_phrase) = Self::get_user_key_hash_id_and_phrase(symbol_hash);
        debug!(
            "read_key_or_generate_key: user_symbol_hash={}, user_hash_id={}, user_phrase={}",
            URL_SAFE_NO_PAD.encode(symbol_hash),
            user_hash_id,
            user_phrase
        );

        let user_key_file =
            Self::get_path_in_sys_key_dir(&format!(".token_user_{}.pem", user_hash_id));
        let phrase_text = format!(
            "{}|{}|{}",
            URL_SAFE_NO_PAD.encode(self.get_device_key()),
            phrase,
            user_phrase
        );

        Self::read_key_or_generate_key_inner(user_key_file.as_path(), &phrase_text, regen)
    }

    fn read_key_or_generate_key_inner(file_path: &Path, phrase: &str, regen: bool) -> [u8; 32] {
        let phrase_bytes = utils::hkdf_key_deadline(phrase.as_bytes(), 0);

        // 核心逻辑
        let result = (|| -> Result<[u8; 32], Box<dyn std::error::Error + Send + Sync>> {
            // 文件不存在，直接生成
            if !file_path.exists() {
                return Ok(Self::generate_new_key_and_save_pem(
                    file_path,
                    &phrase_bytes,
                ));
            }

            // 文件存在，尝试读取和解密
            let s_doc = SecretDocument::read_pem_file(file_path)
                .map(|(_, doc)| doc)
                .map_err(|e| format!("Failed to read PEM file: {}", e))?;

            let decrypted_bytes = EncryptedPrivateKeyInfo::try_from(s_doc.as_bytes())
                .map_err(|e| format!("Failed to parse encrypted key: {}", e))?
                .decrypt(&phrase_bytes)
                .map_err(|e| format!("Failed to decrypt key: {}", e))?;

            let key_info = PrivateKeyInfo::try_from(decrypted_bytes.as_bytes())
                .map_err(|e| format!("Failed to parse private key: {}", e))?;

            let mut pkey: [u8; 32] = [0; 32];
            if key_info.private_key.len() >= 32 {
                pkey.copy_from_slice(&key_info.private_key[..32]);
            } else {
                let mut temp = [0u8; 32];
                let len = std::cmp::min(key_info.private_key.len(), 32);
                temp[..len].copy_from_slice(&key_info.private_key[..len]);
                pkey = temp;
            }

            Ok(pkey)
        })();

        // 错误处理
        match result {
            Ok(key) => key,
            Err(e) => {
                eprintln!(
                    "[read_key_or_generate_key] Error reading key file {}: {}",
                    file_path.display(),
                    e
                );
                if regen {
                    Self::generate_new_key_and_save_pem(file_path, &phrase_bytes)
                } else {
                    println!(
                        "[{}] [SimpBase] Read key error and return 0 key: {}",
                        utils::now_string(),
                        file_path.display()
                    );
                    [0; 32] // 返回零密钥
                }
            }
        }
    }

    fn generate_new_key_and_save_pem(file_path: &Path, phrase: &[u8]) -> [u8; 32] {
        // 创建父目录
        if let Some(parent_dir) = file_path.parent() {
            if !parent_dir.exists() {
                match fs::create_dir_all(parent_dir) {
                    Ok(_) => {}
                    Err(e) => {
                        eprintln!(
                            "Error generating key for {}: Failed to create directory: {}",
                            file_path.display(),
                            e
                        );
                        return [0; 32]; // 返回零密钥作为 fallback
                    }
                }
            }
        }

        println!(
            "{} [SimpBase] generate new key and save: {}",
            utils::now_string(),
            file_path.file_name().unwrap_or_default().to_string_lossy()
        );

        let secret_key = match Self::generate_key_by_file_type(file_path) {
            Ok(key) => key,
            Err(e) => {
                eprintln!(
                    "Error generating key for {}: Failed to generate key: {}",
                    file_path.display(),
                    e
                );
                return [0; 32]; // 返回零密钥作为 fallback
            }
        };

        // 加密并保存到 PEM 文件
        let pem_label = "SIMPLE_AI_KEY";
        let mut csprng = OsRng {};

        let encrypted_key =
            match PrivateKeyInfo::new(ALGORITHM_ID, &secret_key).encrypt(&mut csprng, phrase) {
                Ok(key) => key,
                Err(e) => {
                    eprintln!(
                        "Error generating key for {}: Failed to encrypt key: {}",
                        file_path.display(),
                        e
                    );
                    return [0; 32]; // 返回零密钥作为 fallback
                }
            };

        match encrypted_key.write_pem_file(file_path, pem_label, LineEnding::default()) {
            Ok(_) => {}
            Err(e) => {
                eprintln!(
                    "Error generating key for {}: Failed to write PEM file: {}",
                    file_path.display(),
                    e
                );
                return [0; 32]; // 返回零密钥作为 fallback
            }
        };

        secret_key
    }

    fn generate_key_by_file_type(file_path: &Path) -> Result<[u8; 32], Box<dyn std::error::Error>> {
        let file_name = file_path
            .file_name()
            .ok_or("Invalid file path")?
            .to_string_lossy();

        let secret_key = if file_name.contains("device") {
            Self::generate_device_key()
        } else if file_name.contains("system") {
            Self::generate_system_key()
        } else {
            Self::generate_random_key()
        };

        Ok(secret_key)
    }

    fn generate_device_key() -> [u8; 32] {
        let sysinfo = &utils::SYSTEM_BASE_INFO;

        let seed_data1 = utils::calc_sha256(
            format!("{}{}", sysinfo.disk_uuid, sysinfo.os_time).as_bytes(),
        );
        let seed_data2 = utils::calc_sha256(
            format!("{}{}", sysinfo.host_name, sysinfo.os_time).as_bytes(),
        );

        let seed = Self::derive_key(&seed_data1, &seed_data2).unwrap_or([0u8; 32]);

        SigningKey::from_bytes(&seed).to_bytes()
    }

    fn generate_system_key() -> [u8; 32] {
        let sysinfo = &utils::SYSTEM_BASE_INFO;

        let seed_data1 = utils::calc_sha256(
            format!("{}{}", sysinfo.root_dir, sysinfo.root_time).as_bytes(),
        );
        let seed_data2 = utils::calc_sha256(
            format!("{}{}", sysinfo.exe_name, sysinfo.root_time).as_bytes(),
        );

        let seed = Self::derive_key(&seed_data1, &seed_data2).unwrap_or([0u8; 32]);

        SigningKey::from_bytes(&seed).to_bytes()
    }

    fn generate_random_key() -> [u8; 32] {
        let mut csprng = OsRng {};
        let mut secret_bytes = [0u8; 32];
        csprng.fill_bytes(&mut secret_bytes);

        SigningKey::from_bytes(&secret_bytes).to_bytes()
    }

    fn get_key_hash_id_and_phrase_inner(symbol_hash: &Vec<u8>, period: u64) -> (String, String) {
        let key_file_hash_id = utils::sha256_prefix(symbol_hash, 10);
        let phrase_text =
            utils::sha256_prefix(&utils::hkdf_key_deadline(symbol_hash, period), 10);
        (key_file_hash_id, phrase_text)
    }

    fn get_user_key_hash_id_and_phrase(symbol_hash: &[u8; 32]) -> (String, String) {
        let device_symbol_hash: [u8; 32] = dids::get_key_symbol_hash("Device");
        let (device_hash_id, _device_phrase) =
            Self::get_key_hash_id_and_phrase_inner(&device_symbol_hash.to_vec(), 0);
        let mut com_symbol = Vec::new();
        com_symbol.extend_from_slice(symbol_hash);
        com_symbol.extend_from_slice(device_hash_id.as_bytes());
        Self::get_key_hash_id_and_phrase_inner(&com_symbol, 0)
    }

    pub(crate) fn derive_key(password: &[u8], salt: &[u8]) -> Result<[u8; 32], TokenError> {
        let mut key = [0u8; 32];
        Argon2::default().hash_password_into(password, salt, &mut key)?;
        Ok(key)
    }

    pub(crate) fn is_original_user_key(key_type: &str, symbol_hash: &[u8; 32]) -> bool {
        let (hash_id, phrase) = Self::get_key_hash_id_and_phrase(key_type, symbol_hash);
        debug!("the key testing : {}", hash_id);
        let key = Self::read_key_or_generate_key(key_type, symbol_hash, &phrase, false);
        key != [0u8; 32]
    }

    pub(crate) fn exists_and_valid_user_key(symbol_hash: &[u8; 32], phrase: &str) -> bool {
        let key_type = "User";
        let (key_hash_id, _phrase) = Self::get_key_hash_id_and_phrase(key_type, symbol_hash);
        let key_file = Self::get_path_in_sys_key_dir(&format!(
            ".token_{}_{}.pem",
            key_type.to_lowercase(),
            key_hash_id
        ));
        if key_file.exists() {
            let keys = SystemKeys::instance();
            let mut keys = keys.lock().unwrap();
            let key = keys.read_user_key_or_generate(symbol_hash, &phrase, false);
            debug!(
                "user_key exists: {}, valid: {}",
                key_file.display(),
                key != [0u8; 32]
            );
            key != [0u8; 32]
        } else {
            debug!("user_key do not exists: {}", key_file.display());
            false
        }
    }

    pub(crate) fn exists_key_file(key_type: &str, symbol_hash: &[u8; 32]) -> bool {
        let (key_hash_id, _phrase) = Self::get_key_hash_id_and_phrase(key_type, symbol_hash);
        let key_file = Self::get_path_in_sys_key_dir(&format!(
            ".token_{}_{}.pem",
            key_type.to_lowercase(),
            key_hash_id
        ));
        key_file.exists()
    }

    pub(crate) fn save_key_to_pem(
        symbol_hash: &[u8; 32],
        key: &[u8; 32],
        phrase: &str,
    ) -> [u8; 32] {
        let (user_hash_id, user_phrase) = Self::get_key_hash_id_and_phrase("User", symbol_hash);
        let user_key_file =
            Self::get_path_in_sys_key_dir(&format!(".token_user_{}.pem", user_hash_id));
        if let Some(parent_dir) = user_key_file.parent() {
            if !parent_dir.exists() {
                fs::create_dir_all(parent_dir).unwrap();
            }
        }
        let id_hash = [0u8; 32];
        let device_key = get_device_key();
        let phrase_text = format!(
            "{}|{}|{}",
            URL_SAFE_NO_PAD.encode(device_key.as_slice()),
            phrase,
            user_phrase
        );
        let phrase_bytes = utils::hkdf_key_deadline(&phrase_text.as_bytes(), 0);

        let pem_label = "SIMPLE_AI_KEY";
        let csprng = OsRng {};
        let secret_key = SigningKey::from_bytes(key).to_bytes();

        let encrypted_key_info = PrivateKeyInfo::new(ALGORITHM_ID, &secret_key)
            .encrypt(csprng, &phrase_bytes)
            .unwrap();
        let pem_content = encrypted_key_info
            .to_pem(pem_label, LineEnding::default())
            .unwrap();
        let mut file = fs::File::create(&user_key_file).unwrap();
        file.write_all(pem_content.as_bytes()).unwrap();
        file.sync_all().unwrap();
        debug!("save key to local pem file: {}", user_key_file.display());

        secret_key
    }

    pub(crate) fn change_phrase_for_pem_and_identity_files(
        symbol_hash: &[u8; 32],
        old_phrase: &str,
        new_phrase: &str,
    ) {
        let (user_hash_id, user_phrase) = Self::get_key_hash_id_and_phrase("User", symbol_hash);
        let user_key_file =
            Self::get_path_in_sys_key_dir(&format!(".token_user_{}.pem", user_hash_id));
        let id_hash = [0u8; 32];
        let device_key = get_device_key();
        let old_phrase_text = format!(
            "{}|{}|{}",
            URL_SAFE_NO_PAD.encode(device_key.as_slice()),
            old_phrase,
            user_phrase
        );
        let new_phrase_text = format!(
            "{}|{}|{}",
            URL_SAFE_NO_PAD.encode(device_key.as_slice()),
            new_phrase,
            user_phrase
        );

        let old_phrase_bytes = utils::hkdf_key_deadline(&old_phrase_text.as_bytes(), 0);
        let new_phrase_bytes = utils::hkdf_key_deadline(&new_phrase_text.as_bytes(), 0);
        if user_key_file.exists() {
            let Ok((_, s_doc)) = SecretDocument::read_pem_file(user_key_file.clone()) else {
                todo!()
            };
            let priv_key = match EncryptedPrivateKeyInfo::try_from(s_doc.as_bytes())
                .unwrap()
                .decrypt(&old_phrase_bytes)
            {
                Ok(key) => {
                    let mut pkey: [u8; 32] = [0; 32];
                    pkey.copy_from_slice(
                        PrivateKeyInfo::try_from(key.as_bytes())
                            .unwrap()
                            .private_key,
                    );
                    pkey
                }
                Err(_e) => {
                    println!(
                        "{} [SimpBase] Read key file error: {}",
                        utils::now_string(),
                        _e
                    );
                    let pkey: [u8; 32] = [0; 32];
                    pkey
                }
            };
            let pem_label = "SIMPLE_AI_KEY";
            let csprng = OsRng {};
            PrivateKeyInfo::new(ALGORITHM_ID, &priv_key)
                .encrypt(csprng, &new_phrase_bytes)
                .unwrap()
                .write_pem_file(user_key_file.clone(), pem_label, LineEnding::default())
                .unwrap();
            println!(
                "{} [SimpBase] Change phrase for user_key_file: {}",
                utils::now_string(),
                user_key_file.display()
            );
        }
        let identity_file =
            Self::get_path_in_sys_key_dir(&format!("user_identity_{}.token", user_hash_id));
        if identity_file.exists() {
            let encrypted_identity_base64 =
                fs::read_to_string(identity_file.clone()).unwrap_or("Unknown".to_string());
            let encrypted_identity = URL_SAFE_NO_PAD
                .decode(encrypted_identity_base64.clone())
                .unwrap_or("Unknown".as_bytes().to_vec());
            debug!(
                "import, encrypted_identity: len={}, {}",
                encrypted_identity.len(),
                encrypted_identity_base64
            );
            let vcode = &encrypted_identity[..2];
            let identity = &encrypted_identity[2..];
            if *vcode == utils::calc_sha256(identity)[..2] {
                let telephone_bytes = &encrypted_identity[2..10];
                let telephone = u64::from_le_bytes(telephone_bytes.try_into().unwrap()).to_string();
                let nickname_bytes = &encrypted_identity[78..];
                let nickname = std::str::from_utf8(nickname_bytes).unwrap();
                let encrypted_secret = &encrypted_identity[10..78];
                debug!(
                    "import, identity: nickname: {}, telephone: {}, len={}, {}",
                    nickname,
                    telephone,
                    identity.len(),
                    URL_SAFE_NO_PAD.encode(identity)
                );
                let secret_key = Self::derive_key(old_phrase.as_bytes(), symbol_hash).unwrap();
                let identity_secret = utils::decrypt(encrypted_secret, &secret_key, 0);
                debug!(
                    "import, identity_secret: symbol={}, phrase={}, secret_key={}, len={}, {}",
                    URL_SAFE_NO_PAD.encode(symbol_hash),
                    old_phrase,
                    URL_SAFE_NO_PAD.encode(secret_key),
                    encrypted_secret.len(),
                    URL_SAFE_NO_PAD.encode(encrypted_secret)
                );
                let timestamp_bytes = &identity_secret[..8];
                let mut user_key = [0u8; 32];
                user_key.copy_from_slice(&identity_secret[8..]);

                let secret_key = Self::derive_key(new_phrase.as_bytes(), symbol_hash).unwrap();
                let mut identity_secret =
                    Vec::with_capacity(timestamp_bytes.len() + user_key.len());
                identity_secret.extend_from_slice(&timestamp_bytes);
                identity_secret.extend_from_slice(&user_key);
                let encrypted_secret = utils::encrypt(&identity_secret, &secret_key, 0);
                debug!(
                    "export, identity_secret: symbol={}, phrase={}, secret_key={}, len={}, {}",
                    URL_SAFE_NO_PAD.encode(symbol_hash),
                    new_phrase,
                    URL_SAFE_NO_PAD.encode(secret_key),
                    encrypted_secret.len(),
                    URL_SAFE_NO_PAD.encode(encrypted_secret.clone())
                );
                let length = telephone_bytes.len() + encrypted_secret.len() + nickname_bytes.len();
                let mut identity = Vec::with_capacity(length);
                identity.extend_from_slice(&telephone_bytes);
                identity.extend_from_slice(&encrypted_secret);
                identity.extend_from_slice(nickname_bytes);
                debug!(
                    "export, identity: nickname={}, telephone={}, len={}, {}",
                    nickname,
                    telephone,
                    identity.len(),
                    URL_SAFE_NO_PAD.encode(identity.clone())
                );
                let vcode = &utils::calc_sha256(&identity)[..2];
                let mut encrypted_identity = Vec::with_capacity(vcode.len() + identity.len());
                encrypted_identity.extend_from_slice(&vcode);
                encrypted_identity.extend_from_slice(&identity);
                let encrypted_identity_base64 = URL_SAFE_NO_PAD.encode(encrypted_identity.clone());
                debug!(
                    "export, encrypted_identity: len={}, {}",
                    encrypted_identity.len(),
                    encrypted_identity_base64
                );
                fs::write(identity_file.clone(), encrypted_identity_base64).expect(&format!(
                    "Unable to write file: {}",
                    identity_file.display()
                ));
                println!(
                    "{} [SimpBase] Change phrase for identity_file: {}",
                    utils::now_string(),
                    identity_file.display()
                );
            } else {
                println!("{} [SimpBase] Change phrase for identity_file, parsing encrypted_identity error: {}", utils::now_string(), identity_file.display());
            }
        }
    }

    pub(crate) fn get_path_in_sys_key_dir(filename: &str) -> PathBuf {
        let sysinfo = &utils::SYSTEM_BASE_INFO;
        let home_dirs = match BaseDirs::new() {
            Some(dirs) => dirs.home_dir().to_path_buf(),
            None => PathBuf::from(sysinfo.root_dir.clone()),
        };
        home_dirs
            .join(".simpleai.vip")
            .join(".token")
            .join(filename)
    }

    // 保留原来的全局函数作为兼容性接口
    pub(crate) fn read_key_or_generate_key(
        key_type: &str,
        symbol_hash: &[u8; 32],
        phrase: &str,
        regen: bool,
    ) -> [u8; 32] {
        let instance = SystemKeys::instance();
        let keys_guard = instance.lock().unwrap();
        // 匹配key_type调用不同的方法
        match key_type {
            "Device" => keys_guard.get_device_key(),
            "System" => keys_guard.get_system_key(),
            "User" => keys_guard.read_user_key_or_generate(symbol_hash, phrase, regen),
            _ => {
                eprintln!("Error: Invalid key_type: {}", key_type);
                [0; 32]
            }
        }
    }

    pub(crate) fn get_key_hash_id_and_phrase(
        key_type: &str,
        symbol_hash: &[u8; 32],
    ) -> (String, String) {
        // 匹配key_type调用不同的方法
        match key_type {
            "Device" => {
                let device_symbol_hash: [u8; 32] = dids::get_key_symbol_hash("Device");
                SystemKeys::get_key_hash_id_and_phrase_inner(&device_symbol_hash.to_vec(), 0)
            }
            "System" => {
                let system_symbol_hash: [u8; 32] = dids::get_key_symbol_hash("System");
                SystemKeys::get_key_hash_id_and_phrase_inner(&system_symbol_hash.to_vec(), 0)
            }
            "User" => SystemKeys::get_user_key_hash_id_and_phrase(symbol_hash),
            _ => {
                eprintln!("Error: Invalid key_type: {}", key_type);
                ("".to_string(), "".to_string())
            }
        }
    }
}

pub(crate) fn get_token_crypt_key() -> [u8; 32] {
    let keys = SystemKeys::instance();
    let mut keys = keys.lock().unwrap();
    keys.get_file_crypt_key()
}

pub(crate) fn get_device_key() -> [u8; 32] {
    let keys = SystemKeys::instance();
    let mut keys = keys.lock().unwrap();
    keys.get_device_key()
}

pub(crate) fn get_system_key() -> [u8; 32] {
    let keys = SystemKeys::instance();
    let mut keys = keys.lock().unwrap();
    keys.get_system_key()
}

pub(crate) fn get_user_key(symbol_hash: &[u8; 32], phrase: &str) -> [u8; 32] {
    let keys = SystemKeys::instance();
    let mut keys = keys.lock().unwrap();
    keys.read_user_key_or_generate(symbol_hash, phrase, false)
}
