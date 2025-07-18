use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::fs;
use std::sync::{Arc, Mutex, RwLock};
use std::io::Write;
use std::time::{Duration, SystemTime};
use serde_json::{json, Value};
use directories_next::BaseDirs;

use pkcs8::{EncryptedPrivateKeyInfo, PrivateKeyInfo, LineEnding, ObjectIdentifier, SecretDocument};

use ed25519_dalek::{VerifyingKey, SigningKey, Signer, Signature, Verifier};
use tracing_subscriber::field::debug;
use x25519_dalek::{StaticSecret, PublicKey};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use base58::{ToBase58, FromBase58};
use sha2::{Sha256, Digest, Sha512};
use hkdf::Hkdf;
use rand::RngCore;
use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Key };
use argon2::Argon2;
use chrono::{Local, Timelike};

use tracing::{debug, info};
use lazy_static::lazy_static;
use once_cell::sync::Lazy;
use tokio::runtime::Runtime;
use tracing_subscriber::fmt::format;

use crate::utils::systeminfo::SystemBaseInfo;
use crate::utils::error::TokenError;
use crate::dids::claims::{LocalClaims, IdClaim, UserContext};
use crate::dids::claims;
use crate::dids;
use crate::issue_key;
use crate::exchange_key;

const ALGORITHM_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.112");

/// Ed25519 Algorithm Identifier.
const ALGORITHM_ID: pkcs8::AlgorithmIdentifierRef<'static> = pkcs8::AlgorithmIdentifierRef {
    oid: ALGORITHM_OID,
    parameters: None,
};

lazy_static! {
    pub static ref SYSTEM_BASE_INFO: SystemBaseInfo = SystemBaseInfo::generate();
    static ref SYSTEM_KEYS: Arc<Mutex<SystemKeys>> = Arc::new(Mutex::new(SystemKeys::new()));
}


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
        let id_hash = [0u8; 32];
        let device_key = match exists_key_file("Device", &id_hash) {
            true => {
                let mut device_key = read_key_or_generate_key("Device", &id_hash, "None", false, true);
                if device_key == [0u8; 32] {
                    println!("{} [SimpBase] Device key is invalid, it will be regenerate for your device, then the system will restore default.", now_string());
                    device_key = read_key_or_generate_key("Device", &id_hash, "None", true, true);
                    regenerated = true;
                }
                device_key
            } 
            false => {
                read_key_or_generate_key("Device", &id_hash, "None", true, true)
            }
        };
        debug!("Loaded device key");
        let mut system_key = match exists_key_file("System", &id_hash) {
            true => {
                let mut system_key = read_key_or_generate_key("System", &id_hash, "None", false, true);
                if system_key == [0u8; 32] {
                    println!("{} [SimpBase] System key is invalid, it will be regenerate for your system, then the system will restore default.", now_string());
                    system_key = read_key_or_generate_key("System", &id_hash, "None", true, true);
                    regenerated = true;
                }
                system_key
            } 
            false => {
                read_key_or_generate_key("System", &id_hash, "None", true, true)
            }
        };
        debug!("Loaded system key");
        
        let device_key_hash = calc_sha256(&device_key);
        let local_key_hash = calc_sha256(&system_key);
        let mut com_hash = [0u8; 64];
        com_hash[..32].copy_from_slice(&device_key_hash);
        com_hash[32..].copy_from_slice(&local_key_hash);
        let file_crypt_key = calc_sha256(com_hash.as_ref());

        let (device_name, system_name, guest_name) = dids::get_system_key_name();
        let (dev_hash_id, device_phrase) = get_key_hash_id_and_phrase("Device", &id_hash);
        let (sys_hash_id, system_phrase) = get_key_hash_id_and_phrase("System", &id_hash);
        
        println!("{} [SimpBase] SystemKeys has loaded: system({system_name}, {sys_hash_id}), device({device_name}, {dev_hash_id}).", now_string());
        Self {
            system_key,
            device_key,
            file_crypt_key,
            regenerated,
        }
    }
    pub fn instance() -> Arc<Mutex<SystemKeys>> {
        SYSTEM_KEYS.clone()
    }

    pub fn get_file_crypt_key(&self) -> [u8; 32] {
        self.file_crypt_key
    }
    pub fn get_device_key(&self) -> [u8; 32] {
        self.device_key
    }
    pub fn get_system_key(&self) -> [u8; 32] {
        self.system_key
    }
    pub fn was_regenerated(&self) -> bool {
        self.regenerated
    }
}


pub(crate) fn init_user_crypt_secret(crypt_secrets: &mut HashMap<String, String>, claim: &IdClaim, phrase: &str) {
    let did = claim.gen_did();
    if !crypt_secrets.contains_key(&exchange_key!(did)) {
        let crypt_secret = get_specific_secret_key(
            "exchange",claim.id_type.as_str(), &claim.get_symbol_hash(), &phrase);
        if crypt_secret == [0u8; 32] {
            println!("{} [SimpBase] exchange key generate fail!", now_string());
        }
        crypt_secrets.insert(exchange_key!(did), URL_SAFE_NO_PAD.encode(crypt_secret));
        }
    if !crypt_secrets.contains_key(&issue_key!(did)) {
        let crypt_secret = get_specific_secret_key(
            "issue",claim.id_type.as_str(), &claim.get_symbol_hash(), &phrase);
        if crypt_secret == [0u8; 32] {
            println!("{} [SimpBase] issue key generate fail!", now_string());
        }
        crypt_secrets.insert(issue_key!(did), URL_SAFE_NO_PAD.encode(crypt_secret));
        }
}



pub(crate) fn load_token_of_user_certificates(sys_did: &str, certificates: &mut HashMap<String, String>) {
    let token_file = get_path_in_sys_key_dir(&format!("user_certs_{}.token", sys_did));
    let crypt_key = get_token_crypt_key();
    let token_raw_data = match token_file.exists() {
        true => {
            match fs::read(token_file) {
                Ok(data) => data,
                Err(e) => {
                    println!("{} [SimpBase] read user_certificates file error: {}", now_string(), e);
                    return
                },
            }
        }
        false => return
    };

    let token_data = decrypt(&token_raw_data, &crypt_key, 0);
    let system_token: Value = serde_json::from_slice(&token_data).unwrap_or(serde_json::json!({}));

    debug!("Load user_certs token from file: {}", system_token);
    let claims = claims::GlobalClaims::instance();
    if let Some(Value::Object(user_certs)) = system_token.get("user_certs") {
        for (key, value) in user_certs {
            let parts_key: Vec<&str> = key.split('|').collect();
            let did = parts_key[0];
            if let Value::String(secrets_str) = value {
                let parts: Vec<&str> = secrets_str.split('|').collect();
                if parts.len() >= 4 {
                    let secret_base64 = parts[0];
                    let memo_base64 = parts[1];
                    let timestamp = parts[2];
                    let sig_base64 = parts[3];
                    let text = format!("{}|{}|{}|{}", key, secret_base64, memo_base64, timestamp);
                    let claim = {
                        let mut claims_guard = claims.lock().unwrap();
                        claims_guard.get_claim_from_local(did)
                    };
                    if verify_signature(&text, sig_base64, &claim.get_cert_verify_key()) {
                        certificates.insert(key.clone(), secrets_str.to_string());
                        debug!("Valid signature for user certificate at loading: did={}, key={}", claim.gen_did(), key);
                    } else {
                        debug!("Invalid signature for user certificate at loading: did={}, cert_verify_key={}, key={}, text={}, sig={}", claim.gen_did(), URL_SAFE_NO_PAD.encode(claim.get_cert_verify_key()), key, text, sig_base64, );
                    }
                }
            }
        }
    }
}

pub(crate) fn save_user_certificates_to_file(sys_did: &str, certificates: &HashMap<String, String>) {
    let mut json_system_token = json!({});
    json_system_token["user_certs"] = json!(certificates);
    let json_string = serde_json::to_string(&json_system_token).unwrap_or(String::from("{}"));

    let system_token_file = get_path_in_sys_key_dir(&format!("user_certs_{}.token", sys_did));
    let crypt_key = get_token_crypt_key();
    let token_raw_data = encrypt(json_string.as_bytes(), &crypt_key, 0);
    debug!("Save user_certificates to file: {}", json_string);

    fs::write(system_token_file.clone(), token_raw_data).expect(&format!("Unable to write file: {}", system_token_file.display()))
}

pub(crate) fn get_slim_user_cert(cert_text: &str) -> Vec<u8> {
    let parts: Vec<&str> = cert_text.split('|').collect();
    if parts.len() >= 4 {
        let secret = URL_SAFE_NO_PAD.decode(parts[0]).unwrap_or(Vec::new());   // 60 bytes
        let timestamp = parts[2].parse().unwrap_or(0u64); // 8bytes
        let sig = URL_SAFE_NO_PAD.decode(parts[3]).unwrap_or(Vec::new());  // 64bytes
        debug!("get_slim_user_cert: {}, {}, {}\ncert_text: {}", secret.len(), timestamp, sig.len(), cert_text);
        if secret.len() > 0 && sig.len() > 0 && timestamp != 0 {
            let mut cert_bytes = Vec::with_capacity(secret.len()+sig.len()+8);  // 132 bytes
            cert_bytes.extend_from_slice(&secret);
            cert_bytes.extend_from_slice(&timestamp.to_le_bytes());
            cert_bytes.extend_from_slice(&sig);
            return cert_bytes
        }
    }
    return Vec::new()
}

pub(crate) fn convert_to_short_user_cert_from_slim(cert_bytes: &[u8]) -> String {
    if cert_bytes.len() == 132 {
        let secret = URL_SAFE_NO_PAD.encode(cert_bytes[0..60].to_vec());
        let timestamp = u64::from_le_bytes(cert_bytes[60..68].try_into().unwrap_or(0u64.to_le_bytes()));
        let sig = URL_SAFE_NO_PAD.encode(cert_bytes[68..132].to_vec());
        let memo_base64 = URL_SAFE_NO_PAD.encode("User".as_bytes());
        return format!("{}|{}|{}|{}", secret, memo_base64, timestamp, sig)
    }
    return "Unknown".to_string()
}

pub(crate) fn load_token_of_issued_certs(sys_did: &str, issued_certs: &mut HashMap<String, String>) {
    let token_file = get_path_in_sys_key_dir(&format!("issued_certs_{}.token", sys_did));
    let crypt_key = get_token_crypt_key();
    let token_raw_data = match token_file.exists() {
        true => {
            match fs::read(token_file) {
                Ok(data) => data,
                Err(e) => {
                    println!("{} [SimpBase] read user issued certificates file error: {}", now_string(), e);
                    return
                },
            }
        }
        false => return
    };
    let token_data = decrypt(&token_raw_data, &crypt_key, 0);
    let system_token: Value = serde_json::from_slice(&token_data).unwrap_or(serde_json::json!({}));
    debug!("Load issued_certs token from file: {}", system_token);

    let claims = claims::GlobalClaims::instance();
    if let Some(Value::Object(user_certs)) = system_token.get("user_certs") {
        for (key, value) in user_certs {
            let parts_key: Vec<&str> = key.split('|').collect();
            let did = parts_key[0];
            if let Value::String(secrets_str) = value {
                let parts: Vec<&str> = secrets_str.split('|').collect();
                if parts.len() >= 4 {
                    let secret_base64 = parts[0];
                    let memo_base64 = parts[1];
                    let timestamp = parts[2];
                    let sig_base64 = parts[3];
                    let text = format!("{}|{}|{}|{}", key, secret_base64, memo_base64, timestamp);
                    let claim = {
                        let mut claims_guard = claims.lock().unwrap();
                        claims_guard.get_claim_from_local(did)
                    };
                    if verify_signature(&text, sig_base64, &claim.get_cert_verify_key()) {
                        issued_certs.insert(key.clone(), secrets_str.to_string());
                        debug!("Valid signature for issuer certificate at loading: {}, {}, {}", text, sig_base64, claim.gen_did());
                    } else {
                        debug!("Invalid signature for issuer certificate at loading: {}, {}, {}", text, sig_base64, claim.gen_did());
                    }
                }
            }
        }
    }
}

pub(crate) fn save_issued_certs_to_file(sys_did: &str, issued_certs: &HashMap<String, String>) {
    let mut json_system_token = json!({});
    json_system_token["issued_certs"] = json!(issued_certs);
    let json_string = serde_json::to_string(&json_system_token).unwrap_or(String::from("{}"));

    let system_token_file = get_path_in_sys_key_dir(&format!("issued_certs_{}.token", sys_did));
    let crypt_key = get_token_crypt_key();
    let token_raw_data = encrypt(json_string.as_bytes(), &crypt_key, 0);
    debug!("Save issued_certificates to file: {}", json_string);
    fs::write(system_token_file.clone(), token_raw_data).expect(&format!("Unable to write file: {}", system_token_file.display()))
}


pub(crate) fn load_token_by_authorized2system(sys_did: &str, crypt_secrets: &mut HashMap<String, String>)
                                              -> String {
    let token_file = get_path_in_sys_key_dir(&format!("authorized2system_{}.token", sys_did));
    let crypt_key = get_token_crypt_key();
    let admin_did = match token_file.exists() {
        true => {
            let token_raw_data = match fs::read(token_file) {
                Ok(data) => data,
                Err(e) => {
                    println!("{} [SimpBase] read authorized2system file error: {}", now_string(), e);
                    return String::from("");
                },
            };
            let token_data = decrypt(&token_raw_data, &crypt_key, 0);
            let system_token: Value = serde_json::from_slice(&token_data).unwrap_or(serde_json::json!({}));

            debug!("Load authorized2system token from file: {}", system_token);

            let admin = match system_token.get("admin_did") {
                Some(Value::String(admin)) => admin.clone(),
                _ => String::from(""),
            };

            if let Some(Value::Object(hellman_secrets)) = system_token.get("specific_secrets") {
                for (key, value) in hellman_secrets {
                    if let Value::String(secrets_str) = value {
                        crypt_secrets.insert(key.clone(), secrets_str.to_string());
                    }
                }
            }
            admin
        }
        false => String::from(""),
    };
    admin_did
}

pub(crate) fn save_secret_to_system_token_file(crypt_secrets: &HashMap<String, String>, sys_did: &str, admin: &str) {
    let mut json_system_token = json!({});
    json_system_token["admin_did"] = json!(admin);
    json_system_token["specific_secrets"] = json!(crypt_secrets);
    let json_string = serde_json::to_string(&json_system_token).unwrap_or(String::from("{}"));

    let system_token_file = get_path_in_sys_key_dir(&format!("authorized2system_{}.token", sys_did));
    let crypt_key = get_token_crypt_key();
    let token_raw_data = encrypt(json_string.as_bytes(), &crypt_key, 0);
    debug!("Save secret token to file: {}", json_string);

    fs::write(system_token_file.clone(), token_raw_data).expect(&format!("Unable to write file: {}", system_token_file.display()))
}

pub(crate) fn load_did_blacklist_from_file() -> Vec<String>  {
    let blacklist_file = get_path_in_sys_key_dir(&format!("user_blacklist.txt"));
    match blacklist_file.exists() {
        true => {
            let file_content = match fs::read_to_string(blacklist_file) {
                Ok(content) => content,
                Err(_) => return vec![],
            };
            match serde_json::from_str(&file_content) {
                Ok(blacklist) => blacklist,
                Err(_) => vec![],
            }
        },
        false => vec![]
    }
}

pub(crate) fn get_or_create_user_context_token(did: &str, sys_did: &str, nickname: &str, id_type: &str, symbol_hash: &[u8; 32], phrase: &str) -> UserContext {
    let context = get_user_token_from_file(did, sys_did);
    if context.is_default() {
        debug!("[SimpBase] Create user context token: {}", did);
        let default_permissions = "standard".to_string();
        let default_private_paths = serde_json::to_string(
            &vec!["config", "presets", "wildcards", "styles", "workflows"]).unwrap_or("".to_string());
        let mut context_default = UserContext::new(did, sys_did, nickname, &default_permissions, &default_private_paths);
        let secret_key = get_random_secret_key(id_type, symbol_hash, phrase);
        let default_expire = 0; //90*24*3600;
        context_default.set_auth_sk_with_secret(&URL_SAFE_NO_PAD.encode(secret_key), default_expire);
        let crypt_key = get_specific_secret_key("context", id_type, symbol_hash, phrase);
        let aes_key_encrypted = URL_SAFE_NO_PAD.encode(encrypt(&context_default.get_crypt_key(), &crypt_key, 0));
        context_default.set_aes_key_encrypted(&aes_key_encrypted);
        context_default
    } else {
        context
    }
    /*
            println!("[SimpBase] Renew user context token: {}", did);
            let mut context_renew = get_user_token_from_file(did, sys_did);
            context_renew.set_sys_did(sys_did);
            let crypt_key = get_specific_secret_key("context", id_type, symbol_hash, phrase);
            let aes_key_old_vec = decrypt(&URL_SAFE_NO_PAD.decode(
                context_renew.get_aes_key_encrypted()).unwrap_or(zeroed_key.to_vec()), &crypt_key, 0);
            let aes_key_old = convert_vec_to_key(&aes_key_old_vec);
            let secret_key_new = get_random_secret_key(id_type, symbol_hash, phrase);
            let default_expire = 90*24*3600;
            context_renew.set_auth_sk_with_secret(&URL_SAFE_NO_PAD.encode(secret_key_new), default_expire);
            let aes_key_new = context_renew.get_crypt_key();
            transfer_private_data(&aes_key_old, &aes_key_new, &context_renew.get_private_paths());
            let aes_key_encrypted = URL_SAFE_NO_PAD.encode(encrypt(&context_renew.get_crypt_key(), &crypt_key, 0));
            context_renew.set_aes_key_encrypted(&aes_key_encrypted);
            context_renew
        */
}


pub(crate) fn get_user_token_from_file(did: &str, sys_did: &str) -> UserContext {
    let user_token_file = get_path_in_sys_key_dir(&format!("user_{}.token", did));
    match user_token_file.exists() {
        true => {
            let device_key = calc_sha256(&read_key_or_generate_key("Device", &[0u8; 32], "None", false, false));
            let token_raw_data = match user_token_file.exists() {
                true => {
                    match fs::read(user_token_file) {
                        Ok(data) => data,
                        Err(e) => {
                            println!("{} [SimpBase] read user issued certificates file error: {}", now_string(), e);
                            return UserContext::default()
                        },
                    }
                }
                false => return UserContext::default()
            };
            let token_data = decrypt(&token_raw_data, &device_key, 0);
            let user_tokens: Value = serde_json::from_slice(&token_data).unwrap_or(serde_json::json!({}));
            let user_context: UserContext = match user_tokens.get(sys_did) {
                Some(value) => {
                    let sys_key = calc_sha256(&read_key_or_generate_key("System", &[0u8; 32], "None", false, false));
                    let json_string = serde_json::to_string(&value).unwrap_or(String::from("{}"));
                    let token_data = decrypt(&URL_SAFE_NO_PAD.decode(json_string).unwrap_or([0u8; 32].to_vec()), &sys_key, 0);
                    let user_token: Value = serde_json::from_slice(&token_data).unwrap_or(serde_json::json!({}));
                    serde_json::from_value(user_token.clone()).unwrap_or_else(|_| UserContext::default())
                }
                None => {
                    UserContext::default()
                }
            };
            user_context
        },
        false => UserContext::default()
    }
}

pub(crate) fn update_user_token_to_file(context: &UserContext, method: &str) -> String {
    let did = context.get_did();
    let sys_did = context.get_sys_did();
    let device_key = calc_sha256(&read_key_or_generate_key("Device", &[0u8; 32], "None", false, false));
    let sys_key = calc_sha256(&read_key_or_generate_key("System", &[0u8; 32], "None", false, false));
    let user_token_file = get_path_in_sys_key_dir(&format!("user_{}.token", did));
    match user_token_file.exists() {
        true => {
            let token_raw_data = match fs::read(user_token_file.clone()) {
                Ok(data) => data,
                Err(e) => {
                    debug!("read user token file error: {}",e);
                    return "Err".to_string()
                },
            };
            let token_data = decrypt(&token_raw_data, &device_key, 0);
            let mut user_tokens: serde_json::Value = serde_json::from_slice(&token_data).unwrap_or(serde_json::json!({}));
            debug!("load user token from file({}): {}", user_token_file.display(), user_tokens);
            if method == "add" {
                let context_string = context.to_json_string();
                let context_raw_data = URL_SAFE_NO_PAD.encode(encrypt(context_string.as_bytes(), &sys_key, 0));
                user_tokens[sys_did] = json!(context_raw_data);
            } else if method == "remove" {
                if let Some(obj) = user_tokens.as_object_mut() {
                    obj.remove(&sys_did);
                }
            }
            let json_string = serde_json::to_string(&user_tokens).unwrap_or(String::from("{}"));
            let token_raw_data = encrypt(json_string.as_bytes(), &device_key, 0);
            debug!("Save user token to file: {}", json_string);
            fs::write(user_token_file.clone(), token_raw_data).expect(&format!("Unable to write file: {}", user_token_file.display()));
            "Ok".to_string()
        }
        false => {
            let mut user_tokens: serde_json::Value = json!({});
            if method == "add" {
                let context_string = context.to_json_string();
                let sys_key = calc_sha256(&read_key_or_generate_key("System", &[0u8; 32], "None", false, false));
                let context_raw_data = URL_SAFE_NO_PAD.encode(encrypt(context_string.as_bytes(), &sys_key, 0));
                user_tokens[sys_did] = json!(context_raw_data);
                let json_string = serde_json::to_string(&user_tokens).unwrap_or(String::from("{}"));
                let token_raw_data = encrypt(json_string.as_bytes(), &device_key, 0);
                debug!("Create new file for user token: {}", json_string);
                fs::write(user_token_file.clone(), token_raw_data).expect(&format!("Unable to write file: {}", user_token_file.display()));
                "Ok".to_string()
            } else { "Err".to_string() }
        }
    }
}

pub fn get_path_in_root_dir(catalog: &str, filename: &str) -> PathBuf {
    let sysinfo = &SYSTEM_BASE_INFO;
    let root_dirs = PathBuf::from(sysinfo.root_dir.clone());
    root_dirs.join(catalog).join(filename)
}


pub(crate) fn get_key_hash_id_and_phrase(key_type: &str, symbol_hash: &[u8; 32]) -> (String, String) {

    fn _get_key_hash_id_and_phrase(symbol_hash: &Vec<u8>, period: u64 ) -> (String, String) {
        let key_file_hash_id = sha256_prefix(symbol_hash, 10);
        let phrase_text = sha256_prefix(&hkdf_key_deadline(symbol_hash, period), 10);
        (key_file_hash_id, phrase_text)
    }

    let device_symbol_hash: [u8; 32] = dids::get_key_symbol_hash("Device");
    let system_symbol_hash = dids::get_key_symbol_hash("System");
    match key_type {
        "Device" => {
            _get_key_hash_id_and_phrase(&device_symbol_hash.to_vec(), 0)
        },
        "System" => {
            _get_key_hash_id_and_phrase(&system_symbol_hash.to_vec(), 0)
        },
        _ => {
            let (device_hash_id, _device_phrase) = _get_key_hash_id_and_phrase(&device_symbol_hash.to_vec(), 0);
            let mut com_symbol = Vec::new();
            com_symbol.extend_from_slice(symbol_hash);
            com_symbol.extend_from_slice(device_hash_id.as_bytes());
            _get_key_hash_id_and_phrase(&com_symbol, 0)
        },
    }
}


pub(crate) fn get_verify_key(key_type: &str, symbol_hash: &[u8; 32], phrase: &str) -> [u8; 32] {
    let signing_key = SigningKey::from_bytes(&read_key_or_generate_key(key_type, symbol_hash, phrase, false, false));
    let verifying_key: VerifyingKey = signing_key.verifying_key();
    *verifying_key.as_bytes()
}

pub(crate) fn get_cert_verify_key(cert_secret: &[u8; 32]) -> [u8; 32] {
    let signing_key = SigningKey::from_bytes(cert_secret);
    let verifying_key: VerifyingKey = signing_key.verifying_key();
    *verifying_key.as_bytes()
}

pub(crate) fn get_specific_secret_key(key_name: &str, key_type: &str, symbol_hash: &[u8; 32], phrase: &str) -> [u8; 32] {
    debug!("Get specific secret key: Name({}), Type({}), symbol_hash({}), phrase({})", key_name, key_type, URL_SAFE_NO_PAD.encode(symbol_hash), phrase);
    let key_hash = calc_sha256(&read_key_or_generate_key(key_type, symbol_hash, phrase, false, false));
    let key_name_bytes = calc_sha256(key_name.as_bytes());
    let mut com_phrase = [0u8; 64];
    com_phrase[..32].copy_from_slice(&key_hash);
    com_phrase[32..].copy_from_slice(symbol_hash);
    let secret_key = StaticSecret::from(derive_key(&com_phrase, &key_name_bytes).unwrap_or([0u8; 32]));
    *secret_key.as_bytes()
}


pub(crate) fn get_random_secret_key(key_type: &str, symbol_hash: &[u8; 32], phrase: &str) -> [u8; 32] {
    debug!("Get random secret key: Type({}), symbol_hash({}), phrase({})", key_type, URL_SAFE_NO_PAD.encode(symbol_hash), phrase);
    let key_hash = calc_sha256(&read_key_or_generate_key(key_type, symbol_hash, phrase, false, false));
    let mut csprng = OsRng {};
    let mut random_number = [0u8; 16];
    csprng.fill_bytes(&mut random_number);
    let mut com_phrase = [0u8; 48];
    com_phrase[..16].copy_from_slice(&random_number);
    com_phrase[16..].copy_from_slice(symbol_hash);
    let secret_key = StaticSecret::from(derive_key(&com_phrase, &key_hash).unwrap_or([0u8; 32]));
    *secret_key.as_bytes()
}

pub(crate) fn get_crypt_key(secret_key: [u8; 32]) -> [u8; 32] {
    let secret_key = StaticSecret::from(secret_key);
    let crypt_key = PublicKey::from(&secret_key);
    *crypt_key.as_bytes()
}

pub(crate) fn get_diffie_hellman_key(did_key: [u8; 32], secret_key: [u8; 32]) -> [u8; 32] {
    let secret_key = StaticSecret::from(secret_key);
    let shared_key = secret_key.diffie_hellman(&PublicKey::from(did_key));
    *shared_key.as_bytes()
}

pub(crate) fn get_signature(text: &str, key_type: &str, symbol_hash: &[u8; 32], phrase: &str) -> Vec<u8> {
    get_signature_by_key(text,&read_key_or_generate_key(key_type, symbol_hash, phrase, false, false))

}

pub(crate) fn get_signature_by_key(text: &str, signing_key: &[u8; 32]) -> Vec<u8> {
    let signing_key = SigningKey::from_bytes(signing_key);
    let signature = signing_key.sign(text.as_bytes());
    Vec::from(signature.to_bytes())
}

pub(crate) fn parse_crypt_secrets(secret_text: &str) -> [u8; 32] {
    let parts: Vec<&str> = secret_text.split('|').collect();
    if parts.len() >= 3 {
        convert_base64_to_key(parts[0])
    } else {
        [0u8; 32]
    }
}

pub(crate) fn convert_base64_to_key(key_str: &str) -> [u8; 32] {
    let vec = URL_SAFE_NO_PAD.decode(key_str.as_bytes())
        .unwrap_or_else(|_| [0u8; 32].to_vec());
    let mut key: [u8; 32] = [0; 32];
    let len_vec = vec.len();
    let len = if len_vec > 32 { 32 } else { len_vec };
    key.copy_from_slice(&vec[..len]);
    key
}

pub(crate) fn verify_signature(text: &str, signature: &str, verify_key: &[u8; 32]) -> bool {
    if text.is_empty() || signature.is_empty() {
        return false;
    }
    if verify_key == &[0u8; 32] {
        return false;
    }
    let verifykey = VerifyingKey::from_bytes(&verify_key.as_slice().try_into().unwrap()).unwrap();
    let signature = Signature::from_bytes(&URL_SAFE_NO_PAD.decode(signature).unwrap().as_slice().try_into().unwrap());
    match verifykey.verify(text.as_bytes(), &signature) {
        Ok(()) => true,
        Err(_) => false,
    }
}

pub(crate) fn get_path_in_sys_key_dir(filename: &str) -> PathBuf {
    let sysinfo = &SYSTEM_BASE_INFO;
    let home_dirs = match BaseDirs::new() {
        Some(dirs) => dirs.home_dir().to_path_buf(),
        None => PathBuf::from(sysinfo.root_dir.clone()),
    };
    home_dirs.join(".simpleai.vip").join(".token").join(filename)
}

pub(crate) fn hkdf_key_deadline(key: &[u8], period:u64) -> [u8; 32] {
    let mut salt = [0u8; 16];
    let timestamp = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();
    let input = format!("period:{}", if period == 0 { 0 } else { timestamp / period });
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    let result = hasher.finalize();
    salt.copy_from_slice(&result[..16]);

    let info = b"SimpleAI_SYS";
    let hk = Hkdf::<Sha256>::new(Some(&salt[..]), key);
    let mut aes_key = [0u8; 32];
    hk.expand(info, &mut aes_key).unwrap();
    aes_key
}

pub(crate) fn convert_to_sk_with_expire(secret_key: &[u8; 32], expire: u64) -> [u8; 40] {
    let expire_bytes = expire.to_le_bytes();
    let mut auth_sk = [0; 40];
    auth_sk[..32].copy_from_slice(secret_key);
    auth_sk[32..].copy_from_slice(&expire_bytes);
    auth_sk
}


pub(crate) fn encrypt(data: &[u8], key: &[u8], period:u64) -> Vec<u8> {
    let aes_key = hkdf_key_deadline(key, period);
    let key = Key::<Aes256Gcm>::from_slice(&aes_key);
    let cipher = Aes256Gcm::new(&key);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let encrypted = cipher.encrypt(&nonce, data).unwrap_or("Unknown".as_bytes().to_vec());
    let mut result = Vec::with_capacity(nonce.len() + encrypted.len());
    result.extend_from_slice(&nonce);
    result.extend_from_slice(&encrypted);
    result
}

pub(crate) fn decrypt(data: &[u8], key: &[u8], period:u64) -> Vec<u8> {
    let aes_key = hkdf_key_deadline(key, period);
    let key = Key::<Aes256Gcm>::from_slice(&aes_key);
    let cipher = Aes256Gcm::new(&key);
    let nonce = &data[..12]; // Nonce is 12 bytes for AES-256-GCM
    let encrypted = &data[12..];
    cipher.decrypt(nonce.into(), encrypted).unwrap_or("Unknown".as_bytes().to_vec())
}

pub(crate) fn get_user_copy_hash_id_by_source(nickname: &str, telephone: &str, phrase: &str) -> String {
    get_user_copy_hash_id(nickname, URL_SAFE_NO_PAD.encode(
        calc_sha256(telephone.as_bytes())).as_str(), phrase)
}
pub(crate) fn get_user_copy_hash_id(nickname: &str, telephone_base64: &str, phrase: &str) -> String {
    URL_SAFE_NO_PAD.encode(calc_sha512(
        format!("{}|{}|{}",nickname, telephone_base64, phrase).as_bytes()))
}


pub(crate) fn change_phrase_for_pem_and_identity_files(symbol_hash: &[u8; 32], old_phrase: &str, new_phrase: &str) {
    let (user_hash_id, user_phrase) = get_key_hash_id_and_phrase("User", symbol_hash);
    let user_key_file = get_path_in_sys_key_dir(&format!(".token_user_{}.pem", user_hash_id));
    let id_hash = [0u8; 32];
    let device_key = read_key_or_generate_key("Device", &id_hash, "None", false, false);
    let old_phrase_text = format!("{}|{}|{}",
                              URL_SAFE_NO_PAD.encode(device_key.as_slice()),
                              old_phrase, user_phrase);
    let new_phrase_text = format!("{}|{}|{}",
                                  URL_SAFE_NO_PAD.encode(device_key.as_slice()),
                                  new_phrase, user_phrase);

    let old_phrase_bytes = hkdf_key_deadline(&old_phrase_text.as_bytes(), 0);
    let new_phrase_bytes = hkdf_key_deadline(&new_phrase_text.as_bytes(), 0);
    if user_key_file.exists() {
        let Ok((_, s_doc)) = SecretDocument::read_pem_file(user_key_file.clone()) else { todo!() };
        let priv_key = match EncryptedPrivateKeyInfo::try_from(s_doc.as_bytes()).unwrap().decrypt(&old_phrase_bytes) {
            Ok(key) => {
                let mut pkey: [u8; 32] = [0; 32];
                pkey.copy_from_slice(PrivateKeyInfo::try_from(key.as_bytes()).unwrap().private_key);
                pkey
            },
            Err(_e) => {
                println!("{} [SimpBase] Read key file error: {}", now_string(), _e);
                let pkey: [u8; 32] = [0; 32];
                pkey
            },
        };
        let pem_label = "SIMPLE_AI_KEY";
        let csprng = OsRng {};
        PrivateKeyInfo::new(ALGORITHM_ID, &priv_key)
            .encrypt(csprng, &new_phrase_bytes).unwrap()
            .write_pem_file(user_key_file.clone(), pem_label, LineEnding::default()).unwrap();
        println!("{} [SimpBase] Change phrase for user_key_file: {}", now_string(), user_key_file.display());
    }
    let identity_file = get_path_in_sys_key_dir(&format!("user_identity_{}.token", user_hash_id));
    if identity_file.exists() {
        let encrypted_identity_base64 = fs::read_to_string(identity_file.clone()).unwrap_or("Unknown".to_string());
        let encrypted_identity = URL_SAFE_NO_PAD.decode(encrypted_identity_base64.clone()).unwrap_or("Unknown".as_bytes().to_vec());
        debug!("import, encrypted_identity: len={}, {}", encrypted_identity.len(), encrypted_identity_base64);
        let vcode = &encrypted_identity[..2];
        let identity = &encrypted_identity[2..];
        if  *vcode == calc_sha256(identity)[..2] {
            let telephone_bytes = &encrypted_identity[2..10];
            let telephone = u64::from_le_bytes(telephone_bytes.try_into().unwrap()).to_string();
            let nickname_bytes = &encrypted_identity[78..];
            let nickname = std::str::from_utf8(nickname_bytes).unwrap();
            let encrypted_secret = &encrypted_identity[10..78];
            debug!("import, identity: nickname: {}, telephone: {}, len={}, {}", nickname, telephone, identity.len(), URL_SAFE_NO_PAD.encode(identity));
            let secret_key = derive_key(old_phrase.as_bytes(), symbol_hash).unwrap();
            let identity_secret = decrypt(encrypted_secret, &secret_key, 0);
            debug!("import, identity_secret: symbol={}, phrase={}, secret_key={}, len={}, {}",
                    URL_SAFE_NO_PAD.encode(symbol_hash), old_phrase, URL_SAFE_NO_PAD.encode(secret_key), encrypted_secret.len(), URL_SAFE_NO_PAD.encode(encrypted_secret));
            let timestamp_bytes = &identity_secret[..8];
            let mut user_key = [0u8; 32];
            user_key.copy_from_slice(&identity_secret[8..]);

            let secret_key = derive_key(new_phrase.as_bytes(), symbol_hash).unwrap();
            let mut identity_secret = Vec::with_capacity(timestamp_bytes.len() + user_key.len());
            identity_secret.extend_from_slice(&timestamp_bytes);
            identity_secret.extend_from_slice(&user_key);
            let encrypted_secret = encrypt(&identity_secret, &secret_key, 0);
            debug!("export, identity_secret: symbol={}, phrase={}, secret_key={}, len={}, {}",
                    URL_SAFE_NO_PAD.encode(symbol_hash), new_phrase, URL_SAFE_NO_PAD.encode(secret_key), encrypted_secret.len(), URL_SAFE_NO_PAD.encode(encrypted_secret.clone()));
            let length = telephone_bytes.len() + encrypted_secret.len() + nickname_bytes.len();
            let mut identity = Vec::with_capacity(length);
            identity.extend_from_slice(&telephone_bytes);
            identity.extend_from_slice(&encrypted_secret);
            identity.extend_from_slice(nickname_bytes);
            debug!("export, identity: nickname={}, telephone={}, len={}, {}", nickname, telephone, identity.len(), URL_SAFE_NO_PAD.encode(identity.clone()));
            let vcode = &calc_sha256(&identity)[..2];
            let mut encrypted_identity = Vec::with_capacity(vcode.len() + identity.len());
            encrypted_identity.extend_from_slice(&vcode);
            encrypted_identity.extend_from_slice(&identity);
            let encrypted_identity_base64 = URL_SAFE_NO_PAD.encode(encrypted_identity.clone());
            debug!("export, encrypted_identity: len={}, {}", encrypted_identity.len(), encrypted_identity_base64);
            fs::write(identity_file.clone(), encrypted_identity_base64).expect(&format!("Unable to write file: {}", identity_file.display()));
            println!("{} [SimpBase] Change phrase for identity_file: {}", now_string(), identity_file.display());
        } else {
            println!("{} [SimpBase] Change phrase for identity_file, parsing encrypted_identity error: {}", now_string(), identity_file.display());
        }
    }
}


pub fn calc_sha256(input: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(input);
    let result = hasher.finalize();
    let mut output = [0u8; 32];
    output.copy_from_slice(&result[..]);
    output
}

pub fn calc_sha512(input: &[u8]) -> [u8; 64] {
    let mut hasher = Sha512::new();
    hasher.update(input);
    let result = hasher.finalize();
    let mut output = [0u8; 64];
    output.copy_from_slice(&result[..]);
    output
}

pub fn sha256_prefix(input: &[u8], len: usize) -> String {
    let hash = calc_sha256(input);
    let output = URL_SAFE_NO_PAD.encode(hash);
    if 0<len && len<=output.len() {
        output[..len].to_string()
    } else {
        output.to_string()
    }
}

pub(crate) fn gen_entry_point_of_service(point_id: &str) -> String {
    let service_id = match point_id.from_base58() {
        Ok(bytes) => bytes,
        Err(_) => calc_sha256(std::process::id().to_string().as_bytes()).to_vec(),
    };
    let sysinfo = &SYSTEM_BASE_INFO;
    let now_sec = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_else(|_| std::time::Duration::from_secs(0)).as_secs();
    let salt = calc_sha256(format!("{}:{}", sysinfo.host_name, now_sec/600000).as_bytes());
    derive_key(&service_id, &salt).unwrap_or([0u8; 32]).to_base58()
}

pub(crate) fn check_entry_point_of_service(entry_point: &str) -> bool { // 带有效期的entry_point 600000秒
    let service_id = calc_sha256(std::process::id().to_string().as_bytes());
    let sysinfo = &SYSTEM_BASE_INFO;
    let now_sec = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_else(|_| std::time::Duration::from_secs(0)).as_secs();
    let salt = calc_sha256(format!("{}:{}", sysinfo.host_name, now_sec/600000).as_bytes());
    let entry_point_real =  derive_key(&service_id, &salt).unwrap_or([0u8; 32]).to_base58();
    if entry_point_real != entry_point {
        let salt = calc_sha256(format!("{}:{}", sysinfo.host_name, now_sec/600000 - 1).as_bytes());
        let entry_point_real =  derive_key(&service_id, &salt).unwrap_or([0u8; 32]).to_base58();
        entry_point_real == entry_point
    } else { true  }
}

pub(crate) fn read_key_or_generate_key(key_type: &str, symbol_hash: &[u8; 32], phrase: &str, regen: bool, through: bool) -> [u8; 32] {

    fn _read_key_or_generate_key(file_path: &Path, phrase: &str, regen: bool, through: bool) -> [u8; 32] {
        let phrase_bytes = hkdf_key_deadline(&phrase.as_bytes(), 0);
        let private_key = match file_path.exists() {
            false => generate_new_key_and_save_pem(file_path, &phrase_bytes),
            true => {
                let mut priv_key: [u8; 32] = [0; 32];
                if !through {
                    if let Some(file_name) = file_path.file_name() {
                        let file_name_str = file_name.to_string_lossy();
                        let keys =SystemKeys::instance();
                        let mut keys =keys.lock().unwrap();
                        if file_name_str.contains("device") {
                            priv_key = keys.get_device_key()
                        } else if file_name_str.contains("system") {
                            priv_key = keys.get_system_key()
                        } else {
                            priv_key = [0; 32]
                        }
                    }
                }
                if priv_key == [0; 32] {
                    let Ok((_, s_doc)) = SecretDocument::read_pem_file(file_path) else { todo!() };
                    //println!("_read_key_or_generate_key, SecretDocument: {}", file_path.display());
                    priv_key = match EncryptedPrivateKeyInfo::try_from(s_doc.as_bytes()).unwrap().decrypt(&phrase_bytes) {
                        Ok(key) => {
                            debug!("_read_key_or_generate_key, EncryptedPrivateKeyInfo");
                            let mut pkey: [u8; 32] = [0; 32];
                            pkey.copy_from_slice(PrivateKeyInfo::try_from(key.as_bytes()).unwrap().private_key);
                            pkey
                        },
                        Err(_e) => {
                            if regen {
                                debug!("[SimpBase] Read private key error and generate new key: {}", file_path.display());
                                generate_new_key_and_save_pem(file_path, &phrase_bytes)
                            } else {
                                println!("{} [SimpBase] Read key error and return 0 key: {}", now_string(), file_path.display());
                                [0; 32]
                            }
                        },
                    };
                    debug!("read private key: {}", file_path.display());
                }
                priv_key
            }
        };
        private_key.try_into().unwrap()
    }

    if !through && (key_type == "Device" || key_type == "System"){
        let keys =SystemKeys::instance();
        let mut keys =keys.lock().unwrap();
        if key_type == "Device" {
            return keys.get_device_key();
        } else if key_type == "System" {
            return keys.get_system_key();
        }
    }

    let sysinfo = &SYSTEM_BASE_INFO;
    let (device_hash_id, _device_phrase) = get_key_hash_id_and_phrase("Device", symbol_hash);
    let device_key_file = get_path_in_sys_key_dir(&format!(".token_device_{}.pem", device_hash_id));
    let device_phrase = format!("{}/{}/{}/{}/{}/{}/{}/{}", sysinfo.host_name, sysinfo.disk_uuid,
                                sysinfo.os_name, sysinfo.os_type, sysinfo.cpu_brand, sysinfo.cpu_cores,
                                sysinfo.ram_total + sysinfo.gpu_memory, sysinfo.gpu_name);
    let device_key = if through && (key_type == "Device" || key_type == "System") {
        _read_key_or_generate_key(device_key_file.as_path(), device_phrase.as_str(), regen, through)
    } else { SystemKeys::instance().lock().unwrap().get_device_key() };
    let system_key = match key_type {
        "System" | "User" => {
            let (sys_hash_id, sys_phrase) = get_key_hash_id_and_phrase("System", symbol_hash);
            let system_key_file = get_path_in_sys_key_dir(&format!(".token_system_{}.pem", sys_hash_id));
            let local_phrase = format!("{}@{}:{}/{}/{}/{}/{}/{}/{}", sysinfo.root_dir, sysinfo.host_name,
                                       sysinfo.os_name, sysinfo.os_type, sysinfo.cpu_brand, sysinfo.cpu_cores,
                                       sysinfo.ram_total + sysinfo.gpu_memory, sysinfo.gpu_name, sysinfo.disk_uuid);
            let phrase_text = format!("{}|{}|{}",
                                      URL_SAFE_NO_PAD.encode(device_key.as_slice()),
                                      local_phrase, sys_phrase);
            if through && key_type == "System" {
                _read_key_or_generate_key(system_key_file.as_path(), phrase_text.as_str(), regen, through)
            } else { SystemKeys::instance().lock().unwrap().get_system_key() }
        },
        _ => device_key
    };
    match key_type {
        "System" => system_key,
        "User" => {
            let (user_hash_id, user_phrase) = get_key_hash_id_and_phrase("User", symbol_hash);
            debug!("read_key_or_generate_key: user_symbol_hash={}, user_hash_id={}, user_phrase={}", URL_SAFE_NO_PAD.encode(symbol_hash), user_hash_id, user_phrase);
            let user_key_file = get_path_in_sys_key_dir(&format!(".token_user_{}.pem", user_hash_id));
            let phrase_text = format!("{}|{}|{}",
                                      URL_SAFE_NO_PAD.encode(device_key.as_slice()),
                                      phrase, user_phrase);
            _read_key_or_generate_key(user_key_file.as_path(), phrase_text.as_str(), regen, through)
        },
        _ => device_key
    }

}




fn generate_new_key_and_save_pem(file_path: &Path, phrase: &[u8; 32]) -> [u8; 32] {
    if let Some(parent_dir) = file_path.parent() {
        if !parent_dir.exists() {
            fs::create_dir_all(parent_dir).unwrap();
        }
    }
    println!("{} [SimpBase] generate new key and save: {}", now_string(), file_path.file_name().unwrap_or_default().to_string_lossy());
    let sysinfo = &SYSTEM_BASE_INFO;

    let pem_label = "SIMPLE_AI_KEY";
    let mut csprng = OsRng {};
    let secret_key: [u8; 32];
    if let Some(file_name) = file_path.file_name() {
        let file_name_str = file_name.to_string_lossy();

        if file_name_str.contains("device") {
            let seed = derive_key(&calc_sha256(format!("{}{}", sysinfo.disk_uuid,sysinfo.os_time).as_bytes()),
                                  &calc_sha256(format!("{}{}", sysinfo.host_name, sysinfo.os_time).as_bytes()))
                .unwrap_or([0u8; 32]);
            secret_key = SigningKey::from_bytes(&seed).to_bytes();
        } else if file_name_str.contains("system") {
            let seed = derive_key(&calc_sha256(format!("{}{}", sysinfo.root_dir,sysinfo.root_time).as_bytes()),
                                  &calc_sha256(format!("{}{}", sysinfo.exe_name, sysinfo.root_time).as_bytes()))
                .unwrap_or([0u8; 32]);
            secret_key = SigningKey::from_bytes(&seed).to_bytes();
        } else {
            let mut secret_bytes = [0u8; 32];
            csprng.fill_bytes(&mut secret_bytes);
            secret_key = SigningKey::from_bytes(&secret_bytes).to_bytes();
        }
    } else {
        let mut secret_bytes = [0u8; 32];
        csprng.fill_bytes(&mut secret_bytes);
        secret_key = SigningKey::from_bytes(&secret_bytes).to_bytes();
    }

    PrivateKeyInfo::new(ALGORITHM_ID, &secret_key)
        .encrypt(csprng, &phrase).unwrap()
        .write_pem_file(file_path, pem_label, LineEnding::default()).unwrap();
    secret_key
}


fn save_key_to_pem(symbol_hash: &[u8; 32], key: &[u8; 32], phrase: &str) -> [u8; 32] {
    let (user_hash_id, user_phrase) = get_key_hash_id_and_phrase("User", symbol_hash);
    let user_key_file = get_path_in_sys_key_dir(&format!(".token_user_{}.pem", user_hash_id));
    if let Some(parent_dir) = user_key_file.parent() {
        if !parent_dir.exists() {
            fs::create_dir_all(parent_dir).unwrap();
        }
    }
    let id_hash = [0u8; 32];
    let device_key = read_key_or_generate_key("Device", &id_hash, "None", false, false);
    let phrase_text = format!("{}|{}|{}",
                              URL_SAFE_NO_PAD.encode(device_key.as_slice()),
                              phrase, user_phrase);
    let phrase_bytes = hkdf_key_deadline(&phrase_text.as_bytes(), 0);

    let pem_label = "SIMPLE_AI_KEY";
    let csprng = OsRng {};
    let secret_key = SigningKey::from_bytes(key).to_bytes();

    let encrypted_key_info = PrivateKeyInfo::new(ALGORITHM_ID, &secret_key)
        .encrypt(csprng, &phrase_bytes)
        .unwrap();
    let pem_content = encrypted_key_info.to_pem(pem_label, LineEnding::default()).unwrap();
    let mut file = fs::File::create(&user_key_file).unwrap();
    file.write_all(pem_content.as_bytes()).unwrap();
    file.sync_all().unwrap();
    debug!("save key to local pem file: {}", user_key_file.display());

    secret_key
}

pub(crate) fn exists_key_file(key_type: &str, symbol_hash: &[u8; 32]) -> bool {
    let (key_hash_id, _phrase) = get_key_hash_id_and_phrase(key_type, symbol_hash);
    let key_file = get_path_in_sys_key_dir(&format!(".token_{}_{}.pem",
                                                    key_type.to_lowercase(), key_hash_id));
    key_file.exists()
}

pub(crate) fn is_original_user_key(key_type: &str, symbol_hash: &[u8; 32]) -> bool {
    let (hash_id, phrase) = get_key_hash_id_and_phrase(key_type, symbol_hash);
    debug!("the key testing : {}", hash_id);
    let key = read_key_or_generate_key(key_type, symbol_hash, &phrase, false, false);
    key != [0u8; 32]
}


pub(crate) fn exists_and_valid_user_key(symbol_hash: &[u8; 32], phrase: &str) -> bool {
    let key_type = "User";
    let (key_hash_id, _phrase) = get_key_hash_id_and_phrase(key_type, symbol_hash);
    let key_file = get_path_in_sys_key_dir(&format!(".token_{}_{}.pem",
                                                    key_type.to_lowercase(), key_hash_id));
    if key_file.exists() {
        let key = read_key_or_generate_key("User", symbol_hash, &phrase, false, false);
        debug!("user_key exists: {}, valid: {}", key_file.display(), key != [0u8; 32]);
        key != [0u8; 32]
    } else {
        debug!("user_key do not exists: {}", key_file.display());
        false
    }
}

pub(crate) fn derive_key(password: &[u8], salt: &[u8]) -> Result<[u8; 32], TokenError> {
    let mut key = [0u8; 32];
    Argon2::default().hash_password_into(password, salt, &mut key)?;
    Ok(key)
}

fn get_token_crypt_key() -> [u8; 32] {
    let keys =SystemKeys::instance();
    let mut keys =keys.lock().unwrap();
    keys.get_file_crypt_key()
}





pub(crate) fn convert_vec_to_key(vec: &Vec<u8>) -> [u8; 32] {
    let mut key: [u8; 32] = [0; 32];
    let len_vec = vec.len();
    let len = if len_vec > 32 { 32 } else { len_vec };
    key.copy_from_slice(&vec[..len]);
    key
}

pub fn filter_files(work_paths: &Path, filters: &[&str], suffixes: &[&str]) -> Vec<String> {
    let mut result = Vec::new();
    if let Ok(entries) = fs::read_dir(work_paths) {
        for entry in entries {
            if let Ok(entry) = entry {
                let path = entry.path();
                if path.is_file() {
                    if let Some(file_name) = path.file_name() {
                        if let Some(file_name_str) = file_name.to_str() {
                            let contains_filter = filters.iter().any(|filter| file_name_str.contains(filter));
                            let ends_with_suffix = suffixes.iter().any(|suffix| file_name_str.ends_with(suffix));
                            if contains_filter && ends_with_suffix {
                                result.push(file_name_str.to_string());
                            }
                        }
                    }
                }
            }
        }
    }
    result
}

pub(crate) fn export_identity(nickname: &str, telephone: &str, timestamp: u64, phrase: &str) -> Vec<u8>  {
    let nickname = truncate_nickname(nickname);
    let telephone_bytes = match telephone.parse::<u64>() {
        Ok(number) => number,
        Err(_) => {
            println!("Failed to parse phone number as integer");
            0
        }
    }.to_le_bytes();
    let symbol_hash = IdClaim::get_symbol_hash_by_source(&nickname, Some(telephone.to_string()), None);
    let timestamp_bytes = timestamp.to_le_bytes();
    let user_key = read_key_or_generate_key("User", &symbol_hash, phrase, false, false);
    let nickname_bytes = nickname.as_bytes();
    let secret_key = derive_key(phrase.as_bytes(), &symbol_hash).unwrap();
    let mut identity_secret = Vec::with_capacity(timestamp_bytes.len() + user_key.len());
    identity_secret.extend_from_slice(&timestamp_bytes);
    identity_secret.extend_from_slice(&user_key);
    let encrypted_secret  = encrypt(&identity_secret, &secret_key, 0);
    debug!("export, identity_secret: symbol={}, phrase={}, secret_key={}, len={}, {}",
        URL_SAFE_NO_PAD.encode(symbol_hash), phrase, URL_SAFE_NO_PAD.encode(secret_key), encrypted_secret.len(), URL_SAFE_NO_PAD.encode(encrypted_secret.clone()));
    let length = telephone_bytes.len() + encrypted_secret.len() + nickname_bytes.len();
    let mut identity = Vec::with_capacity(length);
    identity.extend_from_slice(&telephone_bytes);
    identity.extend_from_slice(&encrypted_secret);
    identity.extend_from_slice(nickname_bytes);
    debug!("export, identity: nickname={}, telephone={}, len={}, {}", nickname, telephone, identity.len(), URL_SAFE_NO_PAD.encode(identity.clone()));
    let vcode = &calc_sha256(&identity)[..2];
    let mut encrypted_identity = Vec::with_capacity(vcode.len() + identity.len());
    encrypted_identity.extend_from_slice(&vcode);
    encrypted_identity.extend_from_slice(&identity);
    debug!("export, encrypted_identity: len={}, {}", encrypted_identity.len(), URL_SAFE_NO_PAD.encode(encrypted_identity.clone()));
    encrypted_identity
}

pub(crate) fn import_identity(symbol_hash_base64: &str, encrypted_identity: &Vec<u8>, phrase: &str) -> IdClaim  {
    debug!("import, encrypted_identity: len={}, {}", encrypted_identity.len(), URL_SAFE_NO_PAD.encode(encrypted_identity.clone()));
    let vcode = &encrypted_identity[..2];
    let identity = &encrypted_identity[2..];
    if  *vcode == calc_sha256(identity)[..2] {
        let telephone = u64::from_le_bytes(encrypted_identity[2..10].try_into().unwrap()).to_string();
        let nickname = std::str::from_utf8(&encrypted_identity[78..]).unwrap();
        let encrypted_secret = &encrypted_identity[10..78];
        debug!("import, identity: nickname: {}, telephone: {}, len={}, {}", nickname, telephone, identity.len(), URL_SAFE_NO_PAD.encode(identity));
        let secret_key = derive_key(phrase.as_bytes(), &URL_SAFE_NO_PAD.decode(symbol_hash_base64).unwrap()).unwrap();
        let identity_secret = decrypt(encrypted_secret, &secret_key, 0);
        debug!("import, identity_secret: symbol={}, phrase={}, secret_key={}, len={}, {}",
            symbol_hash_base64, phrase, URL_SAFE_NO_PAD.encode(secret_key), encrypted_secret.len(), URL_SAFE_NO_PAD.encode(encrypted_secret));
        if identity_secret.len() > "Unknown".len() {
            let timestamp = u64::from_le_bytes(identity_secret[..8].try_into().unwrap());
            let mut user_key = [0u8; 32];
            user_key.copy_from_slice(&identity_secret[8..]);

            let telephone_hash = calc_sha256(format!("{}:telephone:{}", nickname, telephone).as_bytes());
            let telephone_base64 = URL_SAFE_NO_PAD.encode(telephone_hash);
            let id_card_base64 = URL_SAFE_NO_PAD.encode(calc_sha256(format!("{}:id_card:{}", nickname, "-").as_bytes()));
            let symbol_hash = calc_sha256(format!("{}|{}|{}", nickname, telephone_base64, id_card_base64).as_bytes());
            save_key_to_pem(&symbol_hash, &user_key, &phrase);
            let mut user_claim = LocalClaims::generate_did_claim("User", nickname, Some(telephone), None, &phrase, Some(timestamp));
            user_claim
        } else {
            println!("{} [SimpBase] import_identity: Invalid identity secret", now_string());
            IdClaim::default()
        }
    } else {
        println!("{} [SimpBase] import_identity: Invalid identity string", now_string());
        IdClaim::default()
    }
}

pub(crate) fn import_identity_qrcode(encrypted_identity: &Vec<u8>) -> (String, String, String, String)  {
    let did_bytes = &encrypted_identity[..21];
    let user_did = did_bytes.to_base58();
    let user_cert_bytes = &encrypted_identity[21..153];
    let user_cert = convert_to_short_user_cert_from_slim(user_cert_bytes);
    let encrypted_identity = &encrypted_identity[153..];
    debug!("import_identity_qrcode: did={} cert={}, encrypted_identity: len={}, {}", user_did, user_cert, encrypted_identity.len(), URL_SAFE_NO_PAD.encode(encrypted_identity));
    let vcode = &encrypted_identity[..2];
    if  *vcode == calc_sha256(&encrypted_identity[2..])[..2] {
        let telephone = u64::from_le_bytes(encrypted_identity[2..10].try_into().unwrap_or([0u8; 8]));
        let nickname = std::str::from_utf8(&encrypted_identity[78..]).unwrap_or("").to_string();
        let symbol_hash = IdClaim::get_symbol_hash_by_source(&nickname, Some(telephone.to_string()), None);
        let (user_hash_id, _user_phrase) = get_key_hash_id_and_phrase("User", &symbol_hash);
        let identity_file = get_path_in_sys_key_dir(&format!("user_identity_{}.token", user_hash_id));
        fs::write(identity_file.clone(), URL_SAFE_NO_PAD.encode(encrypted_identity)).expect(&format!("Unable to write file: {}", identity_file.display()));
        debug!("{} [SimpBase] Import from qrcode and save identity_file: did={}, nickname={}", now_string(), user_did, nickname);
        if telephone == 0 {
            (user_did, nickname, "".to_string(), user_cert)
        } else { (user_did, nickname, telephone.to_string(), user_cert) }
    } else {
        debug!("import_identity_qrcode, Invalid vcode: did={}", user_did);
        ("Unknown".to_string(), "".to_string(), "".to_string(), "Unknown".to_string())
    }
}


fn transfer_private_data(aes_key_old: &[u8; 32], aes_key_new: &[u8; 32], private_paths: &Vec<String>) {
    // TODO
}

pub(crate) fn encrypt_issue_cert_and_get_vcode(issue_cert: &str) -> (String, String) {
    let mut csprng = OsRng {};
    let mut key = [0u8; 32];
    csprng.fill_bytes(&mut key);
    let mut key_1 = [0u8; 28];
    key_1[..28].copy_from_slice(&key[..28]);
    let mut key_2 = [0u8; 4];
    key_2.copy_from_slice(&key[28..32]);
    let encrypted_issue_cert = encrypt(issue_cert.as_bytes(), &key, 0);
    let mut new_encrypted_issue_cert: Vec<u8> = Vec::new();
    new_encrypted_issue_cert.extend_from_slice(&key_1);
    new_encrypted_issue_cert.extend_from_slice(&encrypted_issue_cert);
    let result_issue_cert = URL_SAFE_NO_PAD.encode(new_encrypted_issue_cert);
    (key_2.to_base58().to_string(), result_issue_cert)
}

pub(crate) fn decrypt_issue_cert_with_vcode(vcode: &str, issue_cert: &str) -> String {
    let result_certificate = URL_SAFE_NO_PAD.decode(issue_cert).unwrap_or([0; 32].to_vec());
    let vcode_bytes = vcode.from_base58().unwrap_or([0; 4].to_vec());
    let mut key = [0; 32];
    key[..28].copy_from_slice(&result_certificate[..28]);
    key[28..].copy_from_slice(&vcode_bytes[..4]);
    String::from_utf8_lossy(decrypt(&result_certificate[28..], &key, 0).as_slice()).to_string()
}

pub(crate) fn encrypt_text_and_get_vcode(plain_text: &str) -> (String, String) {
    let mut csprng = OsRng {};
    let mut key = [0u8; 32];
    csprng.fill_bytes(&mut key);
    let mut key_1 = [0u8; 28];
    key_1[..28].copy_from_slice(&key[..28]);
    let mut key_2 = [0u8; 4];
    key_2.copy_from_slice(&key[28..32]);
    let encrypted_issue_cert = encrypt(plain_text.as_bytes(), &key, 0);
    let mut new_encrypted_issue_cert: Vec<u8> = Vec::new();
    new_encrypted_issue_cert.extend_from_slice(&key_1);
    new_encrypted_issue_cert.extend_from_slice(&encrypted_issue_cert);
    let result_issue_cert = URL_SAFE_NO_PAD.encode(new_encrypted_issue_cert);
    (key_2.to_base58().to_string(), result_issue_cert)
}

pub(crate) fn decrypt_text_with_vcode(vcode: &str, encrypted_text: &str) -> String {
    let encrypted_text_bytes = URL_SAFE_NO_PAD.decode(encrypted_text).unwrap_or([0; 32].to_vec());
    let vcode_bytes = vcode.from_base58().unwrap_or([0; 4].to_vec());
    let mut key = [0; 32];
    key[..28].copy_from_slice(&encrypted_text_bytes[..28]);
    key[28..].copy_from_slice(&vcode_bytes[..4]);
    String::from_utf8_lossy(decrypt(&encrypted_text_bytes[28..], &key, 0).as_slice()).to_string()
}

pub(crate) fn is_valid_telephone(telephone: &str) -> bool {
    if telephone.len() < 6 || telephone.len() > 15 {
        return false;
    }
    if !telephone.chars().all(|c| c.is_digit(10)) {
        return false;
    }
    if telephone.chars().next() == Some('0') {
        return false;
    }
    if telephone.starts_with("86") && telephone.len() != 13 {
        return false;
    }
    true
}

pub(crate) fn truncate_nickname(nickname: &str) -> String {
    let max_bytes = 24;
    let mut byte_count = 0;
    let mut result = String::new();

    for c in nickname.chars() {
        let char_bytes = c.len_utf8();
        if byte_count + char_bytes > max_bytes {
            break;
        }
        result.push(c);
        byte_count += char_bytes;
    }

    result
}

pub(crate) fn now_string() -> String {
    let now = Local::now();
    let hours = now.hour();
    let minutes = now.minute();
    let seconds = now.second();
    let millis = now.timestamp_subsec_millis();
    let formatted_time = format!("{:02}:{:02}:{:02}.{:03}", hours, minutes, seconds, millis);
    formatted_time
}