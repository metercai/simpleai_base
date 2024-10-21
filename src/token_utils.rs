use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::fs;
use std::env;
use std::sync::Arc;
use tokio::sync::Mutex;
use std::time::SystemTime;
use serde_json::{json, Value};
use directories_next::BaseDirs;

use pkcs8::{EncryptedPrivateKeyInfo, PrivateKeyInfo, LineEnding, ObjectIdentifier, SecretDocument};

use ed25519_dalek::{VerifyingKey, SigningKey, Signer, Signature, Verifier};
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

use tracing::info;
use crate::systeminfo::{SystemBaseInfo, SystemInfo};
use lazy_static::lazy_static;


use crate::error::TokenError;
use crate::claims::{GlobalClaims, IdClaim, UserContext};
use crate::{claims, token};

const ALGORITHM_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.112");

/// Ed25519 Algorithm Identifier.
const ALGORITHM_ID: pkcs8::AlgorithmIdentifierRef<'static> = pkcs8::AlgorithmIdentifierRef {
    oid: ALGORITHM_OID,
    parameters: None,
};

pub(crate) static TOKEN_TM_URL: &str = "https://v2.token.tm:3030/api/";
pub(crate) static TOKEN_TM_DID: &str = "96PghYp9YVaYsrgY6HBUVzPfwYxCm";

lazy_static! {
    pub static ref SYSTEM_BASE_INFO: SystemBaseInfo = SystemBaseInfo::generate();
    pub static ref VERBOSE_INFO: bool = {
        match env::var("SIMPLEAI_VERBOSE") {
            Ok(val) => if val=="on" {true} else {false},
            Err(_) => false,
        }
    };
}


pub(crate) fn load_pem_and_claim_from_file(id_type: &str, symbol_hash: &[u8; 32], did: &str) -> String {
    let (user_hash_id, _user_phrase) = get_key_hash_id_and_phrase("User", symbol_hash);
    let user_key_file = get_path_in_sys_key_dir(&format!(".token_user_{}.pem", user_hash_id));
    let pem_string = fs::read_to_string(user_key_file).unwrap_or("".to_string());
    let did_file_path = get_path_in_sys_key_dir(format!("{}_{}.did", id_type.to_lowercase(), did).as_str());
    let claim_string  = fs::read_to_string(did_file_path).unwrap_or("".to_string());
    format!("{}|{}", pem_string, claim_string)
}


pub(crate) fn init_user_crypt_secret_with_sig(crypt_secrets: &mut HashMap<String, String>, key_name: &str, claim: &IdClaim, phrase: &str) -> String{
    let crypt_secret_with_sig = get_crypt_secret_with_sig(key_name, claim, phrase);
    crypt_secrets.insert(format!("{}_{}", claim.gen_did(), key_name), crypt_secret_with_sig.clone());
    crypt_secret_with_sig
}

pub(crate) fn get_crypt_secret_with_sig(key_name: &str, claim: &IdClaim, phrase: &str) -> String{
    let crypt_secret = get_specific_secret_key(
        key_name,0,claim.id_type.as_str(), &claim.get_symbol_hash(), &phrase);
    let did = claim.gen_did();
    let secret_base64 = URL_SAFE_NO_PAD.encode(crypt_secret);
    let timestamp = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_else(|_| std::time::Duration::from_secs(0)).as_secs();
    let text = format!("{}_{}|{}|{}", did, key_name, secret_base64, timestamp);
    let sig = URL_SAFE_NO_PAD.encode(get_signature(text.as_str(), &claim.id_type, &claim.get_symbol_hash(), phrase));
    let crypt_secret_with_sig = format!("{}|{}|{}", secret_base64, timestamp, sig);
    crypt_secret_with_sig
}

pub(crate) fn load_token_of_user_certificates(sys_did: &str, certificates: &mut HashMap<String, String>) {
    let token_file = get_path_in_sys_key_dir(&format!("user_certs_{}.token", sys_did));
    let crypt_key = get_token_crypt_key();
    let token_raw_data = match token_file.exists() {
        true => {
            match fs::read(token_file) {
                Ok(data) => data,
                Err(e) => {
                    println!("read user_certificates file error: {}",e);
                    return
                },
            }
        }
        false => return
    };

    let token_data = decrypt(&token_raw_data, &crypt_key, 0);
    let system_token: Value = serde_json::from_slice(&token_data).unwrap_or(serde_json::json!({}));

    if *VERBOSE_INFO {
        println!("Load user_certs token from file: {}", system_token);
    }
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
                        claims_guard.get_claim_from_global(did)
                    };
                    if verify_signature(&text, sig_base64, &claim.get_verify_key()) {
                        certificates.insert(key.clone(), secrets_str.to_string());
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
    if *VERBOSE_INFO {
        println!("Save user_certificates to file: {}", json_string);
    }
    fs::write(system_token_file.clone(), token_raw_data).expect(&format!("Unable to write file: {}", system_token_file.display()))
}

pub(crate) fn load_token_of_issued_certs(sys_did: &str, issued_certs: &mut HashMap<String, String>) {
    let token_file = get_path_in_sys_key_dir(&format!("user_certs_{}.token", sys_did));
    let crypt_key = get_token_crypt_key();
    let token_raw_data = match token_file.exists() {
        true => {
            match fs::read(token_file) {
                Ok(data) => data,
                Err(e) => {
                    println!("read user_certificates file error: {}",e);
                    return
                },
            }
        }
        false => return
    };
    let token_data = decrypt(&token_raw_data, &crypt_key, 0);
    let system_token: Value = serde_json::from_slice(&token_data).unwrap_or(serde_json::json!({}));

    if *VERBOSE_INFO {
        println!("Load issued_certs token from file: {}", system_token);
    }
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
                        claims_guard.get_claim_from_global(did)
                    };
                    if verify_signature(&text, sig_base64, &claim.get_verify_key()) {
                        issued_certs.insert(key.clone(), secrets_str.to_string());
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
    if *VERBOSE_INFO {
        println!("Save issued_certificates to file: {}", json_string);
    }
    fs::write(system_token_file.clone(), token_raw_data).expect(&format!("Unable to write file: {}", system_token_file.display()))
}

pub(crate) fn filter_user_certs(user_did: &str, item: &str, user_certs: &HashMap<String, String>) -> HashMap<String, String> {
    let filter_str = match item {
        "*" => format!("|{}|", user_did),
        &_ => format!("|{}|{}", user_did, item), };

    user_certs
        .iter()
        .filter(|(key, _value)| key.contains(filter_str.as_str()))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect()
}

pub(crate) fn filter_issuer_certs(issuer_did: &str, item: &str,user_certs: &HashMap<String, String>) -> HashMap<String, String> {
    let filter_str = format!("{}|", issuer_did);
    let filted_certs = user_certs
        .iter()
        .filter(|(key, _value)| key.starts_with(filter_str.as_str()))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();
    if item == "*" {
        filted_certs
    } else {
        let filter_str = format!("|{}", item);
        user_certs
            .iter()
            .filter(|(key, _value)| key.ends_with(filter_str.as_str()))
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect()
    }
}

pub(crate) fn parse_user_certs(certificate_string: &str) -> (String, String) {
    let certs_array: Vec<&str> = certificate_string.split("|").collect();
    if certs_array.len() >= 7 {
        let certs_key = format!("{}|{}|{}", certs_array[0], certs_array[1], certs_array[2]);
        let certs_value = format!("{}|{}|{}|{}", certs_array[3], certs_array[4], certs_array[5], certs_array[6]);
        (certs_key, certs_value)
    } else {
        ("Unknown".to_string(), "Unknown".to_string())
    }
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
                    println!("read authorized2system file error: {}",e);
                    return String::from("");
                },
            };
            let token_data = decrypt(&token_raw_data, &crypt_key, 0);
            let system_token: Value = serde_json::from_slice(&token_data).unwrap_or(serde_json::json!({}));

            if *VERBOSE_INFO {
                println!("Load authorized2system token from file: {}", system_token);
            }
            let admin = match system_token.get("admin_did") {
                Some(Value::String(admin)) => admin.clone(),
                _ => String::from(""),
            };

            let claims = claims::GlobalClaims::instance();
            if let Some(Value::Object(hellman_secrets)) = system_token.get("hellman_secrets") {
                for (key, value) in hellman_secrets {
                    let parts_key: Vec<&str> = key.split('_').collect();
                    let did = parts_key[0];
                    if let Value::String(secrets_str) = value {
                        let parts: Vec<&str> = secrets_str.split('|').collect();
                        if parts.len() >= 3 {
                            let secret_base64 = parts[0];
                            let timestamp = parts[1];
                            let sig_base64 = parts[2];
                            let text = format!("{}|{}|{}", key, secret_base64, timestamp);
                            let claim = {
                                let mut claims_guard = claims.lock().unwrap();
                                claims_guard.get_claim_from_global(did)
                            };
                            if verify_signature(&text, sig_base64, &claim.get_verify_key()) {
                                crypt_secrets.insert(key.clone(), secrets_str.to_string());
                            }
                        }
                    }
                }
            }
            admin
        }
        false => String::from(""),
    };
    admin_did
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

pub(crate) fn create_or_renew_user_context_token(did: &str, sys_did: &str, nickname: &str, id_type: &str, symbol_hash: &[u8; 32], phrase: &str) -> UserContext {
    let zeroed_key: [u8; 32] = [0u8; 32];
    let user_token_file = get_path_in_sys_key_dir(&format!("user_{}.token", did));
    let context = match user_token_file.exists() {
        true => {
            println!("Renew user context token: {}", did);
            let Ok(mut context_renew) = read_user_token_from_file(user_token_file.as_path())
                else { todo!() };
            context_renew.set_sys_did(sys_did);
            let crypt_key = get_specific_secret_key("context", 0, id_type, symbol_hash, phrase);
            let aes_key_old_vec = decrypt(&URL_SAFE_NO_PAD.decode(
                context_renew.get_aes_key_encrypted()).unwrap_or(zeroed_key.to_vec()), &crypt_key, 0);
            let aes_key_old = convert_vec_to_key(&aes_key_old_vec);
            let secret_key_new = get_random_secret_key(id_type, 0, symbol_hash, phrase)
                .unwrap_or([0u8; 40]);
            let default_expire = 90*24*3600;
            context_renew.set_auth_sk_with_secret(&URL_SAFE_NO_PAD.encode(secret_key_new), default_expire);
            let aes_key_new = context_renew.get_crypt_key();
            transfer_private_data(&aes_key_old, &aes_key_new, &context_renew.get_private_paths());
            let aes_key_encrypted = URL_SAFE_NO_PAD.encode(encrypt(&context_renew.get_crypt_key(), &crypt_key, 0));
            context_renew.set_aes_key_encrypted(&aes_key_encrypted);
            context_renew
        }
        false => {
            println!("Create user context token: {}", did);
            let default_permissions = "standard".to_string();
            let default_private_paths = serde_json::to_string(
                &vec!["config", "presets", "wildcards", "styles", "workflows"]).unwrap_or("".to_string());
            let mut context_default = UserContext::new(did, sys_did, nickname, &default_permissions, &default_private_paths);
            let secret_key = get_random_secret_key(id_type, 0, symbol_hash, phrase)
                .unwrap_or([0u8; 40]);
            let default_expire = 90*24*3600;
            context_default.set_auth_sk_with_secret(&URL_SAFE_NO_PAD.encode(secret_key), default_expire);
            let crypt_key = get_specific_secret_key("context", 0, id_type, symbol_hash, phrase);
            let aes_key_encrypted = URL_SAFE_NO_PAD.encode(encrypt(&context_default.get_crypt_key(), &crypt_key, 0));
            context_default.set_aes_key_encrypted(&aes_key_encrypted);
            context_default
        }
    };
    context
}


pub(crate) fn get_user_token_from_file(did: &str) -> Result<UserContext, TokenError> {
    let user_token_file = get_path_in_sys_key_dir(&format!("user_{}.token", did));
    match user_token_file.exists() {
        true => read_user_token_from_file(user_token_file.as_path()),
        false => Ok(UserContext::default())
    }
}

pub(crate) fn save_user_token_to_file(context: &UserContext) -> Result<String, TokenError> {
    let json_string = serde_json::to_string(&context)?;
    let user_token_file = get_path_in_sys_key_dir(&format!("user_{}.token", context.get_did()));
    let crypt_key = get_token_crypt_key();
    let token_raw_data = encrypt(json_string.as_bytes(), &crypt_key, 0);
    fs::write(user_token_file, token_raw_data)?;
    Ok(json_string)
}

pub(crate) fn get_path_in_user_dir(did: &str, filename: &str) -> PathBuf {
    let sysinfo = &SYSTEM_BASE_INFO;
    let home_dirs = match BaseDirs::new() {
        Some(dirs) => dirs.home_dir().to_path_buf(),
        None => PathBuf::from(sysinfo.root_dir.clone()),
    };
    home_dirs.join(".simpleai.vip").join(did).join(filename)
}

pub(crate) fn get_key_hash_id_and_phrase(key_type: &str, symbol_hash: &[u8; 32]) -> (String, String) {
    let sysinfo = &SYSTEM_BASE_INFO;
    match key_type {
        "Device" => _get_key_hash_id_and_phrase(&format!("{}{}", sysinfo.host_name, sysinfo.disk_uuid).into_bytes(), 0),
        "System" => _get_key_hash_id_and_phrase(&format!("{}{}", sysinfo.root_dir, sysinfo.disk_uuid).into_bytes(), 0),
        _ => {
            let (device_hash_id, _device_phrase) = _get_key_hash_id_and_phrase
                (&format!("{}{}", sysinfo.host_name, sysinfo.disk_uuid).into_bytes(), 0);
            let mut com_symbol = Vec::new();
            com_symbol.extend_from_slice(symbol_hash);
            com_symbol.extend_from_slice(device_hash_id.as_bytes());
            _get_key_hash_id_and_phrase(&com_symbol, 0)
        },
    }
}

pub(crate) fn exists_key_file(key_type: &str, symbol_hash: &[u8; 32]) -> bool {
    let (key_hash_id, _phrase) = get_key_hash_id_and_phrase(key_type, symbol_hash);
    let key_file = get_path_in_sys_key_dir(&format!(".token_{}_{}.pem",
                                                    key_type.to_lowercase(), key_hash_id));
    key_file.exists()
}

pub(crate) fn get_verify_key(key_type: &str, symbol_hash: &[u8; 32], phrase: &str) -> [u8; 32] {
    let signing_key = SigningKey::from_bytes(&read_key_or_generate_key(key_type, symbol_hash, phrase).unwrap_or([0u8; 32]));
    let verifying_key: VerifyingKey = signing_key.verifying_key();
    *verifying_key.as_bytes()
}

pub(crate) fn get_specific_secret_key(key_name: &str, period:u64, key_type: &str, symbol_hash: &[u8; 32], phrase: &str) -> [u8; 40] {
    let key_hash = calc_sha256(&read_key_or_generate_key(key_type, symbol_hash, phrase).unwrap_or([0u8; 32]));
    let key_name_bytes = calc_sha256(key_name.as_bytes());
    let mut com_phrase = [0u8; 64];
    com_phrase[..32].copy_from_slice(&key_name_bytes);
    com_phrase[32..].copy_from_slice(symbol_hash);
    let secret_key = StaticSecret::from(derive_key(&com_phrase, &key_hash).unwrap_or([0u8; 32]));
    convert_to_sk_with_expire(secret_key.as_bytes(), period)
}


pub(crate) fn get_random_secret_key(key_type: &str, period:u64, symbol_hash: &[u8; 32], phrase: &str) -> Result<[u8; 40], TokenError> {
    let key_hash = calc_sha256(&read_key_or_generate_key(key_type, symbol_hash, phrase)?);
    let mut csprng = OsRng {};
    let mut random_number = [0u8; 16];
    csprng.fill_bytes(&mut random_number);
    let mut com_phrase = [0u8; 48];
    com_phrase[..16].copy_from_slice(&random_number);
    com_phrase[16..].copy_from_slice(symbol_hash);
    let secret_key = StaticSecret::from(derive_key(&com_phrase, &key_hash)?);
    Ok(convert_to_sk_with_expire(secret_key.as_bytes(), period))
}

pub(crate) fn get_crypt_key(secret_key: [u8; 40]) -> Result<[u8; 32], TokenError> {
    let key = &secret_key[..32];
    let expire = u64::from_le_bytes(secret_key[32..].try_into().unwrap_or_else(|_| [0; 8]));
    let secret_key = StaticSecret::from(hkdf_key_deadline(key, expire));
    let crypt_key = PublicKey::from(secret_key.to_bytes());
    Ok(*crypt_key.as_bytes())
}

pub(crate) fn get_diffie_hellman_key(did_key: &PublicKey, secret_key: [u8; 32]) -> [u8; 32] {
    let secret_key = StaticSecret::from(secret_key);
    let shared_key = secret_key.diffie_hellman(&did_key);
    *shared_key.as_bytes()
}
pub(crate) fn get_signature(text: &str, key_type: &str, symbol_hash: &[u8; 32], phrase: &str) -> Vec<u8> {
    let signing_key = SigningKey::from_bytes(&read_key_or_generate_key(key_type, symbol_hash, phrase).unwrap_or([0u8; 32]));
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

pub(crate) fn get_symbol_hash_by_source(nickname: &str, telephone: &str) -> [u8; 32] {
    get_symbol_hash(nickname, URL_SAFE_NO_PAD.encode(
        calc_sha256(telephone.as_bytes())).as_str())
}

pub(crate)fn get_symbol_hash(nickname: &str, telephone_base64: &str) -> [u8; 32] {
    calc_sha256(format!("{}|{}",nickname, telephone_base64).as_bytes())
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

pub(crate) fn save_user_pem(symbol_hash: &[u8; 32], pem: &str) {
    let (user_hash_id, _user_phrase) = get_key_hash_id_and_phrase("User", symbol_hash);
    let user_key_file = get_path_in_sys_key_dir(&format!(".token_user_{}.pem", user_hash_id));
    fs::write(user_key_file.clone(), pem).unwrap_or_else(|_| panic!("Failed to write to file: {}", user_key_file.display()));
}

pub(crate) fn change_phrase_for_pem(symbol_hash: &[u8; 32], old_phrase: &str, new_phrase: &str) {
    let (user_hash_id, _user_phrase) = get_key_hash_id_and_phrase("User", symbol_hash);
    let user_key_file = get_path_in_sys_key_dir(&format!(".token_user_{}.pem", user_hash_id));
    let old_phrase_bytes = hkdf_key_deadline(&old_phrase.as_bytes(), 0);
    let new_phrase_bytes = hkdf_key_deadline(&new_phrase.as_bytes(), 0);
    match user_key_file.exists() {
        true => {
            let Ok((_, s_doc)) = SecretDocument::read_pem_file(user_key_file.clone()) else { todo!() };
            let priv_key = match EncryptedPrivateKeyInfo::try_from(s_doc.as_bytes()).unwrap().decrypt(&old_phrase_bytes) {
                Ok(key) => {
                    let mut pkey: [u8; 32] = [0; 32];
                    pkey.copy_from_slice(PrivateKeyInfo::try_from(key.as_bytes()).unwrap().private_key);
                    pkey
                },
                Err(_e) => {
                    println!("Read key file error: {}", _e);
                    let pkey: [u8; 32] = [0; 32];
                    pkey
                },
            };
            let pem_label = "SIMPLE_AI_KEY";
            let csprng = OsRng {};
            PrivateKeyInfo::new(ALGORITHM_ID, &priv_key)
                .encrypt(csprng, &new_phrase_bytes).unwrap()
                .write_pem_file(user_key_file.clone(), pem_label, LineEnding::default()).unwrap();
        }
        false => {
            println!("File not found: {}", user_key_file.display());
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


pub(crate) async fn sys_login_to_token_tm(sys_claim: &IdClaim, device_claim: &IdClaim, sysinfo: &SystemInfo) -> String {
    let sys_did = sys_claim.gen_did();
    let device_did = device_claim.gen_did();
    let mut request: Value = json!({});
    request["system_claim"] = serde_json::to_value(&sys_claim).unwrap();
    request["device_claim"] = serde_json::to_value(&device_claim).unwrap();

    let result = match token::REQWEST_CLIENT.post(format!("{}/{}", TOKEN_TM_URL, "register"))
        .header("sys_did", sys_did.to_string())
        .header("dev_did", device_did.to_string())
        .body(serde_json::to_string(&request).unwrap())
        .send()
        .await{
        Ok(res) => {
            match res.text().await {
                Ok(text) => text,
                Err(e) => {
                    println!("Failed to register system to  token.tm: {}", e);
                    "Error".to_string()
                }
            }
        },
        Err(e) => {
            println!("Failed to register system to  token.tm: {}", e);
            "Error".to_string()
        }
    };

    SystemInfo::logging_launch_info(&sys_did, sysinfo).await;

    result
}

fn read_key_or_generate_key(key_type: &str, symbol_hash: &[u8; 32], phrase: &str) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let sysinfo = &SYSTEM_BASE_INFO;
    let (device_hash_id, _device_phrase) = get_key_hash_id_and_phrase("Device", symbol_hash);
    let device_key_file = get_path_in_sys_key_dir(&format!(".token_device_{}.pem", device_hash_id));
    let device_phrase = format!("{}/{}/{}/{}/{}/{}/{}/{}", sysinfo.host_name, sysinfo.disk_uuid,
                                sysinfo.os_name, sysinfo.os_type, sysinfo.cpu_brand, sysinfo.cpu_cores,
                                sysinfo.ram_total + sysinfo.gpu_memory, sysinfo.gpu_name);
    let device_key = _read_key_or_generate_key(device_key_file.as_path(), device_phrase.as_str())?;
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
            _read_key_or_generate_key(system_key_file.as_path(), phrase_text.as_str())?
        },
        _ => device_key
    };
    match key_type {
        "System" => Ok(system_key),
        "User" => {
            let (user_hash_id, user_phrase) = get_key_hash_id_and_phrase("User", symbol_hash);
            let user_key_file = get_path_in_sys_key_dir(&format!(".token_user_{}.pem", user_hash_id));
            let phrase_text = format!("{}|{}|{}",
                                      URL_SAFE_NO_PAD.encode(device_key.as_slice()),
                                      phrase, user_phrase);
            Ok(_read_key_or_generate_key(user_key_file.as_path(), phrase_text.as_str())?)
        },
        _ => Ok(device_key)
    }
}



fn _get_key_hash_id_and_phrase(symbol_hash: &Vec<u8>, period: u64 ) -> (String, String) {
    let key_file_hash_id = sha256_prefix(symbol_hash, 10);
    let phrase_text = sha256_prefix(&hkdf_key_deadline(symbol_hash, period), 10);
    (key_file_hash_id, phrase_text)
}

fn _read_key_or_generate_key(file_path: &Path, phrase: &str) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let phrase_bytes = hkdf_key_deadline(&phrase.as_bytes(), 0);
    let private_key = match file_path.exists() {
        false => generate_new_key_and_save_pem(file_path, &phrase_bytes),
        true => {
            let Ok((_, s_doc)) = SecretDocument::read_pem_file(file_path) else { todo!() };
            let priv_key = match EncryptedPrivateKeyInfo::try_from(s_doc.as_bytes()).unwrap().decrypt(&phrase_bytes) {
                Ok(key) => {
                    let mut pkey: [u8; 32] = [0; 32];
                    pkey.copy_from_slice(PrivateKeyInfo::try_from(key.as_bytes()).unwrap().private_key);
                    pkey
                },
                Err(_e) => generate_new_key_and_save_pem(file_path, &phrase_bytes),
            };
            priv_key
        }
    };
    if *VERBOSE_INFO {
        println!("read private key: {}", file_path.display());
    }
    Ok(private_key.try_into().unwrap())
}

fn generate_new_key_and_save_pem(file_path: &Path, phrase: &[u8; 32]) -> [u8; 32] {
    if let Some(parent_dir) = file_path.parent() {
        if !parent_dir.exists() {
            fs::create_dir_all(parent_dir).unwrap();
        }
    }
    let pem_label = "SIMPLE_AI_KEY";
    let mut csprng = OsRng {};
    let secret_key = SigningKey::generate(&mut csprng).to_bytes();
    PrivateKeyInfo::new(ALGORITHM_ID, &secret_key)
        .encrypt(csprng, &phrase).unwrap()
        .write_pem_file(file_path, pem_label, LineEnding::default()).unwrap();
    secret_key
}



pub(crate) fn derive_key(password: &[u8], salt: &[u8]) -> Result<[u8; 32], TokenError> {
    let mut key = [0u8; 32];
    Argon2::default().hash_password_into(password, salt, &mut key)?;
    Ok(key)
}

fn get_token_crypt_key() -> [u8; 32] {
    let mut claims =GlobalClaims::instance();
    let mut claims =claims.lock().unwrap();
    claims.get_file_crypt_key()
}


pub(crate) fn get_file_crypt_key() -> [u8; 32] {
    let id_hash = [0u8; 32];
    let device_key = calc_sha256(&read_key_or_generate_key("Device", &id_hash, "None").unwrap_or(id_hash));
    let local_key = calc_sha256(&read_key_or_generate_key("System", &id_hash, "None").unwrap_or(id_hash));
    let mut com_hash = [0u8; 64];
    com_hash[..32].copy_from_slice(&device_key);
    com_hash[32..].copy_from_slice(&local_key);
    calc_sha256(com_hash.as_ref())
}


fn read_user_token_from_file(user_token_file: &Path) -> Result<UserContext, TokenError> {
    let crypt_key = get_token_crypt_key();
    let token_raw_data = fs::read(user_token_file)?;
    let token_data = decrypt(&token_raw_data, &crypt_key, 0);
    Ok(serde_json::from_slice(&token_data).unwrap_or(UserContext::default()))
}



pub(crate) fn save_secret_to_system_token_file(crypt_secrets: &HashMap<String, String>, sys_did: &str, admin: &str) {
    let mut json_system_token = json!({});
    json_system_token["admin_did"] = json!(admin);
    json_system_token["hellman_secrets"] = json!(crypt_secrets);
    let json_string = serde_json::to_string(&json_system_token).unwrap_or(String::from("{}"));

    let system_token_file = get_path_in_sys_key_dir(&format!("authorized2system_{}.token", sys_did));
    let crypt_key = get_token_crypt_key();
    let token_raw_data = encrypt(json_string.as_bytes(), &crypt_key, 0);
    if *VERBOSE_INFO {
        println!("Save secret token to file: {}", json_string);
    }
    fs::write(system_token_file.clone(), token_raw_data).expect(&format!("Unable to write file: {}", system_token_file.display()))
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
    let mut key = [0; 32];
    key[..28].copy_from_slice(&result_certificate[..28]);
    key[28..].copy_from_slice(&vcode.from_base58().unwrap_or([0; 4].to_vec())[..4]);
    String::from_utf8(decrypt(&result_certificate[24..], &key, 0)).unwrap_or("Unknown".to_string())
}