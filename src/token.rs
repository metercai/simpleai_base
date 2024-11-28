use std::collections::HashMap;
use std::fs;
use std::thread;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use std::path::{Path, PathBuf};
use serde_json::{self, json};
use base58::{ToBase58, FromBase58};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use tracing::{error, warn, info, debug, trace};
use tracing_subscriber::EnvFilter;
use qrcode::{QrCode, Version, EcLevel};
use qrcode::render::svg;
use qrcode::bits::{Bits, encode_auto};


use pyo3::prelude::*;

use crate::token_utils;
use crate::{exchange_key, issue_key};
use crate::error::TokenError;
use crate::env_data::EnvData;
use crate::claims::{GlobalClaims, IdClaim, UserContext};
use crate::rathole::Rathole;
use crate::systeminfo::SystemInfo;
use crate::cert_center::GlobalCerts;



#[derive(Clone, Debug)]
#[pyclass]
pub struct SimpleAI {
    pub sys_name: String,
    pub did: String,
    token_db: Arc<Mutex<sled::Db>>,
    // 用户绑定授权的缓存，来自user_{did}.token
    pub authorized: Arc<Mutex<sled::Tree>>, //HashMap<String, UserContext>,
    pub sysinfo: SystemInfo,
    // 留存本地的身份自证, 用根密钥签
    claims: Arc<Mutex<GlobalClaims>>,
    // 专项密钥，源自pk.pem的派生，避免交互时对phrase的依赖，key={did}_{用途}，value={key}|{time}|{sig}, 用途=['exchange', 'issue']
    crypt_secrets: HashMap<String, String>,
    // 授权给本系统的他证, key={issue_did}|{for_did}|{用途}，value={encrypted_key}|{memo}|{time}|{sig},
    // encrypted_key由for_did交换派生密钥加密, sig由证书密钥签，用途=['Member']
    certificates: Arc<Mutex<GlobalCerts>>, // HashMap<String, String>,
    // 颁发的certificate，key={issue_did}|{for_did}|{用途}，value=encrypt_with_for_sys_did({issue_did}|{for_did}|{用途}|{encrypted_key}|{memo}|{time}|{sig})
    // encrypted_key由for_did交换派生密钥加密, sig由证书密钥签, 整体由接受系统did的交换派生密钥加密
    // issued_certs: HashMap<String, String>,
    admin: String,
    device: String,
    guest: String,
    guest_phrase: String,
    ready_users: Arc<Mutex<sled::Tree>>, //HashMap<String, serde_json::Value>,
    blacklist: Vec<String>, // 黑名单
    upstream_did: String,
    user_base_dir: String,
}

#[pymethods]
impl SimpleAI {
    #[new]
    pub fn new(
        sys_name: String,
    ) -> Self {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(EnvFilter::from_default_env())
            .try_init();

        let sys_base_info = token_utils::SYSTEM_BASE_INFO.clone();
        let sysinfo_handle = token_utils::TOKIO_RUNTIME.spawn(async move {
            SystemInfo::generate().await
        });

        let zeroed_key: [u8; 32] = [0; 32];
        let root_dir = sys_base_info.root_dir.clone();
        let disk_uuid = sys_base_info.disk_uuid.clone();
        let host_name = sys_base_info.host_name.clone();

        let (sys_hash_id, sys_phrase) = token_utils::get_key_hash_id_and_phrase("System", &zeroed_key);
        let (device_hash_id, device_phrase) = token_utils::get_key_hash_id_and_phrase("Device", &zeroed_key);
        let system_name = format!("{}{}", sys_name, &sys_hash_id[..4]).chars().take(24).collect::<String>();
        let device_name = format!("{}{}", host_name, &device_hash_id[..4]).chars().take(24).collect::<String>();
        let guest_name = format!("guest{}", &sys_hash_id[..4]).chars().take(24).collect::<String>();
        debug!("system_name:{}, device_name:{}, guest_name:{}", system_name, device_name, guest_name);

        let guest_symbol_hash = IdClaim::get_symbol_hash_by_source(&guest_name, "Unknown");
        let (_, guest_phrase) = token_utils::get_key_hash_id_and_phrase("User", &guest_symbol_hash);

        let claims = GlobalClaims::instance();
        let (local_did, local_claim, device_did, device_claim, guest_did, guest_claim, claims_local_length) = {
            let mut claims = claims.lock().unwrap();
            let mut local_did = claims.reverse_lookup_did_by_nickname("System", &system_name);
            let mut device_did = claims.reverse_lookup_did_by_nickname("Device", &device_name);
            let mut guest_did = claims.reverse_lookup_did_by_nickname("User", &guest_name);
            let local_claim = match local_did.as_str() {
                "Unknown" => {
                    let local_claim = GlobalClaims::generate_did_claim
                        ("System", &system_name, None, Some(root_dir), &sys_phrase);
                    local_did = local_claim.gen_did();
                    claims.push_claim(&local_claim);
                    local_claim
                }
                _ => claims.get_claim_from_local(&local_did),
            };
            let device_claim = match device_did.as_str() {
                "Unknown" => {
                    let device_claim = GlobalClaims::generate_did_claim
                        ("Device", &device_name, None, Some(disk_uuid), &device_phrase);
                    device_did = device_claim.gen_did();
                    claims.push_claim(&device_claim);
                    device_claim
                }
                _ => claims.get_claim_from_local(&device_did),
            };
            let guest_claim = match guest_did.as_str() {
                "Unknown" => {
                    let guest_claim = GlobalClaims::generate_did_claim
                        ("User", &guest_name, None, None, &guest_phrase);
                    guest_did = guest_claim.gen_did();
                    claims.push_claim(&guest_claim);
                    guest_claim
                }
                _ => claims.get_claim_from_local(&guest_did),
            };
            claims.set_system_device_guest_did(&local_did, &device_did, &guest_did);
            let claims_local_length = claims.local_len();
            debug!("init system/device/guest did and claim ok.");
            (local_did, local_claim, device_did, device_claim, guest_did, guest_claim, claims_local_length)
        };

        let mut crypt_secrets = HashMap::new();
        let admin = token_utils::load_token_by_authorized2system(&local_did, &mut crypt_secrets);
        let blacklist = token_utils::load_did_blacklist_from_file();

        let crypt_secrets_len = crypt_secrets.len();
        token_utils::init_user_crypt_secret(&mut crypt_secrets, &local_claim, &sys_phrase);
        token_utils::init_user_crypt_secret(&mut crypt_secrets, &device_claim, &device_phrase);
        token_utils::init_user_crypt_secret(&mut crypt_secrets, &guest_claim, &guest_phrase);
        if crypt_secrets.len() > crypt_secrets_len {
            token_utils::save_secret_to_system_token_file(&mut crypt_secrets, &local_did, &admin);
        }

        let certificates = GlobalCerts::instance();
        let token_db = {
            let mut certificates = certificates.lock().unwrap();
            let _ = certificates.load_certificates_from_local(&local_did);
            certificates.get_token_db()
        };
        let (authorized_tree, ready_users_tree) = {
            let token_db = token_db.lock().unwrap();
            (token_db.open_tree("authorized").unwrap(), token_db.open_tree("ready_users").unwrap())
        };
        let authorized = Arc::new(Mutex::new(authorized_tree));
        let ready_users = Arc::new(Mutex::new(ready_users_tree));

        let sysinfo = token_utils::TOKIO_RUNTIME.block_on(async {
            sysinfo_handle.await.expect("Sysinfo Task panicked")
        });

        let sys_did = local_did.clone();
        let dev_did = device_did.clone();
        let sysinfo_clone = sysinfo.clone();
        let _logging_handle = token_utils::TOKIO_RUNTIME.spawn(async move {
            SystemInfo::logging_launch_info(&sys_did, &sysinfo_clone).await;
            submit_uncompleted_request_files(&sys_did, &dev_did).await
        });

        let upstream_did = if admin != token_utils::TOKEN_TM_DID {
            SimpleAI::request_token_api_register(&local_claim, &device_claim)
        } else {
            token_utils::TOKEN_TM_DID.to_string()
        };
        let upstream_did = if upstream_did != "Unknown" { upstream_did } else { "".to_string() };
        debug!("upstream_did: {}", upstream_did);
        debug!("init context finished: claims.len={}, crypt_secrets.len={}", claims_local_length, crypt_secrets.len());

        let admin = {
            let admin = if guest_did == admin { "".to_string() } else { admin };
            let mut claims = claims.lock().unwrap();
            claims.set_admin_did(&admin);
            admin
        };

        Self {
            sys_name,
            did: local_did,
            device: device_did,
            admin,
            token_db,
            authorized,
            sysinfo,
            claims,
            crypt_secrets,
            certificates,
            guest: guest_did,
            guest_phrase,
            ready_users,
            blacklist,
            upstream_did,
            user_base_dir: String::new(),
        }
    }


    pub fn start_base_services(&self) -> Result<(), TokenError> {
        let _config = "client.toml";
        let _did = self.did.clone();
        let _rt_handle = thread::spawn(move || {
            token_utils::TOKIO_RUNTIME.block_on(async {
                //let _ = Rathole::new(&config).start_service().await;
                //todo!()
                //println!("Rathole service started");
            });
        });
        Ok(())
    }
    pub fn get_sys_name(&self) -> String { self.sys_name.clone() }
    pub fn get_sys_did(&self) -> String { self.did.clone() }
    pub fn get_upstream_did(&self) -> String { self.upstream_did.clone() }

    pub fn get_sysinfo(&self) -> SystemInfo {
        self.sysinfo.clone()
    }

    pub fn get_device_did(&self) -> String {
        self.device.clone()
    }
    pub fn get_guest_did(&self) -> String {
        self.guest.clone()
    }

    pub fn get_admin_did(&self) -> String {
        self.admin.clone()
    }

    //pub fn get_token_db(&self) -> Arc<Mutex<sled::Db>> { self.token_db.clone() }

    pub fn is_guest(&self, did: &str) -> bool {
        did == self.guest.as_str()
    }

    pub fn is_admin(&self, did: &str) -> bool {
        did == self.admin.as_str()
    }

    pub fn set_admin(&mut self, did: &str) {
        self.admin = {
            let mut claims = self.claims.lock().unwrap();
            claims.set_admin_did(did);
            did.to_string()
        }
    }

    pub fn absent_admin(&self) -> bool {
        self.admin.is_empty()
    }

    pub fn push_claim(&mut self, claim: &IdClaim) {
        let mut claims = self.claims.lock().unwrap();
        claims.push_claim(claim);
    }

    pub fn pop_claim(&mut self, did: &str) -> IdClaim {
        let mut claims = self.claims.lock().unwrap();
        claims.pop_claim(did)
    }

    pub fn get_claim(&mut self, for_did: &str) -> IdClaim {
        let mut claims = self.claims.lock().unwrap();
        if self.admin == token_utils::TOKEN_TM_DID {
            claims.get_claim_from_local(for_did)
        } else {
            debug!("get_claim_from_global: {}, admin={},{}", for_did, self.admin, token_utils::TOKEN_TM_DID);
            claims.get_claim_from_global(for_did)
        }
    }

    pub fn get_register_cert(&self, user_did: &str) -> String {
        let certificates = self.certificates.lock().unwrap();
        certificates.get_register_cert(user_did)
    }

    pub fn is_registered(&self, user_did: &str) -> bool {
        let cert_str = self.get_register_cert(user_did);
        if cert_str.is_empty() || cert_str == "Unknown" {
            return false;
        }
        let parts: Vec<&str> = cert_str.split('|').collect();
        if parts.len() != 4 {
            return false;
        }
        let encrypt_item_key = parts[0].to_string();
        let memo_base64 = parts[1].to_string();
        let timestamp = parts[2].to_string();
        let signature_str = parts[3].to_string();
        let text = format!("{}|{}|{}|{}|{}|{}", token_utils::TOKEN_TM_DID, user_did, "Member", encrypt_item_key, memo_base64, timestamp);
        let claim = GlobalClaims::load_claim_from_local(token_utils::TOKEN_TM_DID);
        token_utils::verify_signature(&text, &signature_str, &claim.get_cert_verify_key())
    }
    pub fn create_user(&mut self, nickname: &str, telephone: &str, id_card: Option<String>, phrase: Option<String>)
                       -> (String, String) {
        let nickname = nickname.chars().take(24).collect::<String>();
        let user_telephone = telephone.to_string();
        if !token_utils::is_valid_telephone(telephone) {
            return ("Unknown".to_string(), "Unknown".to_string());
        }
        let user_symbol_hash = IdClaim::get_symbol_hash_by_source(&nickname, &user_telephone);
        let (user_hash_id, user_phrase) = token_utils::get_key_hash_id_and_phrase("User", &user_symbol_hash);
        let phrase = phrase.unwrap_or(user_phrase);
        let user_claim = GlobalClaims::generate_did_claim("User", &nickname, Some(user_telephone.clone()), id_card, &phrase);
        self.push_claim(&user_claim);
        let user_did = user_claim.gen_did();
        let crypt_secrets_len = self.crypt_secrets.len();
        token_utils::init_user_crypt_secret(&mut self.crypt_secrets, &user_claim, &phrase);
        if self.crypt_secrets.len() > crypt_secrets_len {
            token_utils::save_secret_to_system_token_file(&mut self.crypt_secrets, &self.did, &self.admin);
        }
        let identity = self.export_user(&nickname, &user_telephone, &phrase);
        let identity_file = token_utils::get_path_in_sys_key_dir(&format!("user_identity_{}.token", user_hash_id));
        fs::write(identity_file.clone(), identity).expect(&format!("Unable to write file: {}", identity_file.display()));
        println!("[UserBase] Create user and save identity_file: {}", identity_file.display());

        (user_did, phrase)
    }

    pub fn remove_user(&mut self, user_symbol_hash_base64: &str) -> String {
        let user_symbol_hash = token_utils::convert_base64_to_key(user_symbol_hash_base64);
        let (user_hash_id, _user_phrase) = token_utils::get_key_hash_id_and_phrase("User", &user_symbol_hash);
        let (user_did, claim) = {
            let mut claims = self.claims.lock().unwrap();
            let user_did = claims.reverse_lookup_did_by_symbol(&user_symbol_hash);
            let claim = claims.get_claim_from_local(&user_did);
            (user_did, claim)
        };
        println!("[UserBase] Remove user: {}, {}, {}", user_hash_id, user_did, claim.nickname);
        if user_did != "Unknown" {
            let _ = token_utils::remove_user_pem_and_claim(&user_symbol_hash, &user_did);
            if !claim.is_default() {
                let identity_file = token_utils::get_path_in_sys_key_dir(&format!("user_identity_{}.token", user_hash_id));
                if identity_file.exists() {
                    if let Err(e) = fs::remove_file(identity_file.clone()) {
                        debug!("delete identity_file error: {}", e);
                    } else {
                        debug!("identity_file was deleted: {:?}", identity_file);
                    }
                }
                let exchange_key_value = self.crypt_secrets.remove(&exchange_key!(user_did));
                let issue_key_value = self.crypt_secrets.remove(&issue_key!(user_did));
                if exchange_key_value.is_some() || issue_key_value.is_some() {
                    let _ = token_utils::save_secret_to_system_token_file(&mut self.crypt_secrets, &self.did, &self.admin);
                }
            }
        }
        user_did
    }


    pub fn import_user(&mut self, user_hash_id: &str, encrypted_identity: &str, phrase: &str) -> String {
        let user_claim = token_utils::import_identity(user_hash_id, &URL_SAFE_NO_PAD.decode(encrypted_identity).unwrap(), phrase);
        self.push_claim(&user_claim);
        let user_did = user_claim.gen_did();
        let crypt_secrets_len = self.crypt_secrets.len();
        token_utils::init_user_crypt_secret(&mut self.crypt_secrets, &user_claim, &phrase);
        if self.crypt_secrets.len() > crypt_secrets_len {
            token_utils::save_secret_to_system_token_file(&mut self.crypt_secrets, &self.did, &self.admin);
        }
        println!("[UserBase] Import user: {}", user_did);

        user_did
    }

    pub fn export_user(&self, nickname: &str, telephone: &str, phrase: &str) -> String {
        let nickname = nickname.chars().take(24).collect::<String>();
        let symbol_hash = IdClaim::get_symbol_hash_by_source(&nickname, &telephone);
        let (user_did, claim) = {
            let mut claims = self.claims.lock().unwrap();
            let user_did = claims.reverse_lookup_did_by_symbol(&symbol_hash);
            let claim = claims.get_claim_from_local(&user_did);
            (user_did, claim)
        };
        println!("[UserBase] Export user: {}", user_did);

        URL_SAFE_NO_PAD.encode(token_utils::export_identity(&nickname, telephone, claim.timestamp, phrase))
    }

    #[staticmethod]
    pub fn export_user_qrcode_svg(user_did: &str) -> String {
        let claim = {
            let claims = GlobalClaims::instance();
            let mut claims = claims.lock().unwrap();
            claims.get_claim_from_local(user_did)
        };
        if !claim.is_default() {
            let user_symbol_hash = claim.get_symbol_hash();
            let (user_hash_id, _user_phrase) = token_utils::get_key_hash_id_and_phrase("User", &user_symbol_hash);
            let identity_file = token_utils::get_path_in_sys_key_dir(&format!("user_identity_{}.token", user_hash_id));
            match identity_file.exists() {
                true => {
                    let identity = fs::read_to_string(identity_file.clone()).expect(&format!("Unable to read file: {}", identity_file.display()));
                    let encrypted_identity = URL_SAFE_NO_PAD.decode(identity).unwrap();
                    let did_bytes = user_did.from_base58().unwrap();
                    let user_cert = {
                        let certificates = GlobalCerts::instance();
                        let certificates = certificates.lock().unwrap();
                        certificates.get_register_cert(user_did)
                    };
                    let user_cert_bytes = token_utils::get_slim_user_cert(&user_cert);
                    if user_cert_bytes.len() < 120 {
                        return "".to_string()
                    }
                    let mut encrypted_identity_qr = Vec::with_capacity(encrypted_identity.len() + did_bytes.len() + user_cert_bytes.len());
                    encrypted_identity_qr.extend_from_slice(&did_bytes);
                    encrypted_identity_qr.extend_from_slice(&user_cert_bytes);
                    encrypted_identity_qr.extend_from_slice(&encrypted_identity);
                    let encrypted_identity_qr_base64 = URL_SAFE_NO_PAD.encode(encrypted_identity_qr.clone());
                    debug!("encrypted_identity_qr: did.len={}, user_cert={}, identity={}, total={}", did_bytes.len(), user_cert_bytes.len(), encrypted_identity.len(), encrypted_identity_qr.len());
                    debug!("encrypted_identity({})_qr_base64: len={}, {}", user_did, encrypted_identity_qr_base64.len(), encrypted_identity_qr_base64);
                    //let mut bits = Bits::new(Version::Normal(10));
                    //bits.push_byte_data(&encrypted_identity_qr);
                    //bits.push_terminator(EcLevel::L);
                    let bits = encode_auto(&encrypted_identity_qr_base64.as_bytes(),EcLevel::L).unwrap();
                    let qrcode = QrCode::with_bits(bits, EcLevel::L).unwrap();
                    //let qrcode = QrCode::with_version(encrypted_identity_qr_base64, Version::Normal(12), EcLevel::L).unwrap();
                    let image = qrcode.render()
                        .min_dimensions(400, 400)
                        .dark_color(svg::Color("#800000"))
                        .light_color(svg::Color("#ffff80"))
                        .build();
                    image
                }
                false => "".to_string()
            }
        } else { "".to_string() }
    }

    #[staticmethod]
    pub fn import_identity_qrcode(encrypted_identity: &str) -> (String, String, String) {
        let identity = URL_SAFE_NO_PAD.decode(encrypted_identity).unwrap();
        let (user_did, nickname, telephone, user_cert) = token_utils::import_identity_qrcode(&identity);
        if user_did != "Unknown" && user_cert != "Unknown" {
            let certificates = GlobalCerts::instance();
            let mut certificates = certificates.lock().unwrap();
            certificates.push_user_cert_text(&format!("{}|{}|{}|{}", token_utils::TOKEN_TM_DID, user_did, "Member", user_cert));
        }
        (user_did, nickname, telephone)
    }


    pub fn sign_and_issue_cert_by_admin(&mut self, item: &str, for_did: &str, for_sys_did: &str, memo: &str)
                               -> (String, String) {
        self.sign_and_issue_cert_by_did(&self.admin.clone(), item, for_did, for_sys_did, memo)
    }

    pub fn sign_and_issue_cert_by_system(&mut self, item: &str, for_did: &str, for_sys_did: &str, memo: &str)
                               -> (String, String) {
        self.sign_and_issue_cert_by_did(&self.did.clone(), item, for_did, for_sys_did, memo)
    }

    pub fn sign_and_issue_cert_by_did(&mut self, issuer_did: &str, item: &str, for_did: &str, for_sys_did: &str, memo: &str)
                                      -> (String, String) {
        if !issuer_did.is_empty() && !for_did.is_empty() && !for_sys_did.is_empty() && !item.is_empty() && !memo.is_empty() &&
            IdClaim::validity(issuer_did) && IdClaim::validity(for_did) && IdClaim::validity(for_sys_did) &&
            item.len() < 32 && memo.len() < 256 {
            let unknown = "Unknown".to_string();
            let cert_secret_base64 = self.crypt_secrets.get(&issue_key!(issuer_did)).unwrap_or(&unknown);
            if cert_secret_base64 != "Unknown" {
                let cert_secret = token_utils::convert_base64_to_key(cert_secret_base64);
                if cert_secret != [0u8; 32] {
                    let item_key = token_utils::derive_key(item.as_bytes(), &token_utils::calc_sha256(&cert_secret)).unwrap_or([0u8; 32]);
                    if item_key != [0u8; 32] {
                        let encrypt_item_key = self.encrypt_for_did(&item_key, for_did, 0);
                        debug!("encrypt_item_key: cert_secret.len={}, item_key.len={}, encrypt_item_key.len={}",
                            cert_secret.len(), item_key.len(), URL_SAFE_NO_PAD.decode(encrypt_item_key.clone()).unwrap().len());
                        let memo_base64 = URL_SAFE_NO_PAD.encode(memo.as_bytes());
                        let timestamp = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)
                            .unwrap_or_else(|_| std::time::Duration::from_secs(0)).as_secs();
                        let cert_text = format!("{}|{}|{}|{}|{}|{}", issuer_did, for_did, item, encrypt_item_key, memo_base64, timestamp);
                        let sig = URL_SAFE_NO_PAD.encode(self.sign_by_issuer_key(&cert_text, &URL_SAFE_NO_PAD.encode(cert_secret)));
                        println!("[UserBase] Sign and issue a cert by did: issuer({}), item({}), owner({}), sys({})", issuer_did, item, for_did, for_sys_did);
                        return (format!("{}|{}|{}", issuer_did, for_did, item), self.encrypt_for_did(format!("{}|{}", cert_text, sig).as_bytes(), for_sys_did, 0))
                    }
                }
            }
        }
        println!("[UserBase] Sign and issue a cert by did: invalid params");
        ("Unknown".to_string(), "Unknown".to_string())
    }


    pub fn sign(&mut self, text: &str) -> Vec<u8> {
        self.sign_by_did(text, &self.did.clone(),"not required")
    }

    pub fn sign_by_did(&mut self, text: &str, did: &str, phrase: &str) -> Vec<u8> {
        let claim = self.get_claim(did);
        token_utils::get_signature(text, &claim.id_type, &claim.get_symbol_hash(), phrase)
    }

    pub fn sign_by_issuer_key(&mut self, text: &str, issuer_key: &str) -> Vec<u8> {
        let issuer_key = token_utils::convert_base64_to_key(issuer_key);
        token_utils::get_signature_by_key(text, &issuer_key)
    }

    pub fn verify(&mut self, text: &str, signature: &str) -> bool {
        self.verify_by_did(text, signature, &self.did.clone())
    }

    pub fn verify_by_did(&mut self, text: &str, signature_str: &str, did: &str) -> bool {
        let claim = self.get_claim(did);
        token_utils::verify_signature(text, signature_str, &claim.get_verify_key())
    }

    pub fn cert_verify_by_did(&mut self, text: &str, signature_str: &str, did: &str) -> bool {
        let claim = self.get_claim(did);
        token_utils::verify_signature(text, signature_str, &claim.get_cert_verify_key())
    }

    pub fn encrypt_for_did(&mut self, text: &[u8], for_did: &str, period:u64) -> String {
        let self_crypt_secret = token_utils::convert_base64_to_key(self.crypt_secrets.get(&exchange_key!(self.did)).unwrap());
        let for_did_public = self.get_claim(for_did).get_crypt_key();
        let shared_key = token_utils::get_diffie_hellman_key(for_did_public, self_crypt_secret);
        let ctext = token_utils::encrypt(text, &shared_key, period);
        URL_SAFE_NO_PAD.encode(ctext)
    }

    pub fn decrypt_by_did(&mut self, ctext: &str, by_did: &str, period:u64) -> String {
        let self_crypt_secret = token_utils::convert_base64_to_key(self.crypt_secrets.get(&exchange_key!(self.did)).unwrap());
        let by_did_public = self.get_claim(by_did).get_crypt_key();
        let shared_key = token_utils::get_diffie_hellman_key(by_did_public, self_crypt_secret);
        let text = token_utils::decrypt(URL_SAFE_NO_PAD.decode(ctext).unwrap().as_slice(), &shared_key, period);
        String::from_utf8_lossy(text.as_slice()).to_string()
    }


    pub fn get_entry_point(&self, user_did: &str, entry_point_id: &str) -> String {
        if user_did==self.admin {
            token_utils::gen_entry_point_of_service(entry_point_id)
        } else { "".to_string() }
    }
    pub fn get_guest_sstoken(&mut self, ua_hash: &str) -> String {
        let guest_did = self.guest.clone();
        self.get_user_sstoken(&guest_did, ua_hash)
    }

    pub fn get_user_sstoken(&mut self, did: &str, ua_hash: &str) -> String {
        if IdClaim::validity(did) {
            let now_sec = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_else(|_| std::time::Duration::from_secs(0)).as_secs();
            let context = self.get_user_context(did);
            if context.is_default() || context.is_expired(){
                return String::from("Unknown")
            }
            let text1 = token_utils::calc_sha256(
                format!("{}|{}|{}", ua_hash, self.crypt_secrets[&exchange_key!(self.did)],
                        self.crypt_secrets[&exchange_key!(self.device)]).as_bytes());
            let text2 = token_utils::calc_sha256(format!("{}",now_sec/2000000).as_bytes());
            let mut text_bytes: [u8; 64] = [0; 64];
            text_bytes[..32].copy_from_slice(&text1);
            text_bytes[32..].copy_from_slice(&text2);
            let text_hash = token_utils::calc_sha256(&text_bytes);
            let did_bytes = did.from_base58().unwrap_or("Unknown".to_string().into_bytes());
            let mut padded_did_bytes: [u8; 32] = [0; 32];
            padded_did_bytes[..11].copy_from_slice(&did_bytes[10..]);
            padded_did_bytes[11..].copy_from_slice(&did_bytes);
            let result: [u8; 32] = text_hash.iter()
                .zip(padded_did_bytes.iter())
                .map(|(&a, &b)| a ^ b)
                .collect::<Vec<u8>>()
                .try_into()
                .expect("Failed to convert Vec<u8> to [u8; 32]");
            result.to_base58()
        } else {
            String::from("Unknown")
        }
    }

    pub fn check_sstoken_and_get_did(&mut self, sstoken: &str, ua_hash: &str) -> String {
        let sstoken_bytes = sstoken.from_base58().unwrap_or([0; 32].to_vec());
        if sstoken.len() != 44 || sstoken_bytes==[0; 32] {
            return String::from("Unknown")
        }
        let mut padded_sstoken_bytes: [u8; 32] = [0; 32];
        padded_sstoken_bytes.copy_from_slice(&sstoken_bytes);
        let now_sec = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_else(|_| std::time::Duration::from_secs(0)).as_secs();
        let text1 = token_utils::calc_sha256(
            format!("{}|{}|{}", ua_hash, self.crypt_secrets[&exchange_key!(self.did)],
                    self.crypt_secrets[&exchange_key!(self.device)]).as_bytes());
        let text2 = token_utils::calc_sha256(format!("{}",now_sec/2000000).as_bytes());
        let mut text_bytes: [u8; 64] = [0; 64];
        text_bytes[..32].copy_from_slice(&text1);
        text_bytes[32..].copy_from_slice(&text2);
        let text_hash = token_utils::calc_sha256(&text_bytes);
        let result: [u8; 32] = text_hash.iter()
            .zip(padded_sstoken_bytes.iter())
            .map(|(&a, &b)| a ^ b)
            .collect::<Vec<u8>>()
            .try_into()
            .expect("Failed to convert Vec<u8> to [u8; 32]");
        let mut did_bytes: [u8; 21] = [0; 21];
        let mut padded: [u8; 11] = [0; 11];
        padded.copy_from_slice(&result[..11]);
        did_bytes.copy_from_slice(&result[11..]);
        let did_bytes_slice = &did_bytes[10..];
        if padded.iter().zip(did_bytes_slice.iter()).all(|(a, b)| a == b) {
            let user_did = did_bytes.to_base58();
            let context = self.get_user_context(&user_did);
            if context.is_default() || context.is_expired(){
                String::from("Unknown")
            } else {
                user_did
            }
        } else {
            let text2 = token_utils::calc_sha256(format!("{}",now_sec/2000000 -1).as_bytes());
            let mut text_bytes: [u8; 64] = [0; 64];
            text_bytes[..32].copy_from_slice(&text1);
            text_bytes[32..].copy_from_slice(&text2);
            let text_hash = token_utils::calc_sha256(&text_bytes);
            let result: [u8; 32] = text_hash.iter()
                .zip(padded_sstoken_bytes.iter())
                .map(|(&a, &b)| a ^ b)
                .collect::<Vec<u8>>()
                .try_into()
                .expect("Failed to convert Vec<u8> to [u8; 32]");
            padded.copy_from_slice(&result[..11]);
            did_bytes.copy_from_slice(&result[11..]);
            let did_bytes_slice = &did_bytes[10..];
            if padded.iter().zip(did_bytes_slice.iter()).all(|(a, b)| a == b) {
                let user_did = did_bytes.to_base58();
                let context = self.get_user_context(&user_did);
                if context.is_default() || context.is_expired(){
                    String::from("Unknown")
                } else {
                    user_did
                }
            } else {
                String::from("Unknown")
            }
        }
    }

    #[staticmethod]
    pub fn get_path_in_root_dir(did: &str, catalog: &str) -> String {
        let path_file = token_utils::get_path_in_root_dir(did, catalog);
        path_file.to_string_lossy().to_string()
    }

    pub fn set_user_base_dir(&mut self, user_base_dir: &str) {
        self.user_base_dir = {
            let mut claims = self.claims.lock().unwrap();
            claims.set_user_base_dir(user_base_dir);
            user_base_dir.to_string()
        };
    }

    pub fn get_user_path_in_root(&self, root: &str, user_did: &str) -> String {
        let root_dir = PathBuf::from(root);
        let did_path =
            self.device.from_base58().expect("Failed to decode base58").iter()
                .zip(user_did.from_base58().expect("Failed to decode base58").iter())
                .map(|(&x, &y)| x ^ y).collect::<Vec<_>>().to_base58();

        if !IdClaim::validity(user_did) || self.is_guest(user_did) {
            root_dir.join("guest_user").to_string_lossy().to_string()
        } else if self.is_admin(user_did) {
            root_dir.join(format!("admin_{}", did_path)).to_string_lossy().to_string()
        } else {
            root_dir.join(did_path).to_string_lossy().to_string()
        }
    }


    pub fn get_path_in_user_dir(&self, did: &str, catalog: &str) -> String {
        let claims = self.claims.lock().unwrap();
        claims.get_path_in_user_dir(did, catalog)
    }

    pub fn get_private_paths_list(&self, did: &str, catalog: &str) -> Vec<String> {
        let catalog_paths = self.get_path_in_user_dir(did, catalog);
        let filters = &[];
        let suffixes = &[".json"];
        token_utils::filter_files(&Path::new(&catalog_paths), filters, suffixes)
    }


    pub fn get_private_paths_datas(&self, user_context: &UserContext, catalog: &str, filename: &str) -> String {
        let file_paths = Path::new(&self.get_path_in_user_dir(&user_context.get_did(), catalog)).join(filename);
        match file_paths.exists() {
            true => {
                let crypt_key = user_context.get_crypt_key();
                match fs::read(file_paths) {
                    Ok(raw_data) => {
                        let data = token_utils::decrypt(&raw_data, &crypt_key, 0);
                        let private_datas = serde_json::from_slice(&data).unwrap_or(serde_json::json!({}));
                        private_datas.to_string()
                    },
                    Err(_) => "Unknowns".to_string(),
                }
            }
            false => "Unknowns".to_string(),
        }
    }

    pub fn get_guest_user_context(&mut self) -> UserContext {
        let guest_did = self.get_guest_did();
        self.get_user_context(&guest_did)
    }

    pub fn check_local_user_token(&mut self, nickname: &str, telephone: &str) -> String {
        let nickname = nickname.chars().take(24).collect::<String>();
        if !token_utils::is_valid_telephone(telephone) {
            return "unknown".to_string();
        }
        let symbol_hash = IdClaim::get_symbol_hash_by_source(&nickname, telephone);
        let symbol_hash_base64 = URL_SAFE_NO_PAD.encode(symbol_hash);
        let (user_hash_id, _user_phrase) = token_utils::get_key_hash_id_and_phrase("User", &symbol_hash);
        match token_utils::exists_key_file("User", &symbol_hash) {
            true => {
                if token_utils::is_original_user_key(&symbol_hash)  {
                    let ready_data = {
                        let ready_users = self.ready_users.lock().unwrap();
                        match ready_users.get(&user_hash_id) {
                            Ok(Some(ready_data)) => String::from_utf8(ready_data.to_vec()).unwrap(),
                            _ => "Unknown".to_string(),
                        }
                    };
                    if ready_data != "Unknown" {
                        let parts: Vec<&str> = ready_data.split('|').collect();
                        let old_user_did = match parts.len() >= 3 {
                            true => parts[1].to_string(),
                            false => "Unknown".to_string(),
                        };
                        if old_user_did != "Unknown" && !self.is_registered(&old_user_did) { // 没有经过身份验证的处理
                            debug!("user_key is exist but the code is not verified : {}, {}", nickname, user_hash_id);
                            return "remote".to_string();
                        } // 经过验证但默认身份口令未改的处理
                        debug!("user_key is exist and the phrase hasn't been updated: {}, {}", nickname, user_hash_id);
                        "immature".to_string()
                    } else { // 身份预备数据丢失的处理
                        self.remove_user(&symbol_hash_base64);
                        debug!("user_key is exist but the ready data is empty: {}, {}", nickname, user_hash_id);
                        "re_input".to_string()
                    }
                } else {
                    "local".to_string()
                }
            },
            false => {
                let identity_file = token_utils::get_path_in_sys_key_dir(&format!("user_identity_{}.token", user_hash_id));
                match identity_file.exists() {
                    true => "local".to_string(),
                    false => {
                        println!("[UserBase] The identity is not in local and generate ready_data for new user: {}", nickname);
                        let (user_did, _user_phrase) = self.create_user(&nickname, telephone, None, None);
                        let new_claim = self.get_claim(&user_did);
                        debug!("create new claim: symbol={}, claim_symbol={}",
                            symbol_hash_base64, URL_SAFE_NO_PAD.encode(new_claim.get_symbol_hash()));

                        let mut request: serde_json::Value = json!({});
                        request["telephone"] = serde_json::to_value(telephone).unwrap_or(json!(""));
                        request["claim"] = serde_json::to_value(new_claim.clone()).unwrap_or(json!(""));

                        let user_claim_result = self.request_token_api(
                            "apply2",
                            &serde_json::to_string(&request).unwrap_or("{}".to_string()),);
                        println!("[UserBase] Apply to verify user: symbol({}), result({})", symbol_hash_base64, user_claim_result);
                        if !user_claim_result.starts_with("Unknown") {
                            let ready_data = format!("{}|{}|{}", 3, user_did, user_claim_result);
                            //let ready_data = serde_json::to_string(&ready_data).unwrap_or("Unknown".to_string());
                            let ivec_data = sled::IVec::from(ready_data.as_bytes());
                            {
                                let ready_users = self.ready_users.lock().unwrap();
                                let _ = ready_users.insert(&user_hash_id, ivec_data);
                            }
                            println!("[UserBase] User apply is ok, ready to verify with vcode: did({}), ready_data({})", user_did, ready_data);
                            "remote".to_string()
                        } else {
                            println!("[UserBase] User apply is failure: did({}), symbol({})", user_did, symbol_hash_base64);
                            self.remove_user(&symbol_hash_base64);
                            "unknown".to_string()
                        }
                    }
                }
            }
        }
    }

    pub fn check_user_verify_code(&mut self, nickname: &str, telephone: &str, vcode: &str)-> String {
        let nickname = nickname.chars().take(24).collect::<String>();
        let symbol_hash = IdClaim::get_symbol_hash_by_source(&nickname, telephone);
        let (user_hash_id, user_phrase) = token_utils::get_key_hash_id_and_phrase("User", &symbol_hash);
        let symbol_hash_base64 = URL_SAFE_NO_PAD.encode(symbol_hash);
        let ready_data = {
            let ready_users = self.ready_users.lock().unwrap();
            match ready_users.get(&user_hash_id) {
                Ok(Some(ready_data)) => String::from_utf8(ready_data.to_vec()).unwrap(),
                _ => "Unknown".to_string(),
            }
        };
        if ready_data != "Unknown" {
            let parts: Vec<&str> = ready_data.split('|').collect();
            debug!("ready_data: {:?}", parts);
            if parts.len() >= 3 {
                let mut try_count = parts[0].parse::<i32>().unwrap_or(0);
                let old_user_did = parts[1].to_string();
                let encrypted_user_claim_string = parts[2].to_string();
                try_count -= 1;
                if try_count >= 0 {
                    let user_claim_text = token_utils::decrypt_text_with_vcode(vcode, &encrypted_user_claim_string);
                    if user_claim_text != "Unknown" {
                        let _ = {
                            let ready_users = self.ready_users.lock().unwrap();
                            let _ = ready_users.remove(user_hash_id);
                        };
                        debug!("user_claim_text: {}, symbol({})", user_claim_text, symbol_hash_base64);
                        //let upstream_did = self.get_upstream_did();
                        //let user_claim_text = self.decrypt_by_did(&encrypted_user_claim_base64, &upstream_did, 0);

                        match serde_json::from_str::<IdClaim>(&user_claim_text) {
                            Ok(user_claim) => {
                                let user_did = user_claim.gen_did();
                                println!("[UserBase] The decoding the claim from Root is correct: local_symbol({}), user_did({}), cert({})",
                                         symbol_hash_base64, user_did, user_claim_text);
                                let result_return = match old_user_did == user_did {
                                    true => {
                                        println!("[UserBase] Identity confirmed to create new user: create({})", user_did);
                                        "create".to_string()
                                    }
                                    false => {
                                        println!("[UserBase] Identity confirmed to recall user from root: remote({})", user_did);
                                        self.remove_user(&symbol_hash_base64);
                                        self.push_claim(&user_claim);
                                        "recall".to_string()
                                    }
                                };
                                let mut request: serde_json::Value = json!({});
                                request["user_symbol"] = serde_json::to_value(symbol_hash_base64).unwrap();
                                request["user_vcode"] = serde_json::to_value(vcode).unwrap();
                                let user_copy_hash_id = token_utils::get_user_copy_hash_id_by_source(&nickname, telephone, &user_phrase);
                                request["user_copy_hash_id"] = serde_json::to_value(user_copy_hash_id).unwrap_or(json!(""));

                                let result = self.request_token_api(
                                    "confirm2",
                                    &serde_json::to_string(&request).unwrap_or("{}".to_string()),);
                                if !result.starts_with("Unknown") {
                                    if result.len() > 32 && !self.get_upstream_did().is_empty() {
                                        let upstream_did = self.get_upstream_did();
                                        let user_certificate_text = self.decrypt_by_did(&result, &upstream_did, 0);
                                        println!("[UserBase] Get user certificate : did({}), cert({})", user_did, user_certificate_text);
                                        let result_user_did = {
                                            let mut certificates = self.certificates.lock().unwrap();
                                            certificates.push_user_cert_text(&format!("{}|{}|{}|{}", token_utils::TOKEN_TM_DID, user_did, "Member", user_certificate_text))
                                        };
                                        if result_user_did != "Unknown" && result_user_did == user_did {
                                            return result_return;
                                        }
                                    }
                                }
                                println!("[UserBase] Get user certificate fail: did({})", user_did);
                                return "error in confirming".to_string();
                            }
                            Err(e) => {
                                println!("[UserBase] Identity confirm fail: did({}), error({})", old_user_did, e);
                                self.remove_user(&symbol_hash_base64);
                                return "error in confirming".to_string();
                            }
                        }
                    } else {
                        println!("[UserBase] The decoding the claim from Root is incorrect: symbol({}), old_did({})",
                                 symbol_hash_base64, old_user_did);
                        let ready_data = format!("{}|{}|{}", try_count, old_user_did, encrypted_user_claim_string);
                        let ready_data = serde_json::to_string(&ready_data).unwrap_or("Unknown".to_string());
                        let ivec_data = sled::IVec::from(ready_data.as_bytes());
                        {
                            let ready_users = self.ready_users.lock().unwrap();
                            let _ = ready_users.insert(&user_hash_id, ivec_data);
                        }
                        return format!("error:{}", try_count).to_string();
                    }
                } else {
                    let _ = {
                        let ready_users = self.ready_users.lock().unwrap();
                        let _ = ready_users.remove(user_hash_id);
                    };
                    println!("[UserBase] The try_count of verify the code has run out: symbol({}), did({})", symbol_hash_base64, old_user_did);
                }
            } else {
                println!("[UserBase] The ready data is error: symbol({}), ready_data({})", symbol_hash_base64, ready_data);
            }
        }
        self.remove_user(&symbol_hash_base64);
        "error:0".to_string()
    }


    // 检查本地身份：没有则提前create user，提交远端确认，返回claim
    // 验证码验证：通过则保存claim，不通过则删除预创建用户，vcode提交确认，返回cert，解开，保存cert
    // 设置口令：先检查是否已注册，然后用原始phrase改新的phrase，再提交backup，创建context
    // 验证口令：检验本地身份key有效性，不行看本地身份文件，再不行从云端拉副本

    pub fn set_phrase_and_get_context(&mut self, nickname: &str, telephone: &str, phrase: &str) -> UserContext {
        let nickname = nickname.chars().take(24).collect::<String>();
        let symbol_hash = IdClaim::get_symbol_hash_by_source(&nickname, telephone);
        let user_did = self.reverse_lookup_did_by_symbol(symbol_hash);
        if user_did != "Unknown" && !self.is_registered(&user_did) {
            println!("[UserBase] The user hasn't been verified by root: {}, {}.", nickname, user_did);
            return self.get_guest_user_context()
        }

        let (_user_hash_id, user_phrase) = token_utils::get_key_hash_id_and_phrase("User", &symbol_hash);
        if token_utils::is_original_user_key(&symbol_hash)  {
            let _ = token_utils::change_phrase_for_pem(&symbol_hash, &user_phrase, phrase);
        } else {
            println!("[UserBase] The user_key phrase has been changed and do not to be set: {}, {}.", nickname, user_did);
            return self.get_guest_user_context()
        }

        let context = self.sign_user_context(&user_did, phrase);
        if context.is_default() {
            println!("[UserBase] The user maybe in blacklist: {}", user_did);
            return self.get_guest_user_context()
        }
        let user_copy_to_cloud = self.get_user_copy_string(&user_did, phrase);
        let old_user_copy_hash_id = token_utils::get_user_copy_hash_id_by_source(&nickname, telephone, &user_phrase);
        let user_copy_hash_id = token_utils::get_user_copy_hash_id_by_source(&nickname, telephone, phrase);

        let mut request: serde_json::Value = json!({});
        request["old_user_copy_hash_id"] = serde_json::to_value(old_user_copy_hash_id).unwrap();
        request["user_copy_hash_id"] = serde_json::to_value(user_copy_hash_id).unwrap();
        request["data"] = serde_json::to_value(user_copy_to_cloud).unwrap();
        let params = serde_json::to_string(&request).unwrap_or("{}".to_string());
        let result = self.request_token_api("submit_user_copy", &params);
        if result != "Backup_ok" {
            let encoded_params = self.encrypt_for_did(params.as_bytes(), &self.upstream_did.clone() ,0);
            let user_copy_file = token_utils::get_path_in_sys_key_dir(&format!("user_copy_{}_uncompleted.json", user_did));
            fs::write(user_copy_file.clone(), encoded_params).expect(&format!("Unable to write file: {}", user_copy_file.display()));
        }
        println!("[UserBase] After set phrase, then upload encrypted_user_copy: {}, {}", user_did, params);
        context
    }
    pub fn get_user_context_with_phrase(&mut self, nickname: &str, telephone: &str, phrase: &str) -> UserContext {
        let nickname = nickname.chars().take(24).collect::<String>();
        if Self::is_valid_telephone(telephone) {
            let symbol_hash = IdClaim::get_symbol_hash_by_source(&nickname, telephone);
            let user_did = self.reverse_lookup_did_by_symbol(symbol_hash);
            let (user_hash_id, _user_phrase) = token_utils::get_key_hash_id_and_phrase("User", &symbol_hash);
            match token_utils::exists_and_valid_user_key(&symbol_hash, phrase) && user_did != "Unknown" {
                true => {
                    println!("[UserBase] Get user context:{} from local key file: .token_user_{}.pem", user_did, user_hash_id);
                    let context = self.sign_user_context(&user_did, phrase);
                    if context.is_default() {
                        println!("[UserBase] The user hasn't been verified by root or in blacklist: {}", user_did);
                        self.get_guest_user_context()
                    } else { context }
                },
                false => {
                    let identity_file = token_utils::get_path_in_sys_key_dir(&format!("user_identity_{}.token", user_hash_id));
                    match identity_file.exists() {
                        true => {
                            println!("[UserBase] Get user encrypted copy from identity file: {}, user_identity_{}.token", user_did, user_hash_id);
                            let encrypted_identity = fs::read_to_string(identity_file.clone()).expect(&format!("Unable to read file: {}", identity_file.display()));
                            let user_did = self.import_user(&user_hash_id, &encrypted_identity, phrase);
                            let context = self.sign_user_context(&user_did, phrase);
                            if context.is_default() {
                                println!("[UserBase] The user hasn't been verified by root or in blacklist: {}", user_did);
                                self.get_guest_user_context()
                            } else { context }
                        }
                        false => {
                            let mut request: serde_json::Value = json!({});
                            let user_copy_hash_id = token_utils::get_user_copy_hash_id_by_source(&nickname, telephone, phrase);
                            request["user_copy_hash_id"] = serde_json::to_value(&user_copy_hash_id).unwrap();
                            request["user_symbol"] = serde_json::to_value(URL_SAFE_NO_PAD.encode(symbol_hash)).unwrap();
                            let user_copy_from_cloud =
                                self.request_token_api("get_user_copy", &serde_json::to_string(&request).unwrap_or("{}".to_string()), );

                            match user_copy_from_cloud != "Unknown".to_string() &&
                                user_copy_from_cloud != "Unknown_user".to_string() &&
                                user_copy_from_cloud != "Unknown_backup".to_string() {
                                true => {
                                    let user_copy_from_cloud_array: Vec<&str> = user_copy_from_cloud.split("|").collect();
                                    if user_copy_from_cloud_array.len() >= 3 {
                                        let encrypted_identity = user_copy_from_cloud_array[0];
                                        println!("[UserBase] Download user encrypted_copy: {}, len={}", user_hash_id, encrypted_identity.len());
                                        let user_did = self.import_user(&user_hash_id, &encrypted_identity, phrase);
                                        let identity_file = token_utils::get_path_in_sys_key_dir(&format!("user_identity_{}.token", user_hash_id));
                                        fs::write(identity_file.clone(), encrypted_identity).expect(&format!("Unable to write file: {}", identity_file.display()));
                                        println!("[UserBase] Parsing encrypted_copy and save identity_file: {}, {}", user_hash_id, user_did);

                                        if token_utils::exists_and_valid_user_key(&symbol_hash, phrase) {
                                            println!("[UserBase] The user encrypted copy is valid: {}", user_did);

                                            let certificate_string = String::from_utf8_lossy(token_utils::decrypt(&URL_SAFE_NO_PAD.decode(
                                                user_copy_from_cloud_array[2]).unwrap(), phrase.as_bytes(), 0).as_slice()).to_string();

                                            let certificate_string = certificate_string.replace(":", "|");
                                            let certs_array: Vec<&str> = certificate_string.split(",").collect();
                                            for cert in &certs_array {
                                                let mut certificates = self.certificates.lock().unwrap();
                                                let _user_did = certificates.push_user_cert_text(cert);
                                            }

                                            let _context_string = String::from_utf8_lossy(token_utils::decrypt(&URL_SAFE_NO_PAD.decode(
                                                user_copy_from_cloud_array[1]).unwrap(), phrase.as_bytes(), 0).as_slice()).to_string();
                                            // 取回的context里的sys_did不一定是本地系统的sys_did，需要考虑如何迁移context
                                            //let _ = token_utils::update_user_token_to_file(&serde_json::from_str::<UserContext>(&context_string)
                                            //    .unwrap_or(UserContext::default()), "add");

                                            let context = self.sign_user_context(&user_did, phrase);
                                            if context.is_default() {
                                                println!("[UserBase] The user hasn't been verified by root or in blacklist: {}", user_did);
                                                self.get_guest_user_context()
                                            } else { context }

                                        } else {
                                            println!("[UserBase] The user encrypted copy is not valid: {}", user_did);
                                            self.get_guest_user_context()
                                        }

                                    } else {
                                        println!("[UserBase] The user encrypted copy is not valid: {}", user_hash_id);
                                        self.get_guest_user_context()
                                    }
                                },
                                false => {
                                    println!("[UserBase] The user encrypted copy is not valid: {}", user_hash_id);
                                    self.get_guest_user_context()
                                }
                            }
                        }
                    }
                }
            }
        } else {
            println!("[UserBase] The telephone is not valid: {}", telephone);
            self.get_guest_user_context()
        }
    }

    pub fn unbind_and_return_guest(&mut self, user_did: &str, phrase: &str) -> UserContext {
        if IdClaim::validity(user_did) {
            let claim = self.get_claim(user_did);
            let symbol_hash =claim.get_symbol_hash();
            let context = self.get_user_context(&user_did);
            let user_copy_to_cloud = self.get_user_copy_string(&user_did, phrase);
            let user_copy_hash_id = token_utils::get_user_copy_hash_id(&claim.nickname, &claim.telephone_hash, phrase);
            let mut request: serde_json::Value = json!({});
            request["user_symbol"] = serde_json::to_value(URL_SAFE_NO_PAD.encode(symbol_hash)).unwrap();
            request["user_copy_hash_id"] = serde_json::to_value(user_copy_hash_id).unwrap();
            request["data"] = serde_json::to_value(user_copy_to_cloud).unwrap();
            let params = serde_json::to_string(&request).unwrap_or("{}".to_string());
            let result = self.request_token_api("unbind_node", &params);
            if result != "Unbind_ok" {
                let encoded_params = self.encrypt_for_did(params.as_bytes(), &self.upstream_did.clone() ,0);
                let unbind_node_file = token_utils::get_path_in_sys_key_dir(&format!("unbind_node_{}_uncompleted.json", user_did));
                fs::write(unbind_node_file.clone(), encoded_params).expect(&format!("Unable to write file: {}", unbind_node_file.display()));
            }
            // release user token and conext
            if user_did != self.admin {
                let key = format!("{}_{}", user_did, self.get_sys_did());
                let authorized = self.authorized.lock().unwrap();
                let _ = match authorized.contains_key(&key).unwrap() {
                    false => {},
                    true => {
                        let _ = authorized.remove(&key);
                    }
                };
                let _ = token_utils::update_user_token_to_file(&context, "remove");
            }
            println!("[UserBase] Unbind user({}) from node({}): {}", user_did, self.did, result);
        }
        self.get_guest_user_context()
    }

    pub fn get_user_copy_string(&mut self, user_did: &str, phrase: &str) -> String {
        let symbol_hash = self.get_claim(user_did).get_symbol_hash();
        let (user_hash_id, _user_phrase) = token_utils::get_key_hash_id_and_phrase("User", &symbol_hash);
        let context = self.get_user_context(&user_did);
        let identity_file = token_utils::get_path_in_sys_key_dir(&format!("user_identity_{}.token", user_hash_id));
        let encrypted_identity = fs::read_to_string(identity_file).unwrap_or("".to_string());
        let context_json = serde_json::to_string(&context).unwrap_or("Unknown".to_string());
        let context_crypt = URL_SAFE_NO_PAD.encode(token_utils::encrypt(context_json.as_bytes(), phrase.as_bytes(), 0));
        let certificates = {
            let certificates = self.certificates.lock().unwrap();
            certificates.filter_user_certs(&user_did, "*")
        };
        let certificates_str = certificates
            .iter()
            .map(|(key, value)| format!("{}:{}", key, value))
            .collect::<Vec<String>>()
            .join(",");
        let _ = certificates_str.replace("|", ":");
        let certificate_crypt = URL_SAFE_NO_PAD.encode(token_utils::encrypt(certificates_str.as_bytes(), phrase.as_bytes(), 0));
        format!("{}|{}|{}", encrypted_identity, context_crypt, certificate_crypt)
    }

    pub fn get_user_context(&mut self, did: &str) -> UserContext {
        if !IdClaim::validity(did) {
            return UserContext::default();
        }
        let key = format!("{}_{}", did, self.get_sys_did());
        if !self.blacklist.contains(&did.to_string()) {
            let context = {
                let authorized = self.authorized.lock().unwrap();
                match authorized.get(&key) {
                    Ok(Some(context)) => {
                        let context_string = String::from_utf8(context.to_vec()).unwrap();
                        let user_token: serde_json::Value = serde_json::from_slice(&context_string.as_bytes()).unwrap_or(serde_json::json!({}));
                        serde_json::from_value(user_token.clone()).unwrap_or_else(|_| UserContext::default())
                    },
                    _ => token_utils::get_user_token_from_file(did, &self.get_sys_did())
                }
            };
            if !context.is_default() && context.get_sys_did() == self.did &&
                self.verify_by_did(&context.get_text(), &context.get_sig(), did) {
                let ivec_data = sled::IVec::from(context.to_json_string().as_bytes());
                {
                    let authorized = self.authorized.lock().unwrap();
                    let _ = authorized.insert(&key, ivec_data);
                }
                context
            } else {
                if context.is_default() && did == &self.guest {
                    self.sign_user_context(&self.guest.clone(), &self.guest_phrase.clone())
                } else {
                    UserContext::default()
                }
            }

        } else { UserContext::default()  }
    }

    pub(crate) fn sign_user_context(&mut self, did: &str, phrase: &str) -> UserContext {
        if self.blacklist.contains(&did.to_string()) || (did != self.guest && !self.is_registered(did)) {
            return UserContext::default();
        }
        let claim = self.get_claim(did);
        let mut context = token_utils::get_or_create_user_context_token(
            did, &self.did, &claim.nickname, &claim.id_type, &claim.get_symbol_hash(), phrase);
        let _ = context.signature(phrase);
        if token_utils::update_user_token_to_file(&context, "add") == "Ok"  {
            if self.admin.is_empty() && did != self.guest {
                self.admin = did.to_string();
                token_utils::save_secret_to_system_token_file(&self.crypt_secrets, &self.did, &self.admin);
                println!("[UserBase] Set admin_did/设置系统管理 = {}", self.admin);
            }
            {
                let ivec_data = sled::IVec::from(context.to_json_string().as_bytes());
                let authorized = self.authorized.lock().unwrap();
                let _ = authorized.insert(&format!("{}_{}", did, self.get_sys_did()), ivec_data);
            }
            context
        } else {
            debug!("Failed to save user token");
            UserContext::default()
        }
    }


    #[staticmethod]
    fn is_valid_telephone(user_telephone: &str) -> bool {
        if user_telephone.chars().all(|c| c.is_digit(10)) {
            let len = user_telephone.len();
            return len >= 11 && len <= 16;
        }
        false
    }

    fn reverse_lookup_did_by_symbol(&self, symbol_hash: [u8; 32]) -> String {
        let claims = self.claims.lock().unwrap();
        claims.reverse_lookup_did_by_symbol(&symbol_hash)
    }

    #[staticmethod]
    fn request_token_api_register(sys_claim: &IdClaim, dev_claim: &IdClaim) -> String  {
        let sys_did = sys_claim.gen_did();
        let device_did = dev_claim.gen_did();
        let mut request: serde_json::Value = json!({});
        request["system_claim"] = serde_json::to_value(&sys_claim).unwrap_or(json!(""));
        request["device_claim"] = serde_json::to_value(&dev_claim).unwrap_or(json!(""));
        let params = serde_json::to_string(&request).unwrap_or("{}".to_string());
        token_utils::TOKIO_RUNTIME.block_on(async {
            request_token_api_async(&sys_did, &device_did, "register", &params).await
        })
    }

    fn request_token_api(&mut self, api_name: &str, params: &str) -> String  {
        let upstream_did = self.upstream_did.clone();
        if upstream_did.is_empty() {
            return "Unknown".to_string()
        }
        let encoded_params = self.encrypt_for_did(params.as_bytes(), &upstream_did ,0);
        token_utils::TOKIO_RUNTIME.block_on(async {
            debug!("[UpstreamClient] request api_{} with params: {}", api_name, params);
            request_token_api_async(&self.did, &self.device, api_name, &encoded_params).await
        })
    }

    pub fn check_ready(&self, v1: String, v2: String, v3: String, root: String) -> i32 {
        let start = Instant::now();
        let mut feedback_code = 0;
        if !EnvData::check_basepkg(&root) {
            println!("[SimpleAI] 程序所需基础模型包有检测异常，未完全正确安装。请检查并正确安装后，再启动程序。");
            feedback_code += 2;
        }
        let mut sysinfo = self.get_sysinfo();
        loop {
            if sysinfo.pyhash != "Unknown" {
                break;
            }
            if start.elapsed() > Duration::from_secs(15) {
                println!("[SimpleAI] 系统检测异常，继续运行会影响程序正确执行。请检查系统环境后，重新启动程序。");
                feedback_code += 1;
                break;
            }
            thread::sleep(Duration::from_secs(1));
            sysinfo = self.get_sysinfo();
        }

        let target_pyhash= EnvData::get_pyhash(&v1, &v2, &v3);
        let check_pyhash = EnvData::get_check_pyhash(&sysinfo.pyhash.clone());
        if target_pyhash != "Unknown" && target_pyhash != check_pyhash {
            let now_sec = SystemTime::now().duration_since(UNIX_EPOCH)
                .unwrap_or_else(|_| std::time::Duration::from_secs(0)).as_secs();
            let pyhash_display = URL_SAFE_NO_PAD.encode(token_utils::calc_sha256(
                format!("{}-{}", sysinfo.pyhash, (now_sec/100000*100000).to_string())
                    .as_bytes()));

            println!("[SimpleAI] 所运行程序为非官方版本，请正确使用开源软件，{}。", &pyhash_display[..16]);
            feedback_code += 4;
        }

        feedback_code
    }

    pub fn get_pyhash(&self) -> String {
        let sysinfo = self.get_sysinfo();
        let pyhash = EnvData::get_check_pyhash(&sysinfo.pyhash.clone());
        pyhash
    }

    pub fn get_pyhash_key(&self, v1: String, v2: String, v3: String) -> String {
        return EnvData::get_pyhash_key(&v1, &v2, &v3);
    }

}

async fn request_token_api_async(sys_did: &str, dev_did: &str, api_name: &str, encoded_params: &str) -> String  {
    let encoded_params = encoded_params.to_string();
    match token_utils::REQWEST_CLIENT.post(format!("{}{}", token_utils::TOKEN_TM_URL, api_name))
        .header("Sys-Did", sys_did.to_string())
        .header("Dev-Did", dev_did.to_string())
        .body(encoded_params)
        .send()
        .await{
        Ok(res) => {
            let status_code = res.status();
            match res.text().await {
                Ok(text) => {
                    debug!("[Upstream] response: {}", text);
                    if status_code.is_success() {
                        let result = serde_json::from_str(&text).unwrap_or("".to_string());
                        debug!("[Upstream] result: {}", result);
                        result
                    } else {
                        debug!("status_code is unsuccessful: {},{}", status_code, text);
                        format!("Unknown_{}", status_code).to_string()
                    }
                },
                Err(e) => {
                    debug!("Failed to read response body: {},{}", status_code,e);
                    "Unknown".to_string()
                }
            }
        },
        Err(e) => {
            debug!("Failed to request token api: {}", e);
            "Unknown".to_string()
        }
    }
}

async fn submit_uncompleted_request_files(sys_did: &str, dev_did: &str) {
    let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(5)); // 设置检查周期

    loop {
        interval.tick().await; // 等待下一个周期
        let user_copy_file = token_utils::get_path_in_sys_key_dir("user_copy_xxxxx.json");
        let user_copy_path = match user_copy_file.parent() {
            Some(parent) => {
                if parent.exists() {
                    parent
                } else {
                    fs::create_dir_all(parent).unwrap();
                    parent
                }
            },
            None => panic!("{}", format!("File path does not have a parent directory: {:?}", user_copy_file)),
        };
        // 遍历目录中的所有文件
        if let Ok(mut entries) = tokio::fs::read_dir(user_copy_path).await {
            while let Some(entry) = entries.next_entry().await.transpose() {
                if let Ok(entry) = entry {
                    let file_path = entry.path();
                    if file_path.is_file() {
                        if let Some(file_name) = file_path.file_name() {
                            if let Some(file_name_str) = file_name.to_str() {
                                if let Some(method) = extract_method_from_filename(file_name_str) {
                                    if let Ok(content) = tokio::fs::read_to_string(&file_path).await {
                                        debug!("submit uncompleted request file: method={}, {}", method, file_path.display());
                                        let result = request_token_api_async(sys_did, dev_did, &method, &content).await;
                                        if result != "Unknown"  {
                                            tokio::fs::remove_file(&file_path).await.expect("remove user copy file failed");
                                            debug!("remove the uncompleted request file: {}", file_path.display());
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
fn extract_method_from_filename(file_name: &str) -> Option<String> {
    let re = regex::Regex::new(r"^(.+?)_([a-zA-Z0-9]{29})_uncompleted\.json$").unwrap();
    if let Some(captures) = re.captures(file_name) {
        if let Some(method) = captures.get(1) {
            return Some(method.as_str().to_string());
        }
    }
    None
}
