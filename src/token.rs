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


use pyo3::prelude::*;

use crate::token_utils;
use crate::{exchange_key, issue_key};
use crate::error::TokenError;
use crate::env_data::EnvData;
use crate::claims::{GlobalClaims, IdClaim, UserContext};
use crate::systeminfo::SystemInfo;
use crate::cert_center::GlobalCerts;

pub(crate) static TOKEN_API_VERSION: &str = "v1.1.1";



#[derive(Clone, Debug)]
#[pyclass]
pub struct SimpleAI {
    pub sys_name: String,
    pub did: String,
    token_db: Arc<Mutex<sled::Db>>,
    // 用户绑定授权的缓存，来自user_{did}.token
    pub authorized: Arc<Mutex<sled::Tree>>, //HashMap<String, UserContext>,
    pub user_sessions: Arc<Mutex<sled::Tree>>, //HashMap<sessionid_key, String>,
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
    device: String,
    admin: String,
    node_mode: String,
    guest: String,
    guest_phrase: String,
    ready_users: Arc<Mutex<sled::Tree>>, //HashMap<String, serde_json::Value>,
    blacklist: Vec<String>, // 黑名单
    upstream_did: String,
    user_base_dir: String,
    global_local_vars: Arc<Mutex<sled::Tree>>, //HashMap<global|admin|{did}_{key}, String>,
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

        let sysbaseinfo = token_utils::SYSTEM_BASE_INFO.clone();
        let sysinfo_handle = token_utils::TOKIO_RUNTIME.spawn(async move {
            SystemInfo::generate().await
        });

        let (system_name, sys_phrase, device_name, device_phrase, guest_name, guest_phrase)
            = GlobalClaims::get_system_vars();
        debug!("system_name:{}, device_name:{}, guest_name:{}", system_name, device_name, guest_name);

        let claims = GlobalClaims::instance();
        let (local_did, local_claim, device_did, device_claim, guest_did, guest_claim) = {
            let mut claims = claims.lock().unwrap();
            claims.init_sys_dev_guest_did()
        };

        let mut crypt_secrets = HashMap::new();
        let admin = token_utils::load_token_by_authorized2system(&local_did, &mut crypt_secrets);
        let blacklist = token_utils::load_did_blacklist_from_file();

        debug!("get admin and blacklist: admin={}, blacklist={:?}", admin, blacklist);

        let crypt_secrets_len = crypt_secrets.len();
        token_utils::init_user_crypt_secret(&mut crypt_secrets, &local_claim, &sys_phrase);
        token_utils::init_user_crypt_secret(&mut crypt_secrets, &device_claim, &device_phrase);

        let root_dir = sysbaseinfo.root_dir.clone();
        let disk_uuid = sysbaseinfo.disk_uuid.clone();
        let guest_symbol_hash = IdClaim::get_symbol_hash_by_source(&guest_name, None, Some(format!("{}:{}", root_dir.clone(), disk_uuid.clone())));
        debug!("guest_symbol_hash=by_source{}, by_claim({})", URL_SAFE_NO_PAD.encode(guest_symbol_hash), URL_SAFE_NO_PAD.encode(guest_claim.get_symbol_hash()));
        let (guest_hash_id, guest_phrase) = token_utils::get_key_hash_id_and_phrase("User", &guest_claim.get_symbol_hash());
        debug!("guest_name({}): guest_symbol_hash={}, guest_hash_id={}, guest_phrase={}", guest_claim.nickname, URL_SAFE_NO_PAD.encode(guest_claim.get_symbol_hash()), guest_hash_id, guest_phrase);

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
        let (authorized_tree, ready_users_tree, user_sessions_tree, global_local_vars_tree) = {
            let token_db = token_db.lock().unwrap();
            (token_db.open_tree("authorized").unwrap(), token_db.open_tree("ready_users").unwrap(),
             token_db.open_tree("user_sessions").unwrap(), token_db.open_tree("global_local_vars").unwrap())
        };
        let authorized = Arc::new(Mutex::new(authorized_tree));
        let ready_users = Arc::new(Mutex::new(ready_users_tree));
        let user_sessions = Arc::new(Mutex::new(user_sessions_tree));
        let global_local_vars = Arc::new(Mutex::new(global_local_vars_tree));

        let sysinfo = token_utils::TOKIO_RUNTIME.block_on(async {
            sysinfo_handle.await.expect("Sysinfo Task panicked")
        });

        let sys_did = local_did.clone();
        let dev_did = device_did.clone();
        let sysinfo_clone = sysinfo.clone();
        let _logging_handle = token_utils::TOKIO_RUNTIME.spawn(async move {
            submit_uncompleted_request_files(&sys_did, &dev_did).await
        });

        let upstream_did = if admin == token_utils::TOKEN_TM_DID {
            token_utils::TOKEN_TM_DID.to_string()
        } else { "".to_string() };
        debug!("upstream_did: {}", upstream_did);
        debug!("init context finished: crypt_secrets.len={}", crypt_secrets.len());

        let admin = if !admin.is_empty() {
            if guest_did != admin {
                let mut claims = claims.lock().unwrap();
                claims.set_admin_did(&admin);
                admin
            } else { "".to_string()  }
        } else { admin };

        Self {
            sys_name,
            did: local_did,
            device: device_did,
            admin,
            node_mode: "online".to_string(),
            token_db,
            authorized,
            user_sessions,
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
            global_local_vars,
        }
    }


    pub fn get_sys_name(&self) -> String { self.sys_name.clone() }
    pub fn get_sys_did(&self) -> String { self.did.clone() }
    pub fn get_upstream_did(&mut self) -> String {
        if self.admin == token_utils::TOKEN_TM_DID {
            return token_utils::TOKEN_TM_DID.to_string()
        }
        let start_time = Instant::now();
        let timeout = Duration::from_secs(30);

        loop {
            if !self.upstream_did.is_empty() && !self.upstream_did.starts_with("Unknown"){
                return self.upstream_did.clone();
            }
            let (local_claim, device_claim) = {
                let mut claims = self.claims.lock().unwrap();
                (claims.get_claim_from_local(&self.did), claims.get_claim_from_local(&self.device))
            };
            let result_string = SimpleAI::request_token_api_register(&local_claim, &device_claim);
            let mut global_vars = serde_json::from_str(&result_string).unwrap_or(HashMap::new());
            self.upstream_did = global_vars.get("upstream_did").cloned().unwrap_or("Unknown".to_string());
            global_vars.insert("upstream_did".to_string(), self.did.clone());
            if !self.upstream_did.is_empty() && !self.upstream_did.starts_with("Unknown") {
                let global_local_vars = self.global_local_vars.lock().unwrap();
                for (var, value) in global_vars.iter() {
                    let ivec_data = sled::IVec::from(value.as_bytes());
                    let _ = global_local_vars.insert(&format!("global_{}", var), ivec_data);
                }
                debug!("[UserBase] obtain upstream: upstream_did={}, self_did={}", self.upstream_did, self.did);
            }
            if start_time.elapsed() >= timeout {
                debug!("[UserBase] Unable to obtain upstream address: self_did={}", self.did);
                return "".to_string();
            }
            std::thread::sleep(Duration::from_secs(2));
        }
    }

    pub fn get_sysinfo(&self) -> SystemInfo {
        self.sysinfo.clone()
    }

    pub fn get_device_did(&self) -> String {
        self.device.clone()
    }
    pub fn get_guest_did(&self) -> String {
        self.guest.clone()
    }

    pub fn get_node_mode(&mut self) -> String {
        let system_did = self.get_sys_did();
        self.node_mode = self.get_local_vars_base("node_mode_type", "online", &system_did);
        self.node_mode.clone()
    }

    pub fn set_node_mode(&mut self, mode: &str) {
        if mode != self.node_mode {
            let local_key = format!("{}_{}", self.did, "node_mode_type");
            let local_value = mode.to_string();
            let global_local_vars = self.global_local_vars.lock().unwrap();
            let ivec_data = sled::IVec::from(local_value.as_bytes());
            let _ = global_local_vars.insert(&local_key, ivec_data);
        }
        self.node_mode = mode.to_string();
    }

    pub(crate) fn get_admin_did(&self) -> String {
        self.admin.clone()
    }

    pub fn set_admin(&mut self, did: &str) {
        self.admin = {
            let mut claims = self.claims.lock().unwrap();
            claims.set_admin_did(did);
            did.to_string()
        };
        token_utils::save_secret_to_system_token_file(&self.crypt_secrets, &self.did, &self.admin);
    }

    //pub fn get_token_db(&self) -> Arc<Mutex<sled::Db>> { self.token_db.clone() }

    pub fn get_global_vars(&mut self, key: &str, default: &str) -> String {
        let key = format!("global_{}", key);
        let global_local_vars = self.global_local_vars.lock().unwrap();
        match global_local_vars.get(&key) {
            Ok(Some(context)) => {
                String::from_utf8(context.to_vec()).unwrap()
            },
            _ => default.to_string()
        }
    }

    fn load_global_vars(&mut self) {
        let upstream_did = self.get_upstream_did();
        if upstream_did == self.admin && upstream_did == token_utils::TOKEN_TM_DID {
            let mut global_vars: HashMap<String, String> = HashMap::new();
            let sysinfo = token_utils::SYSTEM_BASE_INFO.clone();
            let root_dir = sysinfo.root_dir.clone();
            let global_vars_path = PathBuf::from(root_dir.clone()).join("global_vars.json");
            if global_vars_path.exists() {
                let global_vars_string = fs::read_to_string(&global_vars_path).unwrap_or("".to_string());
                let local_global_vars: HashMap<String, String> = serde_json::from_str(&global_vars_string).unwrap_or(HashMap::new());
                global_vars.extend(local_global_vars.into_iter());
            }
            global_vars.insert("upstream_did".to_string(), self.did.clone());
            let global_local_vars = self.global_local_vars.lock().unwrap();
            for (var, value) in global_vars.iter() {
                let ivec_data = sled::IVec::from(value.as_bytes());
                let _ = global_local_vars.insert(&format!("global_{}", var), ivec_data);
            }
        }
    }

    pub fn get_global_vars_json(&mut self, reload: Option<bool>) -> String {
        let reload = reload.unwrap_or(false);
        if reload {
            self.load_global_vars();
        }
        let prefix = "global_";
        let mut global_vars: HashMap<String, String> = HashMap::new();
        let global_local_vars = self.global_local_vars.lock().unwrap();
        for result in global_local_vars.scan_prefix(prefix) {
            match result {
                Ok((key, value)) => {
                    if let (Ok(key_str), Ok(value_str)) = (
                        std::str::from_utf8(&key).map(|s| s.to_string()),
                        std::str::from_utf8(&value).map(|s| s.to_string()),
                    ) {
                        global_vars.insert(key_str, value_str);
                    } else {
                        eprintln!("Failed to convert key or value to UTF-8");
                    }
                }
                Err(e) => {
                    eprintln!("Error reading key-value pair: {}", e);
                }
            }
        }
        serde_json::to_string(&global_vars).unwrap()
    }

    pub fn get_local_vars(&mut self, key: &str, default: &str, user_session: &str, ua_hash: &str) -> String {
        let user_did = self.check_sstoken_and_get_did(user_session, ua_hash);
        self.get_local_vars_base(key, default, &user_did)
    }

    pub fn get_local_admin_vars(&mut self, key: &str) -> String {
        let admin_key = format!("admin_{}", key);
        let default = token_utils::ADMIN_DEFAULT.lock().unwrap().get(key).to_string();
        let admin = self.admin.clone();
        self.get_local_vars_base(&admin_key, &default, &admin)
    }

    fn get_local_vars_base(&mut self, key: &str, default: &str, user_did: &str) -> String {
        let (local_did, local_key) = if key.starts_with("admin_") {
            (self.admin.clone(), key.to_string())
        } else {
            (user_did.to_string(), format!("{}_{}", user_did, key))
        };

        let mut value = {
            let mut global_local_vars = self.global_local_vars.lock().unwrap();
            match global_local_vars.get(&local_key) {
                Ok(Some(var_value)) => {
                    String::from_utf8(var_value.to_vec()).unwrap()
                },
                _ => "Default".to_string()
            }
        };
        if local_key.starts_with("admin_") && value != "Default"{
            value = self.decrypt_by_did(&value, &local_did, 0);
        }
        if value == "Default" || value == "Unknown" {
            if local_key.starts_with("admin_") {
                let local_key = local_key.replace("admin_", "");
                let admin_default = token_utils::ADMIN_DEFAULT.lock().unwrap().get(&local_key).to_string();
                admin_default
            } else {
                default.to_string()
            }
        } else { value }

    }

    pub fn set_local_vars(&mut self, key: &str, value: &str, user_session: &str, ua_hash: &str) {
        let user_did = self.check_sstoken_and_get_did(user_session, ua_hash);
        let admin = self.admin.clone();
        let (local_key, local_value) = if key.starts_with("admin_") && admin == user_did  {
            (key.to_string(), self.encrypt_for_did(&value.as_bytes(), &admin, 0))
        } else {
            if key.starts_with("admin_") {
                return;
            }
            (format!("{}_{}", user_did, key), value.to_string())
        };

        let global_local_vars = self.global_local_vars.lock().unwrap();
        let ivec_data = sled::IVec::from(local_value.as_bytes());
        let _ = global_local_vars.insert(&local_key, ivec_data);
    }

    pub fn set_local_vars_for_guest(&mut self, key: &str, value: &str, user_session: &str, ua_hash: &str) {
        let user_did = self.check_sstoken_and_get_did(user_session, ua_hash);
        let admin = self.admin.clone();
        let guest = self.guest.clone();
        if admin == user_did {
            let local_key = format!("{}_{}", guest, key);
            let local_value = value.to_string();
            let global_local_vars = self.global_local_vars.lock().unwrap();
            let ivec_data = sled::IVec::from(local_value.as_bytes());
            let _ = global_local_vars.insert(&local_key, ivec_data);
        }
    }

    pub fn is_guest(&self, did: &str) -> bool {
        did == self.guest.as_str()
    }

    pub fn is_admin(&self, did: &str) -> bool {
        did == self.admin.as_str()
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
            claims.get_claim_from_global(for_did)
        }
    }

    pub fn get_claim_from_local(&mut self, for_did: &str) -> IdClaim {
        let mut claims = self.claims.lock().unwrap();
        claims.get_claim_from_local(for_did)
    }

    pub fn get_register_cert(&mut self, user_did: &str) -> String {
        let register_cert = {
            let certificates = self.certificates.lock().unwrap();
            certificates.get_register_cert(user_did)
        };
        if register_cert != "Unknown".to_string() {
            return register_cert;
        }
        let admin_did = self.admin.clone();
        let node_mode = self.get_node_mode();
        if user_did == self.guest || (node_mode != "online" && user_did == admin_did)  {
            let system_did = self.did.clone();
            let (_issue_cert_key, issue_cert) = self.sign_and_issue_cert_by_system("Member", &user_did, &system_did, "User");
            let register_cert = {
                let mut certificates = self.certificates.lock().unwrap();
                let _ = certificates.push_user_cert_text(&issue_cert);
                certificates.get_register_cert(user_did)
            };
            debug!("sign and issue member cert by system: user_did={}, sys_did={}, node_type={}", user_did, system_did, node_mode);
            register_cert
        } else {
            "Unknown".to_string()
        }
    }

    pub fn is_registered(&mut self, user_did: &str) -> bool {
        if user_did == "Unknown" {
            return false;
        }
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
        if self.get_node_mode() == "online" {
            let text = format!("{}|{}|{}|{}|{}|{}", token_utils::TOKEN_TM_DID, user_did, "Member", encrypt_item_key, memo_base64, timestamp);
            let claim = GlobalClaims::load_claim_from_local(token_utils::TOKEN_TM_DID);
            debug!("did({}), cert_str({}), cert_text({}), sign_did({})", user_did, cert_str, text, claim.gen_did());
            if token_utils::verify_signature(&text, &signature_str, &claim.get_cert_verify_key()) {
                return true;
            }
        }
        if !self.upstream_did.is_empty() && self.get_node_mode() == "online" {
            let text = format!("{}|{}|{}|{}|{}|{}", self.upstream_did, user_did, "Member", encrypt_item_key, memo_base64, timestamp);
            let claim = GlobalClaims::load_claim_from_local(&self.upstream_did);
            debug!("did({}), cert_str({}), cert_text({}), sign_did({})", user_did, cert_str, text, claim.gen_did());
            if token_utils::verify_signature(&text, &signature_str, &claim.get_cert_verify_key()) {
                return true;
            }
        }
        let text = format!("{}|{}|{}|{}|{}|{}", self.get_sys_did(), user_did, "Member", encrypt_item_key, memo_base64, timestamp);
        let claim = GlobalClaims::load_claim_from_local(&self.get_sys_did());
        debug!("did({}), cert_str({}), cert_text({}), sign_did({})", user_did, cert_str, text, claim.gen_did());
        if token_utils::verify_signature(&text, &signature_str, &claim.get_cert_verify_key()) {
            return true;
        }
        false
    }


    pub fn reset_node_mode(&mut self, mode: &str) -> (String, String, String) {
        let node_mode = self.get_node_mode();
        if mode == "isolated" && node_mode != "isolated" {
            // 清除非 device，system，guest 的 crypt_secrets
            let mut remove_did = Vec::new();
            self.crypt_secrets.retain(|key, _| {
                if let Some((did, _)) = key.split_once('_') {
                    let retain = did == self.device || did == self.did || did == self.guest;
                    if !retain {
                        remove_did.push(did.to_string());
                    }
                    retain
                } else {
                    false
                }
            });
            // 清除非 guest 的 token
            for did in &remove_did {
                let context = self.get_user_context(&did);
                let key = format!("{}_{}", did, self.get_sys_did());
                let authorized = self.authorized.lock().unwrap();
                let _ = match authorized.contains_key(&key).unwrap() {
                    false => {},
                    true => {
                        let _ = authorized.remove(&key);
                    }
                };
                let _ = token_utils::update_user_token_to_file(&context, "remove");
                debug!("remove {} context and crypt_secrets", did);
            }
            let (system_name, sys_phrase, device_name, device_phrase, guest_name, guest_phrase)
                = GlobalClaims::get_system_vars();
            let admin_name = guest_name.replace("guest_", "admin_");
            let admin_symbol_hash = IdClaim::get_symbol_hash_by_source(&admin_name, Some("8610000000001".to_string()), None);
            let (admin_hash_id, admin_phrase) = token_utils::get_key_hash_id_and_phrase("User", &admin_symbol_hash);
            let admin_did= {
                let user_did = self.reverse_lookup_did_by_symbol(admin_symbol_hash);
                let identity_file = token_utils::get_path_in_sys_key_dir(&format!("user_identity_{}.token", admin_hash_id));
                if user_did != "Unknown" && identity_file.exists() {
                    let encrypted_identity = fs::read_to_string(identity_file.clone()).expect(&format!("Unable to read file: {}", identity_file.display()));
                    self.import_user(&URL_SAFE_NO_PAD.encode(admin_symbol_hash), &encrypted_identity, &admin_phrase);
                    user_did
                } else {
                    let (admin_did, admin_phrase) = self.create_user(&admin_name, &String::from("8610000000001"), None, None);
                    admin_did
                }
            };
            let admin_phrase_base58 = admin_phrase.as_bytes().to_base58();
            println!("{} [UserBase] local admin/本地管理身份: did/标识={}, phrase/口令={}", token_utils::now_string(), admin_did, admin_phrase_base58);
            self.set_admin(&admin_did);
            self.set_node_mode(mode);
            self.sign_user_context(&admin_did, &admin_phrase);
            (admin_did, admin_name, admin_phrase_base58)
        } else if mode == "online" && node_mode != "online" { //
            let admin_did = self.admin.clone();
            if !admin_did.is_empty() {
                self.crypt_secrets.retain(|key, _| {
                    if let Some((did, _)) = key.split_once('_') {
                        did == self.device || did == self.did || did == self.guest
                    } else {
                        false
                    }
                });
                let context = self.get_user_context(&admin_did);
                let key = format!("{}_{}", admin_did, self.get_sys_did());
                let authorized = self.authorized.lock().unwrap();
                let _ = match authorized.contains_key(&key).unwrap() {
                    false => {},
                    true => {
                        let _ = authorized.remove(&key);
                    }
                };
                let _ = token_utils::update_user_token_to_file(&context, "remove");
            }
            self.set_admin("");
            self.set_node_mode(mode);
            ("".to_string(), "".to_string(), "".to_string())
        } else {
            ("".to_string(), "".to_string(), "".to_string())
        }
    }

    pub(crate) fn create_user(&mut self, nickname: &str, telephone: &str, id_card: Option<String>, phrase: Option<String>)
                       -> (String, String) {
        let nickname = token_utils::truncate_nickname(nickname);
        if !token_utils::is_valid_telephone(telephone) {
            return ("Unknown".to_string(), "Unknown".to_string());
        }
        let user_telephone = telephone.to_string();
        let user_symbol_hash = IdClaim::get_symbol_hash_by_source(&nickname, Some(user_telephone.clone()), None);
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
        println!("{} [UserBase] Create user and save identity_file: {}", token_utils::now_string(), identity_file.display());

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
        debug!("{} [UserBase] Remove user: {}, {}, {}", token_utils::now_string(), user_hash_id, user_did, claim.nickname);
        if user_did != "Unknown" {
            if !claim.is_default() {
                let user_key_file = token_utils::get_path_in_sys_key_dir(&format!(".token_user_{}.pem", user_hash_id));
                if let Err(e) = fs::remove_file(user_key_file.clone()) {
                    debug!("delete user_key_file error: {}", e);
                } else {
                    debug!("user_key_file was deleted: {}", user_key_file.display());
                }
                self.pop_claim(&user_did);
                let identity_file = token_utils::get_path_in_sys_key_dir(&format!("user_identity_{}.token", user_hash_id));
                if identity_file.exists() {
                    if let Err(e) = fs::remove_file(identity_file.clone()) {
                        debug!("delete identity_file error: {}", e);
                    } else {
                        debug!("identity_file was deleted: {}", identity_file.display());
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


    pub fn import_user(&mut self, symbol_hash_base64: &str, encrypted_identity: &str, phrase: &str) -> String {
        let user_claim = token_utils::import_identity(symbol_hash_base64, &URL_SAFE_NO_PAD.decode(encrypted_identity).unwrap(), phrase);
        if user_claim.is_default() {
            return "Unknown".to_string();
        }
        self.push_claim(&user_claim);
        let user_did = user_claim.gen_did();
        let crypt_secrets_len = self.crypt_secrets.len();
        token_utils::init_user_crypt_secret(&mut self.crypt_secrets, &user_claim, &phrase);
        if self.crypt_secrets.len() > crypt_secrets_len {
            token_utils::save_secret_to_system_token_file(&mut self.crypt_secrets, &self.did, &self.admin);
        }
        debug!("{} [UserBase] Import user: {}", token_utils::now_string(), user_did);

        user_did
    }

    pub fn export_user(&self, nickname: &str, telephone: &str, phrase: &str) -> String {
        let nickname = token_utils::truncate_nickname(nickname);
        let symbol_hash = IdClaim::get_symbol_hash_by_source(&nickname, Some(telephone.to_string()), None);
        let (user_did, claim) = {
            let mut claims = self.claims.lock().unwrap();
            let user_did = claims.reverse_lookup_did_by_symbol(&symbol_hash);
            let claim = claims.get_claim_from_local(&user_did);
            (user_did, claim)
        };
        println!("{} [UserBase] Export user: {}, nickname={}, telephone={}", token_utils::now_string(), user_did, nickname, telephone);

        URL_SAFE_NO_PAD.encode(token_utils::export_identity(&nickname, telephone, claim.timestamp, phrase))
    }

    pub fn export_isolated_admin_qrcode_svg(&mut self) -> String{
        if self.get_node_mode() == "isolated" && !self.admin.is_empty() {
            let admin = self.admin.clone();
            let admin_claim = {
                let claims = GlobalClaims::instance();
                let mut claims = claims.lock().unwrap();
                claims.get_claim_from_local(&admin)
            };
            let qrcode_svg = SimpleAI::export_user_qrcode_svg(&admin);
            if !qrcode_svg.is_empty() {
                format!("{}|{}|{}", admin_claim.nickname, admin, qrcode_svg)
            } else { "".to_string() }
        } else { "".to_string() }
    }


    #[staticmethod]
    pub fn export_user_qrcode_svg(user_did: &str) -> String {
        let encrypted_identity_qr_base64 = SimpleAI::export_user_qrcode_base64(user_did);
        if !encrypted_identity_qr_base64.is_empty() {
            let qrcode = QrCode::with_version(encrypted_identity_qr_base64, Version::Normal(12), EcLevel::L).unwrap();
            let image = qrcode.render()
                .min_dimensions(400, 400)
                .dark_color(svg::Color("#800000"))
                .light_color(svg::Color("#ffff80"))
                .build();
            image
        } else { "".to_string() }
    }


    #[staticmethod]
    pub(crate) fn export_user_qrcode_base64(user_did: &str) -> String {
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
                    let encrypted_identity = URL_SAFE_NO_PAD.decode(identity.clone()).unwrap();
                    let did_bytes = user_did.from_base58().unwrap();
                    let user_cert = {
                        let certificates = GlobalCerts::instance();
                        let certificates = certificates.lock().unwrap();
                        certificates.get_register_cert(user_did)
                    };
                    debug!("{} [UserBase] user_cert:{}", token_utils::now_string(), user_cert);
                    let user_cert_bytes = token_utils::get_slim_user_cert(&user_cert);
                    if user_cert_bytes.len() < 120 {
                        return "".to_string()
                    }
                    let mut encrypted_identity_qr = Vec::with_capacity(encrypted_identity.len() + did_bytes.len() + user_cert_bytes.len());
                    encrypted_identity_qr.extend_from_slice(&did_bytes);
                    encrypted_identity_qr.extend_from_slice(&user_cert_bytes);
                    encrypted_identity_qr.extend_from_slice(&encrypted_identity);
                    URL_SAFE_NO_PAD.encode(encrypted_identity_qr.clone())
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
            println!("import_identity_qrcode, ready to push user cert: did={}", user_did);
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
                        println!("{} [UserBase] Sign and issue a cert by did: issuer({}), item({}), owner({}), sys({})", token_utils::now_string(), issuer_did, item, for_did, for_sys_did);
                        if for_sys_did == self.did {
                            return (format!("{}|{}|{}", issuer_did, for_did, item), format!("{}|{}", cert_text, sig))
                        } else {
                            return (format!("{}|{}|{}", issuer_did, for_did, item), self.encrypt_for_did(format!("{}|{}", cert_text, sig).as_bytes(), for_sys_did, 0))
                        }
                    }
                }
            }
        }
        println!("{} [UserBase] Sign and issue a cert by did: invalid params", token_utils::now_string());
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
                debug!("get_user_sstoken, context is default or expired: did={}", did);
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
                .expect("get_user_sstoken, Failed to convert Vec<u8> to [u8; 32]");
            result.to_base58()
        } else {
            debug!("debug: get_user_sstoken, did is incorrect format: {}", did);
            String::from("Unknown")
        }
    }

    pub fn check_sstoken_and_get_did(&mut self, sstoken: &str, ua_hash: &str) -> String {
        let sstoken_bytes = sstoken.from_base58().unwrap_or([0; 32].to_vec());
        if sstoken_bytes.len() != 32 || sstoken_bytes==[0; 32] {
            println!("{} [UserBase] The sstoken in browser is incorrect format: {}", token_utils::now_string(), sstoken);
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
            .expect("check_sstoken_and_get_did, 1, Failed to convert Vec<u8> to [u8; 32]");
        let mut did_bytes: [u8; 21] = [0; 21];
        let mut padded: [u8; 11] = [0; 11];
        padded.copy_from_slice(&result[..11]);
        did_bytes.copy_from_slice(&result[11..]);
        let did_bytes_slice = &did_bytes[10..];
        if padded.iter().zip(did_bytes_slice.iter()).all(|(a, b)| a == b) {
            let user_did = did_bytes.to_base58();
            let context = self.get_user_context(&user_did);
            if context.is_default() || context.is_expired(){
                debug!("{} [UserBase] The context of the sstoken in browser is expired: did={}", token_utils::now_string(), user_did);
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
                .expect("check_sstoken_and_get_did, 2, Failed to convert Vec<u8> to [u8; 32]");
            padded.copy_from_slice(&result[..11]);
            did_bytes.copy_from_slice(&result[11..]);
            let did_bytes_slice = &did_bytes[10..];
            if padded.iter().zip(did_bytes_slice.iter()).all(|(a, b)| a == b) {
                let user_did = did_bytes.to_base58();
                let context = self.get_user_context(&user_did);
                if context.is_default() || context.is_expired(){
                    println!("{} [UserBase] The context2 of the sstoken in browser is expired: did={}", token_utils::now_string(), user_did);
                    String::from("Unknown")
                } else {
                    user_did
                }
            } else {
                println!("{} [UserBase] The sstoken in browser is not validity: sstoken={}, ua={}", token_utils::now_string(), sstoken, ua_hash);
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
        if self.get_node_mode() != "online" {
            if telephone=="8610000000001" {
                return "local".to_string()
            } else {
                println!("{} [UserBase] The system is isolated mode, please take the local admin qrcode to bind.", token_utils::now_string());
                return "isolated".to_string()
            }
        }
        let nickname = token_utils::truncate_nickname(nickname);
        if !token_utils::is_valid_telephone(telephone) {
            return "unknown".to_string();
        }
        if nickname.to_lowercase().starts_with("guest") {
            return "unknown".to_string();
        }
        let symbol_hash = IdClaim::get_symbol_hash_by_source(&nickname, Some(telephone.to_string()), None);
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
                        if old_user_did == "Unknown" { // 身份预备数据格式错误
                            self.remove_user(&symbol_hash_base64);
                            debug!("user_key is exist but the ready data is error: {}, {}", nickname, user_hash_id);
                            return "re_input".to_string();
                        } else if !self.is_registered(&old_user_did) { // 没有经过身份验证
                            self.remove_user(&symbol_hash_base64);
                            debug!("user_key is exist but the vcode is not verified : {}, {}", nickname, user_hash_id);
                            return "re_input".to_string();
                        } // 已经过身份验证
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
                        println!("{} [UserBase] The identity is not in local and generate ready_data for new user: {}, {}, {}, {}",
                                 token_utils::now_string(), nickname, telephone, user_hash_id, symbol_hash_base64);
                        let (user_did, _user_phrase) = self.create_user(&nickname, telephone, None, None);
                        let new_claim = self.get_claim_from_local(&user_did);
                        println!("{} [UserBase] Create new claim for new user: user_did={}, claim_symbol={}",
                            token_utils::now_string(), user_did, URL_SAFE_NO_PAD.encode(new_claim.get_symbol_hash()));

                        let mut request: serde_json::Value = json!({});
                        request["telephone"] = serde_json::to_value(telephone).unwrap_or(json!(""));
                        request["claim"] = serde_json::to_value(new_claim.clone()).unwrap_or(json!(""));

                        let apply_result = self.request_token_api(
                            "apply",
                            &serde_json::to_string(&request).unwrap_or("{}".to_string()),);
                        println!("{} [UserBase] Apply to verify user: symbol({})", token_utils::now_string(), symbol_hash_base64);
                        if !apply_result.starts_with("Unknown") {
                            let parts: Vec<&str> = apply_result.split('|').collect();
                            if parts[0] == "user_claim" {
                                self.remove_user(&symbol_hash_base64);
                                match serde_json::from_str::<IdClaim>(&parts[1]) {
                                    Ok(return_claim) => {
                                        let return_did = return_claim.gen_did();
                                        println!("{} [UserBase] The decoding the claim from Root is correct: user_did({}), nickname={}, claim_symbol({})",
                                                 token_utils::now_string(), return_did, return_claim.nickname, URL_SAFE_NO_PAD.encode(return_claim.get_symbol_hash()));
                                        debug!("return_claim: {}", parts[1]);
                                        if user_did != return_claim.gen_did() {
                                            println!("{} [UserBase] Identity confirmed to recall user from root: local_did({}), remote_did({})",
                                                     token_utils::now_string(), user_did, return_did);
                                            self.push_claim(&return_claim);
                                            return "recall".to_string();
                                        } else {
                                            println!("{} [UserBase] Identity confirmed to recall user from root is same the new before: local_did({}), remote_did({})",
                                                     token_utils::now_string(), user_did, return_did);
                                            self.remove_user(&symbol_hash_base64);
                                            return "unknown".to_string();
                                        }
                                    }
                                    Err(e) => {
                                        println!("{} [UserBase] The decoding the claim from Root is fail: did({}), error({})", token_utils::now_string(), user_did, e);
                                        self.remove_user(&symbol_hash_base64);
                                        return "unknown".to_string();
                                    }
                                }
                            } else if parts[0] == "user_cert" {
                                let ready_data = format!("{}|{}|{}", 3, user_did, parts[1]);
                                let ivec_data = sled::IVec::from(ready_data.as_bytes());
                                {
                                    let ready_users = self.ready_users.lock().unwrap();
                                    let _ = ready_users.insert(&user_hash_id, ivec_data);
                                }
                                debug!("ready_data: {}", ready_data);
                                println!("{} [UserBase] User apply is ok, ready to verify user_cert with vcode: did({})", token_utils::now_string(), user_did);
                                return "create".to_string();
                            } else {
                                self.remove_user(&symbol_hash_base64);
                                println!("{} [UserBase] User apply is ok, but the feedback is undefined: {}", token_utils::now_string(), apply_result);
                                return "unknown".to_string();
                            }
                        } else if apply_result.starts_with("Unknown_Repeat") {
                            println!("{} [UserBase] User apply is failure({}): did({}), symbol({})", token_utils::now_string(), apply_result, user_did, symbol_hash_base64);
                            self.remove_user(&symbol_hash_base64);
                            return "unknown_repeat".to_string();
                        } else if apply_result.starts_with("Unknown_Exceeded") {
                            println!("{} [UserBase] User apply is failure({}): did({}), symbol({})", token_utils::now_string(), apply_result, user_did, symbol_hash_base64);
                            self.remove_user(&symbol_hash_base64);
                            return "unknown_exceeded".to_string();
                        } else {
                            println!("{} [UserBase] User apply is failure({}): sys_did({}), user_did({}), user_symbol({})", token_utils::now_string(), apply_result, self.did, user_did, symbol_hash_base64);
                            self.remove_user(&symbol_hash_base64);
                            return "unknown".to_string();
                        }
                    }
                }
            }
        }
    }

    pub fn check_user_verify_code(&mut self, nickname: &str, telephone: &str, vcode: &str)-> String {
        let nickname = token_utils::truncate_nickname(nickname);
        if !token_utils::is_valid_telephone(telephone) {
            return "unknown".to_string();
        }
        let symbol_hash = IdClaim::get_symbol_hash_by_source(&nickname, Some(telephone.to_string()), None);
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
                let ready_user_did = parts[1].to_string();
                let encrypted_certificate_string = parts[2].to_string();
                try_count -= 1;
                if try_count >= 0 {
                    let user_certificate = token_utils::decrypt_text_with_vcode(vcode, &encrypted_certificate_string);
                    let upstream_did = self.get_upstream_did();
                    if user_certificate.len() > 32 && !upstream_did.is_empty() {
                        let user_certificate_text = self.decrypt_by_did(&user_certificate, &upstream_did, 0);
                        debug!("UserBase] The parsed cert from Root is: cert({})", user_certificate_text);
                        let cert_user_did = {
                            let mut certificates = self.certificates.lock().unwrap();
                            certificates.push_user_cert_text(&user_certificate_text)
                        };
                        if cert_user_did != "Unknown" {
                            let ready_claim = self.get_claim_from_local(&ready_user_did);
                            let symbol_hash_base64 = URL_SAFE_NO_PAD.encode(ready_claim.get_symbol_hash());
                            if cert_user_did != ready_user_did {
                                println!("{} [UserBase] The parsed cert from Root is not match: cert_did({}), ready_did({})",
                                         token_utils::now_string(), cert_user_did, ready_user_did);
                                self.remove_user(&symbol_hash_base64);
                                return "error in confirming".to_string();
                            }
                            println!("{} [UserBase] The parsed cert from Root is correct: did({}), nickname({}), symbol({})",
                                     token_utils::now_string(), ready_user_did, ready_claim.nickname, symbol_hash_base64);
                            let encrypted_claim = URL_SAFE_NO_PAD.encode(token_utils::encrypt(ready_claim.to_json_string().as_bytes(), vcode.as_bytes(), 0));

                            let mut request: serde_json::Value = json!({});
                            request["user_symbol"] = serde_json::to_value(symbol_hash_base64.clone()).unwrap();
                            request["encrypted_claim"] = serde_json::to_value(encrypted_claim).unwrap();
                            let user_copy_hash_id = token_utils::get_user_copy_hash_id_by_source(&nickname, telephone, &user_phrase);
                            request["user_copy_hash_id"] = serde_json::to_value(user_copy_hash_id).unwrap_or(json!(""));

                            let result = self.request_token_api(
                                "confirm",
                                &serde_json::to_string(&request).unwrap_or("{}".to_string()),);
                            if !result.starts_with("Unknown") {
                                return "create".to_string();
                            } else {
                                println!("{} [UserBase] The user confirm request is fail: ready_did({}), symbol({})",
                                         token_utils::now_string(), ready_user_did, symbol_hash_base64);
                                self.remove_user(&symbol_hash_base64);
                                return "error in confirming".to_string();
                            }
                        }
                    }
                    println!("{} [UserBase] The decoding the claim from Root is incorrect: ready_did({}), symbol({})",
                             token_utils::now_string(), ready_user_did, symbol_hash_base64);
                    let ready_data = format!("{}|{}|{}", try_count, ready_user_did, encrypted_certificate_string);
                    let ivec_data = sled::IVec::from(ready_data.as_bytes());
                    {
                        let ready_users = self.ready_users.lock().unwrap();
                        let _ = ready_users.insert(&user_hash_id, ivec_data);
                    }
                    return format!("error:{}", try_count).to_string();
                } else {
                    let _ = {
                        let ready_users = self.ready_users.lock().unwrap();
                        let _ = ready_users.remove(user_hash_id.clone());
                    };
                    println!("{} [UserBase] The try_count of verify the code has run out: ready_did({}), symbol({}), user_hash_id({})",
                             token_utils::now_string(), ready_user_did, symbol_hash_base64, user_hash_id);
                    return "error:0".to_string();
                }
            }
        }
        println!("{} [UserBase] The ready data is not exist or incorrect: symbol({}), user_hash_id({}), ready_data({})",
                 token_utils::now_string(), symbol_hash_base64, user_hash_id, ready_data);
        self.remove_user(&symbol_hash_base64);
        "error:0".to_string()
    }


    pub fn set_phrase_and_get_context(&mut self, nickname: &str, telephone: &str, phrase: &str) -> UserContext {
        let nickname = token_utils::truncate_nickname(nickname);
        if !token_utils::is_valid_telephone(telephone) {
            println!("{} [UserBase] The telephone number is not valid: {}, {}.", token_utils::now_string(), nickname, telephone);
            return self.get_guest_user_context();
        }
        let symbol_hash = IdClaim::get_symbol_hash_by_source(&nickname, Some(telephone.to_string()), None);
        let user_did = self.reverse_lookup_did_by_symbol(symbol_hash);
        let symbol_hash_base64 = URL_SAFE_NO_PAD.encode(symbol_hash);
        if user_did == "Unknown" || !self.is_registered(&user_did) {
            println!("{} [UserBase] The user isn't in local or hasn't been verified by root: nickname={}, telephone={}, symbol={}, user_did={}",
                     token_utils::now_string(), nickname, telephone, symbol_hash_base64, user_did);
            self.remove_user(&symbol_hash_base64);
            return self.get_guest_user_context();
        }

        let (_user_hash_id, user_phrase) = token_utils::get_key_hash_id_and_phrase("User", &symbol_hash);
        if token_utils::is_original_user_key(&symbol_hash)  {
            let _ = token_utils::change_phrase_for_pem_and_identity_files(&symbol_hash, &user_phrase, phrase);
        } else {
            println!("{} [UserBase] The user_key phrase has been changed and can not to be set: {}, {}.",
                     token_utils::now_string(), nickname, user_did);
            return self.get_guest_user_context();
        }

        let context = self.sign_user_context(&user_did, phrase);
        if context.is_default() {
            println!("{} [UserBase] The user maybe in blacklist: {}", token_utils::now_string(), user_did);
            return self.get_guest_user_context();
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
        if result.starts_with("Backup_ok") {
            println!("{} [UserBase] After set phrase, then upload encrypted_user_copy: user_did={}", token_utils::now_string(), user_did);
            context
        } else if result.starts_with("Unknown") {
            //let encoded_params = self.encrypt_for_did(params.as_bytes(), &self.upstream_did.clone() ,0);
            //let user_copy_file = token_utils::get_path_in_sys_key_dir(&format!("user_copy_{}_uncompleted.json", user_did));
            //fs::write(user_copy_file.clone(), encoded_params).expect(&format!("Unable to write file: {}", user_copy_file.display()));
            println!("{} [UserBase] After set phrase, but upload encrypted_user_copy failed: {}, {}", token_utils::now_string(), user_did, result);
            self.get_guest_user_context() //context
        }  else {
            println!("{} [UserBase] After set phrase, but upload encrypted_user_copy failed: {}, {}", token_utils::now_string(), user_did, result);
            self.get_guest_user_context()
        }

    }


    pub fn get_user_context_with_phrase(&mut self, nickname: &str, telephone: &str, did: &str, phrase: &str ) -> UserContext {
        let nickname = token_utils::truncate_nickname(nickname);
        if token_utils::is_valid_telephone(telephone) {
            let phrase = if telephone=="8610000000001" {
                let bytes_phrase = phrase.from_base58();
                let bytes = match bytes_phrase {
                    Ok(bytes) => bytes,
                    Err(_) => "Unknown".into(),
                };
                let string_result = String::from_utf8(bytes);
                match string_result {
                    Ok(s) => s,
                    Err(_) => String::from("Unknown"),
                }
            } else {
                phrase.to_string()
            };
            let symbol_hash = IdClaim::get_symbol_hash_by_source(&nickname, Some(telephone.to_string()), None);
            let symbol_hash_base64 = URL_SAFE_NO_PAD.encode(&symbol_hash);
            let user_did = if did.is_empty() {
                self.reverse_lookup_did_by_symbol(symbol_hash)
            } else {
                did.to_string()
            };
            let (user_hash_id, _user_phrase) = token_utils::get_key_hash_id_and_phrase("User", &symbol_hash);
            let user_did = {
                match token_utils::exists_and_valid_user_key(&symbol_hash, &phrase) && user_did != "Unknown" {
                    true => {
                        println!("{} [UserBase] Get user context:{} from local key file: .token_user_{}.pem",
                                 token_utils::now_string(), user_did, user_hash_id);
                        user_did
                    },
                    false => {
                        let identity_file = token_utils::get_path_in_sys_key_dir(&format!("user_identity_{}.token", user_hash_id));
                        match identity_file.exists() {
                            true => {
                                let encrypted_identity = fs::read_to_string(identity_file.clone()).expect(&format!("Unable to read file: {}", identity_file.display()));
                                println!("{} [UserBase] Get user encrypted copy from identity file: {}, {}, len={}, {}",
                                         token_utils::now_string(), user_did, symbol_hash_base64, encrypted_identity.len(), encrypted_identity);
                                self.import_user(&symbol_hash_base64.clone(), &encrypted_identity, &phrase)
                            }
                            false => {
                                if self.node_mode == "online" {
                                    let mut request: serde_json::Value = json!({});
                                    let user_copy_hash_id = token_utils::get_user_copy_hash_id_by_source(&nickname, &telephone, &phrase);
                                    request["user_copy_hash_id"] = serde_json::to_value(&user_copy_hash_id).unwrap();
                                    request["user_symbol"] = serde_json::to_value(symbol_hash_base64.clone()).unwrap();
                                    let user_copy_from_cloud =
                                        self.request_token_api("get_user_copy", &serde_json::to_string(&request).unwrap_or("{}".to_string()), );

                                    match user_copy_from_cloud != "Unknown".to_string() &&
                                        user_copy_from_cloud != "Unknown_user".to_string() &&
                                        user_copy_from_cloud != "Unknown_backup".to_string() {
                                        true => {
                                            debug!("user_copy_from_cloud:{}", user_copy_from_cloud);
                                            let user_copy_from_cloud_array: Vec<&str> = user_copy_from_cloud.split("|").collect();
                                            if user_copy_from_cloud_array.len() >= 3 {
                                                let encrypted_identity = user_copy_from_cloud_array[0];
                                                println!("{} [UserBase] Download user encrypted_copy: {}, len={}",
                                                         token_utils::now_string(), symbol_hash_base64, encrypted_identity.len());
                                                debug!("user_copy_from_cloud, encrypted_identity:{}", encrypted_identity);
                                                let user_did = self.import_user(&symbol_hash_base64, &encrypted_identity, &phrase);
                                                if user_did != "Unknown" {
                                                    let identity_file = token_utils::get_path_in_sys_key_dir(&format!("user_identity_{}.token", user_hash_id));
                                                    fs::write(identity_file.clone(), encrypted_identity).expect(&format!("Unable to write file: {}", identity_file.display()));
                                                    println!("{} [UserBase] Parsing encrypted_copy and save identity_file: {}, {}",
                                                             token_utils::now_string(), user_hash_id, user_did);

                                                    if token_utils::exists_and_valid_user_key(&symbol_hash, &phrase) {
                                                        println!("{} [UserBase] The user encrypted copy is valid: {}", token_utils::now_string(), user_did);

                                                        let certificate_string = String::from_utf8_lossy(token_utils::decrypt(&URL_SAFE_NO_PAD.decode(
                                                            user_copy_from_cloud_array[2]).unwrap(), phrase.as_bytes(), 0).as_slice()).to_string();

                                                        let certificate_string = certificate_string.replace(":", "|");
                                                        let certs_array: Vec<&str> = certificate_string.split(",").collect();
                                                        let _ = {
                                                            let mut certificates = self.certificates.lock().unwrap();
                                                            for cert in &certs_array {
                                                                debug!("user_copy_from_cloud, cert:{}", cert);
                                                                let _user_did = certificates.push_user_cert_text(cert);
                                                            }
                                                        };
                                                        let _context_string = String::from_utf8_lossy(token_utils::decrypt(&URL_SAFE_NO_PAD.decode(
                                                            user_copy_from_cloud_array[1]).unwrap(), phrase.as_bytes(), 0).as_slice()).to_string();
                                                        // 取回的context里的sys_did不一定是本地系统的sys_did，需要考虑如何迁移context
                                                        //let _ = token_utils::update_user_token_to_file(&serde_json::from_str::<UserContext>(&context_string)
                                                        //    .unwrap_or(UserContext::default()), "add");
                                                        user_did
                                                    } else {
                                                        println!("{} [UserBase] The user encrypted copy is not valid: {}, user_key is error.", token_utils::now_string(), user_did);
                                                        "guest".to_string()
                                                    }
                                                } else {
                                                    println!("{} [UserBase] The user encrypted copy is not valid: {}, import_user is error.", token_utils::now_string(), user_hash_id);
                                                    "guest".to_string()
                                                }
                                            } else {
                                                println!("{} [UserBase] The user encrypted copy is not valid: {}, user_copy_from_cloud is error.", token_utils::now_string(), user_hash_id);
                                                "guest".to_string()
                                            }
                                        },
                                        false => {
                                            println!("{} [UserBase] The user encrypted copy is not valid: {}, get_user_copy response is error", token_utils::now_string(), user_hash_id);
                                            "guest".to_string()
                                        }
                                    }
                                } else {
                                    println!("{} [UserBase] The system is isolated mode, the identity file is no exist: {}", token_utils::now_string(), identity_file.display());
                                    "guest".to_string()
                                }
                            }
                        }
                    }
                }
            };
            if user_did != "guest" && user_did != "Unknown" {
                let context = self.sign_user_context(&user_did, &phrase);
                if context.is_default() {
                    println!("{} [UserBase] The user hasn't been verified by root or in blacklist: {}", token_utils::now_string(), user_did);
                    self.get_guest_user_context()
                } else { context }
            } else {
                self.get_guest_user_context()
            }
        } else {
            println!("{} [UserBase] The telephone is not valid: {}", token_utils::now_string(), telephone);
            self.get_guest_user_context()
        }
    }

    pub fn unbind_and_return_guest(&mut self, user_did: &str, phrase: &str) -> UserContext {
        if IdClaim::validity(user_did) {
            let claim = self.get_claim(user_did);
            if !claim.is_default() {
                let context = self.get_user_context(&user_did);
                if self.node_mode == "online" {
                    let symbol_hash = claim.get_symbol_hash();
                    let user_copy_to_cloud = self.get_user_copy_string(&user_did, phrase);
                    let user_copy_hash_id = token_utils::get_user_copy_hash_id(&claim.nickname, &claim.telephone_hash, phrase);
                    let mut request: serde_json::Value = json!({});
                    request["user_symbol"] = serde_json::to_value(URL_SAFE_NO_PAD.encode(symbol_hash)).unwrap();
                    request["user_copy_hash_id"] = serde_json::to_value(user_copy_hash_id).unwrap();
                    request["data"] = serde_json::to_value(user_copy_to_cloud).unwrap();
                    let params = serde_json::to_string(&request).unwrap_or("{}".to_string());
                    let upstream_did = self.get_upstream_did();
                    let result = self.request_token_api("unbind_node", &params);
                    if result != "Unbind_ok" {
                        let encoded_params = self.encrypt_for_did(params.as_bytes(), &upstream_did, 0);
                        let unbind_node_file = token_utils::get_path_in_sys_key_dir(&format!("unbind_node_{}_uncompleted.json", user_did));
                        fs::write(unbind_node_file.clone(), encoded_params).expect(&format!("Unable to write file: {}", unbind_node_file.display()));
                    }
                    println!("{} [UserBase] Unbind user({}) from node({}): {}", token_utils::now_string(), user_did, self.did, result);
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
            }
        }
        self.get_guest_user_context()
    }

    pub fn get_user_copy_string(&mut self, user_did: &str, phrase: &str) -> String {
        let claim = self.get_claim(user_did);
        if !claim.is_default() {
            let symbol_hash = claim.get_symbol_hash();
            let (user_hash_id, _user_phrase) = token_utils::get_key_hash_id_and_phrase("User", &symbol_hash);
            let identity_file = token_utils::get_path_in_sys_key_dir(&format!("user_identity_{}.token", user_hash_id));
            let encrypted_identity = fs::read_to_string(identity_file.clone()).unwrap_or("Unknown".to_string());
            debug!("get_user_copy_string, identity_file({}), encrypted_identity: {}", identity_file.display(), encrypted_identity);
            let context = self.get_user_context(&user_did);
            let context_crypt = URL_SAFE_NO_PAD.encode(token_utils::encrypt(context.to_json_string().as_bytes(), phrase.as_bytes(), 0));
            debug!("get_user_copy_string, context_json: {}, context_crypt: {}", context.to_json_string(), context_crypt);
            let certificates = {
                let certificates = self.certificates.lock().unwrap();
                certificates.filter_user_certs(&user_did, "*")
            };
            let certificates_str = certificates
                .iter()
                .map(|(key, value)| format!("{}:{}", key, value))
                .collect::<Vec<String>>()
                .join(",");
            let certificates_str = certificates_str.replace("|", ":");
            let certificate_crypt = URL_SAFE_NO_PAD.encode(token_utils::encrypt(certificates_str.as_bytes(), phrase.as_bytes(), 0));
            debug!("get_user_copy_string, certificates_str: {}, certificate_crypt: {}", certificates_str, certificate_crypt);
            format!("{}|{}|{}", encrypted_identity, context_crypt, certificate_crypt)
        } else {
            "Unknown".to_string()
        }
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
        if self.blacklist.contains(&did.to_string()) ||
            (did != self.guest && !self.is_registered(did) && did!=token_utils::TOKEN_TM_DID.to_string()) {
            debug!("sign user context failed, did = {}", did);
            return UserContext::default();
        }
        let claim = self.get_claim(did);
        let mut context = token_utils::get_or_create_user_context_token(
            did, &self.did, &claim.nickname, &claim.id_type, &claim.get_symbol_hash(), phrase);
        let _ = context.signature(phrase);
        if token_utils::update_user_token_to_file(&context, "add") == "Ok"  {
            if self.admin.is_empty() && did != self.guest {
                self.set_admin(did);
                println!("{} [UserBase] Set admin_did/设置系统管理 = {}", token_utils::now_string(), self.admin);
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
        let upstream_did = self.get_upstream_did();
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
        //if !EnvData::check_basepkg(&root) {
        //    println!("[SimpleAI] 程序所需基础模型包有检测异常，未完全正确安装。请检查并正确安装后，再启动程序。");
        //    feedback_code += 2;
        //}
        let mut sysinfo = self.get_sysinfo();
        loop {
            if sysinfo.pyhash != "Unknown" {
                break;
            }
            if start.elapsed() > Duration::from_secs(15) {
                println!("{} [SimpleAI] 系统检测异常，继续运行会影响程序正确执行。请检查系统环境后，重新启动程序。", token_utils::now_string());
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

            println!("{} [SimpleAI] 所运行程序为非官方正式版本，请正确使用开源软件，{}。", token_utils::now_string(), &pyhash_display[..16]);
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
        .header("Version", TOKEN_API_VERSION.to_string())
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
