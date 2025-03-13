use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use directories_next::BaseDirs;
use std::sync::{Arc, Mutex};


use once_cell::sync::Lazy;
use serde::{Serialize, Deserialize};
use base58::{ToBase58, FromBase58};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use tracing::{error, warn, info, debug, trace};

use crate::dids::{self, DidToken, TOKEN_TM_DID, TOKEN_TM_URL};
use crate::dids::token_utils;
use crate::dids::claims::{GlobalClaims, IdClaim, UserContext};
use crate::issue_key;
use crate::exchange_key;

pub(crate) mod user_mgr;

lazy_static::lazy_static! {
    static ref ADMIN_DEFAULT: Arc<Mutex<AdminDefault>> = Arc::new(Mutex::new(AdminDefault::new()));
    static ref TOKEN_USER: Arc<Mutex<TokenUser>> = Arc::new(Mutex::new(TokenUser::new()));
}

pub struct TokenUser {
    sys_did: String,
    device_did: String,
    guest_did: String,
    guest_phrase: String,

    pub authorized: Arc<Mutex<sled::Tree>>, //HashMap<String, UserContext>,
    pub user_sessions: Arc<Mutex<sled::Tree>>, //HashMap<sessionid_key, String>,
    pub blacklist: Vec<String>,
    pub user_base_dir: String,
    pub entry_point: DidEntryPoint,

    didtoken: Arc<Mutex<DidToken>>,
}

impl TokenUser {

    pub fn instance() -> Arc<Mutex<TokenUser>> {
        TOKEN_USER.clone()
    }

    pub fn new() -> Self {
        let (system_name, sys_phrase, device_name, device_phrase, guest_name, guest_phrase)
            = dids::get_system_vars();
        let blacklist = token_utils::load_did_blacklist_from_file();
        let token_db = DidToken::instance().lock().unwrap().get_token_db();
        let (authorized_tree, user_sessions_tree) = {
            let token_db = token_db.lock().unwrap();
            (token_db.open_tree("authorized").unwrap(), token_db.open_tree("user_sessions").unwrap())
        };
        let authorized = Arc::new(Mutex::new(authorized_tree));
        let user_sessions = Arc::new(Mutex::new(user_sessions_tree));
        let entry_point = DidEntryPoint::new();
        let didtoken = DidToken::instance();
        let(sys_did, device_did, guest_did) = {
            let mut didtoken = didtoken.lock().unwrap();
            (didtoken.get_sys_did(), didtoken.get_device_did(), didtoken.get_guest_did())
        };
        let toeknuser = Self {
            sys_did,
            device_did,
            guest_did,
            guest_phrase,
            authorized,
            user_sessions,
            blacklist,
            user_base_dir: "".to_string(),
            entry_point,
            didtoken: didtoken.clone(),
        };
        toeknuser
    }

    pub fn get_sys_did(&self) -> String {
        self.sys_did.clone()
    }
    pub fn get_device_did(&self) -> String {
        self.device_did.clone()
    }

    pub fn get_guest_did(&self) -> String {
        self.guest_did.clone()
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
        let user_did = self.didtoken.lock().unwrap().add_crypt_secret_for_user(&user_claim, &phrase);
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
            let mut didtoken = self.didtoken.lock().unwrap();
            let user_did = didtoken.reverse_lookup_did_by_symbol(user_symbol_hash);
            let claim = didtoken.get_claim_from_local(&user_did);
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
                self.didtoken.lock().unwrap().remove_crypt_secret_for_user(&user_did);
                let identity_file = token_utils::get_path_in_sys_key_dir(&format!("user_identity_{}.token", user_hash_id));
                if identity_file.exists() {
                    if let Err(e) = fs::remove_file(identity_file.clone()) {
                        debug!("delete identity_file error: {}", e);
                    } else {
                        debug!("identity_file was deleted: {}", identity_file.display());
                    }
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

        let user_did = self.didtoken.lock().unwrap().add_crypt_secret_for_user(&user_claim, phrase);
        debug!("{} [UserBase] Import user: {}", token_utils::now_string(), user_did);

        user_did
    }

    pub fn export_user(&self, nickname: &str, telephone: &str, phrase: &str) -> String {
        let nickname = token_utils::truncate_nickname(nickname);
        let symbol_hash = IdClaim::get_symbol_hash_by_source(&nickname, Some(telephone.to_string()), None);
        let (user_did, claim) = {
            let mut didtoken = self.didtoken.lock().unwrap();
            let user_did = didtoken.reverse_lookup_did_by_symbol(symbol_hash);
            let claim = didtoken.get_claim_from_local(&user_did);
            (user_did, claim)
        };
        println!("{} [UserBase] Export user: {}, nickname={}, telephone={}", token_utils::now_string(), user_did, nickname, telephone);

        URL_SAFE_NO_PAD.encode(token_utils::export_identity(&nickname, telephone, claim.timestamp, phrase))
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
            if !context.is_default() && context.get_sys_did() == self.get_sys_did() &&
                self.didtoken.lock().unwrap().verify_by_did(&context.get_text(), &context.get_sig(), did) {
                let ivec_data = sled::IVec::from(context.to_json_string().as_bytes());
                let _ = self.authorized.lock().unwrap().insert(&key, ivec_data);
                context
            } else {
                if context.is_default() && did == &self.get_guest_did() {
                    self.sign_user_context(&self.get_guest_did(), &self.guest_phrase.clone())
                } else {
                    UserContext::default()
                }
            }

        } else { UserContext::default()  }
    }

    pub(crate) fn sign_user_context(&mut self, did: &str, phrase: &str) -> UserContext {
        if self.blacklist.contains(&did.to_string()) ||
            (did != self.get_guest_did() && !self.didtoken.lock().unwrap().is_registered(did) && did!=TOKEN_TM_DID.to_string()) {
            debug!("sign user context failed, did = {}", did);
            return UserContext::default();
        }
        let claim = self.didtoken.lock().unwrap().get_claim(did);
        let mut context = token_utils::get_or_create_user_context_token(
            did, &self.get_sys_did(), &claim.nickname, &claim.id_type, &claim.get_symbol_hash(), phrase);
        let _ = context.signature(phrase);
        if token_utils::update_user_token_to_file(&context, "add") == "Ok"  {
            let admin_did = self.didtoken.lock().unwrap().get_admin_did();
            if admin_did.is_empty() && did != self.get_guest_did() {
                self.didtoken.lock().unwrap().set_admin_did(did);
                println!("{} [UserBase] Set admin_did/设置系统管理 = {}", token_utils::now_string(), admin_did);
            }
            {
                let ivec_data = sled::IVec::from(context.to_json_string().as_bytes());
                let _ = self.authorized.lock().unwrap().insert(&format!("{}_{}", did, self.get_sys_did()), ivec_data);
            }
            context
        } else {
            debug!("Failed to save user token");
            UserContext::default()
        }
    }

    pub(crate) fn remove_context(&mut self, user_did: &str) {
        let context = self.get_user_context(user_did);
        let mut authorized = self.authorized.lock().unwrap();
        let key = format!("{}_{}", user_did, self.get_sys_did());
        let _ = match authorized.contains_key(&key).unwrap() {
            false => {},
            true => {
                let _ = authorized.remove(&key);
            }
        };
        let _ = token_utils::update_user_token_to_file(&context, "remove");
    }

    pub(crate) fn get_did_entry_point(&self, did: &str) -> String {
        self.entry_point.get_entry_point(did)
    }

    pub(crate) fn get_entry_point(&self) -> DidEntryPoint {
        self.entry_point.clone()
    }

    pub(crate) fn set_user_base_dir(&mut self, user_base_dir: &str) {
        self.user_base_dir = user_base_dir.to_string();
    }

    pub fn get_path_in_user_dir(&self, did: &str, catalog: &str) -> String {
        if !IdClaim::validity(did) {
            return "Invalid_did".to_string();
        }
        let sysinfo = &token_utils::SYSTEM_BASE_INFO;
        let user_base_dir = if self.user_base_dir.is_empty() {
            match BaseDirs::new() {
                Some(dirs) => dirs.home_dir().to_path_buf().join(".simpleai.vip").join("users"),
                None => PathBuf::from(sysinfo.root_dir.clone()).join(".simpleai.vip").join("users"),
            }
        } else {
            PathBuf::from(self.user_base_dir.clone())
        };
        if !user_base_dir.exists() {
            if let Err(e) = fs::create_dir_all(&user_base_dir) {
                eprintln!("Failed to create directory {}: {}", user_base_dir.display(), e);
                // 可以根据需要处理错误，例如返回一个默认路径或抛出错误
            }
        }

        let did_path =
            self.device_did.from_base58().expect("Failed to decode base58").iter()
                .zip(did.from_base58().expect("Failed to decode base58").iter())
                .map(|(&x, &y)| x ^ y).collect::<Vec<_>>().to_base58();

        let path_file =  if did == self.didtoken.lock().unwrap().get_admin_did() {
            user_base_dir.join(format!("admin_{}", did_path)).join(catalog)
        } else if did == self.get_guest_did() {
            user_base_dir.join("guest_user").join(catalog)
        } else {
            user_base_dir.join(did_path).join(catalog)
        };
        path_file.to_string_lossy().to_string()
    }
}




#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DidEntryPoint {
    entry_point: HashMap<String, String>,
}

impl DidEntryPoint {
    pub fn new() -> Self {
        let mut entry_point = HashMap::new();
        entry_point.insert(TOKEN_TM_DID.to_string(), TOKEN_TM_URL.to_string());
        Self {
            entry_point,
        }
    }

    pub fn add_entry_point(&mut self, did: &str, entry_point: &str) {
        self.entry_point.insert(did.to_string(), entry_point.to_string());
    }

    pub fn get_entry_point(&self, did: &str) -> String {
        self.entry_point.get(did).cloned().unwrap_or_else(|| TOKEN_TM_URL.to_string())
    }
}

pub struct AdminDefault {
    data: HashMap<String, String>,
}
impl AdminDefault {

    pub fn instance() -> Arc<Mutex<AdminDefault>> {
        ADMIN_DEFAULT.clone()
    }
    pub fn new() -> Self {
        let mut data= HashMap::new();
        data.insert("comfyd_active_checkbox".to_string(), "True".to_string());
        data.insert("fast_comfyd_checkbox".to_string(), "False".to_string());
        data.insert("reserved_vram".to_string(), "0".to_string());
        data.insert("minicpm_checkbox".to_string(), "False".to_string());
        data.insert("advanced_logs".to_string(), "False".to_string());
        data.insert("wavespeed_strength".to_string(), "0.12".to_string());
        data.insert("topbar_button_quantity".to_string(), "10".to_string());
        Self {
            data,
        }
    }
    pub fn get(&self, key: &str) -> String {
        self.data.get(key).unwrap_or(&"None".to_string()).to_string()
    }
    pub fn insert(&mut self, key: String, value: String) {
        self.data.insert(key, value);
    }
    pub fn remove(&mut self, key: &str) -> String {
        self.data.remove(key).unwrap_or("None".to_string())
    }
}
