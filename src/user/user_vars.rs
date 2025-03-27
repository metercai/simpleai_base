use std::sync::{Arc, Mutex, RwLock};
use std::collections::HashMap;
use tracing::{error, warn, info, debug, trace};

use crate::dids::{self, DidToken, token_utils};
use crate::user::TokenUser;

lazy_static::lazy_static! {
    static ref ADMIN_DEFAULT: Arc<Mutex<AdminDefault>> = Arc::new(Mutex::new(AdminDefault::new()));
    static ref GLOBEL_LOCAL_VARS: Arc<Mutex<GlobalLocalVars>> = Arc::new(Mutex::new(GlobalLocalVars::new()));
}

#[derive(Clone, Debug)]
pub struct GlobalLocalVars {
    sys_did: String,
    device_did: String,
    guest_did: String,
    global_local_vars: Arc<Mutex<sled::Tree>>, //HashMap<global|admin|{did}_{key}, String>,
    didtoken: Arc<Mutex<DidToken>>,
    tokenuser: Arc<Mutex<TokenUser>>,
}

impl GlobalLocalVars {
    pub fn instance() -> Arc<Mutex<GlobalLocalVars>> {
        GLOBEL_LOCAL_VARS.clone()
    }

    pub fn new() -> Self {
        let didtoken = DidToken::instance();
        let (sys_did, device_did, guest_did, token_db) = {
            let didtoken = didtoken.lock().unwrap();
            (didtoken.get_sys_did(), didtoken.get_device_did(), didtoken.get_guest_did(), didtoken.get_token_db())
        };
        let global_local_vars_tree = {
            let token_db = token_db.lock().unwrap();
            token_db.open_tree("global_local_vars").unwrap()
        };
        let global_local_vars = Arc::new(Mutex::new(global_local_vars_tree));

        Self {
            sys_did,
            device_did,
            guest_did,
            global_local_vars,
            didtoken,
            tokenuser: TokenUser::instance(),
        }
    }
    
    pub fn get_vars_db(&self) -> Arc<Mutex<sled::Tree>> {
        self.global_local_vars.clone()
    }

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

    pub fn put_global_var(&mut self, key: &str, value: &str) {
        let key = format!("global_{}", key);
        let global_local_vars = self.global_local_vars.lock().unwrap();
        let ivec_data = sled::IVec::from(value.as_bytes());
        let _ = global_local_vars.insert(&key, ivec_data);
    }

    pub fn get_global_vars_json(&mut self) -> String {
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

    pub(crate) fn get_local_admin_vars(&mut self, key: &str) -> String {
        let admin_key = format!("admin_{}", key);
        let default = AdminDefault::instance().lock().unwrap().get(key).to_string();
        let admin = self.didtoken.lock().unwrap().get_admin_did();
        self.get_local_vars(&admin_key, &default, &admin)
    }

    pub(crate) fn get_local_vars(&mut self, key: &str, default: &str, user_did: &str) -> String {
        let (local_did, local_key) = if key.starts_with("admin_") {
            (self.didtoken.lock().unwrap().get_admin_did(), key.to_string())
        } else {
            (user_did.to_string(), format!("{}_{}", user_did, key))
        };

        let mut value = {
            let global_local_vars = self.global_local_vars.lock().unwrap();
            match global_local_vars.get(&local_key) {
                Ok(Some(var_value)) => {
                    String::from_utf8(var_value.to_vec()).unwrap()
                },
                _ => "Default".to_string()
            }
        };
        if local_key.starts_with("admin_") && value != "Default"{
            value = self.didtoken.lock().unwrap().decrypt_by_did(&value, &local_did, 0);
        }
        if value == "Default" || value == "Unknown" {
            if local_key.starts_with("admin_") {
                let local_key = local_key.replace("admin_", "");
                let admin_default = AdminDefault::instance().lock().unwrap().get(&local_key).to_string();
                admin_default
            } else {
                default.to_string()
            }
        } else { value }

    }

    pub(crate) fn set_local_vars(&mut self, key: &str, value: &str, user_did: &str) {
        let admin = self.didtoken.lock().unwrap().get_admin_did();
        let (local_key, local_value) = if key.starts_with("admin_") && admin == user_did  {
            let encrypted_value = self.didtoken.lock().unwrap().encrypt_for_did(&value.as_bytes(), &admin, 0);
            (key.to_string(), encrypted_value)
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

    pub fn set_local_vars_for_guest(&mut self, key: &str, value: &str, user_did: &str) {
        let admin = self.didtoken.lock().unwrap().get_admin_did();
        let guest = self.guest_did.clone();
        if admin == user_did {
            let local_key = format!("{}_{}", guest, key);
            let local_value = value.to_string();
            let global_local_vars = self.global_local_vars.lock().unwrap();
            let ivec_data = sled::IVec::from(local_value.as_bytes());
            let _ = global_local_vars.insert(&local_key, ivec_data);
        }
    }

    pub fn get_message_list(&mut self, user_did: &str) -> String {
        let key = format!("msg_list_{}", user_did);
        if let Ok(Some(data_str)) = self.global_local_vars.lock().unwrap().get(&key) {
            if let Ok(data_str) = String::from_utf8(data_str.to_vec()) {
                return data_str;
            }
        }
        "".to_string()
    }

    pub fn set_message_list(&mut self, user_did: &str, message_list: &str) {
        let key = format!("msg_list_{}", user_did);
        let global_local_vars = self.global_local_vars.lock().unwrap();
        let ivec_data = sled::IVec::from(message_list.as_bytes());
        let _ = global_local_vars.insert(&key, ivec_data);
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
        data.insert("p2p_active_checkbox".to_string(), "False".to_string());
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