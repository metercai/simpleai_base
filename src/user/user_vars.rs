use std::sync::{Arc, Mutex, RwLock};
use std::collections::HashMap;
use chrono::format;
use tracing::{error, warn, info, debug, trace};
use warp::filters::body::form;

use crate::dids::{self, DidToken, token_utils};
use crate::user::TokenUser;

lazy_static::lazy_static! {
    static ref ADMIN_DEFAULT: Arc<RwLock<AdminDefault>> = Arc::new(RwLock::new(AdminDefault::new()));
    static ref GLOBEL_LOCAL_VARS: Arc<RwLock<GlobalLocalVars>> = Arc::new(RwLock::new(GlobalLocalVars::new()));
}

#[derive(Clone, Debug)]
pub struct GlobalLocalVars {
    sys_did: String,
    device_did: String,
    guest_did: String,
    admin_did: String,
    global_local_vars: Arc<RwLock<sled::Tree>>, //HashMap<global|admin|{did}_{key}, String>,
    didtoken: Arc<Mutex<DidToken>>,
    tokenuser: Arc<Mutex<TokenUser>>,
}

impl GlobalLocalVars {
    pub fn instance() -> Arc<RwLock<GlobalLocalVars>> {
        GLOBEL_LOCAL_VARS.clone()
    }

    pub fn new() -> Self {
        let didtoken = DidToken::instance();
        let (sys_did, device_did, guest_did, admin_did, token_db) = {
            let didtoken = didtoken.lock().unwrap();
            (didtoken.get_sys_did(), didtoken.get_device_did(), didtoken.get_guest_did(), didtoken.get_admin_did(), didtoken.get_token_db())
        };
        let global_local_vars_tree = {
            let token_db = token_db.lock().unwrap();
            token_db.open_tree("global_local_vars").unwrap()
        };
        let global_local_vars = Arc::new(RwLock::new(global_local_vars_tree));

        Self {
            sys_did,
            device_did,
            guest_did,
            admin_did,
            global_local_vars,
            didtoken,
            tokenuser: TokenUser::instance(),
        }
    }
    
    /*pub fn get_vars_db(&self) -> Arc<RwLock<sled::Tree>> {
        self.global_local_vars.clone()
    } */

    pub fn get_admin_did(&self) -> String {
        self.sys_did.clone()
    }
    pub(crate) fn set_admin_did(&mut self, admin_did: &str) {
        self.admin_did = admin_did.to_string();
    }

    pub fn get_global_vars(&self, key: &str, default: &str) -> String {
        let key = format!("global_{}", key);
        let global_local_vars = self.global_local_vars.read().unwrap();
        match global_local_vars.get(&key) {
            Ok(Some(context)) => {
                String::from_utf8(context.to_vec()).unwrap()
            },
            _ => default.to_string()
        }
    }

    pub fn put_global_var(&mut self, key: &str, value: &str) {
        let key = format!("global_{}", key);
        let global_local_vars = self.global_local_vars.write().unwrap();
        let ivec_data = sled::IVec::from(value.as_bytes());
        let _ = global_local_vars.insert(&key, ivec_data);
    }

    pub fn get_global_vars_json(&self) -> String {
        let prefix = "global_";
        let mut global_vars: HashMap<String, String> = HashMap::new();
        let global_local_vars = self.global_local_vars.write().unwrap();
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

    pub(crate) fn get_local_admin_vars(&self, key: &str) -> String {
        let admin_key = format!("admin_{}_{}", self.sys_did, key);
        let admin_did = self.get_admin_did();
        self.get_local_vars(&admin_key, "default", &admin_did)
    }

    pub(crate) fn get_local_vars(&self, key: &str, default: &str, user_did: &str) -> String {
        // 1. 确定变量类型和键名
        let is_admin_var = key.starts_with("admin_");
        let (local_did, local_key) = if is_admin_var {
            (self.get_admin_did(), key.to_string())
        } else {
            (user_did.to_string(), format!("{}_{}_{}", user_did, self.sys_did, key))
        };
    
        // 2. 从存储中获取原始值
        let raw_value = {
            let global_local_vars = self.global_local_vars.read().unwrap();
            match global_local_vars.get(&local_key) {
                Ok(Some(var_value)) => String::from_utf8(var_value.to_vec()).unwrap_or_default(),
                _ => "Default".to_string()
            }
        };
        
        // 3. 处理特殊值情况
        if raw_value == "Default" || raw_value == "Unknown" {
            return if is_admin_var {
                let admin_key_prefix =  format!("admin_{}_", self.sys_did);
                let default_key_name = key.trim_start_matches(admin_key_prefix.as_str());
                AdminDefault::instance().read().unwrap().get(default_key_name)
            } else {
                default.to_string()
            };
        }
    
        // 4. 处理管理员变量解密
        if is_admin_var {
            if local_did.is_empty() {
                return "Unknown".to_string();
            }
            let admin_value = self.didtoken.lock().unwrap().decrypt_by_did(&raw_value, &local_did, 0);
            debug!("get and decode admin_value: {}", admin_value);
            if admin_value.is_empty() || admin_value == "Unknown"{
                let global_local_vars = self.global_local_vars.write().unwrap();
                match global_local_vars.remove(&local_key) {
                    Ok(_) => {
                        println!("成功删除变量: key={}", local_key);
                    },
                    Err(e) => {
                        println!("删除变量失败: key={}, error={:?}", local_key, e);
                    }
                }
                let admin_default = {
                    let admin_key_prefix =  format!("admin_{}_", self.sys_did);
                    let default_key_name = key.trim_start_matches(admin_key_prefix.as_str());
                    AdminDefault::instance().read().unwrap().get(default_key_name)
                };
                return admin_default;
            }
            return admin_value;
        }
    
        raw_value
    }

    pub(crate) fn set_local_vars(&mut self, key: &str, value: &str, user_did: &str) {
        let is_admin_var = key.starts_with("admin_");
        let admin_did = self.get_admin_did();
        if is_admin_var && admin_did != user_did {
            debug!("非管理员用户 {} 尝试设置管理员变量 {}", user_did, key);
            return;
        }
        let (local_key, local_value) = if is_admin_var {
            // 管理员变量需要加密
            let encrypted_value = self.didtoken.lock().unwrap()
                .encrypt_for_did(&value.as_bytes(), &admin_did, 0);
            let admin_key = format!("admin_{}_{}", self.sys_did, key);
            (admin_key.to_string(), encrypted_value)
        } else {
            // 普通用户变量
            (format!("{}_{}_{}", user_did, self.sys_did, key), value.to_string())
        };

        match self.global_local_vars.write() {
            Ok(mut global_local_vars) => {
                let ivec_data = sled::IVec::from(local_value.as_bytes());
                if let Err(e) = global_local_vars.insert(&local_key, ivec_data) {
                    error!("插入变量失败: key={}, error={:?}", local_key, e);
                } else {
                    debug!("成功设置变量: key={}", local_key);
                }
            },
            Err(e) => {
                error!("获取global_local_vars写锁失败: {:?}", e);
            }
        }
    }

    pub fn set_local_vars_for_guest(&mut self, key: &str, value: &str, user_did: &str) {
        let admin = self.didtoken.lock().unwrap().get_admin_did();
        let guest = self.guest_did.clone();
        if admin == user_did {
            let local_key = format!("{}_{}", guest, key);
            let local_value = value.to_string();
            let global_local_vars = self.global_local_vars.write().unwrap();
            let ivec_data = sled::IVec::from(local_value.as_bytes());
            let _ = global_local_vars.insert(&local_key, ivec_data);
        }
    }

    pub fn get_message_list(&self, user_did: &str) -> String {
        let key = format!("msg_list_{}", user_did);
        if let Ok(Some(data_str)) = self.global_local_vars.read().unwrap().get(&key) {
            if let Ok(data_str) = String::from_utf8(data_str.to_vec()) {
                return data_str;
            }
        }
        "".to_string()
    }

    pub fn set_message_list(&mut self, user_did: &str, message_list: &str) {
        let key = format!("msg_list_{}", user_did);
        let global_local_vars = self.global_local_vars.write().unwrap();
        let ivec_data = sled::IVec::from(message_list.as_bytes());
        let _ = global_local_vars.insert(&key, ivec_data);
    }
    
}


pub struct AdminDefault {
    data: HashMap<String, String>,
}
impl AdminDefault {

    pub fn instance() -> Arc<RwLock<AdminDefault>> {
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
        data.insert("p2p_remote_process".to_string(), "Disable".to_string());
        data.insert("p2p_in_did_list".to_string(), "".to_string());
        data.insert("p2p_out_did_list".to_string(), "".to_string());
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