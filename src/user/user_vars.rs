use std::sync::{Arc, Mutex, RwLock};
use std::collections::HashMap;
use chrono::format;
use tracing::{error, warn, info, debug, trace};
use warp::filters::body::form;

use crate::dids::{self, DidToken, tokendb::TokenDB};
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
    token_db: Arc<RwLock<TokenDB>>, //HashMap<global|admin|{did}_{key}, String>,
    didtoken: Arc<Mutex<DidToken>>,
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
        
        Self {
            sys_did,
            device_did,
            guest_did,
            admin_did,
            token_db,
            didtoken,
        }
    }

    pub fn get_admin_did(&self) -> String {
        self.admin_did.clone()
    }
    pub(crate) fn set_admin_did(&mut self, admin_did: &str) {
        self.admin_did = admin_did.to_string();
    }

    pub fn get_global_vars(&self, key: &str, default: &str) -> String {
        let key = format!("global_{}", key);
        let token_db = match self.token_db.read() {
            Ok(guard) => guard,
            Err(e) => {
                error!("获取全局变量读锁失败: key={}, error={:?}", key, e);
                return default.to_string();
            }
        };
        let vars_value = token_db.get("global_local_vars", &key);
        if !vars_value.is_empty() && vars_value != "Unknown" {
            vars_value
        } else {
            default.to_string()
        }
    }

    pub fn put_global_var(&mut self, key: &str, value: &str) {
        let key = format!("global_{}", key);
        let mut token_db = match self.token_db.write() {
            Ok(guard) => guard,
            Err(e) => {
                error!("获取全局变量写锁失败: key={}, error={:?}", key, e);
                return;
            }
        };
        token_db.insert("global_local_vars", &key, value);
    }

    pub fn get_global_vars_json(&self) -> String {
        let prefix = "global_";
        let global_vars: HashMap<String, String> = HashMap::new();
        let token_db = match self.token_db.write() {
            Ok(guard) => guard,
            Err(e) => {
                error!("获取全局变量写锁失败: error={:?}", e);
                return serde_json::to_string(&global_vars).unwrap_or_default();
            }
        };
        let global_vars = token_db.scan_prefix("global_local_vars", prefix);
        match serde_json::to_string(&global_vars) {
            Ok(json) => json,
            Err(e) => {
                error!("全局变量JSON序列化失败: error={:?}", e);
                String::new()
            }
        }
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
        let raw_value = match self.token_db.read() {
            Ok(guard) => guard.get("global_local_vars", &local_key),
            Err(e) => {
                error!("从存储中获取原始值: key={}, error={:?}", local_key, e);
                "Unknown".to_string()
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
                match self.token_db.write() {
                    Ok(guard) => guard.remove("global_local_vars", &local_key),
                    Err(e) => {
                        error!("获取全局变量写锁失败: error={:?}", e);
                        false
                    }
                };
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

    pub(crate) fn set_local_admin_vars(&mut self, key: &str, value: &str) {
        let admin_key = format!("admin_{}_{}", self.sys_did, key);
        let admin_did = self.get_admin_did();
        self.set_local_vars(&admin_key, value, &admin_did);
    }

    pub(crate) fn set_local_vars(&mut self, key: &str, value: &str, user_did: &str) {
        let is_admin_var = key.starts_with("admin_");
        let admin_did = self.get_admin_did();
        if is_admin_var && admin_did != user_did {
            println!("非管理员用户 {} 在尝试设置管理员变量 {}", user_did, key);
            return;
        }
        let (local_key, local_value) = if is_admin_var {
            // 管理员变量需要加密
            let encrypted_value = self.didtoken.lock().unwrap()
                .encrypt_for_did(&value.as_bytes(), &admin_did, 0);
            let admin_key = key.trim_start_matches("admin_");
            let admin_key = format!("admin_{}_{}", self.sys_did, admin_key);
            (admin_key.to_string(), encrypted_value)
        } else {
            // 普通用户变量
            (format!("{}_{}_{}", user_did, self.sys_did, key), value.to_string())
        };
        let _ = match self.token_db.write() {
            Ok(mut guard) => guard.insert("global_local_vars", &local_key, &local_value),
            Err(e) => {
                error!("获取global_local_vars写锁失败: {:?}", e);
                false
            }
        };
    }

    pub fn set_local_vars_for_guest(&mut self, key: &str, value: &str, user_did: &str) {
        let admin = self.didtoken.lock().unwrap().get_admin_did();
        let guest = self.guest_did.clone();
        if admin != user_did {
            return;
        }
        let local_key = format!("{}_{}_{}", guest, self.sys_did, key);
        let local_value = value.to_string();
        let _ = match self.token_db.write() {
            Ok(mut guard) => guard.insert("global_local_vars", &local_key, &local_value),
            Err(e) => {
                error!("获取global_local_vars写锁失败: {:?}", e);
                false
            }
        };
    }

    pub fn get_message_list(&self, user_did: &str) -> String {
        let key = format!("msg_list_{}_{}", self.sys_did, user_did);
        let result = match self.token_db.read() {
            Ok(guard) => guard.get("global_local_vars", &key),
            Err(e) => {
                error!("获取消息列表读锁失败: user_did={}, error={:?}", user_did, e);
                String::new()
            }
        };
        result
    }

    pub fn set_message_list(&mut self, user_did: &str, message_list: &str) {
        let key = format!("msg_list_{}_{}", self.sys_did, user_did);
        let _ = match self.token_db.write() {
            Ok(guard) => guard.insert("global_local_vars", &key, &message_list),
            Err(e) => {
                error!("获取消息列表写锁失败: user_did={}, error={:?}", user_did, e);
                false
            }
        };
    }
    
    pub(crate) fn is_allowed_did(&self, did: &str, way: &str) -> bool {
        if way == "web" || way == "p2p" {
            self.get_local_admin_vars(&format!("{way}_in_did_list")).contains(did)
        } else {
            false
        }
    }

    pub(crate) fn get_allowed_did_list(&self, way: &str) -> String {
        if way!= "web" && way!= "p2p" {
            return String::new();
        }
        let list_key = format!("{way}_in_did_list");
        self.get_local_admin_vars(&list_key)
    }

    pub(crate) fn add_allowed_did(&mut self, did: &str, way: &str) {
        if way != "web" && way != "p2p" {
            return;
        }
        let list_key = format!("{way}_in_did_list");

        let mut did_list = self.get_local_admin_vars(&list_key);
        if did_list.is_empty() {
            did_list = did.to_string();
        } else {
            if did_list.contains(did) {
                return;
            } else {
                did_list.push_str(",");
                did_list.push_str(did);
            }
        }
        self.set_local_admin_vars(&list_key, &did_list);
    }

    pub(crate) fn remove_allowed_did(&mut self, did: &str, way: &str) {
        if way != "web" && way != "p2p" {
            return;
        }
        let list_key = format!("{way}_in_did_list");

        let mut did_list = self.get_local_admin_vars(&list_key);
        if did_list.is_empty() {
            return;
        } else {
            if !did_list.contains(did) {
                return;
            } else {
                let updated_list: Vec<&str> = did_list
                    .split(',')
                    .map(|s| s.trim())
                    .filter(|&s| s != did && !s.is_empty())
                    .collect();
                let new_did_list = updated_list.join(",");
                self.set_local_admin_vars(&list_key, &new_did_list);
            }
        }
    }

    pub(crate) fn is_pending_did(&self, did: &str, way: &str) -> bool {
        if way == "web" || way == "p2p" {
            self.get_local_admin_vars(&format!("{way}_pending_did_list")).contains(did)
        } else {
            false
        }
    }

    pub(crate) fn get_pending_did_list(&self, way: &str) -> String {
        if way!= "web" && way!= "p2p" {
            return String::new();
        }
        let list_key = format!("{way}_pending_did_list");
        self.get_local_admin_vars(&list_key)
    }

    pub(crate) fn add_pending_did(&mut self, did: &str, way: &str) {
        if way != "web" && way != "p2p" {
            return;
        }
        let list_key = format!("{way}_pending_did_list");

        let mut did_list = self.get_local_admin_vars(&list_key);
        if did_list.is_empty() {
            did_list = did.to_string();
        } else {
            if did_list.contains(did) {
                return;
            } else {
                did_list.push_str(",");
                did_list.push_str(did);
            }
        }
        self.set_local_admin_vars(&list_key, &did_list);
    }

    pub(crate) fn remove_pending_did(&mut self, did: &str, way: &str) {
        if way != "web" && way != "p2p" {
            return;
        }
        let list_key = format!("{way}_pending_did_list");

        let mut did_list = self.get_local_admin_vars(&list_key);
        if did_list.is_empty() {
            return;
        } else {
            if !did_list.contains(did) {
                return;
            } else {
                let updated_list: Vec<&str> = did_list
                    .split(',')
                    .map(|s| s.trim())
                    .filter(|&s| s != did && !s.is_empty())
                    .collect();
                let new_did_list = updated_list.join(",");
                self.set_local_admin_vars(&list_key, &new_did_list);
            }
        }
    }

    pub(crate) fn pending_to_allowed_did(&mut self, did: &str, way: &str) {
        self.remove_pending_did(did, way);
        self.add_allowed_did(did, way);
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
        data.insert("translation_methods".to_string(), "Third APIs".to_string());
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