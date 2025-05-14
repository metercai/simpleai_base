use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use serde_json::json;
use tracing::{error, warn, info, debug, trace};
use crate::dids::token_utils;
use crate::api;

lazy_static::lazy_static! {
    static ref TOKENDB: Arc<RwLock<TokenDB>> = Arc::new(RwLock::new(TokenDB::new()));
}

#[derive(Clone, Debug)]
pub struct TokenDB {
    sled_db: Arc<RwLock<Option<sled::Db>>>,
    trees: HashMap<String, sled::Tree>,
}
impl TokenDB {
    pub fn new() -> Self {
        let mut sled_db: Option<sled::Db> = None;
        let mut trees: HashMap<String, sled::Tree> = HashMap::new();
        if api::service::is_self_service()  {
            let db_path = token_utils::get_path_in_sys_key_dir("token.db");
            let config = sled::Config::new()
                .path(&db_path)
                .cache_capacity(10_000)
                .flush_every_ms(Some(1000));
            let sled_db1 = config.open().expect("Failed to open token database");
            let ready_users = sled_db1.open_tree("ready_users").unwrap();
            let authorized = sled_db1.open_tree("authorized").unwrap();
            let user_sessions = sled_db1.open_tree("user_sessions").unwrap();
            let global_local_vars = sled_db1.open_tree("global_local_vars").unwrap();
            let users = sled_db1.open_tree("user_tree").unwrap();
            let backups = sled_db1.open_tree("backups_tree").unwrap();
            let phones = sled_db1.open_tree("phone_tree").unwrap();
            
            trees.insert("ready_users".to_string(), ready_users);
            trees.insert("authorized".to_string(), authorized);
            trees.insert("user_sessions".to_string(), user_sessions);
            trees.insert("global_local_vars".to_string(), global_local_vars);
            trees.insert("user_tree".to_string(), users);
            trees.insert("backups_tree".to_string(), backups);
            trees.insert("phone_tree".to_string(), phones);

            sled_db = Some(sled_db1);
            println!("{} [SimpAI] Initialize the local db: {}", token_utils::now_string(), db_path.display());
        }
        Self {
            sled_db: Arc::new(RwLock::new(sled_db)),
            trees,
        }
    }

    pub fn instance() -> Arc<RwLock<TokenDB>> {
        TOKENDB.clone()
    }

    pub fn get(&self, tree: &str, key: &str) -> String {
        if self.trees.contains_key(tree) {
            let tree = self.trees.get(tree).unwrap();
            let value = match tree.get(&key.to_string()) {
                Ok(Some(data)) => String::from_utf8(data.to_vec()).unwrap(),
                _ => "Unknown".to_string(),
            };
            return value;
        } else {
            if api::service_online() {
                let params = json!({
                    "tree": tree,
                    "key": key,
                });
                let value = match api::request_api_sync::<String>("db_get", Some(params)) {
                    Ok(value) =>  value,
                    Err(e) => {
                        error!("Failed to get value from remote DB: {}", e);
                        "Unknown".to_string()
                    }
                };
                return value;
            }
        }
        "Unknown".to_string()
    }

    pub fn insert(&self, tree: &str, key: &str, value: &str) -> bool {
        if self.trees.contains_key(tree) {
            let ivec_data = sled::IVec::from(value.as_bytes());
            let tree = self.trees.get(tree).unwrap();
            tree.insert(key, ivec_data).is_ok()
        } else {
            if api::service_online() {
                let params = json!({
                    "tree": tree,
                    "key": key,
                    "value": value,
                });
                let _ = match api::request_api_sync::<bool>("db_insert", Some(params)) {
                    Ok(_) =>  true,
                    Err(e) => {
                        error!("Failed to insert value into remote DB: {}", e);
                        false
                    }
                };
                return true;
            }
            return false;
        }
    }

    pub fn remove(&self, tree: &str, key: &str) -> bool {
        if self.trees.contains_key(tree) {
            let tree = self.trees.get(tree).unwrap();
            match tree.contains_key(key) {
                Ok(true) => {
                    tree.remove(key).is_ok()
                },
                _ => false,
            }
        } else {
            if api::service_online() {
                let params = json!({
                    "tree": tree,
                    "key": key,
                });
                let _ = match api::request_api_sync::<bool>("db_remove", Some(params)) {
                    Ok(_) =>  true,
                    Err(e) => {
                        error!("Failed to remove value from remote DB: {}", e);
                        false
                    }
                };
                return true;
            }
            return false;
        }   
    }

    pub fn scan_prefix(&self, tree: &str, prefix: &str) -> HashMap<String, String> {
        let mut result: HashMap<String, String> = HashMap::with_capacity(32);
        if self.trees.contains_key(tree) {
            let tree = self.trees.get(tree).unwrap();
            for item in tree.scan_prefix(prefix) {
                match item {
                    Ok((key, value)) => {
                        let key_str = String::from_utf8(key.to_vec()).unwrap();
                        let value_str = String::from_utf8(value.to_vec()).unwrap();
                        result.insert(key_str, value_str);  
                    }
                    Err(e) => {
                        error!("读取全局变量键值对失败: error={:?}", e);
                    }
                }
            }
            return result;
        } else {
            if api::service_online() {
                let params = json!({
                    "tree": tree,
                    "prefix": prefix,
                });
                let result = match api::request_api_sync::<HashMap<String, String>>("db_scan_prefix", Some(params)) {
                    Ok(result_data) =>  result_data,
                    Err(e) => {
                        error!("Failed to scan prefix from remote DB: {}", e);
                        HashMap::new()
                    }
                };
                return result;
            }
            HashMap::new()
        }
    }
}