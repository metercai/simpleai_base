use std::collections::HashMap;
use std::fs;
use std::thread;
use std::sync::{Arc, Mutex, RwLock};

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use std::path::{Path, PathBuf};
use chrono::format;
use prometheus_client::metrics::info;
use serde_json::{self, json};
use base58::{ToBase58, FromBase58};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use tracing::{error, warn, info, debug, trace};
use tracing_subscriber::EnvFilter;
use qrcode::{QrCode, Version, EcLevel};
use qrcode::render::svg;


use pyo3::prelude::*;

use crate::dids::{self, DidToken, token_utils};
use crate::{exchange_key, issue_key};
use crate::utils::error::TokenError;
use crate::utils::env_data::EnvData;
use crate::dids::claims::{GlobalClaims, IdClaim, UserContext, };
use crate::utils::systeminfo::SystemInfo;
use crate::dids::cert_center::GlobalCerts;
use crate::dids::TOKEN_ENTRYPOINT_DID;
use crate::user::user_mgr::{OnlineUsers, MessageQueue};
use crate::user::{TokenUser, DidEntryPoint};
use crate::p2p::{self, P2p, DEFAULT_P2P_CONFIG, P2P_HANDLE, P2P_INSTANCE};
use crate::user::shared::{self, SharedData};
use crate::user::user_vars::{AdminDefault, GlobalLocalVars};


pub(crate) static TOKEN_API_VERSION: &str = "v1.2.2";


static SYNC_TASK_HANDLE: Mutex<Option<tokio::task::JoinHandle<()>>> = Mutex::new(None);

#[derive(Clone)]
#[pyclass]
pub struct SimpleAI {
    pub sys_name: String,
    pub sys_did: String,
    pub device_did: String,
    pub guest_did: String,

    didtoken: Arc<Mutex<DidToken>>,
    tokenuser: Arc<Mutex<TokenUser>>,
    ready_users: Arc<Mutex<sled::Tree>>, //HashMap<String, serde_json::Value>,
    global_local_vars: Arc<Mutex<GlobalLocalVars>>, //HashMap<global|admin|{did}_{key}, String>,
    online_users: OnlineUsers,
    last_timestamp: Arc<RwLock<u64>>,
    sid_did_map: Arc<Mutex<HashMap<String, String>>>,
    shared_data: &'static SharedData,
    p2p_config: String,
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

        let (system_name, sys_phrase, device_name, device_phrase, guest_name, guest_phrase)
            = dids::get_system_vars();
        debug!("system_name:{}, device_name:{}, guest_name:{}", system_name, device_name, guest_name);

        let didtoken = DidToken::instance();
        let tokenuser = TokenUser::instance();
        let global_local_vars = GlobalLocalVars::instance();

        let (sys_did, device_did, guest_did, token_db) = {
            let didtoken = didtoken.lock().unwrap();
            (didtoken.get_sys_did(), didtoken.get_device_did(), didtoken.get_guest_did(), didtoken.get_token_db())
        };
        let ready_users_tree = {
            let token_db = token_db.lock().unwrap();
            token_db.open_tree("ready_users").unwrap()
        };
        let ready_users = Arc::new(Mutex::new(ready_users_tree));
    
        let online_users = OnlineUsers::new(60, 2);
        let message_queue = MessageQueue::new(global_local_vars.clone());
        let mut shared_data = shared::get_shared_data();
        shared_data.set_message_queue(message_queue);
        shared_data.set_sys_did(&sys_did);

        let admin_did = didtoken.lock().unwrap().get_admin_did();
        if !admin_did.is_empty() {
            //online_users.log_register(admin_did.clone());
            shared_data.online_all.log_register(admin_did.clone());
        }
        
        Self {
            sys_name,
            sys_did,
            device_did,
            guest_did,
            didtoken,
            tokenuser,
            ready_users,
            global_local_vars,
            online_users,
            last_timestamp: Arc::new(RwLock::new(0u64)),
            sid_did_map: Arc::new(Mutex::new(HashMap::new())),
            shared_data,
            p2p_config: DEFAULT_P2P_CONFIG.to_string(),
        }
    }


    pub fn get_sys_name(&self) -> String { self.sys_name.clone() }
    pub fn get_sys_did(&self) -> String { self.sys_did.clone() }

    pub fn get_device_did(&self) -> String {
        self.device_did.clone()
    }
    pub fn get_guest_did(&self) -> String {
        self.guest_did.clone()
    }
    pub fn is_guest(&self, did: &str) -> bool {
        did == self.guest_did.as_str()
    }

    pub fn get_sysinfo(&self) -> SystemInfo {
        self.didtoken.lock().unwrap().get_sysinfo()
    }

    pub fn get_node_mode(&mut self) -> String {
        let system_did = self.get_sys_did();
        let node_mode = self.global_local_vars.lock().unwrap().get_local_vars("node_mode_type", "online", &system_did);
        {
            let mut didtoken = self.didtoken.lock().unwrap();
            didtoken.set_node_mode(&node_mode);
            didtoken.get_node_mode()
        }
    }

    pub fn set_node_mode(&mut self, mode: &str) {
        let system_did = self.get_sys_did();
        let current_mode = self.global_local_vars.lock().unwrap().get_local_vars("node_mode_type", "online", &system_did);
        if mode != current_mode.as_str() {
            self.global_local_vars.lock().unwrap().set_local_vars("node_mode_type", mode, &self.get_sys_did());
            self.didtoken.lock().unwrap().set_node_mode(&mode);
        }
    }

    pub(crate) fn get_admin_did(&self) -> String {
        self.didtoken.lock().unwrap().get_admin_did()
    }

    pub(crate) fn set_admin_did(&mut self, did: &str) {
        if !did.is_empty() {
            self.log_register(&did);
            self.didtoken.lock().unwrap().set_admin_did(did);
        }
    }

    pub fn is_admin(&self, did: &str) -> bool {
        did == self.get_admin_did()
    }

    pub fn absent_admin(&self) -> bool {
        self.get_admin_did().is_empty()
    }

    pub fn get_p2p_upstream_did(&mut self) -> String {
        self.sys_name = format!("{}_p2p", self.sys_name);
        self.get_upstream_did()
    }

    pub fn disconnect_upstream(&mut self) {
        self.didtoken.lock().unwrap().set_upstream_did("");
        if self.get_local_admin_vars("p2p_active_checkbox") == "False" && !self.get_sys_name().ends_with("_p2p") {
            self.p2p_stop();
        }
        let mut handle_guard = SYNC_TASK_HANDLE.lock().unwrap();
        if let Some(handle) = handle_guard.take() {
            handle.abort();
            *handle_guard = None;
        }
    }

    pub fn get_upstream_did(&mut self) -> String {
        if self.get_admin_did() == dids::TOKEN_ENTRYPOINT_DID {
            self.didtoken.lock().unwrap().set_upstream_did(dids::TOKEN_ENTRYPOINT_DID);
            if self.get_sys_name().ends_with("_p2p"){
                self.p2p_start();
            }
            return dids::TOKEN_ENTRYPOINT_DID.to_string();
        }
        let upstream_did = self.didtoken.lock().unwrap().get_upstream_did();
        if !upstream_did.is_empty() && !upstream_did.starts_with("Unknown") {
            return upstream_did.clone();
        }
        let timeout = Duration::from_secs(6);
        let start_time = Instant::now();
        let mut upstream_did = upstream_did.clone();
        while start_time.elapsed() < timeout {
            if !upstream_did.is_empty() && !upstream_did.starts_with("Unknown") {
                break;
            }
            upstream_did = self.register_upstream();
            std::thread::sleep(Duration::from_millis(1000));
        }
        debug!("get upstream_did from root: {}", upstream_did);
        if !upstream_did.is_empty() && !upstream_did.starts_with("Unknown") {
            self.didtoken.lock().unwrap().set_upstream_did(&upstream_did.clone());
            let upstream_url =  self.tokenuser.lock().unwrap().get_did_entry_point(&upstream_did.clone());
            let sys_did = self.get_sys_did();
            let dev_did = self.get_device_did();
            let mut handle_guard = SYNC_TASK_HANDLE.lock().unwrap();
            if let Some(handle) = handle_guard.take() {
                handle.abort();
            }
            
            let sys_did_owned = sys_did.clone();
            let dev_did_owned = dev_did.clone();
            let upstream_did_owned = upstream_did.clone();

            let entry_point = self.tokenuser.lock().unwrap().get_entry_point();
            let entry_point = Arc::new(tokio::sync::Mutex::new(entry_point));
            let online_users = Arc::new(tokio::sync::Mutex::new(self.online_users.clone()));
            let message_queue =  self.shared_data.get_message_queue().clone();

            let handle = dids::TOKIO_RUNTIME.spawn(async move {
                let task1 = submit_uncompleted_request_files(&upstream_url, &sys_did_owned, &dev_did_owned);
                let task2 = sync_upstream(&sys_did_owned, &dev_did_owned, upstream_did_owned,
                        entry_point, online_users, message_queue);
                tokio::join!(task1, task2);
            });
            *handle_guard = Some(handle);

            if self.get_local_admin_vars("p2p_active_checkbox") == "True" || self.get_sys_name().ends_with("_p2p"){
                self.p2p_start();
            }
        }
        upstream_did
    }



    pub(crate) fn p2p_start(&mut self) -> String {
        {
            let mut p2p_handle = P2P_HANDLE.lock().unwrap();
            if p2p_handle.is_some() {
                return "P2P 服务已经在运行中".to_string();
            }
        }
        
        let p2p_config = self.get_p2p_config();
        let (local_claim, sysinfo) = {
            let didtoken = self.didtoken.lock().unwrap();
            (didtoken.get_claim(&self.get_sys_did()), didtoken.get_sysinfo())
        };
        let handle = dids::TOKIO_RUNTIME.spawn(async move {
            match P2p::start(p2p_config, &local_claim, &sysinfo).await {
                Ok(p2p) => {
                    let mut p2p_instance_guard = P2P_INSTANCE.lock().await;
                    *p2p_instance_guard = Some(p2p);
                },
                Err(e) => {
                    error!("P2P 服务启动失败: {:?}", e);
                }
            }
        });
        let mut p2p_handle = P2P_HANDLE.lock().unwrap();
        *p2p_handle = Some(handle);

        "P2P 服务启动成功".to_string()
    }
    
    /// 停止 P2P 服务
    pub(crate) fn p2p_stop(&mut self) -> String {
        // 如果没有运行的服务，返回提示信息
        let mut p2p_handle = P2P_HANDLE.lock().unwrap();
        if p2p_handle.is_none() {
            return "P2P 服务未运行".to_string();
        }
        
        // 取出并中止 P2P 服务
        if let Some(handle) = p2p_handle.take() {
            dids::TOKIO_RUNTIME.block_on(async {
                if let Some(p2p) = p2p::get_instance().await {
                    p2p.stop().await;
                }
                let mut p2p_instance_guard = P2P_INSTANCE.lock().await;
                *p2p_instance_guard = None;
            });
            handle.abort();
            println!("{} [P2pNode] p2p server({}) has stopped.", token_utils::now_string(), self.get_sys_did());
            "P2P 服务已停止".to_string()
        } else {
            "P2P 服务未运行".to_string()
        }
    }
    
    /// 重启 P2P 服务
    pub(crate) fn p2p_restart(&mut self) -> String {
        // 先停止服务
        let stop_result = self.p2p_stop();
        
        // 等待一小段时间确保服务完全停止
        std::thread::sleep(Duration::from_millis(500));
        
        // 再启动服务
        let start_result = self.p2p_start();
        
        format!("P2P 服务重启: {}, {}", stop_result, start_result)
    }

    fn get_p2p_config(&mut self) -> String {
        let mut p2p_config = self.get_local_admin_vars("p2p_config");
        if !p2p_config.is_empty() && p2p_config != "None" {
            return p2p_config;
        } else {
            let config_path = Path::new("p2pconfig.toml");
            if config_path.exists() {
                match fs::read_to_string(config_path) {
                    Ok(content) => {
                        debug!("使用本地 p2pconfig.toml 文件配置: {}", content);
                        return content;
                    },
                    Err(e) => {
                        debug!("读取 p2pconfig.toml 文件失败: {}, 使用默认配置", e);
                    }
                }
            }
        } 
        return self.p2p_config.clone();
    }

    pub fn get_global_status(&self, sid: &str, last_timestamp: u64) -> (usize, usize, usize) {
        let last_time = self.last_timestamp.read().unwrap();
        let user_list = self.online_users.get_full_list();
        let did = self.sid_did_map.lock().unwrap().get(sid).cloned().unwrap_or_default();
        self.shared_data.get_last(&did, last_timestamp, Some(&user_list))
    }


    pub fn get_online_users_number(&self) -> usize {
        self.online_users.get_number()
    }

    pub fn get_online_nodes_users(&self) -> (usize, usize) {
        self.online_users.get_nodes_users()
    }

    pub fn get_online_nodes_top(&self) -> String {
        self.online_users.get_nodes_top_list()
    }

    pub fn log_register(&self, sid: &str) {
        let did = self.sid_did_map.lock().unwrap().get(sid).cloned().unwrap_or_default();
        self.online_users.log_register(did.to_string());
        self.shared_data.online_all.log_register(did.to_string());
    }

    pub fn log_access(&self, sid: &str) {
        let did = self.sid_did_map.lock().unwrap().get(sid).cloned().unwrap_or_default();
        self.online_users.log_access(did.to_string());
        self.shared_data.online_all.log_access(did.to_string());
    }

    pub fn get_global_msg_number(&self) -> usize {
        self.shared_data.get_message_queue().get_msg_number(&self.get_sys_did())
    }

    pub fn get_global_msg_all(&self) -> String {
        self.shared_data.get_message_queue().get_messages(&self.get_sys_did(), 0)
    }

    pub fn remove_old_global_msg(&self, timestamp: u64) {
        self.shared_data.get_message_queue().remove_old_messages(&self.get_sys_did(), timestamp);
    }

    pub fn get_global_msg_list(&self, last_timestamp: u64) -> String {
        self.shared_data.get_message_queue().get_messages(&self.get_sys_did(), last_timestamp)
    }

    pub fn put_global_message(&self, message: &str) {
        let _ = self.shared_data.get_message_queue().push_messages(&self.get_sys_did(), message.to_string());
    }

    pub fn get_global_vars(&mut self, key: &str, default: &str) -> String {
        self.global_local_vars.lock().unwrap().get_global_vars(key, default)
    }

    pub fn put_global_var(&mut self, key: &str, value: &str) {
        self.global_local_vars.lock().unwrap().put_global_var(key, value)
    }

    pub fn get_global_vars_json(&mut self) -> String {
        self.global_local_vars.lock().unwrap().get_global_vars_json()
    }

    pub fn get_local_vars(&mut self, key: &str, default: &str, user_session: &str, ua_hash: &str) -> String {
        let user_did = self.check_sstoken_and_get_did(user_session, ua_hash);
        self.global_local_vars.lock().unwrap().get_local_vars(key, default, &user_did)
    }

    pub fn get_local_admin_vars(&mut self, key: &str) -> String {
        self.global_local_vars.lock().unwrap().get_local_admin_vars(key)
    }

    pub fn set_local_vars(&mut self, key: &str, value: &str, user_session: &str, ua_hash: &str) {
        let user_did = self.check_sstoken_and_get_did(user_session, ua_hash);
        self.global_local_vars.lock().unwrap().set_local_vars(key, value, &user_did)
    }

    pub fn set_local_admin_vars(&mut self, key: &str, value: &str, user_session: &str, ua_hash: &str) {
        let user_did = self.check_sstoken_and_get_did(user_session, ua_hash);
        if user_did == self.get_admin_did() {
            self.global_local_vars.lock().unwrap().set_local_vars(&format!("admin_{}", key), value, &user_did)
        }
    }

    pub fn set_local_vars_for_guest(&mut self, key: &str, value: &str, user_session: &str, ua_hash: &str) {
        let user_did = self.check_sstoken_and_get_did(user_session, ua_hash);
        self.global_local_vars.lock().unwrap().set_local_vars_for_guest(key, value, &user_did)
    }



    pub fn reset_admin(&mut self, admin_did: &str) -> String {
        if IdClaim::validity(admin_did) {
            let admin_claim = self.get_claim(admin_did);
            let is_registered = self.is_registered(admin_did);

            if !admin_claim.is_default() && is_registered {
                let old_admin = self.get_admin_did();
                self.set_admin_did(admin_did);
                {
                    let mut tokenuser = self.tokenuser.lock().unwrap();
                    tokenuser.remove_context(admin_did);
                    tokenuser.remove_context(&old_admin);
                }
                println!("{} [UserBase] reset_admin to {}", token_utils::now_string(), admin_did);
                return "OK".to_string();
            }
        }
        "Unknown".to_string()
    }

    pub fn reset_node_mode(&mut self, mode: &str) -> (String, String, String) {
        let node_mode = self.get_node_mode();
        if mode == "isolated" && node_mode != "isolated" {
            println!("{} [UserBase] reset node mode to isolated", token_utils::now_string());
            // 清除非 device，system，guest 的 crypt_secrets
            let remove_dids = self.didtoken.lock().unwrap().remove_crypt_secrets_for_users();
            // 清除非 guest 的 token
            {
                let mut tokenuser = self.tokenuser.lock().unwrap();
                for did in &remove_dids {
                    tokenuser.remove_context(did);
                }
            }
            let (system_name, sys_phrase, device_name, device_phrase, guest_name, guest_phrase)
                = dids::get_system_vars();
            let admin_name = guest_name.replace("guest_", "admin_");
            let admin_symbol_hash = IdClaim::get_symbol_hash_by_source(&admin_name, Some("8610000000001".to_string()), None);
            let (admin_hash_id, admin_phrase) = token_utils::get_key_hash_id_and_phrase("User", &admin_symbol_hash);
            let admin_did= {
                let user_did = self.didtoken.lock().unwrap().reverse_lookup_did_by_symbol(admin_symbol_hash);
                let identity_file = token_utils::get_path_in_sys_key_dir(&format!("user_identity_{}.token", admin_hash_id));
                if user_did != "Unknown" && identity_file.exists() {
                    let encrypted_identity = fs::read_to_string(identity_file.clone()).expect(&format!("Unable to read file: {}", identity_file.display()));
                    self.tokenuser.lock().unwrap().import_user(&URL_SAFE_NO_PAD.encode(admin_symbol_hash), &encrypted_identity, &admin_phrase);
                    user_did
                } else {
                    let (admin_did, admin_phrase) = self.tokenuser.lock().unwrap().create_user(&admin_name, &String::from("8610000000001"), None, None);
                    admin_did
                }
            };
            let admin_phrase_base58 = admin_phrase.as_bytes().to_base58();
            println!("{} [UserBase] local admin/本地管理身份: did/标识={}, phrase/口令={}", token_utils::now_string(), admin_did, admin_phrase_base58);
            self.set_admin_did(&admin_did);
            self.set_node_mode(mode);
            self.tokenuser.lock().unwrap().sign_user_context(&admin_did, &admin_phrase);
            (admin_did, admin_name, admin_phrase_base58)
        } else if mode == "online" && node_mode != "online" { //
            println!("{} [UserBase] reset node mode to online", token_utils::now_string());
            let admin_did = self.get_admin_did();
            if !admin_did.is_empty() {
                let _remove_dids = self.didtoken.lock().unwrap().remove_crypt_secrets_for_users();
                self.tokenuser.lock().unwrap().remove_context(&admin_did);
            }
            self.set_admin_did("");
            self.set_node_mode(mode);
            ("".to_string(), "".to_string(), "".to_string())
        } else {
            ("".to_string(), "".to_string(), "".to_string())
        }
    }



    pub fn export_isolated_admin_qrcode_svg(&mut self) -> String{
        if self.get_node_mode() == "isolated" && !self.get_admin_did().is_empty() {
            let admin = self.get_admin_did();
            let admin_claim = self.get_claim(&admin);
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
        let didtoken = DidToken::instance();
        let claim = didtoken.lock().unwrap().get_claim(user_did);
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
                        let user_cert = certificates.lock().unwrap().get_register_cert(user_did);
                        user_cert
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
            debug!("import_identity_qrcode, ready to push user cert: did={}", user_did);
            let certificates = GlobalCerts::instance();
            certificates.lock().unwrap().push_user_cert_text(&format!("{}|{}|{}|{}", TOKEN_ENTRYPOINT_DID, user_did, "Member", user_cert));
        }
        (user_did, nickname, telephone)
    }


    pub fn get_entry_point(&self, user_did: &str, entry_point_id: &str) -> String {
        if user_did==self.get_admin_did() {
            token_utils::gen_entry_point_of_service(entry_point_id)
        } else { "".to_string() }
    }

    pub fn get_guest_sstoken(&mut self, ua_hash: &str) -> String {
        let guest_did = self.get_guest_did();
        self.get_user_sstoken(&guest_did, ua_hash)
    }

    pub fn get_user_sstoken(&mut self, did: &str, ua_hash: &str) -> String {
        if IdClaim::validity(did) {
            let now_sec = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_else(|_| std::time::Duration::from_secs(0)).as_secs();
            let context = self.tokenuser.lock().unwrap().get_user_context(did);
            if context.is_default() || context.is_expired(){
                println!("{} [UserBase] The user context is error or expired: did={}", token_utils::now_string(), did);
                return String::from("Unknown")
            }
            let text1 = self.didtoken.lock().unwrap().get_local_crypt_text(ua_hash);
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
        let text1 = self.didtoken.lock().unwrap().get_local_crypt_text(ua_hash);
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
            let context = self.tokenuser.lock().unwrap().get_user_context(&user_did);
            if context.is_default() || context.is_expired(){
                self.sid_did_map.lock().unwrap().remove(sstoken);
                println!("{} [UserBase] The context of the sstoken in browser is expired: did={}", token_utils::now_string(), user_did);
                String::from("Unknown")
            } else {
                self.sid_did_map.lock().unwrap().insert(sstoken.to_string(), user_did.clone());
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
                let context = self.tokenuser.lock().unwrap().get_user_context(&user_did);
                if context.is_default() || context.is_expired(){
                    self.sid_did_map.lock().unwrap().remove(sstoken);
                println!("{} [UserBase] The context2 of the sstoken in browser is expired: did={}", token_utils::now_string(), user_did);
                    String::from("Unknown")
                } else {
                    self.sid_did_map.lock().unwrap().insert(sstoken.to_string(), user_did.clone());
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

    pub fn get_user_path_in_root(&self, root: &str, user_did: &str) -> String {
        let root_dir = PathBuf::from(root);
        let did_path =
            self.get_device_did().from_base58().expect("Failed to decode base58").iter()
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

    pub fn set_user_base_dir(&self, user_base_dir: &str) {
        self.tokenuser.lock().unwrap().set_user_base_dir(user_base_dir)
    }

    pub fn get_path_in_user_dir(&self, did: &str, catalog: &str) -> String {
        self.tokenuser.lock().unwrap().get_path_in_user_dir(did, catalog)
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
        self.tokenuser.lock().unwrap().get_user_context(&guest_did)
    }

    pub fn get_user_context(&mut self, did: &str) -> UserContext {
        self.tokenuser.lock().unwrap().get_user_context(did)
    }

    pub fn get_register_cert(&mut self, user_did: &str) -> String {
        self.didtoken.lock().unwrap().get_or_create_register_cert(user_did)
    }

    fn is_registered(&self, did: &str) -> bool {
        self.didtoken.lock().unwrap().is_registered(did)
    }

    fn remove_user(&self, did: &str) -> String {
        self.tokenuser.lock().unwrap().remove_user(did)
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
                        let (user_did, _user_phrase) = self.tokenuser.lock().unwrap().create_user(&nickname, telephone, None, None);
                        let new_claim = self.get_claim(&user_did);
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
                            println!("{} [UserBase] User apply is failure({}): sys_did({}), user_did({}), user_symbol({})", token_utils::now_string(), apply_result, self.get_sys_did(), user_did, symbol_hash_base64);
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
                        let user_certificate_text = self.didtoken.lock().unwrap().decrypt_by_did(&user_certificate, &upstream_did, 0);
                        debug!("UserBase] The parsed cert from Root is: cert({})", user_certificate_text);
                        let cert_user_did = {
                            let certificates = GlobalCerts::instance();
                            let cert_user_did = certificates.lock().unwrap().push_user_cert_text(&user_certificate_text);
                            cert_user_did
                        };
                        if cert_user_did != "Unknown" {
                            let ready_claim = self.get_claim(&ready_user_did);
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
        let user_did = self.didtoken.lock().unwrap().reverse_lookup_did_by_symbol(symbol_hash);
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

        let context = self.tokenuser.lock().unwrap().sign_user_context(&user_did, phrase);
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
                self.didtoken.lock().unwrap().reverse_lookup_did_by_symbol(symbol_hash)
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
                                self.tokenuser.lock().unwrap().import_user(&symbol_hash_base64.clone(), &encrypted_identity, &phrase)
                            }
                            false => {
                                if self.get_node_mode() == "online" {
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
                                                let user_did = self.tokenuser.lock().unwrap().import_user(&symbol_hash_base64, &encrypted_identity, &phrase);
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
                                                            let certificates = GlobalCerts::instance();
                                                            let mut certificates = certificates.lock().unwrap();
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
                let context = self.tokenuser.lock().unwrap().sign_user_context(&user_did, &phrase);
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
                if self.get_node_mode() == "online" {
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
                        let encoded_params = self.didtoken.lock().unwrap().encrypt_for_did(params.as_bytes(), &upstream_did, 0);
                        let unbind_node_file = token_utils::get_path_in_sys_key_dir(&format!("unbind_node_{}_uncompleted.json", user_did));
                        fs::write(unbind_node_file.clone(), encoded_params).expect(&format!("Unable to write file: {}", unbind_node_file.display()));
                    }
                    println!("{} [UserBase] Unbind user({}) from node({}): {}", token_utils::now_string(), user_did, self.get_sys_did(), result);
                }

                // release user token and context
                if user_did != self.get_admin_did() {
                    self.tokenuser.lock().unwrap().remove_context(&user_did);
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
            let context = self.tokenuser.lock().unwrap().get_user_context(&user_did);
            let context_crypt = URL_SAFE_NO_PAD.encode(token_utils::encrypt(context.to_json_string().as_bytes(), phrase.as_bytes(), 0));
            debug!("get_user_copy_string, context_json: {}, context_crypt: {}", context.to_json_string(), context_crypt);
            let certificates = {
                let certificates = GlobalCerts::instance();
                let certificates = certificates.lock().unwrap().filter_user_certs(&user_did, "*");
                certificates
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

    fn register_upstream(&mut self) -> String {
        let sys_did = self.get_sys_did();
        let dev_did = self.get_device_did();
        let (local_claim, device_claim) = {
            (self.get_claim(&sys_did), self.get_claim(&dev_did))
        };
        let last_timestamp = self.shared_data.get_message_queue().get_last_timestamp(&sys_did).unwrap_or_else(|| 0u64);
        let mut request = json!({});
        request["system_claim"] = serde_json::to_value(local_claim).unwrap_or(json!(""));
        request["device_claim"] = serde_json::to_value(device_claim).unwrap_or(json!(""));
        request["msg_timestamp"] = serde_json::to_value(last_timestamp).unwrap_or(json!(0u64));

        let params = serde_json::to_string(&request).unwrap_or("{}".to_string());

        let upstream_url = self.tokenuser.lock().unwrap().get_did_entry_point(dids::TOKEN_ENTRYPOINT_DID);
        let response = dids::TOKIO_RUNTIME.block_on(async {
            request_token_api_async(&upstream_url, &sys_did, &dev_did, "register2", &params).await
        });
        let ping_vars = serde_json::from_str::<HashMap<String, String>>(&response).unwrap_or_else(|_| HashMap::new());
        debug!("register_upstream, response: {}", response);
        if let Some(message_list) = ping_vars.get("message_list") {
            self.shared_data.get_message_queue().push_messages(&sys_did, message_list.to_string());
        }
        if let Some(p2p_config) = ping_vars.get("p2p_config") {
            self.p2p_config = p2p_config.clone();
        }
        if let Some(new_did) = ping_vars.get("upstream_did") {
            new_did.clone()
        } else { "".to_string() }
    }

    fn request_token_api(&mut self, api_name: &str, params: &str) -> String  {
        let upstream_did = self.get_upstream_did();
        if upstream_did.is_empty() {
            return "Unknown".to_string()
        }
        let entry_point = self.tokenuser.lock().unwrap().get_did_entry_point( &upstream_did);
        let encoded_params = self.didtoken.lock().unwrap().encrypt_for_did(params.as_bytes(), &upstream_did ,0);
        dids::TOKIO_RUNTIME.block_on(async {
            debug!("[UpstreamClient] sys({}),dev({}) request {}/api_{} with params: {}", self.get_sys_did(), self.get_device_did(), entry_point, api_name, params);
            request_token_api_async(&entry_point, &self.get_sys_did(), &self.get_device_did(), api_name, &encoded_params).await
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
    
    pub fn get_claim(&self, for_did: &str) -> IdClaim {
        self.didtoken.lock().unwrap().get_claim(for_did)
    }

    pub fn push_claim(&self, claim: &IdClaim) {
        self.didtoken.lock().unwrap().push_claim(claim);
    }

    pub fn pop_claim(&self, did: &str) -> IdClaim {
        self.didtoken.lock().unwrap().pop_claim(did)
    }

    pub fn import_user(&mut self, symbol_hash_base64: &str, encrypted_identity: &str, phrase: &str) -> String {
        self.tokenuser.lock().unwrap().import_user(symbol_hash_base64, encrypted_identity, phrase)
    }

    pub fn decrypt_by_did(&mut self, ctext: &str, by_did: &str, period:u64) -> String {
        self.didtoken.lock().unwrap().decrypt_by_did(ctext, by_did, period)
    }

    pub fn sign_and_issue_cert_by_admin(&mut self, item: &str, for_did: &str, for_sys_did: &str, memo: &str)
                                        -> (String, String) {
        self.didtoken.lock().unwrap().sign_and_issue_cert_by_admin(item, for_did, for_sys_did, memo)
    }

    pub(crate) fn sign_user_context(&mut self, did: &str, phrase: &str) -> UserContext {
        self.tokenuser.lock().unwrap().sign_user_context(did, phrase)
    }

    pub(crate) fn create_user(&mut self, nickname: &str, telephone: &str, id_card: Option<String>, phrase: Option<String>)
                              -> (String, String) {
        self.tokenuser.lock().unwrap().create_user(nickname, telephone, id_card, phrase)
    }
}

async fn request_token_api_async(upstream_url: &str, sys_did: &str, dev_did: &str, api_name: &str, encoded_params: &str) -> String  {
    debug!("[Upstream] request: {}{} with params: {}, sys={}, dev={}, ver={}", upstream_url, api_name, encoded_params, sys_did, dev_did, TOKEN_API_VERSION);
    match dids::REQWEST_CLIENT.post(format!("{}{}", upstream_url, api_name))
        .header("Sys-Did", sys_did.to_string())
        .header("Dev-Did", dev_did.to_string())
        .header("Version", TOKEN_API_VERSION.to_string())
        .body(encoded_params.to_string())
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
            info!("Failed to request token api: {} to {}{}, sys_did={}, dev_did={}", e, upstream_url, api_name, sys_did, dev_did);
            "Unknown".to_string()
        }
    }
}

async fn submit_uncompleted_request_files(upstream_url: &str, sys_did: &str, dev_did: &str) {
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
                                        let result = request_token_api_async(upstream_url, sys_did, dev_did, &method, &content).await;
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


async fn sync_upstream(
    sys_did: &str,
    dev_did: &str,
    upstream_did: String,
    entry_point: Arc<tokio::sync::Mutex<DidEntryPoint>>,
    online_users: Arc<tokio::sync::Mutex<OnlineUsers>>,
    message_queue: Arc<MessageQueue>,
) {
    let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(30));

    loop {
        let mut upstream_did = upstream_did.clone();
        let result_string = {
            let mut request = json!({});
            let online_users_list = {
                let users_guard = online_users.lock().await;
                users_guard.get_full_list()
            };
            let last_timestamp = message_queue.get_last_timestamp(sys_did).unwrap_or_else(|| 0u64);
            request["online_users"] = serde_json::to_value(online_users_list).unwrap_or(json!(""));
            request["msg_timestamp"] = serde_json::to_value(last_timestamp).unwrap_or(json!(0u64));
            let params = serde_json::to_string(&request).unwrap_or("{}".to_string());
            let upstream_url = {
                let ep = entry_point.lock().await;
                ep.get_entry_point(&upstream_did.clone())
            };
            match tokio::time::timeout(
                tokio::time::Duration::from_secs(5),
                request_token_api_async(&upstream_url, sys_did, dev_did, "ping", &params),
            )
                .await
            {
                Ok(result) => result,
                Err(_) => "Unknown".to_string(),
            }
        };

        debug!("{} [Upstream] {} ping upstream node: {}", token_utils::now_string(), sys_did, result_string);
                        
        if result_string != "Unknown" {
            let mut ping_vars = serde_json::from_str::<HashMap<String, String>>(&result_string).unwrap_or_else(|_| HashMap::new());
            if let Some(user_online) = ping_vars.get("user_online") {
                let user_online_array: Vec<&str> = user_online.split(":").collect();
                if user_online_array.len() >= 3 {
                    let nodes = user_online_array[0].parse().unwrap_or(1);
                    let users = user_online_array[1].parse().unwrap_or(1);
                    let top_list = user_online_array[2].to_string();
                    if nodes > 1 && users > 1 {
                        let mut users_guard = online_users.lock().await;
                        users_guard.set_nodes_users(nodes, users, top_list.clone());
                        debug!("{} [Upstream] set_nodes_users: {}:{}:{}", token_utils::now_string(), nodes, users, top_list);
                    } else if nodes == 0 && users == 0 {
                        debug!("{} [Upstream] get null nodes_users: {}:{}:{}", token_utils::now_string(), nodes, users, top_list);
                        let claims = GlobalClaims::instance();
                        let (local_claim, device_claim) = {
                            let mut claims = claims.lock().unwrap();
                            (claims.get_claim_from_local(sys_did), claims.get_claim_from_local(dev_did))
                        };
                        let last_timestamp = message_queue.get_last_timestamp(sys_did).unwrap_or_else(|| 0u64);
                        let mut request = json!({});
                        request["system_claim"] = serde_json::to_value(local_claim).unwrap_or(json!(""));
                        request["device_claim"] = serde_json::to_value(device_claim).unwrap_or(json!(""));
                        request["msg_timestamp"] = serde_json::to_value(last_timestamp).unwrap_or(json!(0u64));

                        let params = serde_json::to_string(&request).unwrap_or("{}".to_string());
                        let upstream_url = {
                            let ep = entry_point.lock().await;
                            ep.get_entry_point(dids::TOKEN_ENTRYPOINT_DID)
                        };
                        let response = request_token_api_async(&upstream_url, &sys_did, &dev_did, "register2", &params).await;
                        ping_vars = serde_json::from_str::<HashMap<String, String>>(&response).unwrap_or_else(|_| HashMap::new());
                        debug!("{} [Upstream] repair ping: {}", token_utils::now_string(), response);
                        upstream_did = if let Some(new_did) = ping_vars.get("upstream_did") {
                            new_did.clone()
                        } else { upstream_did.clone() };
                    } 
                }
            }

            if let Some(message_list) = ping_vars.get("message_list") {
                message_queue.push_messages(&sys_did, message_list.to_string());
            }
        }

        interval.tick().await;
    }

}
