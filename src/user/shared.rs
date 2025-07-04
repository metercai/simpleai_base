use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{SystemTime, UNIX_EPOCH, Duration};
use serde::{Serialize, Deserialize};
use tracing::{debug, info};
use tracing_subscriber::field::debug;

use crate::dids::claims::{GlobalClaims, IdClaim};
use crate::dids::cert_center::GlobalCerts;
use crate::user::user_mgr::{MessageQueue, OnlineUsers};


#[derive(Debug)]
pub struct SharedData {
    sys_did: RwLock<String>,
    node_did: RwLock<String>,
    sys_name: RwLock<String>, 
    pub user_list: Mutex<String>,
    did_node_map: RwLock<HashMap<String, String>>,
    node_did_map: RwLock<HashMap<String, String>>,
    pub message_queue: Mutex<Option<Arc<MessageQueue>>>,
    pub online_all: OnlineUsers,
    pub online_nodes: OnlineUsers,
    pub claims: Arc<Mutex<GlobalClaims>>, 
    pub certificates: Arc<Mutex<GlobalCerts>>,
    pub p2p_in_did_list: Arc<Mutex<HashSet<String>>>,
    pub p2p_out_did_list: Arc<Mutex<HashSet<String>>>,
    
}

impl SharedData {
    pub fn new() -> Self {
        Self {
            sys_did: RwLock::new(String::new()),
            node_did: RwLock::new(String::new()),
            sys_name: RwLock::new(String::new()),
            user_list: Mutex::new(String::new()),
            did_node_map: RwLock::new(HashMap::new()),
            node_did_map: RwLock::new(HashMap::new()),
            message_queue: None.into(),
            online_all: OnlineUsers::new(600, 5),
            online_nodes: OnlineUsers::new(600, 5),
            claims: GlobalClaims::instance(), 
            certificates: GlobalCerts::instance(),
            p2p_in_did_list: Arc::new(Mutex::new(HashSet::new())),
            p2p_out_did_list: Arc::new(Mutex::new(HashSet::new())),
        }
    }

    pub fn set_message_queue(&self, queue: MessageQueue) {
        let mut guard = self.message_queue.lock().unwrap();
        *guard = Some(Arc::new(queue)); // 包装为 Arc
    }

    pub fn get_message_queue(&self) -> Arc<MessageQueue> {
        let guard = self.message_queue.lock().unwrap();
        guard.as_ref().expect("MessageQueue not initialized").clone()
    }

    pub fn sys_did(&self) -> String {
        self.sys_did.read().unwrap().clone()
    }

    pub fn node_did(&self) -> String {
        self.node_did.read().unwrap().clone()
    }

    pub fn sys_name(&self) -> String {
        self.sys_name.read().unwrap().clone()
    }

    pub fn set_sys_data(&self, sys_did: &str, node_did: &str, sys_name: &str) {
        let mut guard = self.sys_did.write().unwrap();
        *guard = sys_did.to_string();
        let mut guard = self.node_did.write().unwrap();
        *guard = node_did.to_string();
        let mut guard = self.sys_name.write().unwrap();
        *guard = sys_name.to_string();
    }

    pub fn get_last(&self, did: &str, last_timestamp: u64, updated_list: Option<&str>) -> (usize, usize, usize) {
        if let Some(list) = updated_list {
            let mut user_list = self.user_list.lock().unwrap();
            *user_list = list.to_string();
            debug!("update online user list: {}", user_list);
        }
        
        let sys_did = self.sys_did.read().unwrap().clone();
        let messages_len = self.get_message_queue().get_msg_number_from(did, last_timestamp);
        let msg_sys_len = self.get_message_queue().get_msg_number_from(&sys_did, last_timestamp);
        let user_all = self.online_all.get_number();
        let node_all = self.online_nodes.get_number();
        debug!("status({}): node:{}, user:{}, local_msg:{}", did, node_all, user_all, messages_len+msg_sys_len);
        (node_all, user_all, messages_len)
    }
    
    pub fn get_node_did(&self, peer_id: &str) -> Option<String> {
        let read_guard = self.node_did_map.read().unwrap();
        read_guard.get(peer_id).cloned()
    }

    pub fn get_did_node(&self, did: &str) -> Option<String> {
        let read_guard = self.did_node_map.read().unwrap();
        read_guard.get(did).cloned()
    }

    pub fn insert_node_did(&self, peer_id: &str, did: &str) {
        let mut write_guard = self.node_did_map.write().unwrap();
        write_guard.insert(peer_id.to_string(), did.to_string());
        let mut write_guard = self.did_node_map.write().unwrap();
        write_guard.insert(did.to_string(), peer_id.to_string());
    }

    pub fn insert_did_node(&self, did: &str, peer_id: &str) {
        let mut write_guard = self.did_node_map.write().unwrap();
        write_guard.insert(did.to_string(), peer_id.to_string());
    }

    pub fn insert_did_node_batch(&self, user_list: &str, peer_id: &str) {
        let mut write_guard = self.did_node_map.write().unwrap();
        user_list
                .split('|') // 按 '|' 分隔字符串
                .map(|id| id.trim()) // 去除空白字符
                .for_each(|id| {
                    write_guard.insert(id.to_string(), peer_id.to_string().clone());
                });
    }

    pub fn is_p2p_in_dids(&self, did: &str) -> bool {
        let guard = self.p2p_in_did_list.lock().unwrap();
        guard.contains(did)
    }

    pub fn is_p2p_out_dids(&self, did: &str) -> bool {
        let guard = self.p2p_out_did_list.lock().unwrap();
        guard.contains(did)
    }

    pub fn set_p2p_in_dids(&self, did_list: &str) {
        if !did_list.is_empty() {
            let mut guard = self.p2p_in_did_list.lock().unwrap();
            guard.clear();
            did_list
                   .split('|') // 按 '|' 分隔字符串
                   .map(|id| id.trim()) // 去除空白字符
                   .for_each(|id| {
                        guard.insert(id.to_string());
                    });
        }
    }
    pub fn set_p2p_out_dids(&self, did_list: &str) {
        if!did_list.is_empty() {
            let mut guard = self.p2p_out_did_list.lock().unwrap();
            guard.clear();
            did_list
                    .split('|') // 按 '|' 分隔字符串
                    .map(|id| id.trim()) // 去除空白字符
                    .for_each(|id| {
                        guard.insert(id.to_string());
                    }); 
        }
    }

}

// 创建全局单例实例
use once_cell::sync::OnceCell;
static SHARED_DATA_INSTANCE: OnceCell<SharedData> = OnceCell::new();

pub fn get_shared_data() -> &'static SharedData {
    SHARED_DATA_INSTANCE.get_or_init(|| {
        SharedData::new()
    })
}