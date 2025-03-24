use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{SystemTime, UNIX_EPOCH, Duration};
use serde::{Serialize, Deserialize};
use tracing::{debug, info};
use tracing_subscriber::field::debug;

use crate::dids::claims::{GlobalClaims, IdClaim};
use crate::dids::cert_center::GlobalCerts;
use crate::user::user_mgr::{MessageQueue, OnlineUsers};


// 任务队列项
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Task {
    pub id: String,
    pub timestamp: u64,
    pub content: String,
    pub status: String,
}


#[derive(Debug)]
pub struct SharedData {
    sys_did: Mutex<String>,
    tasks: Mutex<VecDeque<Task>>,
    pub user_list: Mutex<String>,
    did_node_map: RwLock<HashMap<String, String>>,
    node_did_map: RwLock<HashMap<String, String>>,
    pub message_queue: Mutex<Option<Arc<MessageQueue>>>,
    pub online_all: OnlineUsers,
    pub online_nodes: OnlineUsers,
    pub claims: Arc<Mutex<GlobalClaims>>, 
    pub certificates: Arc<Mutex<GlobalCerts>>,
}

impl SharedData {
    pub fn new() -> Self {
        Self {
            sys_did: Mutex::new(String::new()),
            tasks: Mutex::new(VecDeque::new()),
            user_list: Mutex::new(String::new()),
            did_node_map: RwLock::new(HashMap::new()),
            node_did_map: RwLock::new(HashMap::new()),
            message_queue: None.into(),
            online_all: OnlineUsers::new(600, 5),
            online_nodes: OnlineUsers::new(600, 5),
            claims: GlobalClaims::instance(), 
            certificates: GlobalCerts::instance(),
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

    pub fn set_sys_did(&self, did: &str) {
        let mut guard = self.sys_did.lock().unwrap();
        *guard = did.to_string();
    }

    pub fn get_last(&self, did: &str, last_timestamp: u64, updated_list: Option<&str>) -> (usize, usize, usize) {
        if let Some(list) = updated_list {
            let mut user_list = self.user_list.lock().unwrap();
            *user_list = list.to_string();
            debug!("update online user list: {}", user_list);
        }
        
        // 获取任务队列中时间戳大于 last_timestamp 的任务
        let tasks = {
            let tasks_read = self.tasks.lock().unwrap();
            tasks_read.iter()
                .filter(|task| task.timestamp > last_timestamp)
                .cloned()
                .collect::<Vec<_>>()
        };
        let sys_did = self.sys_did.lock().unwrap().clone();
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

    pub fn insert_did_node_batch(&self, user_list: &str, peer_id: &str) {
        let mut write_guard = self.did_node_map.write().unwrap();
        user_list
                .split('|') // 按 '|' 分隔字符串
                .map(|id| id.trim()) // 去除空白字符
                .for_each(|id| {
                    write_guard.insert(id.to_string(), peer_id.to_string().clone());
                });
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