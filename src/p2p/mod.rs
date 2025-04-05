use base58::ToBase58;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use bytes::Bytes;
use chrono::{DateTime, Local};
use libp2p::PeerId;
use rand::Rng;
use serde::{Deserialize, Serialize};
use serde_json::{self, json};
use std::collections::HashMap;
use std::error::Error;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::Mutex as TokioMutex;
use tokio::time;

use pyo3::prelude::*;
use pyo3::types::PyModule;

mod config;
mod error;
mod http_service;
mod protocol;
mod req_resp;
mod service;
mod utils;

use once_cell::sync::Lazy;
use once_cell::sync::OnceCell;

use crate::dids::cert_center::GlobalCerts;
use crate::dids::claims::{GlobalClaims, IdClaim};
use crate::dids::{token_utils, DidToken, TOKIO_RUNTIME};
use crate::p2p::service::{Client, EventHandler, NodeStatus};
use crate::user::shared::{self, SharedData};
use crate::user::user_mgr::{MessageQueue, OnlineUsers};
use crate::utils::systeminfo::SystemInfo;

const BOOTSTRAP_INTERVAL: Duration = Duration::from_secs(5 * 60);

pub(crate) static P2P_HANDLE: Lazy<Arc<Mutex<Option<tokio::task::JoinHandle<()>>>>> =
    Lazy::new(|| Arc::new(Mutex::new(None)));
pub(crate) static P2P_INSTANCE: Lazy<TokioMutex<Option<Arc<P2p>>>> =
    Lazy::new(|| TokioMutex::new(None));

//address.upstream_nodes = ['/dns4/p2p.simpai.cn/tcp/2316/p2p/12D3KooWGGEDTNkg7dhMnQK9xZAjRnLppAoMMR2q3aUw5vCn4YNc','/dns4/p2p.token.tm/tcp/2316/p2p/12D3KooWFapNfD5a27mFPoBexKyAi4E1RTP4ifpfmNKBV8tsBL4X']
pub(crate) static DEFAULT_P2P_CONFIG: &str = r#"
address.upstream_nodes = ['/dns4/p2p.token.tm/tcp/2316/p2p/12D3KooWFapNfD5a27mFPoBexKyAi4E1RTP4ifpfmNKBV8tsBL4X']
pubsub_topics = ['system','user']
metrics_path = '/metrics' 
discovery_interval = 60
node_status_interval = 60
broadcast_interval = 25
request_interval = 80
req_resp.request_timeout = 30
"#;

pub struct P2p {
    sys_did: String,
    config: config::Config,
    client: Client,
    shared_data: &'static SharedData,
    handle: Option<tokio::task::JoinHandle<()>>,
    pending_task: Arc<Mutex<HashMap<String, String>>>,
}

impl P2p {
    pub async fn start(
        config: String,
        sys_claim: &IdClaim,
        sys_phrase: &str,
    ) -> Result<Arc<P2p>, Box<dyn Error + Send + Sync>> {
        let config = config::Config::from_toml(&config.clone()).expect("无法解析配置字符串");
        let result = service::new(config.clone(), sys_claim, sys_phrase).await;
        let (client, mut server) = match result {
            Ok((c, s)) => (c, s),
            Err(e) => panic!("无法启动服务: {:?}", e),
        };

        let sys_did = sys_claim.gen_did();
        let shared_data = shared::get_shared_data();
        let pending_task = Arc::new(Mutex::new(HashMap::new()));

        let handler = Handler {
            sys_did: sys_did.clone(),
            shared_data,
            pending_task: pending_task.clone(),
        };

        server.set_event_handler(handler);

        let config_clone = config.clone();
        let client_clone = client.clone();

        let handle = TOKIO_RUNTIME.spawn(async move {
            let task_run = server.run();
            let task_node_status = get_node_status(
                client_clone.clone(),
                config_clone.get_node_status_interval(),
            );
            let task_broadcast_online =
                broadcast_online_users(client_clone.clone(), config_clone.get_broadcast_interval());

            tokio::join!(
                task_run,
                task_node_status,
                //task_broadcast_online
            );
        });

        let mut message = DidMessage::new(
            sys_did.clone(),
            "login".to_string(),
            format!("{}:{}", client.get_peer_id().to_base58(), sys_did.clone()),
        );
        message.signature(&sys_phrase);
        match serde_cbor::to_vec(&message) {
            Ok(msg_bytes) => {
                let _ = client
                    .broadcast("user".to_string(), Bytes::from(msg_bytes))
                    .await;
                "ok".to_string()
            }
            Err(e) => {
                println!("Failed to serialize message in start: {:?}", e);
                "Failed to serialize message".to_string()
            }
        };

        let p2p = Self {
            sys_did: sys_did.clone(),
            config: config.clone(),
            client: client.clone(),
            shared_data,
            handle: Some(handle),
            pending_task,
        };

        Ok(Arc::new(p2p))
    }

    pub async fn put_local_claim_to_DHT() {
        let claims = GlobalClaims::instance();
        let claims_copy = {
            let claims_lock = claims.lock().unwrap();
            claims_lock
                .iter()
                .filter(|(_, claim)| claim.self_verify())
                .map(|(_, claim)| claim.clone())
                .collect::<Vec<IdClaim>>()
        };
        if let Some(p2p) = get_instance().await {
            for claim in claims_copy {
                if claim.self_verify() {
                    p2p.put_claim_to_DHT(claim.clone()).await;
                }
            }
        }
    }

    pub async fn get_claim_from_upstream(&self, did: String) -> IdClaim {
        if did.is_empty() || !IdClaim::validity(&did) {
            return IdClaim::default();
        }

        let request_bytes = Bytes::from(
            serde_json::to_vec(&json!({
                "method": "get_claim",
                "did": did
            }))
            .unwrap(),
        );

        let short_peer_id = self.client.get_short_id();

        if let Some(ref upstream_nodes) = self.config.address.upstream_nodes {
            for upstream_node in upstream_nodes {
                let upstream_peer_id = upstream_node.peer_id().to_base58();
                if let Some(target_did) = self.shared_data.get_node_did(&upstream_peer_id) {
                    let request = P2pRequest {
                        target_did: target_did.clone(),
                        method: "get_claim".to_string(),
                        task_id: did.clone(),
                        task_method: "".to_string(),
                        task_args: vec![b' '],
                    };
                    let request = Bytes::from(serde_cbor::to_vec(&request).unwrap());
                    let result_str = self.request(target_did.clone(), request).await;
                    if result_str.is_empty() {
                        tracing::debug!("从上游节点 {} 获取的响应为空", upstream_peer_id);
                        continue;
                    }
                    match serde_json::from_str::<IdClaim>(&result_str) {
                        Ok(claim) => {
                            tracing::info!(
                                "{} [P2pNode] P2P_node({}) 成功从上游节点({}) 获取用户({})的声明",
                                token_utils::now_string(),
                                short_peer_id,
                                upstream_peer_id,
                                did
                            );
                            return claim;
                        }
                        Err(e) => {
                            tracing::debug!(
                                "解析上游节点 {} 返回的声明失败: {:?}",
                                upstream_peer_id,
                                e
                            );
                        }
                    }
                } else {
                    tracing::debug!("上游节点 {} 未找到对应的 DID", upstream_peer_id);
                }
            }
        } else {
            tracing::debug!("没有配置上游节点");
        }
        tracing::debug!("无法从任何上游节点获取用户 {} 的声明", did);
        IdClaim::default()
    }

    pub async fn get_claim_from_DHT(&self, did: &str) -> IdClaim {
        if did.is_empty() || !IdClaim::validity(did) {
            tracing::debug!("无效的DID: {}", did);
            return IdClaim::default();
        }

        let key = token_utils::calc_sha256(format!("did_claim_{}", did).as_bytes()).to_base58();
        tracing::debug!("尝试从DHT获取声明，DID: {}, 键: {}", did, key);

        match self.client.get_key_value(&key).await {
            Ok(value) => {
                if value.is_empty() {
                    tracing::debug!("DHT中未找到DID({})的声明", did);
                    return IdClaim::default();
                }

                match String::from_utf8(value.clone()) {
                    Ok(json_str) => match serde_json::from_str::<IdClaim>(&json_str) {
                        Ok(claim) => {
                            tracing::info!(
                                "{} [P2pNode] 成功从DHT获取DID({})的声明",
                                token_utils::now_string(),
                                did
                            );
                            claim
                        }
                        Err(e) => {
                            tracing::error!(
                                "解析DHT返回的声明失败: {:?}, 原始数据: {}",
                                e,
                                json_str
                            );
                            IdClaim::default()
                        }
                    },
                    Err(e) => {
                        tracing::error!(
                            "DHT返回的数据不是有效的UTF-8字符串: {:?}, 数据长度: {}",
                            e,
                            value.len()
                        );
                        IdClaim::default()
                    }
                }
            }
            Err(e) => {
                tracing::error!("从DHT获取声明失败: {:?}, DID: {}", e, did);
                IdClaim::default()
            }
        }
    }

    pub async fn put_claim_to_DHT(&self, claim: IdClaim) {
        let did = claim.gen_did();
        let key = token_utils::calc_sha256(format!("did_claim_{}", did).as_bytes()).to_base58();

        self.client
            .set_key_value(key, claim.to_json_string().as_bytes().to_vec())
            .await;
        tracing::debug!(
            "{} [P2pNode] put did({}) claim to DHT",
            token_utils::now_string(),
            did
        );
    }

    pub async fn get_node_status(&self) -> NodeStatus {
        let node_status = self.client.get_node_status().await;
        let short_id = self.client.get_short_id();
        println!(
            "{} [P2pNode] {}",
            token_utils::now_string(),
            node_status.short_format()
        );
        node_status
    }

    pub async fn stop(&self) {
        let _ = self.client.stop().await;
        if let Some(handle) = &self.handle {
            handle.abort();
            tracing::info!("[P2pNode] P2P service stopped");
        }
    }

    pub async fn request_task(&self, body: Bytes) -> String {
        match serde_cbor::from_slice::<P2pRequest>(body.to_vec().as_slice()) {
            Ok(request) => self.request(request.target_did, body).await,
            Err(e) => {
                tracing::error!("CBOR反序列化P2pRequest失败: {:?}", e);
                String::new()
            }
        }
    }

    pub async fn response_task(&self, body: Bytes) -> String {
        match serde_cbor::from_slice::<P2pRequest>(body.to_vec().as_slice()) {
            Ok(request) => {
                let target_did = self
                    .pending_task
                    .lock()
                    .unwrap()
                    .get(&request.task_id)
                    .unwrap_or(&request.target_did)
                    .clone();
                let result = self.request(target_did, body).await;
                if request.task_method == "remote_stop" {
                    self.pending_task.lock().unwrap().remove(&request.task_id);
                }
                result
            }
            Err(e) => {
                tracing::error!("CBOR反序列化P2pRequest失败: {:?}", e);
                String::new()
            }
        }
    }

    async fn request(&self, target_did: String, message: Bytes) -> String {
        let short_id = self.client.get_short_id();

        let target_peer_id = {
            if let Some(peer_id) = self.shared_data.get_did_node(&target_did) {
                peer_id.clone()
            } else {
                tracing::warn!("user_did({}) does not belong to a node", target_did);
                return String::new();
            }
        };

        let known_peers = self.client.get_known_peers().await;
        if !known_peers.contains(&target_peer_id) {
            tracing::warn!(
                "The target node({}) is not in the known node list",
                target_did
            );
        }

        let now_time: DateTime<Local> = Local::now();
        let target_short_id = target_peer_id
            .chars()
            .skip(target_peer_id.len() - 7)
            .collect::<String>();
        tracing::debug!(
            "📣 >>>> Outbound request: {} send {} byte to {} with {} at {}",
            short_id,
            message.len(),
            target_did,
            target_short_id,
            now_time
        );

        let response = match self.client.request(&target_peer_id, message).await {
            Ok(resp) => resp,
            Err(e) => {
                tracing::error!("请求失败: {:?}", e);
                "Unknown".as_bytes().to_vec()
            }
        };
        String::from_utf8_lossy(&response).to_string()
    }

    pub async fn broadcast_user_msg(&self, message: Bytes) -> String {
        self.broadcast("user".to_string(), message);
        "ok".to_string()
    }

    async fn broadcast(&self, topic: String, message: Bytes) {
        let _ = self.client.broadcast(topic.clone(), message).await;
        tracing::info!("📣 >>>> Outbound broadcast: {:?}", topic);
    }
}

#[derive(Debug)]
struct Handler {
    sys_did: String,
    shared_data: &'static shared::SharedData,
    pending_task: Arc<Mutex<HashMap<String, String>>>,
}

impl EventHandler for Handler {
    fn handle_inbound_request(
        &self,
        peer: PeerId,
        request: Vec<u8>,
    ) -> Result<Vec<u8>, Box<dyn Error>> {
        let peer_id = peer.to_base58();
        let from_peer_did = {
            if let Some(peer_did) = self.shared_data.get_node_did(&peer_id) {
                peer_did.clone()
            } else {
                tracing::warn!("node_peer({}) does not found sys_did", peer_id);
                return Ok("匹配不到来源节点的did".as_bytes().to_vec());
            }
        };
        match serde_cbor::from_slice::<P2pRequest>(request.as_slice()) {
            Ok(request) => {
                if request.target_did.is_empty() || !IdClaim::validity(&request.target_did) {
                    tracing::warn!("请求的user_did不正确");
                    return Ok("user_did错误".as_bytes().to_vec());
                }
                tracing::debug!("📣 <<<< Inbound REQUEST: method={}, task_id={}, task_method={}", request.method, request.task_id, request.task_method);
                match request.method.as_str() {
                    "get_claim" => {
                        let response =
                            if request.task_id.is_empty() || !IdClaim::validity(&request.task_id) {
                                let claim = self
                                    .shared_data
                                    .claims
                                    .lock()
                                    .unwrap()
                                    .get_claim_from_local(&request.task_id.clone());
                                tracing::info!(
                                    "{} [P2pNode] get did({}) claim from upstream.",
                                    token_utils::now_string(),
                                    request.task_id
                                );
                                claim.to_json_string()
                            } else {
                                tracing::warn!("get_claim 方法缺少 did 参数");
                                IdClaim::default().to_json_string()
                            };
                        return Ok(response.as_bytes().to_vec());
                    }
                    "generate_image" => {
                        println!(
                            "generate_image: is_p2p_in_dids={}, from_peer={}",
                            self.shared_data.is_p2p_in_dids(&from_peer_did),
                            from_peer_did
                        );

                        let response = if self.shared_data.is_p2p_in_dids(&from_peer_did) {
                            self.pending_task
                                .lock()
                                .unwrap()
                                .insert(request.task_id.clone(), from_peer_did.clone());

                            println!(
                                "{} [P2pNode] generate_image task({}) from {}",
                                token_utils::now_string(),
                                request.task_id.clone(),
                                from_peer_did
                            );

                            let results = Python::with_gil(|py| -> PyResult<String> {
                                let p2p_task = PyModule::import_bound(py, "simpleai_base.p2p_task")
                                    .expect("No simpleai_base.p2p_task.");
                                // 将Vec<u8>转换为Python的bytes对象
                                let py_bytes = pyo3::types::PyBytes::new_bound(py, &request.task_args);
                                let result: String = p2p_task
                                    .getattr("call_request_by_p2p_task")?
                                    .call1((
                                        request.task_id,
                                        request.task_method.clone(),
                                        py_bytes,
                                    ))?
                                    .extract()?;
                                Ok(result)
                            });
                            results.unwrap_or_else(|e| {
                                tracing::error!("call_request {} 调用失败: {:?}", request.task_method, e);
                                "error".to_string()
                            })
                        } else {
                            "error".to_string()
                        };
                        return Ok(response.as_bytes().to_vec());
                    }
                    "async_response" => {
                        let response = {
                            println!(
                                "{} [P2pNode] async_response task({}) from {}",
                                token_utils::now_string(),
                                request.task_id.clone(),
                                from_peer_did
                            );

                            let results = Python::with_gil(|py| -> PyResult<String> {
                                let p2p_task = PyModule::import_bound(py, "simpleai_base.p2p_task")
                                    .expect("No simpleai_base.p2p_task.");
                                // 将Vec<u8>转换为Python的bytes对象
                                let py_bytes = pyo3::types::PyBytes::new_bound(py, &request.task_args);
                                let result: String = p2p_task
                                    .getattr("call_response_by_p2p_task")?
                                    .call1((
                                        request.task_id,
                                        request.task_method.clone(),
                                        py_bytes,
                                    ))?
                                    .extract()?;
                                Ok(result)
                            });
                            results.unwrap_or_else(|e| {
                                tracing::error!("call_response {} 调用失败: {:?}", request.task_method, e);
                                "error".to_string()
                            })
                        };
                        return Ok(response.as_bytes().to_vec());
                    }
                    // 可以添加更多方法的处理逻辑
                    _ => {
                        tracing::warn!("未知的方法: {}", request.method);
                        return Ok(format!("未知的方法: {}", request.method)
                            .as_bytes()
                            .to_vec());
                    }
                }
            }
            Err(e) => {
                tracing::error!("CBOR反序列化P2pRequest失败: {:?}", e);
                return Ok("CBOR反序列化P2pRequest失败".as_bytes().to_vec());
            }
        }
    }

    fn handle_broadcast(&self, topic: &str, message: Vec<u8>, sender: PeerId) {
        // 处理不同类型的广播消息
        match topic {
            "user" => {
                match serde_cbor::from_slice::<DidMessage>(message.as_slice()) {
                    Ok(msg) => {
                        if msg.verify() {
                            tracing::info!("📣 <<<< Inbound BROADCAST: {:?} {:?}", topic, msg);
                            match msg.msg_type.as_str() {
                                "login" => {
                                    let mut parts = msg.body.splitn(2, ':');
                                    let node_id = parts.next().unwrap_or("").trim().to_string();
                                    let node_did = parts.next().unwrap_or("").trim().to_string();

                                    if !node_id.is_empty()
                                        && !node_did.is_empty()
                                        && IdClaim::validity(&node_did)
                                        && PeerId::from_bytes(node_id.as_bytes()).is_ok()
                                    {
                                        self.shared_data.insert_node_did(&node_id, &node_did);
                                        self.shared_data.insert_did_node(&msg.user_did, &node_id);
                                        let short_did = node_did
                                            .chars()
                                            .skip(node_did.len() - 7)
                                            .collect::<String>();
                                        let short_id = node_id
                                            .chars()
                                            .skip(node_id.len() - 7)
                                            .collect::<String>();
                                        tracing::info!(
                                            "DID({})已记录到节点({})上",
                                            short_did,
                                            short_id
                                        );
                                    } else {
                                        tracing::warn!(
                                            "无效的登录消息格式或ID/DID: node_id={}, node_did={}",
                                            node_id,
                                            node_did
                                        );
                                    }
                                }
                                _ => {
                                    // 处理其他类型的用户消息
                                }
                            }
                        }
                    }
                    Err(e) => {
                        tracing::error!("CBOR反序列化DidMessage失败: {:?}", e);
                    }
                }
            }
            "system" => {
                let message_str = String::from_utf8_lossy(&message).to_string();
                // 收到系统消息，更新本地消息队列
                if !message_str.is_empty() {
                    let count = self
                        .shared_data
                        .get_message_queue()
                        .push_messages(&self.sys_did, message_str);
                    tracing::info!(
                        "{} [P2pNode] added {} new system meaasge.",
                        token_utils::now_string(),
                        count
                    );
                }
            }
            _ => {
                // 其他类型的消息，可以根据需要添加处理逻辑
            }
        }
    }
}

async fn get_node_status(client: Client, interval: u64) {
    let dur = time::Duration::from_secs(interval);
    loop {
        time::sleep(dur).await;
        let node_status = client.get_node_status().await;
        println!(
            "{} [P2pNode] {}",
            token_utils::now_string(),
            node_status.short_format()
        );
    }
}

async fn broadcast(client: Client, interval: u64) {
    let dur = time::Duration::from_secs(interval);
    loop {
        time::sleep(dur).await;
        let topic = "system".to_string();
        let short_id = client.get_short_id();
        let now_time = Local::now();
        let message = format!("From {} at {}!", short_id, now_time);
        tracing::debug!("📣 >>>> Outbound broadcast: {:?} {:?}", topic, message);
        let _ = client
            .broadcast(topic, Bytes::from(message.as_bytes().to_vec()))
            .await;
    }
}

async fn request(client: Client, interval: u64) {
    let dur = time::Duration::from_secs(interval);
    loop {
        time::sleep(dur).await;
        let known_peers = client.get_known_peers().await;
        let short_id = client.get_short_id();

        // 检查 known_peers 是否为空
        if known_peers.len() > 0 {
            // 只有在有已知节点时才生成随机索引
            let random_index = rand::thread_rng().gen_range(0..known_peers.len());
            let target = &known_peers[random_index];
            let now_time: DateTime<Local> = Local::now();
            //let now_time = now.format("%H:%M:%S.%4f").to_string();
            let target_id = target.chars().skip(target.len() - 7).collect::<String>();
            let request = format!(
                "Hello {}, request from {} at {}!",
                target_id, short_id, now_time
            );
            tracing::debug!("📣 >>>> Outbound request: {:?}", request);
            let response = match client
                .request(target, Bytes::from(request.as_bytes().to_vec()))
                .await
            {
                Ok(resp) => resp,
                Err(e) => {
                    tracing::error!("请求失败: {:?}", e);
                    continue; // 跳过这次失败的请求，继续下一次循环
                }
            };
            let now_time2: DateTime<Local> = Local::now();
            tracing::debug!(
                "📣 <<<< Inbound response: Time({}) {:?}",
                now_time2,
                String::from_utf8_lossy(&response)
            );
        } else {
            // 没有已知节点时记录日志
            tracing::info!("📣 No known peers available for request");
        }
    }
}

// 新增函数：定时广播在线用户列表
async fn broadcast_online_users(client: Client, interval: u64) {
    let shared_data = shared::get_shared_data();
    let dur = time::Duration::from_secs(interval);
    loop {
        time::sleep(dur).await;
        let users_list = shared_data.user_list.lock().unwrap().clone();
        if !users_list.is_empty() {
            let topic = "online".to_string();
            let now_time: DateTime<Local> = Local::now();
            let unix_timestamp = now_time.timestamp();
            tracing::info!(
                "📣 >>>> broadcast({topic}): {} online users in {} at {}, list={}",
                users_list.split('|').count(),
                client.get_short_id(),
                now_time,
                users_list
            );
            let message = format!("{}:{}:{}", client.get_sys_did(), unix_timestamp, users_list);
            let _ = client
                .broadcast(topic, Bytes::from(message.as_bytes().to_vec()))
                .await;
        } else {
            tracing::info!("no users on node ...");
        }
    }
}

pub async fn get_instance() -> Option<Arc<P2p>> {
    let p2p_instance_guard = P2P_INSTANCE.lock().await;
    p2p_instance_guard.clone()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct P2pRequest {
    pub target_did: String,
    pub method: String,
    pub task_id: String,
    pub task_method: String,
    pub task_args: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct P2pMessage {
    pub node_did: String,
    pub msg_type: String,
    pub body: Vec<u8>,
    pub sig: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DidMessage {
    pub user_did: String,
    pub msg_type: String,
    pub body: String,
    pub sig: Vec<u8>,
}
impl DidMessage {
    pub fn new(user_did: String, msg_type: String, body: String) -> Self {
        Self {
            user_did,
            msg_type,
            body,
            sig: Vec::new(),
        }
    }
    pub fn signature(&mut self, phrase: &str) {
        let text = format!("{}|{}|{}", self.user_did, self.msg_type, self.body);
        let didtoken = DidToken::instance();
        self.sig = didtoken
            .lock()
            .unwrap()
            .sign_by_did(&text, &self.user_did, phrase);
    }
    pub fn verify(&self) -> bool {
        let text = format!("{}|{}|{}", self.user_did, self.msg_type, self.body);
        let signature = URL_SAFE_NO_PAD.encode(self.sig.clone());
        let didtoken = DidToken::instance();
        let verify = didtoken
            .lock()
            .unwrap()
            .verify_by_did(&text, &self.user_did, &signature);
        verify
    }
}
