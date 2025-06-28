use std::collections::HashMap;
use std::error::Error;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;
use std::path::Path;
use std::fs;
use base58::ToBase58;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use bytes::Bytes;
use chrono::{DateTime, Local};
use libp2p::PeerId;
use rand::Rng;
use serde::{Deserialize, Serialize};
use serde_json::{self, json};
use tokio::sync::Mutex as TokioMutex;
use tokio::time;
use tracing::{debug, info, error};

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
use crate::user::user_vars::GlobalLocalVars;
use crate::utils::systeminfo::SystemInfo;
use crate::api;

const BOOTSTRAP_INTERVAL: Duration = Duration::from_secs(5 * 60);

pub(crate) static P2P_HANDLE: Lazy<Arc<Mutex<Option<tokio::task::JoinHandle<()>>>>> =
    Lazy::new(|| Arc::new(Mutex::new(None)));
pub(crate) static P2P_INSTANCE: Lazy<TokioMutex<Option<Arc<P2pServer>>>> =
    Lazy::new(|| TokioMutex::new(None));

static MERGED_CONFIG: RwLock<String> = RwLock::new(String::new());

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

pub struct P2pServer {
    sys_did: String,
    node_did: String,
    config: config::Config,
    client: Client,
    shared_data: &'static SharedData,
    handle: Option<tokio::task::JoinHandle<()>>,
    pending_task: Arc<Mutex<HashMap<String, String>>>,
}

pub async fn get_instance() -> Option<Arc<P2pServer>> {
    let p2p_instance_guard = P2P_INSTANCE.lock().await;
    p2p_instance_guard.clone()
}


impl P2pServer {
    pub async fn start() -> Result<Arc<P2pServer>, Box<dyn Error + Send + Sync>> {
        match Self::run().await {
            Ok(p2p) => {
                let mut p2p_instance_guard = P2P_INSTANCE.lock().await;
                *p2p_instance_guard = Some(p2p.clone());
                println!("{} [SimpBase] P2P service startup successfully!", token_utils::now_string());
                Ok(p2p)
            },
            Err(e) => {
                println!("P2P 服务启动失败: {:?}", e);
                Err(e)
            }
        }
    }

    pub async fn run() -> Result<Arc<P2pServer>, Box<dyn Error + Send + Sync>> {
        let config_str = Self::get_p2p_config();
        let config = config::Config::from_toml(&config_str).expect("无法解析配置字符串");
        let didtoken = DidToken::instance();
        let (sys_did, node_did, node_claim, node_phrase) = {
            let didtoken = didtoken.lock().unwrap();
            let sys_did = didtoken.get_sys_did();
            let node_did = didtoken.get_device_did();
            (sys_did, node_did.clone(), didtoken.get_claim(&node_did), didtoken.get_device_phrase())
        };
        let result = service::new(config.clone(), &node_claim, &node_phrase).await;
        let (client, mut server) = match result {
            Ok((c, s)) => (c, s),
            Err(e) => panic!("无法启动服务: {:?}", e),
        };
        let shared_data = shared::get_shared_data();
        let pending_task = Arc::new(Mutex::new(HashMap::new()));

        let handler = Handler {
            sys_did: sys_did.clone(),
            node_did: node_did.clone(),
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
            node_did.clone(),
            "login".to_string(),
            format!("{}:{}", client.get_peer_id().to_base58(), node_did.clone()),
        );
        message.signature(&node_phrase);
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
            sys_did,
            node_did: node_did,
            config: config.clone(),
            client: client.clone(),
            shared_data,
            handle: Some(handle),
            pending_task,
        };

        Ok(Arc::new(p2p))
    }

    pub async fn stop() {
        let mut sys_did = String::new();
        let mut node_did = String::new();
        let p2p = get_instance().await;
        if p2p.is_some() {
            sys_did = p2p.as_ref().unwrap().get_sys_did();
            node_did = p2p.as_ref().unwrap().get_node_did();
            p2p.as_ref().unwrap()._stop().await;
        }
        let mut p2p_instance_guard = P2P_INSTANCE.lock().await;
        *p2p_instance_guard = None;
        println!("{} [SimpBase] P2P service({}/{}) stop successfully!", token_utils::now_string(), sys_did, node_did);
    }

    async fn _stop(&self) {
        let _ = self.client.stop().await;
        if let Some(handle) = &self.handle {
            handle.abort();
            debug!("[P2pNode] P2P service stopped");
        }
    }

    pub fn get_sys_did(&self) -> String {
        self.sys_did.clone()
    }

    pub fn get_node_did(&self) -> String {
        self.node_did.clone()
    }

    fn get_p2p_config() -> String  {
        let mut default_config = MERGED_CONFIG.read().unwrap().clone();
        if default_config.is_empty() {
            default_config = DEFAULT_P2P_CONFIG.to_string();
        }
        let mut final_config = toml::Table::new();
        
        match toml::from_str::<toml::Table>(&default_config) {
            Ok(config) => final_config = config,
            Err(e) => {
                error!("解析默认P2P配置失败: {}", e);
            }
        }
        
        let global_local_vars = GlobalLocalVars::instance();
        let system_config = global_local_vars.read().unwrap().get_local_admin_vars("p2p_config");
        if !system_config.is_empty() && system_config != "None" {
            match toml::from_str::<toml::Table>(&system_config) {
                Ok(sys_config) => {
                    for (key, value) in sys_config {
                        final_config.insert(key, value);
                    }
                    debug!("已合并系统P2P配置");
                },
                Err(e) => error!("解析系统P2P配置失败: {}", e)
            }
        }
        
        let config_path = Path::new("p2pconfig.toml");
        if config_path.exists() {
            match fs::read_to_string(config_path) {
                Ok(content) => {
                    match toml::from_str::<toml::Table>(&content) {
                        Ok(manual_config) => {
                            for (key, value) in manual_config {
                                final_config.insert(key, value);
                            }
                            debug!("已合并本地p2pconfig.toml文件配置");
                        },
                        Err(e) => error!("解析本地P2P配置文件失败: {}", e)
                    }
                },
                Err(e) => error!("读取p2pconfig.toml文件失败: {}", e)
            }
        }
        
        match toml::to_string(&final_config) {
            Ok(merged_config) => {
                let mut config = MERGED_CONFIG.write().unwrap();
                *config = merged_config.clone();
                debug!("合并后的P2P配置: {}", merged_config);
                merged_config
            },
            Err(e) => {
                error!("序列化合并后的P2P配置失败: {}", e);
                default_config
            }
        }
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
                    let result = self.request(target_did.clone(), request, "sync").await;
                    let result_str = String::from_utf8(result).unwrap_or("".to_string());   
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


    pub async fn request_task(&self, target_did: String, body: Bytes, mode: &str) -> String {
        if target_did.is_empty() {
            tracing::warn!("target_did is empty");
            return String::new();
        }
        let response = self.request(target_did, body, mode).await;
        if mode == "sync" {
            String::from_utf8(response).unwrap_or(String::new())
        } else {
            "OK".to_string()
        }
    }

    pub async fn response_task(&self, task_id: String, body: Bytes, mode: &str) -> String {
        let target_full_did = task_id.split_once('@').map(|(_, after)| after).unwrap_or(&task_id).to_string();
        let target_node = target_full_did.split_once('.').map(|(_, after)| after).unwrap_or(&target_full_did).to_string();
        let target_sys = target_full_did.split_once('.').map(|(before, _)| before).unwrap_or(&target_full_did).to_string();
        
        if target_node.is_empty() {
            tracing::warn!("target_did is empty");
            return String::new();
        }
        let response = self.request(target_node, body, mode).await;
        if mode == "sync" {
            String::from_utf8(response).unwrap_or(String::new())
        } else {
            "OK".to_string()
        }
    }

    async fn request(&self, target_did: String, message: Bytes, mode: &str) -> Vec<u8> {
        let short_id = self.client.get_short_id();
        let target_node_did = target_did.split_once('.').map(|(_, after)| after).unwrap_or(&target_did).to_string();
        
        let target_peer_id = {
            if let Some(peer_id) = self.shared_data.get_did_node(&target_node_did) {
                peer_id.clone()
            } else {
                tracing::warn!("the did({}) does not belong to a node", target_node_did);
                return String::new().into();
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
            target_node_did,
            target_short_id,
            now_time
        );

        println!("send request to {} with len={} by {}", target_node_did, message.len(), mode);
        match mode {
            "sync" => {
                match self.client.request(&target_peer_id, message).await {
                    Ok(resp) => resp,
                    Err(e) => {
                        tracing::error!("Outbound request fails: {:?}", e);
                        "Unknown".into()
                    }
                }
            }
            _ => {
                match self.client.request_async(&target_peer_id, message).await {
                    Ok(resp) => Vec::new(),
                    Err(e) => {
                        tracing::error!("Outbound request fails: {:?}", e);
                        "Unknown".into()
                    }
                }
            }
        }
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
    node_did: String,
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
        let from_node_did = {
            if let Some(peer_did) = self.shared_data.get_node_did(&peer_id) {
                peer_did.clone()
            } else {
                tracing::warn!("node_peer({}) does not found did", peer_id);
                return Ok(format!("does not match did for peer{peer_id}").as_bytes().to_vec());
            }
        };
        match serde_cbor::from_slice::<P2pRequest>(request.as_slice()) {
            Ok(req) => {
                let target_did = if req.target_did.is_empty() {
                    req.task_id.split_once('@').map(|(_, after)| after).unwrap_or(&req.task_id).to_string()
                } else {
                    req.target_did.clone()
                };
                let target_node = target_did.split_once('.').map(|(_, after)| after).unwrap_or(&target_did).to_string();
                let target_sys = target_did.split_once('.').map(|(before, _)| before).unwrap_or(&target_did).to_string();
                if !IdClaim::validity(&target_node) || target_node != self.node_did{
                    tracing::warn!("node did error: not valid or not match self node ");
                    return Ok(format!("target did error: {}", target_did).as_bytes().to_vec());
                }
                tracing::info!("📣 <<<< Inbound REQUEST with P2P: method={}, task_id={}, task_method={}, target_did={}", req.method, req.task_id, req.task_method, target_did);
                if req.method == "remote_process" && req.task_method != "remote_ping" && !self.shared_data.is_p2p_in_dids(&from_node_did) {
                    return Ok(format!("the request did is not in allow list for remote process: {}", target_did).as_bytes().to_vec());
                }
                if target_sys != self.sys_did { //非p2p node当前系统任务，通过websocket转发
                    let response = api::request_api_bin_sync(&format!("ws_task/{}", target_sys), Some(request.clone()))
                        .unwrap_or_else(|e| {
                            error!("call_request_ws_task({}) error: {}, target_did={}, method={}", target_sys, e, req.target_did, req.task_method);
                            "error in call_ws_task".to_string()
                        });
                    return Ok(response.as_bytes().to_vec());
                } else {
                    match req.method.as_str() {
                        "get_claim" => {
                            let response =
                                if req.task_id.is_empty() || !IdClaim::validity(&req.task_id) {
                                    let claim = self
                                        .shared_data
                                        .claims
                                        .lock()
                                        .unwrap()
                                        .get_claim_from_local(&req.task_id.clone());
                                    tracing::info!(
                                        "{} [P2pNode] get did({}) claim from upstream.",
                                        token_utils::now_string(),
                                        req.task_id
                                    );
                                    claim.to_json_string()
                                } else {
                                    tracing::warn!("get_claim 方法缺少 did 参数");
                                    IdClaim::default().to_json_string()
                                };
                            return Ok(response.as_bytes().to_vec());
                        }
                        "remote_process" => {
                            let response = p2p_task_request(req.task_id, req.task_method.clone(), &req.task_args);
                             return Ok(response.as_bytes().to_vec());
                        }
                        "async_response" => {
                            let response = p2p_task_response(req.task_id, req.task_method.clone(), &req.task_args);
                            return Ok(response.as_bytes().to_vec());
                        }
                        // 可以添加更多方法的处理逻辑
                        _ => {
                            tracing::warn!("未知的方法: {}", req.method);
                            return Ok(format!("未知的方法: {}", req.method)
                                .as_bytes()
                                .to_vec());
                        }
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
                        .push_messages(&self.node_did, message_str);
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

pub(crate) fn p2p_task_request(task_id: String, task_method: String, task_args: &Vec<u8>) -> String {
    let results = Python::with_gil(|py| -> PyResult<String> {
        let p2p_task = PyModule::import_bound(py, "simpleai_base.p2p_task")
            .expect("No simpleai_base.p2p_task.");
        let py_bytes = pyo3::types::PyBytes::new_bound(py, task_args);
        let result: String = p2p_task
            .getattr("call_request_by_p2p_task")?
            .call1((
                task_id,
                task_method.clone(),
                py_bytes,
            ))?
            .extract()?;
        Ok(result)
    });
    results.unwrap_or_else(|e| {
        tracing::error!("call_request {} fail: {:?}", task_method, e);
        "error in call_response".to_string()
    })
}

pub(crate) fn p2p_task_response(task_id: String, task_method: String, task_args: &Vec<u8>) -> String {
    let results = Python::with_gil(|py| -> PyResult<String> {
        let p2p_task = PyModule::import_bound(py, "simpleai_base.p2p_task")
            .expect("No simpleai_base.p2p_task.");
        // 将Vec<u8>转换为Python的bytes对象
        let py_bytes = pyo3::types::PyBytes::new_bound(py, task_args);
        let result: String = p2p_task
            .getattr("call_response_by_p2p_task")?
            .call1((
                task_id,
                task_method.clone(),
                py_bytes,
            ))?
            .extract()?;
        Ok(result)
    });
    results.unwrap_or_else(|e| {
        tracing::error!("call_response {} fail: {:?}", task_method, e);
        "error in call_response".to_string()
    })
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

