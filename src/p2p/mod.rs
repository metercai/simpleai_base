use std::error::Error;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use base58::ToBase58;
use chrono::{format, DateTime, Local};
use tokio::time;
use tokio::sync::Mutex as TokioMutex;
use rand::Rng;
use libp2p::PeerId;
use serde_json::{self, json};

mod protocol;
mod http_service;
mod error;
mod utils;
mod service;
mod config;
mod req_resp;

use once_cell::sync::OnceCell;
use once_cell::sync::Lazy;

use crate::dids::TOKIO_RUNTIME;
use crate::dids::token_utils;
use crate::dids::cert_center::GlobalCerts;
use crate::dids::claims::{GlobalClaims, IdClaim};
use crate::utils::systeminfo::SystemInfo;
use crate::user::shared::{self, SharedData};
use crate::p2p::service::{Client, Server, EventHandler};
use crate::user::user_mgr::{MessageQueue, OnlineUsers};

const BOOTSTRAP_INTERVAL: Duration = Duration::from_secs(5 * 60);

pub(crate) static P2P_HANDLE: Lazy<Arc<Mutex<Option<tokio::task::JoinHandle<()>>>>> =
    Lazy::new(|| Arc::new(Mutex::new(None)));
pub(crate) static P2P_INSTANCE: Lazy<TokioMutex<Option<Arc<P2p>>>> = Lazy::new(|| TokioMutex::new(None));

//address.upstream_nodes = ['/dns4/p2p.simpai.cn/tcp/2316/p2p/12D3KooWGGEDTNkg7dhMnQK9xZAjRnLppAoMMR2q3aUw5vCn4YNc','/dns4/p2p.token.tm/tcp/2316/p2p/12D3KooWFapNfD5a27mFPoBexKyAi4E1RTP4ifpfmNKBV8tsBL4X']
pub(crate) static DEFAULT_P2P_CONFIG: &str = r#"
address.upstream_nodes = ['/dns4/p2p.token.tm/tcp/2316/p2p/12D3KooWFapNfD5a27mFPoBexKyAi4E1RTP4ifpfmNKBV8tsBL4X']
pubsub_topics = ['system']
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
}

impl P2p {
    pub async fn start(config: String, sys_claim: &IdClaim, sysinfo: &SystemInfo)
        -> Result<Arc<P2p>, Box<dyn Error + Send + Sync>> {
        let config = config::Config::from_toml(&config.clone()).expect("无法解析配置字符串");
        let result = service::new(config.clone(), sys_claim, sysinfo).await;
        let (client, mut server) = match result {
            Ok((c, s)) => (c, s),
            Err(e) => panic!("无法启动服务: {:?}", e),
        };

        let sys_did = sys_claim.gen_did();
        let shared_data = shared::get_shared_data();

        let handler = Handler {
            sys_did: sys_did.clone(),
            shared_data,
        };

        server.set_event_handler(handler);

        let config_clone = config.clone();
        let client_clone = client.clone();
        TOKIO_RUNTIME.spawn(async move {
            let task_run = server.run();
            let task_node_status = get_node_status(client_clone.clone(), config_clone.get_node_status_interval());
            let task_broadcast_online = broadcast_online_users(
                client_clone.clone(),
                config_clone.get_broadcast_interval(),
            );

            tokio::join!(
                task_run, 
                task_node_status, 
                //task_broadcast_online
            );
        });

        let p2p = Self {
            sys_did: sys_did.clone(),
            config: config.clone(),
            client: client.clone(),
            shared_data,
        };

        let claims = GlobalClaims::instance();
        let claims_copy = {
            let claims_lock = claims.lock().unwrap();
            // 收集所有需要处理的claim到Vec中
            claims_lock.iter()
                .filter(|(_, claim)| claim.self_verify())
                .map(|(_, claim)| claim.clone())
                .collect::<Vec<IdClaim>>()
            // MutexGuard在这里自动drop
        };
        for claim in claims_copy {
            if claim.self_verify() {
                p2p.put_claim_to_DHT(claim.clone()).await;
            }
        }
        Ok(Arc::new(p2p))
    }

    pub async fn get_claim_from_upstream(&self, did: String) -> IdClaim {
        if did.is_empty() || !IdClaim::validity(&did) {
            return IdClaim::default();
        }

        let request = json!({
            "method": "get_claim",
            "did": did
        });
        let message = serde_json::to_string(&request).unwrap_or_else(|e| {
            "{}".to_string()
        });
        let short_peer_id = self.client.get_short_id();

        if let Some(ref upstream_nodes) = self.config.address.upstream_nodes {
            for upstream_node in upstream_nodes {
                let upstream_peer_id = upstream_node.peer_id().to_base58();

                if let Some(target_did) = self.shared_data.get_node_did(&upstream_peer_id) {
                    let result_str = self.request(target_did.clone(), message.clone()).await;
                    if result_str.is_empty() {
                        tracing::debug!("从上游节点 {} 获取的响应为空", upstream_peer_id);
                        continue;
                    }
                    match serde_json::from_str::<IdClaim>(&result_str) {
                        Ok(claim) => {
                            tracing::info!("{} [P2pNode] P2P_node({}) 成功从上游节点({}) 获取用户({})的声明",
                                     token_utils::now_string(), short_peer_id, upstream_peer_id, did);
                            return claim;
                        },
                        Err(e) => {
                            tracing::debug!("解析上游节点 {} 返回的声明失败: {:?}", upstream_peer_id, e);
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
        if did.is_empty() ||!IdClaim::validity(did) {
            return IdClaim::default();
        }

        let key = token_utils::calc_sha256(format!("did_claim_{}", did).as_bytes()).to_base58();
        self.client.get_key_value(&key).await.map(|value| {
            match String::from_utf8(value) {
                Ok(json_str) => {
                    match serde_json::from_str::<IdClaim>(&json_str) {
                        Ok(claim) => {
                            tracing::info!("{} [P2pNode] get did({}) claim from DHT", token_utils::now_string(), did);
                            claim
                        },
                        Err(e) => {
                            tracing::error!("解析 DHT 返回的声明失败: {:?}", e);
                            IdClaim::default()
                        }
                    }
                },
                Err(e) => {
                    tracing::error!("DHT 返回的数据不是有效的 UTF-8 字符串: {:?}", e);
                    IdClaim::default()
                }
            }
        }).unwrap_or_else(|e| {
            tracing::error!("从 DHT 获取声明失败: {:?}", e);
            IdClaim::default()
        })
    }

    pub async fn put_claim_to_DHT(&self, claim: IdClaim) {
        let did = claim.gen_did();
        let key = token_utils::calc_sha256(format!("did_claim_{}", did).as_bytes()).to_base58();

        self.client.set_key_value(key, claim.to_json_string().as_bytes().to_vec()).await;
        tracing::info!("{} [P2pNode] pet did({}) claim to DHT", token_utils::now_string(), did);
    }

    async fn get_node_status(&self) {
        let node_status = self.client.get_node_status().await;
        let short_id = self.client.get_short_id();
        tracing::info!("[P2pNode] 📣 {}", node_status.short_format());
    }

    async fn broadcast(&self, topic: String, message: String) {
        let _ = self.client.broadcast(topic.clone(), message.as_bytes().to_vec()).await;
        tracing::debug!("📣 >>>> Outbound broadcast: {:?} {:?}", topic, message);
    }

    async fn request(&self, target: String, message: String) -> String {
        let short_id = self.client.get_short_id();

        let target_peer_id = {
            if let Some(peer_id) = self.shared_data.get_did_node(&target) {
                peer_id.clone()
            } else {
                tracing::warn!("user_did({}) does not belong to a node", target);
                return String::new();
            }
        };

        let known_peers = self.client.get_known_peers().await;
        if !known_peers.contains(&target_peer_id) {
            tracing::warn!("The target node({}) is not in the known node list", target);
        }

        let now_time: DateTime<Local> = Local::now();
        let target_short_id = target_peer_id.chars().skip(target_peer_id.len() - 7).collect::<String>();
        tracing::info!("📣 >>>> Outbound request: {} send {} to {} with {} at {}", short_id, message, target, target_short_id, now_time);
        let message = format!("{}|{}", target, message);
        let response = match self.client.request(&target_peer_id, message.as_bytes().to_vec()).await {
            Ok(resp) => resp,
            Err(e) => {
                tracing::error!("请求失败: {:?}", e);
                "Unknown".as_bytes().to_vec()
            }
        };
        let now_time2: DateTime<Local> = Local::now();
        tracing::info!(
            "📣 <<<< Inbound response: Time({}) {:?}", now_time2,
            String::from_utf8_lossy(&response)
        );
        String::from_utf8_lossy(&response).to_string()
    }
}


#[derive(Debug)]
struct Handler {
    sys_did: String,
    shared_data: &'static shared::SharedData,
}

impl EventHandler for Handler {
    fn handle_inbound_request(&self, request: Vec<u8>) -> Result<Vec<u8>, Box<dyn Error>> {
        let request_str = String::from_utf8_lossy(&request).to_string();
        tracing::info!(
            "📣 <<<< Inbound REQUEST: {}",
            request_str
        );

        // 按照 user_did|msg 格式解析
        let parts: Vec<&str> = request_str.splitn(2, '|').collect();
        if parts.len() != 2 {
            tracing::warn!("请求格式不正确，应为 'user_did|msg'");
            return Ok("格式错误".as_bytes().to_vec());
        }

        let user_did = parts[0];
        if user_did.is_empty() || !IdClaim::validity(user_did) {
            tracing::warn!("请求的user_did不正确");
            return Ok("user_did错误".as_bytes().to_vec());
        }

        let msg_obj = parts[1];
        match serde_json::from_str::<serde_json::Value>(msg_obj) {
            Ok(json_obj) => {
                if let Some(method) = json_obj.get("method").and_then(|m| m.as_str()) {
                    match method {
                        "get_claim" => {
                            let response = if let Some(did) = json_obj.get("did").and_then(|d| d.as_str()) {
                                let claim = self.shared_data.claims.lock().unwrap().get_claim_from_local(did);
                                tracing::info!("{} [P2pNode] get did({}) claim from upstream.", token_utils::now_string(), did);
                                claim.to_json_string()
                            } else {
                                tracing::warn!("get_claim 方法缺少 did 参数");
                                IdClaim::default().to_json_string()
                            };
                            return Ok(response.as_bytes().to_vec());
                        },
                        // 可以添加更多方法的处理逻辑
                        _ => {
                            tracing::warn!("未知的方法: {}", method);
                            return Ok(format!("未知的方法: {}", method).as_bytes().to_vec());
                        }
                    }
                } else {
                    tracing::warn!("JSON 对象中缺少 method 属性");
                    return Ok("缺少 method 属性".as_bytes().to_vec());
                }
            },
            Err(e) => {
                tracing::warn!("JSON 解析错误: {}", e);
                return Ok(format!("JSON 解析错误: {}", e).as_bytes().to_vec());
            }
        }
    }

    fn handle_broadcast(&self, topic: &str, message: Vec<u8>, sender: PeerId) {
        let message_str = String::from_utf8_lossy(&message).to_string();

        tracing::debug!(
            "📣 <<<< Inbound BROADCAST: {:?} {:?}",
            topic,
            message_str
        );

        // 处理不同类型的广播消息
        match topic {
            "online" => {
                if !message_str.is_empty() {
                    let parts: Vec<&str> = message_str.splitn(3, ':').collect();
                    if parts.len() != 3 {
                        tracing::warn!("在线用户消息格式不正确: {}", message_str);
                        return;
                    }
                    let sys_did = parts[0].to_string();
                    let user_list = parts[2].to_string();

                    let sender_id = sender.to_base58();
                    let online_all_num = {
                        self.shared_data.online_all.log_access_batch(user_list.clone());
                        self.shared_data.online_all.get_number()
                    };
                    let (online_nodes_num, online_nodes_top) = {
                        self.shared_data.online_nodes.log_access_batch(sender_id.clone());
                        (self.shared_data.online_nodes.get_number(), self.shared_data.online_nodes.get_nodes_top_list())
                    };
                    tracing::info!("{} [P2pNode] update online list: nodes={}, users={}", token_utils::now_string(), online_nodes_num, online_all_num);
                    let entries: Vec<(String, String)> = message_str
                        .split('|')
                        .filter(|entry| !entry.is_empty())
                        .map(|user_id| (user_id.to_string(), sender_id.clone()))
                        .collect();
                    self.shared_data.insert_node_did(&sender_id, &sys_did);
                    self.shared_data.insert_did_node_batch(&user_list, &sender_id);
                }
            },
            "system" => {
                // 收到系统消息，更新本地消息队列
                if !message_str.is_empty() {
                    let count = self.shared_data.get_message_queue().push_messages(&self.sys_did, message_str);
                    tracing::info!("{} [P2pNode] added {} new system meaasge.", token_utils::now_string(), count);
                }
            },
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
        tracing::info!("{} [P2pNode] 📣 {}", token_utils::now_string(), node_status.short_format());
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
        let _ = client.broadcast(topic, message.as_bytes().to_vec()).await;
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
            let request = format!("Hello {}, request from {} at {}!", target_id, short_id, now_time);
            tracing::info!("📣 >>>> Outbound request: {:?}", request);
            let response = match client.request(target, request.as_bytes().to_vec()).await {
                Ok(resp) => resp,
                Err(e) => {
                    tracing::error!("请求失败: {:?}", e);
                    continue; // 跳过这次失败的请求，继续下一次循环
                }
            };
            let now_time2: DateTime<Local> = Local::now();
            tracing::info!(
            "📣 <<<< Inbound response: Time({}) {:?}", now_time2,
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
            tracing::info!("📣 >>>> broadcast({topic}): {} online users in {} at {}, list={}", users_list.split('|').count(), client.get_short_id(), now_time, users_list);
            let message = format!("{}:{}:{}", client.get_sys_did(), unix_timestamp, users_list);
            let _ = client.broadcast(topic, message.as_bytes().to_vec()).await;
        } else {
            tracing::info!("no users on node ...");
        }
    }
}

pub async fn get_instance() -> Option<Arc<P2p>> {
    let p2p_instance_guard = P2P_INSTANCE.lock().await;
    p2p_instance_guard.clone()
}