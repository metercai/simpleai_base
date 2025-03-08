use std::error::Error;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::thread;
use std::collections::HashMap;
use tracing_subscriber::EnvFilter;
use std::env;
use chrono::{Local, DateTime};
use tokio::time;
use rand::Rng;
use libp2p::PeerId;

mod protocol;
mod http_service;
mod error;
mod utils;
mod service;
mod config;
mod req_resp;

use crate::p2p::service::{Client, Server, EventHandler};
use crate::p2p::error::P2pError;
use crate::claims::{GlobalClaims, IdClaim};
use crate::user_mgr::{MessageQueue, OnlineUsers};
use once_cell::sync::OnceCell;
use crate::token_utils;
use crate::systeminfo::SystemInfo;
use crate::cert_center::GlobalCerts;

const BOOTSTRAP_INTERVAL: Duration = Duration::from_secs(5 * 60);

pub struct P2p {
    sys_did: String,
    config: config::Config,
    client: Client,
    did_node_map: HashMap<String, String>,
    online_users: Arc<Mutex<OnlineUsers>>,
    online_all: Arc<Mutex<OnlineUsers>>,
    message_queue: Arc<Mutex<MessageQueue>>,
    claims: Arc<Mutex<GlobalClaims>>,
    certificates: Arc<Mutex<GlobalCerts>>,
}

impl P2p {
    pub async fn start(config: String, sys_claim: &IdClaim, sysinfo: &SystemInfo, 
        online_users: Arc<Mutex<OnlineUsers>>, online_all: Arc<Mutex<OnlineUsers>>, 
        message_queue: Arc<Mutex<MessageQueue>>, claims: Arc<Mutex<GlobalClaims>>,
        certificates: Arc<Mutex<GlobalCerts>>
    ) -> Self {
        let config = config::Config::from_toml(&config.clone()).expect("无法解析配置字符串");
        let result = service::new(config.clone(), sys_claim, sysinfo).await;
        let (client, mut server) = match result {
            Ok((c, s)) => (c, s),
            Err(e) => panic!("无法启动服务: {:?}", e),
        };
        
        let did_node_map = HashMap::new();
        
        let handler = Handler {
            online_all: online_all.clone(),
            message_queue: message_queue.clone(),
            did_node_map: Arc::new(Mutex::new(did_node_map.clone())), 
            claims: claims.clone(),
            certificates: certificates.clone(),
        };
        server.set_event_handler(handler);
    
        let config_clone = config.clone();
        let client_clone = client.clone();
        let online_users_clone = online_users.clone();
        token_utils::TOKIO_RUNTIME.spawn(async move {
            let task_run = server.run();
            let task_node_status = get_node_status(client_clone.clone(), config_clone.get_node_status_interval());
            let task_broadcast_online = broadcast_online_users(
                client_clone.clone(), 
                online_users_clone.clone(), 
                config_clone.get_broadcast_interval()
            );
    
            tokio::join!(
                task_run, 
                task_node_status, 
                task_broadcast_online
            );
        });
        
        Self {
            sys_did: sys_claim.gen_did(),
            config: config.clone(),
            client: client.clone(),
            did_node_map,
            online_users,
            online_all,
            message_queue,
            claims,
            certificates,
        }
    }

    async fn get_node_status(&self) {
        let node_status = self.client.get_node_status().await;
        let short_id = self.client.get_peer_id();
        tracing::info!("📣 {}", node_status.short_format());
    }

    async fn broadcast(&self, topic: String, message: String) {
        let _ = self.client.broadcast(topic.clone(), message.as_bytes().to_vec()).await;
        tracing::debug!("📣 >>>> Outbound broadcast: {:?} {:?}", topic, message);
    }

    async fn request(&self, target: String, message: String) -> String {
        let short_id = self.client.get_peer_id();

        let target_peer_id = {
            if let Some(peer_id) = self.did_node_map.get(&target) {
                peer_id.clone()
            } else {
                tracing::warn!("用户 ID {} 未找到对应的节点信息", target);
                return String::new();
            }
        };

        let known_peers = self.client.get_known_peers().await;
        if !known_peers.contains(&target_peer_id) {
            tracing::warn!("目标节点 {} 不在已知节点列表中", target);
            return String::new();
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
    online_all: Arc<Mutex<OnlineUsers>>,
    message_queue: Arc<Mutex<MessageQueue>>,
    did_node_map: Arc<Mutex<HashMap<String, String>>>,
    claims: Arc<Mutex<GlobalClaims>>,
    certificates: Arc<Mutex<GlobalCerts>>,
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
                // 获取 method 属性
                if let Some(method) = json_obj.get("method").and_then(|m| m.as_str()) {
                    match method {
                        "get_claim" => {
                            // 处理 get_claim 方法
                            if let Some(did) = json_obj.get("did").and_then(|d| d.as_str()) {
                                let claim = {
                                    let mut claims = self.claims.lock().unwrap();
                                    claims.get_claim_from_local(did)
                                };
                                
                                // 将 IdClaim 转换为 JSON 字符串返回
                                let response = claim.to_json_string();
                                tracing::debug!("处理 get_claim 请求，返回用户 {} 的声明", did);
                                return Ok(response.as_bytes().to_vec());
                            } else {
                                tracing::warn!("get_claim 方法缺少 did 参数");
                                return Ok("缺少 did 参数".as_bytes().to_vec());
                            }
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
        
        tracing::info!(
            "📣 <<<< Inbound BROADCAST: {:?} {:?}",
            topic,
            message_str
        );
        
        // 处理不同类型的广播消息
        match topic {
            "online" => {
                if !message_str.is_empty() {
                    // 更新在线用户列表
                    self.online_all.lock().unwrap().log_access_batch(message_str.clone());
                    tracing::debug!("已更新全网在线用户列表");
                    let sender_id = sender.to_base58();
                    let entries: Vec<(String, String)> = message_str
                        .split('|')
                        .filter(|entry| !entry.is_empty())
                        .map(|user_id| (user_id.to_string(), sender_id.clone()))
                        .collect();
                    {
                        let mut did_map = self.did_node_map.lock().unwrap();
                        for (user_id, node_id) in entries {
                            did_map.insert(user_id, node_id);
                        }
                    }  
                }
            },
            "system" => {
                // 收到系统消息，更新本地消息队列
                if !message_str.is_empty() {
                    let count = self.message_queue.lock().unwrap().push_messages(message_str);
                    tracing::debug!("已添加 {} 条新系统消息到队列", count);
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
        let short_id = client.get_peer_id();
        tracing::info!("📣 {}", node_status.short_format());
    }
}

async fn broadcast(client: Client, interval: u64) {
    let dur = time::Duration::from_secs(interval);
    loop {
        time::sleep(dur).await;
        let topic = "system".to_string();
        let short_id = client.get_peer_id();
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
        let short_id = client.get_peer_id();
        
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
async fn broadcast_online_users(client: Client, online_users: Arc<Mutex<OnlineUsers>>, interval: u64) {
    let dur = time::Duration::from_secs(interval);
    loop {
        time::sleep(dur).await;
        
        // 获取当前在线用户列表
        let users_list = {
            let users = online_users.lock().unwrap();
            users.get_full_list()
        };
        
        // 只有当有在线用户时才广播
        if !users_list.is_empty() {
            let topic = "online".to_string();
            tracing::debug!("广播在线用户列表，共 {} 个用户", users_list.split('|').count());
            let _ = client.broadcast(topic, users_list.as_bytes().to_vec()).await;
        } else {
            tracing::debug!("当前无在线用户，跳过广播");
        }
    }
}

