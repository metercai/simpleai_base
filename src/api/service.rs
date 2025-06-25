use warp::{Filter, Rejection, Reply};
use std::sync::{Arc, LazyLock, Mutex};
use std::net::Ipv4Addr;
use serde::{Deserialize, Serialize};
use serde::de::DeserializeOwned;
use serde_json::{json, Value};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use tracing::{debug, info, error};
use bytes::Bytes;
use tokio::task::JoinHandle;

use std::collections::HashMap;
use tokio::sync::{Mutex as TokioMutex, RwLock, oneshot};
use warp::ws::{Message, WebSocket};
use futures_util::{SinkExt, StreamExt};
use uuid::Uuid;
use lazy_static::lazy_static;

use crate::dids::{token_utils, TOKIO_RUNTIME, DidToken, REQWEST_CLIENT, REQWEST_CLIENT_SYNC};
use crate::dids::claims::{IdClaim, GlobalClaims};
use crate::dids::cert_center::GlobalCerts;
use crate::dids::tokendb::TokenDB;
use crate::user::TokenUser;
use crate::user::shared;
use crate::user::user_vars::GlobalLocalVars;
use crate::p2p;
use crate::token;
use crate::utils::env_utils;
use crate::api::{ApiResponse, P2pStatus, wsclient::WsClient};


static API_PORT: LazyLock<Mutex<u16>> = LazyLock::new(|| Mutex::new(init_api_port()));
static SERVER_HANDLE: LazyLock<Mutex<Option<JoinHandle<()>>>> = LazyLock::new(|| Mutex::new(None));

fn init_api_port() -> u16 {
    let port_file_path = token_utils::get_path_in_sys_key_dir("local.port");
    if !port_file_path.exists() {
        return 0;
    }
    let port_str = std::fs::read_to_string(&port_file_path).unwrap_or("0".to_string());
    let port = port_str.parse::<u16>().unwrap_or(0);
    if port != 0 {
        match REQWEST_CLIENT_SYNC.get(format!("http://127.0.0.1:{}/api/check_sys", port)).send() {
            Ok(resp) => {
                if resp.status().is_success() {
                    println!("{} [SimpBase] REST service is online.", token_utils::now_string());
                    return port
                }
            }
            Err(_) => { }
        }
    } 
    std::fs::remove_file(&port_file_path).unwrap();
    return 0;
}

pub fn get_api_host() -> String {
    let port = *API_PORT.lock().unwrap(); 
    return format!("http://127.0.0.1:{}/api", port);
}

pub fn get_ws_host() -> String {
    let port = *API_PORT.lock().unwrap();
    return format!("ws://127.0.0.1:{}/ws", port);
}

pub fn is_self_service() -> bool {
    let port = *API_PORT.lock().unwrap(); 
    let server_handle = SERVER_HANDLE.lock().unwrap();
    port == 0 || server_handle.is_some()
}


// 自定义错误类型，用于序列化/反序列化错误
#[derive(Debug)]
struct InvalidSerializationError;

impl warp::reject::Reject for InvalidSerializationError {}

#[derive(Debug)]
pub struct WebSocketError {
    message: String,
}

impl std::fmt::Display for WebSocketError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "WebSocket error: {}", self.message)
    }
}

impl std::error::Error for WebSocketError {}
impl warp::reject::Reject for WebSocketError {}
impl From<Box<dyn std::error::Error>> for WebSocketError {
    fn from(err: Box<dyn std::error::Error>) -> Self {
        WebSocketError {
            message: err.to_string(),
        }
    }
}


// WebSocket连接管理结构
#[derive(Debug, Clone)]
pub struct WebSocketConnection {
    pub id: String,
    pub client_did: Option<String>,
    pub client_name: Option<String>,
    pub subscriptions: Vec<String>, // 订阅的频道列表
    pub sender: Arc<TokioMutex<Option<futures_util::stream::SplitSink<WebSocket, Message>>>>,
}

// WebSocket消息类型
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum WsMessage {
    // 客户端发送的消息
    Subscribe { channels: Vec<String> },
    Unsubscribe { channels: Vec<String> },
    Auth { client_did: String, client_name: String  },
    Response { id: String, result: String },
    
    // 服务端发送的消息
    Welcome { connection_id: String },
    Subscribed { channels: Vec<String> },
    Unsubscribed { channels: Vec<String> },
    Authenticated { client_did: String },
    Notification { channel: String, body: Vec<u8> },
    DirectMessage { message: Vec<u8> },
    DirectTask { id: String, body: Vec<u8> },
    Error { message: String },
}


// 全局WebSocket连接管理器
pub type WebSocketManager = Arc<RwLock<HashMap<String, WebSocketConnection>>>;

// 频道订阅管理器
pub type ChannelManager = Arc<RwLock<HashMap<String, Vec<String>>>>; // channel -> connection_ids

lazy_static! {
    static ref WS_MANAGER: WebSocketManager = Arc::new(RwLock::new(HashMap::new()));
    static ref CHANNEL_MANAGER: ChannelManager = Arc::new(RwLock::new(HashMap::new()));
    static ref RESPONSE_WAITERS: TokioMutex<HashMap<String, oneshot::Sender<String>>> = TokioMutex::new(HashMap::new());
}


pub fn start_rest_server() -> bool{
    let address = Ipv4Addr::LOCALHOST;
    let mut port = *API_PORT.lock().unwrap();
    if port != 0 {
        info!("{} [SimpBase] REST service is already running at: http://{}:{}", token_utils::now_string(), address, port);
        return false;
    }
    port =  TOKIO_RUNTIME.block_on(async move {
        env_utils::get_port_availability(address, 4515).await
    });

    let server = TOKIO_RUNTIME.spawn(async move {
        let check_sys = warp::path!("api" / "check_sys")
            .and(warp::get())
            .and_then(handle_check_sys);

        let get_sys_did = warp::path!("api" / "sys_did")
            .and(warp::get())
            .and_then(handle_get_sys_did);

        let get_device_did = warp::path!("api" / "device_did")
            .and(warp::get())
            .and_then(handle_get_device_did);

        let get_upstream_did = warp::path!("api" / "upstream_did")
            .and(warp::get())
            .and_then(handle_get_upstream_did);

        let get_local_vars = warp::path!("api" / "local_vars")
            .and(warp::post())
            .and(warp::body::json())
            .and_then(handle_get_local_vars);

        let get_claim = warp::path!("api" / "get_claim" / String)
            .and(warp::get())
            .and_then(|user_did: String| handle_get_claim(user_did));

        let put_claim = warp::path!("api" / "put_claim")
            .and(warp::post())
            .and(warp::body::json())
            .and_then(handle_put_claim);

        let get_register_cert = warp::path!("api" / "register_cert")
            .and(warp::post())
            .and(warp::body::json())
            .and_then(handle_get_register_cert);

        let is_registered = warp::path!("api" / "is_registered" / String)
            .and(warp::get())
            .and_then(|user_did: String| handle_is_registered(user_did));

        let sign_by_did = warp::path!("api" / "sign_by_did")
            .and(warp::post())
            .and(warp::body::json())
            .and_then(handle_sign_by_did);

        let verify_by_did = warp::path!("api" / "verify_by_did")
            .and(warp::post())
            .and(warp::body::json())
            .and_then(handle_verify_by_did);

        let encrypt_for_did = warp::path!("api" / "encrypt_for_did")
            .and(warp::post())
            .and(warp::body::json())
            .and_then(handle_encrypt_for_did);

        let decrypt_by_did = warp::path!("api" / "decrypt_by_did")
            .and(warp::post())
            .and(warp::body::json())
            .and_then(handle_decrypt_by_did);

        let get_path_in_user_dir = warp::path!("api" / "path_in_user_dir")
            .and(warp::post())
            .and(warp::body::json())
            .and_then(handle_get_path_in_user_dir);

        let put_global_message = warp::path!("api" / "put_global_message")
            .and(warp::post())
            .and(warp::body::json())
            .and_then(handle_put_global_message);
        
        let p2p_request = warp::path!("api" / "p2p_request" / String / String)
            .and(warp::post())
            .and(warp::body::bytes())
            .and_then(|mode: String, target_did: String, body: Bytes| handle_p2p_request(mode, target_did, body));

        let p2p_response = warp::path!("api" / "p2p_response" / String / String)
            .and(warp::post())
            .and(warp::body::bytes())
            .and_then(|mode: String, task_id: String, body: Bytes| handle_p2p_response(mode, task_id, body));

        let p2p_put_msg = warp::path!("api" / "p2p_put_msg")
            .and(warp::post())
            .and(warp::body::bytes())
            .and_then(handle_p2p_put_msg);

        let p2p_mgr = warp::path!("api" / "p2p_mgr" / String)
            .and(warp::get())
            .and_then(|action: String| handle_p2p_mgr(action));

        let db_get = warp::path!("api" / "db_get")
            .and(warp::post())
            .and(warp::body::json())
            .and_then(handle_db_get);

        let db_insert = warp::path!("api" / "db_insert")
            .and(warp::post())
            .and(warp::body::json())
            .and_then( handle_db_insert);

        let db_remove = warp::path!("api" / "db_remove")
            .and(warp::post())
            .and(warp::body::json())
            .and_then(handle_db_remove);

        let db_scan_prefix = warp::path!("api" / "db_scan_prefix")
            .and(warp::post())
            .and(warp::body::json())
            .and_then( handle_db_scan_prefix);
        
        // WebSocket连接端点
        let websocket = warp::path("ws")
            .and(warp::ws())
            .and_then(handle_websocket);

        // 广播推送API
        let broadcast = warp::path!("api" / "broadcast" / String)
            .and(warp::post())
            .and(warp::body::bytes())
            .and_then(|channel: String, body: Bytes| async move {
                handle_broadcast(channel, body).await
            });

        // 定向推送API
        let direct_message = warp::path!("api" / "direct" / String)
            .and(warp::post())
            .and(warp::body::bytes())
            .and_then(|client_did: String, body: Bytes| async move {
                handle_direct_message(client_did, body).await
            });

        // 定向任务API
        let direct_task = warp::path!("api" / "ws_task" / String)
            .and(warp::post())
            .and(warp::body::bytes())
            .and_then(|client_did: String, body: Bytes| async move {
                handle_direct_task(client_did, body).await
            });

        // WebSocket连接状态查询API
        let ws_status = warp::path!("api" / "ws_status")
            .and(warp::get())
            .and_then(|| async move {
                handle_ws_status().await
            });

        let routes_rest = check_sys
            .or(get_sys_did)
            .or(get_device_did)
            .or(get_upstream_did)
            .or(get_local_vars)
            .or(get_claim)
            .or(put_claim)
            .or(get_register_cert)
            .or(is_registered)
            .or(sign_by_did)
            .or(verify_by_did)
            .or(encrypt_for_did)
            .or(decrypt_by_did)
            .or(get_path_in_user_dir)
            .or(put_global_message)
            .or(p2p_request)
            .or(p2p_response)
            .or(p2p_put_msg)
            .or(p2p_mgr)
            .or(db_get)
            .or(db_insert)
            .or(db_remove)
            .or(db_scan_prefix)
            ;

        let routes_ws = websocket      // WebSocket连接
            .or(broadcast)      // 广播推送
            .or(direct_message) // 定向推送
            .or(direct_task)    // 定向任务
            .or(ws_status)
            ;

        let routes = routes_rest.or(routes_ws);
        warp::serve(routes).run((address, port)).await;

        println!("{} [SimpBase] REST server at http://{}:{} has shut down.", 
                 token_utils::now_string(), address, port);
        *API_PORT.lock().unwrap() = 0;
        let port_file_path = token_utils::get_path_in_sys_key_dir("local.port");
        if let Err(e) = std::fs::remove_file(&port_file_path) {
            eprintln!("{} [SimpBase] INFO: Could not remove port file {}: {}", 
                      token_utils::now_string(), port_file_path.display(), e);
        }
        if let Ok(mut server_handle) = SERVER_HANDLE.try_lock() {
            *server_handle = None;
        }
    });
    *SERVER_HANDLE.lock().unwrap() = Some(server);
    let port_file_path = token_utils::get_path_in_sys_key_dir("local.port");
    if let Err(e) = std::fs::write(&port_file_path, port.to_string()) {
        eprintln!("{} [SimpBase] ERROR: Failed to write port {} to {}: {}. Server will run, but other instances might not find it via file.", 
                    token_utils::now_string(), port, port_file_path.display(), e);
    }
    *API_PORT.lock().unwrap() = port;
    println!("{} [SimpBase] REST server started at: http://{}:{}", token_utils::now_string(), address, port);
    true
}

pub fn stop_rest_server() {
    let mut server_handle = SERVER_HANDLE.lock().unwrap();
    if let Some(handle) = server_handle.take() {
        println!("{} [SimpBase] 正在停止REST服务器...", token_utils::now_string());
        // 中止任务
        handle.abort();
        
        // 可选：等待任务完成（在某些情况下可能需要）
        TOKIO_RUNTIME.block_on(async {
            match handle.await {
                Ok(_) => println!("{} [SimpBase] REST服务器已正常停止", token_utils::now_string()),
                Err(e) if e.is_cancelled() => println!("{} [SimpBase] REST服务器已被中止", token_utils::now_string()),
                Err(e) => eprintln!("{} [SimpBase] 停止REST服务器时发生错误: {}", token_utils::now_string(), e),
            }
        });
        
        // 清理端口文件
        let port_file_path = token_utils::get_path_in_sys_key_dir("local.port");
        if port_file_path.exists() {
            if let Err(e) = std::fs::remove_file(&port_file_path) {
                eprintln!("{} [SimpBase] 无法删除端口文件 {}: {}", 
                          token_utils::now_string(), port_file_path.display(), e);
            }
        }
        
        // 重置端口
        *API_PORT.lock().unwrap() = 0;
    } else {
        println!("{} [SimpBase] REST服务器未运行", token_utils::now_string());
    }
}

// WebSocket连接处理
async fn handle_websocket(
    ws: warp::ws::Ws,
) -> Result<impl warp::Reply, warp::Rejection> {
    Ok(ws.on_upgrade(move |socket| handle_socket(socket)))
}

// 处理单个WebSocket连接
async fn handle_socket(
    ws: WebSocket,
) {
    let ws_manager = WS_MANAGER.clone();
    let connection_id = Uuid::new_v4().to_string();
    let (mut ws_sender, mut ws_receiver) = ws.split();
    
    // 发送欢迎消息
    let welcome_msg = WsMessage::Welcome { 
        connection_id: connection_id.clone() 
    };
    if let Ok(msg_str) = serde_json::to_string(&welcome_msg) {
        if ws_sender.send(Message::text(msg_str)).await.is_err() {
            return;
        }
    }

    // 创建连接对象
    let connection = WebSocketConnection {
        id: connection_id.clone(),
        client_did: None,
        client_name: None,
        subscriptions: Vec::new(),
        sender: Arc::new(TokioMutex::new(Some(ws_sender))),
    };

    // 注册连接
    ws_manager.write().await.insert(connection_id.clone(), connection);
    println!("{} [SimpBase] WebSocket client({}) connected", token_utils::now_string(), connection_id);

    // 处理消息
    while let Some(result) = ws_receiver.next().await {
        match result {
            Ok(msg) => {
                let ws_lock = ws_manager.read().await;
                let connection = ws_lock.get(&connection_id).unwrap().clone();
                drop(ws_lock);
                if msg.is_ping() {
                    let ping_time = u128::from_be_bytes(msg.clone().into_bytes().try_into().unwrap());
                    let delay = tokio::time::Instant::now().elapsed().as_micros() - ping_time;
                    
                    info!("{} [SimpBase] WebSocket client({}) ping_delay={}", token_utils::now_string(), connection_id, delay);
                    let mut sender = connection.sender.lock().await;
                    if let Err(e) = sender.as_mut().unwrap().send(Message::pong(msg)).await {
                        error!("{} [SimpBase] 发送Pong响应时发生错误: {}",
                                  token_utils::now_string(), e);
                    }
                } else if msg.is_binary() {
                    handle_ws_message(&connection_id, msg.into_bytes()).await;
                } else if msg.is_close() {
                    debug!("{} [SimpBase] WebSocket client({}) is disconnecting.", 
                            token_utils::now_string(), connection_id);
                    let mut sender = connection.sender.lock().await;
                    if let Err(e) = sender.as_mut().unwrap().send(Message::close()).await {
                        error!("{} [SimpBase] 发送关闭消息时发生错误: {}",
                                  token_utils::now_string(), e);
                    }
                    break;
                }
                
            }
            Err(e) => {
                error!("{} [SimpBase] WebSocket error: {}", 
                          token_utils::now_string(), e);
                let ws_lock = ws_manager.read().await;
                let connection = ws_lock.get(&connection_id).unwrap().clone();
                drop(ws_lock);
                let mut sender = connection.sender.lock().await;
                if let Err(e) = sender.as_mut().unwrap().send(Message::close()).await {
                    error!("{} [SimpBase] 发送关闭消息时发生错误: {}",
                                token_utils::now_string(), e);
                }
                break;
            }
        }
    }

    // 清理连接
    cleanup_connection(&connection_id).await;
    info!("{} [SimpBase] WebSocket client({}) disconnected", token_utils::now_string(), connection_id);
}

// 处理WebSocket的上行消息
async fn handle_ws_message(
    connection_id: &str,
    message: Vec<u8>,
) -> Result<(), Box<dyn std::error::Error>> {
    let ws_message: WsMessage = serde_cbor::from_slice(&message)?;
    
    match ws_message {
        WsMessage::Subscribe { channels } => {
            handle_subscribe(connection_id, channels).await?;
        }
        WsMessage::Unsubscribe { channels } => {
            handle_unsubscribe(connection_id, channels).await?;
        }
        WsMessage::Auth { client_did, client_name } => {
            handle_auth(connection_id, client_did, client_name).await?;
        }
        WsMessage::Response { id, result } => { 
            handle_response(id, result).await;
        }
        _ => {
            // 忽略其他消息类型
        }
    }
    
    Ok(())
}

// 处理上行的订阅
async fn handle_subscribe(
    connection_id: &str,
    channels: Vec<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let ws_manager = WS_MANAGER.clone();
    let channel_manager = CHANNEL_MANAGER.clone();
    let mut ws_lock = ws_manager.write().await;
    let mut ch_lock = channel_manager.write().await;
    
    if let Some(connection) = ws_lock.get_mut(connection_id) {
        for channel in &channels {
            if !connection.subscriptions.contains(channel) {
                connection.subscriptions.push(channel.clone());
                ch_lock.entry(channel.clone())
                    .or_insert_with(Vec::new)
                    .push(connection_id.to_string());
            }
        }
        
        drop(ws_lock);
        drop(ch_lock);
        
        send_to_connection(
            connection_id, 
            WsMessage::Subscribed { channels },
        ).await?;
    }
    
    Ok(())
}

// 处理上行的取消订阅
async fn handle_unsubscribe(
    connection_id: &str,
    channels: Vec<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let ws_manager = WS_MANAGER.clone();
    let mut ws_lock = ws_manager.write().await;
    let channel_manager = CHANNEL_MANAGER.clone();
    let mut ch_lock = channel_manager.write().await;
    
    if let Some(connection) = ws_lock.get_mut(connection_id) {
        for channel in &channels {
            connection.subscriptions.retain(|c| c != channel);
            if let Some(subscribers) = ch_lock.get_mut(channel) {
                subscribers.retain(|id| id != connection_id);
                if subscribers.is_empty() {
                    ch_lock.remove(channel);
                }
            }
        }
        drop(ch_lock);
        drop(ws_lock);
        
        send_to_connection(
            connection_id, 
            WsMessage::Unsubscribed { channels },
        ).await?;
    }
    
    Ok(())
}

// 处理上行的认证
async fn handle_auth(
    connection_id: &str,
    client_did: String,
    client_name: String,
) -> Result<(), Box<dyn std::error::Error>> {
    let ws_manager = WS_MANAGER.clone();
    let mut ws_lock = ws_manager.write().await;
    
    if let Some(connection) = ws_lock.get_mut(connection_id) {
        connection.client_did = Some(client_did.clone());
        connection.client_name = Some(client_name.clone());
        // 遍历所有connection，检查是否有相同client_did的连接，有则关闭
        for (id, conn) in ws_lock.iter() {
            if conn.client_did == Some(client_did.clone()) && id != connection_id {
                debug!("{} [SimpBase] WebSocket client({}): client_did={} is already connected, closing...",
                         token_utils::now_string(), id, client_did);
                let mut sender = conn.sender.lock().await;
                if let Err(e) = sender.as_mut().unwrap().send(Message::close()).await {
                    error!("{} [SimpBase] 发送关闭消息时发生错误: {}",
                              token_utils::now_string(), e);
                }
                cleanup_connection(id).await;
            }
        }
        drop(ws_lock);
        info!("{} [SimpBase] WebSocket client({}): client_did={}, client_name={}", 
             token_utils::now_string(), connection_id, client_did, client_name);
        
        send_to_connection(
            connection_id, 
            WsMessage::Authenticated { client_did },
        ).await?;
    }
    
    Ok(())
}

// 处理返回的任务响应
async fn handle_response(id: String, result: String) {
    if let Some(tx) = RESPONSE_WAITERS.lock().await.remove(&id) {
        let _ = tx.send(result);
    }
}


// 下行广播消息
pub(crate) async fn send_broadcast(
    channel: String,
    body: Bytes,
) -> Result<usize, Box<dyn std::error::Error>> {
    let channel_manager = CHANNEL_MANAGER.clone();
    let ch_lock = channel_manager.read().await;
    let mut sent_count = 0;
    if let Some(subscribers) = ch_lock.get(&channel) {
        let message = WsMessage::Notification { channel: channel.clone(), body: body.to_vec() };
        for connection_id in subscribers {
            if send_to_connection(connection_id, message.clone()).await.is_ok() {
                sent_count += 1;
            }
        } 
    }
    Ok(sent_count) 
}

// 下行定向消息
pub(crate) async fn send_message(
    client_did: String,
    body: Bytes,
) -> Result<usize, Box<dyn std::error::Error>> {
    let message = WsMessage::DirectMessage { message: body.to_vec() };
    let mut sent_count = 0;
    let ws_manager = WS_MANAGER.clone();
    let ws_lock = ws_manager.read().await;
    for connection in ws_lock.values() {
        if let Some(ref conn_client_did) = connection.client_did {
            if conn_client_did == &client_did {
                if send_to_connection(&connection.id, message.clone()).await.is_ok() {
                    sent_count += 1;
                }
            }
        }
    }
    Ok(sent_count)
}


// 下行消息到指定连接, 消息统一成二进制的CBOR格式
async fn send_to_connection(
    connection_id: &str,
    message: WsMessage,
) -> Result<bool, Box<dyn std::error::Error>> {
    let msg_cbor = match serde_cbor::to_vec(&message) {
        Ok(s) => s,
        Err(_) => return Ok(false),
    };
    let ws_manager = WS_MANAGER.clone();
    let ws_lock = ws_manager.read().await;
    if let Some(connection) = ws_lock.get(connection_id) {
        if let Some(sender) = connection.sender.lock().await.as_mut() {
            sender.send(Message::binary(msg_cbor)).await?;
            return Ok(true);
        }
    }
    
    Ok(false)
}

// 清理连接
async fn cleanup_connection(
    connection_id: &str,
) {
    let ws_manager = WS_MANAGER.clone();
    let mut ws_lock = ws_manager.write().await;
    
    if let Some(connection) = ws_lock.remove(connection_id) {
        // 从所有频道中移除该连接
        for channel in &connection.subscriptions {
            let channel_manager = CHANNEL_MANAGER.clone();
            let mut ch_lock = channel_manager.write().await;
            if let Some(subscribers) = ch_lock.get_mut(channel) {
                subscribers.retain(|id| id != connection_id);
                if subscribers.is_empty() {
                    ch_lock.remove(channel);
                }
            }
        }
    }
}


// --- REST的路由处理函数 ---

// --- Websocket相关的REST路由处理函数 ---
// 广播推送处理
pub(crate) async fn handle_broadcast(
    channel: String,
    body: Bytes,
) -> Result<impl warp::Reply, warp::Rejection> {
    let sent_count = send_broadcast(channel.clone(), body)
        .await
        .map_err(|e| warp::reject::custom(WebSocketError::from(e)))?;
    
    let response = serde_json::json!({ 
        "status": "success",
        "channel": channel,
        "sent_to": sent_count 
    });
        
    Ok(warp::reply::with_status(
        warp::reply::json(&response), 
        warp::http::StatusCode::OK
    ))
}

// 定向推送处理
pub(crate) async fn handle_direct_message(
    client_did: String,
    body: Bytes,
) -> Result<impl warp::Reply, warp::Rejection> {
    let sent_count = send_message(client_did.clone(), body)
        .await
        .map_err(|e| warp::reject::custom(WebSocketError::from(e)))?;
    
    let response = serde_json::json!({
        "status": "success",
        "client_did": client_did,
        "sent_to": sent_count
    });
    
    Ok(warp::reply::with_status(warp::reply::json(&response), warp::http::StatusCode::OK))
}

// 推送任务
pub(crate) async fn handle_direct_task(
    client_did: String,
    body: Bytes,
) -> Result<String, warp::Rejection> {
    let task_id = uuid::Uuid::new_v4().to_string();
    let message = WsMessage::DirectTask { id: task_id.clone(), body: body.to_vec() };

    // 准备接收反馈结果通道
    let (tx, rx) = oneshot::channel();
    RESPONSE_WAITERS.lock().await.insert(task_id, tx);
    
    // 发送任务
    let ws_manager = WS_MANAGER.clone();
    let ws_lock = ws_manager.read().await;
    let wsconntions = ws_lock
        .values()
        .filter(|conn| {
            if let Some(ref conn_client_did) = conn.client_did {
                let short_conn_client_did = conn_client_did.chars().take(7).collect::<String>();
                conn_client_did == &client_did || short_conn_client_did == client_did
            } else {
                false
            }
        })
        .cloned()  // 添加克隆确保数据所有权
        .collect::<Vec<_>>();
    drop(ws_lock);

    // 发送任务到所有匹配的连接
    for connection in wsconntions {
        send_to_connection(&connection.id, message.clone()).await
            .map_err(|e| warp::reject::custom(WebSocketError::from(e)))?;
    }
    
    // 等待响应
    match tokio::time::timeout(std::time::Duration::from_secs(30), rx).await {
        Ok(Ok(response)) => Ok(response),
        Ok(Err(_)) => Err(warp::reject::custom(WebSocketError { message: "Channel closed before receiving response".to_string() })),
        Err(_) => Err(warp::reject::custom(WebSocketError { message: "Timeout waiting for response".to_string() })),
    }
}

// WebSocket状态查询
async fn handle_ws_status() -> Result<impl warp::Reply, warp::Rejection> {
    let ws_manager = WS_MANAGER.clone();
    let ws_lock = ws_manager.read().await;
    let mut connections = Vec::new();
    
    for connection in ws_lock.values() {
        connections.push(serde_json::json!({
            "id": connection.id,
            "user_did": connection.client_did,
            "subscriptions": connection.subscriptions
        }));
    }
    
    let response = serde_json::json!({
        "total_connections": connections.len(),
        "connections": connections
    });
    
    Ok(warp::reply::json(&response))
}

// --- 非Websocket相关的REST路由处理函数 ---
// 系统状态检测
async fn handle_check_sys() -> Result<impl Reply, Rejection> {
    let claims = GlobalClaims::instance();
    let claims = claims.lock().unwrap();
    Ok(warp::reply::json(&ApiResponse {
        success: true,
        data: claims.local_claims.get_system_did(),
        error: None,
    }))
}

// 1. 获取系统DID
async fn handle_get_sys_did() -> Result<impl Reply, Rejection> {
    let claims = GlobalClaims::instance();
    let claims = claims.lock().unwrap();
    Ok(warp::reply::json(&ApiResponse {
        success: true,
        data: claims.local_claims.get_system_did(),
        error: None,
    }))
}

async fn handle_get_device_did() -> Result<impl Reply, Rejection> {
    let claims = GlobalClaims::instance();
    let claims = claims.lock().unwrap();
    Ok(warp::reply::json(&ApiResponse {
        success: true,
        data: claims.local_claims.get_device_did(),
        error: None,
    }))
}

async fn handle_get_upstream_did() -> Result<impl Reply, Rejection> {
    let didtoken = DidToken::instance();
    let mut didtoken = didtoken.lock().unwrap();
    Ok(warp::reply::json(&ApiResponse {
        success: true,
        data: didtoken.get_upstream_did(),
        error: None,
    }))
}

// 2. 获取本地变量
#[derive(Debug, Deserialize)]
struct GetLocalVarsRequest {
    key: String,
    default: String,
    user_did: String,
}

async fn handle_get_local_vars(
    req: GetLocalVarsRequest,
) -> Result<impl Reply, Rejection> {
    let global_local_vars = GlobalLocalVars::instance();
    let mut global_local_vars = global_local_vars.read().unwrap();
    let value = global_local_vars.get_local_vars(&req.key, &req.default, &req.user_did);
    Ok(warp::reply::json(&ApiResponse {
        success: !value.is_empty(),
        data: value.clone(),
        error: if value.is_empty() { Some("Invalid params".into()) } else { None },
    }))
}

// 3. 获取身份声明
async fn handle_get_claim(
    user_did: String,
) -> Result<impl Reply, Rejection> {
    let claims = GlobalClaims::instance();
    let mut claim = {
        let mut claims = claims.lock().unwrap();
        claims.get_claim_from_local(&user_did)
    };
    
    if claim.is_default() {
        if let Some(p2p) = p2p::get_instance().await {
            debug!("ready to get claim from DHT networkDID: {}", user_did);
            let did_clone = user_did.clone();
            claim = p2p.get_claim_from_DHT(&did_clone).await;
            
            if claim.is_default() {
                debug!("ready to get claim from upstream with p2p channel, DID: {}", did_clone);
                claim = p2p.get_claim_from_upstream(did_clone.to_string()).await;
                if !claim.is_default() {
                    info!("get did({}) claim from upstream with p2p channel.", did_clone);
                }
            } else {
                info!("get did({}) claim from DHT.", did_clone);
            }
            
            if !claim.is_default() {
                let mut claims = claims.lock().unwrap();
                claims.push_claim_to_local(&claim);
            }
        } else {
            debug!("p2p is not ready");
            let (sys_did, device_did) = {
                let claims = claims.lock().unwrap();
                (claims.local_claims.get_system_did(), claims.local_claims.get_device_did())
            };
            let api_name = "get_use_claim";
            let mut request: serde_json::Value = json!({});
            request["user_symbol"] = serde_json::to_value("").unwrap();
            request["user_did"] = serde_json::to_value(user_did).unwrap();
            let params = serde_json::to_string(&request).unwrap_or("{}".to_string());
            let result = {
                let upstream_did = DidToken::instance().lock().unwrap().get_upstream_did();
                let entry_point = TokenUser::instance().lock().unwrap().get_did_entry_point( &upstream_did);
                let encoded_params = DidToken::instance().lock().unwrap().encrypt_for_did(params.as_bytes(), &upstream_did ,0);
                debug!("[UpstreamClient] sys({}),dev({}) request {}/api_{} with params: {}", sys_did, device_did, entry_point, api_name, params);
                token::request_token_api_async(&entry_point, &sys_did, &device_did, api_name, &encoded_params).await    
            };
            claim = if result != "Unknown" {
                serde_json::from_str(&result).unwrap_or(IdClaim::default())
            } else {
                IdClaim::default()
            };
            if !claim.is_default() {
                let mut claims = claims.lock().unwrap();
                claims.push_claim_to_local(&claim);
            }
        }
    }
    Ok(warp::reply::json(&ApiResponse {
        success: !claim.is_default(),
        data: claim.to_json_string(),
        error: if claim.is_default() { Some("Claim not found".into()) } else { None },
    }))
}

#[derive(Debug, Deserialize)]
struct PutClaimRequest {
    claim: IdClaim,
}

async fn handle_put_claim(
    req: PutClaimRequest,
) -> Result<impl Reply, Rejection> {
    let claims = GlobalClaims::instance();
    {
        let mut claims = claims.lock().unwrap();
        claims.push_claim_to_local(&req.claim)
    };
    if let Some(p2p) = p2p::get_instance().await {
        debug!("ready to get claim from DHT network");
        let claim_clone = req.claim.clone();
        p2p.put_claim_to_DHT(claim_clone).await;
    }

    Ok(warp::reply::json(&ApiResponse {
        success: true,
        data: req.claim.gen_did(),
        error: None,
    }))
}
// 4. 获取注册证书
#[derive(Debug, Deserialize)]
struct GetRegisterCertRequest {
    user_did: String,
}

async fn handle_get_register_cert(
    req: GetRegisterCertRequest,
) -> Result<impl Reply, Rejection> {
    let cert_center = GlobalCerts::instance();
    let mut cert_center = cert_center.lock().unwrap();
    let cert = cert_center.get_register_cert(&req.user_did);
    Ok(warp::reply::json(&ApiResponse {
        success: cert != "Unknown",
        data: cert.clone(),
        error: if cert == "Unknown" { Some("Cert not found".into()) } else { None },
    }))
}

// 5. 检查是否注册
async fn handle_is_registered(
    user_did: String,
) -> Result<impl Reply, Rejection> {
    let didtoken = DidToken::instance();
    let mut didtoken = didtoken.lock().unwrap();
    let mut is_registered = didtoken.is_registered(&user_did);
    if !is_registered {
        let shared_data = shared::get_shared_data();
        is_registered = shared_data.is_p2p_in_dids(&user_did);
    }
    Ok(warp::reply::json(&ApiResponse {
        success: true,
        data: is_registered,
        error: None,
    }))
}

// 6. 通过DID签名
#[derive(Debug, Deserialize)]
struct SignByDidRequest {
    text: String,
    did: String,
    phrase: String,
}

async fn handle_sign_by_did(
    req: SignByDidRequest,
) -> Result<impl Reply, Rejection> {
    let didtoken = DidToken::instance();
    let mut didtoken = didtoken.lock().unwrap();
    let signature = didtoken.sign_by_did(&req.text, &req.did, &req.phrase);
    Ok(warp::reply::json(&ApiResponse {
        success: !signature.is_empty(),
        data: URL_SAFE_NO_PAD.encode(&signature),
        error: if signature.is_empty() { Some("Sign failed".into()) } else { None },
    }))
}

// 7. 通过DID验证签名
#[derive(Debug, Deserialize)]
struct VerifyByDidRequest {
    text: String,
    signature: String,
    did: String,
}

async fn handle_verify_by_did(
    req: VerifyByDidRequest,
) -> Result<impl Reply, Rejection> {
    let didtoken = DidToken::instance();
    let mut didtoken = didtoken.lock().unwrap();
    let is_valid = didtoken.verify_by_did(&req.text, &req.signature, &req.did);
    Ok(warp::reply::json(&ApiResponse {
        success: is_valid,
        data: is_valid,
        error: None,
    }))
}

// 8. 为DID加密数据
#[derive(Debug, Deserialize)]
struct EncryptForDidRequest {
    text: String,
    for_did: String,
    period: u64,
}

async fn handle_encrypt_for_did(
    req: EncryptForDidRequest,
) -> Result<impl Reply, Rejection> {
    let didtoken = DidToken::instance();
    let mut didtoken = didtoken.lock().unwrap();
    let ctext = didtoken.encrypt_for_did(req.text.as_bytes(), &req.for_did, req.period);
    Ok(warp::reply::json(&ApiResponse {
        success: !ctext.is_empty(),
        data: ctext.clone(),
        error: if ctext.is_empty() { Some("Encrypt failed".into()) } else { None },
    }))
}

// 9. 通过DID解密数据
#[derive(Debug, Deserialize)]
struct DecryptByDidRequest {
    ctext: String,
    by_did: String,
    period: u64,
}

async fn handle_decrypt_by_did(
    req: DecryptByDidRequest,
) -> Result<impl Reply, Rejection> {
    let didtoken = DidToken::instance();
    let mut didtoken = didtoken.lock().unwrap();
    let text = didtoken.decrypt_by_did(&req.ctext, &req.by_did, req.period);
    Ok(warp::reply::json(&ApiResponse {
        success: !text.is_empty(),
        data: text.clone(),
        error: if text.is_empty() { Some("Decrypt failed".into()) } else { None },
    }))
}

// 10. 获取用户目录路径
#[derive(Debug, Deserialize)]
struct GetUserPathRequest {
    did: String,
    catalog: String,
}

async fn handle_get_path_in_user_dir(
    req: GetUserPathRequest,
) -> Result<impl Reply, Rejection> {
    let tokenuser = TokenUser::instance();
    let tokenuser = tokenuser.lock().unwrap();
    let path = tokenuser.get_path_in_user_dir(&req.did, &req.catalog);
    Ok(warp::reply::json(&ApiResponse {
        success: !path.is_empty(),
        data: path,
        error: None,
    }))
}


#[derive(Debug, Deserialize)]
struct PutGlobalMessage {
    msg: String,
}

async fn handle_put_global_message(
    req: PutGlobalMessage,
) -> Result<impl Reply, Rejection> {
    let claims = GlobalClaims::instance();
    let claims = claims.lock().unwrap();
    let sys_did = claims.local_claims.get_system_did();
    let mut shared_data = shared::get_shared_data();
    shared_data.get_message_queue().push_messages(&sys_did, req.msg);
    Ok(warp::reply::json(&ApiResponse {
        success: true,
        data: "",
        error: None,
    }))
}

async fn handle_p2p_request(
    mode: String,
    target_did: String,
    body: Bytes,
) -> Result<impl Reply, Rejection> {
    println!("handle_p2p_request: {} {} len={}", mode, target_did, body.len());
    let p2p = p2p::get_instance().await;
    if let Some(p2p) = p2p {
        let res = p2p.request_task(target_did, body, &mode).await;
        println!("handle_p2p_request: res={}", res);
        Ok(warp::reply::json(&ApiResponse {
            success:!res.is_empty(),
            data: res,
            error: None,
        }))
    } else {
        Ok(warp::reply::json(&ApiResponse {
            success: false,
            data: "".to_string(),
            error: Some("P2P not initialized".to_string()),
        }))
    }
}


async fn handle_p2p_response(
    mode: String,
    task_id: String,
    body: Bytes,
) -> Result<impl Reply, Rejection> {
    let p2p = p2p::get_instance().await;
    if let Some(p2p) = p2p {
        // 现在可以使用 task_id 参数
        let res = p2p.response_task(task_id, body, &mode).await;
        Ok(warp::reply::json(&ApiResponse {
            success:!res.is_empty(),
            data: res,
            error: None,
        }))
    } else {
        Ok(warp::reply::json(&ApiResponse {
            success: false,
            data: "".to_string(),
            error: Some("P2P not initialized".to_string()),
        }))
    }
}

async fn handle_p2p_put_msg(
    message: Bytes,
) -> Result<impl Reply, Rejection> {
    let p2p = p2p::get_instance().await;
    if let Some(p2p) = p2p {
        let res = p2p.broadcast_user_msg(message).await;
        Ok(warp::reply::json(&ApiResponse {
            success:!res.is_empty(),
            data: res,
            error: None,
        }))
    } else {
        Ok(warp::reply::json(&ApiResponse {
            success: false,
            data: "".to_string(),
            error: Some("P2P not initialized".to_string()),
        }))
    }
}

async fn handle_p2p_mgr(
    action: String,
) -> Result<impl Reply, Rejection> {
    println!("handle_p2p_mgr: {}", action);
    let mut p2p_server = p2p::get_instance().await;
    if p2p_server.is_none() && action == "turn_on" {
        match p2p::P2pServer::start().await {
            Ok(_p2p) => {
                debug!("P2P server started successfully");
                p2p_server= Some(_p2p);
            }
            Err(e) => {
                error!("Failed to start P2P server: {}", e);
            }
        }
    }
    if p2p_server.is_some() && (action == "status" || action == "turn_on" || action == "turn_off") {
        let res = p2p_server.as_ref().unwrap().get_node_status().await;
        if action == "turn_off" {
            p2p::P2pServer::stop().await;
            debug!("P2P server stopped successfully");
        }
        let p2p_status = P2pStatus {
            node_id: res.local_peer_id.clone(),
            node_did: res.local_node_did.clone(),
            is_debug: res.is_debug,
        };
        let p2p_status = serde_json::to_string(&p2p_status).unwrap_or("".to_string());
        Ok(warp::reply::json(&ApiResponse {
            success:!res.local_peer_id.is_empty(),
            data: p2p_status,
            error: None,
        }))
    } else {
        Ok(warp::reply::json(&ApiResponse {
            success: false,
            data: "".to_string(),
            error: Some("P2P Server is not running or failed to start".to_string()),
        }))
    }
}

#[derive(Debug, Deserialize)]
struct DbGetRequest {
    tree: String,
    key: String,
}

async fn handle_db_get(
    req: DbGetRequest,
) -> Result<impl Reply, Rejection> {
    let token_db = TokenDB::instance();
    let token_db = token_db.read().unwrap();
    let value = token_db.get(&req.tree, &req.key);
    Ok(warp::reply::json(&ApiResponse {
        success: true,
        data: value,
        error: None,
    }))
}

#[derive(Debug, Deserialize)]
struct DbInsertRequest {
    tree: String,
    key: String,
    value: String,
}

async fn handle_db_insert(
    req: DbInsertRequest,
) -> Result<impl Reply, Rejection> {
    let token_db = TokenDB::instance();
    let token_db = token_db.write().unwrap();
    let value = token_db.insert(&req.tree, &req.key, &req.value);
    Ok(warp::reply::json(&ApiResponse {
        success: true,
        data: value,
        error: None,
    }))
}

#[derive(Debug, Deserialize)]
struct DbRemoveRequest {
    tree: String,
    key: String,
}

async fn handle_db_remove(
    req: DbRemoveRequest,
) -> Result<impl Reply, Rejection> {
    let token_db = TokenDB::instance();
    let token_db = token_db.write().unwrap();
    let value = token_db.remove(&req.tree, &req.key);
    Ok(warp::reply::json(&ApiResponse {
        success: true,
        data: value,
        error: None,
    }))
}

#[derive(Debug, Deserialize)]
struct DbScanRequest {
    tree: String,
    prefix: String,
}

async fn handle_db_scan_prefix(
    req: DbScanRequest,
) -> Result<impl Reply, Rejection> {
    let token_db = TokenDB::instance();
    let token_db = token_db.write().unwrap();
    let value = token_db.scan_prefix(&req.tree, &req.prefix);
    Ok(warp::reply::json(&ApiResponse {
        success: true,
        data: value,
        error: None,
    }))
}
