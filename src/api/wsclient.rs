use std::{
    time::Duration,
    collections::HashMap,
    sync::{Arc, Mutex, LazyLock},
};
use futures::stream::SplitSink;
use tokio::sync::watch;
use tokio_tungstenite::{
    connect_async,
    tungstenite::{protocol::{frame::coding::CloseCode, CloseFrame}, Message},
    WebSocketStream,
};
use futures_util::{StreamExt, SinkExt};
use serde_cbor;

use backoff::{ExponentialBackoff, backoff::Backoff};

type WsError = Box<dyn std::error::Error + Send + Sync>;
type Result<T> = std::result::Result<T, WsError>;


use tracing::{debug, info,warn, error};

use pyo3::prelude::*;
use pyo3::types::PyModule;

use crate::{api::service::{get_ws_host, WsMessage}, utils::error::TokenError};
use crate::p2p::P2pRequest;
use crate::dids::claims::IdClaim;
use crate::dids::TOKIO_RUNTIME;
use crate::user::shared;



pub static WS_CLIENT: LazyLock<Arc<WsClient>> = LazyLock::new(|| {
    let ws_url = get_ws_host();
    Arc::new(WsClient::new(ws_url))
});

// WebSocket 客户端控制句柄
pub struct WsClient {
    ws_url: String,
    shutdown_sender: watch::Sender<()>,
    client_task: Arc<Mutex<Option<tokio::task::JoinHandle<()>>>>,
}

impl Clone for WsClient {
    fn clone(&self) -> Self {
        Self {
            ws_url: self.ws_url.clone(),
            shutdown_sender: self.shutdown_sender.clone(),
            client_task: Arc::clone(&self.client_task),
        }
    }
}

impl WsClient {
    pub fn new(ws_url: String) -> Self {
        let (shutdown_sender, _) = watch::channel(());

        Self {
            ws_url,
            shutdown_sender,
            client_task: Arc::new(Mutex::new(None)),
        }
    }

    pub fn start(self: Arc<Self>) {
        let mut task_guard = self.client_task.lock().unwrap();
        if task_guard.is_some() {
            info!("WebSocket client is already running.");
            return;
        }
        
        let this = self.clone();
        let handle = TOKIO_RUNTIME.spawn(async move {
            this.run().await;
        });

        *task_guard = Some(handle);
    }

    async fn run(self: Arc<Self>) {
        loop {
            let mut backoff = ExponentialBackoff::default();
            let mut receiver = self.shutdown_sender.subscribe();
        
            match self.clone().connect_and_run().await {
                Ok(_) => {
                    println!("Connection closed normally");
                }
                Err(e) => {
                    error!("Connection failed: {:?}", e);
                    if let Some(delay) = backoff.next_backoff() {
                        tokio::select! {
                            _ = tokio::time::sleep(delay) => {}
                            _ = receiver.changed() => {
                                println!("Shutdown signaled during backoff");
                                break;
                            }
                        }
                    }
                }
            }

            if receiver.has_changed().unwrap_or(false) {
                println!("Shutdown signaled during connection");
                break;
            }
        }
    }

    async fn connect_and_run(self: Arc<Self>) -> Result<()> {
        println!("Connecting to WebSocket server at {}", self.ws_url);
        let (mut ws_stream, _) = connect_async(&self.ws_url).await?;
        let (mut write_ws, mut read_ws) = ws_stream.split();
        let mut receiver = self.shutdown_sender.subscribe();
        

        let mut authenticated = false;
        let mut ping_interval = tokio::time::interval(Duration::from_secs(30));
        
        let shared_data = shared::get_shared_data();
        let client_did = shared_data.sys_did();
        let client_name = shared_data.sys_name();
        let auth_msg = WsMessage::Auth { client_did, client_name };

        let mut last_pong = tokio::time::Instant::now();
        let pong_timeout = Duration::from_secs(10);

        loop {
            tokio::select! {
                // 消息接收处理
                msg = read_ws.next()  => {
                    match msg {
                        Some(Ok(Message::Binary(data))) => {
                            // 直接处理二进制消息
                            let msg: WsMessage = serde_cbor::from_slice(&data)?;
                            debug!("Received message: {:?}", msg);
                            match msg {
                                WsMessage::DirectTask { id, body } => {
                                    let response = handle_direct_task(id, &body).await;
                                    let res = serde_cbor::to_vec(&response)?;
                                    write_ws.send(Message::Binary(res.into())).await?;
                                }
                                _ => {}
                            }
                        }
                        Some(Ok(Message::Text(text))) => {
                            debug!("Received text message: {}", text);
                        }
                        Some(Ok(Message::Close(close_frame))) => {
                            println!("Received close frame: {:?}", close_frame);
                            // 构建响应关闭帧
                            let response_frame = match close_frame {
                                Some(frame) => Message::Close(Some(frame)),
                                None => Message::Close(Some(CloseFrame {
                                    code: CloseCode::Normal,
                                    reason: "".into(),
                                })),
                            };

                            // 发送响应关闭帧
                            if let Err(e) = write_ws.send(response_frame).await {
                                tracing::error!("发送关闭帧失败: {:?}", e);
                            }
                            break;
                        }
                        Some(Ok(Message::Ping(_))) => {
                            write_ws.send(Message::Pong(vec![1, 2, 3].into())).await?;
                        }
                        Some(Ok(Message::Pong(_))) => {
                            println!("Received Pong");
                            last_pong = tokio::time::Instant::now();
                        }
                        Some(Err(e)) => return Err(e.into()),
                        None => {
                            println!("WebSocket connection closed");
                            return Ok(());
                        }
                        _ => {
                            println!("Unhandled message type received");
                        }
                    }
                },

                // 认证处理
                _ = async {
                    if !authenticated {
                        write_ws.send(Message::Binary(
                            serde_cbor::to_vec(&auth_msg)
                                .map_err(|e| TokenError::CborParseError(e))?.into()
                        )).await
                        .map_err(|e| TokenError::TungsteniteError(e))?;
                        authenticated = true;
                        println!("Sent auth message ok");
                        Ok::<_, TokenError>(())
                    } else {
                        Ok::<_, TokenError>(())
                    }
                } => {},

                // 心跳发送
                _ = ping_interval.tick() => {
                    println!("Sending Ping");
                    write_ws.send(Message::Ping(vec![1, 2, 3].into())).await?;
                },

                // 关闭信号处理
                _ =  receiver.changed() => {
                    println!("Shutdown signaled, wsclient exiting...");
                    // 发送关闭帧
                    let close_frame = CloseFrame {
                        code: CloseCode::Normal,
                        reason: "Shutting down".into(),
                    };
                    write_ws.send(Message::Close(Some(close_frame))).await?;
                    write_ws.close().await?;
                    return Ok(());
                }
                
            }

            // 检查是否超时未收到 Pong
            if tokio::time::Instant::now().duration_since(last_pong) > pong_timeout {
                println!("No Pong received, reconnecting...");
                break;
            }
        }

        Ok(())
    }


    pub fn stop(self: Arc<Self>) {
        info!("Stopping WebSocket client...");
        let _ = self.shutdown_sender.send(());

        let mut task_guard = self.client_task.lock().unwrap();
        if let Some(handle) = task_guard.take() {
            handle.abort();
        }
    }

    pub fn is_running(&self) -> bool {
        let task_guard = self.client_task.lock().unwrap();
        task_guard.is_some()
    }
}

async fn handle_direct_task(id: String, task_body: &[u8]) -> WsMessage {

    let shared_data = shared::get_shared_data();
    let sys_did = shared_data.sys_did();
    let node_did = shared_data.node_did();

    match serde_cbor::from_slice::<P2pRequest>(task_body) {
        Ok(req) => {
            let target_did = if req.target_did.is_empty() {
                req.task_id.split_once('@').map(|(_, after)| after).unwrap_or(&req.task_id).to_string()
            } else {
                req.target_did.clone()
            };
            let target_node = target_did.split_once('.').map(|(_, after)| after).unwrap_or(&target_did).to_string();
            let target_sys = target_did.split_once('.').map(|(before, _)| before).unwrap_or(&target_did).to_string();
            if !IdClaim::validity(&target_node) || target_node != node_did || target_sys != sys_did {
                tracing::warn!("node did error: not valid or not match self node ");
                return WsMessage::Response {
                    id: id,
                    result: format!("node did error: not valid or not match self node: {}", target_did),
                };
            }
            tracing::debug!("📣 <<<< Inbound REQUEST: method={}, task_id={}, task_method={}", req.method, req.task_id, req.task_method);    
            match req.method.as_str() {
                "remote_process" => {
                    let response = {
                        let results = Python::with_gil(|py| -> PyResult<String> {
                            let p2p_task = PyModule::import_bound(py, "simpleai_base.p2p_task")
                                .expect("No simpleai_base.p2p_task.");
                            let py_bytes = pyo3::types::PyBytes::new_bound(py, &req.task_args);
                            let result: String = p2p_task
                                .getattr("call_request_by_p2p_task")?
                                .call1((
                                    req.task_id,
                                    req.task_method.clone(),
                                    py_bytes,
                                ))?
                                .extract()?;
                            Ok(result)
                        });
                        results.unwrap_or_else(|e| {
                            tracing::error!("call_request {} fail: {:?}", req.task_method, e);
                            "error in call_response".to_string()
                        })
                    };
                    
                    WsMessage::Response {
                        id: id,
                        result: response,
                    }
                }
                "async_response" => {
                    let response = {
                        let results = Python::with_gil(|py| -> PyResult<String> {
                            let p2p_task = PyModule::import_bound(py, "simpleai_base.p2p_task")
                                .expect("No simpleai_base.p2p_task.");
                            // 将Vec<u8>转换为Python的bytes对象
                            let py_bytes = pyo3::types::PyBytes::new_bound(py, &req.task_args);
                            let result: String = p2p_task
                                .getattr("call_response_by_p2p_task")?
                                .call1((
                                    req.task_id,
                                    req.task_method.clone(),
                                    py_bytes,
                                ))?
                                .extract()?;
                            Ok(result)
                        });
                        results.unwrap_or_else(|e| {
                            tracing::error!("call_response {} fail: {:?}", req.task_method, e);
                            "error in call_response".to_string()
                        })    
                    };
                    WsMessage::Response {
                        id: id,
                        result: response,
                    }
                }
                _ => {
                    error!("Unknown method: {}", req.method);
                    WsMessage::Response {
                        id: id,
                        result: format!("Unknown method: {}", req.method),
                    }
                }
            }
        }
        Err(e) => {
            error!("Failed to decode P2pRequest: {}", e);
            WsMessage::Response {
                id: id,
                result: format!("Invalid P2pRequest: {}", e),
            }
        }
    }
}