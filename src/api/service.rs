use warp::{Filter, Rejection, Reply};
use std::sync::{Arc, Mutex, LazyLock};
use std::net::Ipv4Addr;
use serde::{Deserialize, Serialize};
use serde::de::DeserializeOwned;
use serde_json::{json, Value};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use tracing::{debug, info, error};
use bytes::Bytes;
use tokio::task::JoinHandle;


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
use crate::api::{ApiResponse, P2pStatus};


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
                    return port
                }
            }
            Err(_) => { }
        }
    } 
    std::fs::remove_file(&port_file_path).unwrap();
    return 0;
}


// 自定义错误类型，用于序列化/反序列化错误
#[derive(Debug)]
struct InvalidSerializationError;

impl warp::reject::Reject for InvalidSerializationError {}


pub fn get_api_host() -> String {
    let port = *API_PORT.lock().unwrap(); 
    return format!("http://127.0.0.1:{}/api", port);
}

pub fn is_self_service() -> bool {
    let port = *API_PORT.lock().unwrap(); 
    let server_handle = SERVER_HANDLE.lock().unwrap();
    port == 0 || server_handle.is_some()
}

pub fn start_rest_server() {
    let address = Ipv4Addr::LOCALHOST;
    let mut port = *API_PORT.lock().unwrap();
    if port != 0 {
        println!("{} [SimpAI] REST service is already running at: http://{}:{}", token_utils::now_string(), address, port);
        return;
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

        let p2p_status = warp::path!("api" / "p2p_status")
        .and(warp::get())
        .and_then(handle_p2p_status);

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

        let routes = check_sys
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
            .or(p2p_status)
            .or(db_get)
            .or(db_insert)
            .or(db_remove)
            .or(db_scan_prefix)
            ;

        warp::serve(routes).run((address, port)).await;

        println!("{} [SimpAI] REST server at http://{}:{} has shut down.", 
                 token_utils::now_string(), address, port);
        *API_PORT.lock().unwrap() = 0;
        let port_file_path = token_utils::get_path_in_sys_key_dir("local.port");
        if let Err(e) = std::fs::remove_file(&port_file_path) {
            eprintln!("{} [SimpAI] INFO: Could not remove port file {}: {}", 
                      token_utils::now_string(), port_file_path.display(), e);
        }
        if let Ok(mut server_handle) = SERVER_HANDLE.try_lock() {
            *server_handle = None;
        }
    });
    *SERVER_HANDLE.lock().unwrap() = Some(server);
    let port_file_path = token_utils::get_path_in_sys_key_dir("local.port");
    if let Err(e) = std::fs::write(&port_file_path, port.to_string()) {
        eprintln!("{} [SimpAI] ERROR: Failed to write port {} to {}: {}. Server will run, but other instances might not find it via file.", 
                    token_utils::now_string(), port, port_file_path.display(), e);
    }
    *API_PORT.lock().unwrap() = port;
    println!("{} [SimpAI] REST server started at: http://{}:{}", token_utils::now_string(), address, port);


}

pub fn stop_rest_server() {
    let mut server_handle = SERVER_HANDLE.lock().unwrap();
    if let Some(handle) = server_handle.take() {
        println!("{} [SimpAI] 正在停止REST服务器...", token_utils::now_string());
        // 中止任务
        handle.abort();
        
        // 可选：等待任务完成（在某些情况下可能需要）
        TOKIO_RUNTIME.block_on(async {
            match handle.await {
                Ok(_) => println!("{} [SimpAI] REST服务器已正常停止", token_utils::now_string()),
                Err(e) if e.is_cancelled() => println!("{} [SimpAI] REST服务器已被中止", token_utils::now_string()),
                Err(e) => eprintln!("{} [SimpAI] 停止REST服务器时发生错误: {}", token_utils::now_string(), e),
            }
        });
        
        // 清理端口文件
        let port_file_path = token_utils::get_path_in_sys_key_dir("local.port");
        if port_file_path.exists() {
            if let Err(e) = std::fs::remove_file(&port_file_path) {
                eprintln!("{} [SimpAI] 无法删除端口文件 {}: {}", 
                          token_utils::now_string(), port_file_path.display(), e);
            }
        }
        
        // 重置端口
        *API_PORT.lock().unwrap() = 0;
    } else {
        println!("{} [SimpAI] REST服务器未运行", token_utils::now_string());
    }
}


// --- 具体路由处理函数 ---
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
    let p2p = p2p::get_instance().await;
    if let Some(p2p) = p2p {
        let res = p2p.request_task(target_did, body, &mode).await;
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

async fn handle_p2p_status() -> Result<impl Reply, Rejection> {
    let p2p = p2p::get_instance().await;
    if let Some(p2p) = p2p {
        let res = p2p.get_node_status().await;
        let p2p_status = P2pStatus {
            node_id: res.local_peer_id.clone(),
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
            error: Some("P2P not initialized".to_string()),
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
