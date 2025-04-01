use warp::{Filter, Rejection, Reply};
use std::sync::{Arc, Mutex};
use std::net::IpAddr;
use serde::{Deserialize, Serialize};
use serde::de::DeserializeOwned;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use tracing::{debug, info, error};
use bytes::Bytes;


use crate::dids::{token_utils, TOKIO_RUNTIME, DidToken, REQWEST_CLIENT, REQWEST_CLIENT_SYNC};
use crate::dids::claims::{IdClaim, GlobalClaims};
use crate::dids::cert_center::GlobalCerts;
use crate::user::TokenUser;
use crate::user::shared;
use crate::user::user_vars::GlobalLocalVars;
use crate::p2p;


pub const API_HOST: &str = "http://127.0.0.1:4515/api";

// 自定义错误类型，用于序列化/反序列化错误
#[derive(Debug)]
struct InvalidSerializationError;

impl warp::reject::Reject for InvalidSerializationError {}

// 统一响应格式
#[derive(Debug, Serialize, Deserialize)]
pub struct ApiResponse<T> {
    success: bool,
    pub data: T,
    error: Option<String>,
}

// 初始化所有路由
pub fn start_rest_server(address: String, port: u16) {
    let address: IpAddr = match address.parse() {
        Ok(addr) => addr,
        Err(_) => {
            error!("Invalid address: {}", address);
            std::process::exit(1);
        }
    };

    let _server = TOKIO_RUNTIME.spawn(async move {
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

        let get_claim = warp::path!("api" / "get_claim")
            .and(warp::post())
            .and(warp::body::json())
            .and_then(handle_get_claim);

        let put_claim = warp::path!("api" / "put_claim")
            .and(warp::post())
            .and(warp::body::json())
            .and_then(handle_put_claim);

        let get_register_cert = warp::path!("api" / "register_cert")
            .and(warp::post())
            .and(warp::body::json())
            .and_then(handle_get_register_cert);

        let is_registered = warp::path!("api" / "is_registered")
            .and(warp::post())
            .and(warp::body::json())
            .and_then(handle_is_registered);

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
        
        let p2p_request = warp::path!("api" / "p2p_request")
        .and(warp::post())
        .and(warp::body::bytes())
        .and_then(handle_p2p_request);

        let p2p_response = warp::path!("api" / "p2p_response")
        .and(warp::post())
        .and(warp::body::bytes())
        .and_then(handle_p2p_response);


        let routes = get_sys_did
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
            ;

        warp::serve(routes).run((address, port)).await;
    });
    println!("{} [RestApi] REST server started at http://{}:{}", token_utils::now_string(), address, port);
}


// 创建一个自定义的CBOR请求体处理过滤器
fn body<T: DeserializeOwned + Send>() -> impl Filter<Extract = (T, ), Error = warp::Rejection> + Clone {
    warp::body::bytes().and_then(|body: Bytes| async move {
        match serde_cbor::from_slice(&body) {
            Ok(resp) => Ok(resp),
            Err(e) => {
                error!("Failed to deserialize CBOR body: {}", e);
                Err(warp::reject::custom(InvalidSerializationError))
            }
        }
    })
}



// --- 具体路由处理函数 ---

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
    let mut global_local_vars = global_local_vars.lock().unwrap();
    let value = global_local_vars.get_local_vars(&req.key, &req.default, &req.user_did);
    Ok(warp::reply::json(&ApiResponse {
        success: !value.is_empty(),
        data: value.clone(),
        error: if value.is_empty() { Some("Invalid params".into()) } else { None },
    }))
}

// 3. 获取身份声明
#[derive(Debug, Deserialize)]
struct GetClaimRequest {
    did: String,
}

async fn handle_get_claim(
    req: GetClaimRequest,
) -> Result<impl Reply, Rejection> {
    let claims = GlobalClaims::instance();
    let mut claim = {
        let mut claims = claims.lock().unwrap();
        claims.get_claim_from_local(&req.did)
    };
    
    if claim.is_default() {
        if let Some(p2p) = p2p::get_instance().await {
            debug!("ready to get claim from DHT networkDID: {}", req.did);
            let did_clone = req.did.clone();
            claim = p2p.get_claim_from_DHT(&did_clone).await;
            
            if claim.is_default() {
                debug!("ready to get claim from upstream with p2p channel，DID: {}", did_clone);
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
#[derive(Debug, Deserialize)]
struct IsRegisteredRequest {
    user_did: String,
}

async fn handle_is_registered(
    req: IsRegisteredRequest,
) -> Result<impl Reply, Rejection> {
    let didtoken = DidToken::instance();
    let mut didtoken = didtoken.lock().unwrap();
    let is_registered = didtoken.is_registered(&req.user_did);
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
    body: Bytes,
) -> Result<impl Reply, Rejection> {
    let p2p = p2p::get_instance().await;
    if let Some(p2p) = p2p {
        let res = p2p.request_task(body).await;
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

#[derive(Debug, Serialize, Deserialize)]
struct P2pResponse {
    target_did: String,
    task_id: String,
    task_method: String,
    task_result: Vec<u8>,
}
async fn handle_p2p_response(
    body: Bytes,
) -> Result<impl Reply, Rejection> {
    let p2p = p2p::get_instance().await;
    if let Some(p2p) = p2p {
        let res = p2p.response_task(body).await;
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

pub async fn request_api<T: Serialize>(endpoint: &str, params: Option<T>) -> Result<String, reqwest::Error> {
    let url = format!("{}/{}", API_HOST, endpoint);

    if let Some(json_params) = params {
        let res = REQWEST_CLIENT.post(&url).json(&json_params).send().await?;
        let data: ApiResponse<String> = res.json().await?;
        Ok(data.data)
    } else {
        Ok("Unknown".to_string())
    }

}

pub fn request_api_sync<T: Serialize>(endpoint: &str, params: Option<T>) -> Result<String, Box<dyn std::error::Error>> {
    let url = format!("{}/{}", API_HOST, endpoint);

    if let Some(json_params) = params {
        let res = REQWEST_CLIENT_SYNC.post(&url).json(&json_params).send()?;
        let data: ApiResponse<String> = res.json()?;
        Ok(data.data)
    } else {
        Ok("Unknown".to_string())
    }
}

pub async fn request_api_cbor<T: Serialize>(endpoint: &str, params: Option<T>) -> Result<String, Box<dyn std::error::Error>> {
    let url = format!("{}/{}", API_HOST, endpoint);
    
    if let Some(cbor_params) = params {
        let cbor_data = serde_cbor::to_vec(&cbor_params)
            .map_err(|e| {
                error!("Failed to serialize CBOR params: {}", e);
                e
            })?;
        let res = REQWEST_CLIENT
            .post(&url)
            .header("Content-Type", "application/cbor")
            .body(cbor_data)
            .send()
            .await?;
        let data: ApiResponse<String> = res.json().await?;
        Ok(data.data)
    } else {
        Ok("Unknown".to_string())
    }
}


pub fn request_api_cbor_sync<T: Serialize>(endpoint: &str, params: Option<T>) -> Result<String, Box<dyn std::error::Error>> {
    let url = format!("{}/{}", API_HOST, endpoint);

    if let Some(cbor_params) = params {
        let cbor_data = serde_cbor::to_vec(&cbor_params)?;
        let res = REQWEST_CLIENT_SYNC
            .post(&url)
            .header("Content-Type", "application/cbor")
            .body(cbor_data)
            .send()?;
        let data: ApiResponse<String> = res.json()?;
        Ok(data.data)
    } else {
        Ok("Unknown".to_string())
    }
}

