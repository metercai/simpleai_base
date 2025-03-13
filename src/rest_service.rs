use warp::{Filter, Rejection, Reply};
use std::sync::{Arc, Mutex};
use std::net::IpAddr;
use serde::{Deserialize, Serialize};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use tracing::error;

use crate::token::SimpleAI;
use crate::dids::{token_utils, TOKIO_RUNTIME, DidToken, REQWEST_CLIENT};
use crate::user::TokenUser;

// 共享状态类型
type SharedAI = Arc<Mutex<SimpleAI>>;

pub const API_HOST: &str = "http://127.0.0.1:4515/api";
    
// 统一响应格式
#[derive(Debug, Serialize, Deserialize)]
pub struct ApiResponse<T> {
    success: bool,
    pub data: T,
    error: Option<String>,
}

// 初始化所有路由
pub fn start_rest_server(simpai: SharedAI, address: String, port: u16) {
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
            .and(with_simpai(simpai.clone()))
            .and_then(handle_get_sys_did);

        let get_device_did = warp::path!("api" / "device_did")
            .and(warp::get())
            .and(with_simpai(simpai.clone()))
            .and_then(handle_get_device_did);

        let get_upstream_did = warp::path!("api" / "upstream_did")
            .and(warp::get())
            .and(with_simpai(simpai.clone()))
            .and_then(handle_get_upstream_did);

        let get_local_vars = warp::path!("api" / "local_vars")
            .and(warp::post())
            .and(warp::body::json())
            .and(with_simpai(simpai.clone()))
            .and_then(handle_get_local_vars);

        let get_claim = warp::path!("api" / "claim")
            .and(warp::post())
            .and(warp::body::json())
            .and(with_simpai(simpai.clone()))
            .and_then(handle_get_claim);

        let get_register_cert = warp::path!("api" / "register_cert")
            .and(warp::post())
            .and(warp::body::json())
            .and(with_simpai(simpai.clone()))
            .and_then(handle_get_register_cert);

        let is_registered = warp::path!("api" / "is_registered")
            .and(warp::post())
            .and(warp::body::json())
            .and(with_simpai(simpai.clone()))
            .and_then(handle_is_registered);

        let sign_by_did = warp::path!("api" / "sign_by_did")
            .and(warp::post())
            .and(warp::body::json())
            .and(with_simpai(simpai.clone()))
            .and_then(handle_sign_by_did);

        let verify_by_did = warp::path!("api" / "verify_by_did")
            .and(warp::post())
            .and(warp::body::json())
            .and(with_simpai(simpai.clone()))
            .and_then(handle_verify_by_did);

        let encrypt_for_did = warp::path!("api" / "encrypt_for_did")
            .and(warp::post())
            .and(warp::body::json())
            .and(with_simpai(simpai.clone()))
            .and_then(handle_encrypt_for_did);

        let decrypt_by_did = warp::path!("api" / "decrypt_by_did")
            .and(warp::post())
            .and(warp::body::json())
            .and(with_simpai(simpai.clone()))
            .and_then(handle_decrypt_by_did);

        let get_path_in_user_dir = warp::path!("api" / "path_in_user_dir")
            .and(warp::post())
            .and(warp::body::json())
            .and(with_simpai(simpai.clone()))
            .and_then(handle_get_path_in_user_dir);

        let put_global_message = warp::path!("api" / "put_global_message")
            .and(warp::post())
            .and(warp::body::json())
            .and(with_simpai(simpai.clone()))
            .and_then(handle_put_global_message);


        let routes = get_sys_did
            .or(get_device_did)
            .or(get_upstream_did)
            .or(get_local_vars)
            .or(get_claim)
            .or(get_register_cert)
            .or(is_registered)
            .or(sign_by_did)
            .or(verify_by_did)
            .or(encrypt_for_did)
            .or(decrypt_by_did)
            .or(get_path_in_user_dir)
            .or(put_global_message);

        warp::serve(routes).run((address, port)).await;
    });
    println!("{} [RestApi] REST server started at http://{}:{}", token_utils::now_string(), address, port);
}

// 辅助函数：共享状态注入
fn with_simpai(ai: SharedAI) -> impl Filter<Extract = (SharedAI,), Error = std::convert::Infallible> + Clone {
    warp::any().map(move || ai.clone())
}

// --- 具体路由处理函数 ---

// 1. 获取系统DID
async fn handle_get_sys_did(ai: SharedAI) -> Result<impl Reply, Rejection> {
    let ai = ai.lock().unwrap();
    Ok(warp::reply::json(&ApiResponse {
        success: true,
        data: ai.get_sys_did(),
        error: None,
    }))
}

async fn handle_get_device_did(ai: SharedAI) -> Result<impl Reply, Rejection> {
    let ai = ai.lock().unwrap();
    Ok(warp::reply::json(&ApiResponse {
        success: true,
        data: ai.get_device_did(),
        error: None,
    }))
}

async fn handle_get_upstream_did(ai: SharedAI) -> Result<impl Reply, Rejection> {
    let mut ai = ai.lock().unwrap();
    Ok(warp::reply::json(&ApiResponse {
        success: true,
        data: ai.get_upstream_did(),
        error: None,
    }))
}

// 2. 获取本地变量
#[derive(Debug, Deserialize)]
struct GetLocalVarsRequest {
    key: String,
    default: String,
    user_session: String,
    ua_hash: String,
}

async fn handle_get_local_vars(
    req: GetLocalVarsRequest,
    ai: SharedAI,
) -> Result<impl Reply, Rejection> {
    let mut ai = ai.lock().unwrap();
    let value = ai.get_local_vars(&req.key, &req.default, &req.user_session, &req.ua_hash);
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
    ai: SharedAI,
) -> Result<impl Reply, Rejection> {
    let didtoken = DidToken::instance();
    let mut ai = didtoken.lock().unwrap();
    let claim = ai.get_claim(&req.did);
    Ok(warp::reply::json(&ApiResponse {
        success: !claim.is_default(),
        data: claim.to_json_string(),
        error: if claim.is_default() { Some("Claim not found".into()) } else { None },
    }))
}

// 4. 获取注册证书
#[derive(Debug, Deserialize)]
struct GetRegisterCertRequest {
    user_did: String,
}

async fn handle_get_register_cert(
    req: GetRegisterCertRequest,
    ai: SharedAI,
) -> Result<impl Reply, Rejection> {
    let didtoken = DidToken::instance();
    let mut ai = didtoken.lock().unwrap();
    let cert = ai.get_register_cert(&req.user_did);
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
    ai: SharedAI,
) -> Result<impl Reply, Rejection> {
    let didtoken = DidToken::instance();
    let mut ai = didtoken.lock().unwrap();
    let is_registered = ai.is_registered(&req.user_did);
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
    ai: SharedAI,
) -> Result<impl Reply, Rejection> {
    let didtoken = DidToken::instance();
    let mut ai = didtoken.lock().unwrap();
    let signature = ai.sign_by_did(&req.text, &req.did, &req.phrase);
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
    ai: SharedAI,
) -> Result<impl Reply, Rejection> {
    let didtoken = DidToken::instance();
    let mut ai = didtoken.lock().unwrap();
    let is_valid = ai.verify_by_did(&req.text, &req.signature, &req.did);
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
    ai: SharedAI,
) -> Result<impl Reply, Rejection> {
    let didtoken = DidToken::instance();
    let mut ai = didtoken.lock().unwrap();
    let ctext = ai.encrypt_for_did(req.text.as_bytes(), &req.for_did, req.period);
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
    ai: SharedAI,
) -> Result<impl Reply, Rejection> {
    let didtoken = DidToken::instance();
    let mut ai = didtoken.lock().unwrap();
    let text = ai.decrypt_by_did(&req.ctext, &req.by_did, req.period);
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
    ai: SharedAI,
) -> Result<impl Reply, Rejection> {
    let tokenuser = TokenUser::instance();
    let ai = tokenuser.lock().unwrap();
    let path = ai.get_path_in_user_dir(&req.did, &req.catalog);
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
    ai: SharedAI,
) -> Result<impl Reply, Rejection> {
    let ai = ai.lock().unwrap();
    ai.put_global_message(&req.msg);
    Ok(warp::reply::json(&ApiResponse {
        success: true,
        data: "",
        error: None,
    }))
}

pub async fn request_api(endpoint: &str) -> Result<String, reqwest::Error> {
    let client = &REQWEST_CLIENT;
    let url = format!("{}/{}", API_HOST, endpoint);
    let res = client.get(&url).send().await?;
    let data: ApiResponse<String> = res.json().await?;
    Ok(data.data)
}