use std::sync::{Arc, Mutex};
use rand::Rng;
use base58::ToBase58;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use tracing::{debug, info, error};

use crate::token::SimpleAI;
use crate::dids::claims::{LocalClaims, IdClaim, UserContext};
use crate::utils::systeminfo::SystemInfo;
use crate::utils::params_mapper::ComfyTaskParams;
use crate::dids::token_utils::calc_sha256;
use crate::dids::{token_utils, TOKIO_RUNTIME, REQWEST_CLIENT, TOKEN_ENTRYPOINT_DID};


use pyo3::prelude::*;

mod token;
mod dids;
mod utils;
mod user;
mod p2p;
mod api;



#[pyfunction]
fn init_local() -> PyResult<SimpleAI> {
    let token = SimpleAI::new();
    Ok(token)
}

#[pyfunction]
fn cert_verify_by_did(cert_str: &str, did: &str) -> bool {
    // issuer_did, for_did, item, encrypt_item_key, memo_base64, timestamp
    if !IdClaim::validity(did) {
        return false;
    }
    let parts: Vec<&str> = cert_str.split('|').collect();
    if parts.len() != 4 {
        return false;
    }
    let encrypt_item_key = parts[0].to_string();
    let memo_base64 = parts[1].to_string();
    let timestamp = parts[2].to_string();
    let signature_str = parts[3].to_string();
    let text = format!("{}|{}|{}|{}|{}", did, "Member", encrypt_item_key, memo_base64, timestamp);
    
    let (system_did, upstream_did) = TOKIO_RUNTIME.block_on(async {
        let sys_fut = api::request_api("sys_did", None::<&serde_json::Value>);
        let up_fut = api::request_api("upstream_did", None::<&serde_json::Value>);
        match tokio::join!(sys_fut, up_fut) {
            (Ok(sys), Ok(up)) => (sys, up),
            _ =>  ("".to_string(), "".to_string()), 
        }
    });
    if !system_did.is_empty() {
        let text_system = format!("{}|{}", system_did, text);
        let claim_system = LocalClaims::load_claim_from_local(&system_did);
        println!("{} cert verify by sys_did:{}, sys_claim_cert_verify_key={}", did, system_did, URL_SAFE_NO_PAD.encode(claim_system.get_cert_verify_key()));
        println!("text_system:{}, signature_str={}", text_system, signature_str);
        if token_utils::verify_signature(&text_system, &signature_str, &claim_system.get_cert_verify_key()) {
            return true;
        }
    }
    
    if !upstream_did.is_empty() {
        let text_upstream = format!("{}|{}", upstream_did, text);
        let claim_upstream = LocalClaims::load_claim_from_local(&upstream_did);
        println!("{} cert verify by upstream did {}, is_default={}", did, upstream_did, claim_upstream.is_default());
        if token_utils::verify_signature(&text_upstream, &signature_str, &claim_upstream.get_cert_verify_key()) {
            return true;
        }
    }
    let root_did = TOKEN_ENTRYPOINT_DID;
    let text_root = format!("{}|{}", root_did, text);
    let claim_root = LocalClaims::load_claim_from_local(root_did);
    println!("{} cert verify by root did {}, is_default={}", did, root_did, claim_root.is_default());
    token_utils::verify_signature(&text_root, &signature_str, &claim_root.get_cert_verify_key())
}

#[pyfunction]
fn is_registered_did(did: &str) -> bool {
    if !IdClaim::validity(did) {
        return false;
    }
    api::request_api_sync(&format!("is_registered/{did}"), None::<&serde_json::Value>)
                .unwrap_or_else(|e| {
                    error!("is_registered_did({}) error: {}", did, e);
                    false
                })
}


#[pyfunction]
fn export_identity_qrcode_svg(user_did: &str) -> String {
    SimpleAI::export_user_qrcode_svg(user_did)
}

#[pyfunction]
fn import_identity_qrcode(encrypted_identity: &str) -> (String, String, String) {
    SimpleAI::import_identity_qrcode(encrypted_identity)
}

#[pyfunction]
fn gen_task_id() -> String {
    let mut rng = rand::thread_rng();
    let mut bytes = [0u8; 7];
    rng.fill(&mut bytes);
    bytes.to_base58()
}


#[pyfunction]
fn gen_entry_point_id(pid: u32) -> String {
    calc_sha256(pid.to_string().as_bytes()).to_base58()
}

#[pyfunction]
fn gen_ua_session(client_ip: &str, client_port: &str, ua_agent: &str) -> String {
    calc_sha256(format!("{}:{}:{}", client_ip, client_port, ua_agent).as_bytes()).to_base58()
}


#[pyfunction]
fn check_entry_point(entry_point: String) -> bool {
    token_utils::check_entry_point_of_service(&entry_point)
}

#[pyfunction]
fn validity_did(did: String) -> bool {
    IdClaim::validity(&did)
}

#[pymodule]
fn simpleai_base(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(init_local, m)?)?;
    m.add_function(wrap_pyfunction!(cert_verify_by_did, m)?)?;
    m.add_function(wrap_pyfunction!(gen_entry_point_id, m)?)?;
    m.add_function(wrap_pyfunction!(gen_ua_session, m)?)?;
    m.add_function(wrap_pyfunction!(check_entry_point, m)?)?;
    m.add_function(wrap_pyfunction!(validity_did, m)?)?;
    m.add_function(wrap_pyfunction!(is_registered_did, m)?)?;
    m.add_function(wrap_pyfunction!(export_identity_qrcode_svg, m)?)?;
    m.add_function(wrap_pyfunction!(import_identity_qrcode, m)?)?;
    m.add_function(wrap_pyfunction!(gen_task_id, m)?)?;
    m.add_class::<SimpleAI>()?;
    m.add_class::<IdClaim>()?;
    m.add_class::<UserContext>()?;
    m.add_class::<SystemInfo>()?;
    m.add_class::<ComfyTaskParams>()?;
    Ok(())
}

