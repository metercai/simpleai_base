use base58::ToBase58;
use std::sync::{Arc, Mutex};

use pyo3::prelude::*;
use crate::token::SimpleAI;
use crate::dids::claims::{LocalClaims, IdClaim, UserContext};
use crate::utils::systeminfo::SystemInfo;
use crate::utils::params_mapper::ComfyTaskParams;
use crate::dids::token_utils::calc_sha256;
use crate::dids::{token_utils, TOKIO_RUNTIME, REQWEST_CLIENT, TOKEN_TM_DID};
use crate::rest_service::{ApiResponse, API_HOST};

mod token;

mod rest_service;

mod p2p;
mod dids;
mod utils;
mod user;
mod shared;

#[pyfunction]
fn init_local(nickname: String) -> PyResult<SimpleAI> {
    let token = SimpleAI::new(nickname);
    let instance_arc = Arc::new(Mutex::new(token.clone()));
    let _rest_server = rest_service::start_rest_server(instance_arc.clone(), "127.0.0.1".to_string(), 4515);
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
        let sys_fut = rest_service::request_api("sys_did", None::<&serde_json::Value>);
        let up_fut = rest_service::request_api("upstream_did", None::<&serde_json::Value>);
        match tokio::join!(sys_fut, up_fut) {
            (Ok(sys), Ok(up)) => (sys, up),
            _ =>  ("".to_string(), "".to_string()), 
        }
    });
    if !system_did.is_empty() {
        let text_system = format!("{}|{}", system_did, text);
        let claim_system = LocalClaims::load_claim_from_local(&system_did);
        println!("{} cert verify by sys_did:{}, is_default={}", did, system_did, claim_system.is_default());
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
    let root_did = TOKEN_TM_DID;
    let text_root = format!("{}|{}", root_did, text);
    let claim_root = LocalClaims::load_claim_from_local(root_did);
    println!("{} cert verify by root did {}, is_default={}", did, root_did, claim_root.is_default());
    token_utils::verify_signature(&text_root, &signature_str, &claim_root.get_cert_verify_key())
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


#[pymodule]
fn simpleai_base(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(init_local, m)?)?;
    m.add_function(wrap_pyfunction!(cert_verify_by_did, m)?)?;
    m.add_function(wrap_pyfunction!(gen_entry_point_id, m)?)?;
    m.add_function(wrap_pyfunction!(gen_ua_session, m)?)?;
    m.add_function(wrap_pyfunction!(check_entry_point, m)?)?;
    m.add_function(wrap_pyfunction!(export_identity_qrcode_svg, m)?)?;
    m.add_function(wrap_pyfunction!(import_identity_qrcode, m)?)?;
    m.add_class::<SimpleAI>()?;
    m.add_class::<IdClaim>()?;
    m.add_class::<UserContext>()?;
    m.add_class::<SystemInfo>()?;
    m.add_class::<ComfyTaskParams>()?;
    Ok(())
}

