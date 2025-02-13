use base58::ToBase58;


use pyo3::prelude::*;
use crate::token::SimpleAI;
use crate::claims::{GlobalClaims, IdClaim, UserContext};
use crate::systeminfo::SystemInfo;
use crate::params_mapper::ComfyTaskParams;
use crate::token_utils::calc_sha256;
use std::sync::{Arc, Mutex};

mod claims;
mod env_utils;
mod token_utils;
mod error;
mod token;
mod systeminfo;
mod env_data;
mod params_mapper;
mod cert_center;
mod rest_service;

#[pyfunction]
fn init_local(nickname: String) -> PyResult<SimpleAI> {
    let token = SimpleAI::new(nickname);
    let instance_arc = Arc::new(Mutex::new(token.clone()));
    let _rest_server = rest_service::start_rest_server(instance_arc.clone(), "0.0.0.0".to_string(), 8080);
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
    let claims = GlobalClaims::instance();
    let (system_did, upstream_did) = {
        let claims = claims.lock().unwrap();
        (claims.get_system_did(), claims.get_upstream_did())
    };
    let text_system = format!("{}|{}", system_did, text);
    let claim_system = GlobalClaims::load_claim_from_local(&system_did);
    if token_utils::verify_signature(&text_system, &signature_str, &claim_system.get_cert_verify_key()) {
        return true;
    }
    let text_upstream = format!("{}|{}", upstream_did, text);
    let claim_upstream = GlobalClaims::load_claim_from_local(&upstream_did);
    if token_utils::verify_signature(&text_upstream, &signature_str, &claim_upstream.get_cert_verify_key()) {
        return true;
    }
    let root_did = token_utils::TOKEN_TM_DID;
    let text_root = format!("{}|{}", root_did, text);
    let claim_root = GlobalClaims::load_claim_from_local(root_did);
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
