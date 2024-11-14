use base58::ToBase58;


use pyo3::prelude::*;
use crate::token::SimpleAI;
use crate::claims::{GlobalClaims, IdClaim, UserContext};
use crate::systeminfo::SystemInfo;
use crate::params_mapper::ComfyTaskParams;
use crate::token_utils::calc_sha256;

mod claims;
mod env_utils;
mod token_utils;
mod error;
mod rathole;
mod token;
mod systeminfo;
mod env_data;
mod params_mapper;


#[pyfunction]
fn init_local(nickname: String) -> PyResult<SimpleAI> {
    let token = SimpleAI::new(nickname);
    //let _ = token.start_base_services();
    Ok(token)
}

#[pyfunction]
fn cert_verify_by_did(cert_str: &str, did: &str) -> bool {
    // issuer_did, for_did, item, encrypt_item_key, memo_base64, timestamp
    let parts: Vec<&str> = cert_str.split('|').collect();
    if parts.len() != 4 {
        return false;
    }
    let encrypt_item_key = parts[0].to_string();
    let memo_base64 = parts[1].to_string();
    let timestamp = parts[2].to_string();
    let signature_str = parts[3].to_string();
    let text = format!("{}|{}|{}|{}|{}|{}", token_utils::TOKEN_TM_DID, did, "Member", encrypt_item_key, memo_base64, timestamp);
    let claim = GlobalClaims::load_claim_from_local(token_utils::TOKEN_TM_DID);
    token_utils::verify_signature(&text, &signature_str, &claim.get_cert_verify_key())
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
fn check_entry_point(entry_point: String) -> bool {
    token_utils::check_entry_point_of_service(&entry_point)
}


#[pymodule]
fn simpleai_base(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(init_local, m)?)?;
    m.add_function(wrap_pyfunction!(cert_verify_by_did, m)?)?;
    m.add_function(wrap_pyfunction!(gen_entry_point_id, m)?)?;
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
