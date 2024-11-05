use std::path::Path;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use base58::{ToBase58, FromBase58};


use pyo3::prelude::*;
use crate::token::SimpleAI;
use crate::claims::{IdClaim, UserContext};
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
fn sha256_base64(input: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(env_utils::calc_sha256(input))
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
    m.add_function(wrap_pyfunction!(sha256_base64, m)?)?;
    m.add_function(wrap_pyfunction!(gen_entry_point_id, m)?)?;
    m.add_function(wrap_pyfunction!(check_entry_point, m)?)?;
    m.add_class::<SimpleAI>()?;
    m.add_class::<IdClaim>()?;
    m.add_class::<UserContext>()?;
    m.add_class::<SystemInfo>()?;
    m.add_class::<ComfyTaskParams>()?;
    Ok(())
}
