use std::fmt;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use base58::*;
use sha2::Digest;
use ripemd::Ripemd160;
use serde_derive::{Serialize, Deserialize};
use crate::env_utils;
use crate::gpureport::AdapterReport;
use pyo3::prelude::*;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[pyclass]
pub struct IdClaim {
    pub nickname: String,
    pub verify_key: [u8; 32],
    pub fingerprint: String,
    pub telephone_hash: String,
    pub id_card_hash: String,
    pub face_image_hash: String,
    pub file_hash_hash: String,
    pub crypt_key: [u8; 32],
}

#[pymethods]
impl IdClaim {
    #[new]
    pub fn new(nickname: String, verify_key: [u8; 32], telephone_hash: [u8; 32], id_card_hash: [u8; 32], face_image_hash: [u8; 32], file_hash_hash: [u8; 32]) -> Self{
        let telephone_base64 = URL_SAFE_NO_PAD.encode(telephone_hash);
        let id_card_base64 = URL_SAFE_NO_PAD.encode(id_card_hash);
        let face_image_base64 = URL_SAFE_NO_PAD.encode(face_image_hash);
        let file_hash_base64 = URL_SAFE_NO_PAD.encode(file_hash_hash);
        let fingerprint_str = format!("telephone:{},id_card:{},face_image:{},file_hash:{}",
                                      telephone_base64, id_card_base64, face_image_base64, file_hash_base64);
        let fingerprint_hash = env_utils::calc_sha256(&fingerprint_str.as_bytes());
        Self{
            nickname,
            verify_key: verify_key,
            fingerprint: URL_SAFE_NO_PAD.encode(fingerprint_hash),
            telephone_hash: telephone_base64,
            id_card_hash: id_card_base64,
            face_image_hash: face_image_base64,
            file_hash_hash: file_hash_base64,
            crypt_key: [0; 32],
        }
    }

    pub fn gen_did(&self) -> String {
        let verify_key_base64 = URL_SAFE_NO_PAD.encode(self.verify_key);
        let did_claim_str = format!("nickname:{},verify_key:{},fingerprint:{}",
                                    self.nickname, verify_key_base64, self.fingerprint);
        let mut hasher = Ripemd160::new();
        hasher.update(env_utils::calc_sha256(&did_claim_str.as_bytes()));
        let did = hasher.finalize();
        did.to_base58()
    }

    pub fn set_crypt_key(&mut self, crypt_key: [u8; 32]) {
        self.crypt_key = crypt_key;
    }

    //pub fn from_json(json_str: String) -> Self {
    //    serde_json::from_str(&json_str).unwrap_or(IdClaim::default())
    //}

    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or("Unknown".to_string())
    }

}


impl fmt::Display for IdClaim {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "IdClaim{{ nickname: {:?}, did: {:?} }}",
            self.nickname,
            self.gen_did()
        )
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[pyclass]
pub struct SystemInfo {
    pub sys_name: String,
    pub local_ip: String,
    pub local_port: u16,
    pub public_ip: String,
    pub mac_address: String,
    pub local_ip_out: String,
    pub public_ip_out: String,
    pub current_dir: String,
    pub current_exe: String,
    pub host_name: String,
    pub distribution_id: String,
    pub cpu_brand: String,
    pub cpu_cores: usize,
    pub cpu_frequency: u64,
    pub total_memory: u64,
    pub gpu_devices: Vec<AdapterReport>,
}
#[pymethods]
impl SystemInfo {
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or("Unknown".to_string())
    }
}

pub struct FileToken {
    pub muid: Vec<u8>,
    pub did: Vec<u8>,
    pub key: Vec<u8>,
    pub expiry: u64,
    pub sig: Vec<u8>,
}
