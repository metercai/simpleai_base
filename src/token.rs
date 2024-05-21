use std::collections::HashMap;
use x25519_dalek::PublicKey;
use ed25519_dalek::{VerifyingKey, Verifier, Signature};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use std::thread;
use std::fs;
use std::time::Duration;

use crate::claim::IdClaim;
use crate::rathole::Rathole;
use crate::env_utils;
use crate::systeminfo::SystemInfo;
use pyo3::prelude::*;
use crate::error::TokenError;

#[derive(Clone, Debug)]
#[pyclass]
pub struct SimpleAI {
    pub nickname: String,
    pub did: String,
    pub sysinfo: SystemInfo,
    claims: HashMap<String, IdClaim>,
    crypt_secret: [u8; 32],
}

#[pymethods]
impl SimpleAI {
    #[new]
    pub fn new(
        nickname: String,
    ) -> Self {
        let sysinfo = env_utils::SYSTEM_INFO.clone();
        let mac_address_hash = env_utils::calc_sha256(format!("{}-{}", nickname, sysinfo.mac_address).as_bytes());
        let telephone_hash = env_utils::calc_sha256(format!("{}-telephone:-", nickname).as_bytes());
        let face_image_hash = env_utils::calc_sha256(format!("{}-face_image:-", nickname).as_bytes());
        let file_hash_hash = env_utils::calc_sha256(format!("{}-file_hash:-", nickname).as_bytes());

        let zeroed_key: [u8; 32] = [0; 32];
        let verify_key = env_utils::get_verify_key().unwrap_or_else(|_| zeroed_key);
        let mut local_claim = IdClaim::new(nickname.clone(), verify_key, telephone_hash, mac_address_hash, face_image_hash, file_hash_hash);

        let did = local_claim.gen_did();
        let crypt_secret = env_utils::get_secret_key(&did).unwrap_or_else(|_| zeroed_key);
        let crypt_key = env_utils::get_crypt_key(crypt_secret).unwrap_or_else(|_| zeroed_key);
        local_claim.set_crypt_key(crypt_key);

        let filename = format!(".user_{}.did", did);
        fs::write(filename, local_claim.to_json()).unwrap();
        let mut claims = HashMap::new();
        claims.insert(did.clone(), local_claim);

        Self {
            nickname,
            did,
            sysinfo,
            claims,
            crypt_secret,
        }
    }

    pub fn start_base_services(&self) -> Result<(), TokenError> {
        let config = "client.toml";
        let did = self.did.clone();
        let sysinfo = self.sysinfo.clone();
        let _rt_handle = thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .unwrap();

            runtime.block_on(async {
                //let _ = Rathole::new(&config).start_service().await;
                let loginfo = format!(
                    "{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
                    did, sysinfo.os_type, sysinfo.os_name, sysinfo.cpu_arch,
                    sysinfo.ram_total/1024, sysinfo.gpu_brand, sysinfo.gpu_name,
                    sysinfo.gpu_memory/1024, sysinfo.location, sysinfo.disk_total/1024,
                    sysinfo.disk_uuid, sysinfo.exe_name, sysinfo.pyhash, sysinfo.uihash);
                let shared_key = b"Simple_114.124";
                let ctext = URL_SAFE_NO_PAD.encode(env_utils::encrypt(loginfo.as_bytes(), shared_key));
                println!("loginfo: {}\nctext: {}", loginfo, ctext);
                match tokio::time::timeout(Duration::from_secs(3), env_utils::logging_launch_info(&ctext)).await {
                    Ok(_) => {},
                    Err(e) => {
                        tracing::info!("start_base_services is err{:}", e);
                    }
                }

                //println!("Rathole service started");
            });
        });
        Ok(())
    }
    pub fn get_name(&self) -> String { self.nickname.clone() }
    pub fn get_did(&self) -> String { self.did.clone() }
    pub fn get_sysinfo(&self) -> SystemInfo {
        self.sysinfo.clone()
    }
    pub fn push_claim(&mut self, claim: &IdClaim) {
        let did = claim.gen_did();
        self.claims.insert(did, claim.clone());
    }


    pub fn get_claim(&self, for_did: &str) -> Option<IdClaim> {
        let did = if for_did.is_empty() { self.did.to_string().clone() } else { for_did.to_string() };
        if self.claims.contains_key(&did) {
            return Some(self.claims.get(&did).unwrap().clone());
        }
        None
    }

    pub fn sign(&self, text: &str) -> Vec<u8> {
        env_utils::get_signature(text).unwrap_or_else(|_| String::from("unknown").into())
    }

    pub fn verify(&self, text: &str, signature: &str) -> bool {
        self.verify_by_did(text, signature, &self.did.clone())
    }

    pub fn verify_by_did(&self, text: &str, signature_str: &str, did: &str) -> bool {
        let claim = self.claims.get(did).unwrap();
        let verify_key_bytes = claim.verify_key.clone();
        let verify_key = VerifyingKey::from_bytes(&verify_key_bytes.as_slice().try_into().unwrap()).unwrap();
        let signature = Signature::from_bytes(&URL_SAFE_NO_PAD.decode(signature_str).unwrap().as_slice().try_into().unwrap());
        match verify_key.verify(text.as_bytes(), &signature) {
            Ok(()) => true,
            Err(_) => false,
        }
    }

    pub fn encrypt_by_did(&self, text: &str, did: &str) -> PyResult<String> {
        let claim = self.claims.get(did).unwrap();
        let did_public = PublicKey::from(claim.crypt_key.clone());
        let shared_key = env_utils::get_diffie_hellman_key(&did_public, self.crypt_secret)?;
        let aes_key = env_utils::hkdf_key(&shared_key);
        let ctext = env_utils::encrypt(text.as_bytes(), &aes_key);
        Ok(URL_SAFE_NO_PAD.encode(ctext))
    }

    pub fn decrypt_by_did(&mut self, ctext: &str, did: &str) -> PyResult<String> {
        let claim = self.claims.get(did).unwrap();
        let did_public = PublicKey::from(claim.crypt_key.clone());
        let shared_key = env_utils::get_diffie_hellman_key(&did_public, self.crypt_secret)?;
        let aes_key = env_utils::hkdf_key(&shared_key);
        let text = env_utils::decrypt(URL_SAFE_NO_PAD.decode(ctext).unwrap().as_slice(), &aes_key);
        Ok(String::from_utf8(text).expect("undecryptable"))
    }
}
