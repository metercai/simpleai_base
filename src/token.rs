use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::path::Path;
use x25519_dalek::PublicKey;
use ed25519_dalek::{VerifyingKey, Verifier, Signature};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use tokio::runtime::Runtime;
use std::sync::{Arc, Mutex};
use std::thread;
use std::fs;

use crate::claim::IdClaim;
use crate::rathole::Rathole;
use crate::env_utils;
use pyo3::prelude::*;

#[derive(Clone, Debug)]
#[pyclass]
pub struct TokenDid {
    pub(crate) nickname: String,
    pub(crate) did: String,
    pub(crate) local_ip: String,
    pub(crate) local_port: u16,
    pub(crate) public_ip: String,
    pub(crate) mac_address: String,
    claims: HashMap<String, IdClaim>,
    crypt_secret: [u8; 32],
}

#[pymethods]
impl TokenDid {
    #[new]
    pub fn new(
        nickname: String,
    ) -> Self {
        print!("TokenDid init: {}", nickname.clone());

        let local_ip = env_utils::get_ipaddr_from_stream(None).unwrap_or_else(|_| Ipv4Addr::new(0, 0, 0, 0));
        let net_mac_addr = env_utils::get_mac_address(local_ip.into()).unwrap_or_else(|| String::from("unknown"));
        let mac_address_hash = env_utils::calc_sha256(format!("{}-{}", nickname, net_mac_addr).as_bytes());
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

        print!("did is ok: {}", did.clone());

        let s_public_ip = Arc::new(Mutex::new(None));
        let s_public_ip_clone = Arc::clone(&s_public_ip);
        let s_local_port = Arc::new(Mutex::new(0));
        let s_local_port_clone = Arc::clone(&s_local_port);
        let rt_handle1 = thread::spawn(move || {
            let runtime = Runtime::new().unwrap();
            runtime.block_on(async {
                let public_ip = env_utils::get_ipaddr_from_public().await;
                *s_public_ip_clone.lock().unwrap() = Some(public_ip);
                let port = env_utils::get_port_availability(local_ip.clone(), 8186).await;
                *s_local_port_clone.lock().unwrap() = port;
            });
        });
        rt_handle1.join().unwrap();
        let public_ip = match *s_public_ip.lock().unwrap() {
            Some(Ok(ip)) => ip.to_string(),
            Some(Err(_)) => "Error occurred while retrieving IP".to_string(),
            None => "No IP available".to_string(),
        };
        let local_port = *s_local_port.lock().unwrap();
        let config = "client.toml";
        let _rt_handle2 = thread::spawn(move || {
            let runtime = Runtime::new().unwrap();
            runtime.block_on(async {
                let _ = Rathole::new(&config).start_service();
            });
        });

        TokenDid {
            nickname,
            did,
            local_ip: local_ip.to_string(),
            local_port,
            public_ip,
            mac_address: net_mac_addr,
            claims,
            crypt_secret,
        }
    }

    pub fn get_name(&self) -> String { self.nickname.clone() }
    pub fn get_did(&self) -> String { self.did.clone() }
    pub fn get_local_ip_port(&self) -> String {
        format!("{}:{}", self.local_ip.clone(), self.local_port.clone())
    }
    pub fn get_mac_address(&self) -> String { self.mac_address.clone() }
    pub fn get_public_ip(&self) -> String { self.public_ip.clone() }

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
