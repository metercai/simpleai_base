use std::collections::HashMap;
use std::thread;
use std::fs;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use x25519_dalek::PublicKey;
use ed25519_dalek::{VerifyingKey, Verifier, Signature};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use tokio::sync::Mutex;

use crate::claim::IdClaim;
use crate::rathole::Rathole;
use crate::env_utils;
use crate::systeminfo::{SystemInfo, RUNTIME};
use pyo3::prelude::*;
use crate::error::TokenError;
use crate::env_data::EnvData;

#[derive(Clone, Debug)]
#[pyclass]
pub struct SimpleAI {
    pub nickname: String,
    pub did: String,
    pub sysinfo: Arc<Mutex<SystemInfo>>,
    claims: HashMap<String, IdClaim>,
    crypt_secret: [u8; 32],
}

#[pymethods]
impl SimpleAI {
    #[new]
    pub fn new(
        nickname: String,
    ) -> Self {
        let sys_base_info = env_utils::SYSTEM_BASE_INFO.clone();

        let disk_uuid_hash = env_utils::calc_sha256(format!("{}-{}", nickname, sys_base_info.disk_uuid).as_bytes());
        let telephone_hash = env_utils::calc_sha256(format!("{}-telephone:-", nickname).as_bytes());
        let face_image_hash = env_utils::calc_sha256(format!("{}-face_image:-", nickname).as_bytes());
        let file_hash_hash = env_utils::calc_sha256(format!("{}-file_hash:-", nickname).as_bytes());

        let zeroed_key: [u8; 32] = [0; 32];
        let verify_key = env_utils::get_verify_key().unwrap_or_else(|_| zeroed_key);
        let mut local_claim = IdClaim::new(nickname.clone(), verify_key, telephone_hash, disk_uuid_hash, face_image_hash, file_hash_hash);

        let did = local_claim.gen_did();

        let sysinfo = Arc::new(Mutex::new(SystemInfo::from_base(sys_base_info.clone())));
        let sysinfo_clone = Arc::clone(&sysinfo);
        SystemInfo::generate(sys_base_info, sysinfo_clone, did.clone());

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
        let _rt_handle = thread::spawn(move || {
            RUNTIME.block_on(async {
                //let _ = Rathole::new(&config).start_service().await;
                //todo!()
                //println!("Rathole service started");
            });
        });
        Ok(())
    }
    pub fn get_name(&self) -> String { self.nickname.clone() }
    pub fn get_did(&self) -> String { self.did.clone() }
    pub fn get_sysinfo(&self) -> SystemInfo {
        SystemInfo::get_sysinfo(self.sysinfo.clone())
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

    pub fn check_ready(&self, v1: String, v2: String, v3: String, root: String) -> i32 {
        let start = Instant::now();
        let mut feedback_code = 0;
        let target_pyhash = EnvData::get_pyhash(&v1, &v2, &v3);
        if !EnvData::check_basepkg(&root) {
            println!("[SimpleAI] 程序所需基础模型包有检测异常，未完全正确安装。请检查并正确安装后，再启动程序。");
            feedback_code += 2;
        }
        let mut sysinfo = self.get_sysinfo();
        loop {
            if sysinfo.pyhash != "Unknown" {
                break;
            }
            if start.elapsed() > Duration::from_secs(15) {
                println!("[SimpleAI] 系统检测异常，继续运行会影响程序正确执行。请检查系统环境后，重新启动程序。");
                feedback_code += 1;
                break;
            }
            thread::sleep(Duration::from_secs(1));
            sysinfo = self.get_sysinfo();
        }

        if target_pyhash != "Unknown" && target_pyhash != sysinfo.pyhash {
            let now_sec = SystemTime::now().duration_since(UNIX_EPOCH).expect("error time").as_secs();
            let pyhash_display = URL_SAFE_NO_PAD.encode(env_utils::calc_sha256(
                format!("{}{}", sysinfo.pyhash, (now_sec/100000).to_string())
                    .as_bytes()));

            println!("[SimpleAI] 所运行程序为非官方版本，请正确使用开源软件，{}。", &pyhash_display[..16]);
            feedback_code += 4;
        }

        feedback_code
    }

    pub fn get_pyhash_key(&self, v1: String, v2: String, v3: String) -> String {
        return EnvData::get_pyhash_key(&v1, &v2, &v3);
    }
}
