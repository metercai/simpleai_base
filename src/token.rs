use std::collections::HashMap;
use std::thread;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use x25519_dalek::PublicKey;
use ed25519_dalek::{VerifyingKey, Verifier, Signature};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use tokio::sync::Mutex;

use crate::claim::{IdClaim, UserContext};
use crate::rathole::Rathole;
use crate::env_utils;
use crate::systeminfo::{SystemInfo, RUNTIME};
use pyo3::prelude::*;
use crate::error::TokenError;
use crate::env_data::EnvData;


#[derive(Clone, Debug)]
#[pyclass]
pub struct SimpleAI {
    pub sys_name: String,
    pub did: String,
    pub users: Vec<String>,
    pub authorized: HashMap<String, UserContext>,
    pub sysinfo: Arc<Mutex<SystemInfo>>,
    device: String,
    claims: HashMap<String, IdClaim>,
    crypt_secrets: HashMap<String, [u8; 32]>,
    guest_phrase: String,
}

#[pymethods]
impl SimpleAI {
    #[new]
    pub fn new(
        sys_name: String,
    ) -> Self {
        let sys_base_info = env_utils::SYSTEM_BASE_INFO.clone();
        let mut claims = HashMap::new();
        let mut users = vec![];
        let mut crypt_secrets = HashMap::new();

        let root_dir = sys_base_info.root_dir.clone();
        let disk_uuid = sys_base_info.disk_uuid.clone();
        let host_name = sys_base_info.host_name.clone();
        let Ok((local_claim, local_crypt_secret, _local_phrase)) = env_utils::generate_did_claim("System", &sys_name.clone(), Some(root_dir), None) else { todo!() };
        let local_did = local_claim.gen_did();
        let sysinfo = Arc::new(Mutex::new(SystemInfo::from_base(sys_base_info.clone())));
        let sysinfo_clone = Arc::clone(&sysinfo);
        SystemInfo::generate(sys_base_info, sysinfo_clone, local_did.clone());
        claims.insert(local_did.clone(), local_claim);
        crypt_secrets.insert(local_did.clone(), local_crypt_secret);

        let Ok((device_claim, device_crypt_secret, _device_phrase)) = env_utils::generate_did_claim("Device", &host_name, Some(disk_uuid), None) else { todo!() };
        let device_did = device_claim.gen_did();
        claims.insert(device_did.clone(), device_claim);
        crypt_secrets.insert(device_did.clone(), device_crypt_secret);

        let Ok((guest_claim, guest_crypt_secret, guest_phrase)) = env_utils::generate_did_claim("User", "guest_default", None, None) else { todo!() };
        let guest_did = guest_claim.gen_did();
        claims.insert(guest_did.clone(), guest_claim);
        crypt_secrets.insert(guest_did.clone(), guest_crypt_secret);

        users.push(guest_did);

        Self {
            sys_name,
            did: local_did,
            device: device_did,
            users,
            authorized: HashMap::new(),
            sysinfo,
            claims,
            crypt_secrets,
            guest_phrase,
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
    pub fn get_name(&self) -> String { self.sys_name.clone() }
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
        self.sign_by_did(text, &self.did.clone(),"no need")
    }

    pub fn sign_by_did(&self, text: &str, did: &str, phrase: &str) -> Vec<u8> {
        let claim = self.claims.get(did).unwrap();
        env_utils::get_signature(text, &claim.id_type, &claim.telephone_hash, phrase)
            .unwrap_or_else(|_| String::from("unknown").into())
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

    pub fn encrypt_by_did(&self, text: &str, did: &str, period:u64) -> PyResult<String> {
        let claim = self.claims.get(did).unwrap();
        let crypt_secret = self.crypt_secrets.get(did).unwrap();
        let did_public = PublicKey::from(claim.crypt_key.clone());
        let shared_key = env_utils::get_diffie_hellman_key(&did_public, *crypt_secret)?;
        let ctext = env_utils::encrypt(text.as_bytes(), &shared_key, period);
        Ok(URL_SAFE_NO_PAD.encode(ctext))
    }

    pub fn decrypt_by_did(&mut self, ctext: &str, did: &str, period:u64) -> PyResult<String> {
        let claim = self.claims.get(did).unwrap();
        let crypt_secret = self.crypt_secrets.get(did).unwrap();
        let did_public = PublicKey::from(claim.crypt_key.clone());
        let shared_key = env_utils::get_diffie_hellman_key(&did_public, *crypt_secret)?;
        let text = env_utils::decrypt(URL_SAFE_NO_PAD.decode(ctext).unwrap().as_slice(), &shared_key, period);
        Ok(String::from_utf8(text).expect("undecryptable"))
    }

    pub fn get_guest_did(&self) -> String {
        self.users.first().unwrap().clone()
    }

    pub fn get_guest_user_context(&mut self) -> UserContext {
        let guest_did = self.get_guest_did();
        let mut guest_user_context = self.get_user_context(&guest_did);
        guest_user_context = match guest_user_context.is_default() {
            true => self.sign_user_context(&guest_did, &self.guest_phrase.clone()),
            _ => guest_user_context,
        };
        guest_user_context
    }

    pub fn get_user_context(&mut self, did: &str) -> UserContext {
        self.authorized.get(did).cloned().unwrap_or_else(|| {
            let (context, sig) = env_utils::get_user_token_from_file(did).unwrap_or(
                (UserContext::default(), String::from("unknown"))
            );
            let token_text = format!("{}{}", did, context.get_text());
            if sig != "unknown" && self.verify_by_did(&token_text, &sig, did) {
                self.authorized.insert(did.to_string(), context.clone());
                context
            } else {
                UserContext::default()
            }
        })
    }

    pub fn sign_user_context(&mut self, did: &str, phrase: &str) -> UserContext {
        let claim = self.claims.get(did).unwrap();
        let zeroed_key: [u8; 32] = [0u8; 32];
        let secret_key = env_utils::get_random_secret_key(&claim.id_type, &claim.telephone_hash, phrase)
                .unwrap_or([0u8; 32]);
        match secret_key {
            zeroed_key => UserContext::default(),
            _ => {
                // 检测user_token文件，判断是全新创建还是继承历史数据（也就是展期）的token
                let default_context = env_utils::create_user_token(
                    did, &claim.nickname, &claim.id_type, &claim.telephone_hash, phrase);
                let token_text = format!("{}{}", did, default_context.get_text());
                let sig = URL_SAFE_NO_PAD.encode(self.sign_by_did(&token_text, did, phrase));
                match env_utils::save_user_token_to_file(did, &default_context, &sig) {
                    Ok(_) => {
                        self.authorized.insert(did.to_string(), default_context.clone());
                        default_context
                    },
                    Err(e) => {
                        eprintln!("Failed to save user token: {}", e);
                        UserContext::default()
                    }
                }
            }
        }
    }

    pub fn check_ready(&self, v1: String, v2: String, v3: String, root: String) -> i32 {
        let start = Instant::now();
        let mut feedback_code = 0;
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

        let target_pyhash= EnvData::get_pyhash(&v1, &v2, &v3);
        let check_pyhash = EnvData::get_check_pyhash(&sysinfo.pyhash.clone());
        if target_pyhash != "Unknown" && target_pyhash != check_pyhash {
            let now_sec = SystemTime::now().duration_since(UNIX_EPOCH)
                .unwrap_or_else(|_| std::time::Duration::from_secs(0)).as_secs();
            let pyhash_display = URL_SAFE_NO_PAD.encode(env_utils::calc_sha256(
                format!("{}-{}", sysinfo.pyhash, (now_sec/100000*100000).to_string())
                    .as_bytes()));

            println!("[SimpleAI] 所运行程序为非官方版本，请正确使用开源软件，{}。", &pyhash_display[..16]);
            feedback_code += 4;
        }

        feedback_code
    }

    pub fn get_pyhash(&self) -> String {
        let sysinfo = self.get_sysinfo();
        let pyhash = EnvData::get_check_pyhash(&sysinfo.pyhash.clone());
        pyhash
    }

    pub fn get_pyhash_key(&self, v1: String, v2: String, v3: String) -> String {
        return EnvData::get_pyhash_key(&v1, &v2, &v3);
    }
}
