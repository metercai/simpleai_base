use std::collections::HashMap;
use std::thread;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use x25519_dalek::PublicKey;
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
    pub authorized: HashMap<String, UserContext>,
    pub sysinfo: Arc<Mutex<SystemInfo>>,
    device: String,
    claims: HashMap<String, IdClaim>,
    crypt_secrets: HashMap<String, String>,
    guest: String,
    guest_phrase: String,
}

#[pymethods]
impl SimpleAI {
    #[new]
    pub fn new(
        sys_name: String,
    ) -> Self {
        let sys_base_info = env_utils::SYSTEM_BASE_INFO.clone();
        let zeroed_key: [u8; 32] = [0; 32];

        let root_dir = sys_base_info.root_dir.clone();
        let disk_uuid = sys_base_info.disk_uuid.clone();
        let host_name = sys_base_info.host_name.clone();

        let (sys_hash_id, sys_phrase) = env_utils::get_key_hash_id_and_phrase("System", &zeroed_key);
        let (device_hash_id, device_phrase) = env_utils::get_key_hash_id_and_phrase("Device", &zeroed_key);
        let system_name = format!("{}@{}", sys_name, sys_hash_id);
        let device_name = format!("{}@{}", host_name, device_hash_id);
        let guest_name = format!("guest@{}", sys_hash_id);
        println!("system_name:{}, device_name:{}, guest_name:{}", system_name, device_name, guest_name);

        let guest_symbol_hash = env_utils::get_symbol_hash_by_source(&guest_name, "Unknown");
        let (guest_hash_id, guest_phrase) = env_utils::get_key_hash_id_and_phrase("User", &guest_symbol_hash);

        let mut claims =  HashMap::new();
        let _ = env_utils::load_did_in_local(&mut claims);
        println!("load_did_in_local: len={}", claims.len());

        let mut local_did = String::new();
        let mut device_did = String::new();
        let mut guest_did = String::new();
        for (key, id_claim) in claims.iter() {
            if id_claim.nickname == system_name && id_claim.id_type == "System" {
                local_did = key.clone();
            }
            if id_claim.nickname == device_name && id_claim.id_type == "Device" {
                device_did = key.clone();
            }
            if id_claim.nickname == guest_name && id_claim.id_type == "User" {
                guest_did = key.clone();
            }
            if !local_did.is_empty() && !device_did.is_empty() && !guest_did.is_empty() {
                break;
            }
        }

        let mut local_claim = match local_did.is_empty() {
            true => {
                let Ok(_local_claim) = env_utils::generate_did_claim
                    ("System", &system_name, Some(root_dir), None, &sys_phrase) else { todo!() };
                local_did = _local_claim.gen_did();
                println!("system_did:{}", local_did);
                _local_claim
            }
            false => claims.get(&local_did).unwrap().clone(),
        };
        let sysinfo = Arc::new(Mutex::new(SystemInfo::from_base(sys_base_info.clone())));
        let sysinfo_clone = Arc::clone(&sysinfo);
        SystemInfo::generate(sys_base_info, sysinfo_clone, local_did.clone());
        println!("SystemInfo::generat ok");

        let mut crypt_secrets = HashMap::new();
        let _ = env_utils::load_token_by_authorized2system(&local_did, &mut crypt_secrets, &mut claims);
        println!("load_token_by_authorized2system: len={}", crypt_secrets.len());

        if !crypt_secrets.contains_key(&local_did) {
            let local_crypt_secret = env_utils::create_and_save_crypt_secret(&mut crypt_secrets, &local_did, "System", &mut local_claim, &sys_phrase);
            println!("create_and_save_crypt_secret ok, sys_did: {}, local_crypt_secret: {}", local_claim.gen_did(), local_crypt_secret);
        }
        claims.insert(local_did.clone(), local_claim);

        let mut device_claim = match device_did.is_empty() {
            true => {
                let Ok(_device_claim) = env_utils::generate_did_claim
                    ("Device", &device_name, Some(disk_uuid), None, &device_phrase) else { todo!() };
                device_did = _device_claim.gen_did();
                println!("Device_did:{}", device_did);
                _device_claim
            }
            false => claims.get(&device_did).unwrap().clone(),
        };
        if !crypt_secrets.contains_key(&device_did) {
            let _ = env_utils::create_and_save_crypt_secret(&mut crypt_secrets, &local_did, "Device", &mut device_claim, &device_phrase);
        }
        claims.insert(device_did.clone(), device_claim);

        let mut guest_claim = match guest_did.is_empty() {
            true => {
                let Ok(_guest_claim) = env_utils::generate_did_claim
                    ("User", &guest_name, None, None, &guest_phrase) else { todo!() };
                guest_did = _guest_claim.gen_did();
                println!("User_did:{}", guest_did);
                _guest_claim
            }
            false => claims.get(&guest_did).unwrap().clone(),
        };
        if !crypt_secrets.contains_key(&guest_did) {
            let _ = env_utils::create_and_save_crypt_secret(&mut crypt_secrets, &local_did, "User", &mut guest_claim, &guest_phrase);
        }
        claims.insert(guest_did.clone(), guest_claim);

        println!("init context finished: claims.len={}, crypt_secrets.len={}", claims.len(), crypt_secrets.len());

        Self {
            sys_name,
            did: local_did,
            device: device_did,
            authorized: HashMap::new(),
            sysinfo,
            claims,
            crypt_secrets,
            guest: guest_did,
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
        env_utils::get_signature(text, &claim.id_type, &claim.get_symbol_hash(), phrase)
            .unwrap_or_else(|_| String::from("Unknown").into())
    }
    pub fn verify(&mut self, text: &str, signature: &str) -> bool {
        self.verify_by_did(text, signature, &self.did.clone())
    }

    pub fn verify_by_did(&mut self, text: &str, signature_str: &str, did: &str) -> bool {
        env_utils::virify_signature(text, signature_str, did, &mut self.claims)
    }

    pub fn encrypt_for_did(&self, did: &str, text: &str, for_did: &str, period:u64) -> PyResult<String> {
        let self_crypt_secret = env_utils::convert_base64_to_key(self.crypt_secrets.get(did).unwrap());
        let for_did_public = PublicKey::from(self.claims.get(for_did).unwrap().get_crypt_key());
        let shared_key = env_utils::get_diffie_hellman_key(&for_did_public, self_crypt_secret)?;
        let ctext = env_utils::encrypt(text.as_bytes(), &shared_key, period);
        Ok(URL_SAFE_NO_PAD.encode(ctext))
    }

    pub fn decrypt_by_did(&mut self, did: &str, ctext: &str, by_did: &str, period:u64) -> PyResult<String> {
        let self_crypt_secret = env_utils::convert_base64_to_key(self.crypt_secrets.get(did).unwrap());
        let by_did_public = PublicKey::from(self.claims.get(by_did).unwrap().get_crypt_key());
        let shared_key = env_utils::get_diffie_hellman_key(&by_did_public, self_crypt_secret)?;
        let text = env_utils::decrypt(URL_SAFE_NO_PAD.decode(ctext).unwrap().as_slice(), &shared_key, period);
        Ok(String::from_utf8(text).expect("undecryptable"))
    }

    pub fn get_device_did(&self) -> String {
        self.device.clone()
    }

    pub fn get_guest_did(&self) -> String {
        self.guest.clone()
    }

    pub fn get_guest_user_context(&mut self) -> UserContext {
        let guest_did = self.get_guest_did();
        println!("guest_user_context, did: {}", guest_did);
        let mut guest_user_context = self.get_user_context(&guest_did);
        guest_user_context = match guest_user_context.is_default() {
            true => self.sign_user_context(&guest_did, &self.guest_phrase.clone()),
            _ => guest_user_context,
        };
        guest_user_context
    }

    pub fn get_user_context(&mut self, did: &str) -> UserContext {
        println!("user_context, did: {}", did);
        self.authorized.get(did).cloned().unwrap_or_else(|| {
            let (context, sig) = env_utils::get_user_token_from_file(did).unwrap_or(
                (UserContext::default(), String::from("Unknown"))
            );
            let token_text = format!("{}{}", did, context.get_text());
            if sig != "Unknown" && self.verify_by_did(&token_text, &sig, did) {
                self.authorized.insert(did.to_string(), context.clone());
                context
            } else {
                UserContext::default()
            }
        })
    }

    pub fn sign_user_context(&mut self, did: &str, phrase: &str) -> UserContext {
        println!("sign_user_context, did: {}", did);
        let claim = self.claims.get(did).unwrap();
        // 要检测user_token文件，判断是全新创建还是继承历史数据（也就是展期）的token
        let context = env_utils::create_or_renew_user_token(
            did, &claim.nickname, &claim.id_type, &claim.get_symbol_hash(), phrase);
        let token_text = format!("{}{}", did, context.get_text());
        let sig = URL_SAFE_NO_PAD.encode(self.sign_by_did(&token_text, did, phrase));
        match env_utils::save_user_token_to_file(did, &context, &sig) {
            Ok(_) => {
                self.authorized.insert(did.to_string(), context.clone());
                context
            },
            Err(e) => {
                eprintln!("Failed to save user token: {}", e);
                UserContext::default()
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
