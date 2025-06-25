use base58::*;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ripemd::Ripemd160;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::Digest;
use std::collections::HashMap;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;
use tracing_subscriber::field::debug;

use pyo3::prelude::*;
use tracing::{debug, info};

use crate::dids;
use crate::dids::token_utils;
use crate::api;

lazy_static::lazy_static! {
    static ref GLOBAL_CLAIMS: Arc<Mutex<GlobalClaims>> = Arc::new(Mutex::new(GlobalClaims::new()));
}

#[derive(Clone, Debug)]
pub struct GlobalClaims {
    pub local_claims: LocalClaims,
}

impl GlobalClaims {
    pub fn instance() -> Arc<Mutex<GlobalClaims>> {
        GLOBAL_CLAIMS.clone()
    }

    pub fn new() -> Self {
        //println!("{} [SimpBase] GlobalClaims: new()", token_utils::now_string());
        let local_claims = LocalClaims::new();
        Self { local_claims }
    }

    pub fn get_claim(&mut self, for_did: &str) -> IdClaim {
        if for_did.is_empty() {
            debug!("get_claim for_did is empty");
            return IdClaim::default();
        }
        let mut claim = self.local_claims.get_claim_from_local(for_did.clone());
        if claim.is_default() {
            claim = GlobalClaims::get_claim_from_DHT(for_did);
        }
        claim
    }

    pub fn push_claim(&mut self, claim: &IdClaim) {
        self.local_claims.push_claim(claim);
        GlobalClaims::push_claim_to_DHT(claim);
    }

    pub fn iter(&self) -> impl Iterator<Item = (&String, &IdClaim)> {
        self.local_claims.iter()
    }

    pub fn get_claim_from_DHT(for_did: &str) -> IdClaim {
        
        let claim = match api::request_api_sync::<String>(&format!("get_claim/{for_did}"), None::<&serde_json::Value>) {
            Ok(claim_json) => match serde_json::from_str::<IdClaim>(&claim_json) {
                Ok(parsed_claim) => parsed_claim,
                Err(err) => {
                    debug!("解析claim({}) JSON失败: {:?}", for_did, err);
                    IdClaim::default()
                }
            },
            Err(err) => {
                debug!("从全局获取 claim({}) 失败: {:?}", for_did, err);
                IdClaim::default()
            }
        };
        claim
    }

    pub(crate) fn push_claim_to_DHT(claim: &IdClaim) {
        let params = json!({
            "claim": claim,
        });
        let _did = match api::request_api_sync("put_claim", Some(params)) {
            Ok(did) => did,
            Err(err) => {
                debug!("get claim from global failures: {:?}", err);
                String::from("")
            }
        };
    }

    pub(crate) fn get_claim_from_local(&mut self, for_did: &str) -> IdClaim {
        self.local_claims.get_claim_from_local(for_did.clone())
    }

    pub(crate) fn push_claim_to_local(&mut self, claim: &IdClaim) {
        self.local_claims.push_claim(claim)
    }
}

#[derive(Clone, Debug)]
pub struct LocalClaims {
    claims: HashMap<String, IdClaim>, // 留存本地的身份自证
    sys_did: String,                  // 系统did
    device_did: String,               // 设备id
    guest: String,                    // 游客账号
}

impl LocalClaims {
    fn new() -> Self {
        let sysinfo = token_utils::SYSTEM_BASE_INFO.clone();
        let root_dir = sysinfo.root_dir.clone();


        let mut sys_did = "Unknown".to_string();
        let mut device_did = "Unknown".to_string();
        let mut guest = "Unknown".to_string();

        let mut claims = HashMap::new();

        let root_did_path = PathBuf::from(root_dir.clone()).join(".did");
        if root_did_path.exists() {
            match fs::read_dir(root_did_path) {
                Ok(entries) => {
                    for entry in entries {
                        match entry {
                            Ok(entry) => {
                                let path = entry.path();
                                if let Some(file_name) =
                                    path.file_name().and_then(|name| name.to_str())
                                {
                                    if file_name.ends_with(".did") {
                                        let claim = IdClaim::from_file(path.to_str().unwrap_or(""));
                                        if !claim.is_default() {
                                            let did = claim.gen_did();
                                            claims.insert(did.clone(), claim.clone());
                                            debug!(
                                                "Load root_did_claim({}): {}",
                                                did,
                                                claim.to_json_string()
                                            );
                                        }
                                    }
                                }
                            }
                            Err(e) => {
                                eprintln!("Failed to read root_did_claim: {}", e);
                            }
                        }
                    }
                }
                Err(e) => {
                    eprintln!("Failed to read root_did_claim: {}", e);
                }
            }
        }

        let did_file_path = token_utils::get_path_in_sys_key_dir("user_xxxxx.did");
        let root_path = match did_file_path.parent() {
            Some(parent) => {
                if parent.exists() {
                    parent
                } else {
                    fs::create_dir_all(parent).unwrap();
                    parent
                }
            }
            None => panic!(
                "{}",
                format!(
                    "File path does not have a parent directory: {:?}",
                    did_file_path
                )
            ),
        };
        let device_symbol_hash = dids::get_key_symbol_hash("Device");
        let system_symbol_hash = dids::get_key_symbol_hash("System");
        let guest_symbol_hash = dids::get_key_symbol_hash("Guest");
        match fs::read_dir(root_path) {
            Ok(entries) => {
                for entry in entries {
                    match entry {
                        Ok(entry) => {
                            let path = entry.path();
                            if let Some(file_name) = path.file_name().and_then(|name| name.to_str())
                            {
                                if file_name.ends_with(".did") {
                                    let claim = IdClaim::from_file(path.to_str().unwrap_or(""));
                                    if !claim.is_default() {
                                        let did = claim.gen_did();
                                        claims.insert(did.clone(), claim.clone());
                                        if claim.id_type == "System"
                                            && claim.get_symbol_hash() == system_symbol_hash
                                        {
                                            sys_did = did;
                                        } else if claim.id_type == "Device"
                                            && claim.get_symbol_hash() == device_symbol_hash
                                        {
                                            device_did = did;
                                        } else if claim.id_type == "User"
                                            && claim.get_symbol_hash() == guest_symbol_hash
                                        {
                                            guest = did;
                                        }
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            eprintln!("Failed to read directory entry: {}", e);
                        }
                    }
                }
            }
            Err(e) => {
                eprintln!("Failed to read directory: {}", e);
            }
        }

        // 遍历claims，判断是否有重复的id_claim.get_symbol_hash()，如果有重复的则取id_claim.timestamp 最大的保留，其他的删除
        let mut symbol_hash_map: HashMap<Vec<u8>, (String, u64)> = HashMap::new();
        let mut dids_to_remove: Vec<String> = Vec::new();
        
        // 第一次遍历：找出每个symbol_hash对应的最新DID
        for (did, claim) in claims.iter() {
            let symbol_hash = claim.get_symbol_hash().to_vec();
            
            if let Some((existing_did, existing_timestamp)) = symbol_hash_map.get(&symbol_hash) {
                if claim.timestamp > *existing_timestamp {
                    // 如果当前声明比已记录的更新，则将旧的DID加入删除列表
                    dids_to_remove.push(existing_did.clone());
                    // 更新为当前最新的DID
                    symbol_hash_map.insert(symbol_hash, (did.clone(), claim.timestamp));
                } else {
                    // 如果当前声明比已记录的更旧，则将当前DID加入删除列表
                    dids_to_remove.push(did.clone());
                }
            } else {
                // 第一次遇到这个symbol_hash，直接记录
                symbol_hash_map.insert(symbol_hash, (did.clone(), claim.timestamp));
            }
        }
        
        // 第二次处理：删除所有旧的DID
        for did_to_remove in dids_to_remove {
            claims.remove(&did_to_remove);
            
            // 同时删除对应的文件
            let claim = claims.get(&did_to_remove);
            if let Some(claim) = claim {
                let did_file_path = token_utils::get_path_in_sys_key_dir(&format!(
                    "{}_{}.did",
                    claim.id_type.to_lowercase(),
                    did_to_remove
                ));
                if did_file_path.exists() {
                    if let Err(e) = fs::remove_file(did_file_path.clone()) {
                        debug!("删除重复的DID文件失败: {}, 错误: {}", did_file_path.display(), e);
                    } else {
                        debug!("删除了重复的DID文件: {}", did_file_path.display());
                    }
                }
            }
        }
        
        (device_did, sys_did, guest) = LocalClaims::generate_sys_dev_guest_did(&mut claims, &device_did, &sys_did, &guest);        
        println!("{} [SimpBase] Loaded claims from local: len={}", token_utils::now_string(), claims.len());
        
        LocalClaims {
            claims: claims.clone(),
            sys_did: sys_did.clone(),
            device_did: device_did.clone(),
            guest: guest.clone(),
        }
    }

    pub(crate) fn get_sys_dev_guest_did(
        &mut self, 
        was_regenerated: bool,
    ) -> (String, IdClaim, String, IdClaim, String, IdClaim) {
        if was_regenerated {
            let (device_did_new, sys_did_new, guest_new) = LocalClaims::generate_sys_dev_guest_did(
                &mut self.claims, "Unknown", "Unknown", "Unknown");
            
            // 移除旧的claims
            let dids_to_remove = [self.device_did.clone(), self.sys_did.clone(), self.guest.clone()];
            for did in dids_to_remove {
                self.pop_claim(&did);
            }
            
            // 更新新的DIDs
            self.device_did = device_did_new;
            self.sys_did = sys_did_new;
            self.guest = guest_new;
        }

        let device_did = self.device_did.clone();
        let sys_did = self.sys_did.clone();
        let guest = self.guest.clone();
        // 返回当前值
        (
            self.sys_did.clone(),
            self.get_claim_from_local(&sys_did),
            self.device_did.clone(),
            self.get_claim_from_local(&device_did),
            self.guest.clone(),
            self.get_claim_from_local(&guest),
        )
    }

    pub(crate) fn get_system_did(&self) -> String {
        self.sys_did.clone()
    }

    pub(crate) fn get_device_did(&self) -> String {
        self.device_did.clone()
    }

    pub(crate) fn get_guest_did(&self) -> String {
        self.guest.clone()
    }

    pub fn local_len(&self) -> usize {
        self.claims.len()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&String, &IdClaim)> {
        self.claims.iter()
    }

    pub fn get_claim_from_local(&mut self, did: &str) -> IdClaim {
        if did == "Unknown" {
            return IdClaim::default();
        }
        if !self.claims.contains_key(did) {
            let claim = LocalClaims::load_claim_from_local(did);
            if !claim.is_default() {
                self.claims.insert(did.to_string(), claim.clone());
                claim
            } else {
                claim
            }
        } else {
            self.claims.get(did).unwrap().clone()
        }
    }

    pub fn push_claim(&mut self, claim: &IdClaim) {
        self.claims.insert(claim.gen_did(), claim.clone());
        let did_file_path = token_utils::get_path_in_sys_key_dir(&format!(
            "{}_{}.did",
            claim.id_type.to_lowercase(),
            claim.gen_did()
        ));
        fs::write(did_file_path, claim.to_json_string()).unwrap();
    }

    pub fn pop_claim(&mut self, did: &str) -> IdClaim {
        let claim = self.get_claim_from_local(did);
        self.claims.remove(did);
        let did_file_path = token_utils::get_path_in_sys_key_dir(&format!(
            "{}_{}.did",
            claim.id_type.to_lowercase(),
            did
        ));
        if did_file_path.exists() {
            if let Err(e) = fs::remove_file(did_file_path.clone()) {
                debug!("delete user_did_file error: {}", e);
            } else {
                debug!("user_did_file was deleted: {}", did_file_path.display());
            }
        }

        claim
    }


    pub(crate) fn generate_sys_dev_guest_did(
        claims: &mut HashMap<String, IdClaim>, 
        device_did: &str, 
        sys_did: &str, 
        guest_did: &str) -> (String, String, String) { 
        
        let sysinfo = token_utils::SYSTEM_BASE_INFO.clone();
        let root_dir = sysinfo.root_dir.clone();
        let disk_uuid = sysinfo.disk_uuid.clone();

        let (system_name, sys_phrase, device_name, device_phrase, guest_name, guest_phrase) =
            dids::get_system_vars();

        let device_did = if device_did == "Unknown" {
            let device_claim = LocalClaims::generate_did_claim(
                "Device", &device_name, None, 
                Some(disk_uuid.clone()), &device_phrase, None,
            );
            let device_did = device_claim.gen_did();
            claims.insert(device_did.clone(), device_claim.clone());
            let did_file_path = token_utils::get_path_in_sys_key_dir(&format!(
                "{}_{}.did", device_claim.id_type.to_lowercase(), device_claim.gen_did()
            ));
            fs::write(did_file_path, device_claim.to_json_string()).unwrap();
            device_did
        } else {
            device_did.to_string() 
        };

        let sys_did = if sys_did == "Unknown" {
            let local_claim = LocalClaims::generate_did_claim(
                "System", &system_name, None,
                Some(format!("{}:{}", root_dir.clone(), disk_uuid.clone())),
                &sys_phrase, None,
            );
            let sys_did = local_claim.gen_did();
            claims.insert(sys_did.clone(), local_claim.clone());
            let did_file_path = token_utils::get_path_in_sys_key_dir(&format!(
                "{}_{}.did",
                local_claim.id_type.to_lowercase(),
                local_claim.gen_did()
            ));
            fs::write(did_file_path, local_claim.to_json_string()).unwrap();
            sys_did
        } else {
            sys_did.to_string() 
        };
        
        let guest_did = if guest_did == "Unknown" {
            let guest_claim = LocalClaims::generate_did_claim(
                "User",
                &guest_name,
                None,
                Some(format!("{}:{}", root_dir.clone(), disk_uuid.clone())),
                &guest_phrase,
                None,
            );
            let guest_did = guest_claim.gen_did();
            claims.insert(guest_did.clone(), guest_claim.clone());
            let did_file_path = token_utils::get_path_in_sys_key_dir(&format!(
                "{}_{}.did",
                guest_claim.id_type.to_lowercase(),
                guest_claim.gen_did()
            ));
            fs::write(did_file_path, guest_claim.to_json_string()).unwrap();
            guest_did
        } else {
            guest_did.to_string() 
        };
        
        (device_did, sys_did, guest_did)
    }


    pub(crate) fn generate_did_claim(
        id_type: &str,
        nickname: &str,
        telephone: Option<String>,
        id_card: Option<String>,
        phrase: &str,
        timestamp: Option<u64>,
    ) -> IdClaim {
        debug!(
            "generate_did_claim: id_type={}, nickname={}",
            id_type, nickname
        );
        let nickname = token_utils::truncate_nickname(nickname);
        let id_card = id_card.unwrap_or("-".to_string());
        let telephone = telephone.unwrap_or("-".to_string());
        let id_card_hash =
            token_utils::calc_sha256(format!("{}:id_card:{}", nickname, id_card).as_bytes());
        let telephone_hash =
            token_utils::calc_sha256(format!("{}:telephone:{}", nickname, telephone).as_bytes());
        let face_image_hash =
            token_utils::calc_sha256(format!("{}:face_image:-", nickname).as_bytes());
        let file_hash_hash =
            token_utils::calc_sha256(format!("{}:file_hash:-", nickname).as_bytes());
        let claim = IdClaim::new(
            id_type,
            &phrase,
            &nickname,
            telephone_hash,
            id_card_hash,
            face_image_hash,
            file_hash_hash,
            timestamp,
        );
        debug!("generate_did_claim result: {}", claim.to_json_string());
        claim
    }

    pub(crate) fn load_claim_from_local(did: &str) -> IdClaim {
        let user_did_file_path_root =
            token_utils::get_path_in_root_dir(".did", format!("user_{}.did", did).as_str());
        let user_did_file_path =
            token_utils::get_path_in_sys_key_dir(format!("user_{}.did", did).as_str());
        let sys_did_file_path_root =
            token_utils::get_path_in_root_dir(".did", format!("system_{}.did", did).as_str());
        let sys_did_file_path =
            token_utils::get_path_in_sys_key_dir(format!("system_{}.did", did).as_str());
        let device_did_file_path =
            token_utils::get_path_in_sys_key_dir(format!("device_{}.did", did).as_str());

        let did_file_path = if user_did_file_path_root.exists() {
            user_did_file_path_root
        } else if user_did_file_path.exists() {
            user_did_file_path
        } else if sys_did_file_path_root.exists() {
            sys_did_file_path_root
        } else if sys_did_file_path.exists() {
            sys_did_file_path
        } else if device_did_file_path.exists() {
            device_did_file_path
        } else {
            return IdClaim::default();
        };
        let file_content = match fs::read_to_string(did_file_path) {
            Ok(content) => content,
            Err(_e) => {
                return IdClaim::default();
            }
        };
        serde_json::from_str(&file_content).unwrap_or(IdClaim::default())
    }

    pub fn reverse_lookup_did_by_symbol(&mut self, symbol_hash: &[u8; 32]) -> String {
        let mut latest_did = "Unknown".to_string();
        let mut latest_timestamp: u64 = 0;
        let mut old_dids = Vec::new();

        // 第一次遍历：找出最新的DID和所有匹配的DID
        for (did, id_claim) in self.claims.iter() {
            if id_claim.get_symbol_hash() == *symbol_hash {
                if id_claim.timestamp >= latest_timestamp {
                    // 如果找到更新的DID，将当前最新的DID加入到旧DID列表
                    if latest_did != "Unknown" {
                        old_dids.push(latest_did);
                    }
                    latest_timestamp = id_claim.timestamp;
                    latest_did = did.to_string();
                } else {
                    // 如果当前DID不是最新的，加入到旧DID列表
                    old_dids.push(did.to_string());
                }
            }
        }

        // 第二次处理：删除所有旧的DID
        for old_did in old_dids {
            self.pop_claim(&old_did);
        }

        latest_did
    }

    pub fn verify_by_claim(text: &str, signature_str: &str, claim: &IdClaim) -> bool {
        token_utils::verify_signature(text, signature_str, &claim.get_verify_key())
    }

    pub fn cert_verify_by_claim(text: &str, signature_str: &str, claim: &IdClaim) -> bool {
        token_utils::verify_signature(text, signature_str, &claim.get_cert_verify_key())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[pyclass]
pub struct IdClaim {
    pub id_type: String,
    pub nickname: String,
    pub verify_key: String,      // 验签公钥
    pub cert_verify_key: String, // 证书公钥, 需要根据代理的did做扩展，通过DHT获取授予不同代理处的验证公钥
    pub crypt_key: String,       // 交换公钥，需要根据代理的did做扩展，通过DHT获取授予不同代理处的验证公钥
    pub fingerprint: String,
    pub timestamp: u64,
    pub signature: String,
    pub telephone_hash: String,
    pub id_card_hash: String,
    pub face_image_hash: String,
    pub file_hash_hash: String,
}

#[pymethods]
impl IdClaim {
    #[new]
    pub fn new(
        id_type: &str,
        phrase: &str,
        nickname: &str,
        telephone_hash: [u8; 32],
        id_card_hash: [u8; 32],
        face_image_hash: [u8; 32],
        file_hash_hash: [u8; 32],
        timestamp: Option<u64>,
    ) -> Self {
        let nickname = token_utils::truncate_nickname(nickname);
        let telephone_base64 = URL_SAFE_NO_PAD.encode(telephone_hash);
        let id_card_base64 = URL_SAFE_NO_PAD.encode(id_card_hash);
        let face_image_base64 = URL_SAFE_NO_PAD.encode(face_image_hash);
        let file_hash_base64 = URL_SAFE_NO_PAD.encode(file_hash_hash);
        let fingerprint_str = format!(
            "telephone:{},id_card:{},face_image:{},file_hash:{}",
            telephone_base64, id_card_base64, face_image_base64, file_hash_base64
        );
        let fingerprint =
            URL_SAFE_NO_PAD.encode(token_utils::calc_sha256(&fingerprint_str.as_bytes()));
        let symbol_hash = token_utils::calc_sha256(
            format!("{}|{}|{}", nickname, telephone_base64, id_card_base64).as_bytes(),
        );
        let verify_key =
            URL_SAFE_NO_PAD.encode(token_utils::get_verify_key(id_type, &symbol_hash, phrase));
        let crypt_secret =
            token_utils::get_specific_secret_key("exchange", id_type, &symbol_hash, phrase);
        let cert_secret =
            token_utils::get_specific_secret_key("issue", id_type, &symbol_hash, phrase);
        debug!(
            "IdClaim new() get {} exchange_key: {}",
            URL_SAFE_NO_PAD.encode(symbol_hash),
            URL_SAFE_NO_PAD.encode(crypt_secret)
        );
        debug!(
            "IdClaim new() get {} issue_key: {}",
            URL_SAFE_NO_PAD.encode(symbol_hash),
            URL_SAFE_NO_PAD.encode(cert_secret)
        );

        let crypt_key = URL_SAFE_NO_PAD.encode(token_utils::get_crypt_key(crypt_secret));
        let cert_verify_key =
            URL_SAFE_NO_PAD.encode(token_utils::get_cert_verify_key(&cert_secret));
        let sysinfo = token_utils::SYSTEM_BASE_INFO.clone();
        let claim_time = match id_type {
            "User" => {
                if let Some(ts) = timestamp {
                    ts
                } else {
                    SystemTime::now()
                        .duration_since(SystemTime::UNIX_EPOCH)
                        .unwrap_or_else(|_| std::time::Duration::from_secs(0))
                        .as_secs()
                }
            }
            "Device" => sysinfo.os_time,
            "System" => sysinfo.root_time,
            _ => 0,
        };
        let text_sig = format!(
            "nickname:{},verify_key:{},cert_verify_key:{},crypt_key:{},fingerprint:{},timestamp:{}",
            nickname, verify_key, cert_verify_key, crypt_key, fingerprint, claim_time
        );
        let signature = URL_SAFE_NO_PAD.encode(token_utils::get_signature(
            &text_sig,
            id_type,
            &symbol_hash,
            phrase,
        ));

        Self {
            id_type: id_type.to_string(),
            nickname: nickname.to_string(),
            verify_key,
            cert_verify_key,
            crypt_key,
            fingerprint,
            timestamp: claim_time,
            signature,
            telephone_hash: telephone_base64,
            id_card_hash: id_card_base64,
            face_image_hash: face_image_base64,
            file_hash_hash: file_hash_base64,
        }
    }

    #[staticmethod]
    pub fn from_file(path_str: &str) -> IdClaim {
        if path_str.is_empty() {
            return IdClaim::default();
        }
        let did_path = PathBuf::from(path_str);
        match fs::read_to_string(did_path) {
            Ok(content) => match serde_json::from_str::<IdClaim>(&content) {
                Ok(claim) => {
                    if claim.self_verify() {
                        claim
                    } else {
                        eprintln!("Failed to verify signature");
                        IdClaim::default()
                    }
                }
                Err(e) => {
                    eprintln!("Failed to parse JSON: {}", e);
                    IdClaim::default()
                }
            },
            Err(e) => {
                eprintln!("Failed to read file: {}", e);
                IdClaim::default()
            }
        }
    }


    fn get_format_text(&self) -> String {
        format!(
            "nickname:{},verify_key:{},cert_verify_key:{},crypt_key:{},fingerprint:{},timestamp:{}",
            self.nickname,
            self.verify_key,
            self.cert_verify_key,
            self.crypt_key,
            self.fingerprint,
            self.timestamp
        )
    }
    pub fn gen_did(&self) -> String {
        let did_claim_str = self.get_format_text();
        let mut hasher = Ripemd160::new();
        hasher.update(token_utils::calc_sha256(&did_claim_str.as_bytes()));
        let did = hasher.finalize();
        let did_hash = token_utils::calc_sha256(&did);
        let mut did_check = [0; 21];
        did_check[..20].copy_from_slice(&did);
        did_check[20..].copy_from_slice(&did_hash[..1]);
        did_check.to_base58()
    }

    pub fn self_verify(&self) -> bool {
        token_utils::verify_signature(
            &self.get_format_text(),
            &self.signature,
            &self.get_verify_key(),
        )
    }

    #[staticmethod]
    pub fn validity(did: &str) -> bool {
        let did_bytes = did
            .from_base58()
            .unwrap_or("Unknown".to_string().into_bytes());
        if did_bytes.len() == 21 {
            let did = did_bytes[..20].to_vec();
            let did_hash1 = did_bytes[20];
            let did_hash2 = token_utils::calc_sha256(&did)[0];
            if did_hash1 == did_hash2 {
                return true;
            }
        }
        false
    }

    pub(crate) fn get_verify_key(&self) -> [u8; 32] {
        token_utils::convert_base64_to_key(&self.verify_key)
    }

    pub(crate) fn get_cert_verify_key(&self) -> [u8; 32] {
        token_utils::convert_base64_to_key(&self.cert_verify_key)
    }

    pub(crate) fn get_crypt_key(&self) -> [u8; 32] {
        token_utils::convert_base64_to_key(&self.crypt_key)
    }

    #[staticmethod]
    pub fn get_symbol_hash_by_source(
        nickname: &str,
        telephone: Option<String>,
        id_card: Option<String>,
    ) -> [u8; 32] {
        let nickname = token_utils::truncate_nickname(nickname);
        let id_card = id_card.unwrap_or("-".to_string());
        let telephone = telephone.unwrap_or("-".to_string());
        let id_card_hash = URL_SAFE_NO_PAD.encode(token_utils::calc_sha256(
            format!("{}:id_card:{}", nickname, id_card).as_bytes(),
        ));
        let telephone_hash = URL_SAFE_NO_PAD.encode(token_utils::calc_sha256(
            format!("{}:telephone:{}", nickname, telephone).as_bytes(),
        ));
        token_utils::calc_sha256(
            format!("{}|{}|{}", nickname, telephone_hash, id_card_hash).as_bytes(),
        )
    }

    pub fn get_symbol_hash(&self) -> [u8; 32] {
        token_utils::calc_sha256(
            format!(
                "{}|{}|{}",
                self.nickname, self.telephone_hash, self.id_card_hash
            )
            .as_bytes(),
        )
    }

    pub(crate) fn to_json_string(&self) -> String {
        serde_json::to_string(self).unwrap_or("Unknown".to_string())
    }

    pub fn is_default(&self) -> bool {
        self.nickname == "Default"
    }
}

impl Default for IdClaim {
    fn default() -> Self {
        IdClaim {
            nickname: "Default".to_string(),
            id_type: "User".to_string(),
            verify_key: "Default_verify_key".to_string(),
            cert_verify_key: "Default_cert_verify_key".to_string(),
            fingerprint: "Default_fingerprint".to_string(),
            telephone_hash: "Default_telephone_hash".to_string(),
            id_card_hash: "Default_id_card_hash".to_string(),
            face_image_hash: "Default_face_image_hash".to_string(),
            file_hash_hash: "Default_file_hash_hash".to_string(),
            crypt_key: "Default_crypt_key".to_string(),
            signature: "Default_signature".to_string(),
            timestamp: 0,
        }
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

#[derive(Clone, Debug, Serialize, Deserialize)]
#[pyclass]
pub struct UserContext {
    did: String,
    sys_did: String, // 授权给哪个系统
    timestamp: u64,
    nickname: String,
    auth_sk: String,           // 授权密钥
    permissions: String,       // 权限
    private_paths: String,     // 个性化目录
    aes_key_encrypted: String, // 加密后的加密密钥
    sig: String,
    is_pending: bool,
}

#[pymethods]
impl UserContext {
    #[new]
    pub fn new(
        did: &str,
        sys_did: &str,
        nickname: &str,
        permissions: &str,
        private_paths: &str,
    ) -> Self {
        let now_sec = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_else(|_| std::time::Duration::from_secs(0))
            .as_secs();
        Self {
            did: did.to_string(),
            sys_did: sys_did.to_string(),
            timestamp: now_sec,
            nickname: nickname.to_string(),
            auth_sk: String::new(),
            permissions: permissions.to_string(),
            private_paths: private_paths.to_string(),
            aes_key_encrypted: String::new(),
            sig: String::new(),
            is_pending: true,
        }
    }

    pub fn get_nickname(&self) -> String {
        self.nickname.clone()
    }
    pub fn get_did(&self) -> String {
        self.did.clone()
    }

    pub fn get_sys_did(&self) -> String {
        self.sys_did.clone()
    }

    pub fn set_sys_did(&mut self, sys_did: &str) {
        self.sys_did = sys_did.to_string();
    }

    pub fn get_timestamp(&self) -> u64 {
        self.timestamp.clone()
    }

    pub(crate) fn get_permissions(&self) -> String {
        self.permissions.clone()
    }

    pub(crate) fn get_crypt_key(&self) -> [u8; 32] {
        let auth_sk = URL_SAFE_NO_PAD
            .decode(self.auth_sk.as_bytes())
            .unwrap_or_else(|_| [0u8; 40].to_vec());
        let key = &auth_sk[..32];
        let expire = u64::from_le_bytes(auth_sk[32..].try_into().unwrap_or_else(|_| [0; 8]));
        let mut com_key = [0; 64];
        com_key[..32].copy_from_slice(key);
        com_key[32..].copy_from_slice(&token_utils::calc_sha256(self.sys_did.as_bytes()));
        token_utils::hkdf_key_deadline(&token_utils::calc_sha256(&com_key), expire)
    }

    pub(crate) fn set_auth_sk(&mut self, auth_sk: &str) {
        self.auth_sk = auth_sk.to_string();
    }

    pub(crate) fn set_auth_sk_with_secret(&mut self, secret_key: &str, expire: u64) {
        let secret_key_bytes = token_utils::convert_base64_to_key(secret_key);
        self.auth_sk = URL_SAFE_NO_PAD.encode(token_utils::convert_to_sk_with_expire(
            &secret_key_bytes,
            expire,
        ));
    }

    pub(crate) fn get_aes_key_encrypted(&self) -> String {
        self.aes_key_encrypted.clone()
    }

    pub(crate) fn set_aes_key_encrypted(&mut self, key: &str) {
        self.aes_key_encrypted = key.to_string();
    }

    pub(crate) fn get_sig(&self) -> String {
        self.sig.clone()
    }

    pub fn signature(&mut self, phrase: &str) -> String {
        let text = self.get_text();
        let claim = {
            let claims = GlobalClaims::instance();
            let mut claims = claims.lock().unwrap();
            claims.get_claim_from_local(&self.get_did())
        };
        self.sig = URL_SAFE_NO_PAD.encode(token_utils::get_signature(
            &text,
            &claim.id_type,
            &claim.get_symbol_hash(),
            phrase,
        ));
        self.sig.clone()
    }

    pub(crate) fn get_text(&self) -> String {
        format!(
            "{}|{}|{}|{}|{}|{}|{}|{}",
            self.did,
            self.sys_did,
            self.timestamp,
            self.nickname,
            self.auth_sk,
            self.permissions,
            self.private_paths,
            self.aes_key_encrypted
        )
    }

    pub fn is_default(&self) -> bool {
        self.nickname == "Default" && self.did == "Default_did"
    }

    pub fn is_expired(&self) -> bool {
        let now_sec = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_else(|_| std::time::Duration::from_secs(0))
            .as_secs();
        now_sec > self.timestamp + 3600 * 24 * 30 * 12 * 10
    }
    pub(crate) fn to_json_string(&self) -> String {
        serde_json::to_string(self).unwrap_or("Unknown".to_string())
    }

    pub fn is_pending(&self) -> bool {
        self.is_pending
    }
    pub fn set_pending(&mut self, pending: bool) {
        self.is_pending = pending;
    }
}

impl Default for UserContext {
    fn default() -> Self {
        UserContext {
            did: "Default_did".to_string(),
            sys_did: "Default_sys_did".to_string(),
            timestamp: 0,
            nickname: "Default".to_string(),
            auth_sk: "Default_auth_sk".to_string(),
            permissions: "Default_permissions".to_string(),
            private_paths: "Default_private_paths".to_string(),
            aes_key_encrypted: "Default_aes_key_encrypted".to_string(),
            sig: "Unknown".to_string(),
            is_pending: false,
        }
    }
}
