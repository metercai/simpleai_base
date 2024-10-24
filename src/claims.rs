use std::collections::HashMap;
use std::fmt;
use std::fs;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use base58::*;
use sha2::Digest;
use ripemd::Ripemd160;
use serde_derive::{Serialize, Deserialize};
use serde_json::{json, Value};
use crate::{token, token_utils};

use pyo3::prelude::*;

lazy_static::lazy_static! {
    static ref GLOBAL_CLAIMS: Arc<Mutex<GlobalClaims>> = Arc::new(Mutex::new(GlobalClaims::new()));
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GlobalClaims {
    claims: HashMap<String, IdClaim>,       // 留存本地的身份自证
    sys_did: String,                      // 系统did
    device_did: String,                    // 设备id
    file_crypt_key: String,                // 文件加密密钥
}

impl GlobalClaims {
    fn new() -> Self {
        let mut claims = HashMap::new();
        let did_file_path = token_utils::get_path_in_sys_key_dir("user_xxxxx.did");
        let root_path = match  did_file_path.parent() {
            Some(parent) => {
                if parent.exists() {
                    parent
                } else {
                    fs::create_dir_all(parent).unwrap();
                    parent
                }
            },
            None => panic!("{}", format!("File path does not have a parent directory: {:?}", did_file_path)),
        };
        match fs::read_dir(root_path) {
            Ok(entries) => {
                for entry in entries {
                    match entry {
                        Ok(entry) => {
                            let path = entry.path();
                            if let Some(file_name) = path.file_name().and_then(|name| name.to_str()) {
                                if file_name.ends_with(".did") {
                                    match fs::read_to_string(path) {
                                        Ok(content) => {
                                            match serde_json::from_str::<IdClaim>(&content) {
                                                Ok(claim) => {
                                                    claims.insert(claim.gen_did(), claim.clone());
                                                    if *token_utils::VERBOSE_INFO {
                                                        println!("Load did: {}", claim.to_json_string());
                                                    }
                                                },
                                                Err(e) => {
                                                    eprintln!("Failed to parse JSON: {}", e);
                                                }
                                            }
                                        },
                                        Err(e) => {
                                            eprintln!("Failed to read file: {}", e);
                                        }
                                    }
                                }
                            }
                        },
                        Err(e) => {
                            eprintln!("Failed to read directory entry: {}", e);
                        }
                    }
                }
            },
            Err(e) => {
                eprintln!("Failed to read directory: {}", e);
            }
        }

        if *token_utils::VERBOSE_INFO {
            println!("Loaded claims.len={}", claims.len());
        }

        GlobalClaims {
            claims,
            sys_did: String::new(),
            device_did: String::new(),
            file_crypt_key: String::new(),
        }
    }

    pub(crate) fn set_system_device_did(&mut self, sys_did: &str, device_id: &str)  {
        self.sys_did = sys_did.to_string();
        self.device_did = device_id.to_string();
    }
    pub fn instance() -> Arc<Mutex<GlobalClaims>> {
        GLOBAL_CLAIMS.clone()
    }

    pub fn get_file_crypt_key(&mut self) -> [u8; 32] {
        if self.file_crypt_key.is_empty() {
            self.file_crypt_key = URL_SAFE_NO_PAD.encode(token_utils::get_file_crypt_key());
        };
        token_utils::convert_vec_to_key(&URL_SAFE_NO_PAD.decode(self.file_crypt_key.as_bytes()).unwrap())
    }

    pub fn local_len(&self) -> usize {
        self.claims.len()
    }

    pub fn push_claim(&mut self, claim: IdClaim) {
        self.claims.insert(claim.gen_did(), claim.clone());
        let did_file_path = token_utils::get_path_in_sys_key_dir(&format!("{}_{}.did", claim.id_type.to_lowercase(), claim.gen_did()));
        fs::write(did_file_path, claim.to_json_string()).unwrap()
    }

    pub fn pop_claim(&mut self, did: &str) -> IdClaim {
        let claim = self.get_claim_from_local(did);
        self.claims.remove(did);
        let did_file_path = token_utils::get_path_in_sys_key_dir(&format!("{}_{}.did", claim.id_type.to_lowercase(), did));
        if let Err(e) = fs::remove_file(did_file_path) {
            eprintln!("无法删除文件: {}", e);
        }
        claim
    }

    pub(crate) fn generate_did_claim(id_type: &str, nickname: &str, id_card: Option<String>, telephone: Option<String>, phrase: &str)
                                     -> IdClaim {
        let id_card = id_card.unwrap_or("-".to_string());
        let telephone = telephone.unwrap_or("-".to_string());
        let id_card_hash = token_utils::calc_sha256(format!("{}:id_card:{}", nickname, id_card).as_bytes());
        let telephone_hash = token_utils::calc_sha256(format!("{}:telephone:{}", nickname, telephone).as_bytes());
        let face_image_hash = token_utils::calc_sha256(format!("{}:face_image:-", nickname).as_bytes());
        let file_hash_hash = token_utils::calc_sha256(format!("{}:file_hash:-", nickname).as_bytes());
        let claim = IdClaim::new(id_type, &phrase, nickname, telephone_hash, id_card_hash, face_image_hash, file_hash_hash);
        claim
    }

    pub fn get_claim_from_local(&mut self, did: &str) -> IdClaim {
        if !self.claims.contains_key(did) {
            let claim = GlobalClaims::load_claim_from_local(did);
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

    pub fn get_claim_from_global(&mut self, did: &str) -> IdClaim {
        if !self.claims.contains_key(did) {
            let claim = GlobalClaims::load_claim_from_local(did);
            if !claim.is_default() {
                self.claims.insert(did.to_string(), claim.clone());
                claim
            } else {
                // get claim from global
                let mut request: Value = json!({});
                request["user_symbol"] = serde_json::to_value("").unwrap();
                request["user_did"] = serde_json::to_value(did).unwrap();

                println!("get claim from global with did: {}", did);
                let result = token::TOKIO_RUNTIME.block_on(async {
                    match token::REQWEST_CLIENT.post(
                        format!("{}{}", token_utils::TOKEN_TM_URL, "get_use_claim"))
                        .header("Sys-Did", self.sys_did.to_string())
                        .header("Dev-Did", self.device_did.to_string())
                        .body(serde_json::to_string(&request).unwrap())
                        .send().await {
                        Ok(res) => {
                            match res.text().await {
                                Ok(text) => text,
                                Err(e) => {
                                    println!("Failed to register system to  token.tm: {}", e);
                                    serde_json::to_string(&IdClaim::default()).unwrap()
                                }
                            }
                        },
                        Err(e) => {
                            println!("Failed to register system to  token.tm: {}", e);
                            serde_json::to_string(&IdClaim::default()).unwrap()
                        }
                    }
                });


                let claim = serde_json::from_str(&result).unwrap_or(IdClaim::default());
                self.push_claim(claim.clone());
                claim
            }
        } else {
            self.claims.get(did).unwrap().clone()
        }

    }

    fn load_claim_from_local(did: &str) -> IdClaim {
        let user_did_file_path = token_utils::get_path_in_sys_key_dir(
            format!("user_{}.did", did).as_str());
        let sys_did_file_path = token_utils::get_path_in_sys_key_dir(
            format!("system_{}.did", did).as_str());
        let device_did_file_path = token_utils::get_path_in_sys_key_dir(
            format!("device_{}.did", did).as_str());

        let did_file_path = if user_did_file_path.exists() {
            user_did_file_path
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

    pub fn reverse_lookup_did_by_symbol(&self, symbol_hash: &[u8; 32]) -> String {
        for (did, id_claim) in self.claims.iter() {
            if id_claim.get_symbol_hash() == *symbol_hash {
                return did.to_string();
            }
        }
        "Unknown".to_string()
    }

    pub fn reverse_lookup_did_by_nickname(&self, id_type: &str, nickname: &str) -> String {
        for (did, id_claim) in self.claims.iter() {
            if id_claim.nickname == nickname && id_claim.id_type == id_type {
                return did.to_string();
            }
        }
        "Unknown".to_string()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[pyclass]
pub struct IdClaim {
    pub id_type: String,
    pub nickname: String,
    pub verify_key: String,   // 验签公钥
    pub crypt_key: String,    // 交换公钥
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
    pub fn new(id_type: &str, phrase: &str, nickname: &str, telephone_hash: [u8; 32], id_card_hash: [u8; 32], face_image_hash: [u8; 32], file_hash_hash: [u8; 32]) -> Self{
        let telephone_base64 = URL_SAFE_NO_PAD.encode(telephone_hash);
        let id_card_base64 = URL_SAFE_NO_PAD.encode(id_card_hash);
        let face_image_base64 = URL_SAFE_NO_PAD.encode(face_image_hash);
        let file_hash_base64 = URL_SAFE_NO_PAD.encode(file_hash_hash);
        let fingerprint_str = format!("telephone:{},id_card:{},face_image:{},file_hash:{}",
                                      telephone_base64, id_card_base64, face_image_base64, file_hash_base64);
        let fingerprint = URL_SAFE_NO_PAD.encode(token_utils::calc_sha256(&fingerprint_str.as_bytes()));

        let symbol_hash = token_utils::calc_sha256(format!("{}|{}", nickname, telephone_base64).as_bytes());
        let verify_key = URL_SAFE_NO_PAD.encode(token_utils::get_verify_key(id_type, &symbol_hash, phrase));
        let crypt_secret = token_utils::get_specific_secret_key("exchange", id_type, &symbol_hash, phrase);
        println!("IdClaim new() get {} exchange_key: {}", URL_SAFE_NO_PAD.encode(symbol_hash), URL_SAFE_NO_PAD.encode(crypt_secret));
        let crypt_key = URL_SAFE_NO_PAD.encode(token_utils::get_crypt_key(crypt_secret));
        let now_sec = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_else(|_| std::time::Duration::from_secs(0)).as_secs();
        let text_sig = format!("nickname:{},verify_key:{},crypt_key:{},fingerprint:{},timestamp:{}",
                               nickname, verify_key, crypt_key, fingerprint, now_sec);
        let signature = URL_SAFE_NO_PAD.encode(token_utils::get_signature(&text_sig, id_type, &symbol_hash, phrase));

        Self{
            id_type: id_type.to_string(),
            nickname: nickname.to_string(),
            verify_key,
            crypt_key,
            fingerprint,
            timestamp: now_sec,
            signature,
            telephone_hash: telephone_base64,
            id_card_hash: id_card_base64,
            face_image_hash: face_image_base64,
            file_hash_hash: file_hash_base64,
        }
    }

    fn get_format_text(&self) -> String {
        format!("nickname:{},verify_key:{},crypt_key:{},fingerprint:{},timestamp:{}",
                self.nickname, self.verify_key, self.crypt_key, self.fingerprint, self.timestamp)
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
        token_utils::verify_signature(&self.get_format_text(), &self.signature, &self.get_verify_key())
    }

    #[staticmethod]
    pub fn validity(did: &str) -> bool {
        let did_bytes = did.from_base58().unwrap_or("Unknown".to_string().into_bytes());
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

    pub(crate) fn get_crypt_key(&self) -> [u8; 32] {
        token_utils::convert_base64_to_key(&self.crypt_key)
    }

    #[staticmethod]
    pub fn get_symbol_hash_by_source(nickname: &str, telephone: &str) -> [u8; 32] {
        let telephone_hash = URL_SAFE_NO_PAD.encode(token_utils::calc_sha256(
            format!("{}:telephone:{}", nickname, telephone).as_bytes()));
        token_utils::calc_sha256(format!("{}|{}", nickname, telephone_hash).as_bytes())
    }

    pub fn get_symbol_hash(&self) -> [u8; 32] {
        token_utils::calc_sha256(format!("{}|{}", self.nickname, self.telephone_hash).as_bytes())
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
            id_type: "Default_User".to_string(),
            verify_key: "Default_verify_key".to_string(),
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
    sys_did: String,                // 授权给哪个系统
    nickname: String,
    auth_sk: String,                // 授权密钥
    permissions: String,            // 权限
    private_paths: String,          // 个性化目录
    aes_key_encrypted: String,      // 加密后的加密密钥
    sig: String,
}

#[pymethods]
impl UserContext {
    #[new]
    pub fn new(did: &str, sys_did: &str, nickname: &str, permissions: &str, private_paths: &str) -> Self {
        Self {
            did: did.to_string(),
            sys_did: sys_did.to_string(),
            nickname: nickname.to_string(),
            auth_sk: String::new(),
            permissions: permissions.to_string(),
            private_paths: private_paths.to_string(),
            aes_key_encrypted: String::new(),
            sig: String::new(),
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

    pub(crate) fn get_permissions(&self) -> String {
        self.permissions.clone()
    }

    pub(crate) fn get_crypt_key(&self) -> [u8; 32] {
        let auth_sk = URL_SAFE_NO_PAD.decode(self.auth_sk.as_bytes()).unwrap_or_else(|_| [0u8; 40].to_vec());
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
            &secret_key_bytes, expire));
    }

    pub fn get_private_paths(&self) -> Vec<String> {
        serde_json::from_str(&self.private_paths).unwrap_or_default()
    }

    pub fn get_private_paths_list(&self, catalog: &str) -> Vec<String> {
        let catalog_paths = token_utils::get_path_in_user_dir(self.did.as_str(), catalog);
        let filters = &[];
        let suffixes = &[".json"];
        token_utils::filter_files(&catalog_paths, filters, suffixes)
    }

    pub fn get_private_paths_datas(&self, catalog: &str, filename: &str) -> String {
        let file_paths = token_utils::get_path_in_user_dir(self.did.as_str(), catalog).join(filename);
        match file_paths.exists() {
            true => {
                let crypt_key = self.get_crypt_key();
                match fs::read(file_paths) {
                    Ok(raw_data) => {
                        let data = token_utils::decrypt(&raw_data, &crypt_key, 0);
                        let private_datas: Value = serde_json::from_slice(&data).unwrap_or(serde_json::json!({}));
                        private_datas.to_string()
                    },
                    Err(_) => "Unknowns".to_string(),
                }
            }
            false => "Unknowns".to_string(),
        }
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

    pub(crate) fn set_sig(&mut self, sig: &str) {
        self.sig = sig.to_string();
    }

    pub(crate) fn get_text(&self) -> String {
        format!("{}|{}|{}|{}|{}|{}|{}", self.did, self.sys_did, self.nickname, self.auth_sk, self.permissions,
                self.private_paths, self.aes_key_encrypted)
    }

    pub fn is_default(&self) -> bool {
        self.nickname == "Default"
    }

    pub(crate) fn to_json_string(&self) -> String {
        serde_json::to_string(self).unwrap_or("Unknown".to_string())
    }

}

impl Default for UserContext {
    fn default() -> Self {
        UserContext {
            did: "Default_did".to_string(),
            sys_did: "Default_sys_did".to_string(),
            nickname: "Default".to_string(),
            auth_sk: "Default_auth_sk".to_string(),
            permissions: "Default_permissions".to_string(),
            private_paths: "Default_private_paths".to_string(),
            aes_key_encrypted: "Default_aes_key_encrypted".to_string(),
            sig: "Unknown".to_string(),
        }
    }
}
