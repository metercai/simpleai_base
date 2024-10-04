use std::fmt;
use std::fs;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use base58::*;
use sha2::Digest;
use ripemd::Ripemd160;
use serde_derive::{Serialize, Deserialize};
use crate::env_utils;
use pyo3::prelude::*;


#[derive(Clone, Debug, Serialize, Deserialize)]
#[pyclass]
pub struct IdClaim {
    pub nickname: String,
    pub verify_key: [u8; 32],   // 验签公钥
    pub fingerprint: [u8; 32],
    pub telephone_hash: [u8; 32],
    pub id_card_hash: [u8; 32],
    pub face_image_hash: [u8; 32],
    pub file_hash_hash: [u8; 32],
    pub crypt_key: [u8; 32],    // 交换密钥
    pub id_type: String
}

#[pymethods]
impl IdClaim {
    #[new]
    pub fn new(id_type: &str, phrase: &str, nickname: &str, telephone_hash: [u8; 32], id_card_hash: [u8; 32], face_image_hash: [u8; 32], file_hash_hash: [u8; 32]) -> Self{
        let zeroed_key: [u8; 32] = [0; 32];
        let telephone_base64 = URL_SAFE_NO_PAD.encode(telephone_hash);
        let id_card_base64 = URL_SAFE_NO_PAD.encode(id_card_hash);
        let face_image_base64 = URL_SAFE_NO_PAD.encode(face_image_hash);
        let file_hash_base64 = URL_SAFE_NO_PAD.encode(file_hash_hash);
        let fingerprint_str = format!("telephone:{},id_card:{},face_image:{},file_hash:{}",
                                      telephone_base64, id_card_base64, face_image_base64, file_hash_base64);
        let fingerprint_hash = env_utils::calc_sha256(&fingerprint_str.as_bytes());

        let verify_key = env_utils::get_verify_key(id_type, &telephone_hash, phrase).unwrap_or_else(|_| zeroed_key);

        Self{
            nickname: nickname.to_string(),
            verify_key: verify_key,
            fingerprint: fingerprint_hash,
            telephone_hash,
            id_card_hash,
            face_image_hash,
            file_hash_hash,
            crypt_key: [0; 32],
            id_type: id_type.to_string()
        }
    }

    pub fn gen_did(&self) -> String {
        let verify_key_base64 = URL_SAFE_NO_PAD.encode(self.verify_key);
        let fingerprint_base64 = URL_SAFE_NO_PAD.encode(self.fingerprint);
        let did_claim_str = format!("nickname:{},verify_key:{},fingerprint:{}",
                                    self.nickname, verify_key_base64, fingerprint_base64);
        let mut hasher = Ripemd160::new();
        hasher.update(env_utils::calc_sha256(&did_claim_str.as_bytes()));
        let did = hasher.finalize();
        did.to_base58()
    }

    pub fn set_crypt_key_and_save_to_file(&mut self, crypt_secret: [u8; 32]) {
        let zeroed_key: [u8; 32] = [0; 32];
        let crypt_key = env_utils::get_crypt_key(crypt_secret).unwrap_or_else(|_| zeroed_key);
        self.crypt_key = crypt_key;
        let did_file_path = env_utils::get_path_in_sys_key_dir(format!("{}_{}.did", self.id_type.to_lowercase(), self.gen_did()).as_str());
        fs::write(did_file_path, self.to_json()).unwrap();
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


#[derive(Clone, Debug, Serialize, Deserialize)]
#[pyclass]
pub struct UserContext {
    nickname: String,
    auth_sk: String,        // 授权密钥
    permissions: String,    // 权限
    private_paths: String,  // 个性化目录
    aes_key_encrypted: String,   // 加密的aes密钥
}

#[pymethods]
impl UserContext {
    #[new]
    pub fn new(nickname: &str, permissions: &str, private_paths: &str) -> Self {
        Self {
            nickname: nickname.to_string(),
            auth_sk: String::new(),
            permissions: permissions.to_string(),
            private_paths: private_paths.to_string(),
            aes_key_encrypted: String::new(),
        }
    }


    pub fn get_crypt_key(&self) -> [u8; 32] {
        let auth_sk = URL_SAFE_NO_PAD.decode(self.auth_sk.as_bytes()).unwrap_or_else(|_| [0u8; 40].to_vec());
        let key = &auth_sk[..32];
        let expire = u64::from_le_bytes(auth_sk[32..].try_into().unwrap_or_else(|_| [0; 8]));
        env_utils::hkdf_key_deadline(&key, expire)
    }

    pub fn set_auth_sk(&mut self, auth_sk: &str) {
        self.auth_sk = auth_sk.to_string();
    }

    pub fn set_auth_sk_with_secret(&mut self, secret_key: &str, expire: u64) {
        let secret_key_bytes = env_utils::convert_vec_to_key(&URL_SAFE_NO_PAD.decode(secret_key).unwrap_or([0u8; 32].to_vec()));
        self.auth_sk = env_utils::convert_to_auth_sk_in_context(
            &secret_key_bytes, expire);
    }

    pub fn get_private_paths(&self) -> Vec<String> {
        serde_json::from_str(&self.private_paths).unwrap_or_default()
    }

    pub fn get_aes_key_encrypted(&self) -> String {
        self.aes_key_encrypted.clone()
    }

    pub fn set_aes_key_encrypted(&mut self, key: &str) {
        self.aes_key_encrypted = key.to_string();
    }


    pub fn get_text(&self) -> String {
        format!("{}{}{}{}{}", self.nickname, self.auth_sk, self.permissions,
                self.private_paths, self.aes_key_encrypted)
    }

    pub fn is_default(&self) -> bool {
        self.nickname == "Default"
    }
}

impl Default for UserContext {
    fn default() -> Self {
        UserContext {
            nickname: "Default".to_string(),
            auth_sk: "Default_auth_sk".to_string(),
            permissions: "Default_permissions".to_string(),
            private_paths: "Default_private_paths".to_string(),
            aes_key_encrypted: "Default_aes_key_encrypted".to_string(),
        }
    }
}
pub struct FileToken {
    pub muid: Vec<u8>,
    pub did: Vec<u8>,
    pub key: Vec<u8>,
    pub expiry: u64,
    pub sig: Vec<u8>,
}
