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
    pub id_type: String,
    pub nickname: String,
    verify_key: String,   // 验签公钥
    fingerprint: String,
    telephone_hash: String,
    id_card_hash: String,
    face_image_hash: String,
    file_hash_hash: String,
    crypt_key: String,    // 交换公钥，crypt_key+sys_did+sig, 授予某个系统的交换密钥
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
        let symbol_hash = env_utils::get_symbol_hash(nickname, &telephone_base64);

        let verify_key = env_utils::get_verify_key(id_type, &symbol_hash, phrase).unwrap_or_else(|_| zeroed_key);

        Self{
            nickname: nickname.to_string(),
            verify_key: URL_SAFE_NO_PAD.encode(verify_key),
            fingerprint: URL_SAFE_NO_PAD.encode(fingerprint_hash),
            telephone_hash: telephone_base64,
            id_card_hash: id_card_base64,
            face_image_hash: face_image_base64,
            file_hash_hash: file_hash_base64,
            crypt_key: URL_SAFE_NO_PAD.encode([0; 32]),
            id_type: id_type.to_string()
        }
    }

    pub fn gen_did(&self) -> String {
        let did_claim_str = format!("nickname:{},verify_key:{},fingerprint:{}",
                                    self.nickname, self.verify_key, self.fingerprint);
        let mut hasher = Ripemd160::new();
        hasher.update(env_utils::calc_sha256(&did_claim_str.as_bytes()));
        let did = hasher.finalize();
        did.to_base58()
    }

    pub fn get_verify_key(&self) -> [u8; 32] {
        env_utils::convert_base64_to_key(&self.verify_key)
    }

    pub fn get_crypt_key(&self) -> [u8; 32] {
        env_utils::convert_base64_to_key(&self.crypt_key)
    }

    pub fn get_id_card_hash(&self) -> [u8; 32] {
        env_utils::convert_base64_to_key(&self.id_card_hash)
    }

    pub fn get_telephone_hash(&self) -> [u8; 32] {
        env_utils::convert_base64_to_key(&self.telephone_hash)
    }

    pub fn get_symbol_hash(&self) -> [u8; 32] {
        env_utils::get_symbol_hash(&self.nickname, &self.telephone_hash)
    }

    pub fn set_crypt_key_and_save_file(&mut self, crypt_secret: [u8; 40]) {
        let zeroed_key: [u8; 32] = [0; 32];
        let crypt_key = env_utils::get_crypt_key(crypt_secret).unwrap_or_else(|_| zeroed_key);
        self.crypt_key = URL_SAFE_NO_PAD.encode(crypt_key);
        let did_file_path = env_utils::get_path_in_sys_key_dir(format!("{}_{}.did", self.id_type.to_lowercase(), self.gen_did()).as_str());
        fs::write(did_file_path, self.to_json()).unwrap();
    }

    pub fn to_json(&self) -> String {
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
    nickname: String,
    auth_sk: String,        // 授权密钥
    permissions: String,    // 权限
    private_paths: String,  // 个性化目录
    aes_key_encrypted: String,   // 加密后的加密密钥
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
        let secret_key_bytes = env_utils::convert_base64_to_key(secret_key);
        self.auth_sk = URL_SAFE_NO_PAD.encode(env_utils::convert_to_sk_with_expire(
            &secret_key_bytes, expire));
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

    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or("Unknown".to_string())
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
