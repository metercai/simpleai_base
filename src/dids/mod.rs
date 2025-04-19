use std::collections::HashMap;
use std::time::{Duration, SystemTime};
use std::sync::{Arc, Mutex};

use once_cell::sync::Lazy;
use serde::de;
use tokio::runtime::Runtime;
use base58::{ToBase58, FromBase58};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use lazy_static::lazy_static;
use tracing_subscriber::EnvFilter;
use tracing::{error, warn, info, debug, trace};

use crate::dids::claims::{GlobalClaims, LocalClaims, IdClaim};
use crate::dids::cert_center::GlobalCerts;
use crate::dids::token_utils::SYSTEM_BASE_INFO;
use crate::utils::systeminfo::SystemInfo;

pub(crate) mod cert_center;
pub(crate) mod claims;
pub(crate) mod token_utils;

pub(crate) static TOKEN_ENTRYPOINT_URL: &str = "http://120.79.179.136:3030/api_";
pub(crate) static TOKEN_ENTRYPOINT_DID: &str = "6eR3Pzp9e2VSUC6suwPSycQ93qi6T";

pub(crate)  static TOKIO_RUNTIME: Lazy<Runtime> = Lazy::new(|| {
    Runtime::new().expect("Failed to create Tokio runtime")
});
pub(crate)  static REQWEST_CLIENT: Lazy<reqwest::Client> = Lazy::new(|| {
    reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(3)) // 连接超时时间
        .timeout(Duration::from_secs(5)) // 总超时时间
        .build()
        .expect("Failed to build reqwest client")
});

pub(crate)  static REQWEST_CLIENT_SYNC: Lazy<reqwest::blocking::Client> = Lazy::new(|| {
    reqwest::blocking::Client::builder()
        .connect_timeout(Duration::from_secs(3)) // 连接超时时间
        .timeout(Duration::from_secs(5)) // 总超时时间
        .build()
        .expect("Failed to build reqwest blocking client")
});


lazy_static::lazy_static! {
    static ref DID_TOKEN: Arc<Mutex<DidToken>> = Arc::new(Mutex::new(DidToken::new()));
}

#[macro_export]
macro_rules! exchange_key {
    ($did:expr) => {
        format!("{}_exchange", $did)
    };
}

#[macro_export]
macro_rules! issue_key {
    ($did:expr) => {
        format!("{}_issue", $did)
    };
}

#[derive(Clone, Debug)]
pub struct DidToken {
    pub did: String,
    pub node: String,
    pub device: String,
    pub admin: String,
    pub guest: String,
    pub upstream_did: String,
    pub node_mode: String,
    pub sysinfo: SystemInfo,

    claims: Arc<Mutex<GlobalClaims>>,
    certificates: Arc<Mutex<GlobalCerts>>,
    // 专项密钥，源自pk.pem的派生，避免交互时对phrase的依赖，key={did}_{用途}，value={key}|{time}|{sig}, 用途=['exchange', 'issue']
    crypt_secrets: HashMap<String, String>,
    token_db: Arc<Mutex<sled::Db>>,
}

impl DidToken {
    pub fn instance() -> Arc<Mutex<DidToken>> {
        DID_TOKEN.clone()
    }
    pub fn new() -> Self {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(EnvFilter::from_default_env())
            .try_init();

        debug!("init DidToken context started");
        let sysbaseinfo = SYSTEM_BASE_INFO.clone();
        let sysinfo_handle = TOKIO_RUNTIME.spawn(async move {
            SystemInfo::generate().await
        });

        let (system_name, sys_phrase, device_name, device_phrase, guest_name, guest_phrase)
            = get_system_vars();
        
        let db_path = token_utils::get_path_in_sys_key_dir("token.db");
        let config = sled::Config::new()
            .path(db_path)
            .cache_capacity(10_000)
            .flush_every_ms(Some(1000));
        let seld_db: sled::Db = config.open().expect("Failed to open token database");
        let token_db = Arc::new(Mutex::new(seld_db));

        let is_regenerate = {
            let systemskeys = token_utils::SystemKeys::instance();
            let mut systemskeys = systemskeys.read().unwrap();
            systemskeys.is_regenerate()
        };
        let guest_symbol_hash = get_key_symbol_hash("Guest");
        let mut guest_key = match token_utils::exists_key_file("User", &guest_symbol_hash) {
            true => {
                let mut guest_key = token_utils::read_key_or_generate_key("User", &guest_symbol_hash, &guest_phrase, false, true);
                if guest_key == [0u8; 32] {
                    println!("{} [UserBase] Guest key is invalid, it will be regenerate for your system, then the system will restore default.", token_utils::now_string());
                    guest_key = token_utils::read_key_or_generate_key("User", &guest_symbol_hash, &guest_phrase, true, true);
                }
                guest_key
            } 
            false => {
                token_utils::read_key_or_generate_key("User", &guest_symbol_hash, &guest_phrase, true, true)
            }
        };

        let claims = GlobalClaims::instance();
        let (local_did, local_claim, device_did, device_claim, guest_did, guest_claim) = {
            let mut claims = claims.lock().unwrap();
            claims.local_claims.get_sys_dev_guest_did(is_regenerate)
        };
        
        let mut crypt_secrets = HashMap::new();
        let admin = token_utils::load_token_by_authorized2system(&local_did, &mut crypt_secrets);
        let crypt_secrets_len = crypt_secrets.len();
        token_utils::init_user_crypt_secret(&mut crypt_secrets, &local_claim, &sys_phrase);
        token_utils::init_user_crypt_secret(&mut crypt_secrets, &device_claim, &device_phrase);

        let (guest_hash_id, guest_phrase) = token_utils::get_key_hash_id_and_phrase("User", &guest_symbol_hash);
        token_utils::init_user_crypt_secret(&mut crypt_secrets, &guest_claim, &guest_phrase);
        if crypt_secrets.len() > crypt_secrets_len {
            token_utils::save_secret_to_system_token_file(&mut crypt_secrets, &local_did, &admin);
        }
        println!("{} [SimpAI] Guest has loaded: guest_name({}), guest_hash({})", token_utils::now_string(), guest_name, guest_hash_id);


        let sysinfo = TOKIO_RUNTIME.block_on(async {
            sysinfo_handle.await.expect("Sysinfo Task panicked")
        });

        let admin = if !admin.is_empty() && admin == guest_did {
            String::new()
        } else {
            admin
        };

        let upstream_did = if admin == TOKEN_ENTRYPOINT_DID {
            TOKEN_ENTRYPOINT_DID.to_string()
        } else {
            String::new()
        };
        let certificates = GlobalCerts::instance();
        debug!("DidToken context build finished: {} -> crypt_secrets.len={}", 
            crypt_secrets_len, crypt_secrets.len());
        debug!("admin_did: {}, upstream_did: {}", admin, upstream_did);
        
        Self {
            did: local_did,
            node: "".to_string(),
            device: device_did,
            guest: guest_did,
            node_mode: "online".to_string(),
            admin,
            upstream_did,
            sysinfo,
            claims,
            certificates,
            token_db,
            crypt_secrets,
        }
    }

    pub fn get_sys_did(&self) -> String {
        self.did.clone()
    }

    pub fn get_node_id(&self) -> String {
        self.node.clone()
    }
    pub fn set_node_id(&mut self, node_id: &str) {
        self.node = node_id.to_string();
    }
    
    pub fn get_device_did(&self) -> String {
        self.device.clone()
    }

    pub fn get_guest_did(&self) -> String {
        self.guest.clone()
    }

    pub fn get_admin_did(&self) -> String {
        self.admin.clone()
    }

    pub fn set_admin_did(&mut self, admin_did: &str) {
        self.admin = admin_did.to_string();
        token_utils::save_secret_to_system_token_file(&self.crypt_secrets, &self.did, &self.admin);
    }

    pub fn get_upstream_did(&self) -> String {
        self.upstream_did.clone()
    }

    pub fn set_upstream_did(&mut self, upstream_did: &str) {
        self.upstream_did = upstream_did.to_string();
        self.certificates.lock().unwrap().set_upstream_did(upstream_did);
    }

    pub fn get_sysinfo(&self) -> SystemInfo {
        self.sysinfo.clone()
    }
    pub fn get_token_db(&self) -> Arc<Mutex<sled::Db>> {
        self.token_db.clone()
    }

    pub fn get_node_mode(&self) -> String {
        self.node_mode.clone()
    }
    pub fn set_node_mode(&mut self, node_mode: &str) {
        self.node_mode = node_mode.to_string();
    }

    pub fn sign_and_issue_cert_by_admin(&mut self, item: &str, for_did: &str, for_sys_did: &str, memo: &str)
                                        -> (String, String) {
        self.sign_and_issue_cert_by_did(&self.admin.clone(), item, for_did, for_sys_did, memo)
    }

    pub fn sign_and_issue_cert_by_system(&mut self, item: &str, for_did: &str, for_sys_did: &str, memo: &str)
                                         -> (String, String) {
        self.sign_and_issue_cert_by_did(&self.did.clone(), item, for_did, for_sys_did, memo)
    }

    pub fn sign_and_issue_cert_by_did(&mut self, issuer_did: &str, item: &str, for_did: &str, for_sys_did: &str, memo: &str)
                                      -> (String, String) {
        if !issuer_did.is_empty() && !for_did.is_empty() && !for_sys_did.is_empty() && !item.is_empty() && !memo.is_empty() &&
            IdClaim::validity(issuer_did) && IdClaim::validity(for_did) && IdClaim::validity(for_sys_did) &&
            item.len() < 32 && memo.len() < 256 {
            
            let unknown = "Unknown".to_string();
            let cert_secret_base64 = self.crypt_secrets.get(&issue_key!(issuer_did)).unwrap_or(&unknown);
            if cert_secret_base64 != "Unknown" {
                let cert_secret = token_utils::convert_base64_to_key(cert_secret_base64);
                if cert_secret != [0u8; 32] {
                    let item_key = token_utils::derive_key(item.as_bytes(), &token_utils::calc_sha256(&cert_secret)).unwrap_or([0u8; 32]);
                    if item_key != [0u8; 32] {
                        let encrypt_item_key = self.encrypt_for_did(&item_key, for_did, 0);
                        info!("encrypt_item_key: cert_secret.len={}, item_key.len={}, encrypt_item_key.len={}",
                            cert_secret.len(), item_key.len(), URL_SAFE_NO_PAD.decode(encrypt_item_key.clone()).unwrap().len());
                        let memo_base64 = URL_SAFE_NO_PAD.encode(memo.as_bytes());
                        let timestamp = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)
                            .unwrap_or_else(|_| std::time::Duration::from_secs(0)).as_secs();
                        let cert_text = format!("{}|{}|{}|{}|{}|{}", issuer_did, for_did, item, encrypt_item_key, memo_base64, timestamp);
                        let sig = URL_SAFE_NO_PAD.encode(self.sign_by_issuer_key(&cert_text, &URL_SAFE_NO_PAD.encode(cert_secret)));
                        debug!("{} [UserBase] Sign and issue a cert by did: issuer_did={}, for_did={}, for_sys_did={}, item={}, memo={}",
                            token_utils::now_string(), issuer_did, for_did, for_sys_did, item, memo);
                        debug!("cert_secret_key:{}, cert_text:{}, sig:{}", URL_SAFE_NO_PAD.encode(cert_secret), cert_text, sig);
                        if for_sys_did == self.did {
                            return (format!("{}|{}|{}", issuer_did, for_did, item), format!("{}|{}", cert_text, sig))
                        } else {
                            return (format!("{}|{}|{}", issuer_did, for_did, item), self.encrypt_for_did(format!("{}|{}", cert_text, sig).as_bytes(), for_sys_did, 0))
                        }
                    }
                }
            }
        }
        println!("{} [UserBase] Sign and issue a cert by did: invalid params", token_utils::now_string());
        ("Unknown".to_string(), "Unknown".to_string())
    }


    pub fn sign(&mut self, text: &str) -> Vec<u8> {
        self.sign_by_did(text, &self.did.clone(),"not required")
    }

    pub fn sign_by_did(&mut self, text: &str, did: &str, phrase: &str) -> Vec<u8> {
        let claim = self.get_claim(did);
        token_utils::get_signature(text, &claim.id_type, &claim.get_symbol_hash(), phrase)
    }

    pub fn sign_by_issuer_key(&mut self, text: &str, issuer_key: &str) -> Vec<u8> {
        let issuer_key = token_utils::convert_base64_to_key(issuer_key);
        token_utils::get_signature_by_key(text, &issuer_key)
    }

    pub fn verify(&mut self, text: &str, signature: &str) -> bool {
        self.verify_by_did(text, signature, &self.did.clone())
    }

    pub fn verify_by_did(&mut self, text: &str, signature_str: &str, did: &str) -> bool {
        let claim = self.get_claim(did);
        token_utils::verify_signature(text, signature_str, &claim.get_verify_key())
    }

    pub fn cert_verify_by_did(&mut self, text: &str, signature_str: &str, did: &str) -> bool {
        let claim = self.get_claim(did);
        token_utils::verify_signature(text, signature_str, &claim.get_cert_verify_key())
    }

    pub fn encrypt_for_did(&mut self, text: &[u8], for_did: &str, period:u64) -> String {
        let ctext = self.encrypt_bytes_for_did(text, for_did, period);
        URL_SAFE_NO_PAD.encode(ctext)
    }

    pub fn decrypt_by_did(&mut self, ctext: &str, by_did: &str, period:u64) -> String {
        let text = self.decrypt_bytes_by_did(&URL_SAFE_NO_PAD.decode(ctext).unwrap(), by_did, period);
        String::from_utf8_lossy(text.as_slice()).to_string()
    }

    pub fn encrypt_bytes_for_did(&mut self, text: &[u8], for_did: &str, period:u64) -> Vec<u8> {
        let self_crypt_secret = token_utils::convert_base64_to_key(self.crypt_secrets.get(&exchange_key!(self.did)).unwrap());
        let for_did_public = self.get_claim(for_did).get_crypt_key();
        let shared_key = token_utils::get_diffie_hellman_key(for_did_public, self_crypt_secret);
        token_utils::encrypt(text, &shared_key, period)
    }

    pub fn decrypt_bytes_by_did(&mut self, ctext: &[u8], by_did: &str, period:u64) -> Vec<u8> {
        let self_crypt_secret = token_utils::convert_base64_to_key(self.crypt_secrets.get(&exchange_key!(self.did)).unwrap());
        let by_did_public = self.get_claim(by_did).get_crypt_key();
        let shared_key = token_utils::get_diffie_hellman_key(by_did_public, self_crypt_secret);
        token_utils::decrypt(ctext, &shared_key, period)
    }

    pub(crate) fn add_crypt_secret_for_user(&mut self, user_claim: &IdClaim, phrase: &str) -> String{
        self.push_claim(user_claim);
        let user_did = user_claim.gen_did();
        let crypt_secrets_len = self.crypt_secrets.len();
        token_utils::init_user_crypt_secret(&mut self.crypt_secrets, user_claim, phrase);
        if self.crypt_secrets.len() > crypt_secrets_len {
            token_utils::save_secret_to_system_token_file(&mut self.crypt_secrets, &self.did, &self.admin);
        }
        user_did
    }

    pub(crate) fn remove_crypt_secret_for_user(&mut self, user_did: &str) {
        self.pop_claim(&user_did);
        let exchange_key_value = self.crypt_secrets.remove(&exchange_key!(user_did));
        let issue_key_value = self.crypt_secrets.remove(&issue_key!(user_did));
        if exchange_key_value.is_some() || issue_key_value.is_some() {
            let _ = token_utils::save_secret_to_system_token_file(&mut self.crypt_secrets, &self.did, &self.admin);
        }
    }

    pub fn remove_crypt_secrets_for_users(&mut self) -> Vec<String>{
        let admin_did = self.get_admin_did();
        let sys_did = self.get_sys_did();
        let guest_did = self.get_guest_did();

        let mut remove_dids = Vec::new();
        self.crypt_secrets.retain(|key, _| {
            if let Some((did, _)) = key.split_once('_') {
                let retain = did == admin_did || did == sys_did || did == guest_did;
                if !retain {
                    remove_dids.push(did.to_string());
                }
                retain
            } else {
                false
            }
        });
        remove_dids
    }

    pub fn get_local_crypt_text(&mut self, ua_hash: &str) -> [u8; 32] {
        token_utils::calc_sha256(
            format!("{}|{}|{}", ua_hash, self.crypt_secrets[&exchange_key!(self.did)],
                    self.crypt_secrets[&exchange_key!(self.device)]).as_bytes())
    }

    pub fn push_claim(&self, claim: &IdClaim) {
        self.claims.lock().unwrap().push_claim(claim);
    }

    pub fn pop_claim(&self, did: &str) -> IdClaim {
        self.claims.lock().unwrap().local_claims.pop_claim(did)
    }

    pub fn get_claim(&self, for_did: &str) -> IdClaim {
        if for_did.is_empty() {
            debug!("get_claim in Didtoken: for_did is empty");
            return IdClaim::default();
        }
        let mut claims = self.claims.lock().unwrap();
        if self.admin == TOKEN_ENTRYPOINT_DID {
            claims.get_claim_from_local(for_did)
        } else {
            claims.get_claim(for_did)
        }
    }

    pub fn reverse_lookup_did_by_symbol(&self, symbol_hash: [u8; 32]) -> String {
        self.claims.lock().unwrap().local_claims.reverse_lookup_did_by_symbol(&symbol_hash)
    }

    pub fn get_or_create_register_cert(&mut self, user_did: &str) -> String {
        let register_cert = self.certificates.lock().unwrap().get_register_cert(user_did);
        if register_cert != "Unknown".to_string() {
            return register_cert;
        }
        let admin_did = self.admin.clone();
        let node_mode = self.node_mode.clone();
        if user_did == self.guest || (node_mode != "online" && user_did == admin_did)  {
            let system_did = self.did.clone();
            let (_issue_cert_key, issue_cert) = self.sign_and_issue_cert_by_system("Member", &user_did, &system_did, "User");
            let register_cert = {
                let mut certificates = self.certificates.lock().unwrap();
                let _ = certificates.push_user_cert_text(&issue_cert);
                certificates.get_register_cert(user_did)
            };
            println!("sign and issue member cert by system: user_did={}, sys_did={}, node_type={}, cert={}", user_did, system_did, node_mode, register_cert);
            register_cert
        } else {
            "Unknown".to_string()
        }
    }

    pub fn is_registered(&mut self, user_did: &str) -> bool {
        if user_did == "Unknown" {
            return false;
        }
        let cert_str = self.certificates.lock().unwrap().get_register_cert(user_did);
        if cert_str.is_empty() || cert_str == "Unknown" {
            return false;
        }
        let parts: Vec<&str> = cert_str.split('|').collect();
        if parts.len() != 4 {
            return false;
        }
        let encrypt_item_key = parts[0].to_string();
        let memo_base64 = parts[1].to_string();
        let timestamp = parts[2].to_string();
        let signature_str = parts[3].to_string();
        if self.node_mode == "online" {
            let text = format!("{}|{}|{}|{}|{}|{}", TOKEN_ENTRYPOINT_DID, user_did, "Member", encrypt_item_key, memo_base64, timestamp);
            let claim = LocalClaims::load_claim_from_local(TOKEN_ENTRYPOINT_DID);
            debug!("did({}), cert_str({}), cert_text({}), sign_did({})", user_did, cert_str, text, claim.gen_did());
            if token_utils::verify_signature(&text, &signature_str, &claim.get_cert_verify_key()) {
                return true;
            }
        }
        if !self.upstream_did.is_empty() && self.node_mode == "online" {
            let text = format!("{}|{}|{}|{}|{}|{}", self.upstream_did, user_did, "Member", encrypt_item_key, memo_base64, timestamp);
            let claim = LocalClaims::load_claim_from_local(&self.upstream_did);
            debug!("did({}), cert_str({}), cert_text({}), sign_did({})", user_did, cert_str, text, claim.gen_did());
            if token_utils::verify_signature(&text, &signature_str, &claim.get_cert_verify_key()) {
                return true;
            }
        }
        let text = format!("{}|{}|{}|{}|{}|{}", self.get_sys_did(), user_did, "Member", encrypt_item_key, memo_base64, timestamp);
        let claim = LocalClaims::load_claim_from_local(&self.get_sys_did());
        debug!("did({}), cert_str({}), sign_did({})", user_did, cert_str, claim.gen_did());
        debug!("text_system:{}, signature_str:{}, cert_verify_key:{}", text, signature_str, URL_SAFE_NO_PAD.encode(claim.get_cert_verify_key()));
        if token_utils::verify_signature(&text, &signature_str, &claim.get_cert_verify_key()) {
            return true;
        }
        false
    }


}

pub(crate) fn get_system_vars() -> (String, String, String, String, String, String) {
    let zeroed_key: [u8; 32] = [0; 32];

    let (device_name, system_name, guest_name) = get_system_key_name();

    let (dev_hash_id, device_phrase) = token_utils::get_key_hash_id_and_phrase("Device", &zeroed_key);
    let (sys_hash_id, system_phrase) = token_utils::get_key_hash_id_and_phrase("System", &zeroed_key);
    let guest_symbol_hash = get_key_symbol_hash("Guest");
    let (guest_hash_id, guest_phrase) = token_utils::get_key_hash_id_and_phrase("User", &guest_symbol_hash);
    
    (system_name, system_phrase, device_name, device_phrase, guest_name, guest_phrase)
}


pub(crate) fn get_system_key_name() -> (String, String, String)  {
    let sysinfo = token_utils::SYSTEM_BASE_INFO.clone();
    let device_name = token_utils::truncate_nickname(&sysinfo.host_name);
    let guest_name = format!("guest_{}", &sysinfo.disk_uuid[..4]).chars().take(24).collect::<String>();
    let mut system_name = sysinfo.root_name;
    if system_name.len() > 18 {
        system_name = system_name[..18].to_string();
    }
    system_name = token_utils::truncate_nickname(&format!("{}_{}",  system_name, &token_utils::calc_sha256(sysinfo.root_dir.as_bytes()).to_base58()[..4]));

    (device_name, system_name, guest_name)
}

pub(crate) fn get_key_symbol_hash(key_type: &str) -> [u8; 32] {
    let sysinfo = token_utils::SYSTEM_BASE_INFO.clone();
    let (device_name, system_name, guest_name) = get_system_key_name();

    let root_dir = sysinfo.root_dir.clone();
    let disk_uuid = sysinfo.disk_uuid.clone();
    match key_type {
        "Device" => IdClaim::get_symbol_hash_by_source(&device_name, None, Some(disk_uuid.clone())),
        "System" => IdClaim::get_symbol_hash_by_source(&system_name,None,Some(format!("{}:{}", root_dir.clone(), disk_uuid.clone()))),
        "Guest" => IdClaim::get_symbol_hash_by_source(&guest_name,None,Some(format!("{}:{}", root_dir.clone(), disk_uuid.clone()))),
        _ => [0u8; 32],
    }
}
