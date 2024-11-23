use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tracing::{error, warn, info, debug, trace};

use crate::claims::{IdClaim, GlobalClaims};
use crate::token_utils;

lazy_static::lazy_static! {
    static ref GLOBAL_CERTS: Arc<Mutex<GlobalCerts>> = Arc::new(Mutex::new(GlobalCerts::new()));
}

#[derive(Clone, Debug)]
pub struct GlobalCerts {
    // 所以证书(他证), key={issue_did}|{for_did}|{用途}，value={encrypted_key}|{memo}|{time}|{sig},
    // encrypted_key由for_did交换派生密钥加密, sig由证书密钥签，用途=['Member']
    user_certs: HashMap<String, String>, // 留存本地的证书(他证)
    // 颁发的certificate，key={issue_did}|{for_did}|{用途}，value=encrypt_with_for_sys_did({issue_did}|{for_did}|{用途}|{encrypted_key}|{memo}|{time}|{sig})
    // encrypted_key由for_did交换派生密钥加密, sig由证书密钥签, 整体由接受系统did的交换派生密钥加密
    issued_certs: HashMap<String, String>,
    token_db: Arc<Mutex<sled::Db>>,
    claims: Arc<Mutex<GlobalClaims>>,
    sys_did: String,
}

impl GlobalCerts {
    pub fn new() -> Self {
        let db_path = token_utils::get_path_in_sys_key_dir("token.db");
        let config = sled::Config::new()
            .path(db_path)
            .cache_capacity(10_000)
            .flush_every_ms(Some(1000));
        let seld_db: sled::Db = config.open().expect("Failed to open token database");
        let token_db = Arc::new(Mutex::new(seld_db));
        let claims = GlobalClaims::instance();

        Self {
            user_certs: HashMap::new(),
            issued_certs: HashMap::new(),
            token_db,
            claims,
            sys_did: String::new(),
        }
    }

    pub fn instance() -> Arc<Mutex<GlobalCerts>> {
        GLOBAL_CERTS.clone()
    }

    pub fn load_certificates_from_local(&mut self, sys_did: &str) {
        self.sys_did = sys_did.to_string();
        let _ = token_utils::load_token_of_user_certificates(sys_did, &mut self.user_certs);
        let _ = token_utils::load_token_of_issued_certs(sys_did, &mut self.issued_certs);
    }

    pub fn get_token_db(&self) -> Arc<Mutex<sled::Db>> {
        self.token_db.clone()
    }

    pub fn get_register_cert(&self, for_did: &str) -> String {
        self.get_member_cert(token_utils::TOKEN_TM_DID, for_did)
    }

    pub fn get_member_cert(&self, issue_did: &str, for_did: &str) -> String {
        self.get_user_cert(issue_did, for_did, "Member")
    }

    pub fn get_user_cert(&self, issue_did: &str, for_did: &str, item: &str) -> String {
        if !issue_did.is_empty() && !for_did.is_empty() &&
            IdClaim::validity(issue_did) && IdClaim::validity(for_did) {
            let cert_key = format!("{}|{}|{}", issue_did, for_did, item);
            let cert = self.user_certs.get(&cert_key).unwrap_or(&"Unknown".to_string()).clone();
            debug!("get_user_cert, cert_key: {}, {}", cert_key, cert);
            cert
        } else { "Unknown".to_string()  }
    }

    pub fn push_user_cert_text(&mut self, user_cert_text: &str) -> String {
        let (cert_key, certs_value) = GlobalCerts::parse_user_certs(user_cert_text);
        if cert_key != "Unknown" && certs_value != "Unknown" {
            self.push_user_cert(&cert_key, &certs_value)
        } else {  "Unknown".to_string() }
    }

    pub fn push_user_cert(&mut self, cert_key: &str, cert: &str) -> String {
        let cert_key_array: Vec<&str> = cert_key.split("|").collect();
        if cert_key_array.len() > 2 && IdClaim::validity(cert_key_array[0]) && IdClaim::validity(cert_key_array[1]) {
            self.user_certs.insert(cert_key.to_string(), cert.to_string());
            token_utils::save_user_certificates_to_file(&self.sys_did, &self.user_certs);
            let mut claims = self.claims.lock().unwrap();
            claims.get_claim_from_global(cert_key_array[0]);
            claims.get_claim_from_global(cert_key_array[1]);
            cert_key_array[1].to_string()
        } else { "Unknown".to_string()  }
    }

    pub fn push_issue_cert(&mut self, issue_key: &str, issue_cert: &str) -> String{
        let issue_key_array: Vec<&str> = issue_key.split("|").collect();
        if issue_key_array.len() > 2 && IdClaim::validity(issue_key_array[0]) && IdClaim::validity(issue_key_array[1]) {
            self.issued_certs.insert(issue_key.to_string(), issue_cert.to_string());
            token_utils::save_issued_certs_to_file(&self.sys_did, &self.issued_certs);
            let mut claims = self.claims.lock().unwrap();
            claims.get_claim_from_global(issue_key_array[0]);
            claims.get_claim_from_global(issue_key_array[1]);
            issue_key_array[1].to_string()
        } else { "Unknown".to_string()  }
    }



    pub(crate) fn filter_user_certs(&self, user_did: &str, item: &str) -> HashMap<String, String> {
        let filter_str = match item {
            "*" => format!("|{}|", user_did),
            &_ => format!("|{}|{}", user_did, item), };

        self.user_certs
            .iter()
            .filter(|(key, _value)| key.contains(filter_str.as_str()))
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect()
    }

    pub(crate) fn filter_issuer_certs(&self, issuer_did: &str, item: &str) -> HashMap<String, String> {
        let filter_str = format!("{}|", issuer_did);
        let filted_certs = self.issued_certs
            .iter()
            .filter(|(key, _value)| key.starts_with(filter_str.as_str()))
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect();
        if item == "*" {
            filted_certs
        } else {
            let filter_str = format!("|{}", item);
            self.issued_certs
                .iter()
                .filter(|(key, _value)| key.ends_with(filter_str.as_str()))
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect()
        }
    }

    pub(crate) fn parse_user_certs(certificate_string: &str) -> (String, String) {
        let certs_array: Vec<&str> = certificate_string.split("|").collect();
        if certs_array.len() >= 7 && IdClaim::validity(certs_array[0]) && IdClaim::validity(certs_array[1]){
            let certs_key = format!("{}|{}|{}", certs_array[0], certs_array[1], certs_array[2]);
            let certs_value = format!("{}|{}|{}|{}", certs_array[3], certs_array[4], certs_array[5], certs_array[6]);
            (certs_key, certs_value)
        } else {
            ("Unknown".to_string(), "Unknown".to_string())
        }
    }

    pub fn parse_issue_cert(cert: &str) -> (String, String, String, String, String, u64, String) {
        let mut items = cert.split("|");
        let issuer_did = items.next().unwrap().to_string();
        let for_did = items.next().unwrap().to_string();
        let item = items.next().unwrap().to_string();
        let encrypt_item_key = items.next().unwrap().to_string();
        let memo = items.next().unwrap().to_string();
        let timestamp = items.next().unwrap().parse::<u64>().unwrap();
        let sig = items.next().unwrap().to_string();
        (issuer_did, for_did, item, encrypt_item_key, memo, timestamp, sig)
    }
}