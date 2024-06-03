use std::collections::HashMap;
use std::fs::File;
use std::io::{self, Error, ErrorKind};
use std::path::Path;
use std::env;
use std::net::{IpAddr, Ipv4Addr, TcpListener, SocketAddr, TcpStream};
use std::str::FromStr;
use std::time::SystemTime;
use libp2p::identity::ed25519;
use serde_json::Value;

use pkcs8::{EncryptedPrivateKeyInfo, PrivateKeyInfo, LineEnding, ObjectIdentifier, SecretDocument};

//use pnet::datalink::interfaces;
use ed25519_dalek::{VerifyingKey, SigningKey, Signer};
use x25519_dalek::{StaticSecret, PublicKey};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use sha2::{Sha256, Digest};
use hkdf::Hkdf;
use rand::{Rng, rngs::SmallRng};
use rand::SeedableRng;
use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Key };
use argon2::Argon2;
use tokio::time::{self, Duration};
use tracing::info;
use lazy_static::lazy_static;
use zeroize::Zeroizing;

use crate::error::TokenError;
use crate::systeminfo::SystemBaseInfo;

pub const ALGORITHM_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.112");

/// Ed25519 Algorithm Identifier.
pub const ALGORITHM_ID: pkcs8::AlgorithmIdentifierRef<'static> = pkcs8::AlgorithmIdentifierRef {
    oid: ALGORITHM_OID,
    parameters: None,
};

lazy_static! {
    pub static ref SYSTEM_BASE_INFO: SystemBaseInfo = SystemBaseInfo::generate();
}
pub(crate) fn read_keypaire_or_generate_keypaire() -> Result<ed25519::Keypair, Box<dyn std::error::Error>> {
    Ok(ed25519::Keypair::from(ed25519::SecretKey::try_from_bytes(read_key_or_generate_key()?)?))
}
fn read_key_or_generate_key() -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let sysinfo =  &SYSTEM_BASE_INFO;

    let password = format!("{}:{}@{}/{}/{}/{}/{}/{}/{}/{}", sysinfo.root_dir, sysinfo.exe_name, sysinfo.host_name,
                           sysinfo.os_name, sysinfo.os_type, sysinfo.cpu_brand, sysinfo.cpu_cores,
                           sysinfo.ram_total + sysinfo.gpu_memory, sysinfo.gpu_name, sysinfo.disk_uuid);
    //tracing::info!("password: {password}");

    let file_path = Path::new(".token_user.pem");
    let pem_label = "SIMPLE_AI_USER_KEY";
    let private_key = match file_path.exists() {
        false => {
            let mut csprng = OsRng {};
            let secret_key = SigningKey::generate(&mut csprng).to_bytes();
            PrivateKeyInfo::new(ALGORITHM_ID, &secret_key)
                .encrypt(csprng, &password.as_bytes())?
                .write_pem_file(file_path, pem_label, LineEnding::default())?;
            secret_key
        }
        true => {
            let Ok((_, s_doc)) = SecretDocument::read_pem_file(file_path) else { todo!() };
            let mut pkey: [u8; 32] = [0; 32];
            let private_key = match EncryptedPrivateKeyInfo::try_from(s_doc.as_bytes()).unwrap().decrypt(&password.as_bytes()) {
                Ok(key) => {
                    pkey.copy_from_slice(PrivateKeyInfo::try_from(key.as_bytes()).unwrap().private_key)
                },
                Err(e) => {
                    let mut csprng = OsRng {};
                    let secret_key = SigningKey::generate(&mut csprng).to_bytes();
                    PrivateKeyInfo::new(ALGORITHM_ID, &secret_key)
                        .encrypt(csprng, &password.as_bytes())?
                        .write_pem_file(file_path, pem_label, LineEnding::default())?;
                    pkey.copy_from_slice(secret_key.as_slice())
                }
            };

            //let pkinfo = PrivateKeyInfo::try_from(pkey)?;
            //let mut pk_array: [u8; 32] = [0; 32];
            //pk_array.copy_from_slice(pkinfo.private_key);
            pkey
        }
    };

    Ok(private_key.try_into().unwrap())
}


pub(crate) async fn get_ipaddr_from_stream(dns_ip: Option<&str>) -> Result<Ipv4Addr, TokenError> {
    //println!("get_ipaddr_from_stream, in, dns_ip: {:?}", dns_ip);
    let default_ip = Ipv4Addr::new(114,114,114,114);
    let socket_addr = match dns_ip {
        Some(dns_ip) => SocketAddr::new(IpAddr::V4(Ipv4Addr::from_str(dns_ip).unwrap_or(default_ip)), 53),
        None => SocketAddr::new(IpAddr::V4(default_ip), 53)
    };
    let stream = TcpStream::connect(socket_addr)?;
    let local_addr = stream.local_addr()?;
    let local_ip = local_addr.ip();
    tracing::info!("TcpStream({}) local_ip={}", socket_addr.to_string(), local_ip);
    println!("get_ipaddr_from_stream, out, local_ip: {:?}", local_ip);
    print!(".");
    match local_ip {
        IpAddr::V4(ipv4) => Ok(ipv4),
        _ => Err(TokenError::IoError(Error::new(ErrorKind::Other, "No IPv4 address found"))),
    }
}

pub(crate) async fn get_ipaddr_from_public(is_out: bool ) -> Result<Ipv4Addr, TokenError> {
    let default_url =  match is_out {
        true => "https://ipinfo.io/ip",
        false => "https://ipinfo.io/ip",
    };
    //println!("get_ipaddr_from_public, in, default_url: {default_url}");
    let client = reqwest::Client::new();
    let response = client.get(default_url)
        .send()
        .await?
        .text()
        .await?;
    let ip_addr = response.parse::<Ipv4Addr>()?;
    tracing::info!("CURL({}) public_ip={}", default_url, ip_addr);
    println!("get_ipaddr_from_public, out, CURL({}) public_ip={}", default_url, ip_addr);
    print!(".");
    Ok(ip_addr)
}

pub(crate) async fn get_location() -> Result<String, TokenError> {
    //println!("get_location, in");
    let client = reqwest::Client::new();
    let response = client.get("http://ip-api.com/json")
        .send()
        .await?
        .text()
        .await?;
    let json: Value = serde_json::from_str(&response)?;
    let country_code = json["countryCode"].as_str().map(|s| s.to_string()).unwrap_or("CN".to_string());
    println!("get_location, out, country_code: {country_code}");
    print!(".");
    Ok(country_code)
}

pub(crate) async fn get_port_availability(ip: Ipv4Addr, port: u16) -> u16 {
    let addr = format!("{}:{}", ip, port);
    //println!("get_port_availability, in, addr: {addr}");
    let real_port = match TcpListener::bind(addr) {
        Ok(_) => port,
        Err(_) => {
            let mut rng = SmallRng::from_entropy();
            loop {
                let random_port = rng.gen_range((port-100)..=(port+100));
                let addr = format!("{}:{}", ip, random_port);
                match TcpListener::bind(addr) {
                    Ok(_) => return random_port,
                    Err(_) => {
                        time::sleep(Duration::from_millis(10)).await;
                        continue
                    },
                }
            };
        }
    };
    println!("get_port_availability, out, port: {real_port}");
    print!(".");
    real_port
}

pub(crate) async fn get_program_hash() -> Result<(String, String), TokenError> {
    let path_py = vec!["", "modules", "ldm_patched/modules", "enhanced", "javascript", "css", "comfy", "comfy/comfy"];
    let path_ui = vec!["language/cn.json", "simplesdxl_log.md", "webui.py", "enhanced/attached/welcome.jpg"];

    let path_root = env::current_dir()?;

    let mut py_hashes: HashMap<String, String> = HashMap::new();
    for path in path_py {
        let full_path = path_root.join(path);
        if full_path.is_dir() {
            for entry in std::fs::read_dir(&full_path)? {
                let entry = entry?;
                if entry.file_type()?.is_file() && entry.path().extension().and_then(|s| s.to_str()) == Some("py") {
                    let Ok((hash, _)) = get_file_hash_size(&entry.path()) else { todo!() };
                    py_hashes.insert(entry.file_name().into_string().unwrap(), hash);
                }
            }
        } else if full_path.is_file() && full_path.extension().and_then(|s| s.to_str()) == Some("py") {
            let Ok((hash, _)) = get_file_hash_size(&full_path.as_path()) else { todo!() };
            let file_name = full_path.file_name().and_then(|os_str| os_str.to_str()).unwrap().to_string();
            py_hashes.insert(file_name, hash);
        }
    }
    let mut keys: Vec<&String> = py_hashes.keys().collect();
    keys.sort();

    let mut combined_py_hash = Sha256::new();
    for key in keys {
        combined_py_hash.update(&py_hashes[key]);
    }
    let combined_py_hash = combined_py_hash.finalize();
    let py_hash_base64 = URL_SAFE_NO_PAD.encode(&combined_py_hash);
    let py_hash_output = &py_hash_base64[..7];

    let mut ui_hashes = Vec::new();
    for path in path_ui {
        let full_path = path_root.join(path);
        if full_path.is_file() {
            let Ok((hash, _)) = get_file_hash_size(&full_path.as_path()) else { todo!() };
            ui_hashes.push(hash);
        }
    }
    let mut combined_ui_hash = Sha256::new();
    for ui_hash in ui_hashes {
        combined_ui_hash.update(&ui_hash);
    }
    let combined_ui_hash = combined_ui_hash.finalize();
    let ui_hash_base64 = URL_SAFE_NO_PAD.encode(&combined_ui_hash);
    let ui_hash_output = &ui_hash_base64[..7];

    println!("get_program_hash, out, hash: {py_hash_output}, {ui_hash_output}");
    print!(".");
    Ok((py_hash_output.to_string(), ui_hash_output.to_string()))
}

pub(crate) async fn logging_launch_info(did: &str, info: &str) -> Result<(), TokenError>{
    let did = did.to_string();
    let info = info.to_string();
    let url = reqwest::Url::parse_with_params("https://edge.tokentm.net/log.gif", &[("d", did), ("p", info)])?;
    let client = reqwest::Client::new();
    let _ = client.get(url.as_str())
        .send()
        .await?
        .text()
        .await?;
    Ok(())
}

pub(crate) async fn get_mac_address(ip: IpAddr) -> String {
    //let interfaces = interfaces();
    //for interface in interfaces {
    //    for network in interface.ips {
    //        if network.contains(ip) {
    //            return format!("{:?}",interface.mac);
    //        }
    //    }
    //}
    "unknown".to_string()
}

pub(crate) fn get_verify_key() -> Result<[u8; 32], TokenError> {
    let signing_key = SigningKey::from_bytes(&read_key_or_generate_key()?);
    let verifying_key: VerifyingKey = signing_key.verifying_key();
    Ok(*verifying_key.as_bytes())
}

pub(crate) fn get_secret_key(did: &String) -> Result<[u8; 32], TokenError> {
    let key_hash = calc_sha256(&read_key_or_generate_key()?);
    let secret_key = StaticSecret::from(derive_key(did, &key_hash)?);
    Ok(*secret_key.as_bytes())
}

pub(crate) fn get_crypt_key(secret_key: [u8; 32]) -> Result<[u8; 32], TokenError> {
    let secret_key = StaticSecret::from(secret_key);
    let crypt_key = PublicKey::from(secret_key.to_bytes());
    Ok(*crypt_key.as_bytes())
}

pub(crate) fn get_diffie_hellman_key(did_key: &PublicKey, secret_key: [u8; 32]) -> Result<[u8; 32], TokenError> {
    let secret_key = StaticSecret::from(secret_key);
    let shared_key = secret_key.diffie_hellman(&did_key);
    Ok(*shared_key.as_bytes())
}
pub(crate) fn get_signature(text: &str) -> Result<Vec<u8>, TokenError> {
    let signing_key = SigningKey::from_bytes(&read_key_or_generate_key()?);
    let signature = signing_key.sign(text.as_bytes());
    Ok(Vec::from(signature.to_bytes()))
}

pub fn calc_sha256(input: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(input);
    //URL_SAFE_NO_PAD.encode(hasher.finalize())
    let result = hasher.finalize();
    let mut output = [0u8; 32];
    output.copy_from_slice(&result[..]);
    output
}

pub fn get_file_hash_size(path: &Path) -> io::Result<(String, u64)> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let file_size = io::copy(&mut file, &mut hasher)?;
    let file_hash = URL_SAFE_NO_PAD.encode(hasher.finalize());
    Ok((file_hash, file_size))
}

pub fn derive_key(password: &str, salt: &[u8]) -> Result<[u8; 32], TokenError> {
    let mut key = [0u8; 32];
    Argon2::default().hash_password_into(password.as_bytes(), salt, &mut key)?;
    Ok(key)
}

pub fn hkdf_key(key: &[u8]) -> [u8; 32] {
    let mut salt = [0u8; 16];
    let timestamp = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();
    let input = format!("now()={}", timestamp / 600);
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    let result = hasher.finalize();
    salt.copy_from_slice(&result[..16]);

    let info = b"SimpleAI_SYS";
    let hk = Hkdf::<Sha256>::new(Some(&salt[..]), key);
    let mut aes_key = [0u8; 32];
    hk.expand(info, &mut aes_key).unwrap();
    aes_key
}
pub fn encrypt(data: &[u8], key: &[u8]) -> Vec<u8> {
    let aes_key = hkdf_key(key);
    let key = Key::<Aes256Gcm>::from_slice(&aes_key);
    let cipher = Aes256Gcm::new(&key);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let encrypted = cipher.encrypt(&nonce, data).unwrap();
    let mut result = Vec::with_capacity(nonce.len() + encrypted.len());
    result.extend_from_slice(&nonce);
    result.extend_from_slice(&encrypted);
    result
}

pub fn decrypt(data: &[u8], key: &[u8]) -> Vec<u8> {
    let aes_key = hkdf_key(key);
    let key = Key::<Aes256Gcm>::from_slice(&aes_key);
    let cipher = Aes256Gcm::new(&key);
    let nonce = &data[..12]; // Nonce is 12 bytes for AES-256-GCM
    let encrypted = &data[12..];
    cipher.decrypt(nonce.into(), encrypted).unwrap()
}

