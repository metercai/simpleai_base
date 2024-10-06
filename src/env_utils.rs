use std::collections::HashMap;
use std::fs::File;
use std::io::{self, Read, Error, ErrorKind};
use std::path::{Path, MAIN_SEPARATOR, PathBuf};
use std::ffi::OsString;
use std::{env, fs};
use std::net::{IpAddr, Ipv4Addr, TcpListener, SocketAddr, TcpStream};
use std::str::FromStr;
use std::time::SystemTime;
use serde_json::{json, Value};
use directories_next::BaseDirs;

use pkcs8::{EncryptedPrivateKeyInfo, PrivateKeyInfo, LineEnding, ObjectIdentifier, SecretDocument};

//use pnet::datalink::interfaces;
use ed25519_dalek::{VerifyingKey, SigningKey, Signer, Signature, Verifier};
use x25519_dalek::{StaticSecret, PublicKey};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use sha2::{Sha256, Digest};
use hkdf::Hkdf;
use rand::{Rng, RngCore, rngs::SmallRng};
use rand::SeedableRng;
use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Key };
use argon2::Argon2;
use tokio::time::{self, Duration};
use tracing::info;
use lazy_static::lazy_static;

use crate::error::TokenError;
use crate::systeminfo::SystemBaseInfo;
use crate::claim::{IdClaim, UserContext};

pub const ALGORITHM_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.112");
const CHUNK_SIZE: usize = 1024 * 1024; // 1 MB chunks

/// Ed25519 Algorithm Identifier.
pub const ALGORITHM_ID: pkcs8::AlgorithmIdentifierRef<'static> = pkcs8::AlgorithmIdentifierRef {
    oid: ALGORITHM_OID,
    parameters: None,
};

lazy_static! {
    pub static ref SYSTEM_BASE_INFO: SystemBaseInfo = SystemBaseInfo::generate();
    pub static ref VERBOSE_INFO: bool = {
        match env::var("SIMPLEAI_VERBOSE") {
            Ok(val) => if val=="on" {true} else {false},
            Err(_) => false,
        }
    };
}

fn read_key_or_generate_key(key_type: &str, symbol_hash: &[u8; 32], phrase: &str) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let sysinfo = &SYSTEM_BASE_INFO;
    let (device_hash_id, _device_phrase) = get_key_hash_id_and_phrase("Device", symbol_hash);
    let device_key_file = get_path_in_sys_key_dir(&format!(".token_device_{}.pem", device_hash_id));
    let device_phrase = format!("{}/{}/{}/{}/{}/{}/{}/{}", sysinfo.host_name, sysinfo.disk_uuid,
                                sysinfo.os_name, sysinfo.os_type, sysinfo.cpu_brand, sysinfo.cpu_cores,
                                sysinfo.ram_total + sysinfo.gpu_memory, sysinfo.gpu_name);
    let device_key = _read_key_or_generate_key(device_key_file.as_path(), device_phrase.as_str())?;
    let system_key = match key_type {
        "System" | "User" => {
            let (sys_hash_id, sys_phrase) = get_key_hash_id_and_phrase("System", symbol_hash);
            let system_key_file = get_path_in_sys_key_dir(&format!(".token_system_{}.pem", sys_hash_id));
            let local_phrase = format!("{}@{}:{}/{}/{}/{}/{}/{}/{}", sysinfo.root_dir, sysinfo.host_name,
                                       sysinfo.os_name, sysinfo.os_type, sysinfo.cpu_brand, sysinfo.cpu_cores,
                                       sysinfo.ram_total + sysinfo.gpu_memory, sysinfo.gpu_name, sysinfo.disk_uuid);
            let phrase_text = format!("{}:{}:{}",
                                      URL_SAFE_NO_PAD.encode(device_key.as_slice()),
                                      local_phrase, sys_phrase);
            _read_key_or_generate_key(system_key_file.as_path(), phrase_text.as_str())?
        },
        _ => device_key
    };
    match key_type {
        "System" => Ok(system_key),
        "User" => {
            let (user_hash_id, _user_phrase) = get_key_hash_id_and_phrase("User", symbol_hash);
            let user_key_file = get_path_in_sys_key_dir(&format!(".token_user_{}.pem", user_hash_id));
            let phrase_text = format!("{}:{}",
                                      URL_SAFE_NO_PAD.encode(device_key.as_slice()),
                                      phrase);
            Ok(_read_key_or_generate_key(user_key_file.as_path(), phrase_text.as_str())?)
        },
        _ => Ok(device_key)
    }
}

pub fn get_path_in_sys_key_dir(filename: &str) -> PathBuf {
    let sysinfo = &SYSTEM_BASE_INFO;
    let home_dirs = match BaseDirs::new() {
        Some(dirs) => dirs.home_dir().to_path_buf(),
        None => PathBuf::from(sysinfo.root_dir.clone()),
    };
    let sys_key_dir = home_dirs.join("simpleai.vip").join(".token");
    sys_key_dir.join(filename)
}

pub fn get_path_in_user_dir(did: &str, filename: &str) -> PathBuf {
    let sysinfo = &SYSTEM_BASE_INFO;
    let home_dirs = match BaseDirs::new() {
        Some(dirs) => dirs.home_dir().to_path_buf(),
        None => PathBuf::from(sysinfo.root_dir.clone()),
    };
    let user_dir = home_dirs.join("simpleai.vip").join(did);
    user_dir.join(filename)
}

pub fn get_key_hash_id_and_phrase(key_type: &str, symbol_hash: &[u8; 32]) -> (String, String) {
    let sysinfo = &SYSTEM_BASE_INFO;
    match key_type {
        "Device" => _get_key_hash_id_and_phrase(&format!("{}{}", sysinfo.host_name, sysinfo.disk_uuid).into_bytes(), 0),
        "System" => _get_key_hash_id_and_phrase(&format!("{}{}", sysinfo.root_dir, sysinfo.disk_uuid).into_bytes(), 0),
        _ => {
            let (device_hash_id, _device_phrase) = _get_key_hash_id_and_phrase
                (&format!("{}{}", sysinfo.host_name, sysinfo.disk_uuid).into_bytes(), 0);
            let mut com_symbol = Vec::new();
            com_symbol.extend_from_slice(symbol_hash);
            com_symbol.extend_from_slice(device_hash_id.as_bytes());
            _get_key_hash_id_and_phrase(&com_symbol, 0)
        },
    }
}

pub fn exists_key_file(key_type: &str, symbol_hash: &[u8; 32]) -> bool {
    let (key_hash_id, _phrase) = get_key_hash_id_and_phrase(key_type, symbol_hash);
    let key_file = get_path_in_sys_key_dir(&format!(".token_{}_{}.pem",
                                                    key_type.to_lowercase(), key_hash_id));
    key_file.exists()
}

fn _get_key_hash_id_and_phrase(symbol_hash: &Vec<u8>, period: u64 ) -> (String, String) {
    let key_file_hash_id = sha256_prefix(symbol_hash, 10);
    let phrase_text = sha256_prefix(&hkdf_key_deadline(symbol_hash, period), 10);
    (key_file_hash_id, phrase_text)
}

fn _read_key_or_generate_key(file_path: &Path, phrase: &str) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let phrase_bytes = hkdf_key_deadline(&phrase.as_bytes(), 0);
    let private_key = match file_path.exists() {
        false => generate_new_key_and_save_pem(file_path, &phrase_bytes),
        true => {
            let Ok((_, s_doc)) = SecretDocument::read_pem_file(file_path) else { todo!() };
            let priv_key = match EncryptedPrivateKeyInfo::try_from(s_doc.as_bytes()).unwrap().decrypt(&phrase_bytes) {
                Ok(key) => {
                    let mut pkey: [u8; 32] = [0; 32];
                    pkey.copy_from_slice(PrivateKeyInfo::try_from(key.as_bytes()).unwrap().private_key);
                    pkey
                },
                Err(_e) => generate_new_key_and_save_pem(file_path, &phrase_bytes),
            };
            priv_key
        }
    };
    if *VERBOSE_INFO {
        println!("read private key: {}", file_path.display());
    }
    Ok(private_key.try_into().unwrap())
}

fn generate_new_key_and_save_pem(file_path: &Path, phrase: &[u8; 32]) -> [u8; 32] {
    if let Some(parent_dir) = file_path.parent() {
        if !parent_dir.exists() {
            fs::create_dir_all(parent_dir).unwrap();
        }
    }
    let pem_label = "SIMPLE_AI_KEY";
    let mut csprng = OsRng {};
    let secret_key = SigningKey::generate(&mut csprng).to_bytes();
    PrivateKeyInfo::new(ALGORITHM_ID, &secret_key)
        .encrypt(csprng, &phrase).unwrap()
        .write_pem_file(file_path, pem_label, LineEnding::default()).unwrap();
    secret_key
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
    //println!("get_ipaddr_from_stream, out, local_ip: {:?}", local_ip);
    //print!(".");
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
    //println!("get_ipaddr_from_public, out, CURL({}) public_ip={}", default_url, ip_addr);
    //print!(".");
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
    //println!("get_location, out, country_code: {country_code}");
    //print!(".");
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
    //println!("get_port_availability, out, port: {real_port}");
    //print!(".");
    real_port
}

pub(crate) async fn get_program_hash() -> Result<(String, String), TokenError> {
    let path_py = vec!["", "modules", "extras", "ldm_patched/modules", "enhanced", "enhanced/libs", "comfy", "comfy/comfy"];
    let path_ui = vec!["language/cn.json", "simplesdxl_log.md", "webui.py", "enhanced/attached/welcome.png"];

    let path_root = env::current_dir()?;

    let extensions = vec!["py", "whl"];
    let mut py_hashes: HashMap<OsString, String> = HashMap::new();
    for path in path_py {
        let path_os = path.replace("/", &MAIN_SEPARATOR.to_string());
        let full_path = path_root.join(path_os);
        if full_path.is_dir() {
            for entry in std::fs::read_dir(&full_path)? {
                let entry = entry?;
                if entry.file_type()?.is_file() {
                    if let Some(ext) = entry.path().extension().and_then(|s| s.to_str()) {
                        if extensions.contains(&ext) {
                            let subpath = entry.path().strip_prefix(path_root.clone()).unwrap().to_path_buf().into_os_string();
                            let Ok((hash, _)) = get_file_hash_size(&entry.path()) else { todo!() };
                            py_hashes.insert(subpath, hash);
                        }
                    }
                }
            }
        } else if full_path.is_file() {
            if let Some(ext) = full_path.extension().and_then(|s| s.to_str()) {
                if extensions.contains(&ext) {
                    let subpath = full_path.strip_prefix(path_root.clone()).unwrap().to_path_buf().into_os_string();
                    let Ok((hash, _)) = get_file_hash_size(&full_path.as_path()) else { todo!() };
                    py_hashes.insert(subpath, hash);
                }
            }
        }
    }
    let mut keys: Vec<OsString> = py_hashes.keys().cloned().collect();
    keys.sort_by(|a, b| {
        let a_str = a.to_string_lossy();
        let b_str = b.to_string_lossy();
        a_str.to_lowercase().cmp(&b_str.to_lowercase())
    });

    let mut combined_py_hash = Sha256::new();
    for key in keys {
        if *VERBOSE_INFO {
            println!("file key: {:?},{:?}", key, py_hashes[&key]);
        }
        combined_py_hash.update(&py_hashes[&key]);
    }
    let combined_py_hash = combined_py_hash.finalize();
    let py_hash_base64 = URL_SAFE_NO_PAD.encode(&combined_py_hash);
    let py_hash_output = &py_hash_base64[..10];

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

    //println!("get_program_hash, out, hash: {py_hash_output}, {ui_hash_output}");
    //print!(".");
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
    "Unknown".to_string()
}

pub(crate) fn get_verify_key(key_type: &str, symbol_hash: &[u8; 32], phrase: &str) -> Result<[u8; 32], TokenError> {
    let signing_key = SigningKey::from_bytes(&read_key_or_generate_key(key_type, symbol_hash, phrase)?);
    let verifying_key: VerifyingKey = signing_key.verifying_key();
    Ok(*verifying_key.as_bytes())
}

pub(crate) fn get_specific_secret_key(key_name: &str, period:u64, key_type: &str, symbol_hash: &[u8; 32], phrase: &str) -> Result<[u8; 40], TokenError> {
    let key_hash = calc_sha256(&read_key_or_generate_key(key_type, symbol_hash, phrase)?);
    let key_name_bytes = calc_sha256(key_name.as_bytes());
    let mut com_phrase = [0u8; 64];
    com_phrase[..32].copy_from_slice(&key_name_bytes);
    com_phrase[32..].copy_from_slice(symbol_hash);
    let secret_key = StaticSecret::from(derive_key(&com_phrase, &key_hash)?);
    Ok(convert_to_sk_with_expire(secret_key.as_bytes(), period))
}

pub(crate) fn get_random_secret_key(key_type: &str, period:u64, symbol_hash: &[u8; 32], phrase: &str) -> Result<[u8; 40], TokenError> {
    let key_hash = calc_sha256(&read_key_or_generate_key(key_type, symbol_hash, phrase)?);
    let mut csprng = OsRng {};
    let mut random_number = [0u8; 16];
    csprng.fill_bytes(&mut random_number);
    let mut com_phrase = [0u8; 48];
    com_phrase[..16].copy_from_slice(&random_number);
    com_phrase[16..].copy_from_slice(symbol_hash);
    let secret_key = StaticSecret::from(derive_key(&com_phrase, &key_hash)?);
    Ok(convert_to_sk_with_expire(secret_key.as_bytes(), period))
}

pub(crate) fn get_crypt_key(secret_key: [u8; 40]) -> Result<[u8; 32], TokenError> {
    let key = &secret_key[..32];
    let expire = u64::from_le_bytes(secret_key[32..].try_into().unwrap_or_else(|_| [0; 8]));
    let secret_key = StaticSecret::from(hkdf_key_deadline(key, expire));
    let crypt_key = PublicKey::from(secret_key.to_bytes());
    Ok(*crypt_key.as_bytes())
}

pub(crate) fn get_diffie_hellman_key(did_key: &PublicKey, secret_key: [u8; 32]) -> Result<[u8; 32], TokenError> {
    let secret_key = StaticSecret::from(secret_key);
    let shared_key = secret_key.diffie_hellman(&did_key);
    Ok(*shared_key.as_bytes())
}
pub(crate) fn get_signature(text: &str, key_type: &str, symbol_hash: &[u8; 32], phrase: &str) -> Result<Vec<u8>, TokenError> {
    let signing_key = SigningKey::from_bytes(&read_key_or_generate_key(key_type, symbol_hash, phrase)?);
    let signature = signing_key.sign(text.as_bytes());
    Ok(Vec::from(signature.to_bytes()))
}

pub fn virify_signature(text: &str, signature: &str, did: &str, claims: &mut HashMap<String, IdClaim>) -> bool {
    let mut claim = IdClaim::default();
    if !claims.contains_key(did) {
        claim = read_did_claim_from_file(did).unwrap_or(IdClaim::default());
        if !claim.is_default() {
            claims.insert(did.to_string(), claim.clone());
        }
    } else {
        claim = claims.get(did).unwrap().clone();
    }
    let verify_key_bytes = claim.get_verify_key();
    let verify_key = VerifyingKey::from_bytes(&verify_key_bytes.as_slice().try_into().unwrap()).unwrap();
    let signature = Signature::from_bytes(&URL_SAFE_NO_PAD.decode(signature).unwrap().as_slice().try_into().unwrap());
    match verify_key.verify(text.as_bytes(), &signature) {
        Ok(()) => true,
        Err(_) => false,
    }
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

pub fn sha256_prefix(input: &[u8], len: usize) -> String {
    let hash = calc_sha256(input);
    let output = URL_SAFE_NO_PAD.encode(hash);
    if 0<len && len<=output.len() {
        output[..len].to_string()
    } else {
        output.to_string()
    }
}

pub fn get_file_hash_size(path: &Path) -> io::Result<(String, u64)> {
    let is_text = match path.extension().and_then(|ext| ext.to_str()) {
        Some(ext) if matches!(ext, "txt" | "log" | "py" | "rs" | "toml" | "md") => true,
        _ => false,
    };
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut file_size = 0;

    if is_text {
        let mut content = String::new();
        file.read_to_string(&mut content)?;
        let normalized_content = content.replace("\r\n", "\n");
        hasher.update(normalized_content.as_bytes());
        file_size = normalized_content.len() as u64;
    } else {
        let mut buffer = [0; CHUNK_SIZE];
        loop {
            let bytes_read = file.read(&mut buffer)?;
            if bytes_read == 0 { break; }
            hasher.update(&buffer[..bytes_read]);
            file_size += bytes_read as u64;
        }
    }
    let file_hash = URL_SAFE_NO_PAD.encode(hasher.finalize());
    Ok((file_hash, file_size))
}

pub fn derive_key(password: &[u8], salt: &[u8]) -> Result<[u8; 32], TokenError> {
    let mut key = [0u8; 32];
    Argon2::default().hash_password_into(password, salt, &mut key)?;
    Ok(key)
}

pub fn hkdf_key_deadline(key: &[u8], period:u64) -> [u8; 32] {
    let mut salt = [0u8; 16];
    let timestamp = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();
    let input = format!("period:{}", if period == 0 { 0 } else { timestamp / period });
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

pub fn encrypt(data: &[u8], key: &[u8], period:u64) -> Vec<u8> {
    let aes_key = hkdf_key_deadline(key, period);
    let key = Key::<Aes256Gcm>::from_slice(&aes_key);
    let cipher = Aes256Gcm::new(&key);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let encrypted = cipher.encrypt(&nonce, data).unwrap();
    let mut result = Vec::with_capacity(nonce.len() + encrypted.len());
    result.extend_from_slice(&nonce);
    result.extend_from_slice(&encrypted);
    result
}

pub fn decrypt(data: &[u8], key: &[u8], period:u64) -> Vec<u8> {
    let aes_key = hkdf_key_deadline(key, period);
    let key = Key::<Aes256Gcm>::from_slice(&aes_key);
    let cipher = Aes256Gcm::new(&key);
    let nonce = &data[..12]; // Nonce is 12 bytes for AES-256-GCM
    let encrypted = &data[12..];
    cipher.decrypt(nonce.into(), encrypted).unwrap()
}

pub fn generate_did_claim(id_type: &str, nickname: &str, id_card: Option<String>, telephone: Option<String>, phrase: &str)
    -> Result<IdClaim, TokenError> {
    let id_card = id_card.unwrap_or("-".to_string());
    let telephone = telephone.unwrap_or("-".to_string());
    let id_card_hash = calc_sha256(format!("{}:id_card:{}", nickname, id_card).as_bytes());
    let telephone_hash = calc_sha256(format!("{}:telephone:{}", nickname, telephone).as_bytes());
    let face_image_hash = calc_sha256(format!("{}:face_image:-", nickname).as_bytes());
    let file_hash_hash = calc_sha256(format!("{}:file_hash:-", nickname).as_bytes());
    let claim = IdClaim::new(id_type, &phrase, nickname, telephone_hash, id_card_hash, face_image_hash, file_hash_hash);
    Ok(claim)

}

pub fn read_did_claim_from_file(did: &str) -> Result<IdClaim, TokenError> {
    let did_file_path = get_path_in_sys_key_dir(
        format!("User_{}.did", did).as_str());
    let root_path = did_file_path.parent().unwrap();
    for entry in fs::read_dir(root_path)? {
        let entry = entry?;
        let path = entry.path();
        if let Some(file_name) = path.file_name().and_then(|name| name.to_str()) {
            let suffix = format!("_{}.did", did);
            if file_name.ends_with(suffix.as_str())  {
                let prefix = file_name[..(file_name.len() - suffix.len())].to_string();
                let did_file_path = get_path_in_sys_key_dir(
                    format!("{}_{}.did", prefix, did).as_str());
                return Ok(serde_json::from_str(&fs::read_to_string(did_file_path)?)?)
            }
        }
    }
    Ok(IdClaim::default())
}

fn get_token_cyrpt_key() -> [u8; 32] {
    let id_hash = [0u8; 32];
    let device_key = read_key_or_generate_key("Device", &id_hash, "None").unwrap_or(id_hash);
    let local_key = read_key_or_generate_key("System", &id_hash, "None").unwrap_or(id_hash);
    let mut com_hash = [0u8; 64];
    com_hash[..32].copy_from_slice(&device_key);
    com_hash[32..].copy_from_slice(&local_key);
    calc_sha256(com_hash.as_ref())
}

pub fn get_user_token_from_file(did: &str) -> Result<(UserContext, String), TokenError> {
    let user_token_file = get_path_in_sys_key_dir(&format!("user_{}.token", did));
    match user_token_file.exists() {
        true => read_user_token_from_file(user_token_file.as_path()),
        false => Ok((UserContext::default(), "Unknown".to_string()))
    }
}

pub fn save_user_token_to_file(did: &str, context: &UserContext, sig: &str) -> Result<String, TokenError> {
    let mut json_context = serde_json::to_value(&context)?;
    if let serde_json::Value::Object(ref mut token_map) = json_context {
        token_map.insert("did".to_string(), did.to_string().into());
        token_map.insert("sig".to_string(), serde_json::Value::String(sig.to_string()));
    }
    let json_string = serde_json::to_string(&json_context)?;

    let user_token_file = get_path_in_sys_key_dir(&format!("user_{}.token", did));
    let crypt_key = get_token_cyrpt_key();
    let token_raw_data = encrypt(json_string.as_bytes(), &crypt_key, 0);
    fs::write(user_token_file, token_raw_data)?;
    Ok(json_string)
}

pub fn create_or_renew_user_token(did: &str, nickname: &str, id_type: &str, symbol_hash: &[u8; 32], phrase: &str) -> UserContext {
    let zeroed_key: [u8; 32] = [0u8; 32];
    let user_token_file = get_path_in_sys_key_dir(&format!("user_{}.token", did));
    let context = match user_token_file.exists() {
        true => {
            println!("Renew user token: {}", did);
            let Ok((mut context_renew, _sig)) = read_user_token_from_file(user_token_file.as_path())
                else { todo!() };
            let crypt_key = get_specific_secret_key("context", 0, id_type, symbol_hash, phrase).unwrap_or([0u8; 40]);
            let aes_key_old_vec = decrypt(&URL_SAFE_NO_PAD.decode(
                context_renew.get_aes_key_encrypted()).unwrap_or(zeroed_key.to_vec()), &crypt_key, 0);
            let aes_key_old = convert_vec_to_key(&aes_key_old_vec);
            let secret_key_new = get_random_secret_key(id_type, 0, symbol_hash, phrase)
                .unwrap_or([0u8; 40]);
            let default_expire = 90*24*3600;
            context_renew.set_auth_sk_with_secret(&URL_SAFE_NO_PAD.encode(secret_key_new), default_expire);
            let aes_key_new = context_renew.get_crypt_key();
            transfer_private_data(&aes_key_old, &aes_key_new, &context_renew.get_private_paths());
            let aes_key_encrypted = URL_SAFE_NO_PAD.encode(encrypt(&context_renew.get_crypt_key(), &crypt_key, 0));
            context_renew.set_aes_key_encrypted(&aes_key_encrypted);
            context_renew
        }
        false => {
            println!("Create user token: {}", did);
            let default_permissions = "standard".to_string();
            let default_private_paths = serde_json::to_string(
                &vec!["config", "presets", "wildcards", "styles", "workflows"]).unwrap_or("".to_string());
            let mut context_default = UserContext::new(did, nickname, &default_permissions, &default_private_paths);
            let secret_key = get_random_secret_key(id_type, 0, symbol_hash, phrase)
                .unwrap_or([0u8; 40]);
            let default_expire = 90*24*3600;
            context_default.set_auth_sk_with_secret(&URL_SAFE_NO_PAD.encode(secret_key), default_expire);
            let crypt_key = get_specific_secret_key("context", 0, id_type, symbol_hash, phrase).unwrap_or([0u8; 40]);
            let aes_key_encrypted = URL_SAFE_NO_PAD.encode(encrypt(&context_default.get_crypt_key(), &crypt_key, 0));
            context_default.set_aes_key_encrypted(&aes_key_encrypted);
            context_default
        }
    };
    context
}



fn read_user_token_from_file(user_token_file: &Path) -> Result<(UserContext, String), TokenError> {
    let crypt_key = get_token_cyrpt_key();
    let token_raw_data = fs::read(user_token_file)?;
    let token_data = decrypt(&token_raw_data, &crypt_key, 0);
    let user_token: Value = serde_json::from_slice(&token_data).unwrap_or(serde_json::json!({}));
    let did = user_token.get("did")
        .and_then(Value::as_str)
        .unwrap_or("None");
    let auth_sk = user_token.get("auth_sk")
        .and_then(Value::as_str)
        .unwrap_or("None");
    let nickname = user_token.get("nickname")
        .and_then(Value::as_str)
        .unwrap_or("None");
    let permissions = user_token.get("permissions")
        .and_then(Value::as_str)
        .unwrap_or("None");
    let private_paths = user_token.get("private_paths")
        .and_then(Value::as_str)
        .unwrap_or("None");
    let aes_key_encrypted = user_token.get("aes_key_encrypted")
        .and_then(Value::as_str)
        .unwrap_or("None");
    let sig = user_token.get("sig")
        .and_then(Value::as_str)
        .unwrap_or("None");
    let mut context = UserContext::new(did, nickname, permissions, private_paths);
    context.set_auth_sk(auth_sk);
    context.set_aes_key_encrypted(aes_key_encrypted);
    Ok((context, sig.to_string()))
}

pub fn load_token_by_authorized2system(sys_did: &str, crypt_secrets: &mut HashMap<String, String>, claims: &mut HashMap<String, IdClaim>)
    -> Result<(), TokenError> {
    let token_file = get_path_in_sys_key_dir(&format!("authorized2system_{}.token", sys_did));
    let crypt_key = get_token_cyrpt_key();
    let token_raw_data = fs::read(token_file)?;
    let token_data = decrypt(&token_raw_data, &crypt_key, 0);
    let system_token: Value = serde_json::from_slice(&token_data).unwrap_or(serde_json::json!({}));

    if *VERBOSE_INFO {
        println!("Load token from file: {}", system_token);
    }
    if let Some(Value::Object(hellman_secrets)) = system_token.get("hellman_secrets") {
        for (key, value) in hellman_secrets {
            if let Value::String(secrets_str) = value {
                let parts: Vec<&str> = secrets_str.split(':').collect();
                if parts.len() == 3 {
                    let secret_base64 = parts[0];
                    let timestamp = parts[1];
                    let sig_base64 = parts[2];
                    let text = format!("{}:{}:{}", key, secret_base64, timestamp);
                    if virify_signature(&text, sig_base64, key, claims) {
                        crypt_secrets.insert(key.clone(), secret_base64.to_string());
                    }
                }
            }
        }
    }
    Ok(())
}

pub fn create_and_save_crypt_secret(crypt_secrets: &mut HashMap<String, String>, sys_did: &str,
                                    id_type: &str, claim: &mut IdClaim,  phrase: &str) -> String {
    let zeroed_key_40: [u8; 40] = [0; 40];
    let crypt_secret = get_specific_secret_key(
        "hellman",0,id_type, &claim.get_symbol_hash(), &phrase).unwrap_or_else(|_| zeroed_key_40);
    let crypt_secret_with_sig = save_secret_to_system_token_file(crypt_secrets,
        &sys_did, &claim.gen_did(), &crypt_secret, id_type, &claim.get_symbol_hash(), &phrase);
    claim.set_crypt_key_and_save_file(crypt_secret);
    crypt_secret_with_sig.unwrap_or_else(|_| String::from("Unknown"))
}

pub fn save_secret_to_system_token_file(
    crypt_secrets: &mut HashMap<String, String>, sys_did: &str, did: &str, secret: &[u8; 40],
    id_type: &str, symbol_hash: &[u8; 32], phrase: &str) -> Result<String, TokenError> {
    let secret_base64 = URL_SAFE_NO_PAD.encode(secret);
    let timestamp = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();
    let text = format!("{}:{}:{}", did, secret_base64, timestamp);
    let sig = URL_SAFE_NO_PAD.encode(get_signature(text.as_str(), id_type, symbol_hash, phrase)
        .unwrap_or_else(|_| String::from("Unknown").into()));
    let token_value = format!("{}:{}:{}", secret_base64, timestamp, sig);
    crypt_secrets.insert(did.to_string(), token_value);

    let mut json_system_token = json!({});
    json_system_token["hellman_secrets"] = json!(crypt_secrets);
    let json_string = serde_json::to_string(&json_system_token)?;

    let system_token_file = get_path_in_sys_key_dir(&format!("authorized2system_{}.token", sys_did));
    let crypt_key = get_token_cyrpt_key();
    let token_raw_data = encrypt(json_string.as_bytes(), &crypt_key, 0);
    if *VERBOSE_INFO {
        println!("Save token to file: {}", json_string);
    }
    fs::write(system_token_file, token_raw_data)?;
    Ok(secret_base64.clone())
}

pub fn load_did_in_local(claims: &mut HashMap<String, IdClaim>) -> Result<(), TokenError> {
    let did_file_path = get_path_in_sys_key_dir("user_xxxxx.did");
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
    for entry in fs::read_dir(root_path)? {
        let entry = entry?;
        let path = entry.path();
        if let Some(file_name) = path.file_name().and_then(|name| name.to_str()) {
            if file_name.ends_with(".did") {
                let claim: IdClaim = serde_json::from_str(&fs::read_to_string(path)?)?;
                claims.insert(claim.gen_did(), claim);
            }
        }
    }
    Ok(())
}

pub fn convert_to_sk_with_expire(secret_key: &[u8; 32], expire: u64) -> [u8; 40] {
    let expire_bytes = expire.to_le_bytes();
    let mut auth_sk = [0; 40];
    auth_sk[..32].copy_from_slice(secret_key);
    auth_sk[32..].copy_from_slice(&expire_bytes);
    auth_sk
}

pub fn convert_vec_to_key(vec: &Vec<u8>) -> [u8; 32] {
    let mut key: [u8; 32] = [0; 32];
    let len_vec = vec.len();
    let len = if len_vec > 32 { 32 } else { len_vec };
    key.copy_from_slice(&vec[..len]);
    key
}

pub fn convert_base64_to_key(key_str: &str) -> [u8; 32] {
    let vec = URL_SAFE_NO_PAD.decode(key_str.as_bytes())
        .unwrap_or_else(|_| [0u8; 32].to_vec());
    let mut key: [u8; 32] = [0; 32];
    let len_vec = vec.len();
    let len = if len_vec > 32 { 32 } else { len_vec };
    key.copy_from_slice(&vec[..len]);
    key
}
pub fn get_symbol_hash_by_source(nickname: &str, telephone: &str) -> [u8; 32] {
    get_symbol_hash(nickname, URL_SAFE_NO_PAD.encode(
        calc_sha256(telephone.as_bytes())).as_str())
}
pub fn get_symbol_hash(nickname: &str, telephone_base64: &str) -> [u8; 32] {
    calc_sha256(format!("{}:{}",nickname, telephone_base64).as_bytes())
}

pub fn filter_files(work_paths: &Path, filters: &[&str], suffixes: &[&str]) -> Vec<String> {
    let mut result = Vec::new();
    if let Ok(entries) = fs::read_dir(work_paths) {
        for entry in entries {
            if let Ok(entry) = entry {
                let path = entry.path();
                if path.is_file() {
                    if let Some(file_name) = path.file_name() {
                        if let Some(file_name_str) = file_name.to_str() {
                            let contains_filter = filters.iter().any(|filter| file_name_str.contains(filter));
                            let ends_with_suffix = suffixes.iter().any(|suffix| file_name_str.ends_with(suffix));
                            if contains_filter && ends_with_suffix {
                                result.push(file_name_str.to_string());
                            }
                        }
                    }
                }
            }
        }
    }
    result
}
pub fn transfer_private_data(aes_key_old: &[u8; 32], aes_key_new: &[u8; 32], private_paths: &Vec<String>) {
     // TODO
}