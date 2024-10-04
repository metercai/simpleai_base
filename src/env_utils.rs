use std::collections::HashMap;
use std::fs::File;
use std::io::{self, Read, Error, ErrorKind};
use std::path::{Path, MAIN_SEPARATOR, PathBuf};
use std::ffi::OsString;
use std::{env, fs};
use std::net::{IpAddr, Ipv4Addr, TcpListener, SocketAddr, TcpStream};
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};
use serde_json::Value;
use directories_next::BaseDirs;

use pkcs8::{EncryptedPrivateKeyInfo, PrivateKeyInfo, LineEnding, ObjectIdentifier, SecretDocument};

//use pnet::datalink::interfaces;
use ed25519_dalek::{VerifyingKey, SigningKey, Signer};
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
    static ref VERBOSE_INFO: bool = {
        match env::var("SIMPLEAI_VERBOSE") {
            Ok(val) => if val=="on" {true} else {false},
            Err(_) => false,
        }
    };
}

fn read_key_or_generate_key(key_type: &str, id_hash: &[u8; 32], phrase: &str) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let sysinfo = &SYSTEM_BASE_INFO;
    let (device_file_hash_id, device_phrase) = get_key_hash_id_and_phrase(&format!("{}{}", sysinfo.host_name, sysinfo.disk_uuid));
    let device_key_file = get_path_in_sys_key_dir(&format!(".token_device_{}.pem", device_file_hash_id));
    let device_phrase = format!("{}-{}-{}-{}-{}-{}-{}-{}", sysinfo.host_name, sysinfo.disk_uuid,
                                sysinfo.os_name, sysinfo.os_type, sysinfo.cpu_brand, sysinfo.cpu_cores,
                                sysinfo.ram_total + sysinfo.gpu_memory, sysinfo.gpu_name);

    let device_key = _read_key_or_generate_key(device_key_file.as_path(), device_phrase.as_str())?;
    let system_key = match key_type {
        "System" | "User" => {
            let (sys_file_hash_id, sys_phrase) = get_key_hash_id_and_phrase(&sysinfo.root_dir);
            let system_key_file = get_path_in_sys_key_dir(&format!(".token_system_{}.pem", sys_file_hash_id));
            let local_phrase = format!("{}@{}:{}/{}/{}/{}/{}/{}/{}", sysinfo.root_dir, sysinfo.host_name,
                                       sysinfo.os_name, sysinfo.os_type, sysinfo.cpu_brand, sysinfo.cpu_cores,
                                       sysinfo.ram_total + sysinfo.gpu_memory, sysinfo.gpu_name, sysinfo.disk_uuid);
            let phrase_text = format!("{}-{}-{}",
                                      URL_SAFE_NO_PAD.encode(device_key.as_slice()),
                                      local_phrase, sys_phrase);
            _read_key_or_generate_key(system_key_file.as_path(), phrase_text.as_str())?
        },
        _ => device_key
    };
    match key_type {
        "System" => Ok(system_key),
        "User" => {
            let mut filename_org: [u8; 64] = [0; 64];
            filename_org[..32].copy_from_slice(id_hash);
            filename_org[32..].copy_from_slice(&device_key);
            let user_file_hash_id = sha256_prefix(&filename_org, 10);
            let user_key_file = get_path_in_sys_key_dir(&format!(".token_user_{}.pem", user_file_hash_id));
            let phrase_text = format!("{}-{}",
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
    let sys_key_dir = home_dirs.join(".token");
    sys_key_dir.join(filename)
}

pub fn get_key_hash_id_and_phrase(id_symbol: &str) -> (String, String) {
    let sys_file_hash_id = sha256_prefix(id_symbol.as_bytes(), 10);
    let phrase_text = sha256_prefix(&hkdf_key_deadline(id_symbol.as_bytes(), 0), 10);
    (sys_file_hash_id, phrase_text)
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
                Err(e) => generate_new_key_and_save_pem(file_path, &phrase_bytes),
            };
            priv_key
        }
    };
    Ok(private_key.try_into().unwrap())
}

fn generate_new_key_and_save_pem(file_path: &Path, phrase: &[u8; 32]) -> [u8; 32] {
    let pem_label = "SIMPLE_AI_KEY";
    let mut csprng = OsRng {};
    let secret_key = SigningKey::generate(&mut csprng).to_bytes();
    PrivateKeyInfo::new(ALGORITHM_ID, &secret_key)
        .encrypt(csprng, &phrase).unwrap()
        .write_pem_file(file_path, pem_label, LineEnding::default()).unwrap();
    secret_key
}
//fn read_token_file(file_path: &Path) -> Result<String, Box<dyn std::error::Error>> {

//}
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
    "unknown".to_string()
}

pub(crate) fn get_verify_key(key_type: &str, telephone_hash: &[u8; 32], phrase: &str) -> Result<[u8; 32], TokenError> {
    let signing_key = SigningKey::from_bytes(&read_key_or_generate_key(key_type, telephone_hash, phrase)?);
    let verifying_key: VerifyingKey = signing_key.verifying_key();
    Ok(*verifying_key.as_bytes())
}

pub(crate) fn get_secret_key(key_name: &str, key_type: &str, telephone_hash: &[u8; 32], phrase: &str) -> Result<[u8; 32], TokenError> {
    let key_hash = calc_sha256(&read_key_or_generate_key(key_type, telephone_hash, phrase)?);
    let mut key_bytes = [b' '; 16];
    let key_name_bytes = key_name.as_bytes();
    let len = key_name_bytes.len();
    for i in 0..16 {
        if i < len {
            key_bytes[i] = key_name_bytes[i];
        } else {
            break;
        }
    }
    let mut com_phrase = [0u8; 48];
    com_phrase[..16].copy_from_slice(&key_bytes);
    com_phrase[16..].copy_from_slice(telephone_hash);

    let secret_key = StaticSecret::from(derive_key(&com_phrase, &key_hash)?);
    Ok(*secret_key.as_bytes())
}

pub(crate) fn get_random_secret_key(key_type: &str, telephone_hash: &[u8; 32], phrase: &str) -> Result<[u8; 32], TokenError> {
    let key_hash = calc_sha256(&read_key_or_generate_key(key_type, telephone_hash, phrase)?);
    let mut csprng = OsRng {};
    let mut random_number = [0u8; 16];
    csprng.fill_bytes(&mut random_number);
    let mut com_phrase = [0u8; 48];
    com_phrase[..16].copy_from_slice(&random_number);
    com_phrase[16..].copy_from_slice(telephone_hash);
    let secret_key = StaticSecret::from(derive_key(&com_phrase, &key_hash)?);
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
pub(crate) fn get_signature(text: &str, key_type: &str, telephone_hash: &[u8; 32], phrase: &str) -> Result<Vec<u8>, TokenError> {
    let signing_key = SigningKey::from_bytes(&read_key_or_generate_key(key_type, telephone_hash, phrase)?);
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
    let input = format!("period={}", if period == 0 { 0 } else { timestamp / period });
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

pub fn hkdf_key(key: &[u8]) -> [u8; 32] {
    hkdf_key_deadline(key, 600)
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

pub fn generate_did_claim(id_type: &str, id_name: &str, id_symbol: Option<String>, telephone: Option<String>) -> Result<(IdClaim,[u8; 32], String), TokenError> {
    let id_symbol = id_symbol.unwrap_or("None".to_string());
    let telephone = telephone.unwrap_or("None".to_string());
    let id_symbol_hash = match id_type {
        "User" => {
            let real_id_symbol = match id_symbol.as_str() {
                "None" => SystemTime::now().duration_since(UNIX_EPOCH)
                        .unwrap_or_else(|_| std::time::Duration::from_secs(0)).as_millis().to_string(),
                _ => id_symbol
            };
            calc_sha256(format!("{}-id_card:{}", id_name, real_id_symbol).as_bytes())
        },
        _ => calc_sha256(format!("{}-id_card:{}", id_name, id_symbol).as_bytes()),
    };
    let telephone_hash = match id_type {
        "User" => match telephone.as_str() {
                "None" => calc_sha256(format!("{}-telephone:-", id_name).as_bytes()),
                _ => calc_sha256(format!("{}-telephone:{}", id_name, telephone).as_bytes()),
            },
        _  => calc_sha256(format!("{}-telephone:-", id_name).as_bytes())
    };
    let face_image_hash = calc_sha256(format!("{}-face_image:-", id_name).as_bytes());
    let file_hash_hash = calc_sha256(format!("{}-file_hash:-", id_name).as_bytes());
    let now_millis = SystemTime::now().duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| std::time::Duration::from_secs(0)).as_millis();
    let phrase = sha256_prefix(&hkdf_key_deadline(
        format!("timestamp:{},nickname:{},telephone:{}", now_millis.to_string(),
                id_name, URL_SAFE_NO_PAD.encode(telephone_hash)).as_bytes(), 0), 10);

    let mut claim = IdClaim::new(id_type, &phrase, id_name, telephone_hash, id_symbol_hash, face_image_hash, file_hash_hash);
    let zeroed_key: [u8; 32] = [0; 32];
    let crypt_secret = get_secret_key("hellman",id_type, &telephone_hash, &phrase).unwrap_or_else(|_| zeroed_key);
    claim.set_crypt_key_and_save_to_file(crypt_secret);
    Ok((claim, crypt_secret, phrase))
}

pub fn get_user_token_from_file(did: &str) -> Result<(UserContext, String), TokenError> {
    let user_token_file = get_path_in_sys_key_dir(&format!("user_{}.token", did));
    match user_token_file.exists() {
        true => read_user_token_from_file(user_token_file.as_path()),
        false => Ok((UserContext::default(), "unknown".to_string()))
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
    let id_hash = [0u8; 32];
    let device_key = read_key_or_generate_key("Device", &id_hash, "None")?;
    let local_key = read_key_or_generate_key("System", &id_hash, "None")?;
    let mut com_hash = [0u8; 64];
    com_hash[..32].copy_from_slice(&device_key);
    com_hash[32..].copy_from_slice(&local_key);
    let crypt_key = calc_sha256(com_hash.as_ref());
    let token_raw_data = encrypt(json_string.as_bytes(), &crypt_key, 0);
    fs::write(user_token_file, token_raw_data)?;
    Ok(json_string)
}

pub fn create_user_token(did: &str, nickname: &str, id_type: &str, telephone_hash: &[u8; 32], phrase: &str) -> UserContext {
    let zeroed_key: [u8; 32] = [0u8; 32];
    let user_token_file = get_path_in_sys_key_dir(&format!("user_{}.token", did));
    match user_token_file.exists() {
        true => {
            let Ok((mut context, _)) = read_user_token_from_file(user_token_file.as_path())
                else { todo!() };
            let crypt_key = get_secret_key("context", id_type, telephone_hash, phrase).unwrap_or([0u8; 32]);
            let aes_key_old_vec = decrypt(&URL_SAFE_NO_PAD.decode(
                context.get_aes_key_encrypted()).unwrap_or(zeroed_key.to_vec()), &crypt_key, 0);
            let aes_key_old = convert_vec_to_key(&aes_key_old_vec);
            let secret_key_new = get_random_secret_key(id_type, telephone_hash, phrase)
                .unwrap_or([0u8; 32]);
            let default_expire = 90*24*3600;
            context.set_auth_sk_with_secret(&URL_SAFE_NO_PAD.encode(secret_key_new), default_expire);
            let aes_key_new = context.get_crypt_key();
            transfer_private_data(&aes_key_old, &aes_key_new, &context.get_private_paths());
            let crypt_key = get_secret_key("context", id_type, telephone_hash, phrase).unwrap_or([0u8; 32]);
            let aes_key_encrypted = URL_SAFE_NO_PAD.encode(encrypt(&context.get_crypt_key(), &crypt_key, 0));
            context.set_aes_key_encrypted(&aes_key_encrypted);
            context
        }
        false => {
            let default_permissions = "standard".to_string();
            let default_private_paths = serde_json::to_string(&vec!["config", "preset", "wildcard", "style"]).unwrap_or("".to_string());
            let mut default_context = UserContext::new(nickname, &default_permissions, &default_private_paths);
            let secret_key = get_random_secret_key(id_type, telephone_hash, phrase)
                .unwrap_or([0u8; 32]);
            let default_expire = 90*24*3600;
            default_context.set_auth_sk_with_secret(&URL_SAFE_NO_PAD.encode(secret_key), default_expire);
            let crypt_key = get_secret_key("context", id_type, telephone_hash, phrase).unwrap_or([0u8; 32]);
            let aes_key_encrypted = URL_SAFE_NO_PAD.encode(encrypt(&default_context.get_crypt_key(), &crypt_key, 0));
            default_context.set_aes_key_encrypted(&aes_key_encrypted);
            default_context
        }
    }
}

fn read_user_token_from_file(user_token_file: &Path) -> Result<(UserContext, String), TokenError> {
    let id_hash = [0u8; 32];
    let device_key = read_key_or_generate_key("Device", &id_hash, "None")?;
    let local_key = read_key_or_generate_key("System", &id_hash, "None")?;
    let mut com_hash = [0u8; 64];
    com_hash[..32].copy_from_slice(&device_key);
    com_hash[32..].copy_from_slice(&local_key);
    let crypt_key = calc_sha256(com_hash.as_ref());
    let token_raw_data = fs::read(user_token_file)?;
    let token_data = decrypt(&token_raw_data, &crypt_key, 0);
    let user_token: Value = serde_json::from_slice(&token_data).unwrap_or(serde_json::json!({}));
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
    let mut context = UserContext::new(nickname, permissions, private_paths);
    context.set_auth_sk(auth_sk);
    context.set_aes_key_encrypted(aes_key_encrypted);
    Ok((context, sig.to_string()))
}
pub fn convert_to_auth_sk_in_context(secret_key: &[u8; 32], expire: u64) -> String {
    let expire_bytes = expire.to_le_bytes();
    let mut auth_sk = [0; 40];
    auth_sk[..32].copy_from_slice(secret_key);
    auth_sk[32..].copy_from_slice(&expire_bytes);
    URL_SAFE_NO_PAD.encode(auth_sk)
}

pub fn convert_vec_to_key(vec: &Vec<u8>) -> [u8; 32] {
    let mut key: [u8; 32] = [0; 32];
    let len_vec = vec.len();
    let len = if len_vec > 32 { 32 } else { len_vec };
    key.copy_from_slice(&vec[..len]);
    key
}

pub fn transfer_private_data(aes_key_old: &[u8; 32], aes_key_new: &[u8; 32], private_paths: &Vec<String>) {
     // TODO
}