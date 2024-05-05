use std::fs::File;
use std::io::{self, Read, Write, Error, ErrorKind};
use std::env;
use std::path::Path;
use std::net::{IpAddr, Ipv4Addr, TcpListener, SocketAddr, TcpStream};
use std::str::FromStr;
use libp2p::identity::ed25519;
use openssl::pkey::PKey;
use openssl::symm::Cipher;
use sysinfo::System;
use pnet::datalink::interfaces;
use ed25519_dalek::{VerifyingKey, SigningKey, Signer};
use x25519_dalek::{StaticSecret, PublicKey};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use sha2::{Sha256, Digest};
use hkdf::Hkdf;
use rand::{thread_rng, Rng};
use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Key };
use argon2::Argon2;
use tokio::time::{self, Duration};
use tokio::runtime::Runtime;
use std::sync::{Arc, Mutex};
use std::thread;

use crate::error::TokenError;
use crate::claim::SystemInfo;
use crate::gpureport::GpuReport;

pub(crate) fn read_keypaire_or_generate_keypaire() -> Result<ed25519::Keypair, Box<dyn std::error::Error>> {
    Ok(ed25519::Keypair::from(ed25519::SecretKey::try_from_bytes(read_key_or_generate_key()?)?))
}
fn read_key_or_generate_key() -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let mut sys = System::new_all();
    sys.refresh_all();

    let exe_path = env::current_exe()?;
    let cpu = sys.cpus().get(0).unwrap();
    let password = format!("{}@{}/{}/{}/{}/{}/{}/{}", exe_path.display(), System::host_name().unwrap(),
                           System::distribution_id(), System::name().unwrap(), cpu.brand(), sys.cpus().len(), cpu.frequency(), sys.total_memory()/(1024*1024*1024));
    tracing::info!("password: {password}");

    let file_path = Path::new(".token_user.pem");
    let private_key = match file_path.exists() {
        false => {
            let private_key = PKey::generate_ed25519()?;
            let pem_key = private_key.private_key_to_pem_pkcs8_passphrase(Cipher::aes_256_cbc(), password.as_bytes())?;
            let mut file = File::create(file_path)?;
            file.write_all(&pem_key)?;
            private_key.raw_private_key()?
        }
        true => {
            let mut file = File::open(file_path)?;
            let mut key_data = Vec::new();
            file.read_to_end(&mut key_data)?;
            let private_key = PKey::private_key_from_pem_passphrase(&key_data, password.as_bytes())?;
            private_key.raw_private_key()?
        }
    };

    Ok(private_key.try_into().unwrap())
}

pub fn get_system_info() -> SystemInfo {
    let mut sys = System::new_all();
    sys.refresh_all();
    let exe_path = match env::current_exe() {
        Ok(path) => path.to_string_lossy().into_owned(),
        Err(_) => "".to_string(),
    };
    let cpu = sys.cpus().get(0).unwrap();
    let local_ip = get_ipaddr_from_stream(None).unwrap_or_else(|_| Ipv4Addr::new(0, 0, 0, 0));
    let local_ip_out = get_ipaddr_from_stream(Some("8.8.8.8")).unwrap_or_else(|_| Ipv4Addr::new(0, 0, 0, 0));

    let s_public_ip = Arc::new(Mutex::new(None));
    let s_public_ip_clone = Arc::clone(&s_public_ip);
    let s_public_ip_out = Arc::new(Mutex::new(None));
    let s_public_ip_out_clone = Arc::clone(&s_public_ip_out);
    let s_local_port = Arc::new(Mutex::new(0));
    let s_local_port_clone = Arc::clone(&s_local_port);
    let rt_handle = thread::spawn(move || {
        let runtime = Runtime::new().unwrap();
        runtime.block_on(async {
            let public_ip = get_ipaddr_from_public(false).await;
            *s_public_ip_clone.lock().unwrap() = Some(public_ip);
            let public_ip_out = get_ipaddr_from_public(true).await;
            *s_public_ip_out_clone.lock().unwrap() = Some(public_ip_out);
            let port = get_port_availability(local_ip.clone(), 8186).await;
            *s_local_port_clone.lock().unwrap() = port;
        });
    });
    rt_handle.join().unwrap();
    let public_ip = match *s_public_ip.lock().unwrap() {
        Some(Ok(ip)) => ip.to_string(),
        Some(Err(_)) => "Error occurred while retrieving IP".to_string(),
        None => "No IP available".to_string(),
    };
    let public_ip_out = match *s_public_ip_out.lock().unwrap() {
        Some(Ok(ip)) => ip.to_string(),
        Some(Err(_)) => "Error occurred while retrieving IP".to_string(),
        None => "No IP available".to_string(),
    };
    let local_port = *s_local_port.lock().unwrap();

    let report = GpuReport::generate();
    SystemInfo {
        sys_name: System::name().unwrap(),
        local_ip: local_ip.to_string(),
        local_port: local_port,
        public_ip: public_ip,
        mac_address: get_mac_address(local_ip.into()),
        local_ip_out: local_ip_out.to_string(),
        public_ip_out: public_ip_out,
        current_dir: get_current_dir(),
        current_exe: exe_path,
        host_name: System::host_name().unwrap(),
        distribution_id: System::distribution_id(),
        cpu_brand: cpu.brand().to_string(),
        cpu_cores: sys.cpus().len(),
        cpu_frequency: cpu.frequency(),
        total_memory: sys.total_memory(),
        gpu_devices: report.devices,
    }
}

pub(crate) fn get_ipaddr_from_stream(dns_ip: Option<&str>) -> Result<Ipv4Addr, TokenError> {
    let default_ip = Ipv4Addr::new(114,114,114,114);
    let socket_addr = match dns_ip {
        Some(dns_ip) => SocketAddr::new(IpAddr::V4(Ipv4Addr::from_str(dns_ip).unwrap_or(default_ip)), 53),
        None => SocketAddr::new(IpAddr::V4(default_ip), 53)
    };
    let stream = TcpStream::connect(socket_addr)?;
    let local_addr = stream.local_addr()?;
    let local_ip = local_addr.ip();
    tracing::info!("TcpStream({}) local_ip={}", socket_addr.to_string(), local_ip);
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
    let client = reqwest::Client::new();
    let response = client.get(default_url).send().await?;
    let ip_str = response.text().await?;
    let ip_addr = ip_str.parse::<Ipv4Addr>()?;
    tracing::info!("CURL({}) public_ip={}", default_url, ip_addr);
    Ok(ip_addr)
}

pub(crate) async fn get_port_availability(ip: Ipv4Addr, port: u16) -> u16 {
    let addr = format!("{}:{}", ip, port);
    match TcpListener::bind(addr) {
        Ok(_) => port,
        Err(_) => {
            let mut rng = rand::thread_rng();
            loop {
                let random_port = rng.gen_range(8000..=9000);
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
    }
}

pub(crate) fn get_mac_address(ip: IpAddr) -> String {
    let interfaces = interfaces();
    for interface in interfaces {
        for network in interface.ips {
            if network.contains(ip) {
                return format!("{:?}",interface.mac);
            }
        }
    }
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
    output[..result.len()].copy_from_slice(&result[..]);
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
    let mut rng = thread_rng();
    let mut salt = [0u8; 12];
    rng.fill(&mut salt);
    let info = b"model_file_hub_sys";
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
    cipher.encrypt(&nonce, data).unwrap()
}

pub fn decrypt(data: &[u8], key: &[u8]) -> Vec<u8> {
    let aes_key = hkdf_key(key);
    let key = Key::<Aes256Gcm>::from_slice(&aes_key);
    let cipher = Aes256Gcm::new(&key);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    cipher.decrypt(&nonce, data).unwrap()
}

pub fn get_current_dir() -> String {
    match env::current_dir() {
        Ok(path) => path.to_string_lossy().into_owned(),
        Err(_) => "".to_string(),
    }
}

/*pub(crate) fn read_key_or_generate_key() -> Result<Vec<u8>, Box<dyn std::error::Error>> {

    //let key2 = pbkdf2_hmac_array::<Sha256, 20>(password, salt, n);
    let file_path = Path::new(".token_user.pem");
    let private_key = match file_path.exists() {
        false => {
            let mut csprng = OsRng;
            let private_key = SigningKey::generate(&mut csprng).to_bytes();
            let private_key_pkcs8_bytes = PrivateKeyInfo::try_from(private_key.as_ref()).unwrap()
                    .encrypt(csprng, password.as_bytes())?;
            //let private_key_pem = pem::encode(Pem::new("ENCRYPTED PRIVATE KEY", private_key_pkcs8_bytes.as_ref()));
            let private_key_pem =
                EncryptedPrivateKeyInfo::try_from(private_key_pkcs8_bytes).unwrap()
                    .to_pem(Default::default()).unwrap();

            let mut file = OpenOptions::new()
                .write(true)
                .create(true)
                .open(file_path)?;
            file.write_all(private_key_pem.as_ref())?;
            private_key
        },
        true => {
            let private_key_pem = fs::read_to_string(file_path)?;
            println!("File content:\n{}", private_key_pem);
            let enc_pk = EncryptedPrivateKeyInfo::try_from(pem::parse(private_key_pem).unwrap().contents()).unwrap();
            let private_key = enc_pk.decrypt(password).unwrap();
            private_key
        }
    };

    Ok(private_key)
}*/

