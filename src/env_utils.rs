use std::fs::File;
use std::io::{self, Error, ErrorKind};
use std::path::Path;
use std::net::{IpAddr, Ipv4Addr, TcpListener, SocketAddr, TcpStream};
use std::str::FromStr;
use libp2p::identity::ed25519;

use pkcs8::{EncryptedPrivateKeyInfo, PrivateKeyInfo, LineEnding, ObjectIdentifier, SecretDocument};

//use pnet::datalink::interfaces;
use ed25519_dalek::{VerifyingKey, SigningKey, Signer};
use x25519_dalek::{StaticSecret, PublicKey};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use sha2::{Sha256, Digest};
use hkdf::Hkdf;
use rand::{thread_rng, Rng, rngs::SmallRng};
use rand::SeedableRng;
use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Key };
use argon2::Argon2;
use tokio::time::{self, Duration};
use lazy_static::lazy_static;

use crate::error::TokenError;
use crate::systeminfo::SystemInfo;

pub const ALGORITHM_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.112");

/// Ed25519 Algorithm Identifier.
pub const ALGORITHM_ID: pkcs8::AlgorithmIdentifierRef<'static> = pkcs8::AlgorithmIdentifierRef {
    oid: ALGORITHM_OID,
    parameters: None,
};

lazy_static! {
    pub static ref SYSTEM_INFO: SystemInfo = SystemInfo::generate();
}
pub(crate) fn read_keypaire_or_generate_keypaire() -> Result<ed25519::Keypair, Box<dyn std::error::Error>> {
    Ok(ed25519::Keypair::from(ed25519::SecretKey::try_from_bytes(read_key_or_generate_key()?)?))
}
fn read_key_or_generate_key() -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let sysinfo =  &SYSTEM_INFO;

    let password = format!("{}:{}@{}/{}/{}/{}/{}/{}/{}", sysinfo.root_dir, sysinfo.exe_name, sysinfo.host_name,
                           sysinfo.os_name, sysinfo.os_type, sysinfo.cpu_brand, sysinfo.cpu_cores,
                           sysinfo.ram_total + sysinfo.gpu_memory, sysinfo.gpu_name);
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

            //let private_key = PKey::generate_ed25519()?;
            //let pem_key = private_key.private_key_to_pem_pkcs8_passphrase(Cipher::aes_256_cbc(), password.as_bytes())?;
            //let mut file = File::create(file_path)?;
            //file.write_all(&pem_key)?;
            //private_key.raw_private_key()?
        }
        true => {
            let Ok((_, s_doc)) = SecretDocument::read_pem_file(file_path) else { todo!() };
            let private_key = EncryptedPrivateKeyInfo::try_from(s_doc.as_bytes()).unwrap().decrypt(&password.as_bytes())?;
            let pkey = private_key.as_bytes();
            let pkinfo = PrivateKeyInfo::try_from(pkey)?;

            //let mut file = File::open(file_path)?;
            //let mut key_data = Vec::new();
            //file.read_to_end(&mut key_data)?;
            //let private_key = PKey::private_key_from_pem_passphrase(&key_data, password.as_bytes())?;

            //let pk = private_key.as_bytes();
            let mut pk_array: [u8; 32] = [0; 32];
            pk_array.copy_from_slice(pkinfo.private_key);
            pk_array
        }
    };

    Ok(private_key.try_into().unwrap())
}


pub(crate) async fn get_ipaddr_from_stream(dns_ip: Option<&str>) -> Result<Ipv4Addr, TokenError> {
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
    }
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

