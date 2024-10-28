use std::collections::HashMap;
use std::fs::File;
use std::io::{self, Read, Error, ErrorKind};
use std::path::{Path, MAIN_SEPARATOR, PathBuf};
use std::ffi::OsString;
use std::env;
use std::net::{IpAddr, Ipv4Addr, TcpListener, SocketAddr, TcpStream};
use std::str::FromStr;
use serde_json::Value;

//use pnet::datalink::interfaces;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use sha2::{Sha256, Digest};
use rand::{Rng, rngs::SmallRng};
use rand::SeedableRng;
use tokio::time::{self, Duration};
use tracing::info;
use lazy_static::lazy_static;

use crate::error::TokenError;
use crate::systeminfo::SystemBaseInfo;
use crate::token;

const CHUNK_SIZE: usize = 1024 * 1024; // 1 MB chunks


lazy_static! {
    pub static ref SYSTEM_BASE_INFO: SystemBaseInfo = SystemBaseInfo::generate();
    pub static ref VERBOSE_INFO: bool = {
        match env::var("SIMPLEAI_VERBOSE") {
            Ok(val) => if val=="on" {true} else {false},
            Err(_) => false,
        }
    };
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
    if *VERBOSE_INFO {
        println!("TcpStream({}) local_ip={}", socket_addr.to_string(), local_ip);
    }
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
     let response = token::REQWEST_CLIENT.get(default_url)
        .send()
        .await?
        .text()
        .await?;
    let ip_addr = response.parse::<Ipv4Addr>()?;
    if *VERBOSE_INFO {
        println!("CURL({}) public_ip={}", default_url, ip_addr);
    }
    //println!("get_ipaddr_from_public, out, CURL({}) public_ip={}", default_url, ip_addr);
    //print!(".");
    Ok(ip_addr)
}

pub(crate) async fn get_location() -> Result<String, TokenError> {
    //println!("get_location, in");
    let response = token::REQWEST_CLIENT.get("http://ip-api.com/json")
        .send()
        .await?
        .text()
        .await?;
    let json: Value = serde_json::from_str(&response)?;
    let country_code = json["countryCode"].as_str().map(|s| s.to_string()).unwrap_or("CN".to_string());
    if *VERBOSE_INFO {
        println!("get_location country_code: {}", country_code);
    }
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
    if *VERBOSE_INFO {
        println!("get_port_availability, out, port: {}", real_port);
    }
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

    if *VERBOSE_INFO {
        println!("get program_hash and ui_hash: {}, {}", py_hash_output, ui_hash_output);
    }
    //println!("get_program_hash, out, hash: {py_hash_output}, {ui_hash_output}");
    //print!(".");
    Ok((py_hash_output.to_string(), ui_hash_output.to_string()))
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


pub fn calc_sha256(input: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(input);
    let result = hasher.finalize();
    let mut output = [0u8; 32];
    output.copy_from_slice(&result[..]);
    output
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

pub fn get_path_in_root_dir(catalog: &str, filename: &str) -> PathBuf {
    let sysinfo = &SYSTEM_BASE_INFO;
    let root_dirs = PathBuf::from(sysinfo.root_dir.clone());
    root_dirs.join(catalog).join(filename)
}


