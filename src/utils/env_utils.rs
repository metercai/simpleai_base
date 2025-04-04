use std::collections::HashMap;
use std::fs::File;
use std::io::{self, Read, Error, ErrorKind};
use std::path::{Path, MAIN_SEPARATOR, PathBuf};
use std::ffi::OsString;
use std::env;
use std::net::{IpAddr, Ipv4Addr, TcpListener, SocketAddr, TcpStream};
use std::str::FromStr;
use serde_json::Value;

use pyo3::prelude::*;
use pyo3::types::PyList;

//use pnet::datalink::interfaces;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use sha2::{Sha256, Digest};
use rand::{Rng, rngs::SmallRng};
use rand::SeedableRng;
use tokio::time::{self, Duration};
use tracing::{debug, info};
use lazy_static::lazy_static;

use crate::utils::error::TokenError;
use crate::utils::systeminfo::SystemBaseInfo;
use crate::dids::{token_utils, REQWEST_CLIENT};

const CHUNK_SIZE: usize = 1024 * 1024; // 1 MB chunks


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
    debug!("TcpStream({}) local_ip={}", socket_addr.to_string(), local_ip);

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
     let response = REQWEST_CLIENT.get(default_url)
        .send()
        .await?
        .text()
        .await?;
    let ip_addr = response.parse::<Ipv4Addr>()?;
    debug!("CURL({}) public_ip={}", default_url, ip_addr);

    //println!("get_ipaddr_from_public, out, CURL({}) public_ip={}", default_url, ip_addr);
    //print!(".");
    Ok(ip_addr)
}

pub(crate) async fn get_location() -> String {
    debug!("get_location, in");

    match REQWEST_CLIENT.get("https://ip-api.com/json")
        .send()
        .await {
            Ok(response) => match response.text().await {
                Ok(text) => match serde_json::from_str::<Value>(&text) {
                    Ok(json) => {
                        let country_code = json["countryCode"]
                            .as_str()
                            .map(|s| s.to_string())
                            .unwrap_or("CN".to_string());
                        debug!("get_location country_code: {}", country_code);
                        country_code
                    },
                    Err(_) => {
                        debug!("Failed to parse JSON response, using default CN");
                        "CN".to_string()
                    }
                },
                Err(_) => {
                    debug!("Failed to get response text, using default CN");
                    "CN".to_string()
                }
            },
            Err(_) => {
                debug!("Failed to send request, using default CN");
                "CN".to_string()
            }
    }
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
    debug!("get_port_availability, out, port: {}", real_port);

    //println!("get_port_availability, out, port: {real_port}");
    //print!(".");
    real_port
}

pub(crate) async fn get_random_port_availability(ip: Ipv4Addr, port: u16) -> u16 {
    let mut rng = SmallRng::from_entropy();
    loop {
        let random_port = rng.gen_range((port-100)..=port);
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

pub(crate) async fn get_program_hash() -> Result<(String, String), TokenError> {
    let path_py = vec!["", "modules", "extras", "ldm_patched/modules", "enhanced", "enhanced/libs", "comfy", "comfy/comfy"];
    let path_ui = vec!["language/cn.json", "simplesdxl_log.md", "webui.py", "enhanced/attached/welcome.png"];
    let path_root = env::current_dir()?;
    let extensions = vec!["py", "whl"];
    let mut py_hashes: HashMap<String, String> = HashMap::new(); // 键类型改为String

    for path in path_py {
        // 将路径中的/替换为系统分隔符，确保正确找到文件
        let path_os = path.replace('/', &std::path::MAIN_SEPARATOR.to_string());
        let full_path = path_root.join(path_os);

        if full_path.is_dir() {
            for entry in std::fs::read_dir(&full_path)? {
                let entry = entry?;
                if entry.file_type()?.is_file() {
                    if let Some(ext) = entry.path().extension().and_then(|s| s.to_str()) {
                        if extensions.contains(&ext) {
                            // 统一路径分隔符为/
                            let subpath = entry.path()
                                .strip_prefix(&path_root)?
                                .to_string_lossy()
                                .replace(std::path::MAIN_SEPARATOR, "/");

                            let Ok((hash, _)) = get_file_hash_size(&entry.path()) else { todo!() };
                            py_hashes.insert(subpath, hash);
                        }
                    }
                }
            }
        } else if full_path.is_file() {
            if let Some(ext) = full_path.extension().and_then(|s| s.to_str()) {
                if extensions.contains(&ext) {
                    // 统一路径分隔符为/
                    let subpath = full_path
                        .strip_prefix(&path_root)?
                        .to_string_lossy()
                        .replace(std::path::MAIN_SEPARATOR, "/");

                    let Ok((hash, _)) = get_file_hash_size(&full_path) else { todo!() };
                    py_hashes.insert(subpath, hash);
                }
            }
        }
    }

    // 使用统一后的路径字符串进行排序
    let mut keys: Vec<String> = py_hashes.keys().cloned().collect();
    keys.sort_by(|a, b| a.to_lowercase().cmp(&b.to_lowercase()));

    let mut combined_py_hash = Sha256::new();
    for key in &keys {
        if let Some(hash) = py_hashes.get(key) {
            combined_py_hash.update(hash.as_bytes());
        }
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

    debug!("get program_hash and ui_hash: {}, {}", py_hash_output, ui_hash_output);

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


pub fn get_file_hash_size(path: &Path) -> io::Result<(String, u64)> {
    let is_text = match path.extension().and_then(|ext| ext.to_str()) {
        Some(ext) if matches!(ext, "txt" | "log" | "py" | "rs" | "toml" | "md" | "json") => true,
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


pub(crate) fn get_ram_and_gpu_info() -> String {
    {
        let results = Python::with_gil(|py| -> PyResult<String> {
            let systeminfo= PyModule::import_bound(py, "simpleai_base.systeminfo").expect("No simpleai_base.systeminfo.");
            let result: String = systeminfo.getattr("get_ram_and_gpu_info")?
                .call0()?.extract()?;
            Ok(result)
        });
        let result = results.unwrap();
        result
    }
}


