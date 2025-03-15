use std::fs::File;
use std::io::{Read, Write};
use std::env;
use std::path::Path;
use std::net::{IpAddr, Ipv4Addr};
use libp2p::PeerId;
use openssl::pkey::PKey;
use openssl::symm::Cipher;
use sysinfo::System;
use std::net::{SocketAddr, TcpStream};
use std::io::{Error, ErrorKind};
use std::str::FromStr;
use if_addrs;

use crate::p2p::error::P2pError;


pub(crate) fn read_key_or_generate_key() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut sys = System::new_all();
    sys.refresh_all();

    let exe_path = env::current_exe()?;
    let cpu = sys.cpus().get(0).unwrap();
    let password = format!("{}@{}/{}/{}/{}/{}/{}/{}", exe_path.display(), System::host_name().unwrap(),
        System::distribution_id(), System::name().unwrap(), cpu.brand(),sys.cpus().len(), cpu.frequency(), sys.total_memory()/(1024*1024*1024));
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

    Ok(private_key)
}

pub(crate) fn get_ipaddr_from_netif() -> Result<Vec<Ipv4Addr>, Box<dyn std::error::Error>> {
    let mut ipaddrs: Vec<Ipv4Addr> = Vec::new();
    
    let interfaces = if_addrs::get_if_addrs()?;
    
    for interface in interfaces {
        // 跳过 bridge 和 docker 接口
        if interface.name.starts_with("bridge") || interface.name.starts_with("docker") {
            continue;
        }
        
        // 只处理 IPv4 地址
        if let if_addrs::IfAddr::V4(ref addr) = interface.addr {
            let ipv4 = addr.ip;
            
            // 使用与原函数相同的过滤逻辑
            if (!ipv4.is_private() && !ipv4.is_loopback() && !ipv4.is_multicast())
                || (ipv4.is_private()) {
                ipaddrs.push(ipv4);
                tracing::info!("Network IFace({}) ip={}", interface.name, ipv4);
            }
        }
    }
    
    Ok(ipaddrs)
}

pub(crate) fn get_ipaddr_from_stream(dns_ip: Option<String>) -> Result<Ipv4Addr, P2pError> {
    let default_ip = Ipv4Addr::new(114,114,114,114);
    let socket_addr = match dns_ip {
        Some(dns_ip) => SocketAddr::new(IpAddr::V4(Ipv4Addr::from_str(&dns_ip).unwrap_or(default_ip)), 53),
        None => SocketAddr::new(IpAddr::V4(default_ip), 53)
    };
    let stream = TcpStream::connect(socket_addr)?;
    let local_addr = stream.local_addr()?;
    let local_ip = local_addr.ip();
    tracing::info!("TcpStream({}) local_ip={}", socket_addr.to_string(), local_ip);
    match local_ip {
        IpAddr::V4(ipv4) => Ok(ipv4),
        _ => Err(P2pError::IoError(Error::new(ErrorKind::Other, "No IPv4 address found"))),
    }
}

pub(crate) async fn get_ipaddr_from_public() -> Result<Ipv4Addr, P2pError> {
    let default_url = "https://ipinfo.io/ip";
    let client = reqwest::Client::new();
    let response = client.get(default_url).send().await?;
    let ip_str = response.text().await?;
    let ip_addr = ip_str.parse::<Ipv4Addr>()?;
    tracing::info!("CURL({}) public_ip={}", default_url, ip_addr);
    Ok(ip_addr)
}


pub(crate) fn get_short_id(peer_id: PeerId) -> String {
    let base58_peer_id = peer_id.to_base58();
    let short_peer_id = base58_peer_id.chars().skip(base58_peer_id.len() - 7).collect::<String>();
    short_peer_id
}

pub trait PeerIdExt {
    /// 返回 PeerId 的短格式（最后7个字符）
    fn short_id(&self) -> String;
}

impl PeerIdExt for PeerId {
    fn short_id(&self) -> String {
        let base58_peer_id = self.to_base58();
        base58_peer_id.chars().skip(base58_peer_id.len().saturating_sub(7)).collect()
    }
}

