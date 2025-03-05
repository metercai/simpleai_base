use std::path::Path;
use std::error::Error;
use std::{fmt, str::FromStr};
use crate::p2p::error::P2pError;
use libp2p::{multiaddr, Multiaddr, PeerId};
use serde::{Deserialize, Serialize};

#[derive(Clone, Default, Deserialize)]
pub(crate) struct Config {
    pub(crate) address: Address,
    pub(crate) is_relay_server: Option<bool>,
    pub(crate) pubsub_topics: Vec<String>,
    pub(crate) metrics_path: String,
    pub(crate) discovery_interval: Option<u64>,
    pub(crate) broadcast_interval: Option<u64>,
    pub(crate) node_status_interval: Option<u64>,
    pub(crate) request_interval: Option<u64>,
    pub(crate) req_resp: ReqRespConfig
}

#[derive(Clone, Default, Deserialize)]
pub(crate) struct Address {
    pub(crate) boot_nodes: Option<Vec<PeerIdWithMultiaddr>>,
    pub(crate) relay_nodes: Option<PeerIdWithMultiaddr>,
    pub(crate) dns_ip: Option<String>,
}

/// Configuration for the request-response protocol.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct ReqRespConfig {
    /// Connection keep-alive time in seconds.
    // pub connection_keep_alive: Option<u64>,
    /// Request timeout in seconds.
    pub request_timeout: Option<u64>,
    /// Maximum size of an inbound request.
    pub max_request_size: Option<usize>,
    /// Maximum size of an inbound response.
    pub max_response_size: Option<usize>,
}
impl Config {
    pub(crate) fn from_file(path: &Path) -> Self {
        let file_content = match std::fs::read_to_string(path) {
            Ok(content) => content,
            Err(e) => {
                eprintln!("Failed to read file: {}", e);
                return Self::default();
            }
        };

        let config = match toml::from_str::<Self>(&file_content) {
            Ok(cfg) => cfg,
            Err(e) => {
                eprintln!("Failed to parse TOML: {}", e);
                return Self::default();
            }
        };
        Self{
            address: config.address,
            is_relay_server: config.is_relay_server,
            pubsub_topics: config.pubsub_topics,
            metrics_path: config.metrics_path,
            discovery_interval: config.discovery_interval,
            broadcast_interval: config.broadcast_interval,
            node_status_interval: config.node_status_interval,
            request_interval: config.request_interval,
            req_resp: config.req_resp
        }
    }
    pub(crate) fn get_is_relay_server(&self) -> bool {
        if let Some(v) = self.is_relay_server { v } else { false }
    }
    pub(crate) fn get_discovery_interval(&self) -> u64 {
        if let Some(v) = self.discovery_interval { v } else { 30 }
    }
    pub(crate) fn get_broadcast_interval(&self) -> u64 {
        if let Some(v) = self.broadcast_interval { v } else { 60 }
    }
    pub(crate) fn get_node_status_interval(&self) -> u64 {
        if let Some(v) = self.node_status_interval { v } else { 35 }
    }
    pub(crate) fn get_request_interval(&self) -> u64 {
        if let Some(v) = self.request_interval { v } else { 70 }
    }
}


/// Peer ID with multiaddress.
///
/// This struct represents a decoded version of a multiaddress that ends with `/p2p/<peerid>`.
///
/// # Example
///
/// ```
/// use p2pserver::config::PeerIdWithMultiaddr;
/// let addr: PeerIdWithMultiaddr =
///     "/ip4/127.0.0.1/tcp/34567/p2p/12D3KooWSoC2ngFnfgSZcyJibKmZ2G58kbFcpmSPSSvDxeqkBLJc".parse().unwrap();
/// assert_eq!(addr.peer_id().to_base58(), "12D3KooWSoC2ngFnfgSZcyJibKmZ2G58kbFcpmSPSSvDxeqkBLJc");
/// assert_eq!(addr.address().to_string(), "/ip4/127.0.0.1/tcp/34567");
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(try_from = "String", into = "String")]
pub struct PeerIdWithMultiaddr(PeerId, Multiaddr);

impl PeerIdWithMultiaddr {
    pub fn peer_id(&self) -> PeerId {
        self.0
    }
    pub fn address(&self) -> Multiaddr {
        self.1.clone()
    }
}

impl fmt::Display for PeerIdWithMultiaddr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let proto = multiaddr::Protocol::P2p(self.0);
        let p2p_addr = self.1.clone().with(proto);

        fmt::Display::fmt(&p2p_addr, f)
    }
}

impl FromStr for PeerIdWithMultiaddr {
    type Err = P2pError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (peer_id, multiaddr) = parse_str_addr(s)?;
        Ok(Self(peer_id, multiaddr))
    }
}

impl From<PeerIdWithMultiaddr> for String {
    fn from(ma: PeerIdWithMultiaddr) -> String {
        format!("{}", ma)
    }
}

impl TryFrom<String> for PeerIdWithMultiaddr {
    type Error = P2pError;
    fn try_from(string: String) -> Result<Self, Self::Error> {
        string.parse()
    }
}

fn parse_str_addr(addr_str: &str) -> Result<(PeerId, Multiaddr), P2pError> {
    let mut addr: Multiaddr = addr_str.parse()?;
    let peer_id = match addr.pop() {
        Some(multiaddr::Protocol::P2p(peer_id)) => peer_id,
        _ => return Err(P2pError::InvalidPeerId),
    };

    Ok((peer_id, addr))
}
