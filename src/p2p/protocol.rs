use libp2p::{autonat, dcutr, mdns, upnp};
use libp2p::identify;
use libp2p::kad;
use libp2p::ping;
use libp2p::relay;
use libp2p::multiaddr::Protocol;
use libp2p::request_response::{self, OutboundRequestId, ResponseChannel, ProtocolSupport};
use libp2p::gossipsub::{self, IdentTopic, TopicHash};
use libp2p::swarm::behaviour::toggle::Toggle;
use libp2p::swarm::{NetworkBehaviour, StreamProtocol};
use libp2p::{identity, Multiaddr, PeerId};
use std::{
    str::FromStr,
    net::IpAddr,
    time::Duration,
    error::Error,
    collections::{hash_map::DefaultHasher, HashMap},
    hash::{Hash, Hasher},
};
use rand::rngs::OsRng;
use lazy_static::lazy_static;

use crate::p2p::req_resp;
use crate::p2p::config::{ReqRespConfig, PeerIdWithMultiaddr};

lazy_static! {
    static ref  BOOT_NODES: Vec<PeerIdWithMultiaddr> = vec![
    PeerIdWithMultiaddr::from_str("/dns4/p2p.token.tm/tcp/2316/p2p/12D3KooWFapNfD5a27mFPoBexKyAi4E1RTP4ifpfmNKBV8tsBL4X").unwrap(),
    //PeerIdWithMultiaddr::from_str("/dns4/p2p.simpai.cn/tcp/2316/p2p/12D3KooWFHKN2kYDzPtfQrikN6bGkAnqeJLYt7eNNg9dZa5wxd9E").unwrap()
    ];
}

pub(crate) const TOKEN_PROTO_NAME: StreamProtocol = StreamProtocol::new("/token/kad/1.0.0");

#[derive(NetworkBehaviour)]
pub(crate) struct Behaviour {
    ping: ping::Behaviour,
    identify: identify::Behaviour,
    pub(crate) kademlia: kad::Behaviour<kad::store::MemoryStore>,
    mdns: mdns::tokio::Behaviour,
    pub(crate) pubsub: gossipsub::Behaviour,
    req_resp: request_response::Behaviour<req_resp::GenericCodec>,
    relay: Toggle<relay::Behaviour>,
    relay_client: Toggle<relay::client::Behaviour>,
    autonat: Toggle<autonat::v2::server::Behaviour>,
    autonat_client: Toggle<autonat::v2::client::Behaviour>,
    dcutr: Toggle<dcutr::Behaviour>,
    upnp: Toggle<upnp::tokio::Behaviour>,
}

impl Behaviour {
    pub(crate) fn new(
        local_key: identity::Keypair,
        relay_client: Option<relay::client::Behaviour>,
        is_global: bool,
        pubsub_topics: Vec<String>,
        req_resp_config: Option<ReqRespConfig>,
    ) -> Self {
        let pub_key = local_key.public();
        let kademlia = {
            // 使用 Default::default() 创建配置，然后设置协议名称
            let mut kademlia_config = kad::Config::new(TOKEN_PROTO_NAME);
            // kademlia_config.set_protocol_names(vec![TOKEN_PROTO_NAME]);
            // Instantly remove records and provider records.
            // kademlia_config.set_record_ttl(Some(Duration::from_secs(0)));
            // kademlia_config.set_provider_record_ttl(Some(Duration::from_secs(0)));
            let kademlia = kad::Behaviour::with_config(
                pub_key.to_peer_id(),
                kad::store::MemoryStore::new(pub_key.to_peer_id()),
                kademlia_config,
            );
            kademlia
        };

        let autonat = if is_global {
            Some(autonat::v2::server::Behaviour::new(OsRng)
            )
        } else {
            None
        }.into();

        let autonat_client = if !is_global {
            Some(autonat::v2::client::Behaviour::new(
                OsRng,
                autonat::v2::client::Config::default()
                .with_probe_interval(Duration::from_secs(2)),
            ))
        } else {
            None
        }.into();

        let relay = if is_global {
            Some(relay::Behaviour::new(PeerId::from(pub_key.clone()), Default::default()))
        } else {
            None
        }.into();

        let mdns = 
            mdns::tokio::Behaviour::new(
                mdns::Config::default(), pub_key.clone().to_peer_id()).expect("Mdns service initialization failed！");

        let dcutr = if !is_global {
            Some(dcutr::Behaviour::new(pub_key.clone().to_peer_id()))
        } else {
            None
        }.into();

        let upnp = if !is_global {
            Some(upnp::tokio::Behaviour::default())
        } else {
            None
        }.into();

        Self {
            ping: ping::Behaviour::new(ping::Config::default().with_interval(Duration::from_secs(15))),
            identify: identify::Behaviour::new(
                identify::Config::new("token/0.1.0".to_string(), pub_key.clone()).with_agent_version(
                    format!("p2pserver/{}", env!("CARGO_PKG_VERSION")),
                ),
            ),
            kademlia,
            mdns,
            pubsub: Self::new_gossipsub(local_key, pubsub_topics),
            req_resp: Self::new_req_resp(req_resp_config),
            relay,
            relay_client: relay_client.into(),
            autonat,
            autonat_client,
            dcutr,
            upnp,
        }
    }

    fn new_gossipsub(
        local_key: identity::Keypair,
        topics: Vec<String>,
    ) -> gossipsub::Behaviour {
        let message_id_fn = |message: &gossipsub::Message| {
            let mut s = DefaultHasher::new();
            message.data.hash(&mut s);
            gossipsub::MessageId::from(s.finish().to_string())
        };

        let gossipsub_config = gossipsub::ConfigBuilder::default()
            .heartbeat_initial_delay(Duration::from_millis(500))
            .heartbeat_interval(Duration::from_millis(5000))
            .history_length(10)
            .history_gossip(10)
            .validation_mode(gossipsub::ValidationMode::Strict)
            .message_id_fn(message_id_fn)
            .build()
            .expect("Failed to create gossipsub configuration");

        let mut gossipsub = gossipsub::Behaviour::new(
            gossipsub::MessageAuthenticity::Signed(local_key),
            gossipsub_config,
        ).expect("Failed to create gossipsub behaviour");

        for t in topics {
            let topic = IdentTopic::new(t);
            gossipsub.subscribe(&topic).expect("Failed to subscribe to topic");
        }
        gossipsub
    }

    fn new_req_resp(config: Option<ReqRespConfig>) -> request_response::Behaviour<req_resp::GenericCodec> {
        if let Some(config) = config {
            return req_resp::BehaviourBuilder::new()
                //.with_connection_keep_alive(config.connection_keep_alive)
                .with_request_timeout(config.request_timeout)
                .with_max_request_size(config.max_request_size)
                .with_max_response_size(config.max_response_size)
                .build();
        }

        req_resp::BehaviourBuilder::default().build()
    }

    pub fn send_request(&mut self, target: &PeerId, request: Vec<u8>) -> OutboundRequestId {
        self.req_resp.send_request(target, request)
    }

    pub fn send_response(&mut self, ch: ResponseChannel<req_resp::ResponseType>, response: req_resp::ResponseType) {
        let _ = self.req_resp.send_response(ch, response);
    }

    pub(crate) fn discover_peers(&mut self) {
        if self.known_peers().is_empty() {
            tracing::info!("☕ The known peers is empty and the default boot node will be added.");
        } 
        for boot_node in BOOT_NODES.iter() {
            self.kademlia.add_address(&boot_node.peer_id(), boot_node.address());
        }
        tracing::info!("☕ Starting a discovery process: known_peers={}", self.known_peers().len());
        let _ = self.kademlia.bootstrap();
        
    }

    pub(crate) fn known_peers(&mut self) -> HashMap<PeerId, Vec<Multiaddr>> {
        let mut peers = HashMap::new();
        for b in self.kademlia.kbuckets() {
            for e in b.iter() {
                peers.insert(*e.node.key.preimage(), e.node.value.clone().into_vec());
            }
        }
        peers
    }

    pub(crate) fn pubsub_peers(&mut self) -> HashMap<PeerId, Vec<TopicHash>> {
        let mut peers = HashMap::new();
        let mut peers_iter = self.pubsub.all_peers();
        while let Some((peer_id, topics)) = peers_iter.next() {
            let cloned_peer_id = (*peer_id).clone();
            let cloned_topics: Vec<TopicHash> = topics.iter().map(|topic| (*topic).clone()).collect();
            peers.insert(cloned_peer_id, cloned_topics);
        }
        peers
    }

    pub(crate) fn broadcast(&mut self, topic: String, message: Vec<u8>) -> Result<(), Box<dyn Error>> {
        let topic = gossipsub::IdentTopic::new(topic);
        self.pubsub.publish(topic.clone(), message)?;
        tracing::info!("☕ =====>>>  Broadcast message to topic {}", topic);
        Ok(())
    }

    pub(crate) fn add_address(&mut self, peer_id: &PeerId, addr: Multiaddr) {
        if can_add_to_dht(&addr) {
            tracing::info!("☕ Adding address {} from {:?} to the DHT.", addr, peer_id);
            self.kademlia.add_address(peer_id, addr);
        }
    }

    pub(crate) fn remove_peer(&mut self, peer_id: &PeerId) {
        tracing::info!("☕ Removing peer {} from the DHT.", peer_id);
        self.kademlia.remove_peer(peer_id);
    }

}

fn can_add_to_dht(addr: &Multiaddr) -> bool {
    let ip = match addr.iter().next() {
        Some(Protocol::Ip4(ip)) => IpAddr::V4(ip),
        Some(Protocol::Ip6(ip)) => IpAddr::V6(ip),
        Some(Protocol::Dns(_)) | Some(Protocol::Dns4(_)) | Some(Protocol::Dns6(_)) => return true,
        _ => return false,
    };

    !ip.is_loopback() && !ip.is_unspecified()
}
