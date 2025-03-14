use std::{
        cell::OnceCell,
        collections::HashMap,
        fmt::{self, Debug},
        error::Error,
        str::FromStr,
        io,
        net::{Ipv4Addr, IpAddr},
        time::{Duration, Instant} };
use tokio::{
        select,
        sync::{oneshot, Mutex},
        time::{self, Interval},
        sync::mpsc::{self, UnboundedSender, UnboundedReceiver} };
use libp2p::{
        kad, tcp, identify, noise, yamux, ping, mdns, autonat, relay, dcutr, upnp, rendezvous,
        core::multiaddr::Protocol,
        identity::{Keypair, ed25519},
        futures::{StreamExt, FutureExt},
        metrics::{Metrics, Recorder},
        swarm::SwarmEvent,
        gossipsub::{self, TopicHash},
        request_response::{self, OutboundFailure, OutboundRequestId, ResponseChannel},
        Swarm, Multiaddr, PeerId,};
use std::sync::Arc;
use futures::{executor::block_on};
use prometheus_client::{metrics::info::Info, registry::Registry};
use zeroize::Zeroizing;
use rand::Rng;

use crate::p2p::{http_service, utils};
use crate::p2p::protocol::*;
use crate::p2p::req_resp::*;
use crate::p2p::config::*;
use crate::p2p::error::P2pError;
use crate::p2p::utils::PeerIdExt;
use crate::dids::token_utils;
use crate::dids::claims::IdClaim;
use crate::utils::systeminfo::SystemInfo;
use crate::shared;

const TOKEN_SERVER_IPADDR: &str = "0.0.0.0";
const TOKEN_SERVER_PORT: u16 = 2316;

/// `EventHandler` is the trait that defines how to handle requests / broadcast-messages from remote peers.
pub(crate) trait EventHandler: Debug + Send + 'static {
    /// Handles an inbound request from a remote peer.
    fn handle_inbound_request(&self, request: Vec<u8>) -> Result<Vec<u8>, Box<dyn Error>>;
    /// Handles an broadcast message from a remote peer.
    fn handle_broadcast(&self, topic: &str, message: Vec<u8>, sender: PeerId);
}

#[derive(Clone, Debug)]
pub(crate) struct Client {
    cmd_sender: UnboundedSender<Command>,
    peer_id: String,
    sys_did: String,
}

/// Create a new p2p node, which consists of a `Client` and a `Server`.
pub(crate) async fn new<E: EventHandler>(config: Config, sys_claim: &IdClaim, sysinfo: &SystemInfo) -> Result<(Client, Server<E>), Box<dyn Error>> {
    let (cmd_sender, cmd_receiver) = mpsc::unbounded_channel();
    let server = Server::new(config, sys_claim, sysinfo, cmd_receiver).await?;
    let local_peer_id = server.get_peer_id().to_base58();
    let client = Client {
        cmd_sender,
        peer_id: local_peer_id[local_peer_id.len() - 7..].to_string(),
        sys_did: sys_claim.gen_did(),
    };

    Ok((client, server))
}

impl Client {
    /// Get the short peer id of the local node.
    pub(crate) fn get_peer_id(&self) -> String {
        self.peer_id.clone()
    }

    /// Get the did of the local node.
    pub(crate) fn get_sys_did(&self) -> String {
        self.sys_did.clone()
    }

    /// Send a blocking request to the `target` peer.
    pub(crate) async fn request(&self, target: &str, request: Vec<u8>) -> Result<Vec<u8>, P2pError> {
        let target = target.parse().map_err(|_| P2pError::InvalidPeerId)?;

        let (responder, receiver) = oneshot::channel();
        let _ = self.cmd_sender.send(Command::SendRequest {
            target,
            request,
            responder,
        });

        let response = receiver.await.map_err(|_| P2pError::RequestRejected)?;
        Ok(response?)
    }

    /// Publish a message to the given topic.
    pub(crate) async fn broadcast(&self, topic: String, message: Vec<u8>) {
        let _ = self.cmd_sender.send(Command::Broadcast {
            topic: topic.into(),
            message: message,
        });
    }

    /// Get known peers of the node.
    pub(crate) async fn get_known_peers(&self) -> Vec<String> {
        self.get_node_status().await
            .known_peers
            .into_keys()
            .map(|id| id.to_base58())
            .collect()
    }

    pub(crate) async fn get_node_status(&self) -> NodeStatus {
        let (responder, receiver) = oneshot::channel();
        let _ = self.cmd_sender.send(Command::GetStatus(responder));
        receiver.await.unwrap_or_default()
    }
}

/// The commands sent by the `Client` to the `Server`.
pub(crate) enum Command {
    SendRequest {
        target: PeerId,
        request: Vec<u8>,
        responder: oneshot::Sender<ResponseType>,
    },
    Broadcast {
        topic: String,
        message: Vec<u8>,
    },
    GetStatus(oneshot::Sender<NodeStatus>),
}

pub(crate) struct Server<E: EventHandler> {
    sys_did: String,
    /// The actual network service.
    network_service: Swarm<Behaviour>,
    /// The local peer id.
    local_peer_id: PeerId,
    /// The addresses that the server is listening on.
    listened_addresses: Vec<Multiaddr>,
    /// The receiver of commands from the client.
    cmd_receiver: UnboundedReceiver<Command>,
    /// The handler of events from remote peers.
    event_handler: OnceCell<E>,
    /// The ticker to periodically discover new peers.
    discovery_ticker: Interval,
    /// The pending outbound requests, awaiting for a response from the remote.
    pending_outbound_requests: HashMap<OutboundRequestId, oneshot::Sender<ResponseType>>,
    /// The topics will be hashed when subscribing to the gossipsub protocol,
    /// but we need to keep the original topic names for broadcasting.
    pubsub_topics: Vec<String>,
    upstream_nodes: Vec<PeerIdWithMultiaddr>,
    metrics: Metrics,
    is_global: bool,
    upnp_mapped: bool,
    rendezvous_point: PeerId,
    rendezvous_cookie: Option<rendezvous::Cookie>,
    connection_failure_counts: Mutex<HashMap<PeerId, Vec<Instant>>>,
    connection_quality: Mutex<HashMap<PeerId, ConnectionQuality>>,
}

#[derive(Debug, Clone)]
struct ConnectionQuality {
    // 平均 RTT (毫秒)
    avg_rtt: f64,
    // RTT 样本数
    rtt_samples: usize,
    // 最后更新时间
    last_updated: Instant,
    // 连接类型 (直连、中继等)
    connection_type: ConnectionType,
    // 连接评分 (0-100)
    score: u8,
}

#[derive(Debug, Clone, PartialEq)]
enum ConnectionType {
    Direct,
    Relayed,
    Unknown,
}

impl<E: EventHandler> Server<E> {
    /// Create a new `Server`.
    pub(crate) async fn new(
        config: Config,
        sys_claim: &IdClaim,
        sysinfo: &SystemInfo,
        cmd_receiver: UnboundedReceiver<Command>,
    ) -> Result<Self, Box<dyn Error>> {
        let mut metric_registry = Registry::default();
        let (sys_hash_id, sys_phrase) = token_utils::get_key_hash_id_and_phrase("System", &sys_claim.get_symbol_hash());
        let local_keypair  = Keypair::from(ed25519::Keypair::from(ed25519::SecretKey::
            try_from_bytes(Zeroizing::new(token_utils::read_key_or_generate_key("System", &sys_claim.get_symbol_hash(), &sys_phrase, false, false)))?));

        let is_upstream_server = if let Some(v) = config.is_upstream_server { v } else { false };
        let pubsub_topics: Vec<_> = config.pubsub_topics.clone();
        let req_resp_config = config.req_resp.clone();

        let netifs_ip = utils::get_ipaddr_from_netif()?;
        let locale_ip = sysinfo.local_ip.parse::<Ipv4Addr>().unwrap();
        let public_ip = sysinfo.public_ip.parse::<Ipv4Addr>().unwrap();
        let is_global = if locale_ip == public_ip || is_upstream_server { true } else { false };
        tracing::info!("P2P_node({:?}/{:?}) ready to start up : public_ip({:?}) is_global({})",
            locale_ip, 
            netifs_ip, 
            public_ip, 
            is_global
        );
        let mut swarm =
            libp2p::SwarmBuilder::with_existing_identity(local_keypair.clone())
                .with_tokio()
                .with_tcp(
                    tcp::Config::default().nodelay(true),
                    noise::Config::new,
                    yamux::Config::default,
                )?
                .with_quic()
                .with_dns()?
                .with_relay_client(noise::Config::new, yamux::Config::default)?
                .with_bandwidth_metrics(&mut metric_registry)
                .with_behaviour(|key, relay_client | {
                    Behaviour::new(key.clone(), Some(relay_client), is_global, pubsub_topics.clone(), Some(req_resp_config.clone()))
                })?
                .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
                .build();

        let locale_port = if is_global { TOKEN_SERVER_PORT } else { 0 };
        swarm
            .listen_on(format!("/ip4/0.0.0.0/udp/{}/quic-v1", locale_port).parse().unwrap())
            .unwrap();
        swarm
            .listen_on(format!("/ip4/0.0.0.0/tcp/{}", locale_port).parse().unwrap())
            .unwrap();

        let mut listened_addresses = Vec::new();

        block_on(async {
            let mut delay = futures_timer::Delay::new(std::time::Duration::from_secs(1)).fuse();
            loop {
                futures::select! {
            event = swarm.next() => {
                match event.unwrap() {
                    SwarmEvent::NewListenAddr { address, .. } => {
                        tracing::debug!(%address, "📣 P2P node listening on address:");
                        listened_addresses.push(address);
                    }
                    event => {},
                }
            }
            _ = delay => {
                break;
            }
        }
            }
        });


        let short_peer_id = swarm.local_peer_id().short_id();
        let sys_did = sys_claim.gen_did();
        let short_sys_did = sys_did.chars().skip(sys_did.len() - 7).collect::<String>();
        tracing::info!("P2P_node({}/{}) start up, peer_id({})", short_sys_did, short_peer_id, swarm.local_peer_id().to_base58());

        swarm.behaviour_mut().kademlia
            .set_mode(Some(kad::Mode::Server));

        let upstream_nodes = if let Some(ref upstream_nodes) = config.address.upstream_nodes {
            for upstream_node in upstream_nodes {
                let upstream_addr = Multiaddr::from_str(format!("{}/p2p/{}", upstream_node.address(), upstream_node.peer_id()).as_str())?;
                swarm.dial(upstream_addr.clone()).unwrap();
                let id = swarm.listen_on(upstream_addr.clone().with(Protocol::P2pCircuit))?;
                tracing::info!("P2P_node({}) listening on relay_node({})", short_peer_id, upstream_addr);

            }
            upstream_nodes
        } else {
            &BOOT_NODES
        };

        let random_index = rand::thread_rng().gen_range(0..upstream_nodes.len());
        let rendezvous_point = upstream_nodes[random_index].peer_id();
        
        match config.address.boot_nodes {
            Some(ref boot_nodes) => {
                for boot_node in boot_nodes.iter() {
                    swarm.behaviour_mut().add_address(&boot_node.peer_id(), boot_node.address());
                };
            }
            None => {}
        };

        swarm.behaviour_mut().discover_peers();

        let metrics = Metrics::new(&mut metric_registry);
        let build_info = Info::new(vec![("version".to_string(), env!("CARGO_PKG_VERSION"))]);
        metric_registry.register(
            "build",
            "A metric with a constant '1' value labeled by version",
            build_info,
        );
        let metrics_path = config.metrics_path.clone();
        tokio::task::spawn(async move {
            if let Err(e) = http_service::metrics_server(metric_registry, locale_ip, metrics_path).await {
                tracing::error!("Metrics server failed: {e}");
            }
        });

        // Create a ticker to periodically discover new peers.
        let interval_secs = config.get_discovery_interval();
        let instant = time::Instant::now() + Duration::from_secs(15);
        let discovery_ticker = time::interval_at(instant, Duration::from_secs(interval_secs));

        Ok(Self {
            sys_did,
            network_service: swarm,
            local_peer_id: local_keypair.public().into(),
            listened_addresses,
            cmd_receiver,
            event_handler: OnceCell::new(),
            discovery_ticker,
            pending_outbound_requests: HashMap::new(),
            pubsub_topics,
            upstream_nodes: upstream_nodes.to_vec(),
            metrics,
            is_global,
            upnp_mapped: false,
            rendezvous_point,
            rendezvous_cookie: None,
            connection_failure_counts: Mutex::new(HashMap::new()),
            connection_quality: Mutex::new(HashMap::new()),
        })
    }

    /// Set the handler of events from remote peers.
    pub(crate) fn set_event_handler(&mut self, handler: E) {
        self.event_handler.set(handler).unwrap();
    }

    /// Run the `Server`.
    pub(crate) async fn run(mut self) {
        loop {
            select! {
                // Next discovery process.
                _ = self.discovery_ticker.tick() => {
                    self.network_service.behaviour_mut().discover_peers();
                    if self.rendezvous_cookie.is_some() {
                        if let Some(rendezvous) = self.network_service.behaviour_mut().rendezvous_client.as_mut() {
                            let random_index = rand::thread_rng().gen_range(0..self.upstream_nodes.len());
                            self.rendezvous_point = self.upstream_nodes[random_index].peer_id();
                            rendezvous.discover(
                                Some(rendezvous::Namespace::new(NAMESPACE.to_string()).unwrap()),
                                self.rendezvous_cookie.clone(),
                                None,
                                self.rendezvous_point,
                            )
                        }
                    }
                },
                // Next command from the `Client`.
                msg = self.cmd_receiver.recv() => {
                    if let Some(cmd) = msg {
                        self.handle_command(cmd);
                    }
                },
                // Next event from `Swarm`.
                event = self.network_service.select_next_some() => {
                    self.metrics.record(&event);
                    self.handle_swarm_event(event);
                },
            }

        }
    }

    // Process the next command coming from `Client`.
    fn handle_command(&mut self, cmd: Command) {
        match cmd {
            Command::SendRequest {
                target,
                request,
                responder,
            } => self.handle_outbound_request(target, request, responder),
            Command::Broadcast { topic, message } => self.handle_outbound_broadcast(topic, message),
            Command::GetStatus(responder) => responder.send(self.get_status()).unwrap(),
        }
    }
    // Process the next event coming from `Swarm`.
    fn handle_swarm_event(&mut self, event: SwarmEvent<BehaviourEvent>) {
        let behaviour_ev = match event {
            SwarmEvent::Behaviour(ev) => ev,
            SwarmEvent::NewListenAddr { address, .. } => {
                tracing::info!(%address, "📣 P2P_node listening on address");
                return self.update_listened_addresses(); },

            SwarmEvent::ListenerClosed {
                reason, addresses, ..
            } => return Self::log_listener_close(reason, addresses),

            SwarmEvent::ExternalAddrConfirmed { address } 
            => {
                tracing::info!("External address confirmed from relay node: {address}");
                return;
            }

            SwarmEvent::ConnectionEstablished {
                peer_id, endpoint, ..
            } => {
                tracing::info!("Established new connection peer({})={}", peer_id.short_id(), endpoint.get_remote_address());
                let peer_id_clone = peer_id.clone();
                if self.upstream_nodes.iter().any(|node| node.peer_id() == peer_id) {
                    if let Some(rendezvous) = self.network_service.behaviour_mut().rendezvous_client.as_mut() {
                        if let Err(error) = rendezvous.register(
                            rendezvous::Namespace::new(NAMESPACE.to_string()).unwrap(),
                            peer_id_clone,
                            None,
                        ) {
                            tracing::error!("Failed to register after ConnectionEstablished({}): {error}", peer_id.short_id());
                            return;
                        }
                        tracing::info!("Connection established with rendezvous point: {}", peer_id.short_id());
                        rendezvous.discover(
                            Some(rendezvous::Namespace::new(NAMESPACE.to_string()).unwrap()),
                            None,
                            None,
                            self.rendezvous_point,
                        );
                    }
                }
                return;
            }

            // Can't connect to the `peer`, remove it from the DHT.
            SwarmEvent::OutgoingConnectionError {
                peer_id: Some(peer),
                ..
            } => {
                if self.record_peer_failure(&peer, "Connection") {
                    tracing::info!("Connection failures has reached the threshold, remove the node: {:?}", peer.short_id());
                    self.network_service.behaviour_mut().remove_peer(&peer);
                }
                return;
            },
            

            _ => return,
        };
        self.handle_behaviour_event(behaviour_ev);
    }

    fn handle_behaviour_event(&mut self, ev: BehaviourEvent) {
        tracing::debug!("{:?}", ev);
        self.record_event_metrics(&ev);
        match ev {
            BehaviourEvent::Ping(ping::Event {
                peer,
                result: Ok(rtt),
                ..
            }) => {
                self.update_connection_quality(&peer, rtt);
            },
            
            // The remote peer is unreachable, remove it from the DHT.
            BehaviourEvent::Ping(ping::Event {
                peer,
                result: Err(_),
                ..
            }) => {
                if self.record_peer_failure(&peer, "Ping") {
                    tracing::info!("Ping failures has reached the threshold, remove the node: {:?}", peer.short_id());
                    self.network_service.behaviour_mut().remove_peer(&peer)
                }
            },

            BehaviourEvent::Mdns(mdns::Event::Discovered(list)) => {
                for (peer_id, multiaddr) in list {
                    tracing::info!("mDNS discovered a new peer: {} at {multiaddr}", peer_id.short_id());
                    self.add_addresses(&peer_id, vec![multiaddr]);
                    self.network_service.behaviour_mut().pubsub.add_explicit_peer(&peer_id);
                }
            }
            BehaviourEvent::Mdns(mdns::Event::Expired(list)) => {
                for (peer_id, _multiaddr) in list {
                    tracing::info!("mDNS discover peer has expired: {}", peer_id.short_id());
                    self.network_service.behaviour_mut().pubsub.remove_explicit_peer(&peer_id);
                }
            }
            BehaviourEvent::Pubsub(gossipsub::Event::Message {
                propagation_source: peer_id,
                message_id: id,
                message,
            }) => {
                tracing::debug!("<<==== Got broadcast message with id({id}) from peer({}): '{}'",
                    peer_id.short_id(), String::from_utf8_lossy(&message.data));
                self.handle_inbound_broadcast(message)
            },
            // BehaviourEvent::Identify(identify::Event::Sent { peer_id, .. }) => {
            //     tracing::info!("Sent identify info: {:?}", ev)
            // }
            // See https://docs.rs/libp2p/latest/libp2p/kad/index.html#important-discrepancies
            BehaviourEvent::Identify(identify::Event::Received {
                peer_id,
                info: identify::Info {
                    listen_addrs,
                    protocols,
                    observed_addr,
                    agent_version,
                    .. }, connection_id 
            }) => {
                if protocols.iter().any(|p| *p == TOKEN_PROTO_NAME) {
                    tracing::info!("P2P_node({}) add peer({}, {:?})", self.get_short_id(), peer_id.short_id(), agent_version);
                    self.add_addresses(&peer_id, listen_addrs);
                };
                self.network_service.add_external_address(observed_addr.clone());
                tracing::debug!("P2P_node({}) add external_address({:?})", self.get_short_id(), observed_addr.clone());

                if let Some(rendezvous) = self.network_service.behaviour_mut().rendezvous_client.as_mut() {
                    if let Err(error) = rendezvous.register(
                        rendezvous::Namespace::new(NAMESPACE.to_string()).unwrap(),
                        self.rendezvous_point,
                        None,
                    ) {
                        tracing::error!("Failed to register after Identify({}): {error}", peer_id.short_id());
                        return;
                    }
                    tracing::info!("Connection established with rendezvous point {}", peer_id.short_id());
                }
            }

            BehaviourEvent::ReqResp(request_response::Event::Message {
                message:
                request_response::Message::Request { request, channel, .. },
                ..
            }) => self.handle_inbound_request(request, channel),

            BehaviourEvent::ReqResp(request_response::Event::Message {
                message:
                request_response::Message::Response { request_id, response, },
                ..
            }) => self.handle_inbound_response(request_id, response),

            BehaviourEvent::ReqResp(request_response::Event::OutboundFailure {
                request_id,
                error,
                ..
            }) => self.handle_outbound_failure(request_id, error),

            BehaviourEvent::AutonatClient(autonat::v2::client::Event {
                server,
                tested_addr,
                bytes_sent,
                result: Ok(()),
            }) => {
                self.network_service.add_external_address(tested_addr.clone());
                tracing::info!("Tested {tested_addr} with {}. Sent {bytes_sent} bytes for verification. Everything Ok and verified.", server.short_id());
            }
            BehaviourEvent::AutonatClient(autonat::v2::client::Event {
                server,
                tested_addr,
                bytes_sent,
                result: Err(e),
            }) => {
                tracing::info!("Tested {tested_addr} with {}. Sent {bytes_sent} bytes for verification. Failed with {e:?}.", server.short_id());
            }

            BehaviourEvent::Upnp(upnp::Event::NewExternalAddr(addr)) => {
                tracing::info!("UPnP address: {}", addr);
                self.network_service.add_external_address(addr);
                self.upnp_mapped = true;
            }
            BehaviourEvent::Upnp(upnp::Event::GatewayNotFound) => {
                tracing::debug!("UPnP gateway not found");
            }
            BehaviourEvent::Upnp(upnp::Event::NonRoutableGateway) => {
                tracing::debug!("UPnP gateway unreachable");
            }

            BehaviourEvent::RelayClient(
                relay::client::Event::ReservationReqAccepted { .. },
            ) => {
                //assert!(opts.mode == Mode::Listen);
                tracing::info!("Relay accepted our reservation request");
            }
            BehaviourEvent::RelayClient(event) => {
                tracing::info!(?event)
            }
            BehaviourEvent::Dcutr(event) => {
                tracing::info!(?event)
            }

            BehaviourEvent::Rendezvous(
                rendezvous::server::Event::PeerRegistered { peer, registration },
            ) => {
                tracing::info!(
                    "Peer {} registered for namespace '{}'",
                    peer,
                    registration.namespace
                );
            }
            BehaviourEvent::Rendezvous(
                rendezvous::server::Event::DiscoverServed {
                    enquirer,
                    registrations,
                },
            ) => {
                tracing::info!(
                    "Served peer {} with {} registrations",
                    enquirer,
                    registrations.len()
                );
            }

            BehaviourEvent::RendezvousClient(
                rendezvous::client::Event::Registered {
                    namespace,
                    ttl,
                    rendezvous_node,
                },
            ) => {
                tracing::info!(
                    "Registered for namespace '{}' at rendezvous point {} for the next {} seconds",
                    namespace,
                    rendezvous_node.short_id(),
                    ttl
                );
            }
            BehaviourEvent::RendezvousClient(
                rendezvous::client::Event::RegisterFailed {
                    rendezvous_node,
                    namespace,
                    error,
                },
            ) => {
                tracing::error!(
                    "Failed to register: rendezvous_node={}, namespace={}, error_code={:?}",
                    rendezvous_node.short_id(),
                    namespace,
                    error
                );
                return;
            }

            BehaviourEvent::RendezvousClient(
                rendezvous::client::Event::Discovered {
                    registrations,
                    cookie: new_cookie,
                    ..
            }) => {
                self.rendezvous_cookie.replace(new_cookie);

                for registration in registrations {
                    for address in registration.record.addresses() {
                        let peer = registration.record.peer_id();
                        tracing::info!(%peer, %address, "Discovered peer");

                        let p2p_suffix = Protocol::P2p(peer);
                        let address_with_p2p =
                            if !address.ends_with(&Multiaddr::empty().with(p2p_suffix.clone())) {
                                address.clone().with(p2p_suffix)
                            } else {
                                address.clone()
                            };

                        self.network_service.dial(address_with_p2p).unwrap();
                    }
                }
            }
            
            _ => {}
        }
    }

    // Inbound requests are handled by the `EventHandler` which is provided by the application layer.
    fn handle_inbound_request(&mut self, request: Vec<u8>, ch: ResponseChannel<ResponseType>) {
        if let Some(handler) = self.event_handler.get() {
            let response = handler.handle_inbound_request(request).map_err(|_| ());
            self.network_service.behaviour_mut().send_response(ch, response);
        }
    }

    // Store the request_id with the responder so that we can send the response later.
    fn handle_outbound_request(
        &mut self,
        target: PeerId,
        request: Vec<u8>,
        responder: oneshot::Sender<ResponseType>,
    ) {
        let req_id = self
            .network_service
            .behaviour_mut()
            .send_request(&target, request);
        self.pending_outbound_requests.insert(req_id, responder);
    }

    // An outbound request failed, notify the application layer.
    fn handle_outbound_failure(&mut self, request_id: OutboundRequestId, error: OutboundFailure) {
        if let Some(responder) = self.pending_outbound_requests.remove(&request_id) {
            tracing::error!("❌ Outbound request failed: {:?}", error);
            let _ = responder.send(Err(()));
        } else {
            tracing::warn!("❗ Received failure for unknown request: {}", request_id);
            debug_assert!(false);
        }
    }

    // An inbound response was received, notify the application layer.
    fn handle_inbound_response(&mut self, request_id: OutboundRequestId, response: ResponseType) {
        if let Some(responder) = self.pending_outbound_requests.remove(&request_id) {
            let _ = responder.send(response);
        } else {
            tracing::warn!("❗ Received response for unknown request: {}", request_id);
            debug_assert!(false);
        }
    }

    // Inbound broadcasts are handled by the `EventHandler` which is provided by the application layer.
    fn handle_inbound_broadcast(&mut self, message: gossipsub::Message) {
        if let Some(handler) = self.event_handler.get() {
            let topic_hash = message.topic;
            if message.source.is_none() {
                tracing::debug!("❗ 收到没有源节点信息的广播消息，已丢弃");
                return;
            }
            let peer_id = message.source.unwrap();
            match self.get_topic(&topic_hash) {
                Some(topic) => handler.handle_broadcast(&topic, message.data, peer_id),
                None => {
                    tracing::debug!("❗ Received broadcast for unknown topic: {:?}", topic_hash);
                    debug_assert!(false);
                }
            }
        }
    }

    // Broadcast a message to all peers subscribed to the given topic.
    fn handle_outbound_broadcast(&mut self, topic: String, message: Vec<u8>) {
        let _ = self
            .network_service
            .behaviour_mut()
            .broadcast(topic, message);
    }

    fn add_addresses(&mut self, peer_id: &PeerId, addresses: Vec<Multiaddr>) {
        for addr in addresses.into_iter() {
            let parts = addr.iter().collect::<Vec<_>>();
            if let Protocol::Ip4(ip4) = parts[0] {
                self.network_service.behaviour_mut().add_address(peer_id, addr);
            }
        }
    }

    fn get_external_address(&self) -> Vec<Multiaddr> {
        self.network_service.external_addresses()
            .map(|addr| addr.clone())
            .collect()
    }

    fn get_status(&mut self) -> NodeStatus {
        let known_peers = self.network_service.behaviour_mut().known_peers();
        let pubsub_peers = self.network_service.behaviour_mut().pubsub_peers();
        let connection_quality = self.connection_quality.try_lock().unwrap().clone();
        let external_addresses = self.get_external_address();
        let total_in = 0;
        let total_out = 0;
        NodeStatus {
            local_peer_id: self.local_peer_id.to_base58(),
            local_sys_did: self.sys_did.clone(),
            listened_addresses: self.listened_addresses.clone(),
            known_peers_count: known_peers.len(),
            known_peers,
            pubsub_peers,
            external_addresses,
            connection_quality,
            total_inbound_bytes: total_in,
            total_outbound_bytes: total_out,
        }
    }

    fn get_peer_id(&self) -> PeerId {
        self.local_peer_id.clone()
    }

    fn get_node_did(&self) -> String {
        self.sys_did.clone()
    }

    fn get_short_id(&self) -> String {
        let sys_did = self.sys_did.clone();
        let short_sys_did = sys_did.chars().skip(sys_did.len() - 7).collect::<String>();
        format!("{}/{}", short_sys_did, self.local_peer_id.short_id())
    }

    fn update_listened_addresses(&mut self) {
        self.listened_addresses = self
            .network_service
            .listeners()
            .map(ToOwned::to_owned)
            .collect();
    }

    /// Returns the topic name for the given topic hash.
    fn get_topic(&self, topic_hash: &TopicHash) -> Option<String> {
        for t in &self.pubsub_topics {
            let topic = gossipsub::IdentTopic::new(t);
            if topic.hash() == *topic_hash {
                return Some(t.clone());
            }
        }
        None
    }

    fn log_listener_close(reason: io::Result<()>, addresses: Vec<Multiaddr>) {
        let addrs = addresses
            .into_iter()
            .map(|a| a.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        match reason {
            Ok(()) => {
                tracing::info!("📣 Listener ({}) closed gracefully", addrs)
            }
            Err(e) => {
                tracing::error!("❌ Listener ({}) closed: {}", addrs, e)
            }
        }
    }

    fn record_peer_failure(&mut self, peer: &PeerId, failure_type: &str) -> bool {
        const MAX_FAILURE_COUNT: usize = 3;
        const FAILURE_WINDOW_SECS: u64 = 60;
        let now = Instant::now();
        
        // 使用 try_lock 而不是 lock.await
        if let Ok(mut failure_counts) = self.connection_failure_counts.try_lock() {
            let failures = failure_counts.entry(peer.clone()).or_insert_with(Vec::new);
            failures.push(now);
            
            // 移除超过时间窗口的失败记录
            let cutoff = now - Duration::from_secs(FAILURE_WINDOW_SECS);
            failures.retain(|&time| time >= cutoff);
            let recent_failures = failures.len();
            
            if recent_failures >= MAX_FAILURE_COUNT {
                tracing::debug!("节点失败次数达到阈值({}次/{}秒)，移除节点: {:?}，最后失败类型: {}", 
                              MAX_FAILURE_COUNT, FAILURE_WINDOW_SECS, peer, failure_type);
                // 重置计数器
                failure_counts.remove(peer);
                
                // 同时从 gossipsub 的对等节点列表中移除
                self.network_service.behaviour_mut().pubsub.remove_explicit_peer(peer);
                tracing::info!("Removed node from gossipsub node list: {:?}", peer);
                
                return true; // 应该移除节点
            } else {
                tracing::debug!("节点失败(第{}次/{}秒)，失败类型: {}，暂不移除节点: {:?}", 
                              recent_failures, FAILURE_WINDOW_SECS, failure_type, peer);
                return false; // 不需要移除节点
            }
        } else {
            // 如果无法获取锁，记录警告并默认不移除节点
            tracing::debug!("无法获取失败计数锁，暂不处理节点失败: {:?}, 类型: {}", peer, failure_type);
            return false;
        }
    }

    fn update_connection_quality(&self, peer: &PeerId, rtt: Duration) {
        if let Ok(mut quality_map) = self.connection_quality.try_lock() {
            let quality = quality_map.entry(peer.clone()).or_insert_with(|| ConnectionQuality {
                avg_rtt: 0.0,
                rtt_samples: 0,
                last_updated: Instant::now(),
                connection_type: ConnectionType::Unknown,
                score: 50, // 初始评分
            });
            
            // 更新 RTT 平均值 (使用指数移动平均)
            let rtt_ms = rtt.as_millis() as f64;
            if quality.rtt_samples == 0 {
                quality.avg_rtt = rtt_ms;
            } else {
                // 权重因子 (0.2 表示新样本占 20% 权重)
                let alpha = 0.2;
                quality.avg_rtt = (1.0 - alpha) * quality.avg_rtt + alpha * rtt_ms;
            }
            
            quality.rtt_samples += 1;
            quality.last_updated = Instant::now();
            
            // 更新评分 (RTT 越低评分越高，简单线性映射)
            // 假设 RTT < 50ms 为最佳 (100分)，RTT > 500ms 为最差 (0分)
            let score = if quality.avg_rtt < 50.0 {
                100
            } else if quality.avg_rtt > 500.0 {
                0
            } else {
                ((500.0 - quality.avg_rtt) / 450.0 * 100.0) as u8
            };
            
            quality.score = score;
            
            tracing::debug!(
                "更新节点 {:?} 的连接质量: RTT={:.2}ms, 样本数={}, 评分={}",
                peer, quality.avg_rtt, quality.rtt_samples, quality.score
            );
        }
    }

    fn record_event_metrics(&self, event: &BehaviourEvent) {
        // 根据事件类型记录不同的指标
        match event {
            BehaviourEvent::Ping(_) => {
                // 记录 Ping 事件指标
            },
            BehaviourEvent::Pubsub(_) => {
                // 记录 Pubsub 事件指标
            },
            // 其他事件类型...
            _ => {}
        }
    }
}

/// The node status, for debugging.
#[derive(Clone, Debug, Default)]
pub(crate) struct NodeStatus {
    pub(crate) local_peer_id: String,
    pub(crate) local_sys_did: String,
    pub(crate) listened_addresses: Vec<Multiaddr>,
    pub(crate) known_peers_count: usize,
    pub(crate) known_peers: HashMap<PeerId, Vec<Multiaddr>>,
    pub(crate) pubsub_peers: HashMap<PeerId, Vec<TopicHash>>,
    pub(crate) external_addresses: Vec<Multiaddr>,
    pub(crate) connection_quality: HashMap<PeerId, ConnectionQuality>,
    pub(crate) total_inbound_bytes: u64,
    pub(crate) total_outbound_bytes: u64,
}

impl NodeStatus {
    pub(crate) fn short_format(&self) -> String {
        let shared_data = shared::get_shared_data();
        let short_sys_did = (|| {
            self.local_sys_did[self.local_sys_did.len() - 7..].to_string()
        })();
        let short_peer_id = (|| {
            self.local_peer_id[self.local_peer_id.len() - 7..].to_string()
        })();
        let external_addresses = self.external_addresses
            .iter()
            .map(|addr| addr.to_string())
            .collect::<Vec<_>>()
            .join(",");
        let head= format!("NodeStatus({short_sys_did}/{short_peer_id}), peers({})[", self.known_peers_count);
        let peers = self.known_peers.iter()
            .map(|(peer_id, multiaddrs)| {
                let peer_did = shared_data.get_did_node(&peer_id.to_base58()).unwrap_or_else(|| peer_id.to_base58().into());
                let short_peer_did = peer_did.chars().skip(peer_did.len() - 7).collect::<String>();
                let ip_addrs = multiaddrs.iter()
                    .filter_map(|addr| {
                        let parts = addr.iter().collect::<Vec<_>>();
                        if let (Some(Protocol::Ip4(ip4)), Some(Protocol::Tcp(port))) = (parts.get(0), parts.get(1)) {
                            Some(format!("{}:{}", ip4, port))
                        } else {
                            Some(addr.to_string())
                        }
                    })
                    .collect::<Vec<_>>()
                    .join(",");
                let rtt = self.connection_quality.get(peer_id).map(|q| format!("{:.2}ms", q.avg_rtt)).unwrap_or("?".to_string());
                format!("({}:{})", short_peer_did, rtt)
            }).collect::<Vec<_>>().join(";");
        let listeneds: String = self.listened_addresses
            .iter()
            .filter_map(|addr| {
                let parts = addr.iter().collect::<Vec<_>>();
                if let (Some(Protocol::Ip4(ip4)), Some(Protocol::Tcp(port))) = (parts.get(0), parts.get(1)) {
                    Some(format!("{}:{}", ip4, port))
                } else {
                    Some(addr.to_string())
                }
            })
            .collect::<Vec<_>>()
            .join(",");
        let pubsubs = self.pubsub_peers.iter()
            .map(|(peer_id, topichashs)| {
                let peer_did = shared_data.get_did_node(&peer_id.to_base58()).unwrap_or_else(|| peer_id.to_base58().into());
                let short_peer_did = peer_did.chars().skip(peer_did.len() - 7).collect::<String>();
                let topics = (*topichashs).iter().map(|topic| topic.to_string()).collect::<Vec<_>>().join(", ");

                format!("{}", short_peer_did)
            }).collect::<Vec<_>>().join(";");
        format!("{}{}], pubsubs({})({})", head, peers,
                self.pubsub_peers.len(), pubsubs)
    }
}
