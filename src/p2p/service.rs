use std::{
        cell::OnceCell, 
        collections::{hash_map, HashMap, HashSet}, 
        error::Error, 
        fmt::{self, Debug}, 
        io, 
        net::{IpAddr, Ipv4Addr}, 
        path::PathBuf, 
        str::FromStr, 
        time::{Duration, Instant, UNIX_EPOCH} 
    };
use tokio::{
        select,
        sync::{oneshot, Mutex},
        time::{self, Interval},
        sync::mpsc::{self, UnboundedSender, UnboundedReceiver},
        fs::{File, metadata},
        io::AsyncWriteExt, // Required for write_all 
    };

use libp2p::{
        autonat, 
        core::multiaddr::Protocol, 
        dcutr, 
        futures::{FutureExt, StreamExt}, 
        gossipsub::{self, TopicHash}, identify,
        identity::{ed25519, Keypair}, 
        kad::{self, GetClosestPeersOk, QueryId, PeerInfo}, 
        mdns, 
        metrics::{Metrics, Recorder}, 
        noise, ping, relay, rendezvous, 
        request_response::{self, OutboundFailure, OutboundRequestId, ResponseChannel}, 
        swarm::{dial_opts::DialOpts, SwarmEvent}, 
        tcp, upnp, yamux, Multiaddr, PeerId, Swarm};
use std::sync::Arc;
use futures::{executor::block_on};
use prometheus_client::{metrics::info::Info, registry::Registry};
use zeroize::Zeroizing;
use rand::Rng;
use bytes::Bytes;
use serde::{Deserialize, Serialize};

use crate::p2p::utils;
use crate::p2p::protocol::*;
use crate::p2p::req_resp::*;
use crate::p2p::config::*;
use crate::p2p::error::P2pError;
use crate::p2p::utils::PeerIdExt;
use crate::dids::{self, DidToken, TOKIO_RUNTIME};
use crate::dids::claims::IdClaim;
use crate::dids::key_mgr::get_device_key;
use crate::user::shared;

const TOKEN_SERVER_IPADDR: &str = "0.0.0.0";
const TOKEN_SERVER_PORT: u16 = 2316;

/// `EventHandler` is the trait that defines how to handle requests / broadcast-messages from remote peers.
pub(crate) trait EventHandler: Debug + Send + 'static {
    /// Handles an inbound request from a remote peer.
    fn handle_inbound_request(&self, peer: PeerId, request: Vec<u8>) -> Result<Vec<u8>, Box<dyn Error>>;
    /// Handles an broadcast message from a remote peer.
    fn handle_broadcast(&self, topic: &str, message: Vec<u8>, sender: PeerId);

    fn handle_download_progress(&self, peer: PeerId, progress: String);
}

#[derive(Clone, Debug)]
pub(crate) struct Client {
    cmd_sender: UnboundedSender<Command>,
    peer_id: PeerId,
    node_did: String,
}

/// Create a new p2p node, which consists of a `Client` and a `Server`.
pub(crate) async fn new<E: EventHandler>(config: Config, node_claim: &IdClaim, node_phrase: &str) -> Result<(Client, Server<E>), Box<dyn Error + Send + Sync>> {
    let (cmd_sender, cmd_receiver) = mpsc::unbounded_channel();
    // let (event_sender, event_receiver) = mpsc::channel(0);

    let server = Server::new(config, node_claim, node_phrase, cmd_receiver).await?;
    let local_peer_id = server.get_peer_id();

    let client = Client {
        cmd_sender,
        peer_id: local_peer_id,
        node_did: node_claim.gen_did(),
    };

    Ok((client, server))
}

impl Client {
    /// Get the short peer id of the local node.
    pub(crate) fn get_peer_id(&self) -> PeerId {
        self.peer_id.clone()
    }

    pub(crate) fn get_short_id(&self) -> String {
        self.peer_id.short_id()
    }

    /// Get the did of the local node.
    pub(crate) fn get_node_did(&self) -> String {
        self.node_did.clone()
    }

    pub(crate) fn get_short_did(&self) -> String {
        self.node_did.chars().skip(self.node_did.len() - 7).collect::<String>()
    }

    /// Send a blocking request to the `target` peer.
    pub(crate) async fn request(&self, target: &str, request: Bytes) -> Result<Vec<u8>, P2pError> {
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

    /// 发送异步请求，不等待响应结果
    pub(crate) async fn request_async(&self, target: &str, request: Bytes) -> Result<Vec<u8>, P2pError> {
        let target = target.parse().map_err(|_| P2pError::InvalidPeerId)?;
        
        let _ = self.cmd_sender.send(Command::SendOneWayRequest {
            target,
            request,
        });
        
        Ok("Ok".into())
    }

    /// 发送异步请求，并在收到响应时执行回调函数
    /// 
    /// # Example
    /// client.request_with_callback("peer_id", request_data, |result| {
    ///     match result {
    ///         Ok(response) => {
    ///             println!("收到响应: {:?}", response);
    ///             // 处理响应数据...
    ///         },
    ///         Err(e) => {
    ///             println!("请求失败: {:?}", e);
    ///             // 处理错误...
    ///         }
    ///     }
    /// }).unwrap();
    pub(crate) async fn request_with_callback<F>(&self, target: &str, request: Bytes, callback: F) -> Result<(), P2pError>
    where
        F: FnOnce(Result<Vec<u8>, P2pError>) + Send + 'static,
    {
        let target = target.parse().map_err(|_| P2pError::InvalidPeerId)?;

        let (responder, receiver) = oneshot::channel();
        let _ = self.cmd_sender.send(Command::SendRequest {
            target,
            request,
            responder,
        });

        // 在新的任务中等待响应并执行回调
        TOKIO_RUNTIME.spawn(async move {
            let result = match receiver.await {
                Ok(response) => match response {
                    Ok(data) => Ok(data),
                    Err(_) => Err(P2pError::RequestFailed),
                },
                Err(_) => Err(P2pError::RequestRejected),
            };
            callback(result);
        });

        Ok(())
    }

    /// Publish a message to the given topic.
    pub(crate) async fn broadcast(&self, topic: String, message: Bytes) {
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

    pub(crate) async fn get_key_value(&self, key: &str) -> Result<Vec<u8>, P2pError> {
        let (responder, receiver) = oneshot::channel();
        let _ = self.cmd_sender.send(Command::GetKeyValue(key.to_string(), responder));
        let response = receiver.await.map_err(|_| P2pError::RequestRejected)?;
        Ok(response)
    }

    pub(crate) async fn set_key_value(&self, key: String, value: Vec<u8>) {
        let _ = self.cmd_sender.send(Command::SetKeyValue(key, value));
    }

    pub(crate) async fn stop(&self) {
        let _ = self.cmd_sender.send(Command::Stop);
    }

    /// Advertise the local node as the provider of the given file on the DHT.
    pub(crate) async fn provide_file(&self, file_name: String, file_path: PathBuf) {
        let _ = self.cmd_sender.send(Command::StartProviding { file_name, file_path }); // Use unbounded_send
    }

    /// Find the providers for the given file on the DHT.
    pub(crate) async fn get_providers(&self, file_name: String) -> HashSet<PeerId> {
        let (responder, receiver) = oneshot::channel();
        self.cmd_sender
            .send(Command::GetProviders { file_name, responder }) // Use unbounded_send
            .expect("Command receiver not to be dropped.");
        receiver.await.expect("Sender not be dropped.")
    }

    /// Initiate the process of getting a file by name.
    pub(crate) async fn download_file(&self, full_file_name: String) {
        //let (sender, _) = oneshot::channel(); // No need to wait for a result here, EventLoop handles it
        let _ = self.cmd_sender.send(Command::DownloadFile { full_file_name }); // Use unbounded_send
    }



}

/// The commands sent by the `Client` to the `Server`.
pub(crate) enum Command {
    SendRequest {
        target: PeerId,
        request: Bytes,
        responder: oneshot::Sender<ResponseType>,
    },
    SendOneWayRequest {
        target: PeerId,
        request: Bytes,
    },
    Broadcast {
        topic: String,
        message: Bytes,
    },
    GetStatus(oneshot::Sender<NodeStatus>),
    GetKeyValue(String, oneshot::Sender<Vec<u8>>),
    SetKeyValue(String, Vec<u8>),
    Stop,
    
    StartProviding {
        file_name: String,
        file_path: PathBuf,
        // sender: oneshot::Sender<()>,
    },
    GetProviders {
        file_name: String,
        responder: oneshot::Sender<HashSet<PeerId>>,
    },
    DownloadFile {
        full_file_name: String,
    },
}

pub(crate) struct Server<E: EventHandler> {
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
    pending_kad_query: HashMap<QueryId, oneshot::Sender<Vec<u8>>>,
    /// file-sharing related requests
    pending_providing: HashMap<QueryId, String>, // Store file_name with sender
    pending_providers: HashMap<QueryId, oneshot::Sender<HashSet<PeerId>>>, // For GetProviders method returning via oneshot
    pending_downloading: HashMap<QueryId, (String, String, u64)>, // For GetFile internal use, stores (file_key, filename, filesize)
    pending_get_file: HashMap<OutboundRequestId, (String, File, String, u64)>, // Store (file_key, file_handle, filename, filesize) for streaming
    temp_files: HashMap<OutboundRequestId, PathBuf>, // Track temp file paths for cleanup
    completed_downloads: HashSet<String>, // Track successfully completed downloads by file_key
    // Store file paths and names for serving
    provided_files: HashMap<String, PathBuf>, // Map file_key to file_path for serving

    /// The topics will be hashed when subscribing to the gossipsub protocol,
    /// but we need to keep the original topic names for broadcasting.
    pubsub_topics: Vec<String>,
    upstream_nodes: UpstreamNodes,
    lan_addresses: Vec<PeerIdWithMultiaddr>,
    metrics: Metrics,
    is_global: bool,
    upnp_mapped: bool,
    rendezvous_cookie: Option<rendezvous::Cookie>,
    connection_failure_counts: Mutex<HashMap<PeerId, Vec<Instant>>>,
    connection_quality: Mutex<HashMap<PeerId, ConnectionQuality>>,
    /// Flag to control server running state
    stop_flag: bool,
    debug: i32,
    shared_data: &'static shared::SharedData,
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
        node_claim: &IdClaim,
        node_phrase: &str,
        cmd_receiver: UnboundedReceiver<Command>,
    ) -> Result<Self, Box<dyn Error + Send + Sync>> {
        let mut metric_registry = Registry::default();
        let shared_data = shared::get_shared_data();
        let node_did = shared_data.node_did();
        let local_keypair  = Keypair::from(ed25519::Keypair::from(ed25519::SecretKey::
            try_from_bytes(Zeroizing::new(get_device_key()))?));
        let didtoken = DidToken::instance();
        let sysinfo = didtoken.lock().unwrap().get_sysinfo();
        let is_upstream_node = if let Some(v) = config.is_upstream_node { v } else { false };
        let pubsub_topics: Vec<_> = config.pubsub_topics.clone();
        let req_resp_config = config.req_resp.clone();

        let netifs_ip = utils::get_ipaddr_from_netif()?;
        let locale_ip = sysinfo.local_ip.parse::<Ipv4Addr>().unwrap();
        let public_ip = sysinfo.public_ip.parse::<Ipv4Addr>().unwrap();
        let is_global = if locale_ip == public_ip || is_upstream_node { true } else { false };
        let debug = if let Some(v) = config.debug { v } else { 0 };
        if (debug & (1 << 0)) != 0 {
            println!("{} P2P_node({:?}/{:?}) ready to start up.", dids::utils::now_string(), locale_ip, public_ip);
        }
        
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
                //.with_bandwidth_metrics(&mut metric_registry)
                .with_behaviour(|key, relay_client | {
                    Behaviour::new(node_did.clone(), key.clone(), Some(relay_client), is_global, pubsub_topics.clone(), Some(req_resp_config.clone()))
                })?
                .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(120))
                .with_max_negotiating_inbound_streams(128)
                )
                .build();

        let locale_port = if is_global { TOKEN_SERVER_PORT } else { 0 };
        let locale_port = if let Some(v) = config.address.fixed_port { v } else { locale_port };
        
        for ip in &netifs_ip {
            if ip == &locale_ip {
                swarm.listen_on(format!("/ip4/{}/udp/{}/quic-v1", ip, locale_port).parse().unwrap());
                swarm.listen_on(format!("/ip4/{}/tcp/{}", ip, locale_port).parse().unwrap());
            }
        }

        let mut listened_addresses = Vec::new();
        let mut lan_addresses = Vec::new();

        block_on(async {
            let mut delay = futures_timer::Delay::new(std::time::Duration::from_secs(1)).fuse();
            loop {
                futures::select! {
                    event = swarm.next() => {
                        match event.unwrap() {
                            SwarmEvent::NewListenAddr { address, .. } => {
                                if (debug & (1 << 0)) != 0 {
                                    println!("{} 📣 P2P node listening on address:{}", dids::utils::now_string(), address.clone());
                                }
                                listened_addresses.push(address.clone());
                                lan_addresses.push(format!("{}/p2p/{}", address.clone(), swarm.local_peer_id().to_base58()).parse().unwrap());
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
        let short_node_did = node_did.chars().skip(node_did.len() - 7).collect::<String>();
        if is_global {
            println!("{} P2P_node({}/{}) start up, peer_id({})", dids::utils::now_string(), short_node_did, short_peer_id, swarm.local_peer_id().to_base58());
        } 

        swarm.behaviour_mut().kademlia
            .set_mode(Some(kad::Mode::Server));

        let mut upstream_nodes = UpstreamNodes::new(&config);
        
        let mut upstream_node = upstream_nodes.get_first();
        let mut upstream_addr = Multiaddr::from_str(format!("{}/p2p/{}", upstream_node.address(), upstream_node.peer_id()).as_str())?;
        let timeout_duration = Duration::from_secs(6); 
        let start_time = Instant::now();
        while swarm.dial(upstream_addr.clone()).is_err() {
            if start_time.elapsed() > timeout_duration {
                println!("{} Timeout reached while trying to connect to upstream nodes. Entering no-upstream mode.", dids::utils::now_string());
                break;
            }
            upstream_node = upstream_nodes.get_select();
            upstream_addr = Multiaddr::from_str(format!("{}/p2p/{}", upstream_node.address(), upstream_node.peer_id()).as_str())?;
        }
        if !is_global {
            let listener_id = swarm.listen_on(upstream_addr.clone().with(Protocol::P2pCircuit))?;
            if (debug & (1 << 0)) != 0 {
                println!("{} P2P_node({}/{}) listening on upstream node({}) at listenerid({})", 
                    dids::utils::now_string(), short_node_did, short_peer_id, upstream_node.peer_id().short_id(), listener_id);
            }
        }
        for node in upstream_nodes.iter() {
            /*let node_addr = Multiaddr::from_str(format!("{}/p2p/{}", node.address(), node.peer_id()).as_str())?;
            swarm.dial(node_addr.clone()).unwrap();
            if !is_global {
                let listener_id = swarm.listen_on(node_addr.clone().with(Protocol::P2pCircuit))?;
                tracing::info!("P2P_node({}) listening on upstream node({})", short_peer_id, node_addr);
            }*/
            swarm.behaviour_mut().add_address(&node.peer_id(), node.address());
        }
        swarm.behaviour_mut().discover_peers();

        let metrics = Metrics::new(&mut metric_registry);
        /*let build_info = Info::new(vec![("version".to_string(), env!("CARGO_PKG_VERSION"))]);
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
        });*/

        // Create a ticker to periodically discover new peers.
        let interval_secs = config.get_discovery_interval();
        let instant = time::Instant::now() + Duration::from_secs(15);
        let discovery_ticker = time::interval_at(instant, Duration::from_secs(interval_secs));
        
        Ok(Self {
            network_service: swarm,
            local_peer_id: local_keypair.public().into(),
            listened_addresses,
            cmd_receiver,
            event_handler: OnceCell::new(),
            discovery_ticker,
            pending_outbound_requests: HashMap::new(),
            pending_kad_query: HashMap::new(),
            pending_providing: Default::default(),
            pending_providers: Default::default(),
            pending_downloading: Default::default(),
            pending_get_file: Default::default(),
            temp_files: Default::default(),
            completed_downloads: Default::default(),
            provided_files: Default::default(),
            pubsub_topics,
            upstream_nodes,
            lan_addresses,
            metrics,
            is_global,
            upnp_mapped: false,
            rendezvous_cookie: None,
            connection_failure_counts: Mutex::new(HashMap::new()),
            connection_quality: Mutex::new(HashMap::new()),
            stop_flag: false,
            debug,
            shared_data,
        })
    }

    /// Set the handler of events from remote peers.
    pub(crate) fn set_event_handler(&mut self, handler: E) {
        self.event_handler.set(handler).unwrap();
    }

    /// Run the `Server`.
    pub(crate) async fn run(mut self) {
        while !self.stop_flag {
            select! {
                // Next discovery process.
                _ = self.discovery_ticker.tick() => {
                        self.network_service.behaviour_mut().discover_peers();
                        if self.rendezvous_cookie.is_some() {
                            if let Some(rendezvous) = self.network_service.behaviour_mut().rendezvous_client.as_mut() {
                                let rendezvous_point = self.upstream_nodes.get_select().peer_id();
                                rendezvous.discover(
                                    Some(rendezvous::Namespace::new(NAMESPACE.to_string()).unwrap()),
                                    self.rendezvous_cookie.clone(),
                                    None,
                                    rendezvous_point,
                                )
                            }
                        }
                    },
                // Next command from the `Client`.
                msg = self.cmd_receiver.recv() =>  match msg {
                    Some(c) => self.handle_command(c).await,
                    // Command channel closed, thus shutting down the network event loop.
                    None =>  return,
                },
                // Next event from `Swarm`.
                event = self.network_service.select_next_some() => {
                    self.metrics.record(&event);
                    self.handle_swarm_event(event).await;
                },
            }

        }
    }

    // Process the next command coming from `Client`.
    async fn handle_command(&mut self, cmd: Command) {
        match cmd {
            Command::SendRequest {
                target,
                request,
                responder,
            } => self.handle_outbound_request(target, request, responder),
            Command::SendOneWayRequest {
                target,
                request,
            } => self.handle_outbound_one_way_request(target, request),
            Command::Broadcast { topic, message } => self.handle_outbound_broadcast(topic, message),
            Command::GetStatus(responder) => {
                let status = self.get_status();
                if let Err(e) = responder.send(status) {
                    tracing::error!("{} 无法发送节点状态信息: 接收方可能已关闭", dids::utils::now_string());
                }
            },
            Command::GetKeyValue(key, responder) => self.handle_kad_get_key(key, responder).unwrap(),
            Command::SetKeyValue(key, value) => self.handle_kad_set_value(key, value, None, None, None),
            Command::Stop => self.stop_flag = true,

            Command::StartProviding { file_name, file_path} => {
                let file_key = format!("{}@{}|DF", file_name.clone(), self.shared_data.node_name());
                let filename = file_path
                    .file_name()
                    .map(|name| name.to_string_lossy().to_string())
                    .unwrap_or_else(|| file_name.clone());
                let metadata = metadata(file_path.clone()).await.unwrap();
                let value = format!("{}|{}|{}", filename, metadata.len(), metadata.accessed().unwrap().duration_since(UNIX_EPOCH).unwrap().as_secs())
                    .into_bytes();
                let expires = Some(Instant::now() + Duration::from_secs(60));
                let (sender, receiver) = oneshot::channel();
                self.handle_kad_set_value(file_key.clone(), value, Some(self.local_peer_id.clone()), expires, Some(sender));
                let _ = receiver.await;
                
                self.provided_files.insert(file_key.clone(), file_path.clone());
                let query_id = self
                    .network_service
                    .behaviour_mut()
                    .kademlia
                    .start_providing(file_key.clone().into_bytes().into())
                    .expect("No store error.");
                self.pending_providing.insert(query_id, file_key);
            }
            Command::GetProviders { file_name, responder } => {
                let query_id = self
                    .network_service
                    .behaviour_mut()
                    .kademlia
                    .get_providers(file_name.into_bytes().into());
                self.pending_providers.insert(query_id, responder);
            }
            Command::DownloadFile { full_file_name } => {
                let file_key = format!("{}|DF", full_file_name.clone());
                let (sender, receiver) = oneshot::channel();
                self.handle_kad_get_key(file_key.clone(), sender);
                let value = receiver.await.unwrap();
                if value.len() == 0 {
                    tracing::error!("{} 无法下载文件 {}，文件不存在", dids::utils::now_string(), full_file_name);
                } else {
                    let value_str = String::from_utf8_lossy(&value);
                    let parts: Vec<&str> = value_str.split('|').collect();
                    if parts.len() != 3 {
                        tracing::error!("{} 无法下载文件 {}，文件元数据格式错误", dids::utils::now_string(), full_file_name);
                    } else {
                        let filename = parts[0].to_string();
                        let filesize = parts[1].parse::<u64>().unwrap();
                        let last_modified = parts[2].parse::<u64>().unwrap();
                        // Initiate the Kademlia query to find providers
                        // The file handle creation is deferred until providers are found in handle_event
                        let query_id = self
                            .network_service
                            .behaviour_mut()
                            .kademlia
                            .get_providers(file_key.clone().into_bytes().into());
                        // Store the file_name for the query ID, to be used when providers are found
                        self.pending_downloading.insert(query_id, (file_key, filename, filesize));
                    }
                }
            }
        }
    }
    // Process the next event coming from `Swarm`.
    async fn handle_swarm_event(&mut self, event: SwarmEvent<BehaviourEvent>) {
        let behaviour_ev = match event {
            SwarmEvent::Behaviour(ev) => ev,
            SwarmEvent::NewListenAddr { address, .. } => {
                if (self.debug & (1 << 0)) != 0 {
                    println!("{} 📣 P2P_node listening on address: {}", dids::utils::now_string(), address);
                }
                return self.update_listened_addresses(); },

            SwarmEvent::ListenerClosed {
                reason, addresses, ..
            } => return Self::log_listener_close(reason, addresses),

            SwarmEvent::ExternalAddrConfirmed { address } 
            => {
                if (self.debug & (1 << 0)) != 0 {
                    println!("{} External address confirmed from relay node: {address}", dids::utils::now_string(),);
                }
                return;
            }

            SwarmEvent::ConnectionEstablished {
                peer_id, endpoint, ..
            } => {
                if (self.debug & (1 << 0)) != 0  {
                    println!("{} Established new connection peer({})={}", dids::utils::now_string(), peer_id.short_id(), endpoint.get_remote_address());
                }
                let peer_id_clone = peer_id.clone();
                if self.upstream_nodes.iter().any(|node| node.peer_id() == peer_id) {
                    if let Some(rendezvous) = self.network_service.behaviour_mut().rendezvous_client.as_mut() {
                        if let Err(error) = rendezvous.register(
                            rendezvous::Namespace::new(NAMESPACE.to_string()).unwrap(),
                            peer_id_clone,
                            None,
                        ) {
                            if (self.debug & (1 << 7)) != 0  {
                                println!("{} Failed to register after ConnectionEstablished({}): {error}", dids::utils::now_string(), peer_id.short_id());
                            }
                            return;
                        }
                        if (self.debug & (1 << 7)) != 0  {
                            println!("{} Connection established after ConnectionEstablished with rendezvous point: {}", dids::utils::now_string(), peer_id.short_id());
                        }
                        rendezvous.discover(
                            Some(rendezvous::Namespace::new(NAMESPACE.to_string()).unwrap()),
                            None,
                            None,
                            peer_id_clone,
                        );
                    }
                }
                return;
            }

            // Can't connect to the `peer`, remove it from the DHT.
            SwarmEvent::OutgoingConnectionError {
                peer_id: Some(remote_peer),
                error,
                connection_id,
                ..
            } => {
                if self.record_peer_failure(&remote_peer, "Connection") {
                    if (self.debug & (1 << 0)) != 0  {
                        if self.debug > 0 {
                            println!("{} Connection failures has reached the threshold, remove the node: {}", dids::utils::now_string(), remote_peer.short_id());
                        } else {
                            println!("{} Connection failures({:?}) has reached the threshold, remove the node: {}", dids::utils::now_string(), error, remote_peer.short_id());
                        }
                        
                    }
                    self.network_service.behaviour_mut().remove_peer(&remote_peer);

                    if !self.is_global && self.network_service.local_peer_id().to_base58() != remote_peer.to_base58(){
                        let relay_node = self.upstream_nodes.get_select();
                        if (self.debug & (1 << 0)) != 0  {
                            println!("{} Try to connect to {} with the upstream node: {}", dids::utils::now_string(), remote_peer.short_id(), relay_node.peer_id().short_id());
                        }
                        let opts = DialOpts::from(
                            relay_node.address()
                                .with(Protocol::P2pCircuit)
                                .with(Protocol::P2p(remote_peer)),
                        );
                        let id = opts.connection_id();
                        self.network_service.dial(opts);
                    }
                    
                }
                return;
            }
            SwarmEvent::IncomingConnection { .. } => { return; }
            SwarmEvent::ConnectionClosed { .. } => { return; }
            SwarmEvent::IncomingConnectionError { .. } => { return; }
            SwarmEvent::Dialing {
                peer_id: Some(peer_id),
                ..
            } => { println!("{} Dialing {peer_id}", dids::utils::now_string()); 
                return;
            },

            _ => return,
        };
        self.handle_behaviour_event(behaviour_ev);
    }

    async fn handle_behaviour_event(&mut self, ev: BehaviourEvent) {
        tracing::debug!("{:?}", ev);
        //self.record_event_metrics(&ev);
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
                    if (self.debug & (1 << 8)) != 0  {
                        println!("{} Ping failures has reached the threshold, remove the node: {:?}", dids::utils::now_string(), peer.short_id());
                    }
                    self.network_service.behaviour_mut().remove_peer(&peer)
                }
            },

            BehaviourEvent::Mdns(mdns::Event::Discovered(list)) => {
                for (peer_id, multiaddr) in list {
                    if (self.debug & (1 << 9)) != 0  {
                        println!("{} mDNS discovered a new peer: {} at {multiaddr}", dids::utils::now_string(), peer_id.short_id());
                    }
                    self.add_addresses(&peer_id, vec![multiaddr]);
                    self.network_service.behaviour_mut().pubsub.add_explicit_peer(&peer_id);
                }
            }
            BehaviourEvent::Mdns(mdns::Event::Expired(list)) => {
                for (peer_id, _multiaddr) in list {
                    if (self.debug & (1 << 9)) != 0  {
                        tracing::info!("{} mDNS discover peer has expired: {}", dids::utils::now_string(), peer_id.short_id());
                    }
                    self.network_service.behaviour_mut().pubsub.remove_explicit_peer(&peer_id);
                }
            }
            BehaviourEvent::Pubsub(gossipsub::Event::Message {
                propagation_source: peer_id,
                message_id: id,
                message,
            }) => {
                if (self.debug & (1 << 0)) != 0  {
                    println!("{} <<==== Got broadcast message with id({id}) from peer({}): '{}'",
                    dids::utils::now_string(), peer_id.short_id(), String::from_utf8_lossy(&message.data));
                }
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
                    self.add_addresses(&peer_id, listen_addrs);
                    if (self.debug & (1 << 1)) != 0  {
                        println!("{} P2P_node({}) add peer({}, {:?})", dids::utils::now_string(), self.get_short_id(), peer_id.short_id(), agent_version);
                    }
                    
                    let mut parts = agent_version.splitn(3, '/');
                    let agent_name = parts.next().unwrap_or("").trim().to_string();
                    let agent_did = parts.next().unwrap_or("").trim().to_string();
                    let agent_ver = parts.next().unwrap_or("").trim().to_string();
                    if !agent_did.is_empty() && IdClaim::validity(&agent_did) {
                        self.shared_data.insert_node_did(&peer_id.to_base58(), &agent_did);
                        let short_did = agent_did.chars().skip(agent_did.len() - 7).collect::<String>();
                        if (self.debug & (1 << 1)) != 0  {
                            println!("{} P2P_node({}) record id-did mapping({}, {})", dids::utils::now_string(), self.get_short_id(), peer_id.short_id(), short_did);
                        }
                    }                                    
                };
                self.network_service.add_external_address(observed_addr.clone());
                if (self.debug & (1 << 1)) != 0  {
                    println!("{} P2P_node({}) add external_address({:?})", dids::utils::now_string(), self.get_short_id(), observed_addr.clone());
                }
                
                if peer_id == self.local_peer_id && (self.debug & (1 << 1)) != 0  {
                    println!("{} ❗ P2P_node({}) add local_address({:?})", dids::utils::now_string(), self.get_short_id(), observed_addr.clone());
                }
                if let Some(rendezvous) = self.network_service.behaviour_mut().rendezvous_client.as_mut() {
                    if let Err(error) = rendezvous.register(
                        rendezvous::Namespace::new(NAMESPACE.to_string()).unwrap(),
                        self.upstream_nodes.get_last().peer_id(),
                        None,
                    ) {
                        if (self.debug & (1 << 1)) != 0  {
                            println!("{} Failed to register after Identify({}): {error}", dids::utils::now_string(), peer_id.short_id());
                        }
                        return;
                    }
                    if (self.debug & (1 << 1)) != 0  {
                        println!("{} Connection established after Identify with rendezvous point: {}", dids::utils::now_string(), peer_id.short_id());
                    }
                }

                if self.upstream_nodes.contains(&peer_id) && !self.is_global {
                    let short_peer_id = self.network_service.local_peer_id().short_id();
                    let node = self.upstream_nodes.get_with_peer_id(&peer_id).unwrap();
                    match Multiaddr::from_str(format!("{}/p2p/{}", node.address(), node.peer_id()).as_str()) {
                        Ok(node_addr) => {
                            match self.network_service.listen_on(node_addr.clone().with(Protocol::P2pCircuit)) {
                                Ok(listener_id) => {
                                    if (self.debug & (1 << 1)) != 0  {
                                        println!("{} P2P_node({}) listening on upstream node({})", dids::utils::now_string(), short_peer_id, node_addr);
                                    }
                                },
                                Err(e) => {
                                    if (self.debug & (1 << 1)) != 0  {
                                        println!("{} Failed to listen on upstream node({}): {}", dids::utils::now_string(), node_addr, e);
                                    }
                                }
                            }
                        },
                        Err(e) => {
                            if (self.debug & (1 << 1)) != 0  {
                                println!("{} Failed to parse multiaddr for node {}: {}", dids::utils::now_string(), node.peer_id().short_id(), e);
                            }
                        }
                    }
                }
                
            }

            BehaviourEvent::ReqResp(request_response::Event::Message {
                peer,
                message:
                request_response::Message::Request { request, channel, .. },
                ..
            }) => self.handle_inbound_request(peer, request, channel),

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
                if (self.debug & (1 << 3)) != 0  {
                    println!("{} Tested {tested_addr} with {}. Sent {bytes_sent} bytes for verification. Everything Ok and verified.", dids::utils::now_string(), server.short_id());
                }
            }
            BehaviourEvent::AutonatClient(autonat::v2::client::Event {
                server,
                tested_addr,
                bytes_sent,
                result: Err(e),
            }) => {
                if (self.debug & (1 << 3)) != 0  {
                    println!("{} Tested {tested_addr} with {}. Sent {bytes_sent} bytes for verification. Failed with {e:?}.", dids::utils::now_string(), server.short_id());
                }
            }

            BehaviourEvent::Upnp(upnp::Event::NewExternalAddr(addr)) => {
                if (self.debug & (1 <<10)) != 0  {
                    println!("{} UPnP address: {}", dids::utils::now_string(), addr);
                }
                self.network_service.add_external_address(addr);
                self.upnp_mapped = true;
            }
            BehaviourEvent::Upnp(upnp::Event::GatewayNotFound) => {
                if (self.debug & (1 <<10)) != 0  {
                    println!("{} UPnP gateway not found", dids::utils::now_string());
                }
            }
            BehaviourEvent::Upnp(upnp::Event::NonRoutableGateway) => {
                if (self.debug & (1 <<10)) != 0  {
                    println!("{} UPnP gateway unreachable",dids::utils::now_string());
                }
            }

            BehaviourEvent::RelayClient(
                relay::client::Event::ReservationReqAccepted { 
                    relay_peer_id,
                    limit,
                    .. },
            ) => {
                if (self.debug & (1 << 4)) != 0  {
                    println!("{} Relay({}) accepted our reservation request, limit={:?}.", dids::utils::now_string(), relay_peer_id.short_id(), limit);
                }
            }

            BehaviourEvent::RelayClient(
                relay::client::Event::OutboundCircuitEstablished { 
                    relay_peer_id,
                    limit,
                    .. },
            ) => {
                if (self.debug & (1 << 4)) != 0  {
                    println!("{} Relay({}) accepted our CircuitEstablished limit={:?}.", dids::utils::now_string(), relay_peer_id.short_id(), limit);
                }
            }

            BehaviourEvent::Dcutr(dcutr::Event {
                remote_peer_id,
                result: Ok(connection_id),
            }) => {
                if (self.debug & (1 << 5)) != 0  {
                    println!("{} DCUTR({}) accepted our reservation request.", dids::utils::now_string(), remote_peer_id.short_id());
                }
            }

            BehaviourEvent::Rendezvous(
                rendezvous::server::Event::PeerRegistered { peer, registration },
            ) => {
                if (self.debug & (1 <<6)) != 0  {
                    println!(
                        "{} Peer {} registered for namespace '{}'",
                        dids::utils::now_string(), peer,
                        registration.namespace
                    );
                }
            }
            BehaviourEvent::Rendezvous(
                rendezvous::server::Event::DiscoverServed {
                    enquirer,
                    registrations,
                },
            ) => {
                if (self.debug & (1 <<6)) != 0  {
                    println!(
                        "{} Served peer {} with {} registrations",
                        dids::utils::now_string(), enquirer,
                        registrations.len()
                    );
                }
            }

            BehaviourEvent::RendezvousClient(
                rendezvous::client::Event::Registered {
                    namespace,
                    ttl,
                    rendezvous_node,
                },
            ) => {
                if (self.debug & (1 << 7)) != 0  {
                    println!(
                        "{} Registered for namespace '{}' at rendezvous point {} for the next {} seconds",
                        dids::utils::now_string(), namespace,
                        rendezvous_node.short_id(),
                        ttl
                    );
                }
            }
            BehaviourEvent::RendezvousClient(
                rendezvous::client::Event::RegisterFailed {
                    rendezvous_node,
                    namespace,
                    error,
                },
            ) => {
                if (self.debug & (1 << 7)) != 0  {
                    println!(
                        "{} Failed to register: rendezvous_node={}, namespace={}, error_code={:?}",
                        dids::utils::now_string(), rendezvous_node.short_id(),
                        namespace,
                        error
                    );
                }
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
                        if (self.debug & (1 << 7)) != 0  {
                            println!("{} Discovered peer with rendezvous: {}, address={}", dids::utils::now_string(), peer.short_id(), address);
                        }

                        let p2p_suffix = Protocol::P2p(peer);
                        let address_with_p2p =
                            if !address.ends_with(&Multiaddr::empty().with(p2p_suffix.clone())) {
                                address.clone().with(p2p_suffix)
                            } else {
                                address.clone()
                            };
                        
                        match self.network_service.dial(address_with_p2p.clone()) {
                            Ok(_) => {
                                if (self.debug & (1 << 7)) != 0  {
                                    println!("{} Successfully dialed peer {} at {}", dids::utils::now_string(), peer.short_id(), address_with_p2p);
                                }
                            },
                            Err(e) => {
                                if (self.debug & (1 << 7)) != 0  {
                                    println!("{} Failed to dial peer {} at {}: {}", dids::utils::now_string(), peer.short_id(), address_with_p2p, e);
                                }
                            }
                        }
                    }
                }
            }

            BehaviourEvent::Kademlia(
                kad::Event::OutboundQueryProgressed {
                    id, result, .. 
            }) => {
                match result {
                    kad::QueryResult::GetClosestPeers(Ok(GetClosestPeersOk { key, peers , ..})) => {
                        if (self.debug & (1 << 2)) != 0  {
                            println!("{} ☕ Got {} closest peers for key {:?}.", dids::utils::now_string(), peers.len(), key);
                        }
                        let target_peer_id = match PeerId::from_bytes(key.as_ref()) {
                            Ok(peer_id) => peer_id,
                            Err(e) => {
                                println!("❌ Failed to convert key to PeerId: {}", e);
                                return;
                            }
                        };
                        for peer in peers {
                            if peer.peer_id == target_peer_id {
                                // 遍历peer的地址，尝试连接，连接成功后加入kad地址表
                                for addr in peer.addrs {
                                    let full_addr = addr.with(Protocol::P2p(peer.peer_id));
                                    match self.network_service.dial(full_addr.clone()) {
                                        Ok(()) => {
                                            println!("🔄 Dialing target {} at {}", peer.peer_id, full_addr);
                                            self.network_service.behaviour_mut().kademlia.add_address(&peer.peer_id, full_addr);
                                            break; // 成功连接一个地址即可
                                        }
                                        Err(e) => {
                                            println!("❌ Failed to dial {} at {}: {}", peer.peer_id, full_addr, e);
                                            continue;
                                        }
                                    }
                                }
                            }
                        }
                    }
                    kad::QueryResult::GetClosestPeers(Err(error)) => {
                        if (self.debug & (1 << 2)) != 0  {
                            println!("{} ❌ Kad get closest peers failed: {:?}", dids::utils::now_string(), error);
                        }
                    }
                    kad::QueryResult::GetRecord(Ok(
                        kad::GetRecordOk::FoundRecord(kad::PeerRecord {
                            record: kad::Record { key, value, .. },
                            ..
                        })
                    )) => {
                        match std::str::from_utf8(key.as_ref()) {
                            Ok(key_str) => {
                                if (self.debug & (1 << 2)) != 0  {
                                    println!("{} ☕ Got record: {} -> {:?}", dids::utils::now_string(), key_str, value);
                                }
                                self.handle_kad_result(id, value.clone());
                            },
                            Err(_) => {
                                if (self.debug & (1 << 2)) != 0  {
                                    println!("{} ☕ 获取到记录但无法解析为UTF-8字符串",dids::utils::now_string());
                                }
                                self.handle_kad_result(id, value.clone());
                            }
                        }
                    }
                    kad::QueryResult::GetRecord(Err(err)) => {
                        if (self.debug & (1 << 2)) != 0  {
                            println!("{} ❌ Kad get record failed: {:?}", dids::utils::now_string(), err);
                        }
                        self.handle_kad_failure(id);
                    } 
                    kad::QueryResult::PutRecord(Ok(kad::PutRecordOk { key })) => {
                        if (self.debug & (1 << 2)) != 0  {
                            println!(
                                "{} Successfully put record {:?}", dids::utils::now_string(),
                                std::str::from_utf8(key.as_ref()).unwrap()
                            );
                        }
                        self.handle_kad_result(id, key.to_vec());
                    }
                    kad::QueryResult::PutRecord(Err(err)) => {
                        if (self.debug & (1 << 2)) != 0  {
                            println!("{} ❌ Kad set record failed: {:?}", dids::utils::now_string(), err);
                        }
                        self.handle_kad_failure(id);
                    }

                    kad::QueryResult::StartProviding(_) => {
                        if (self.debug & (1 << 2)) != 0  {
                            if let Some(file_name) = self.pending_providing.remove(&id) {
                                println!("{} Successfully started providing record: {}", dids::utils::now_string(), file_name);
                            }
                            
                        }
                    }
                    kad::QueryResult::GetProviders(Ok(kad::GetProvidersOk::FoundProviders {
                            providers,
                            ..
                    })) => {
                        if (self.debug & (1 << 2)) != 0  {
                            if let Some(sender) = self.pending_providers.remove(&id) {
                                sender.send(providers.clone()).expect("Receiver not to be dropped");
                                // Finish the query. We are only interested in the first result.
                                self.network_service
                                    .behaviour_mut()
                                    .kademlia
                                    .query_mut(&id)
                                    .unwrap()
                                    .finish();
                                println!("{} Successfully got providers: {:?}", dids::utils::now_string(), providers);      
                            // Handle result for GetFile internal use (event return)
                            } else if let Some((file_key, filename, filesize)) = self.pending_downloading.remove(&id) {
                                // Finish the query. We are only interested in the first result.
                                self.network_service
                                    .behaviour_mut()
                                    .kademlia
                                    .query_mut(&id)
                                    .unwrap()
                                    .finish();
                                // Now that we have providers, initiate requests to them (similar to original Get logic)
                                for provider in providers {
                                    // Create a temporary file path for this specific request to this provider
                                    let temp_path = std::path::PathBuf::from(format!("received_{}_from_{}.{}.bin.tmp", filename.clone(), provider.to_base58(), id));
                                    // Create the file handle
                                    match File::create(&temp_path).await {
                                        Ok(file_handle) => {
                                            // Send the request to the provider
                                            let request_id = self
                                                .network_service
                                                .behaviour_mut()
                                                .request_response
                                                .send_request(&provider, FileRequest(file_key.clone()));
                                            // Store the file handle and temp path for the specific request ID
                                            self.pending_get_file.insert(request_id, (file_key.clone(), file_handle, filename.clone(), filesize));
                                            // Also track the temp path for potential cleanup
                                            self.temp_files.insert(request_id, temp_path.clone());
                                            println!("Sent file request for '{}' to provider {}", filename, provider);
                                            
                                        }
                                        Err(e) => {
                                            eprintln!("Failed to create temporary file for request to {}: {}", provider, e);
                                            // Could send an error event or handle this failure, e.g., try next provider
                                        }
                                    }
                                }
                            }
                        }
                    }
                    kad::QueryResult::GetProviders(Ok(
                            kad::GetProvidersOk::FinishedWithNoAdditionalRecord { .. }
                        )) => {
                            // Handle case where no providers were found for GetFile
                            if let Some((file_key, filename, filesize)) = self.pending_downloading.remove(&id) {
                                eprintln!("Could not find any providers for file: {}", filename);
                                // Could send an error event here if needed
                            }
                        }
                    
                    _ => {}
                }
            }
            BehaviourEvent::Kademlia(_) => {}
            BehaviourEvent::RequestResponse(
                request_response::Event::Message { message, .. },
            ) => match message {
                request_response::Message::Request {
                    request, channel, ..
                } => {
                    // Handle incoming file requests
                    let requested_file_key = request.0;
                    if let Some(file_path) = self.provided_files.get(&requested_file_key) {
                        // Read the file content
                        match tokio::fs::read(file_path).await { // Use tokio::fs for async read
                            Ok(file_content) => {
                                // Send the file content as response
                                self.network_service
                                    .behaviour_mut()
                                    .request_response
                                    .send_response(channel, FileResponse(file_content))
                                    .expect("Connection to peer to be still open.");
                                println!("Sent file '{}' to peer", requested_file_key);
                            }
                            Err(e) => {
                                eprintln!("Failed to read file '{}' for serving: {}", file_path.display(), e);
                                // Optionally send an error response
                                // self.swarm
                                //     .behaviour_mut()
                                //     .request_response
                                //     .send_response(channel, FileResponse(vec![])); // Or an error message
                            }
                        }
                    } else {
                        eprintln!("Received request for non-provided file: {}", requested_file_key);
                         // Optionally send an error response
                        // self.swarm
                        //     .behaviour_mut()
                        //     .request_response
                        //     .send_response(channel, FileResponse(vec![])); // Or an error message
                    }
                }
                request_response::Message::Response {
                    request_id,
                    response,
                } => {
                    if let Some((file_key, ref mut file_handle, filename, filesize)) = self.pending_get_file.get_mut(&request_id) {
                        // Check if this file_key has already been successfully downloaded
                        if self.completed_downloads.contains(file_key) {
                            println!("File '{}' already downloaded successfully, ignoring response for request {}.", file_key, request_id);
                            // Clean up resources for this ignored request
                            if let Some((file_key, _, filename, _)) = self.pending_get_file.remove(&request_id) {
                                if let Some(temp_path) = self.temp_files.remove(&request_id) {
                                    let _ = tokio::fs::remove_file(temp_path).await; // Ignore error on cleanup
                                }
                            }
                            return; // Exit early, ignore this response
                        }

                        let chunk = response.0;
                        let chunk_len = chunk.len();

                        // Stream the chunk directly to the file
                        match file_handle.write_all(&chunk).await {
                            Ok(()) => {
                                // Report progress
                                println!("Received {}/{} bytes for file '{}'", chunk_len, filesize, filename);
                                // If this is the last chunk (or the only chunk), finalize
                                // In this simple model, we assume one response = full file.
                                // Remove the entry from the map, which takes ownership of the File handle.
                                if let Some((file_key, mut file_handle, filename, filesize)) = self.pending_get_file.remove(&request_id) {
                                    // Flush the file to ensure data is written to disk
                                    if let Err(e) = file_handle.flush().await {
                                         eprintln!("Failed to flush file for '{}': {}", filename, e);
                                    } else {
                                        println!("Successfully wrote received file for '{}' to disk.", filename);
                                        // Mark this file as completed *before* renaming and sending the final event
                                        self.completed_downloads.insert(file_key.clone());
                                        
                                        // Send final progress event with final path
                                        if let Some(final_path) = self.temp_files.remove(&request_id) {
                                            // Rename temporary file to final name if needed
                                            let final_file_name = format!("received_{}.bin", filename);
                                            let final_path = std::path::PathBuf::from(final_file_name);
                                            if let Err(e) = tokio::fs::rename(&final_path.with_extension("tmp"), &final_path).await {
                                                eprintln!("Failed to rename temporary file to final name: {}", e);
                                                // Still report the temp path as the saved path
                                                println!("Still reporting temp path as saved path for '{}': {}", filename, final_path.with_extension("tmp").display());
                                            } else {
                                                println!("Successfully renamed temporary file to final name for '{}': {}", filename, final_path.display());
                                            }
                                        }
                                    }
                                }
                            }
                            Err(e) => {
                                eprintln!("Failed to write chunk to file for request {}: {}", request_id, e);
                                // Attempt to remove the temp file on write error
                                if let Some(temp_path) = self.temp_files.remove(&request_id) {
                                    let _ = tokio::fs::remove_file(temp_path).await; // Ignore error on cleanup
                                }
                                self.pending_get_file.remove(&request_id); // Clean up the handle
                            }
                        }
                    }
                }
            }
            BehaviourEvent::RequestResponse(
                request_response::Event::OutboundFailure {
                    request_id, error, ..
                },
            ) => {
                if let Some((file_key, _, filename, _)) = self.pending_get_file.remove(&request_id) {
                     eprintln!("Failed to get file '{}' from peer (request_id: {}): {}", filename, request_id, error);
                     // Attempt to remove the temp file on failure
                     if let Some(temp_path) = self.temp_files.remove(&request_id) {
                         let _ = tokio::fs::remove_file(temp_path).await; // Ignore error on cleanup
                     }
                     // Could send an error event here if needed
                }
            }
            BehaviourEvent::RequestResponse(
                request_response::Event::ResponseSent { .. }
            ) => {}
            _ => {}
        }
    }

    // Inbound requests are handled by the `EventHandler` which is provided by the application layer.
    fn handle_inbound_request(&mut self, peer: PeerId, request: Vec<u8>, ch: ResponseChannel<ResponseType>) {
        if let Some(handler) = self.event_handler.get() {
            let response = handler.handle_inbound_request(peer, request).map_err(|_| ());
            match &response {
                Ok(data) => {
                    if let Ok(response_str) = std::str::from_utf8(data) {
                        if response_str == "no_response" {
                            return; // 直接返回，不发送响应
                        }
                    }
                },
                _ => {}
            }
            self.network_service.behaviour_mut().send_response(ch, response);
        }
    }

    // Store the request_id with the responder so that we can send the response later.
    fn handle_outbound_request(
        &mut self,
        target: PeerId,
        request: Bytes,
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

    fn handle_outbound_one_way_request(&mut self, target: PeerId, request: Bytes) {
        let req_id = self.network_service.behaviour_mut().send_request(&target, request);
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
    fn handle_outbound_broadcast(&mut self, topic: String, message: Bytes) {
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
        let is_debug = self.debug>0;
        NodeStatus {
            local_peer_id: self.local_peer_id.to_base58(),
            local_node_did: self.shared_data.node_did(),
            listened_addresses: self.listened_addresses.clone(),
            known_peers_count: known_peers.len(),
            known_peers,
            pubsub_peers,
            external_addresses,
            connection_quality,
            total_inbound_bytes: total_in,
            total_outbound_bytes: total_out,
            is_debug,
        }
    }

    fn handle_kad_get_key(
        &mut self,
        key: String,
        responder: oneshot::Sender<Vec<u8>>,
    ) -> Result<(), Box<dyn Error>> {
        let query_id = self
            .network_service
            .behaviour_mut()
            .get_key_value(key.clone());
        self.pending_kad_query.insert(query_id, responder);
        Ok(())
    }

    fn handle_kad_failure(&mut self, query_id: QueryId) {
        if let Some(responder) = self.pending_kad_query.remove(&query_id) {
            let _ = responder.send(Vec::new());
        } else {
            tracing::warn!("❗ Received failure for unknown request: {}", query_id);
            debug_assert!(false);
        }
    }

    fn handle_kad_result(&mut self, query_id: QueryId, response: Vec<u8> ) {
        if let Some(responder) = self.pending_kad_query.remove(&query_id) {
            let _ = responder.send(response);
        }
    }

    fn handle_kad_set_value(&mut self, key: String, value: Vec<u8>, publisher: Option<PeerId>, expiry: Option<Instant>, responder: Option<oneshot::Sender<Vec<u8>>>) {
        let query_id = self
            .network_service
            .behaviour_mut()
            .set_key_value(key.clone(), value.clone(), publisher, expiry);
        if let Some(responder) = responder {
            self.pending_kad_query.insert(query_id, responder);
        }
        
        tracing::debug!("☕ 存储键值对: {} -> {:?}, query_id: {:?}", key, value.len(), query_id);
    }

    fn get_peer_id(&self) -> PeerId {
        self.local_peer_id.clone()
    }

    fn get_node_did(&self) -> String {
        self.shared_data.node_did()
    }

    fn get_short_id(&self) -> String {
        let node_did = self.shared_data.node_did();
        let short_sys_did = node_did.chars().skip(node_did.len() - 7).collect::<String>();
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
                tracing::info!("Listener ({}) closed gracefully", addrs)
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
    pub(crate) local_node_did: String,
    pub(crate) listened_addresses: Vec<Multiaddr>,
    pub(crate) known_peers_count: usize,
    pub(crate) known_peers: HashMap<PeerId, Vec<Multiaddr>>,
    pub(crate) pubsub_peers: HashMap<PeerId, Vec<TopicHash>>,
    pub(crate) external_addresses: Vec<Multiaddr>,
    pub(crate) connection_quality: HashMap<PeerId, ConnectionQuality>,
    pub(crate) total_inbound_bytes: u64,
    pub(crate) total_outbound_bytes: u64,
    pub(crate) is_debug: bool,
}

impl NodeStatus {
    pub(crate) fn short_format(&self) -> String {
        let shared_data = shared::get_shared_data();
        let short_node_did = (|| {
            self.local_node_did[self.local_node_did.len() - 7..].to_string()
        })();
        let short_peer_id = (|| {
            self.local_peer_id[self.local_peer_id.len() - 7..].to_string()
        })();
        let external_addresses = self.external_addresses
            .iter()
            .map(|addr| addr.to_string())
            .collect::<Vec<_>>()
            .join(",");
        let head= format!("NodeStatus({short_node_did}/{short_peer_id}), peers({})[", self.known_peers_count);
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
        format!("{}{}], pubsubs({})", head, peers,
                self.pubsub_peers.len())
    }
}

#[derive(Debug)]
pub(crate) enum Event {
    ProviderReady {
        file_name: String,
    },
    FileChunkReceived {
        file_name: String,
        path: PathBuf, // Path where the file is saved
        progress: usize, // Current received bytes or chunk index
        total_size: Option<usize>, // Total size if known, None for the final event
    },
    ProvidersFound {
        file_name: String,
        providers: HashSet<PeerId>,
    },
}

