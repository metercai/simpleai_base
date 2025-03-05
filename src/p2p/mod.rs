use std::error::Error;
use std::path::PathBuf;
use std::time::Duration;
use std::thread;
use tracing_subscriber::EnvFilter;
use std::env;
use chrono::{Local, DateTime};
use tokio::time;
use rand::Rng;

mod protocol;
mod http_service;
mod error;
mod utils;
mod service;
mod config;
mod req_resp;

use crate::p2p::service::{Client, EventHandler};
use crate::p2p::error::P2pError;
use crate::claims::IdClaim;
use once_cell::sync::OnceCell;
use crate::token_utils;
use crate::systeminfo::SystemInfo;

const BOOTSTRAP_INTERVAL: Duration = Duration::from_secs(5 * 60);


pub async fn start(config: String, sys_claim: &IdClaim, sysinfo: &SystemInfo) {

    let config = config::Config::from_file(PathBuf::from(config).as_path());

    let result = service::new(config.clone(), sys_claim, sysinfo).await;
    let (client, mut server) = match result {
        Ok((c, s)) => (c, s),
        Err(e) => return
    };
    server.set_event_handler(Handler);

    token_utils::TOKIO_RUNTIME.spawn(async move {
        let task_run = server.run();
        let task_node_status = get_node_status(client.clone(), config.get_node_status_interval());
        let task_request = request(client.clone(), config.get_request_interval());
        let task_broadcast = broadcast(client.clone(), config.get_broadcast_interval());

        tokio::join!(task_run, task_node_status, task_request, task_broadcast);
    });
}


#[derive(Debug)]
struct Handler;

impl EventHandler for Handler {
    fn handle_inbound_request(&self, request: Vec<u8>) -> Result<Vec<u8>, Box<dyn Error>> {
        tracing::info!(
            "📣 <<<< Inbound REQUEST: {:?}",
            String::from_utf8_lossy(request.as_slice())
        );
        Ok(request)
    }

    fn handle_broadcast(&self, topic: &str, message: Vec<u8>) {
        tracing::info!(
            "📣 <<<< Inbound BROADCAST: {:?} {:?}",
            topic,
            String::from_utf8_lossy(message.as_slice())
        );
    }
}

async fn get_node_status(client: Client, interval: u64) {
    let dur = time::Duration::from_secs(interval);
    loop {
        time::sleep(dur).await;
        let node_status = client.get_node_status().await;
        let short_id = client.get_peer_id();
        tracing::info!("📣 {}", node_status.short_format());
    }
}

async fn broadcast(client: Client, interval: u64) {
    let dur = time::Duration::from_secs(interval);
    loop {
        time::sleep(dur).await;
        let topic = "system".to_string();
        let short_id = client.get_peer_id();
        let now_time = Local::now();
        let message = format!("From {} at {}!", short_id, now_time);
        tracing::info!("📣 >>>> Outbound broadcast: {:?} {:?}", topic, message);
        let _ = client.broadcast(topic, message.as_bytes().to_vec()).await;
    }
}

async fn request(client: Client, interval: u64) {
    let dur = time::Duration::from_secs(interval);
    loop {
        time::sleep(dur).await;
        let known_peers = client.get_known_peers().await;
        let short_id = client.get_peer_id();
        let random_index = rand::thread_rng().gen_range(0..known_peers.len());
        if known_peers.len()>0 {
            let target = &known_peers[random_index];
            let now_time: DateTime<Local> = Local::now();
            //let now_time = now.format("%H:%M:%S.%4f").to_string();
            let target_id = target.chars().skip(target.len() - 7).collect::<String>();
            let request = format!("Hello {}, request from {} at {}!", target_id, short_id, now_time);
            tracing::info!("📣 >>>> Outbound request: {:?}", request);
            let response = client
                .request(target, request.as_bytes().to_vec()).await
                .unwrap();
            let now_time2: DateTime<Local> = Local::now();
            tracing::info!(
            "📣 <<<< Inbound response: Time({}) {:?}", now_time2,
            String::from_utf8_lossy(&response)
            );
        }

    }
}

