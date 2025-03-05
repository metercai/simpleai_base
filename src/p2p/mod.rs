use clap::Parser;
use std::error::Error;
use std::path::PathBuf;
use std::time::Duration;
use std::thread;
use tracing_subscriber::EnvFilter;
use std::env;
use chrono::{Local, DateTime};
use tokio::time;
use openssl::rand::rand_bytes;

mod protocol;
mod http_service;
mod error;
mod utils;
mod service;
mod config;
mod req_resp;

use crate::p2p::service::{Client, EventHandler};
use crate::claims::IdClaim;
use once_cell::sync::OnceCell;

const BOOTSTRAP_INTERVAL: Duration = Duration::from_secs(5 * 60);

static P2P_TASK_HANDLE: OnceCell<tokio::task::JoinHandle<()>> = OnceCell::new();


pub fn start(config: String, sys_claim: &IdClaim) -> Result<(), Box<dyn Error>> {

    let config = config::Config::from_file(config.as_path())?;

    let (client, mut server) = service::new(config.clone(), sys_claim.clone()).await?;
    server.set_event_handler(Handler);

    P2P_TASK_HANDLE.get_or_init(|| {
        let sys_claim_owned = sys_claim.clone();
        
        token_utils::TOKIO_RUNTIME.spawn(async move {
            let task_run = server.run();
            let task_node_status = get_node_status(client.clone(), config.get_node_status_interval());
            let task_request = request(client.clone(), config.get_request_interval());
            let task_broadcast = broadcast(client.clone(), config.get_broadcast_interval());

            tokio::join!(task_run, task_node_status, task_request, task_broadcast);
        })
    });
    Ok(())
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
        let mut random_bytes = [0u8; 1];
        rand_bytes(&mut random_bytes).unwrap();
        if known_peers.len()>0 {
            let random_index = random_bytes[0] as usize % known_peers.len();
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

