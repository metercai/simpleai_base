use rathole::{run, Cli};
use tokio::sync::broadcast;
use tracing_subscriber::EnvFilter;


pub struct Rathole {
    args: Cli,
    shutdown_tx: broadcast::Sender<bool>,
}

impl Rathole {

    pub fn new(path: &str) -> Self {
        let args = Cli {
            config_path: Some(path.into()),
            server: false,
            client: true,
            genkey: None
        };
        let (shutdown_tx, _) = broadcast::channel::<bool>(1);
        Self {
            args,
            shutdown_tx,
        }
    }
    pub async fn start_service(&self) {

        let is_atty = atty::is(atty::Stream::Stdout);
        let level = "info";
        tracing_subscriber::fmt()
            .with_env_filter(
                EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::from(level)),
            )
            .with_ansi(is_atty)
            .init();
        let shutdown_rx = self.shutdown_tx.subscribe();
        let _ = run(self.args.clone(), shutdown_rx).await;
    }

    pub fn send_shutdown_signal(&self) {
        if let Err(e) = self.shutdown_tx.send(true) {
            panic!("Failed to send shutdown signal: {:?}", e);
        }
    }
}

