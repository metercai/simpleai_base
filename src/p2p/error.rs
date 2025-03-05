use std::error::Error;
use std::io;
use std::fmt;
use libp2p::{gossipsub, multiaddr, swarm, TransportError};
use tokio::sync::oneshot;
use std::net::AddrParseError;

#[derive(thiserror::Error, Debug)]
pub enum P2pError {
    #[error("Invalid secret key: {0}")]
    InvalidSecretKey(String),
    #[error("Invalid address")]
    InvalidAddress(#[from] multiaddr::Error),
    #[error("Invalid peer ID")]
    InvalidPeerId,
    #[error(transparent)]
    DialError(#[from] swarm::DialError),
    #[error(transparent)]
    ListenError(#[from] TransportError<io::Error>),
    #[error("The remote peer rejected the request")]
    RequestRejected,
    #[error(transparent)]
    ChanError(#[from] oneshot::error::RecvError),
    #[error("Failed to build pub/sub behaviour: {0}")]
    PubsubBuildError(String),
    #[error(transparent)]
    SubscribeError(#[from] gossipsub::SubscriptionError),
    #[error(transparent)]
    PublishError(#[from] gossipsub::PublishError),
    #[error("Error in Reqwest")]
    ReqwestError(#[from] reqwest::Error),
    #[error("io Error ")]
    IoError(#[from] io::Error),
    #[error("Config error: {0}")]
    ConfigError(#[from] Box<dyn Error + Send + Sync>),
    #[error("Unknown error")]
    Unknown,
}

impl From<()> for P2pError {
    fn from(_: ()) -> Self {
        P2pError::Unknown
    }
}

impl From<AddrParseError> for P2pError {
    fn from(_: AddrParseError) -> Self {
        P2pError::Unknown
    }
}
