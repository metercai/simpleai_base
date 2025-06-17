use std::io;
use std::net::AddrParseError;
use serde::ser::StdError;
use argon2::Error as Argon2Error;
use pyo3::exceptions::PyBaseException;
use pyo3::PyErr;
use serde_json::Error as SerdeJsonError;
use serde_cbor::Error as SerdeCborError;
use tokio_tungstenite::tungstenite::Error as TungsteniteError;

#[derive(thiserror::Error, Debug)]
pub enum TokenError {
    #[error("Invalid secret key: {0}")]
    InvalidSecretKey(String),
    #[error("Error in Reqwest")]
    ReqwestError(#[from] reqwest::Error),
    #[error("Error in argon2")]
    Argon2Error(Argon2Error),
    #[error("Error in StdError")]
    BoxStdError(#[from] Box<dyn StdError>),
    #[error("io Error ")]
    IoError(#[from] io::Error),
    #[error("Error in serde_json")]
    JsonParseError(#[from] SerdeJsonError),
    #[error("Error in serde_cbor")]
    CborParseError(#[from] SerdeCborError),
    #[error("Error in Tungstenite")]
    TungsteniteError(#[from] TungsteniteError),
    #[error("Error in url parser")]
    UrlParseError(#[from] url::ParseError),
    #[error("路径前缀错误: {0}")]
    StripPrefix(#[from] std::path::StripPrefixError),
    #[error("Unknown error")]
    Unknown,
}

impl From<()> for TokenError {
    fn from(_: ()) -> Self {
        TokenError::Unknown
    }
}

impl From<AddrParseError> for TokenError {
    fn from(_: AddrParseError) -> Self {
        TokenError::Unknown
    }
}

impl From<Argon2Error> for TokenError {
    fn from(err: Argon2Error) -> Self {
        TokenError::Argon2Error(err)
    }
}

impl From<TokenError> for PyErr {
    fn from(err: TokenError) -> Self {
        PyBaseException::new_err(format!("TokenError: {:?}", err))
    }
}


unsafe impl Send for TokenError {}