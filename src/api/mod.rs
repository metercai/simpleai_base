use serde::{Deserialize, Serialize};
use serde::de::DeserializeOwned;
use tracing::{debug, info, error};

use crate::dids::{REQWEST_CLIENT, REQWEST_CLIENT_SYNC};

pub(crate) mod service;

#[derive(Debug, Serialize, Deserialize)]
pub struct ApiResponse<T> {
    success: bool,
    pub data: T,
    error: Option<String>,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub(crate) struct P2pStatus {
    pub node_id: String,
    pub is_debug: bool,
}

pub fn service_online() -> bool {
    let api_host = service::get_api_host();
    match REQWEST_CLIENT_SYNC.get(format!("{}/check_sys", api_host)).send() {
        Ok(resp) => {
            if resp.status().is_success() {
                return true;
            } 
        }
        Err(_) => { }
    }
    false
}

pub async fn request_api<T: DeserializeOwned>(endpoint: &str, params: Option<impl Serialize>) -> Result<T, reqwest::Error> {
    let url = format!("{}/{}", service::get_api_host(), endpoint);

    let response = if let Some(json_params) = params {
        REQWEST_CLIENT.post(&url).json(&json_params).send().await?
    } else {
        REQWEST_CLIENT.get(&url).send().await?
    };
    
    let api_response: ApiResponse<T> = response.json().await?;
    Ok(api_response.data)
}

pub fn request_api_sync<T: DeserializeOwned>(endpoint: &str, params: Option<impl Serialize>) -> Result<T, Box<dyn std::error::Error>> {
    let url = format!("{}/{}", service::get_api_host(), endpoint);

    let response = if let Some(json_params) = params {
        REQWEST_CLIENT_SYNC.post(&url).json(&json_params).send()?
    } else {
        REQWEST_CLIENT_SYNC.get(&url).send()?
    };
    
    let api_response: ApiResponse<T> = response.json()?;
    Ok(api_response.data)
}


pub async fn request_api_cbor<T: Serialize>(endpoint: &str, params: Option<T>) -> Result<String, Box<dyn std::error::Error>> {
    let url = format!("{}/{}", service::get_api_host(), endpoint);
    
    if let Some(cbor_params) = params {
        let cbor_data = serde_cbor::to_vec(&cbor_params)
            .map_err(|e| {
                error!("Failed to serialize CBOR params: {}", e);
                e
            })?;
        let res = REQWEST_CLIENT
            .post(&url)
            .header("Content-Type", "application/cbor")
            .body(cbor_data)
            .send()
            .await?;
        let data: ApiResponse<String> = res.json().await?;
        Ok(data.data)
    } else {
        let res = REQWEST_CLIENT.get(&url).send().await?;
        let data: ApiResponse<String> = res.json().await?;
        Ok(data.data)
    }
}


pub fn request_api_cbor_sync<T: Serialize>(endpoint: &str, params: Option<T>) -> Result<String, Box<dyn std::error::Error>> {
    let url = format!("{}/{}", service::get_api_host(), endpoint);

    if let Some(cbor_params) = params {
        let cbor_data = serde_cbor::to_vec(&cbor_params)?;
        let res = REQWEST_CLIENT_SYNC
            .post(&url)
            .header("Content-Type", "application/cbor")
            .body(cbor_data)
            .send()?;
        let data: ApiResponse<String> = res.json()?;
        Ok(data.data)
    } else {
        let res = REQWEST_CLIENT_SYNC.get(&url).send()?;
        let data: ApiResponse<String> = res.json()?;
        Ok(data.data)
    }
}
