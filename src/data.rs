use std::path::PathBuf;

use clap::Parser;
use opaque_ke::{
    CredentialRequest, CredentialResponse, RegistrationRequest, RegistrationResponse,
    RegistrationUpload,
};
use uuid::Uuid;

use crate::opaque::DefaultCipherSuite;

#[derive(Parser)]
#[command(version, about, long_about = None)]
pub struct Cli {
    #[arg(short, long, value_name = "CONFIG_PATH")]
    pub config: Option<PathBuf>,
}

pub trait ResponseError {
    /// Return an instance of Self with optional
    /// fields empty and status = "Err"
    fn err() -> Self;
}

#[derive(serde::Deserialize, Clone)]
pub struct RegistrationRequestPayload {
    pub registration_request: RegistrationRequest<DefaultCipherSuite>,
}

#[derive(serde::Serialize)]
pub struct RegistrationRequestResponse {
    pub status: String,
    pub identifier: Option<Uuid>,
    pub registration_response: Option<RegistrationResponse<DefaultCipherSuite>>,
}

impl ResponseError for RegistrationRequestResponse {
    fn err() -> Self {
        Self {
            status: "Err".to_string(),
            identifier: None,
            registration_response: None,
        }
    }
}

#[derive(serde::Deserialize, Clone)]
pub struct RegistrationUploadPayload {
    pub uuid: Uuid,
    pub registration_upload: RegistrationUpload<DefaultCipherSuite>,
}

#[derive(serde::Serialize)]
pub struct RegistrationUploadResponse {
    pub status: String,
}

impl ResponseError for RegistrationUploadResponse {
    fn err() -> Self {
        Self {
            status: "Err".to_string(),
        }
    }
}

#[derive(serde::Deserialize, Clone)]
pub struct LoginPayload {
    pub uuid: Uuid,
    pub credential_request: CredentialRequest<DefaultCipherSuite>,
}

#[derive(serde::Serialize)]
pub struct LoginResponse {
    pub status: String,
    pub session_id: Option<Uuid>,
    pub credential_response: Option<CredentialResponse<DefaultCipherSuite>>,
}

impl ResponseError for LoginResponse {
    fn err() -> Self {
        Self {
            status: "Err".to_string(),
            session_id: None,
            credential_response: None,
        }
    }
}
