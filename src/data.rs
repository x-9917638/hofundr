use opaque_ke::{RegistrationRequest, RegistrationResponse, RegistrationUpload};
use uuid::Uuid;

use crate::opaque::DefaultCipherSuite;

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

impl RegistrationRequestResponse {
    pub fn new_err() -> Self {
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

impl RegistrationUploadResponse {
    pub fn err() -> Self {
        Self {
            status: "Err".to_string(),
        }
    }
}
