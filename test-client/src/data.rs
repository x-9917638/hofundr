use opaque_ke::{
    CipherSuite, CredentialRequest, CredentialResponse, RegistrationRequest, RegistrationResponse,
    RegistrationUpload, Ristretto255, TripleDh, argon2::Argon2,
};
use uuid::Uuid;
pub struct DefaultCipherSuite;

impl CipherSuite for DefaultCipherSuite {
    type OprfCs = Ristretto255;
    type KeyExchange = TripleDh<Ristretto255, sha2::Sha512>;
    type Ksf = Argon2<'static>;
}

#[derive(serde::Serialize, Clone)]
pub struct RegistrationRequestPayload {
    pub registration_request: RegistrationRequest<DefaultCipherSuite>,
}

impl RegistrationRequestPayload {
    pub fn new(msg: RegistrationRequest<DefaultCipherSuite>) -> Self {
        Self {
            registration_request: msg,
        }
    }
}

#[derive(serde::Serialize, Clone)]
pub struct RegistrationUploadPayload {
    pub uuid: Uuid,
    pub registration_upload: RegistrationUpload<DefaultCipherSuite>,
}

impl RegistrationUploadPayload {
    pub fn new(uuid: Uuid, msg: RegistrationUpload<DefaultCipherSuite>) -> Self {
        Self {
            uuid,
            registration_upload: msg,
        }
    }
}

#[derive(serde::Serialize, Clone)]
pub struct LoginPayload {
    pub uuid: Uuid,
    pub credential_request: CredentialRequest<DefaultCipherSuite>,
}

impl LoginPayload {
    pub fn new(uuid: Uuid, msg: CredentialRequest<DefaultCipherSuite>) -> Self {
        Self {
            uuid,
            credential_request: msg,
        }
    }
}

#[derive(serde::Deserialize)]
pub struct RegistrationRequestResponse {
    pub status: String,
    pub identifier: Option<Uuid>,
    pub registration_response: Option<RegistrationResponse<DefaultCipherSuite>>,
}

#[derive(serde::Deserialize)]
pub struct RegistrationUploadResponse {
    pub status: String,
}

#[derive(serde::Deserialize)]
pub struct LoginResponse {
    pub status: String,
    pub session_id: Option<Uuid>,
    pub credential_response: Option<CredentialResponse<DefaultCipherSuite>>,
}
