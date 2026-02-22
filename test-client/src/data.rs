// Copyright (C) 2026 Valerie <valerie@ouppy.gay>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, under version 3 of the License only.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

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
    pub identifier: Uuid,
    pub registration_upload: RegistrationUpload<DefaultCipherSuite>,
}

impl RegistrationUploadPayload {
    pub fn new(uuid: Uuid, msg: RegistrationUpload<DefaultCipherSuite>) -> Self {
        Self {
            identifier: uuid,
            registration_upload: msg,
        }
    }
}

#[derive(serde::Serialize, Clone)]
pub struct LoginPayload {
    pub identifier: Uuid,
    pub credential_request: CredentialRequest<DefaultCipherSuite>,
}

impl LoginPayload {
    pub fn new(uuid: Uuid, msg: CredentialRequest<DefaultCipherSuite>) -> Self {
        Self {
            identifier: uuid,
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
