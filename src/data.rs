// Hofundr
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

use std::{path::PathBuf, rc::Rc};

use crate::opaque::DefaultCipherSuite;
use clap::Parser;
use opaque_ke::{
    CredentialRequest, CredentialResponse, RegistrationRequest, RegistrationResponse,
    RegistrationUpload,
};
use uuid::Uuid;

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

#[derive(utoipa::ToSchema, serde::Deserialize, Clone)]
pub struct RegistrationRequestPayload {
    #[schema(value_type = &[u8], format = Binary)]
    pub registration_request: RegistrationRequest<DefaultCipherSuite>,
}

#[derive(utoipa::ToSchema, serde::Serialize)]
pub struct RegistrationRequestResponse {
    pub status: String,
    pub identifier: Option<Uuid>,
    #[schema(value_type = Option<&[u8]>, format = Binary)]
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

#[derive(utoipa::ToSchema, serde::Deserialize, Clone)]
pub struct RegistrationUploadPayload {
    pub identifier: Uuid,
    #[schema(value_type = &[u8], format = Binary)]
    pub registration_upload: RegistrationUpload<DefaultCipherSuite>,
}

#[derive(utoipa::ToSchema, serde::Serialize)]
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

#[derive(utoipa::ToSchema, serde::Deserialize, Clone)]
pub struct LoginPayload {
    pub identifier: Uuid,
    #[schema(value_type = &[u8], format = Binary)]
    pub credential_request: CredentialRequest<DefaultCipherSuite>,
}

#[derive(utoipa::ToSchema, serde::Serialize)]
pub struct LoginResponse {
    pub status: String,
    pub session_id: Option<Uuid>,
    #[schema(value_type = Option<&[u8]>, format = Binary)]
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

#[derive(serde::Deserialize, Clone, utoipa::ToSchema)]
pub struct PushPayload {
    identifier: Uuid,
    session_id: Uuid,
    session_key: Rc<[u8]>,
    file: Rc<[u8]>,
    checksum: Rc<[u8]>,
    last_modified: u64,
    device_id: Rc<str>,
}

pub struct PushResponse {
    status: String,
}

#[derive(serde::Deserialize, Clone, utoipa::ToSchema)]
pub struct PullPayload {
    identifier: Uuid,
    session_id: Uuid,
    session_key: Rc<[u8]>,
    last_modified: u64,
}

pub struct PullResponse {
    status: String,
    file: Vec<u8>,
    checksum: [u8; 32],
}
