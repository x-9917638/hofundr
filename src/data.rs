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

use std::{
    io::{Read, Write},
    path::PathBuf,
    rc::Rc,
};

use crate::opaque::DefaultCipherSuite;
use clap::Parser;
use opaque_ke::{
    CredentialFinalization, CredentialRequest, CredentialResponse, RegistrationRequest,
    RegistrationResponse, RegistrationUpload,
};
use uuid::Uuid;

#[derive(Parser)]
#[command(version, about, long_about = None)]
pub struct Cli {
    #[arg(short, long, value_name = "CONFIG_PATH")]
    pub config: Option<PathBuf>,
}

// TODO: Implement a way to send more descriptive error messages
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
    pub identifier: Uuid,
    pub session_id: Uuid,
    pub nonce: [u8; 12],
    #[schema(value_type = Option<&[u8]>, format = Binary)]
    pub credential_finalization: CredentialFinalization<DefaultCipherSuite>,
    pub ciphertext: EncryptedPush,
    pub session_key: Rc<[u8]>,
}

// ChaCha20-Poly1305 encrypted with session key
#[derive(serde::Deserialize, Clone, utoipa::ToSchema)]
pub struct EncryptedPush {
    pub file: Rc<[u8]>,
    /// SHA-256 checksum
    pub checksum: [u8; 32],
    pub last_modified: u64,
    pub device_id: Rc<str>,
}

impl From<EncryptedPush> for Vec<u8> {
    fn from(val: EncryptedPush) -> Self {
        let mut out = Vec::new();

        // File
        out.write_all(&val.file.len().to_le_bytes()).unwrap();
        out.write_all(&val.file).unwrap();

        out.write_all(&val.checksum).unwrap();

        out.write_all(&val.last_modified.to_le_bytes()).unwrap();

        // Device id
        out.write_all(&val.device_id.len().to_le_bytes()).unwrap();
        out.write_all(val.device_id.as_bytes()).unwrap();

        out
    }
}

impl From<Vec<u8>> for EncryptedPush {
    fn from(value: Vec<u8>) -> Self {
        let mut r = value.as_slice();

        let file_len = {
            let mut buf = [0u8; 8];
            r.read_exact(&mut buf).unwrap();
            u64::from_le_bytes(buf) as usize
        };

        let file = {
            let mut buf = Vec::with_capacity(file_len);
            r.read_exact(&mut buf).unwrap();
            Rc::from(buf)
        };

        let mut checksum = [0u8; 32];
        r.read_exact(&mut checksum).unwrap();

        let last_modified = {
            let mut buf = [0u8; 8];
            r.read_exact(&mut buf).unwrap();
            u64::from_le_bytes(buf)
        };

        let device_id_len = {
            let mut buf = [0u8; 8];
            r.read_exact(&mut buf).unwrap();
            u64::from_le_bytes(buf) as usize
        };

        let device_id = {
            let mut buf = Vec::with_capacity(device_id_len);
            r.read_exact(&mut buf).unwrap();
            Rc::from(str::from_utf8(&buf).unwrap())
        };
        Self {
            file,
            checksum,
            last_modified,
            device_id,
        }
    }
}

#[derive(utoipa::ToSchema, serde::Serialize)]
pub struct PushResponse {
    pub status: String,
}

impl ResponseError for PushResponse {
    fn err() -> Self {
        Self {
            status: "Err".to_string(),
        }
    }
}

#[derive(serde::Deserialize, Clone, utoipa::ToSchema)]
pub struct PullPayload {
    pub identifier: Uuid,
    pub session_id: Uuid,
    pub nonce: [u8; 12],
    #[schema(value_type = Option<&[u8]>, format = Binary)]
    pub credential_finalization: CredentialFinalization<DefaultCipherSuite>,
    /// Should decrupt to a EncryptedPull,
    pub ciphertext: Vec<u8>,
}

// ChaCha20-Poly1305 encrypted with session key
#[derive(serde::Deserialize, Copy, Clone, utoipa::ToSchema)]
pub struct EncryptedPullBody {
    pub last_modified: u64,
}

impl From<EncryptedPullBody> for [u8; 8] {
    fn from(val: EncryptedPullBody) -> Self {
        val.last_modified.to_le_bytes()
    }
}

impl TryFrom<Vec<u8>> for EncryptedPullBody {
    type Error = String;
    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        if value.len() != 8 {
            return Err("Length of value was not 8".to_string());
        }
        let mut arr = [0u8; 8];
        arr.copy_from_slice(&value);
        Ok(Self {
            last_modified: u64::from_le_bytes(arr),
        })
    }
}

#[derive(utoipa::ToSchema, serde::Serialize)]
pub struct PullResponse {
    pub status: String,
    pub file: Option<Vec<u8>>,
    pub checksum: Option<[u8; 32]>,
}

impl ResponseError for PullResponse {
    fn err() -> Self {
        Self {
            status: "Err".to_string(),
            file: None,
            checksum: None,
        }
    }
}
