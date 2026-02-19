// Hofundr
// Copyright (C) 2026 Valerie <valerie@ouppy.gay>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

use opaque_ke::{
    CipherSuite, Ristretto255, ServerSetup, TripleDh, argon2::Argon2, errors::ProtocolError,
    rand::rngs::OsRng,
};
use tokio::{
    fs,
    io::{self, AsyncWriteExt},
};

pub struct DefaultCipherSuite;

impl CipherSuite for DefaultCipherSuite {
    type OprfCs = Ristretto255;
    type KeyExchange = TripleDh<Ristretto255, sha2::Sha512>;
    type Ksf = Argon2<'static>;
}

#[derive(Debug)]
pub struct ToIoError {
    source: String,
}

impl From<ProtocolError> for ToIoError {
    fn from(err: ProtocolError) -> Self {
        Self {
            source: err.to_string(),
        }
    }
}

impl From<ToIoError> for io::Error {
    fn from(err: ToIoError) -> Self {
        io::Error::new(io::ErrorKind::Other, err.source)
    }
}

/// Load an existing ServerSetup from disk,
/// or create one if none exists.
pub async fn opaque_setup(path: &str) -> Result<ServerSetup<DefaultCipherSuite>, io::Error> {
    if let Ok(res) = fs::try_exists(path).await {
        if res {
            let contents = fs::read(path).await?;
            let server_setup = ServerSetup::<DefaultCipherSuite>::deserialize(&contents)
                .map_err(ToIoError::from)?;
            return Ok(server_setup);
        }
    }
    let mut file = fs::File::create(path).await?;
    let mut rng = OsRng;
    let server_setup = ServerSetup::<DefaultCipherSuite>::new(&mut rng);
    let _ = file.write_all(&server_setup.serialize()).await;
    let _ = file.flush().await;
    Ok(server_setup)
}
