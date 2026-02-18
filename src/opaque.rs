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
