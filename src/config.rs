use std::path::PathBuf;

use tokio::{
    fs::{self, File},
    io::{self, AsyncWriteExt},
};

#[derive(serde::Deserialize, serde::Serialize, Debug)]
#[cfg_attr(test, derive(PartialEq))]
pub struct Config {
    pub server_setup_path: PathBuf,
    pub database_dir: PathBuf,
    pub port: u16,
    pub secret_key: String,
    // TODO!
    // ...
}

impl Config {
    /// Attempts to load a config file from a given path.
    pub async fn load(path: &str) -> Result<Self, tokio::io::Error> {
        let toml_str = fs::read_to_string(path).await?;
        toml::from_str(&toml_str)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.message()))
    }
    /// Attempts to write a config file to disk.
    pub async fn write(&self, path: &str) -> Result<(), tokio::io::Error> {
        let toml_str = toml::to_string_pretty(self)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
        let mut file = File::create(path).await?;
        file.write(toml_str.as_bytes()).await?;
        Ok(())
    }

    pub fn new() -> Self {
        Self::default()
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server_setup_path: PathBuf::new(),
            database_dir: PathBuf::new(),
            port: 8080,
            secret_key: String::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_write() -> Result<(), io::Error> {
        let config = Config::default();
        config.write("/tmp/test.toml").await
    }

    #[tokio::test]
    async fn test_load() {
        let config = Config::default();
        config.write("/tmp/test.toml").await.expect("");
        let loaded = Config::load("/tmp/test.toml").await.expect("");
        assert!(config == loaded);
    }
}
