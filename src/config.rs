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

use expanduser::expanduser;
use log::LevelFilter;
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
    pub logfile: PathBuf,
    pub log_level: Level,
    // TODO!
    // ...
}

impl Config {
    /// Attempts to load a config file from a given path.
    pub async fn load(path: &str) -> Result<Self, tokio::io::Error> {
        let toml_str = fs::read_to_string(path).await?;
        let mut config: Config = toml::from_str(&toml_str)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.message()))?;

        // Fix ~ paths
        config.server_setup_path = expanduser(
            config
                .server_setup_path
                .to_str()
                .expect("Non UTF-8 characters in server_setup_path."),
        )?;
        config.database_dir = expanduser(
            config
                .database_dir
                .to_str()
                .expect("Non UTF-8 characters in database_dir."),
        )?;
        config.logfile = expanduser(
            config
                .logfile
                .to_str()
                .expect("Non UTF-8 characters in logfile."),
        )?;

        Ok(config)
    }

    /// Attempts to write a config file to disk.
    pub async fn write(&self, path: &str) -> Result<(), tokio::io::Error> {
        let toml_str = toml::to_string_pretty(self)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
        let mut file = File::create(path).await?;
        file.write_all(toml_str.as_bytes()).await?;
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
            logfile: PathBuf::new(),
            port: 8080,
            log_level: Level::Warn,
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

#[derive(serde::Serialize, serde::Deserialize, Debug)]
#[serde(rename_all = "UPPERCASE")]
#[cfg_attr(test, derive(PartialEq))]
pub enum Level {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
    Off,
}

impl From<&Level> for LevelFilter {
    fn from(value: &Level) -> Self {
        match value {
            Level::Off => Self::Off,
            Level::Trace => Self::Trace,
            Level::Debug => Self::Debug,
            Level::Info => Self::Info,
            Level::Warn => Self::Warn,
            Level::Error => Self::Error,
        }
    }
}
