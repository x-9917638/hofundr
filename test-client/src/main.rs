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

mod cli;
mod data;

use crate::data::{
    DefaultCipherSuite, LoginPayload, LoginResponse, RegistrationRequestPayload,
    RegistrationRequestResponse, RegistrationUploadPayload, RegistrationUploadResponse,
};
use clap::Parser;
use cli::{Cli, Commands};
use opaque_ke::{
    ClientLogin, ClientRegistration, ClientRegistrationFinishParameters, rand::rngs::OsRng,
};
use std::{env, path::Path};
use tokio::{
    fs::{self, File},
    io::{AsyncReadExt, AsyncWriteExt},
};

static APP_USER_AGENT: &str = concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION"),);

#[tokio::main]
async fn main() -> Result<(), String> {
    let cli = Cli::parse();
    let client = reqwest::ClientBuilder::new()
        .user_agent(APP_USER_AGENT)
        .build()
        .unwrap();

    #[cfg(feature = "logging")]
    structured_logger::Builder::with_level(&cli.log_level.to_string())
        .with_target_writer(
            "*",
            structured_logger::async_json::new_writer(tokio::io::stdout()),
        )
        .try_init()
        .map_err(|e| e.to_string())?;

    match cli.command {
        Commands::Login {
            password,
            input,
            output,
        } => login(&client, &cli.url, &password, &input, &output).await,
        Commands::Register { password, output } => {
            register(&client, &cli.url, &password, &output).await
        }
    }
}

async fn login(
    client: &reqwest::Client,
    url: &str,
    password: &str,
    input: &Path,
    output: &Path,
) -> Result<(), String> {
    let mut registration_file = fs::File::open(input).await.map_err(|e| e.to_string())?;

    let mut identifier_buf = [0u8; 16];
    registration_file
        .read_exact(&mut identifier_buf)
        .await
        .map_err(|e| e.to_string())?;
    let identifier = uuid::Uuid::from_bytes(identifier_buf);

    let mut client_rng = OsRng;
    let client_login_start_result =
        ClientLogin::<DefaultCipherSuite>::start(&mut client_rng, password.as_bytes())
            .map_err(|e| e.to_string())?;

    let res = client
        .post(url.to_owned() + "/login")
        .header("Content-Type", "application/json")
        .json(&LoginPayload::new(
            identifier,
            client_login_start_result.message,
        ))
        .send()
        .await
        .map_err(|e| e.to_string())?;
    let res: LoginResponse = res.json().await.map_err(|e| e.to_string())?;

    if &res.status == "Error" {
        return Err("Failed to initiate CredentialRequest".to_string());
    }

    let mut file = fs::File::create(output).await.map_err(|e| e.to_string())?;
    file.write_all(res.session_id.unwrap().as_bytes())
        .await
        .map_err(|e| e.to_string())?;
    file.write_all(&res.credential_response.unwrap().serialize())
        .await
        .map_err(|e| e.to_string())?;

    println!("Got login response back from server");
    Ok(())
}

async fn register(
    client: &reqwest::Client,
    url: &str,
    password: &str,
    output: &Path,
) -> Result<(), String> {
    log::info!("Start test /register_start route");

    log::debug!("Create OPAQUE client registration");
    let mut client_rng = OsRng;
    let client_registration_start_result =
        ClientRegistration::<DefaultCipherSuite>::start(&mut client_rng, password.as_bytes())
            .map_err(|e| e.to_string())?;

    log::debug!("Sending request to {}/register_start", url);
    let res = client
        .post(url.to_owned() + "/register_start")
        .header("Content-Type", "application/json")
        .json(&RegistrationRequestPayload::new(
            client_registration_start_result.message,
        ))
        .send()
        .await
        .map_err(|e| e.to_string())?;
    let res: RegistrationRequestResponse = res.json().await.map_err(|e| e.to_string())?;
    log::debug!("Got response!");

    if &res.status == "Error" {
        return Err("Failed to initiate RegistrationRequest".to_string());
    }

    log::debug!("Finishing OPAQUE client registration");
    let client_registration_finish_result = client_registration_start_result
        .state
        .finish(
            &mut client_rng,
            password.as_bytes(),
            res.registration_response.unwrap(),
            ClientRegistrationFinishParameters::default(),
        )
        .map_err(|e| e.to_string())?;

    log::debug!("Saving identifier uuid to file at {:?}", output);
    let mut file = File::create(output).await.map_err(|e| e.to_string())?;
    file.write_all(res.identifier.unwrap().as_bytes())
        .await
        .map_err(|e| e.to_string())?;

    log::debug!("Sending request to {}/register_end", url);
    let res = client
        .post(url.to_owned() + "/register_end")
        .header("Content-Type", "application/json")
        .json(&RegistrationUploadPayload::new(
            res.identifier.unwrap(),
            client_registration_finish_result.message,
        ))
        .send()
        .await
        .map_err(|e| e.to_string())?;
    let res: RegistrationUploadResponse = res.json().await.map_err(|e| e.to_string())?;
    log::debug!("Got response!");

    if &res.status == "Error" {
        return Err("Failed to confirm RegistrationUpload".to_string());
    }

    println!("Successfully registered client!");
    Ok(())
}
