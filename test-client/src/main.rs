mod cli;
mod data;

use crate::data::{
    DefaultCipherSuite, RegistrationRequestPayload, RegistrationRequestResponse,
    RegistrationUploadPayload, RegistrationUploadResponse,
};
use clap::Parser;
use cli::{Cli, Commands};
use opaque_ke::{ClientRegistration, ClientRegistrationFinishParameters, rand::rngs::OsRng};
use std::{env, path::Path};
use tokio::{fs::File, io::AsyncWriteExt};

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
        Commands::FullTest => full_test(&client, &cli.url).await,
        Commands::TestLogin { input } => test_login(&client, &cli.url, &input).await,
        Commands::TestRegister { password, output } => {
            test_register(&client, &cli.url, &password, &output).await
        }
    }
}

async fn full_test(client: &reqwest::Client, url: &str) -> Result<(), String> {
    todo!()
}

async fn test_login(client: &reqwest::Client, url: &str, input: &Path) -> Result<(), String> {
    todo!()
}

async fn test_register(
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

    log::debug!("Saving output to file at {:?}", output);
    File::create(output)
        .await
        .map_err(|e| e.to_string())?
        .write_all(&client_registration_finish_result.message.serialize())
        .await
        .map_err(|e| e.to_string())?;

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

    if &res.status == "Error" {
        return Err("Failed to confirm RegistrationUpload".to_string());
    }

    println!("Successfully registered client!");
    Ok(())
}
