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
    collections::HashMap, io, ops::Deref as _, path::PathBuf, process::exit, time::Duration,
};

use actix_web::{
    App, HttpResponse, HttpResponseBuilder, HttpServer,
    http::StatusCode,
    post,
    web::{self, JsonConfig},
};
use actix_web_lab::extract::Json;
use clap::Parser;
use heed::{
    EnvOpenOptions,
    types::{SerdeBincode, Str},
};
use home::home_dir;
use log::{LevelFilter, set_max_level};
use opaque_ke::{
    ServerLogin, ServerLoginParameters, ServerRegistration, ServerSetup, rand::rngs::OsRng,
};
use spdlog::log_crate_proxy;
use tokio::{fs, sync::Mutex, task, time::sleep};
use uuid::Uuid;

mod api;
mod config;
mod data;
mod opaque;
mod scalar;

use crate::{
    config::Config,
    data::*,
    opaque::{DefaultCipherSuite, opaque_setup},
};

const LIMIT_REGISTRATION_START: usize = 256;
const LIMIT_REGISTRATION_END: usize = 1024;
const LIMIT_LOGIN: usize = 512;
// const LIMIT_PULL: usize = 1024;
// const LIMIT_PUSH: usize = 1024;

struct AppState {
    server_setup: ServerSetup<DefaultCipherSuite>,
    database_env: heed::Env,
    database: heed::Database<Str, SerdeBincode<ClientEntry>>,
    sessions: Mutex<HashMap<Uuid, ServerLogin<DefaultCipherSuite>>>,
}

#[derive(serde::Serialize, serde::Deserialize, Default, utoipa::ToSchema)]
struct ClientEntry {
    #[schema(value_type = Option<&[u8]>, format = Binary)]
    password_file: Option<ServerRegistration<DefaultCipherSuite>>,
    database_file: Option<Box<[u8]>>,
    /// A sha256 hash of the database
    checksum: Option<[u8; 32]>,
    /// A timestamp (denoting seconds since UNIX_EPOCH) of when
    /// the last push occured.
    last_push: Option<u64>,
    /// Records the last device to push.
    last_device: Option<Box<str>>,
}

#[post("/register_start")]
async fn register_start(
    data: web::Data<AppState>,
    payload: Json<RegistrationRequestPayload, LIMIT_REGISTRATION_START>,
) -> HttpResponse {
    let payload = payload.into_inner();
    let identifier = Uuid::new_v4();
    let reg_result = match ServerRegistration::<DefaultCipherSuite>::start(
        &data.server_setup,
        payload.registration_request,
        identifier.as_bytes(),
    ) {
        Ok(v) => v,
        Err(e) => {
            log::warn!("{}", e);
            log::error!("Failed to start server registration");
            return HttpResponseBuilder::new(StatusCode::BAD_REQUEST)
                .json(RegistrationRequestResponse::err());
        }
    };
    let mut wtxn = match data.database_env.write_txn() {
        Ok(w) => w,
        Err(e) => {
            log::warn!("{}", e);
            log::error!("Failed to initialise write transaction in the /register_start route");
            return HttpResponseBuilder::new(StatusCode::BAD_REQUEST)
                .json(RegistrationRequestResponse::err());
        }
    };

    if let Err(e) = data
        .database
        .put(&mut wtxn, &identifier.to_string(), &ClientEntry::default())
    {
        log::warn!("{}", e);
        return HttpResponseBuilder::new(StatusCode::BAD_REQUEST)
            .json(RegistrationRequestResponse::err());
    }

    if let Err(e) = wtxn.commit() {
        log::warn!("{}", e);
        log::error!("A database write transaction failed in the /register_end route.");
        return HttpResponseBuilder::new(StatusCode::BAD_REQUEST)
            .json(RegistrationRequestResponse::err());
    }

    HttpResponseBuilder::new(StatusCode::OK).json(RegistrationRequestResponse {
        status: "Ok".to_string(),
        identifier: Some(identifier),
        registration_response: Some(reg_result.message),
    })
}

#[post("/register_end")]
async fn register_end(
    data: web::Data<AppState>,
    payload: Json<RegistrationUploadPayload, LIMIT_REGISTRATION_END>,
) -> web::Json<RegistrationUploadResponse> {
    let payload = payload.into_inner();
    let password_file = ServerRegistration::finish(payload.registration_upload);

    let mut wtxn = match data.database_env.write_txn() {
        Ok(w) => w,
        Err(e) => {
            log::warn!("{}", e);
            log::error!("Failed to initialise write transaction in the /register_end route");
            return web::Json(RegistrationUploadResponse::err());
        }
    };

    if let Err(e) = data.database.put(
        &mut wtxn,
        &payload.identifier.to_string(),
        &ClientEntry {
            password_file: Some(password_file),
            database_file: None,
            checksum: None,
            last_device: None,
            last_push: None,
        },
    ) {
        log::warn!("{}", e);
        return web::Json(RegistrationUploadResponse::err());
    }

    if let Err(e) = wtxn.commit() {
        log::warn!("{}", e);
        log::error!("A database write transaction failed in the /register_end route.");
        return web::Json(RegistrationUploadResponse::err());
    }

    web::Json(RegistrationUploadResponse {
        status: "Ok".to_string(),
    })
}

#[post("/login")]
// Completes the first login stage of opaque
// The client must send the login response to push or pull
// a file.
async fn login(
    data: web::Data<AppState>,
    payload: Json<LoginPayload, LIMIT_LOGIN>,
) -> HttpResponse {
    let payload = payload.into_inner();
    let rtxn = match data.database_env.read_txn() {
        Ok(r) => r,
        Err(e) => {
            log::warn!("{}", e);
            log::error!("Failed to initialise read transaction in the /login route");
            return HttpResponseBuilder::new(StatusCode::INTERNAL_SERVER_ERROR)
                .json(LoginResponse::err());
        }
    };
    let password_file = {
        if let Ok(Some(entry)) = data.database.get(&rtxn, &payload.identifier.to_string()) {
            entry.password_file
        } else {
            None
        }
    };
    if let Err(e) = rtxn.commit() {
        log::warn!("{}", e);
        log::error!("A database read transaction failed in the /login route.");
        return HttpResponseBuilder::new(StatusCode::INTERNAL_SERVER_ERROR)
            .json(LoginResponse::err());
    };
    let mut server_rng = OsRng;
    let server_login_start_result = match ServerLogin::start(
        &mut server_rng,
        &data.server_setup,
        password_file,
        payload.credential_request,
        payload.identifier.as_bytes(),
        ServerLoginParameters::default(),
    ) {
        Ok(s) => s,
        Err(e) => {
            log::warn!("{}", e);
            return HttpResponseBuilder::new(StatusCode::BAD_REQUEST).json(LoginResponse::err());
        }
    };
    let session_id = Uuid::new_v4();

    let sessions = data.sessions.lock();
    sessions
        .await
        .insert(session_id, server_login_start_result.state);

    // If client doesn't complete login within a minute,
    // close the session.
    task::spawn(async move {
        sleep(Duration::from_mins(1)).await;
        log::warn!("Session of id {} timed out", session_id);
        let mut sessions = data.sessions.lock().await;
        sessions.remove(&session_id);
    });

    HttpResponseBuilder::new(StatusCode::OK).json(LoginResponse {
        status: "Ok".to_string(),
        session_id: Some(session_id),
        credential_response: Some(server_login_start_result.message),
    })
}

#[post("/pull")]
async fn pull(data: web::Data<AppState>, payload: Json<PullPayload>) -> HttpResponse {
    let payload = payload.into_inner();
    let mut sessions = data.sessions.lock().await;
    let server_login = sessions.remove(&payload.session_id);
    if server_login.is_none() {
        log::warn!("Client attempted to use invalid session!");
        return HttpResponseBuilder::new(StatusCode::INTERNAL_SERVER_ERROR)
            .json(PullResponse::err());
    }
    let server_login = server_login.unwrap();
    let server_login_finish_result = match server_login.finish(
        payload.credential_finalization,
        ServerLoginParameters::default(),
    ) {
        Ok(res) => res,
        Err(_) => {
            log::warn!("Failed server login finish for route /pull");
            return HttpResponseBuilder::new(StatusCode::INTERNAL_SERVER_ERROR)
                .json(PullResponse::err());
        }
    };

    if server_login_finish_result.session_key.as_slice() != payload.session_key.deref() {
        log::warn!("Invalid session key for route /pull");
        return HttpResponseBuilder::new(StatusCode::INTERNAL_SERVER_ERROR)
            .json(PullResponse::err());
    }

    let rtxn = match data.database_env.read_txn() {
        Ok(r) => r,
        Err(_) => {
            log::warn!("Failed database read transaction init for route /pull");
            return HttpResponseBuilder::new(StatusCode::INTERNAL_SERVER_ERROR)
                .json(PullResponse::err());
        }
    };

    // This should never fail.
    let client_entry = match data.database.get(&rtxn, &payload.identifier.to_string()) {
        Ok(c) => c.unwrap(),
        Err(_) => {
            log::warn!("Failed database getting entry for route /pull");
            return HttpResponseBuilder::new(StatusCode::INTERNAL_SERVER_ERROR)
                .json(PullResponse::err());
        }
    };

    if let Some(atime) = client_entry.last_push
        && payload.last_written > atime
    {
        // TODO: Refactor the errors I send back to client so
        // that i can inform client that their version is later
        // than the server's.
        return HttpResponseBuilder::new(StatusCode::INTERNAL_SERVER_ERROR)
            .json(PullResponse::err());
    }

    if let Some(file) = client_entry.database_file {
        // TODO: Encrypt file with session key.
        //
        // Note: What if I got client to encrypt database_files
        // with the export key so the files on the server have
        // been encrypted twice, with the server not having any
        // way to decrypt? This should be more secure + no need
        // to do any encryption on server so yay less resources.
        // However menas I can't check if the file is a valid
        // Forseti database...
        todo!();
    } else {
        // TODO: Send error informing no file stored.
    }

    HttpResponseBuilder::new(StatusCode::OK).finish()
}

#[post("/push")]
async fn push(data: web::Data<AppState>, payload: Json<PushPayload>) -> HttpResponse {
    let payload = payload.into_inner();
    let mut sessions = data.sessions.lock().await;
    let server_login = sessions.remove(&payload.session_id);
    if server_login.is_none() {
        log::warn!("Client attempted to use invalid session!");
        return HttpResponseBuilder::new(StatusCode::INTERNAL_SERVER_ERROR)
            .json(PushResponse::err());
    }
    let server_login = server_login.unwrap();
    let server_login_finish_result = match server_login.finish(
        payload.credential_finalization,
        ServerLoginParameters::default(),
    ) {
        Ok(res) => res,
        Err(_) => {
            log::warn!("Failed server login finish for route /pull");
            return HttpResponseBuilder::new(StatusCode::INTERNAL_SERVER_ERROR)
                .json(PushResponse::err());
        }
    };

    if server_login_finish_result.session_key.as_slice() != payload.session_key.deref() {
        log::warn!("Invalid session key for route /pull");
        return HttpResponseBuilder::new(StatusCode::INTERNAL_SERVER_ERROR)
            .json(PushResponse::err());
    }

    let rtxn = match data.database_env.read_txn() {
        Ok(r) => r,
        Err(_) => {
            log::warn!("Failed database read transaction init for route /pull");
            return HttpResponseBuilder::new(StatusCode::INTERNAL_SERVER_ERROR)
                .json(PushResponse::err());
        }
    };

    // This should never fail.
    let client_entry = match data.database.get(&rtxn, &payload.identifier.to_string()) {
        Ok(c) => c.unwrap(),
        Err(_) => {
            log::warn!("Failed database getting entry for route /pull");
            return HttpResponseBuilder::new(StatusCode::INTERNAL_SERVER_ERROR)
                .json(PullResponse::err());
        }
    };
    todo!()
}

async fn load_config(config_path: PathBuf) -> Result<Config, std::io::Error> {
    Ok(match Config::load(
        config_path
            .to_str()
            .expect("Non UTF-8 characters in config path."),
    )
    .await
    {
        Ok(c) => Ok(c),
        Err(e) => match e.kind() {
            io::ErrorKind::NotFound => {
                let new = Config::new();
                let default_path = home_dir()
                    .expect("Could not get home directory!")
                    .join(".config/hofundr/config.toml");
                if default_path != config_path {
                    println!("No config found at '{}'", config_path.to_str().unwrap());
                    exit(1)
                }
                // unwrap() is safe here as we already know what the
                // path is: ~/.config/hofundr/config.toml
                fs::create_dir_all(config_path.parent().unwrap())
                    .await
                    .expect("Could not create config directory");
                // unwrap() is safe here, we already expected utf-8 path above.
                new.write(config_path.to_str().unwrap()).await?;

                println!(
                    "No config found. Please edit the generated config at {}",
                    config_path.to_str().unwrap()
                );
                // We can call exit(1) here because there should be nothing
                // important that needs destructors to be called on.
                exit(1)
            }
            _ => Err(e),
        },
    }
    .expect("Could not load config!"))
}

fn init_logger(config: &Config) -> Result<(), io::Error> {
    spdlog::init_log_crate_proxy()
        .expect("users should only call `init_log_crate_proxy` function once");
    log_crate_proxy().set_logger(None);
    set_max_level(LevelFilter::from(&config.log_level));
    let file_sink = spdlog::sink::FileSink::builder()
        .path(&config.logfile)
        .build_arc()
        .map_err(io::Error::other)?;
    let async_pool_sink = spdlog::sink::AsyncPoolSink::builder()
        .sink(file_sink)
        .build_arc()
        .map_err(io::Error::other)?;
    let async_logger = spdlog::Logger::builder()
        .sink(async_pool_sink)
        .flush_level_filter(spdlog::LevelFilter::All)
        .build_arc()
        .map_err(io::Error::other)?;
    log_crate_proxy().set_logger(Some(async_logger));

    Ok(())
}

async fn init_data(config: &Config) -> Result<web::Data<AppState>, std::io::Error> {
    let server_setup = opaque_setup(config.server_setup_path.to_str().unwrap()).await?;
    let dir = &config.database_dir;

    // SAFETY:
    // - All transactions are commited as soon as possible.
    // - The NO_LOCK flag is NOT set.
    //
    // However, this may cause UB if the user aborts the
    // process, modifies the memory map or breaks the
    // logfile.
    //
    // To avoid this, clearly document these limitations.
    // TODO!
    let database_env = unsafe { EnvOpenOptions::new().open(dir).map_err(io::Error::other)? };
    let mut wtxn = database_env.write_txn().map_err(io::Error::other)?;
    let database = database_env
        .create_database(&mut wtxn, None)
        .map_err(io::Error::other)?;
    wtxn.commit().map_err(io::Error::other)?;
    let sessions = Mutex::from(HashMap::new());
    let data = web::Data::new(AppState {
        server_setup,
        database,
        database_env,
        sessions,
    });
    Ok(data)
}

#[actix_web::main]
async fn main() -> Result<(), std::io::Error> {
    let cli = Cli::parse();

    let config_path = match cli.config {
        Some(p) => p,
        None => home_dir()
            .expect("Could not get home directory!")
            .join(".config/hofundr/config.toml"),
    };

    let config = load_config(config_path).await?;

    init_logger(&config)?;

    let data = init_data(&config).await?;

    HttpServer::new(move || {
        let json_cfg = JsonConfig::default()
            .content_type(|mime| mime == actix_web::mime::APPLICATION_JSON)
            .content_type_required(true);
        let scope = web::scope("/api")
            .service(register_start)
            .service(register_end)
            .service(login)
            .service(pull)
            .service(push);
        App::new()
            .app_data(data.clone())
            .app_data(json_cfg)
            // Api Documentation
            .service(crate::api::api_json)
            .service(crate::api::api_index)
            .service(scope)
    })
    .bind(("127.0.0.1", config.port))?
    .run()
    .await
}
