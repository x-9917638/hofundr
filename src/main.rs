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

use std::collections::HashMap;
use std::io;
use std::process::exit;
use std::time::Duration;

use actix_web::{App, HttpResponse, HttpResponseBuilder, HttpServer, get, post, web};
use clap::Parser;
use heed::EnvOpenOptions;
use heed::types::{SerdeBincode, Str};
use home::home_dir;
use opaque_ke::rand::rngs::OsRng;
use opaque_ke::{ServerLogin, ServerLoginParameters, ServerRegistration, ServerSetup};
use structured_logger::async_json::new_writer;
use tokio::sync::Mutex;
use tokio::time::sleep;
use tokio::{fs, task};
use utoipa::{OpenApi};
use utoipa_swagger_ui::SwaggerUi;
use uuid::Uuid;

mod config;
mod data;
mod opaque;

use crate::config::Config;
use crate::data::*;
use crate::opaque::{DefaultCipherSuite, opaque_setup};

struct AppState {
    server_setup: ServerSetup<DefaultCipherSuite>,
    database_env: heed::Env,
    database: heed::Database<Str, SerdeBincode<ClientEntry>>,
    sessions: Mutex<HashMap<Uuid, ServerLogin<DefaultCipherSuite>>>,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct ClientEntry {
    password_file: Option<ServerRegistration<DefaultCipherSuite>>,
    database_file: Option<Box<[u8]>>,
}

impl Default for ClientEntry {
    fn default() -> Self {
        Self {
            password_file: None,
            database_file: None,
        }
    }
}

#[post("/register_start")]
async fn register_start(
    data: web::Data<AppState>,
    payload: web::Json<RegistrationRequestPayload>,
) -> web::Json<RegistrationRequestResponse> {
    let uuid = Uuid::new_v4();
    let reg_result = match ServerRegistration::<DefaultCipherSuite>::start(
        &data.server_setup,
        payload.registration_request.clone(),
        uuid.as_bytes(),
    ) {
        Ok(v) => v,
        Err(e) => {
            log::warn!("{}", e);
            return web::Json(RegistrationRequestResponse::err());
        }
    };
    let mut wtxn = match data.database_env.write_txn() {
        Ok(w) => w,
        Err(e) => {
            log::warn!("{}", e);
            log::error!("Failed to initialise write transaction in the /register_start route");
            return web::Json(RegistrationRequestResponse::err());
        }
    };

    if let Err(e) = data
        .database
        .put(&mut wtxn, &uuid.to_string(), &ClientEntry::default())
    {
        log::warn!("{}", e);
        return web::Json(RegistrationRequestResponse::err());
    }

    if let Err(e) = wtxn.commit() {
        log::warn!("{}", e);
        log::error!("A database write transaction failed in the /register_end route.");
        return web::Json(RegistrationRequestResponse::err());
    }

    web::Json(RegistrationRequestResponse {
        status: "Ok".to_string(),
        identifier: Some(uuid),
        registration_response: Some(reg_result.message),
    })
}

#[post("register_end")]
async fn register_end(
    data: web::Data<AppState>,
    payload: web::Json<RegistrationUploadPayload>,
) -> web::Json<RegistrationUploadResponse> {
    let password_file = ServerRegistration::finish(payload.registration_upload.clone());

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
        &payload.uuid.to_string(),
        &ClientEntry {
            password_file: Some(password_file),
            database_file: None,
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

#[utoipa::path(
    responses(
        (
            status = 200, 
            body = LoginResponse, 
            description = "The server completed the first login stage sucessfully
            but does not guarantee that you are actually authorised to take actions. 
            Upon success, guarantees a session id and credential response.
            See the OPAQUE protocol for more details.",
            examples((
                "default" = (
                    summary = "Response upon correct request", 
                    value = json!({
                        "status": "Ok",
                        "session_id": "Some(Uuid)",
                        "credential_response": "Some(CredentialResponse<DefaultCipherSuite>)"
                    })
                )
            ))
        ),
        (
            status = 400, 
            body = LoginResponse, 
            description = "Client sent incorrect request",
            examples((
                "default" = (
                    summary = "Response upon incorrect request",
                    value = json!({
                        "status": "Err",
                        "session_id": None::<u8>,
                        "credential_response": None::<u8>
                    })
                )
            ))
        )
    ),
    request_body(
        description = "
        JSON containing keys 'uuid' and 'credential_request'.
        
        - 'uuid' should be the identifier returned to the client upon successful registration.
        - 'credential_request' should be an opaque-ke CredentialRequest
        ",
        content = LoginPayload,
        example = json!({
            "uuid": "Uuid",
            "credential_response": "Some(CredentialRequest<DefaultCipherSuite>)"
        })
    )
)]
#[post("/login")]
// Completes the first login stage of opaque
// The client must send the login response to push or pull
// a file.
async fn login(
    data: web::Data<AppState>,
    payload: web::Json<LoginPayload>,
) -> web::Json<LoginResponse> {
    let rtxn = match data.database_env.read_txn() {
        Ok(r) => r,
        Err(e) => {
            log::warn!("{}", e);
            log::error!("Failed to initialise read transaction in the /login route");
            return web::Json(LoginResponse::err());
        }
    };
    let password_file = {
        if let Ok(res) = data.database.get(&rtxn, &payload.uuid.to_string()) {
            if let Some(entry) = res {
                entry.password_file
            } else {
                None
            }
        } else {
            None
        }
    };
    if let Err(e) = rtxn.commit() {
        log::warn!("{}", e);
        log::error!("A database read transaction failed in the /login route.");
        return web::Json(LoginResponse::err());
    };
    let mut server_rng = OsRng;
    let server_login_start_result = match ServerLogin::start(
        &mut server_rng,
        &data.server_setup,
        password_file,
        payload.credential_request.clone(),
        payload.uuid.as_bytes(),
        ServerLoginParameters::default(),
    ) {
        Ok(s) => s,
        Err(e) => {
            log::warn!("{}", e);
            return web::Json(LoginResponse::err());
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
        let mut sessions = data.sessions.lock().await;
        sessions.remove(&session_id);
    });

    web::Json(LoginResponse {
        status: "Ok".to_string(),
        session_id: Some(session_id),
        credential_response: Some(server_login_start_result.message),
    })
}

#[post("/pull")]
async fn pull() -> HttpResponse {
    todo!()
}

#[post("/push")]
async fn push() -> HttpResponse {
    todo!()
}

#[derive(OpenApi)]
#[openapi(
    paths(login),
    info(
        description = "
        Hofundr is the API/server backend for syncing .fedb databases. 
        
        Whilst designed for the Forseti client, this should be usable for any 
        client given they comply with these API specifications. Hofundr expects
        structs from the Rust crate opaque-ke, but other implementations of 
        OPAQUE may be usable too.

        Many routes will return opaque-ke structs. The CipherSuite used for 
        these structs should be as such:
        
        impl CipherSuite for DefaultCipherSuite {
            type OprfCs = Ristretto255;
            type KeyExchange = TripleDh<Ristretto255, sha2::Sha512>;
            type Ksf = Argon2<'static>;
        }
        "
    ),
)]
struct ApiDoc;

#[actix_web::main]
async fn main() -> Result<(), std::io::Error> {
    let cli = Cli::parse();

    let config_path = match cli.config {
        Some(p) => p,
        None => home_dir()
            .expect("Could not get home directory!")
            .join(".config/hofundr/config.toml"),
    };

    let config = match Config::load(
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
                if !(default_path == config_path) {
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
    .expect("Could not load config!");

    structured_logger::Builder::with_level("WARN")
        .with_target_writer("*", new_writer(tokio::io::stdout()))
        .try_init()
        .map_err(|e| std::io::Error::new(io::ErrorKind::Other, e.to_string()))?;

    let server_setup = opaque_setup(config.server_setup_path.to_str().unwrap()).await?;
    let dir = config.database_dir;

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
    let database_env = unsafe {
        EnvOpenOptions::new()
            .open(dir)
            .map_err(heed_err_to_io_err)?
    };
    let mut wtxn = database_env.write_txn().map_err(heed_err_to_io_err)?;
    let database = database_env
        .create_database(&mut wtxn, None)
        .map_err(heed_err_to_io_err)?;
    wtxn.commit().map_err(heed_err_to_io_err)?;
    let sessions = Mutex::from(HashMap::new());

    let data = web::Data::new(AppState {
        server_setup,
        database,
        database_env,
        sessions,
    });
    HttpServer::new(move || {
        let scope = web::scope("/api")
            .service(register_start)
            .service(register_end)
            .service(login)
            .service(pull)
            .service(push);
        App::new()
            .app_data(data.clone())
            .service(
                SwaggerUi::new("/{_:.*}").url("/api-docs/openapi.json", ApiDoc::openapi())
            )
            .service(scope)
     })
    .bind(("127.0.0.1", config.port))?
    .run()
    .await
}

fn heed_err_to_io_err(e: heed::Error) -> io::Error {
    io::Error::new(io::ErrorKind::Other, e.to_string())
}
