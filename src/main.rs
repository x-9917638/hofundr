use std::collections::HashMap;
use std::io;
use std::process::exit;
use std::time::Duration;

use actix_web::{App, HttpResponse, HttpServer, post, web};
use clap::Parser;
use heed::EnvOpenOptions;
use heed::types::{SerdeBincode, Str};
use home::home_dir;
use opaque_ke::argon2::{Algorithm, Argon2, Params, Version};
use opaque_ke::rand::RngCore;
use opaque_ke::rand::rngs::OsRng;
use opaque_ke::{ServerLogin, ServerLoginParameters, ServerRegistration, ServerSetup};
use structured_logger::async_json::new_writer;
use tokio::sync::Mutex;
use tokio::time::sleep;
use tokio::{fs, task};
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
    secret_key: [u8; 32],
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

    web::Json(RegistrationRequestResponse {
        status: "Ok".to_string(),
        identifier: Some(uuid),
        registration_response: Some(reg_result.message),
    })
}

#[post("register_fin")]
async fn register_end(
    data: web::Data<AppState>,
    payload: web::Json<RegistrationUploadPayload>,
) -> web::Json<RegistrationUploadResponse> {
    let password_file = ServerRegistration::finish(payload.registration_upload.clone());

    let mut wtxn = match data.database_env.write_txn() {
        Ok(w) => w,
        Err(e) => {
            log::warn!("{}", e);
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
    payload: web::Json<LoginPayload>,
) -> web::Json<LoginResponse> {
    let rtxn = data.database_env.read_txn().unwrap();
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
        let sessions = data.sessions.lock();
        sessions.await.remove(&session_id);
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
    let secret_key = derive_secret_key(&config.secret_key);
    let sessions = Mutex::from(HashMap::new());

    let data = web::Data::new(AppState {
        server_setup,
        database,
        database_env,
        secret_key,
        sessions,
    });
    HttpServer::new(move || {
        let scope = web::scope("/api")
            .service(register_start)
            .service(register_end)
            .service(login)
            .service(pull)
            .service(push);
        App::new().app_data(data.clone()).service(scope)
    })
    .bind(("127.0.0.1", config.port))?
    .run()
    .await
}

fn derive_secret_key(secret: &str) -> [u8; 32] {
    let argon2 = Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        Params::new(10240, 10, 4, None).unwrap(),
    );
    let mut out = [0u8; 32];
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);
    argon2
        .hash_password_into(secret.as_bytes(), &salt, &mut out)
        .expect("Invalid secret key");
    out
}

fn heed_err_to_io_err(e: heed::Error) -> io::Error {
    io::Error::new(io::ErrorKind::Other, e.to_string())
}
