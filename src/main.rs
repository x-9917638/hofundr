use std::io;
use std::process::exit;

use actix_web::{App, HttpResponse, HttpServer, post, web};
use heed::EnvOpenOptions;
use heed::types::{SerdeBincode, Str};
use home::home_dir;
use opaque_ke::{ServerRegistration, ServerSetup};
use tokio::fs;
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
        Err(_) => return web::Json(RegistrationRequestResponse::new_err()),
    };
    let mut wtxn = match data.database_env.write_txn() {
        Ok(w) => w,
        Err(_) => return web::Json(RegistrationRequestResponse::new_err()),
    };

    if let Err(_) = data
        .database
        .put(&mut wtxn, &uuid.to_string(), &ClientEntry::default())
    {
        return web::Json(RegistrationRequestResponse::new_err());
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
        Err(_) => return web::Json(RegistrationUploadResponse::err()),
    };

    if let Err(_) = data.database.put(
        &mut wtxn,
        &payload.uuid.to_string(),
        &ClientEntry {
            password_file: Some(password_file),
            database_file: None,
        },
    ) {
        return web::Json(RegistrationUploadResponse::err());
    }

    web::Json(RegistrationUploadResponse {
        status: "Ok".to_string(),
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
    let config_path = home_dir()
        .expect("Could not get home directory!")
        .join(".config/hofundr/config.toml");

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

    let data = web::Data::new(AppState {
        server_setup,
        database,
        database_env,
    });
    HttpServer::new(move || {
        App::new()
            .app_data(data.clone())
            .service(register_start)
            .service(register_end)
            .service(pull)
            .service(push)
    })
    .bind(("127.0.0.1", config.server_port))?
    .run()
    .await
}

fn heed_err_to_io_err(e: heed::Error) -> io::Error {
    io::Error::new(io::ErrorKind::Other, e.to_string())
}
