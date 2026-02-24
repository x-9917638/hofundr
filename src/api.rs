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

// All routes in this file are for documentation purposes only and are stubs.
// See main.rs

use actix_web::{HttpResponse, HttpResponseBuilder, post, web};
use actix_web_lab::extract::Json;
use utoipa::{Modify, OpenApi, openapi::extensions::ExtensionsBuilder};

use crate::{
    data::{
        LoginPayload, LoginResponse, PullPayload, PullResponse, PushPayload, PushResponse,
        RegistrationRequestPayload, RegistrationRequestResponse, RegistrationUploadPayload,
        RegistrationUploadResponse,
    },
    scalar::SCALAR_HTML,
};

#[allow(dead_code)]
struct AppState;

#[utoipa::path(
    responses(
        (
            status = 200,
            body = RegistrationRequestResponse,
            description =
"The server completed the first registration stage sucessfully.
Upon success, guarantees an identifier (that should be persisted) and
registration response.

See the OPAQUE protocol for more details.",
            examples((
                "default" = (
                    summary = "Response upon correct request",
                    value = json!({
                        "status": "Ok",
                        "identifier": "Some(Uuid)",
                        "registration_response": "Some(RegistrationResponse<DefaultCipherSuite>)"
                    })
                )
            ))
        ),
        (
            status = 400,
            body = RegistrationRequestResponse,
            description = "The client sent an incorrect request.",
            examples((
                "default" = (
                    summary = "Response upon incorrect request",
                    value = json!({
                        "status": "Err",
                        "identifier": None::<u8>,
                        "registration_response": None::<u8>
                    })
                )
            ))
        ),
        (
            status = 400,
            body = RegistrationRequestResponse,
            description = "An error occured processing the request.",
            examples((
                "default" = (
                    summary = "Response upon internal server error",
                    value = json!({
                        "status": "Err",
                        "identifier": None::<u8>,
                        "registration_response": None::<u8>
                    })
                )
            ))
        )
    ),
    request_body(
        description = "
JSON containing key `registration_request`.

- `registration_request` should be an opaque-ke RegistrationRequest
",
        content = RegistrationRequestPayload,
        example = json!({
            "registration_request": "RegistrationRequest<DefaultCipherSuite>"
        })
    )
)]
#[post("/register_start")]
async fn register_start(
    _data: web::Data<AppState>,
    _payload: Json<RegistrationRequestPayload>,
) -> HttpResponse {
    unimplemented!()
}

#[utoipa::path(
    responses(
        (
            status = 200,
            body = RegistrationUploadResponse,
            description =
"The server completed the second registration stage sucessfully.
Does not return anything of significance.

See the OPAQUE protocol for more details.",
            examples((
                "default" = (
                    summary = "Response upon correct request",
                    value = json!({
                        "status": "Ok",
                    })
                )
            ))
        ),
        (
            status = 400,
            body = RegistrationUploadResponse,
            description = "The client sent an incorrect request.",
            examples((
                "default" = (
                    summary = "Response upon incorrect request",
                    value = json!({
                        "status": "Err",
                    })
                )
            ))
        ),
        (
            status = 500,
            body = RegistrationUploadResponse,
            description = "An error occured processing the request.",
            examples((
                "default" = (
                    summary = "Response upon internal server error",
                    value = json!({
                        "status": "Err",
                    })
                )
            ))
        )
    ),
    request_body(
        description = "
JSON containing key `identifier` and `registration_upload`.

- `identifier` should be the identifier returned by the /register_start route.
- `registration_upload` should be an opaque-ke RegistrationUpload
",
        content = RegistrationUploadPayload,
        example = json!({
            "identifier": "Uuid",
            "registration_upload": "RegistrationUpload<DefaultCipherSuite>"
        })
    )
)]
#[post("/register_end")]
async fn register_end(
    _data: web::Data<AppState>,
    _payload: Json<RegistrationUploadPayload>,
) -> web::Json<RegistrationUploadResponse> {
    unimplemented!()
}

#[utoipa::path(
    responses(
        (
            status = 200,
            body = LoginResponse,
            description =
"The server completed the first login stage sucessfully
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
            description = "The client sent an incorrect request.",
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
        ),
        (
            status = 500,
            body = LoginResponse,
            description = "An error occured processing the request.",
            examples((
                "default" = (
                    summary = "Response upon internal server error",
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
JSON containing keys `uuid` and `credential_request`.

- `uuid` should be the identifier returned to the client upon successful registration.
- `credential_request` should be an opaque-ke CredentialRequest
",
        content = LoginPayload,
        example = json!({
            "identifier": "Uuid",
            "credential_response": "Some(CredentialRequest<DefaultCipherSuite>)"
        })
    )
)]
#[post("/login")]
async fn login(_data: web::Data<AppState>, _payload: Json<LoginPayload>) -> HttpResponse {
    unimplemented!()
}

#[post("/pull")]
async fn pull(_data: web::Data<AppState>, _payload: Json<PullPayload>) -> HttpResponse {
    unimplemented!()
}

#[post("/push")]
async fn push(_data: web::Data<AppState>, _payload: Json<PushPayload>) -> HttpResponse {
    unimplemented!()
}

#[derive(OpenApi)]
#[openapi(
    paths(login, register_start, register_end),
    info(
        description = "Hofundr is the API/server backend for syncing .fedb databases.

Whilst designed for the Forseti client, this should be usable for any
client given they comply with these API specifications. Hofundr expects
structs from the Rust crate opaque-ke, but other implementations of
OPAQUE may be usable too.

Many routes will return opaque-ke structs. In the following documentation,
the CipherSuite of the various structs will be named DefaultCipherSuite,
with the CipherSuite trait implemented as such:

```rust
impl CipherSuite for DefaultCipherSuite {
    type OprfCs = Ristretto255;
    type KeyExchange = TripleDh<Ristretto255, sha2::Sha512>;
    type Ksf = Argon2<'static>;
}
```
This page uses Scalar, licensed under the MIT License.

Per the AGPL-3.0, source code can be found [here](https://git.ouppy.gay/valerie/hofundr).",
        license(
            name = "Licensed under the GNU Affero General Public License 3.0 only.",
            identifier = "AGPL-3.0-only"
        )
    )
)]
pub struct ApiDoc;

pub struct CodeSamples;

macro_rules! add_code_sample {
    ($openapi:expr, $path:literal, $label:literal, $lang:literal, $source:literal) => {{
        if let Some(item) = $openapi.paths.paths.get_mut($path) {
            if let Some(op) = item.post.as_mut() {
                let _ = op.extensions
                    .insert(ExtensionsBuilder::new()
                        .add("x-codeSamples", serde_json::json!({
                            "label": $label,
                            "lang": $lang,
                            "source": $source
                        }))
                        .build()
                    );
            }
        }
    }};
}

impl Modify for CodeSamples {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        add_code_sample!(
            openapi,
            "/register_start",
            "Rust (reqwest)",
            "Rust",
            r#"use serde_json::json;
use opaque_ke::{ClientRegistration, rand::rngs::OsRng};

let password = b"example";
let mut client_rng = OsRng;

let client_registration_start_result =
    ClientRegistration::<DefaultCipherSuite>::start(
        &mut client_rng,
        password
    )?;

let client = reqwest::ClientBuilder::new().build()?;
let res = client
    .post("https://example.com/api/register_start")
    .header("Content-Type", "application/json")
    .json(json!({
        "registration_request": client_registration_start_result.message,
    }))
    .send()
    .await?;
let res = res.json()?;"#
        );

        add_code_sample!(
            openapi,
            "/register_end",
            "Rust (reqwest)",
            "Rust",
            r#"use serde_json::json;
use opaque_ke::{ClientRegistration, ClientRegistrationFinishParameters, rand::rngs::OsRng};
let res; // JSON from /register_start
let password = b"example";
let mut client_rng = OsRng;

let client_registration_start_result =
    ClientRegistration::<DefaultCipherSuite>::start(
        &mut client_rng,
        password
    )?;
let client_registration_finish_result =
    client_registration_start_result
        .state
        .finish(
            &mut client_rng,
            password,
            res.registration_response.unwrap(),
            ClientRegistrationFinishParameters::default(),
        )?;

let client = reqwest::ClientBuilder::new().build()?;
let res = client
    .post("https://example.com/api/register_end")
    .header("Content-Type", "application/json")
    .json(json!({
        "identifier": res.identifier.unwrap(),
        "registration_upload": client_registration_finish_result.message,
    }))
    .send()
    .await?;
let res = res.json().await?;"#
        );

        add_code_sample!(
            openapi,
            "/login",
            "Rust (reqwest)",
            "Rust",
            r#"use serde_json::json;
use opaque_ke::{ClientLogin, rand::rngs::OsRng};
let uuid; // UUID from /register_start
let password = b"example";
let mut client_rng = OsRng;
let client_login_start_result =
    ClientLogin::<DefaultCipherSuite>::start(
        &mut client_rng,
        password
    )?;

let client = reqwest::ClientBuilder::new().build()?;
let res = client
    .post("https://example.com/api/login")
    .header("Content-Type", "application/json")
    .json(json!({
        "identifier": uuid,
        "credential_request": client_login_start_result.message
    }))
    .send()
    .await?;
let res = res.json().await?;"#
        );
    }
}

#[actix_web::get("/")]
pub async fn api_index() -> HttpResponse {
    HttpResponseBuilder::new(200.try_into().unwrap()).body(SCALAR_HTML)
}

#[actix_web::get("/api-docs/openapi.json")]
pub async fn api_json() -> HttpResponse {
    HttpResponseBuilder::new(200.try_into().unwrap())
        .insert_header(("Content-Type", "application/json"))
        .body(API_JSON.as_str())
}

static API_JSON: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| {
    let mut api = ApiDoc::openapi();
    CodeSamples.modify(&mut api);
    api.to_json().unwrap()
});
