mod utilities;

use axum::{
    extract,
    response::Html,
    routing::{get, post},
    Router, Server,
};
use hyper::{Body, Client, StatusCode};
use hyper_rustls::HttpsConnectorBuilder;
use std::sync::{Arc, RwLock};
use tower_http::add_extension::AddExtensionLayer;
use tower_livereload::LiveReloadLayer;
use utilities::{JavaScript, Json};
use web_push_native::{jwt_simple::algorithms::ES256KeyPair, WebPushBuilder};

// VAPID private and public keys
const ES256_PRIVATE: &str = "RS0WdYWWo1HajXg3NZR1olzCf31i-ZBGDkFyCs7j1jw";
const ES256_PUBLIC: &str =
    "BAFpiPJBZOqNZcJGy0eiB1CIwMflt7ugC2B083zKPFu9djmajpSnVnUAFnlDNkzaKHf2gla5_FuDhXE-zIkx5MI";

async fn push(message: String, builder: WebPushBuilder) -> Result<(), Box<dyn std::error::Error>> {
    let https = HttpsConnectorBuilder::new()
        .with_native_roots()
        .https_only()
        .enable_http1()
        .build();
    let client: Client<_, Body> = Client::builder().build(https);

    let key_bytes = &base64::decode_config(ES256_PRIVATE, base64::URL_SAFE)?;
    let request = builder
        .with_vapid(ES256KeyPair::from_bytes(key_bytes)?, "")
        .build(format!(r#"{{"title": "{}", "body": ""}}"#, message))?
        .map(|body| body.into());

    client.request(request).await?;

    Ok(())
}

type SharedState = Arc<RwLock<State>>;

#[derive(Debug, Default)]
struct State {
    builder: Option<WebPushBuilder>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let app = static_routes()
        .nest("/api", api_routes())
        .layer(LiveReloadLayer::new());

    Server::bind(&"0.0.0.0:3030".parse()?)
        .serve(app.into_make_service())
        .await?;

    Ok(())
}

fn api_routes() -> Router {
    Router::new()
        .route(
            "/vapid.json",
            get(|| async { Json(format!(r#"{{ "publicKey": "{}" }}"#, ES256_PUBLIC)) }),
        )
        .route(
            "/put",
            post(
                |extract::Json(builder): extract::Json<WebPushBuilder>,
                 extract::Extension(state): axum::Extension<SharedState>| {
                    if let Ok(ref mut state) = state.try_write() {
                        state.builder = Some(builder)
                    }
                    async {}
                },
            ),
        )
        .route(
            "/message",
            post(
                |extract::Json(message): extract::Json<String>,
                 extract::Extension(state): axum::Extension<SharedState>| {
                    let maybe = state.read().ok().map(|it| it.builder.clone()).flatten();
                    async {
                        if let Some(builder) = maybe {
                            match push(message, builder).await {
                                Ok(_) => (StatusCode::OK, "Ok".to_owned()),
                                Err(err) => (StatusCode::INTERNAL_SERVER_ERROR, format!("{}", err)),
                            }
                        } else {
                            (
                                StatusCode::SERVICE_UNAVAILABLE,
                                "No browser connected".to_owned(),
                            )
                        }
                    }
                },
            ),
        )
        .layer(AddExtensionLayer::new(SharedState::default()))
}

fn static_routes() -> Router {
    Router::new()
        .route(
            "/",
            get(|| async { Html(include_str!("../assets/index.html")) }),
        )
        .route(
            "/index.js",
            get(|| async { JavaScript(include_str!("../assets/index.js")) }),
        )
        .route(
            "/sw.js",
            get(|| async { JavaScript(include_str!("../assets/sw.js")) }),
        )
}
