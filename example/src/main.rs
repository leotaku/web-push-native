use axum::{
    extract,
    http::HeaderValue,
    response::Html,
    routing::{get, post},
    Json, Router, Server,
};
use base64ct::{Base64UrlUnpadded, Encoding};
use hyper::{header, Body, Client, StatusCode};
use hyper_rustls::HttpsConnectorBuilder;
use once_cell::sync::Lazy;
use std::sync::{Arc, RwLock};
use tower_livereload::LiveReloadLayer;
use web_push_native::{
    jwt_simple::algorithms::{ECDSAP256KeyPairLike, ES256KeyPair},
    WebPushBuilder,
};

/// VAPID key pair (keep private for real applications)
static VAPID_PRIVATE: Lazy<ES256KeyPair> = Lazy::new(|| {
    let bytes = Base64UrlUnpadded::decode_vec("RS0WdYWWo1HajXg3NZR1olzCf31i-ZBGDkFyCs7j1jw")
        .expect("this to be valid base64");
    ES256KeyPair::from_bytes(&bytes).expect("this to be a valid private key")
});

async fn push(
    message: serde_json::Value,
    builder: WebPushBuilder,
) -> Result<(), Box<dyn std::error::Error>> {
    let https = HttpsConnectorBuilder::new()
        .with_native_roots()
        .https_only()
        .enable_http1()
        .build();
    let client: Client<_, Body> = Client::builder().build(https);

    let request = builder
        .with_vapid(&VAPID_PRIVATE, "mailto:john.doe@example.com")
        .build(message.to_string())?
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

    let addr = &"127.0.0.1:3030".parse()?;
    eprintln!("http://{}", addr);

    Server::bind(addr).serve(app.into_make_service()).await?;

    Ok(())
}

fn api_routes() -> Router {
    Router::new()
        .route(
            "/vapid.json",
            get(|| async {
                let encoded = Base64UrlUnpadded::encode_string(
                    &VAPID_PRIVATE
                        .key_pair()
                        .public_key()
                        .to_bytes_uncompressed(),
                );
                Json(serde_json::json!({
                    "publicKey": encoded,
                }))
            }),
        )
        .route(
            "/register",
            post(
                |extract::State(state): extract::State<SharedState>,
                 extract::Json(builder): extract::Json<WebPushBuilder>| {
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
                |extract::State(state): extract::State<SharedState>,
                 extract::Json(message): extract::Json<serde_json::Value>| {
                    let maybe = state.read().ok().and_then(|it| it.builder.clone());
                    async {
                        if let Some(builder) = maybe {
                            match push(message, builder).await {
                                Ok(_) => (StatusCode::OK, "Ok".to_owned()),
                                Err(error) => {
                                    (StatusCode::INTERNAL_SERVER_ERROR, format!("{}", error))
                                }
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
        .with_state(SharedState::default())
}

fn static_routes() -> Router {
    Router::new()
        .route(
            "/",
            get(|| async { Html(include_str!("../assets/index.html")) }),
        )
        .route(
            "/index.js",
            get(|| async {
                (
                    [(
                        header::CONTENT_TYPE,
                        HeaderValue::from_static("application/javascript"),
                    )],
                    include_str!("../assets/index.js"),
                )
            }),
        )
        .route(
            "/service-worker.js",
            get(|| async {
                (
                    [(
                        header::CONTENT_TYPE,
                        HeaderValue::from_static("application/javascript"),
                    )],
                    include_str!("../assets/service-worker.js"),
                )
            }),
        )
}
