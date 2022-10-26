use axum::{
    extract,
    http::HeaderValue,
    response::Html,
    routing::{get, post},
    Json, Router, Server,
};
use hyper::{header, Body, Client, StatusCode};
use hyper_rustls::HttpsConnectorBuilder;
use once_cell::sync::Lazy;
use std::sync::{Arc, RwLock};
use tower_http::add_extension::AddExtensionLayer;
use tower_livereload::LiveReloadLayer;
use web_push_native::{
    jwt_simple::algorithms::{ECDSAP256KeyPairLike, ES256KeyPair},
    WebPushBuilder,
};

/// VAPID key pair (keep private for real applications)
static VAPID_PRIVATE: Lazy<ES256KeyPair> = Lazy::new(|| {
    let bytes = base64::decode_config(
        b"RS0WdYWWo1HajXg3NZR1olzCf31i-ZBGDkFyCs7j1jw",
        base64::URL_SAFE,
    )
    .expect("this to be valid base64");
    ES256KeyPair::from_bytes(&bytes).expect("this to be a valid private key")
});

async fn push(message: String, builder: WebPushBuilder) -> Result<(), Box<dyn std::error::Error>> {
    let https = HttpsConnectorBuilder::new()
        .with_native_roots()
        .https_only()
        .enable_http1()
        .build();
    let client: Client<_, Body> = Client::builder().build(https);

    let request = builder
        .with_vapid(&*VAPID_PRIVATE, "mailto:john.doe@example.com")
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
            get(|| async {
                let encoded = base64::encode(
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
            "/sw.js",
            get(|| async {
                (
                    [(
                        header::CONTENT_TYPE,
                        HeaderValue::from_static("application/javascript"),
                    )],
                    include_str!("../assets/sw.js"),
                )
            }),
        )
}
