mod utilities;

use axum::{response::Html, routing::get, Router, Server};
use hyper::{Body, Client};
use hyper_rustls::HttpsConnectorBuilder;
use utilities::{JavaScript, Json};
use web_push_native::{
    jwt_simple::algorithms::ES256KeyPair, p256::PublicKey, Auth, WebPushBuilder,
};

const ENDPOINT: &str = "https://updates.push.services.mozilla.com/wpush/v2/gAAAAABjG7g28Cs8QW50E7jLMvsUE4rplq_1H2NBttI7eYUoyb_BFodreMuvSivI6YNWzT9xtFSyDIV5GqG2SIMMA8Qj41bJipSrPJx-vIrtSD_cYXvmyg0WaI3sOweJxkxWqJ9IS3-f7eBd4W2P9R9RqKHzZsPIMiAI_2m5YiiPjnByOhQgZMg";
const P256DH_AUTH: &str = "IhlBM-pjyTBtpuAvRLic_w";
const P256DH_PUBLIC: &str =
    "BLicFCTt_kNT8eOULZJbowc6lULJ1p_KHVu5VUXixD-tn82RIwc4pLZef90E2QZqBs0D-dz47_dnNbKmVc_NHBQ";
const ES256_PRIVATE: &str = "RS0WdYWWo1HajXg3NZR1olzCf31i-ZBGDkFyCs7j1jw";
const ES256_PUBLIC: &str =
    "BAFpiPJBZOqNZcJGy0eiB1CIwMflt7ugC2B083zKPFu9djmajpSnVnUAFnlDNkzaKHf2gla5_FuDhXE-zIkx5MI";

async fn push() -> Result<(), Box<dyn std::error::Error>> {
    let https = HttpsConnectorBuilder::new()
        .with_native_roots()
        .https_only()
        .enable_http1()
        .build();
    let client: Client<_, Body> = Client::builder().build(https);

    let webpush = WebPushBuilder::new(
        ENDPOINT.parse()?,
        PublicKey::from_sec1_bytes(&base64::decode_config(P256DH_PUBLIC, base64::URL_SAFE)?)?,
        Auth::clone_from_slice(&base64::decode_config(P256DH_AUTH, base64::URL_SAFE)?),
    )
    .with_vapid(
        ES256KeyPair::from_bytes(&base64::decode_config(ES256_PRIVATE, base64::URL_SAFE)?)?,
        "mailto:nobody@example.com",
    )
    .build(r#"{"title": "Title", "body": "Body"}"#)?
    .map(|body| body.into());

    let res = client.request(webpush).await?;
    println!("{:?}", res);
    println!("{:?}", hyper::body::to_bytes(res).await?);

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let app = Router::new()
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
        .route(
            "/vapid.json",
            get(|| async { Json(format!(r#"{{ "publicKey": "{}" }}"#, ES256_PUBLIC)) }),
        )
        .route("/trigger", get(|| async { push().await.unwrap() }));

    Server::bind(&"0.0.0.0:3030".parse()?)
        .serve(app.into_make_service())
        .await?;

    Ok(())
}
