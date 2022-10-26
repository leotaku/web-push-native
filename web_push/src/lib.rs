//! This crate implements "Generic Event Delivery Using Http Push" (web-push)
//! according to [RFC8030](https://www.rfc-editor.org/rfc/rfc8030).
//!
//! # Example
//!
//! This example shows how to use the [`WebPushBuilder`] to create a HTTP push
//! request to one, hard-coded client.
//!
//! In most cases, you will need to implement some form of state management to
//! send messages to all of your clients. You are expected to create one
//! [`WebPushBuilder`] for each client you want to send messages to, but can
//! reuse the same builder for multiple push requests to the same
//! client.
//!
//! Please see the [`/example`](https://github.com/leotaku/web-push-native/tree/master/example)
//! directory on GitHub for a more fully-featured example.
//!
//! ```
//! use hyper::{Body, Client};
//! use hyper_rustls::HttpsConnectorBuilder;
//! use web_push_native::{
//!     jwt_simple::algorithms::ES256KeyPair, p256::PublicKey, Auth, Error, WebPushBuilder,
//! };
//!
//! // Placeholders for variables provided by individual clients. In most cases,
//! // these will be retrieved in-browser using `pushManager.subscribe` on a service
//! // worker registration object.
//! const ENDPOINT: &str = "";
//! const P256DH: &str = "";
//! const AUTH: &str = "";
//!
//! // Placeholder for your private VAPID key. Keep this private and out of your
//! // source tree in real projects!
//! const VAPID: &str = "";
//!
//! async fn push(content: Body) -> Result<http::Request<Body>, Error> {
//!     let https = HttpsConnectorBuilder::new()
//!         .with_native_roots()
//!         .https_only()
//!         .enable_http1()
//!         .build();
//!     let client: Client<_, Body> = Client::builder().build(https);
//!
//!     let builder = WebPushBuilder::new(
//!         ENDPOINT.parse()?,
//!         PublicKey::from_sec1_bytes(&base64::decode_config(P256DH, base64::URL_SAFE)?)?,
//!         Auth::clone_from_slice(&base64::decode_config(AUTH, base64::URL_SAFE)?),
//!     )
//!     .with_vapid(
//!         ES256KeyPair::from_bytes(&base64::decode_config(VAPID, base64::URL_SAFE)?)?,
//!         "mailto:example@example.com",
//!     );
//!
//!     builder.build(content).map(|body| body.into())
//! }
//! ```

#[cfg(feature = "serde")]
mod serde_;
#[cfg(test)]
mod tests;
#[cfg(feature = "vapid")]
mod vapid;

#[cfg(feature = "vapid")]
pub use jwt_simple;
pub use p256;

use aes_gcm::aead::{
    generic_array::{typenum::U16, GenericArray},
    rand_core::RngCore,
    OsRng,
};
use hkdf::Hkdf;
use http::{self, header, Request, Uri};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use sha2::Sha256;
use std::time::Duration;

/// Opaque error type for HTTP push failure modes
pub type Error = Box<dyn std::error::Error>;

/// HTTP push authentication secret
pub type Auth = GenericArray<u8, U16>;

/// Reusable builder for HTTP push requests
#[derive(Clone, Debug)]
pub struct WebPushBuilder<A = ()> {
    endpoint: Uri,
    valid_duration: Duration,
    ua_public: p256::PublicKey,
    ua_auth: Auth,
    http_auth: A,
}

impl WebPushBuilder {
    /// Creates a new [`WebPushBuilder`] factory for HTTP push requests.
    ///
    /// Requests generated using this factory will have a valid  duration of 12
    /// hours and no VAPID signature.
    ///
    /// Most providers accepting HTTP push requests will require a valid VAPID
    /// signature, so you will most likely want to add one using
    /// [`WebPushBuilder::with_vapid`].
    pub fn new<'a>(endpoint: Uri, ua_public: p256::PublicKey, ua_auth: Auth) -> Self {
        Self {
            endpoint,
            ua_public,
            ua_auth,
            valid_duration: Duration::from_secs(12 * 60 * 60),
            http_auth: (),
        }
    }

    /// Sets the valid duration for generated HTTP push requests.
    pub fn with_valid_duration(self, valid_duration: Duration) -> Self {
        let mut this = self;
        this.valid_duration = valid_duration;
        this
    }

    /// Sets the VAPID signature header for generated HTTP push requests.
    #[cfg(feature = "vapid")]
    pub fn with_vapid<'a>(
        self,
        vapid_kp: &'a ES256KeyPair,
        contact: &'a str,
    ) -> WebPushBuilder<vapid::VapidAuthorization<'a>> {
        WebPushBuilder {
            endpoint: self.endpoint,
            valid_duration: self.valid_duration,
            ua_public: self.ua_public,
            ua_auth: self.ua_auth,
            http_auth: vapid::VapidAuthorization::new(vapid_kp, contact),
        }
    }
}

#[doc(hidden)]
pub trait AddHeaders: Sized {
    fn add_headers(
        this: &WebPushBuilder<Self>,
        builder: http::request::Builder,
    ) -> Result<http::request::Builder, Error>;
}

impl AddHeaders for () {
    fn add_headers(
        _this: &WebPushBuilder<Self>,
        builder: http::request::Builder,
    ) -> Result<http::request::Builder, Error> {
        Ok(builder)
    }
}

impl<A: AddHeaders> WebPushBuilder<A> {
    /// Generates a new HTTP push request according to the
    /// specifications of the builder.
    pub fn build<T: Into<Vec<u8>>>(&self, body: T) -> Result<Request<Vec<u8>>, Error> {
        let body = body.into();

        let payload = encrypt(body, &self.ua_public, &self.ua_auth)?;
        let builder = Request::builder()
            .uri(self.endpoint.clone())
            .method(http::method::Method::POST)
            .header("TTL", self.valid_duration.as_secs())
            .header(header::CONTENT_ENCODING, "aes128gcm")
            .header(header::CONTENT_TYPE, "application/octet-stream")
            .header(header::CONTENT_LENGTH, payload.len());

        let builder = AddHeaders::add_headers(self, builder)?;

        Ok(builder.body(payload)?)
    }
}

/// Lower-level encryption used for HTTP push request content
pub fn encrypt(
    message: Vec<u8>,
    ua_public: &p256::PublicKey,
    ua_auth: &Auth,
) -> Result<Vec<u8>, ece_native::Error> {
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);
    let as_secret = p256::SecretKey::random(&mut OsRng);
    encrypt_predictably(salt, message, &as_secret, ua_public, ua_auth)
}

fn encrypt_predictably(
    salt: [u8; 16],
    message: Vec<u8>,
    as_secret: &p256::SecretKey,
    ua_public: &p256::PublicKey,
    ua_auth: &Auth,
) -> Result<Vec<u8>, ece_native::Error> {
    let as_public = as_secret.public_key();
    let shared = p256::ecdh::diffie_hellman(as_secret.to_nonzero_scalar(), ua_public.as_affine());

    let ikm = compute_ikm(
        ua_auth.as_slice().try_into().unwrap(),
        &shared,
        ua_public,
        &as_public,
    );
    let keyid = as_public.as_affine().to_encoded_point(false);
    let encrypted_record_length = (message.len() + 17)
        .try_into()
        .map_err(|_| ece_native::Error::RecordLengthInvalid)?;

    ece_native::encrypt(
        ikm,
        salt,
        keyid,
        Some(message).into_iter(),
        encrypted_record_length,
    )
}

/// Lower-level decryption used for HTTP push request content
pub fn decrypt(
    encrypted_message: Vec<u8>,
    as_secret: &p256::SecretKey,
    ua_auth: &Auth,
) -> Result<Vec<u8>, ece_native::Error> {
    let idlen = encrypted_message[20];
    let keyid = &encrypted_message[21..21 + (idlen as usize)];

    let ua_public =
        p256::PublicKey::from_sec1_bytes(keyid).map_err(|_| ece_native::Error::Aes128Gcm)?;
    let shared = p256::ecdh::diffie_hellman(as_secret.to_nonzero_scalar(), ua_public.as_affine());

    let ikm = compute_ikm(&ua_auth, &shared, &as_secret.public_key(), &ua_public);

    ece_native::decrypt(ikm, encrypted_message)
}

fn compute_ikm(
    auth: &Auth,
    shared: &p256::ecdh::SharedSecret,
    ua_public: &p256::PublicKey,
    as_public: &p256::PublicKey,
) -> [u8; 32] {
    let mut info = Vec::new();
    info.extend_from_slice(&b"WebPush: info"[..]);
    info.push(0u8);
    info.extend_from_slice(ua_public.as_affine().to_encoded_point(false).as_bytes());
    info.extend_from_slice(as_public.as_affine().to_encoded_point(false).as_bytes());

    let mut okm = [0u8; 32];
    let hk = Hkdf::<Sha256>::new(Some(&auth), shared.raw_secret_bytes().as_ref());
    hk.expand(&info, &mut okm)
        .expect("okm length is always 32 bytes, cannot be too large");

    okm
}
