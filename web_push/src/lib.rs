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
//! use base64ct::{Base64UrlUnpadded, Encoding};
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
//! async fn push(content: Vec<u8>) -> Result<http::Request<Vec<u8>>, Box<dyn std::error::Error>> {
//!     let key_pair = ES256KeyPair::from_bytes(&Base64UrlUnpadded::decode_vec(VAPID)?)?;
//!     let builder = WebPushBuilder::new(
//!         ENDPOINT.parse()?,
//!         PublicKey::from_sec1_bytes(&Base64UrlUnpadded::decode_vec(P256DH)?)?,
//!         Auth::clone_from_slice(&Base64UrlUnpadded::decode_vec(AUTH)?),
//!     )
//!     .with_vapid(&key_pair, "mailto:john.doe@example.com");
//!
//!     Ok(builder.build(content)?)
//! }
//! ```

#[cfg(feature = "serialization")]
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

/// Error type for HTTP push failure modes
#[derive(Debug)]
pub enum Error {
    /// Key prefix of the encrypted message was too short
    PrefixLengthInvalid,
    /// Internal ECE error
    ECE(ece_native::Error),
    /// Internal error coming from an http auth provider
    Extension(Box<dyn std::error::Error + Send + Sync + 'static>),
}

impl std::error::Error for Error {}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::PrefixLengthInvalid => write!(f, "invalid prefix length"),
            Error::ECE(ece) => write!(f, "ece: {}", ece),
            Error::Extension(ext) => write!(f, "extension: {}", ext),
        }
    }
}

/// HTTP push authentication secret
pub type Auth = GenericArray<u8, U16>;

/// Reusable builder for HTTP push requests
#[derive(Clone, Debug)]
pub struct WebPushBuilder<A = ()> {
    endpoint: Uri,
    valid_duration: Duration,
    ua_public: p256::PublicKey,
    ua_auth: Auth,
    #[cfg_attr(not(feature = "vapid"), allow(dead_code))]
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
    pub fn new(endpoint: Uri, ua_public: p256::PublicKey, ua_auth: Auth) -> Self {
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
        vapid_kp: &'a jwt_simple::algorithms::ES256KeyPair,
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
    type Error: Into<Box<dyn std::error::Error + Sync + Send + 'static>>;

    fn add_headers(
        this: &WebPushBuilder<Self>,
        builder: http::request::Builder,
    ) -> Result<http::request::Builder, Self::Error>;
}

impl AddHeaders for () {
    type Error = std::convert::Infallible;

    fn add_headers(
        _this: &WebPushBuilder<Self>,
        builder: http::request::Builder,
    ) -> Result<http::request::Builder, Self::Error> {
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

        let builder =
            AddHeaders::add_headers(self, builder).map_err(|it| Error::Extension(it.into()))?;

        Ok(builder
            .body(payload)
            .expect("builder arguments are always well-defined"))
    }
}

/// Lower-level encryption used for HTTP push request content
pub fn encrypt(
    message: Vec<u8>,
    ua_public: &p256::PublicKey,
    ua_auth: &Auth,
) -> Result<Vec<u8>, Error> {
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);
    let as_secret = p256::SecretKey::random(&mut OsRng);
    encrypt_predictably(salt, message, &as_secret, ua_public, ua_auth).map_err(Error::ECE)
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
) -> Result<Vec<u8>, Error> {
    if encrypted_message.len() < 21 {
        return Err(Error::PrefixLengthInvalid);
    }

    let idlen = encrypted_message[20];
    let keyid = &encrypted_message[21..21 + usize::from(idlen)];

    let ua_public = p256::PublicKey::from_sec1_bytes(keyid)
        .map_err(|_| ece_native::Error::Aes128Gcm)
        .map_err(Error::ECE)?;
    let shared = p256::ecdh::diffie_hellman(as_secret.to_nonzero_scalar(), ua_public.as_affine());

    let ikm = compute_ikm(ua_auth, &shared, &as_secret.public_key(), &ua_public);

    ece_native::decrypt(ikm, encrypted_message).map_err(Error::ECE)
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
    let hk = Hkdf::<Sha256>::new(Some(auth), shared.raw_secret_bytes().as_ref());
    hk.expand(&info, &mut okm)
        .expect("okm length is always 32 bytes, cannot be too large");

    okm
}
