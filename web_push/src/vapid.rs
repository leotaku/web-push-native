//! Utilities for creating VAPID signatures according to [RFC8292](https://datatracker.ietf.org/doc/html/rfc8292).
//!
//! [`WebPushBuilder::with_vapid`] can be used to automatically add
//! VAPID signature headers to your responses. Use [`VapidSignature`]
//! when you need to manually create and store VAPID signatures.
//!
//! # Example
//!
//! ```
//! use base64ct::{Base64UrlUnpadded, Encoding as _};
//! use web_push_native::{jwt_simple::algorithms::ES256KeyPair, vapid::VapidSignature};
//!
//! const VAPID_PRIVATE: &str = "RS0WdYWWo1HajXg3NZR1olzCf31i-ZBGDkFyCs7j1jw";
//!
//! let key_pair = ES256KeyPair::from_bytes(&Base64UrlUnpadded::decode_vec(VAPID_PRIVATE)?)?;
//! let signature = VapidSignature::sign(
//!     &http::Uri::from_static("https://example.com/"),
//!     std::time::Duration::new(60, 0),
//!     "mailto:john.doe@example.com",
//!     &key_pair,
//! )?;
//!
//! assert!(signature.to_string().starts_with("vapid"));
//! #
//! # Ok::<_, Box<dyn std::error::Error>>(())
//! ```

use std::{fmt::Display, time::Duration};

use base64ct::{Base64UrlUnpadded, Encoding};
use http::{header, Uri};
use jwt_simple::{
    algorithms::{ECDSAP256KeyPairLike, ECDSAP256PublicKeyLike, ES256KeyPair, ES256PublicKey},
    claims::Claims,
};

use super::{AddHeaders, WebPushBuilder};

#[doc(hidden)]
pub struct VapidAuthorization<'a> {
    vapid_kp: &'a ES256KeyPair,
    contact: &'a str,
}

impl<'a> VapidAuthorization<'a> {
    pub fn new(vapid_kp: &'a ES256KeyPair, contact: &'a str) -> Self {
        Self { vapid_kp, contact }
    }
}

impl<'a> AddHeaders for VapidAuthorization<'a> {
    type Error = jwt_simple::Error;

    fn add_headers(
        this: &WebPushBuilder<Self>,
        builder: http::request::Builder,
    ) -> Result<http::request::Builder, Self::Error> {
        let vapid = VapidSignature::sign(
            &this.endpoint,
            this.valid_duration,
            this.http_auth.contact.to_string(),
            this.http_auth.vapid_kp,
        )?;
        Ok(builder.header(header::AUTHORIZATION, vapid))
    }
}

#[derive(Clone, Debug)]
/// VAPID (Voluntary Application Server Identification) signature
pub struct VapidSignature {
    token: String,
    public_key: ES256PublicKey,
}

impl VapidSignature {
    /// Creates and signs a new [`VapidSignature`] which can be used
    /// as a HTTP header value.
    pub fn sign<T: ToString>(
        endpoint: &Uri,
        valid_duration: Duration,
        contact: T,
        key: &ES256KeyPair,
    ) -> Result<VapidSignature, jwt_simple::Error> {
        let claims = Claims::create(valid_duration.into())
            .with_audience(format!(
                "{}://{}",
                endpoint
                    .scheme_str()
                    .ok_or(jwt_simple::Error::msg("missing scheme in endpoint"))?,
                endpoint
                    .host()
                    .ok_or(jwt_simple::Error::msg("missing host in endpoint"))?
            ))
            .with_subject(contact);

        Ok(VapidSignature {
            token: key.sign(claims)?,
            public_key: key.public_key(),
        })
    }
}

impl Display for VapidSignature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let encoded_public =
            Base64UrlUnpadded::encode_string(&self.public_key.public_key().to_bytes_uncompressed());
        write!(f, "vapid t={}, k={}", self.token, encoded_public)
    }
}

impl From<VapidSignature> for http::HeaderValue {
    fn from(signature: VapidSignature) -> Self {
        Self::try_from(signature.to_string()).expect("given string is always a valid header value")
    }
}
