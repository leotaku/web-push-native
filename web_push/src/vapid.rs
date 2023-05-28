use super::{AddHeaders, WebPushBuilder};
use base64ct::{Base64UrlUnpadded, Encoding};
use http::{header, Uri};
use jwt_simple::{
    algorithms::{ECDSAP256KeyPairLike, ECDSAP256PublicKeyLike, ES256KeyPair, ES256PublicKey},
    claims::Claims,
};
use std::time::Duration;

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
struct VapidSignature {
    token: String,
    public_key: ES256PublicKey,
}

impl VapidSignature {
    /// Creates and signs a new [`VapidSignature`] which can be used
    /// as a HTTP header value.
    fn sign<T: ToString>(
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

impl From<VapidSignature> for http::HeaderValue {
    fn from(signature: VapidSignature) -> Self {
        let encoded_public = Base64UrlUnpadded::encode_string(
            &signature.public_key.public_key().to_bytes_uncompressed(),
        );
        let value = format!("vapid t={}, k={}", signature.token, encoded_public);
        Self::try_from(value).unwrap()
    }
}
