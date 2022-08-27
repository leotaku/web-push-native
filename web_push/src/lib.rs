use aes_gcm::aead::{rand_core::RngCore, OsRng};
use ece_native;
use hkdf::Hkdf;
use http::{self, header, Request, Uri};
use jwt_simple::prelude::*;
use p256::{ecdh::EphemeralSecret, elliptic_curve::sec1::ToEncodedPoint};
use sha2::Sha256;

pub type WebPushError = Box<dyn std::error::Error>;

pub type P256PublicKey = p256::PublicKey;

pub type ES256KeyPair = jwt_simple::algorithms::ES256KeyPair;

#[derive(Clone, Debug)]
pub struct WebPushBuilder {
    uri: Uri,
    ua_public: P256PublicKey,
    vapid_sign: VapidSignature,
}

impl WebPushBuilder {
    pub fn new<'a>(
        uri: Uri,
        vapid_kp: ES256KeyPair,
        ua_public: P256PublicKey,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let vapid_sign = vapid_sign(&uri, vapid_kp)?;
        Ok(Self {
            uri,
            vapid_sign,
            ua_public,
        })
    }

    pub fn build<T: Into<Vec<u8>>>(
        &self,
        body: T,
    ) -> Result<http::request::Request<Vec<u8>>, WebPushError> {
        let payload = encrypt(body.into(), &self.ua_public).map_err(|_| ":(")?;
        let request = Request::builder()
            .uri(self.uri.clone())
            .method(http::method::Method::POST)
            .header(header::AUTHORIZATION, self.vapid_sign.clone())
            .header("TTL", Duration::from_hours(12).as_secs())
            .header(header::CONTENT_ENCODING, "aes128gcm")
            .header(header::CONTENT_TYPE, "application/octet-stream")
            .header(header::CONTENT_LENGTH, payload.len())
            .body(payload)?;

        Ok(request)
    }
}

pub fn encrypt(
    plaintext: Vec<u8>,
    ua_public: &P256PublicKey,
) -> Result<Vec<u8>, ece_native::Error> {
    let as_ephemeral = EphemeralSecret::random(&mut OsRng);
    let as_public = as_ephemeral.public_key();
    let shared = as_ephemeral.diffie_hellman(ua_public);
    let mut salt = [0u8; 16];
    RngCore::fill_bytes(&mut OsRng, &mut salt[..]);

    let ikm = compute_ikm(salt, &shared, ua_public, &as_public);
    let keyid = as_public.as_affine().to_encoded_point(false);
    let encrypted_record_length = (plaintext.len() + 16)
        .try_into()
        .map_err(|_| ece_native::Error::RecordLengthInvalid)?;

    ece_native::encrypt(
        ikm,
        salt,
        keyid,
        Some(plaintext).into_iter(),
        encrypted_record_length,
    )
}

fn compute_ikm(
    salt: [u8; 16],
    shared: &p256::ecdh::SharedSecret,
    ua_public: &p256::PublicKey,
    as_public: &p256::PublicKey,
) -> [u8; 16] {
    let mut info = Vec::new();
    info.extend_from_slice(&b"WebPush: info"[..]);
    info.push(0u8);
    info.extend_from_slice(ua_public.as_affine().to_encoded_point(false).as_bytes());
    info.extend_from_slice(as_public.as_affine().to_encoded_point(false).as_bytes());

    let mut ikm = [0u8; 16];
    let hk = Hkdf::<Sha256>::new(Some(&salt), shared.as_bytes());
    hk.expand(&info, &mut ikm)
        .expect("okm length is always 16 bytes, cannot be too large");

    ikm
}

#[derive(Clone, Debug)]
pub struct VapidSignature {
    token: String,
    public_key: ES256PublicKey,
}

impl From<VapidSignature> for http::HeaderValue {
    fn from(signature: VapidSignature) -> Self {
        let encoded_public = base64::encode_config(
            signature.public_key.public_key().to_bytes_uncompressed(),
            base64::URL_SAFE_NO_PAD,
        );
        let value = format!("vapid t={}, k={}", signature.token, encoded_public);
        Self::try_from(value).unwrap()
    }
}

fn vapid_sign(endpoint: &Uri, key: ES256KeyPair) -> Result<VapidSignature, jwt_simple::Error> {
    let claims = Claims::create(Duration::from_hours(12))
        .with_audience(format!(
            "{}://{}",
            endpoint.scheme_str().unwrap(),
            endpoint.host().unwrap()
        ))
        .with_subject("mailto:nobody@example.com");

    let token = key.sign(claims)?;
    let key = key.public_key();
    Ok(VapidSignature {
        token,
        public_key: key,
    })
}
