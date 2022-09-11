pub use jwt_simple;
pub use p256;

use aes_gcm::aead::{
    generic_array::{typenum::U16, GenericArray},
    rand_core::RngCore,
    OsRng,
};
use hkdf::Hkdf;
use http::{self, header, Request, Uri};
use jwt_simple::{
    algorithms::{ECDSAP256KeyPairLike, ECDSAP256PublicKeyLike, ES256KeyPair, ES256PublicKey},
    claims::Claims,
    prelude::Duration,
};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use sha2::Sha256;

pub type WebPushError = Box<dyn std::error::Error>;

pub type Auth = GenericArray<u8, U16>;

#[derive(Clone, Debug)]
pub struct WebPushBuilder {
    uri: Uri,
    ua_public: p256::PublicKey,
    ua_auth: Auth,
    vapid_sign: VapidSignature,
}

impl WebPushBuilder {
    pub fn new<'a>(
        uri: Uri,
        vapid_kp: ES256KeyPair,
        ua_public: p256::PublicKey,
        ua_auth: Auth,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let vapid_sign = vapid_sign(&uri, vapid_kp)?;
        Ok(Self {
            uri,
            ua_public,
            ua_auth,
            vapid_sign,
        })
    }

    pub fn build<T: Into<Vec<u8>>>(
        &self,
        body: T,
    ) -> Result<http::request::Request<Vec<u8>>, WebPushError> {
        let body = body.into();

        let payload = encrypt(body, &self.ua_public, &self.ua_auth)?;
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
    ua_public: &p256::PublicKey,
    ua_auth: &Auth,
) -> Result<Vec<u8>, ece_native::Error> {
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);
    let as_secret = p256::SecretKey::random(&mut OsRng);
    encrypt_predictably(salt, plaintext, &as_secret, ua_public, ua_auth)
}

fn encrypt_predictably(
    salt: [u8; 16],
    plaintext: Vec<u8>,
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
    let encrypted_record_length = (plaintext.len() + 17)
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

pub fn decrypt(
    ciphertext: Vec<u8>,
    as_secret: &p256::SecretKey,
    ua_auth: &Auth,
) -> Result<Vec<u8>, ece_native::Error> {
    let idlen = ciphertext[20];
    let keyid = &ciphertext[21..21 + (idlen as usize)];

    let ua_public =
        p256::PublicKey::from_sec1_bytes(keyid).map_err(|_| ece_native::Error::AesGcm)?;
    let shared = p256::ecdh::diffie_hellman(as_secret.to_nonzero_scalar(), ua_public.as_affine());

    let ikm = compute_ikm(
        ua_auth.as_slice().try_into().unwrap(),
        &shared,
        &as_secret.public_key(),
        &ua_public,
    );

    ece_native::decrypt(ikm, ciphertext)
}

fn compute_ikm(
    salt: [u8; 16],
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
    let hk = Hkdf::<Sha256>::new(Some(&salt), shared.raw_secret_bytes().as_ref());
    hk.expand(&info, &mut okm)
        .expect("okm length is always 32 bytes, cannot be too large");

    okm
}

#[derive(Clone, Debug)]
struct VapidSignature {
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
