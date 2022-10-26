use super::*;
use base64;
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use std::time::Duration;

#[derive(Serialize, Deserialize)]
#[serde(rename = "WebPushBuilder", rename_all = "camelCase")]
struct WebPushSerde {
    #[serde(serialize_with = "url_to_string", deserialize_with = "string_to_url")]
    endpoint: Uri,
    expiration_time: (),
    keys: Keys,
}

#[derive(Serialize, Deserialize)]
struct Keys {
    #[serde(serialize_with = "auth_to_bytes", deserialize_with = "bytes_to_auth")]
    auth: Auth,
    #[serde(serialize_with = "p256_to_bytes", deserialize_with = "bytes_to_p256")]
    p256dh: p256::PublicKey,
}

fn url_to_string<S: Serializer>(url: &Uri, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&url.to_string())
}

fn string_to_url<'de, D: Deserializer<'de>>(d: D) -> Result<Uri, D::Error> {
    let s: &str = Deserialize::deserialize(d)?;
    s.parse().map_err(de::Error::custom)
}

fn auth_to_bytes<S: Serializer>(auth: &Auth, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&base64::encode_config(auth.as_slice(), base64::URL_SAFE))
}

fn bytes_to_auth<'de, D: Deserializer<'de>>(d: D) -> Result<Auth, D::Error> {
    let b64: &str = Deserialize::deserialize(d)?;
    Ok(Auth::clone_from_slice(
        &base64::decode_config(b64, base64::URL_SAFE).map_err(de::Error::custom)?,
    ))
}

fn p256_to_bytes<S: Serializer>(auth: &p256::PublicKey, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&base64::encode_config(
        auth.to_encoded_point(false).as_bytes(),
        base64::URL_SAFE,
    ))
}

fn bytes_to_p256<'de, D: Deserializer<'de>>(d: D) -> Result<p256::PublicKey, D::Error> {
    let b64: &str = Deserialize::deserialize(d)?;
    p256::PublicKey::from_sec1_bytes(
        &base64::decode_config(b64, base64::URL_SAFE).map_err(de::Error::custom)?,
    )
    .map_err(de::Error::custom)
}

impl Serialize for WebPushBuilder {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        WebPushSerde {
            endpoint: self.endpoint.clone(),
            expiration_time: (),
            keys: Keys {
                auth: self.ua_auth,
                p256dh: self.ua_public,
            },
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for WebPushBuilder {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let serde = WebPushSerde::deserialize(deserializer)?;
        Ok(WebPushBuilder {
            endpoint: serde.endpoint,
            valid_duration: Duration::from_secs(12 * 60 * 60),
            ua_public: serde.keys.p256dh,
            ua_auth: serde.keys.auth,
            http_auth: (),
        })
    }
}
