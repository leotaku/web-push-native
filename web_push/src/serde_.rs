use super::{Auth, WebPushBuilder};
use base64ct::{Base64UrlUnpadded, Encoding};
use http::Uri;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use std::{borrow::Cow, time::Duration};

#[derive(Serialize, Deserialize)]
#[serde(rename = "WebPushBuilder", rename_all = "camelCase")]
struct WebPushSerde<'a> {
    #[serde(serialize_with = "url_to_string", deserialize_with = "string_to_url")]
    endpoint: Cow<'a, Uri>,
    expiration_time: Option<Duration>,
    keys: Keys,
}

#[derive(Serialize, Deserialize)]
struct Keys {
    #[serde(serialize_with = "auth_to_bytes", deserialize_with = "bytes_to_auth")]
    auth: Auth,
    #[serde(serialize_with = "p256_to_bytes", deserialize_with = "bytes_to_p256")]
    p256dh: p256::PublicKey,
}

fn url_to_string<S: Serializer>(url: &Cow<Uri>, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&url.to_string())
}

fn string_to_url<'de, D: Deserializer<'de>>(d: D) -> Result<Cow<'static, Uri>, D::Error> {
    let s: &str = Deserialize::deserialize(d)?;
    s.parse().map(Cow::Owned).map_err(de::Error::custom)
}

fn auth_to_bytes<S: Serializer>(auth: &Auth, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&Base64UrlUnpadded::encode_string(auth.as_slice()))
}

fn bytes_to_auth<'de, D: Deserializer<'de>>(d: D) -> Result<Auth, D::Error> {
    let b64: &str = Deserialize::deserialize(d)?;
    Ok(Auth::clone_from_slice(
        &Base64UrlUnpadded::decode_vec(b64).map_err(de::Error::custom)?,
    ))
}

fn p256_to_bytes<S: Serializer>(auth: &p256::PublicKey, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&Base64UrlUnpadded::encode_string(
        auth.to_encoded_point(false).as_bytes(),
    ))
}

fn bytes_to_p256<'de, D: Deserializer<'de>>(d: D) -> Result<p256::PublicKey, D::Error> {
    let b64: &str = Deserialize::deserialize(d)?;
    p256::PublicKey::from_sec1_bytes(
        &Base64UrlUnpadded::decode_vec(b64).map_err(de::Error::custom)?,
    )
    .map_err(de::Error::custom)
}

impl Serialize for WebPushBuilder {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        WebPushSerde {
            endpoint: Cow::Borrowed(&self.endpoint),
            expiration_time: None,
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
            endpoint: serde.endpoint.into_owned(),
            valid_duration: Duration::from_secs(12 * 60 * 60),
            ua_public: serde.keys.p256dh,
            ua_auth: serde.keys.auth,
            http_auth: (),
        })
    }
}
