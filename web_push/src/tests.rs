use super::*;

macro_rules! DECODE {
    ($e:expr) => {
        Lazy::new(|| {
            let decoded = base64::decode_config($e, base64::URL_SAFE_NO_PAD).unwrap();
            decoded.try_into().unwrap()
        })
    };
    ($extract:expr, $e:expr) => {
        Lazy::new(|| {
            let decoded = base64::decode_config($e, base64::URL_SAFE_NO_PAD).unwrap();
            Some($extract(&decoded).ok()).flatten().unwrap()
        })
    };
}

#[test]
fn test_encrypt_decrypt() {
    let vapid_pair = jwt_simple::algorithms::ES256KeyPair::generate();
    let ece_secret = p256::SecretKey::random(&mut OsRng);
    let mut auth = vec![0u8; 16];
    OsRng.fill_bytes(&mut auth);
    let auth = GenericArray::clone_from_slice(&auth);

    let builder = WebPushBuilder::new(
        "https://example.com/".parse().unwrap(),
        ece_secret.public_key(),
        auth,
    )
    .with_vapid(&vapid_pair, "mailto:nobody@example.com");

    let plaintext = b"I am the walrus".to_vec();
    let ciphertext = builder.build(plaintext.clone()).unwrap().into_body();
    let decrypted = decrypt(ciphertext, &ece_secret, &auth).unwrap();
    assert_eq!(decrypted, plaintext);
}

mod rfc8291_example {
    use super::*;
    use once_cell::sync::Lazy;

    const PLAINTEXT: &[u8] = b"When I grow up, I want to be a watermelon";
    const CIPHERTEXT: Lazy<Vec<u8>> = DECODE!("DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A_yl95bQpu6cVPTpK4Mqgkf1CXztLVBSt2Ks3oZwbuwXPXLWyouBWLVWGNWQexSgSxsj_Qulcy4a-fN");
    const AUTH: Lazy<Auth> = DECODE!(
        |it| Ok::<_, ()>(Auth::clone_from_slice(it)),
        "BTBZMqHH6r4Tts7J_aSIgg"
    );
    const UA_PRIVATE: Lazy<p256::SecretKey> = DECODE!(
        p256::SecretKey::from_be_bytes,
        "q1dXpw3UpT5VOmu_cf_v6ih07Aems3njxI-JWgLcM94"
    );
    const UA_PUBLIC: Lazy<p256::PublicKey> = DECODE!(
        p256::PublicKey::from_sec1_bytes,
        "BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4"
    );
    const AS_PRIVATE: Lazy<p256::SecretKey> = DECODE!(
        p256::SecretKey::from_be_bytes,
        "yfWPiYE-n46HLnH0KqZOF1fJJU3MYrct3AELtAQ-oRw"
    );
    const AS_PUBLIC: Lazy<p256::PublicKey> = DECODE!(
        p256::PublicKey::from_sec1_bytes,
        "BP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A8"
    );
    const SALT: Lazy<[u8; 16]> = DECODE!("DGv6ra1nlYgDCS1FRnbzlw");

    const IKM: Lazy<[u8; 32]> = DECODE!("S4lYMb_L0FxCeq0WhDx813KgSYqU26kOyzWUdsXYyrg");
    const SHARED: Lazy<[u8; 32]> = DECODE!("kyrL1jIIOHEzg3sM2ZWRHDRB62YACZhhSlknJ672kSs");

    #[test]
    fn test_derive_ikm() {
        let shared =
            p256::ecdh::diffie_hellman(AS_PRIVATE.to_nonzero_scalar(), UA_PUBLIC.as_affine());
        assert_eq!(shared.raw_secret_bytes().as_slice(), &*SHARED);

        let ikm = compute_ikm(&AUTH, &shared, &UA_PUBLIC, &AS_PUBLIC);
        assert_eq!(ikm, *IKM);
    }

    #[test]
    fn test_encrypt() {
        let ciphertext =
            encrypt_predictably(*SALT, PLAINTEXT.to_vec(), &AS_PRIVATE, &UA_PUBLIC, &AUTH).unwrap();

        assert_eq!(&ciphertext[21..], &CIPHERTEXT[21..]);
    }

    #[test]
    fn test_encrypt_decrypt() {
        let ciphertext =
            encrypt_predictably(*SALT, PLAINTEXT.to_vec(), &AS_PRIVATE, &UA_PUBLIC, &AUTH).unwrap();

        let plaintext = decrypt(ciphertext, &UA_PRIVATE, &AUTH).unwrap();

        assert_eq!(plaintext, PLAINTEXT);
    }
}
