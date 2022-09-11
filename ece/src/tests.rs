use super::*;
use base64;
use once_cell::sync::Lazy;

macro_rules! DECODE {
    ($e:expr) => {
        Lazy::new(|| {
            let decoded = base64::decode_config($e, base64::URL_SAFE_NO_PAD).unwrap();
            decoded.try_into().unwrap()
        })
    };
}

mod rfc8188_example1 {
    use super::*;

    pub(crate) const PLAINTEXT: &[u8] = b"I am the walrus";
    const RS: u32 = 4096;
    const IKM: Lazy<[u8; 16]> = DECODE!("yqdlZ-tYemfogSmv7Ws5PQ");
    const KEYID: &[u8] = "".as_bytes();

    const ENCRYPTED: Lazy<[u8; 53]> =
        DECODE!("I1BsxtFttlv3u_Oo94xnmwAAEAAA-NAVub2qFgBEuQKRapoZu-IxkIva3MEB1PD-ly8Thjg");

    const SALT: Lazy<[u8; 16]> = DECODE!("I1BsxtFttlv3u_Oo94xnmw");
    const PRK: Lazy<[u8; 32]> = DECODE!("zyeH5phsIsgUyd4oiSEIy35x-gIi4aM7y0hCF8mwn9g");
    const CEK: Lazy<[u8; 16]> = DECODE!("_wniytB-ofscZDh4tbSjHw");
    const NONCE: Lazy<[u8; 12]> = DECODE!("Bcs8gkIRKLI8GeI8");

    #[test]
    fn test_prk_generation() {
        let (prk, _) = Hkdf::<Sha256>::extract(Some(&*SALT), &*IKM);
        assert_eq!(prk.as_slice().len(), PRK.len());
        assert_eq!(prk.as_slice(), *PRK);
    }

    #[test]
    fn test_key_derivation() {
        assert_eq!(
            &derive_key(*SALT, *IKM),
            aes_gcm::Key::<Aes128Gcm>::from_slice(&*CEK)
        );
    }

    #[test]
    fn test_nonce_derivation() {
        let seq = [0u8; 12];
        assert_eq!(derive_nonce(*SALT, *IKM, seq), Nonce::from(*NONCE));
    }

    #[test]
    fn test_header_generation() {
        let header = generate_encryption_header(*SALT, 0, "").unwrap();
        assert_eq!(header.len(), 21)
    }

    #[test]
    fn test_encryption() {
        let encrypted =
            encrypt(*IKM, *SALT, KEYID, Some(PLAINTEXT.to_vec()).into_iter(), RS).unwrap();

        assert_eq!(encrypted.len(), ENCRYPTED.len());
        assert_eq!(encrypted[..16], ENCRYPTED[..16]);
        assert_eq!(
            u32::from_be_bytes(ENCRYPTED[16..16 + 4].try_into().unwrap()),
            u32::from_be_bytes(encrypted[16..16 + 4].try_into().unwrap())
        );
        assert_eq!(encrypted[21..], ENCRYPTED[21..]);
        assert_eq!(encrypted, &ENCRYPTED[..]);
    }
}

mod rfc8188_example2 {
    use super::*;

    use super::rfc8188_example1::PLAINTEXT;
    const RS: u32 = 25;
    const IKM: Lazy<[u8; 16]> = DECODE!("BO3ZVPxUlnLORbVGMpbT1Q");
    const KEYID: &[u8] = "a1".as_bytes();

    const SALT: Lazy<[u8; 16]> = Lazy::new(|| ENCRYPTED[0..16].try_into().unwrap());
    const ENCRYPTED: Lazy<[u8; 73]> = DECODE!("uNCkWiNYzKTnBN9ji3-qWAAAABkCYTHOG8chz_gnvgOqdGYovxyjuqRyJFjEDyoF1Fvkj6hQPdPHI51OEUKEpgz3SsLWIqS_uA");

    #[test]
    fn test_encryption() {
        let encrypted = encrypt(
            *IKM,
            *SALT,
            &*KEYID,
            vec![PLAINTEXT[..7].to_vec(), PLAINTEXT[7..7 + 8].to_vec()].into_iter(),
            RS,
        )
        .unwrap();

        assert_eq!(encrypted.len(), ENCRYPTED.len());
        assert_eq!(encrypted[..16], ENCRYPTED[..16]);
        assert_eq!(
            u32::from_be_bytes(ENCRYPTED[16..16 + 4].try_into().unwrap()),
            u32::from_be_bytes(encrypted[16..16 + 4].try_into().unwrap())
        );
        assert_eq!(encrypted[21..], ENCRYPTED[21..]);
        assert_eq!(encrypted, &ENCRYPTED[..]);
    }
}
