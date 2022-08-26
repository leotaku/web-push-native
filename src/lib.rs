#[cfg(test)]
mod tests;

use aes_gcm::{aead::consts::U12, AeadInPlace, Aes128Gcm, KeyInit, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;

#[derive(Debug)]
pub enum Error {
    KeyIdLengthInvalid,
    RecordLengthInvalid,
    AesGcm,
}

fn derive_key(salt: [u8; 16], ikm: [u8; 16]) -> aes_gcm::Key<Aes128Gcm> {
    let info = b"Content-Encoding: aes128gcm\0";
    let mut okm = [0u8; 16];
    let hk = Hkdf::<Sha256>::new(Some(&salt), &ikm);
    hk.expand(info, &mut okm)
        .expect("okm length is always 16, impossile for it to be too large");

    aes_gcm::Key::<Aes128Gcm>::from(okm)
}

fn derive_nonce(salt: [u8; 16], ikm: [u8; 16], seq: [u8; 12]) -> Nonce<U12> {
    let info = b"Content-Encoding: nonce\0";
    let mut okm = [0u8; 12];
    let hk = Hkdf::<Sha256>::new(Some(salt.as_ref()), ikm.as_ref());
    hk.expand(info, &mut okm)
        .expect("okm length is always 12, impossile for it to be too large");

    for i in 0..12 {
        okm[i] ^= seq[i]
    }

    Nonce::from(okm)
}

fn generate_encryption_header<KI: AsRef<[u8]>>(
    salt: [u8; 16],
    record_size: u32,
    keyid: KI,
) -> Result<Vec<u8>, Error> {
    let mut header = Vec::new();
    header.extend(&salt[..]);
    header.extend_from_slice(&record_size.to_be_bytes());
    let keyid = keyid.as_ref();
    header.push(
        keyid
            .len()
            .try_into()
            .map_err(|_| Error::KeyIdLengthInvalid)?,
    );
    header.extend_from_slice(keyid);

    Ok(header)
}

fn encrypt_record<B: aes_gcm::aead::Buffer>(
    key: &aes_gcm::Key<Aes128Gcm>,
    nonce: &Nonce<U12>,
    mut record: B,
    encrypted_record_size: u32,
    is_last: bool,
) -> Result<B, Error> {
    let plain_record_size: u32 = record
        .len()
        .try_into()
        .map_err(|_| Error::RecordLengthInvalid)?;

    if !(plain_record_size <= encrypted_record_size - 16) {
        return Err(Error::RecordLengthInvalid);
    }

    if is_last {
        record
            .extend_from_slice(b"\x02")
            .map_err(|_| Error::AesGcm)?;
    } else {
        let pad_len = encrypted_record_size - plain_record_size - 16;
        record
            .extend_from_slice(b"\x01")
            .map_err(|_| Error::AesGcm)?;
        record
            .extend_from_slice(&b"\x00".repeat((pad_len - 1).try_into().unwrap())[..])
            .map_err(|_| Error::AesGcm)?;
    }

    Aes128Gcm::new(key)
        .encrypt_in_place(nonce, b"", &mut record)
        .map_err(|_| Error::AesGcm)?;

    Ok(record)
}

fn encrypt<R: Iterator<Item = Vec<u8>>, KI: AsRef<[u8]>>(
    ikm: [u8; 16],
    salt: [u8; 16],
    keyid: KI,
    records: R,
    encrypted_record_size: u32,
) -> Result<Vec<u8>, Error> {
    let header = generate_encryption_header(salt, encrypted_record_size, keyid.as_ref())?;

    let records = records.enumerate().map(|(n, record)| {
        let mut seq = [0u8; 12];
        seq[4..].copy_from_slice(&n.to_be_bytes());
        let key = derive_key(salt, ikm);
        let nonce = derive_nonce(salt, ikm, seq);
        (key, nonce, record)
    });

    let mut output = Vec::new();
    output.extend(header);

    let mut peekable = records.peekable();
    while let Some((key, nonce, record)) = peekable.next() {
        let is_last_record = peekable.peek().is_none();
        let record = encrypt_record(&key, &nonce, record, encrypted_record_size, is_last_record)?;
        output.extend(record);
    }

    Ok(output)
}
