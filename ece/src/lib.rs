//! This crate implements ECE encryption according to rfc8188.

#[cfg(test)]
mod tests;

use aes_gcm::{
    aead::{consts::U12, generic_array::typenum::Unsigned, Tag},
    AeadInPlace, Aes128Gcm, KeyInit, Nonce,
};
use hkdf::Hkdf;
use sha2::Sha256;

/// Error modes for rfc8188 encryption and decryption
#[derive(Debug)]
pub enum Error {
    /// Header of the encrypted payload was too short
    HeaderLengthInvalid,
    /// The `keyid` parameter passed to the encryption routine was too large
    KeyIdLengthInvalid,
    /// One of the records passed to the encryption routine was too large
    RecordLengthInvalid,
    /// Padding of one the records in the encrypted message was malformed
    PaddingInvalid,
    /// Internal aes128gcm error
    Aes128Gcm,
}

impl std::error::Error for Error {}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
    }
}

fn derive_key<IKM: AsRef<[u8]>>(salt: [u8; 16], ikm: IKM) -> aes_gcm::Key<Aes128Gcm> {
    let info = b"Content-Encoding: aes128gcm\0";
    let mut okm = [0u8; 16];
    let hk = Hkdf::<Sha256>::new(Some(&salt), ikm.as_ref());
    hk.expand(info, &mut okm)
        .expect("okm length is always 16, impossile for it to be too large");

    aes_gcm::Key::<Aes128Gcm>::from(okm)
}

fn derive_nonce<IKM: AsRef<[u8]>>(salt: [u8; 16], ikm: IKM, seq: [u8; 12]) -> Nonce<U12> {
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
    header.extend_from_slice(&salt[..]);
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

    if !(plain_record_size < encrypted_record_size - 16) {
        return Err(Error::RecordLengthInvalid);
    }

    if is_last {
        record
            .extend_from_slice(b"\x02")
            .map_err(|_| Error::Aes128Gcm)?;
    } else {
        let pad_len = encrypted_record_size - plain_record_size - 16;
        record
            .extend_from_slice(b"\x01")
            .map_err(|_| Error::Aes128Gcm)?;
        record
            .extend_from_slice(&b"\x00".repeat((pad_len - 1).try_into().unwrap())[..])
            .map_err(|_| Error::Aes128Gcm)?;
    }

    Aes128Gcm::new(key)
        .encrypt_in_place(nonce, b"", &mut record)
        .map_err(|_| Error::Aes128Gcm)?;

    Ok(record)
}

/// Low-level rfc8188 ece encryption routine
pub fn encrypt<IKM: AsRef<[u8]>, KI: AsRef<[u8]>, R: Iterator<Item = Vec<u8>>>(
    ikm: IKM,
    salt: [u8; 16],
    keyid: KI,
    records: R,
    encrypted_record_size: u32,
) -> Result<Vec<u8>, Error> {
    let header = generate_encryption_header(salt, encrypted_record_size, keyid.as_ref())?;

    let records = records.enumerate().map(|(n, record)| {
        let mut seq = [0u8; 12];
        seq[4..].copy_from_slice(&n.to_be_bytes());
        let key = derive_key(salt, ikm.as_ref());
        let nonce = derive_nonce(salt, ikm.as_ref(), seq);
        (key, nonce, record)
    });

    let mut output = Vec::new();
    output.extend_from_slice(&header);

    let mut peekable = records.peekable();
    while let Some((key, nonce, record)) = peekable.next() {
        let is_last_record = peekable.peek().is_none();
        let record = encrypt_record(&key, &nonce, record, encrypted_record_size, is_last_record)?;
        output.extend_from_slice(&record);
    }

    Ok(output)
}

fn decrypt_record<'a>(
    key: &aes_gcm::Key<Aes128Gcm>,
    nonce: &Nonce<U12>,
    record: &'a mut [u8],
    is_last: bool,
) -> Result<&'a [u8], Error> {
    if record.len() < <Aes128Gcm as aes_gcm::AeadCore>::TagSize::to_usize() {
        return Err(Error::RecordLengthInvalid);
    }
    let tag_pos = record.len() - <Aes128Gcm as aes_gcm::AeadCore>::TagSize::to_usize();
    let (msg, tag) = record.as_mut().split_at_mut(tag_pos);

    Aes128Gcm::new(&key)
        .decrypt_in_place_detached(&nonce, b"", msg, Tag::<Aes128Gcm>::from_slice(tag))
        .map_err(|_| Error::Aes128Gcm)?;

    let pad_index = msg
        .as_ref()
        .iter()
        .rposition(|it| *it != 0)
        .ok_or_else(|| Error::PaddingInvalid)?;
    match msg.as_ref()[pad_index] {
        2 if !is_last => Err(Error::PaddingInvalid),
        1 if is_last => Err(Error::PaddingInvalid),
        _ => Ok(&msg[..pad_index]),
    }
}

/// Low-level rfc8188 ece decryption routine
pub fn decrypt<IKM: AsRef<[u8]>>(
    ikm: IKM,
    mut encrypted_message: Vec<u8>,
) -> Result<Vec<u8>, Error> {
    if encrypted_message.len() < 21 {
        return Err(Error::HeaderLengthInvalid);
    }

    let (header, keyid_and_records) = encrypted_message.split_at_mut(21);
    let salt = header[..16].try_into().unwrap();
    let encrypted_record_size = u32::from_be_bytes(header[16..16 + 4].try_into().unwrap());
    let idlen = header[20] as usize;

    if keyid_and_records.len() < idlen {
        return Err(Error::KeyIdLengthInvalid);
    }

    let (_, records) = keyid_and_records.split_at_mut(idlen);
    let records = records
        .chunks_mut(
            encrypted_record_size
                .try_into()
                .map_err(|_| Error::RecordLengthInvalid)?,
        )
        .enumerate()
        .map(|(n, record)| {
            let mut seq = [0u8; 12];
            seq[4..].copy_from_slice(&n.to_be_bytes());
            let nonce = derive_nonce(salt, ikm.as_ref(), seq);
            let key = derive_key(salt, ikm.as_ref());
            (key, nonce, record)
        });

    let mut output = Vec::new();

    let mut peekable = records.peekable();
    while let Some((key, nonce, record)) = peekable.next() {
        let is_last_record = peekable.peek().is_none();
        let plaintext = decrypt_record(&key, &nonce, record, is_last_record)?;
        output.extend_from_slice(plaintext)
    }

    Ok(output)
}
