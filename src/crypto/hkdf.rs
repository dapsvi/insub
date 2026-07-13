use sha2::Sha256;
use hkdf::Hkdf;

pub fn derive_key(shared_secret: &[u8], salt: Option<&[u8]>) -> Result<[u8; 32], &'static str> {
    let hk = Hkdf::<Sha256>::new(salt, shared_secret);
    let mut key = [0u8; 32];
    hk.expand(b"encryption-key", &mut key)
        .map_err(|_| "HKDF expand failed")?;

    Ok(key)
}