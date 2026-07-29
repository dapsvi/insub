use sha2::Sha256;
use hkdf::Hkdf;

// derive a key based on an initial secret and an optional salt/info
pub fn derive_key(shared_secret: &[u8], salt: Option<&[u8]>, info: &[u8]) -> Result<[u8; 32], &'static str> {
    let hk = Hkdf::<Sha256>::new(salt, shared_secret);
    let mut key = [0u8; 32];
    hk.expand(info, &mut key)
        .map_err(|_| "HKDF expand failed")?;

    Ok(key)
}