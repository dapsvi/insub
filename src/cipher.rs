use sha2::Sha256;
use hkdf::Hkdf;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce, aead::Aead};
use rand_core::{RngCore, OsRng};

fn compute_cipher(shared_secret: &[u8], salt: Option<&[u8]>) -> Result<ChaCha20Poly1305, &'static str> {
    let hk = Hkdf::<Sha256>::new(salt, shared_secret);
    let mut key = [0u8; 32];
    hk.expand(b"encryption-key", &mut key)
        .map_err(|_| "HKDF expand failed")?;
    let cipher = ChaCha20Poly1305::new(&key.into());
    Ok(cipher)
}

pub fn encrypt(plaintext: &str, shared_secret: &[u8]) -> Result<(Vec<u8>, [u8; 12]), &'static str> {
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from(nonce_bytes);

    let cipher = compute_cipher(shared_secret, Some(b"cipher-salt"))?;

    let ciphertext = cipher.encrypt(&nonce, plaintext.as_bytes())
        .map_err(|_| "encryption failed")?;

    Ok((ciphertext, nonce_bytes))
}

pub fn decrypt(ciphertext: &[u8], nonce_bytes: &[u8; 12], shared_secret: &[u8]) -> Result<String, &'static str> {
    let nonce = Nonce::from(*nonce_bytes);

    let cipher = compute_cipher(shared_secret, Some(b"cipher-salt"))?;

    let plaintext_bytes = cipher.decrypt(&nonce, ciphertext)
        .map_err(|_| "decryption failed: wrong key, wrong nonce, or corrupted/tampered data")?;

    String::from_utf8(plaintext_bytes)
        .map_err(|_| "decrypted data is not valid UTF-8")
}