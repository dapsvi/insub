use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce, aead::Aead};
use rand_core::{RngCore, OsRng};

// encrypt the bytes using the shared secret
pub fn encrypt(bytes: &[u8], key: &[u8; 32]) -> Result<(Vec<u8>, [u8; 12]), String> {
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from(nonce_bytes);

    let cipher = ChaCha20Poly1305::new(key.into());

    let encrypted_bytes = cipher.encrypt(&nonce, bytes)
        .map_err(|_| "encryption failed")?;

    Ok((encrypted_bytes, nonce_bytes))
}

// decrypt the bytes using the shared secret and the nonce
pub fn decrypt(cipher_bytes: &[u8], nonce_bytes: &[u8; 12], key: &[u8; 32]) -> Result<Vec<u8>, String> {
    let nonce = Nonce::from(*nonce_bytes);

    let cipher = ChaCha20Poly1305::new(key.into());

    let decrypted_bytes = cipher.decrypt(&nonce, cipher_bytes)
        .map_err(|_| "decryption failed: wrong key, wrong nonce, or corrupted/tampered data")?;

    Ok(decrypted_bytes)
}