use sha2::Sha256;
use hkdf::Hkdf;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce, aead::Aead};
use rand_core::{RngCore, OsRng};

// helper function that returns a cipher for encrypting and decrypting based on a pre-computed shared secret
fn compute_cipher(shared_secret: &[u8], salt: Option<&[u8]>) -> Result<ChaCha20Poly1305, &'static str> {
    let hk = Hkdf::<Sha256>::new(salt, shared_secret);
    let mut key = [0u8; 32];
    hk.expand(b"encryption-key", &mut key)
        .map_err(|_| "HKDF expand failed")?;
    let cipher = ChaCha20Poly1305::new(&key.into());
    Ok(cipher)
}

// encrypt the bytes using the shared secret
pub fn encrypt(bytes: &[u8], shared_secret: &[u8]) -> Result<(Vec<u8>, [u8; 12]), &'static str> {
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from(nonce_bytes); // no idea why we need that but otherwise it's not secure -> to be reviewed

    let cipher = compute_cipher(shared_secret, Some(b"cipher-salt"))?;

    let ciphertext = cipher.encrypt(&nonce, bytes)
        .map_err(|_| "encryption failed")?;

    Ok((ciphertext, nonce_bytes))
}

// decrypt the bytes using the shared secret and the nonce
pub fn decrypt(cipher_bytes: &[u8], nonce_bytes: &[u8; 12], shared_secret: &[u8]) -> Result<Vec<u8>, &'static str> {
    let nonce = Nonce::from(*nonce_bytes);

    let cipher = compute_cipher(shared_secret, Some(b"cipher-salt"))?;

    let decrypted_bytes = cipher.decrypt(&nonce, cipher_bytes)
        .map_err(|_| "decryption failed: wrong key, wrong nonce, or corrupted/tampered data")?;

    Ok(decrypted_bytes)
}