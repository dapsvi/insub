use argon2::{Argon2, Algorithm, Version, Params};
use rand_core::{RngCore, OsRng};
use zeroize::Zeroize;

use crate::crypto::cipher;

// encrypt plaintext with a password (low-entropy secret) using Argon2id + ChaCha20-Poly1305
pub fn encrypt_with_password(plaintext: &[u8], password: &[u8]) -> Result<Vec<u8>, String> {
    // generate random salt for Argon2id
    let mut salt = [0u8; 32];
    OsRng.fill_bytes(&mut salt);

    // derive a 32-byte key from the password using Argon2id
    let mut key = derive_key(password, &salt).map_err(|e| format!("argon2id key derivation failed: {e}"))?;

    // encrypt with ChaCha20-Poly1305
    let (ciphertext, nonce) = cipher::encrypt(plaintext, &key)?;

    key.zeroize();

    // format: salt || nonce || ciphertext
    let mut output = Vec::with_capacity(32 + 12 + ciphertext.len());
    output.extend_from_slice(&salt);
    output.extend_from_slice(&nonce);
    output.extend_from_slice(&ciphertext);
    Ok(output)
}

// decrypt bytes produced by encrypt_with_password
pub fn decrypt_with_password(encrypted: &[u8], password: &[u8]) -> Result<Vec<u8>, String> {
    // minimum length: salt (32) + nonce (12) = 44 bytes plus at least 16 for AEAD tag
    if encrypted.len() < 44 + 16 {
        return Err("encrypted data too short".to_string());
    }

    let salt: &[u8; 32] = encrypted[..32]
        .try_into()
        .map_err(|_| "failed to read salt")?;
    let nonce: &[u8; 12] = encrypted[32..44]
        .try_into()
        .map_err(|_| "failed to read nonce")?;
    let ciphertext = &encrypted[44..];

    // re-derive the same key from password + salt
    let mut key = derive_key(password, salt).map_err(|e| format!("argon2id key derivation failed: {e}"))?;

    // decrypt
    let plaintext = cipher::decrypt(ciphertext, nonce, &key)?;

    key.zeroize();
    Ok(plaintext)
}

// 64 MiB, 3 iterations, 4 lanes, 32-byte output
fn derive_key(password: &[u8], salt: &[u8; 32]) -> Result<[u8; 32], argon2::Error> {
    let argon2 = Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        Params::new(65_536, 3, 4, Some(32))
            .expect("valid argon2id parameters"),
    );

    let mut key = [0u8; 32];
    argon2.hash_password_into(password, salt, &mut key)?;
    Ok(key)
}
