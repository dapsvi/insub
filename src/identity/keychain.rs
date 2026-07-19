use std::fs;
use std::path::Path;
use zeroize::Zeroize;
use bip39::{Mnemonic, Language};
use x25519_dalek::{PublicKey, StaticSecret};
use ed25519_dalek::SigningKey;

use crate::crypto::hkdf::derive_key;

pub struct Keychain {
    pub has_password: bool,
    pub device_ed25519_pub: [u8; 32],
    pub device_ed25519_priv: [u8; 32],
    pub device_x25519_pub: [u8; 32],
    pub device_x25519_priv: [u8; 32],
}

impl Keychain {
    pub fn from_mnemonic(mnemonic: &Mnemonic, password: Option<&str>) -> Self {
        let mut seed_64 = mnemonic.to_seed(password.unwrap_or(""));
        let mut seed_32 = derive_key(&seed_64, None, b"keychain-ed25519")
            .expect("HKDF key derivation failed");
        let ed25519_private_key = SigningKey::from_bytes(&seed_32);
        let ed25519_public_key = ed25519_private_key.verifying_key();
        seed_32.zeroize();

        let mut seed_32 = derive_key(&seed_64, None, b"keychain-x25519")
            .expect("HKDF key derivation failed");
        let x25519_private_key = StaticSecret::from(seed_32);
        let x25519_public_key = PublicKey::from(&x25519_private_key);

        seed_64.zeroize();
        seed_32.zeroize();
        Keychain {
            has_password: password.is_some(),
            device_ed25519_pub: ed25519_public_key.to_bytes(),
            device_ed25519_priv: ed25519_private_key.to_bytes(),
            device_x25519_pub: x25519_public_key.to_bytes(),
            device_x25519_priv: x25519_private_key.to_bytes(),
        }
    }

    pub fn serialize(&self, password: Option<&str>) -> Vec<u8> {
        let mut privkeys = Vec::with_capacity(64);
        privkeys.extend_from_slice(&self.device_ed25519_priv);
        privkeys.extend_from_slice(&self.device_x25519_priv);

        let mut output = Vec::new();
        output.push(password.is_some() as u8);

        if let Some(pw) = password {
            let encrypted = crate::crypto::argon::encrypt_with_password(&privkeys, pw.as_bytes())
                .expect("keychain encryption failed");
            output.extend_from_slice(&encrypted);
        } else {
            output.extend_from_slice(&privkeys);
        }

        output
    }

    pub fn new(path: &Path, password: Option<&str>) -> Result<(Self, Mnemonic), String> {
        let mnemonic = Mnemonic::generate_in(Language::English, 12)
            .map_err(|e| format!("failed to generate mnemonic: {e}"))?;
        let keychain = Self::from_mnemonic(&mnemonic, password);
        keychain.save(path, password)?;
        Ok((keychain, mnemonic))
    }

    pub fn save(&self, path: &Path, password: Option<&str>) -> Result<(), String> {
        let data = self.serialize(password);
        fs::write(path, &data).map_err(|e| format!("failed to write keychain: {e}"))
    }

    pub fn load(path: &Path, password: Option<&str>) -> Result<Self, String> {
        let data = fs::read(path).map_err(|e| format!("failed to read keychain: {e}"))?;
        Self::from_serialized(&data, password)
    }

    pub fn from_serialized(bytes: &[u8], password: Option<&str>) -> Result<Self, String> {
        if bytes.is_empty() {
            return Err("empty keychain data".to_string());
        }

        let has_password = bytes[0] != 0;
        let privkeys = if has_password {
            let pw = password.ok_or("keychain is encrypted but no password provided")?;
            crate::crypto::argon::decrypt_with_password(&bytes[1..], pw.as_bytes())?
        } else {
            if bytes.len() < 1 + 64 {
                return Err("truncated keychain data".to_string());
            }
            bytes[1..65].to_vec()
        };

        if privkeys.len() < 64 {
            return Err("invalid keychain data".to_string());
        }

        let device_ed25519_priv: [u8; 32] = privkeys[..32].try_into().unwrap();
        let device_x25519_priv: [u8; 32] = privkeys[32..64].try_into().unwrap();

        let ed25519_key = SigningKey::from_bytes(&device_ed25519_priv);
        let device_ed25519_pub = ed25519_key.verifying_key().to_bytes();

        let x25519_secret = StaticSecret::from(device_x25519_priv);
        let device_x25519_pub = PublicKey::from(&x25519_secret).to_bytes();

        Ok(Keychain {
            has_password,
            device_ed25519_pub,
            device_ed25519_priv,
            device_x25519_pub,
            device_x25519_priv,
        })
    }
}
