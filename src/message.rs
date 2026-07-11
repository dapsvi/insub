use std::ops::Not;

use x25519_dalek::PublicKey;
use ed25519_dalek::{Signature, VerifyingKey};
use crate::identity::{MasterKeyPair, UserID};
use crate::exchange::EphemeralExchangeKeyPair;
use crate::cipher;

// struct containing all the data that will be sent over the network to send a message
pub struct Message {
    pub sender_identity: VerifyingKey,
    pub exchange_key: PublicKey,
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
    pub signature: Signature,
}

impl Message {
    pub fn new(
        sender: &MasterKeyPair,
        sender_exchange: &mut EphemeralExchangeKeyPair,
        recipient_exchange_pubkey: &PublicKey,
        plaintext: &str,
    ) -> Result<Message, &'static str> {
        // 1. compute the shared secret
        sender_exchange.compute_shared_secret(recipient_exchange_pubkey)?;
        let shared_secret = sender_exchange
            .shared_secret
            .as_ref()
            .ok_or("shared secret missing after computation")?;

        // 2. encryption
        let (ciphertext, nonce) = cipher::encrypt(plaintext.as_bytes(), shared_secret.as_slice())?;

        // 3. sign ciphertext, nonce and exchange_key
        let mut signed_data = Vec::with_capacity(ciphertext.len() + nonce.len() + 32);
        signed_data.extend_from_slice(&ciphertext);
        signed_data.extend_from_slice(&nonce);
        signed_data.extend_from_slice(sender_exchange.public_key.as_bytes());

        let signature = sender.sign(&signed_data);

        Ok(Message {
            sender_identity: sender.public_key,
            exchange_key: sender_exchange.public_key,
            nonce,
            ciphertext,
            signature,
        })
    }

    pub fn open(
        &self,
        recipient_exchange: &mut EphemeralExchangeKeyPair,
        sender_identity: &UserID,
    ) -> Result<String, &'static str> {
        // 1. verify signature
        let mut signed_data = Vec::with_capacity(self.ciphertext.len() + self.nonce.len() + 32);
        signed_data.extend_from_slice(&self.ciphertext);
        signed_data.extend_from_slice(&self.nonce);
        signed_data.extend_from_slice(self.exchange_key.as_bytes());
        
        let is_signature_valid = sender_identity.verify(&signed_data, &self.signature);
        if !is_signature_valid {
            return Err("The signature does not match");
        }
        
        // 2. compute shared secret
        recipient_exchange.compute_shared_secret(&self.exchange_key)?;
        let shared_secret = recipient_exchange
            .shared_secret
            .as_ref()
            .ok_or("shared secret missing after computation")?;

        // 3. decryption
        let decrypted_bytes = cipher::decrypt(&self.ciphertext, &self.nonce, shared_secret.as_slice())?;
        let decrypted_text = String::from_utf8(decrypted_bytes)
            .map_err(|_| "decrypted data is not valid UTF-8")?;

        Ok(decrypted_text)
    }
}