use x25519_dalek::{PublicKey, StaticSecret};

use crate::crypto::{cipher, hkdf::derive_key};

pub struct Chain {
    pub key: [u8; 32]
}

impl Chain {
    pub fn advance(&mut self) -> Result<[u8; 32], String> {
        let message_key = derive_key(&self.key, None, b"message-key")?;
        self.key = derive_key(&self.key, None, b"chain-key")?;

        Ok(message_key)
    }
}

pub struct DoubleRatchet {
    root_key: [u8; 32],
    sending_chain: Chain,
    receiving_chain: Chain,
    our_dh_priv: [u8; 32],
    their_dh_pub: [u8; 32],
}

impl DoubleRatchet {
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<(Vec<u8>, [u8; 12], [u8; 32]), String> {
        let message_key = self.sending_chain.advance()?;

        let (ciphertext, nonce) = cipher::encrypt(plaintext, &message_key)?;

        let secret = StaticSecret::from(self.our_dh_priv);
        let our_dh_pub = *PublicKey::from(&secret).as_bytes();

        Ok((ciphertext, nonce, our_dh_pub))
    }

    pub fn decrypt(&mut self, their_dh_pub: [u8; 32], nonce: &[u8; 12], ciphertext: &[u8]) -> Result<Vec<u8>, String> {
        let is_new_key = self.their_dh_pub != their_dh_pub;

        if is_new_key {
            self.dh_ratchet_step(their_dh_pub);
        }

        let message_key = self.receiving_chain.advance()?;

        cipher::decrypt(ciphertext, nonce, &message_key)
    }

    fn dh_ratchet_step(&mut self, their_new_dh_pub: [u8; 32]) {
        let their_pubkey = PublicKey::from(their_new_dh_pub);

        let our_old_secret = StaticSecret::from(self.our_dh_priv);
        let shared_secret_1 = our_old_secret.diffie_hellman(&their_pubkey);

        let new_root_key = derive_key(
            shared_secret_1.as_bytes(),
            Some(&self.root_key),
            b"root-key"
        ).unwrap();

        let new_receiving_chain_key = derive_key(
            shared_secret_1.as_bytes(),
            Some(&self.root_key),
            b"receiving-chain-key"
        ).unwrap();

        let our_new_secret = StaticSecret::random();
        // let _our_new_pub = PublicKey::from(&our_new_secret);     // not used

        let shared_secret_2 = our_new_secret.diffie_hellman(&their_pubkey);

        let final_root_key = derive_key(
            shared_secret_2.as_bytes(),
            Some(&new_root_key),
            b"root-key",
        ).unwrap();

        let new_sending_chain_key = derive_key(
            shared_secret_2.as_bytes(),
            Some(&new_root_key),
            b"sending-chain-key",
        ).unwrap();

        self.root_key = final_root_key;
        self.receiving_chain = Chain { key: new_receiving_chain_key };
        self.sending_chain = Chain { key: new_sending_chain_key };
        self.our_dh_priv = *our_new_secret.as_bytes();
        self.their_dh_pub = their_new_dh_pub;
    }

    pub fn new(shared_secret: [u8; 32], our_dh_priv: [u8; 32], their_dh_pub: [u8; 32]) -> Self {
        // both chains start identical so the first message in either direction decrypts correctly regardless of who sends first
        let initial_chain_key = derive_key(&shared_secret, None, b"init-chain").unwrap();

        DoubleRatchet {
            root_key: shared_secret,
            sending_chain: Chain { key: initial_chain_key },
            receiving_chain: Chain { key: initial_chain_key },
            our_dh_priv,
            their_dh_pub,
        }
    }
}