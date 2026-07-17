use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::crypto::{cipher, hkdf::derive_key};

pub struct Chain {
    pub key: [u8; 32],
}

impl Chain {
    pub fn advance(&mut self) -> Result<[u8; 32], String> {
        let message_key = derive_key(&self.key, None, b"message-key")?;
        self.key = derive_key(&self.key, None, b"chain-key")?;
        Ok(message_key)
    }
}

fn kdf_rk(rk: [u8; 32], dh_out: [u8; 32]) -> ([u8; 32], [u8; 32]) {
    let mut output = [0u8; 64];
    Hkdf::<Sha256>::new(Some(&rk), &dh_out)
        .expand(b"WhisperRatchet", &mut output)
        .expect("HKDF expand failed");

    (
        output[..32].try_into().unwrap(),
        output[32..].try_into().unwrap(),
    )
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

    pub fn decrypt(
        &mut self,
        their_dh_pub: [u8; 32],
        nonce: &[u8; 12],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, String> {
        if self.their_dh_pub != their_dh_pub {
            self.dh_ratchet_step(their_dh_pub);
        }

        let message_key = self.receiving_chain.advance()?;
        cipher::decrypt(ciphertext, nonce, &message_key)
    }

    fn dh_ratchet_step(&mut self, their_new_dh_pub: [u8; 32]) {
        let their_pubkey = PublicKey::from(their_new_dh_pub);

        // receive side: our OLD key x their NEW key
        let our_old_secret = StaticSecret::from(self.our_dh_priv);
        let dh_recv = our_old_secret.diffie_hellman(&their_pubkey);
        let (root_after_recv, new_receiving_chain_key) = kdf_rk(self.root_key, *dh_recv.as_bytes());

        // send side: a FRESH key of ours x their (same) new key
        let our_new_secret = StaticSecret::random();
        let dh_send = our_new_secret.diffie_hellman(&their_pubkey);
        let (root_final, new_sending_chain_key) = kdf_rk(root_after_recv, *dh_send.as_bytes());

        self.root_key = root_final;
        self.receiving_chain = Chain { key: new_receiving_chain_key };
        self.sending_chain = Chain { key: new_sending_chain_key };
        self.our_dh_priv = *our_new_secret.as_bytes();
        self.their_dh_pub = their_new_dh_pub;
    }

    pub fn new(shared_secret: [u8; 32], our_dh_priv: [u8; 32], their_dh_pub: [u8; 32]) -> Self {
        let initial_chain_key = derive_key(&shared_secret, None, b"init-chain").unwrap();

        DoubleRatchet {
            root_key: shared_secret,
            sending_chain: Chain { key: initial_chain_key },
            receiving_chain: Chain { key: initial_chain_key },
            our_dh_priv,
            their_dh_pub,
        }
    }

    pub fn initiator_pre_ratchet(&mut self) {
        let their_pubkey = PublicKey::from(self.their_dh_pub);

        let our_new_secret = StaticSecret::random();
        let dh_send = our_new_secret.diffie_hellman(&their_pubkey);
        let (new_root, new_sending_chain_key) = kdf_rk(self.root_key, *dh_send.as_bytes());

        self.root_key = new_root;
        self.sending_chain = Chain { key: new_sending_chain_key };
        self.our_dh_priv = *our_new_secret.as_bytes();
        // their_dh_pub and receiving_chain are deliberately untouched
    }
}
