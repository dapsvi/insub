use bip39::{Mnemonic, Language};
use ed25519_dalek::{Signer, Verifier, SigningKey, VerifyingKey};
use zeroize::Zeroize;

use crate::crypto::hkdf::derive_key;

// key pair used to sign messages (for now)
pub struct MasterKeyPair {
    pub public_key: VerifyingKey,
    private_key: SigningKey,
}

impl MasterKeyPair {
    // allows to create a pair based on a seed phrase (like cryptocurrencies)
    pub fn from_mnemonic(mnemonic: &Mnemonic, password: Option<&str>) -> Self {
        let mut seed_64 = mnemonic.to_seed(password.unwrap_or(""));
        let mut seed_32 = derive_key(&seed_64, None, b"insub-master-ed25519-v1")
            .expect("HKDF key derivation failed");
        let private_key = SigningKey::from_bytes(&seed_32);
        let public_key = private_key.verifying_key();

        seed_64.zeroize();
        seed_32.zeroize();

        MasterKeyPair { public_key, private_key }
    }

    // sign bytes using the private key
    pub fn sign(&self, bytes: &[u8]) -> ed25519_dalek::Signature {
        self.private_key.sign(bytes)
    }

    // generate a 24-word seed phrase
    fn generate_mnemonic() -> Mnemonic {
        Mnemonic::generate_in(Language::English, 24).expect("Failed to generate mnemonic")
    }

    // generate a seed phrase and a keypair
    pub fn new() -> (Self, Mnemonic) {
        let mnemonic = Self::generate_mnemonic();
        let keypair = Self::from_mnemonic(&mnemonic, None);
        (keypair, mnemonic)
    }

    // for saving (unsafe right now, should be encrypted with a password)
    pub fn to_bytes(&self) -> [u8; 32] {
        self.private_key.to_bytes()
    }

    // for retrieving
    pub fn from_signing_key_bytes(bytes: &[u8; 32]) -> Self {
        let private_key = SigningKey::from_bytes(bytes);
        let public_key = private_key.verifying_key();
        MasterKeyPair { public_key, private_key }
    }
}

impl std::fmt::Debug for MasterKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MasterKeyPair")
            .field("public_key", &self.public_key)
            .field("private_key", &"<redacted>") // don't print the private key, e.g. in logs
            .finish()
    }
}


// struct representing another user, we only have their public key
pub struct UserID {
    pub public_key: VerifyingKey,
}

impl UserID {
    // verify if the signature is valid
    pub fn verify(&self, bytes: &[u8], signature: &ed25519_dalek::Signature) -> bool {
        self.public_key.verify(bytes, signature).is_ok()
    }
}

// to create a UserID using a MasterKeyPair
impl From<&MasterKeyPair> for UserID {
    fn from(kp: &MasterKeyPair) -> Self {
        UserID { public_key: kp.public_key }
    }
}