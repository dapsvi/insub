use bip39::{Mnemonic, Language};
use ed25519_dalek::{Signer, Verifier, SigningKey, VerifyingKey};
use zeroize::Zeroize;

pub struct MasterKeyPair {
    pub public_key: VerifyingKey,
    private_key: SigningKey,
}

impl MasterKeyPair {
    pub fn from_mnemonic(mnemonic: &Mnemonic, password: Option<&str>) -> Self {
        let mut seed_64 = mnemonic.to_seed(password.unwrap_or(""));
        let mut seed_32 = [0u8; 32];
        seed_32.copy_from_slice(&seed_64[..32]);
        let private_key = SigningKey::from_bytes(&seed_32);
        let public_key = private_key.verifying_key();

        seed_64.zeroize();
        seed_32.zeroize();

        MasterKeyPair { public_key, private_key }
    }

    pub fn sign(&self, message: &[u8]) -> ed25519_dalek::Signature {
        self.private_key.sign(message)
    }

    fn generate_mnemonic() -> Mnemonic {
        Mnemonic::generate_in(Language::English, 24).expect("Failed to generate mnemonic")
    }

    pub fn new() -> (Self, Mnemonic) {
        let mnemonic = Self::generate_mnemonic();
        let keypair = Self::from_mnemonic(&mnemonic, None);
        (keypair, mnemonic)
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.private_key.to_bytes()
    }

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
            .field("private_key", &"<redacted>")
            .finish()
    }
}



pub struct UserID {
    pub public_key: VerifyingKey,
}

impl UserID {
    pub fn verify(&self, message: &[u8], signature: &ed25519_dalek::Signature) -> bool {
        self.public_key.verify(message, signature).is_ok()
    }
}

impl From<&MasterKeyPair> for UserID {
    fn from(kp: &MasterKeyPair) -> Self {
        UserID { public_key: kp.public_key }
    }
}