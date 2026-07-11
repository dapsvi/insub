use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};
use zeroize::Zeroizing;

pub struct StaticExchangeKeyPair {
    pub public_key: PublicKey,
    secret: StaticSecret,
    pub shared_secret: Option<Zeroizing<[u8; 32]>>,
}

pub struct EphemeralExchangeKeyPair {
    pub public_key: PublicKey,
    secret: Option<EphemeralSecret>,
    pub shared_secret: Option<Zeroizing<[u8; 32]>>,
}

impl StaticExchangeKeyPair {
    pub fn new() -> Self {
        let secret = StaticSecret::random();
        let public_key = PublicKey::from(&secret);
        StaticExchangeKeyPair { public_key, secret: secret, shared_secret: None }
    }

    pub fn compute_shared_secret(&mut self, peer_public_key: &PublicKey) {
        let shared_secret = self.secret.diffie_hellman(peer_public_key);
        self.shared_secret = Some(Zeroizing::new(*shared_secret.as_bytes()));
    }
}

impl EphemeralExchangeKeyPair {
    pub fn new() -> Self {
        let secret = EphemeralSecret::random();
        let public_key = PublicKey::from(&secret);
        EphemeralExchangeKeyPair { public_key, secret: Some(secret), shared_secret: None }
    }

    pub fn compute_shared_secret(&mut self, peer_public_key: &PublicKey) -> Result<(), &'static str> {
        let secret = self.secret
            .take()
            .ok_or("ephemeral secret already consumed")?;
        let shared_secret = secret.diffie_hellman(peer_public_key);
        self.shared_secret = Some(Zeroizing::new(*shared_secret.as_bytes()));
        Ok(())
    }
}