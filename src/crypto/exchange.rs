use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};
use zeroize::Zeroizing;

// struct holding a static (reusable) key pair for exchanging data
pub struct StaticExchangeKeyPair {
    pub public_key: PublicKey,
    secret: StaticSecret,
    pub shared_secret: Option<Zeroizing<[u8; 32]>>, // the shared secret will be computed using self.secret and other.public_key
}                                                   // it will be the same for both machines without having to transmit that shared secret directly

// struct holding an ephemeral (non reusable) key pair for exchanging data
pub struct EphemeralExchangeKeyPair {
    pub public_key: PublicKey,
    secret: Option<EphemeralSecret>, // Option<> because we can't use this key pair more than once, the secret is consumed after the first use
    pub shared_secret: Option<Zeroizing<[u8; 32]>>,
}

impl StaticExchangeKeyPair {
    // generate a new random static pair
    pub fn new() -> Self {
        let secret = StaticSecret::random();
        let public_key = PublicKey::from(&secret);
        StaticExchangeKeyPair { public_key, secret: secret, shared_secret: None }
    }

    // compute the shared secret using the Diffie-Hellman algorithm
    pub fn compute_shared_secret(&mut self, peer_public_key: &PublicKey) -> Result<(), &'static str> {
        let shared_secret = self.secret.diffie_hellman(peer_public_key);
        self.shared_secret = Some(Zeroizing::new(*shared_secret.as_bytes()));
        Ok(())
    }
}

impl EphemeralExchangeKeyPair {
    // generate a new random ephemeral pair
    pub fn new() -> Self {
        let secret = EphemeralSecret::random();
        let public_key = PublicKey::from(&secret);
        EphemeralExchangeKeyPair { public_key, secret: Some(secret), shared_secret: None }
    }

    // compute the shared secret using the Diffie-Hellman algorithm (this consumes the self.secret)
    pub fn compute_shared_secret(&mut self, peer_public_key: &PublicKey) -> Result<(), &'static str> {
        let secret = self.secret
            .take()        // it is here that the secret is consumed
            .ok_or("ephemeral secret already consumed")?;
        let shared_secret = secret.diffie_hellman(peer_public_key);
        self.shared_secret = Some(Zeroizing::new(*shared_secret.as_bytes()));
        Ok(())
    }
}