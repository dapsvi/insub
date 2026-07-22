use hkdf::Hkdf;
use rand::RngExt;
use sha2::{Sha256, Digest};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::crypto::handshake::{Initiator, Responder};
use crate::crypto::ratchet::DoubleRatchet;
use crate::protocol::message::Message;
use crate::protocol::packet::Packet;
use crate::protocol::payload::{Payload, PayloadTag};

pub struct Session {
    initiator: Option<Initiator>,
    responder: Option<Responder>,
    ratchet: Option<DoubleRatchet>,
    handshake_hash: Option<[u8; 32]>,
    remote_static: Option<[u8; 32]>,
    our_ratchet_dh_priv: Option<[u8; 32]>,
    their_ratchet_dh_pub: Option<[u8; 32]>,
}

impl Session {
    pub fn new_initiator(
        our_device_x25519_priv: &[u8; 32],
        peer_device_x25519_pub: &[u8; 32],
    ) -> Result<Session, String> {
        let initiator = Initiator::new(our_device_x25519_priv, peer_device_x25519_pub)?;

        Ok(Session {
            initiator: Some(initiator),
            responder: None,
            ratchet: None,
            handshake_hash: None,
            remote_static: None,
            our_ratchet_dh_priv: None,
            their_ratchet_dh_pub: None,
        })
    }

    pub fn initiate_handshake(&mut self) -> Result<Vec<u8>, String> {
        // generate the ratchet DH keypair so we can send the pubkey through the handshake payload
        let ratchet_secret = StaticSecret::random();
        let ratchet_pub = *PublicKey::from(&ratchet_secret).as_bytes();
        self.our_ratchet_dh_priv = Some(*ratchet_secret.as_bytes());

        self.initiator
            .as_mut()
            .ok_or("Session is not an initiator")?
            .initiate(ratchet_pub.to_vec())
    }

    pub fn complete_handshake(&mut self, response: &[u8]) -> Result<(), String> {
        let result = self.initiator
            .take()
            .ok_or("Session is not an initiator")?
            .finish(response)?;

        let their_ratchet_pub: [u8; 32] = result.peer_ratchet_pub
            .try_into()
            .map_err(|_| "invalid peer ratchet pubkey length")?;

        let root_key = derive_root_key(
            &result.handshake_hash,
            &self.our_ratchet_dh_priv.unwrap(),
            &their_ratchet_pub,
        );

        self.ratchet = Some(DoubleRatchet::new(
            root_key,
            self.our_ratchet_dh_priv.unwrap(),
            their_ratchet_pub,
        ));
        self.ratchet
            .as_mut()
            .ok_or("Ratchet not initialized properly")?
            .initiator_pre_ratchet();

        self.handshake_hash = Some(result.handshake_hash);
        self.remote_static = Some(result.remote_static);
        Ok(())
    }

    pub fn new_responder(
        our_device_x25519_priv: &[u8; 32],
    ) -> Result<Self, String> {
        let responder = Responder::new(our_device_x25519_priv)?;

        Ok(Session {
            initiator: None,
            responder: Some(responder),
            ratchet: None,
            handshake_hash: None,
            remote_static: None,
            our_ratchet_dh_priv: None,
            their_ratchet_dh_pub: None,
        })
    }

    pub fn accept_handshake(&mut self, incoming: &[u8]) -> Result<(), String> {
        let peer_ratchet_pub = self.responder
            .as_mut()
            .ok_or("Session is not a responder")?
            .accept(incoming)?;

        let pubkey: [u8; 32] = peer_ratchet_pub
            .try_into()
            .map_err(|_| "invalid ratchet pubkey length")?;
        self.their_ratchet_dh_pub = Some(pubkey);
        Ok(())
    }

    pub fn reply_handshake(&mut self) -> Result<Vec<u8>, String> {
        let ratchet_secret = StaticSecret::random();
        let ratchet_pub = *PublicKey::from(&ratchet_secret).as_bytes();
        self.our_ratchet_dh_priv = Some(*ratchet_secret.as_bytes());

        let (outgoing_message, result) = self.responder
            .take()
            .ok_or("Session is not a responder")?
            .reply(ratchet_pub.to_vec())?;

        let root_key = derive_root_key(
            &result.handshake_hash,
            &self.our_ratchet_dh_priv.unwrap(),
            &self.their_ratchet_dh_pub.unwrap(),
        );

        self.ratchet = Some(DoubleRatchet::new(
            root_key,
            self.our_ratchet_dh_priv.unwrap(),
            self.their_ratchet_dh_pub.unwrap(),
        ));
        // responder does NOT call initiator_pre_ratchet: its first decrypt() triggers dh_ratchet_step, which catches up via DH commutativity and also prepares the sending chain for the reply
        self.handshake_hash = Some(result.handshake_hash);
        self.remote_static = Some(result.remote_static);
        Ok(outgoing_message)
    }

    pub fn is_initiator(&self) -> bool {
        self.initiator.is_some()
    }

    pub fn is_established(&self) -> bool {
        !self.ratchet.is_none()
    }

    pub fn send(&mut self, message: &Message) -> Result<Packet, String> {
        let bytes = message.serialize()?;
        let (ciphertext, nonce, our_dh_pub) = self.ratchet
            .as_mut()
            .ok_or("Session not established")?
            .encrypt(&bytes)
            .map_err(|e| e.to_string())?;

        let mut data = Vec::with_capacity(12 + 32 + ciphertext.len());
        data.extend_from_slice(&nonce);
        data.extend_from_slice(&our_dh_pub);
        data.extend_from_slice(&ciphertext);

        let payload = Payload::new(PayloadTag::Message, data);

        Ok(Packet::new(1, 0, rand::rng().random(), payload))
    }

    pub fn receive(&mut self, packet: &Packet) -> Result<Message, String> {
        if packet.payload.tag != PayloadTag::Message {
            return Err(format!("expected Message payload, got {:?}", packet.payload.tag));
        }

        if packet.payload.data.len() < 44 {
            return Err("packet too short".to_string());
        }

        let nonce: [u8; 12] = packet.payload.data[..12]
            .try_into()
            .map_err(|_| "bad nonce")?;
        let their_dh_pub: [u8; 32] = packet.payload.data[12..44]
            .try_into()
            .map_err(|_| "bad DH public key")?;
        let ciphertext = &packet.payload.data[44..];

        let plaintext = self.ratchet
            .as_mut()
            .ok_or("Session not established")?
            .decrypt(their_dh_pub, &nonce, ciphertext)
            .map_err(|_| "Couldn't decrypt the message")?;

        Message::from_serialized(plaintext)
            .map_err(|e| e.to_string())
    }

    pub fn safety_number(
        &self,
        our_master_ed25519_pub: &[u8; 32],
        peer_master_ed25519_pub: &[u8; 32],
    ) -> Option<[u8; 32]> {
        let handshake_hash = self.handshake_hash?;

        let (first, second) = if our_master_ed25519_pub < peer_master_ed25519_pub {
            (our_master_ed25519_pub, peer_master_ed25519_pub)
        } else {
            (peer_master_ed25519_pub, our_master_ed25519_pub)
        };

        let mut hasher = Sha256::new();
        hasher.update(handshake_hash);
        hasher.update(first);
        hasher.update(second);
        let result = hasher.finalize();

        let mut safety = [0u8; 32];
        safety.copy_from_slice(&result);
        Some(safety)
    }
}

fn derive_root_key(handshake_hash: &[u8; 32], our_ratchet_priv: &[u8; 32], their_ratchet_pub: &[u8; 32]) -> [u8; 32] {
    let our_secret = StaticSecret::from(*our_ratchet_priv);
    let their_pubkey = PublicKey::from(*their_ratchet_pub);
    let dh_output = *our_secret.diffie_hellman(&their_pubkey).as_bytes();

    let mut root_key = [0u8; 32];
    Hkdf::<Sha256>::new(Some(handshake_hash), &dh_output)
        .expand(b"insub-ratchet-root", &mut root_key)
        .expect("HKDF expand failed");
    root_key
}