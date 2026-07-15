use rand::RngExt;
use snow::TransportState;

use crate::identity::identity::UserID;
use crate::crypto::handshake::{Initiator, Responder};
use crate::protocol::message::Message;
use crate::protocol::packet::Packet;
use sha2::{Sha256, Digest};

pub struct Session {
    peer_identity: Option<UserID>,
    initiator: Option<Initiator>,
    responder: Option<Responder>,
    transport: Option<TransportState>,
    handshake_hash: Option<[u8; 32]>,
    remote_static: Option<[u8; 32]>,
}

impl Session {
    pub fn new_initiator(
        our_device_x25519_priv: &[u8],
        peer_device_x25519_pub: &[u8],
        peer_identity: UserID,
    ) -> Result<Session, String> {
        let initiator = Initiator::new(our_device_x25519_priv, peer_device_x25519_pub)?;

        Ok(Session { peer_identity: Some(peer_identity), initiator: Some(initiator), responder: None, transport: None, handshake_hash: None, remote_static: None })
    }

    pub fn initiate_handshake(&mut self) -> Result<Vec<u8>, String> {
        self.initiator
            .as_mut()
            .ok_or("Session is not an initiator")?
            .initiate()
    }

    pub fn complete_handshake(&mut self, response: &[u8]) -> Result<(), String> {
        let result = self.initiator
            .take()
            .ok_or("Session is not an initiator")?
            .finish(response)?;

        self.transport = Some(result.transport);
        self.handshake_hash = Some(result.handshake_hash);
        self.remote_static = Some(result.remote_static);
        Ok(())
    }

    pub fn new_responder(
        our_device_x25519_priv: &[u8],
    ) -> Result<Self, String> {
        let responder = Responder::new(our_device_x25519_priv)?;
        
        Ok(Session { peer_identity: None, initiator: None, responder: Some(responder), transport: None, handshake_hash: None, remote_static: None })
    }

    pub fn accept_handshake(&mut self, incoming: &[u8]) -> Result<(), String> {
        self.responder
            .as_mut()
            .ok_or("Session is not a responder")?
            .accept(incoming)
    }

    pub fn reply_handshake(&mut self) -> Result<Vec<u8>, String> {
        let (outgoing_message, result) = self.responder
            .take()
            .ok_or("Session is not a responder")?
            .reply()?;

        self.transport = Some(result.transport);
        self.handshake_hash = Some(result.handshake_hash);
        self.remote_static = Some(result.remote_static);
        Ok(outgoing_message)
    }

    pub fn is_established(&self) -> bool {
        !self.transport.is_none()
    }

    pub fn send(&mut self, message: Message) -> Result<Packet, String> {
        let bytes = message.serialize()?;
        let mut buffer = vec![0u8; bytes.len() + 16];
        let ciphertext_length = self.transport
            .as_mut()
            .ok_or("Session not established")?
            .write_message(&bytes, &mut buffer)
            .map_err(|e| e.to_string())?;

        buffer.truncate(ciphertext_length);

        Ok(Packet::new(1, 0, rand::rng().random(), [0u8; 12], buffer))
    }

    pub fn receive(&mut self, packet: &Packet) -> Result<Message, String> {
        let mut buffer = vec![0u8; packet.payload.len()];
        let plaintext_length = self.transport
            .as_mut()
            .ok_or("Session not established")?
            .read_message(&packet.payload, &mut buffer)
            .map_err(|_| "Couldn't decrypt the message")?;

        buffer.truncate(plaintext_length);
        Message::from_serialized(buffer)
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