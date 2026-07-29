use std::net::SocketAddr;

use hkdf::Hkdf;
use rand::RngExt;
use sha2::{Sha256, Digest};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::crypto::handshake::{Initiator, Responder};
use crate::crypto::ratchet::DoubleRatchet;
use crate::identity::certificates::DeviceCertificate;
use crate::identity::identity::UserID;
use crate::protocol::message::Message;
use crate::protocol::packet::Packet;
use crate::protocol::payload::{Payload, PayloadTag};

fn derive_connection_id(handshake_hash: &[u8; 32]) -> [u8; 16] {
    let mut id = [0u8; 16];
    Hkdf::<Sha256>::new(None, handshake_hash)
        .expand(b"connection-id", &mut id)
        .expect("HKDF expand failed");
    id
}

pub struct Session {
    initiator: Option<Initiator>,
    responder: Option<Responder>,
    ratchet: Option<DoubleRatchet>,
    handshake_hash: Option<[u8; 32]>,
    remote_static: Option<[u8; 32]>,
    our_ratchet_dh_priv: Option<[u8; 32]>,
    their_ratchet_dh_pub: Option<[u8; 32]>,
    our_device_certificate: DeviceCertificate,
    our_master_pubkey: Option<[u8; 32]>,
    peer_device_certificate: Option<DeviceCertificate>,
    peer_user_id: Option<UserID>,
    peer_master_pubkey: Option<[u8; 32]>,
    peer_addr: Option<SocketAddr>,
    connection_id: Option<[u8; 16]>,
}

impl Session {
    pub fn new_initiator(
        our_device_x25519_priv: &[u8; 32],
        peer_device_x25519_pub: &[u8; 32],
        our_cert: DeviceCertificate,
        our_master_pubkey: [u8; 32],
        peer_user_id: UserID,
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
            our_device_certificate: our_cert,
            our_master_pubkey: Some(our_master_pubkey),
            peer_device_certificate: None,
            peer_user_id: Some(peer_user_id),
            peer_master_pubkey: None,
            peer_addr: None,
            connection_id: None,
        })
    }

    pub fn initiate_handshake(&mut self, our_addr: SocketAddr) -> Result<Vec<u8>, String> {
        let ratchet_secret = StaticSecret::random();
        let mut payload = PublicKey::from(&ratchet_secret).as_bytes().to_vec();
        payload.extend(self.our_device_certificate.serialize().iter());
        payload.extend_from_slice(&self.our_master_pubkey
            .ok_or("master pubkey not set")?);

        match our_addr.ip() {
            std::net::IpAddr::V4(v4) => {
                payload.push(4);
                payload.extend_from_slice(&v4.octets());
            }
            std::net::IpAddr::V6(v6) => {
                payload.push(6);
                payload.extend_from_slice(&v6.octets());
            }
        }
        payload.extend_from_slice(&our_addr.port().to_be_bytes());

        self.our_ratchet_dh_priv = Some(*ratchet_secret.as_bytes());

        self.initiator
            .as_mut()
            .ok_or("Session is not an initiator")?
            .initiate(payload)
    }

    pub fn complete_handshake(&mut self, response: &[u8]) -> Result<(), String> {
        let result = self.initiator
            .take()
            .ok_or("Session is not an initiator")?
            .finish(response)?;

        // payload is [ratchet_dh_pub (32)] [device_certificate (128)]
        if result.peer_payload.len() < 32 + 128 {
            return Err("handshake payload too short for certificate".to_string());
        }

        let their_ratchet_pub: [u8; 32] = result.peer_payload[..32]
            .try_into()
            .map_err(|_| "invalid peer ratchet pubkey length")?;

        let cert_bytes = result.peer_payload[32..].to_vec();
        let peer_cert = DeviceCertificate::from_serialized(cert_bytes)
            .map_err(|e| format!("bad peer device certificate: {e}"))?;

        // the Noise-authenticated static key must match the certificate
        let cert_x25519: [u8; 32] = *peer_cert.device_x25519_pubkey.as_bytes();
        if cert_x25519 != result.remote_static {
            return Err("peer certificate x25519 key doesn't match handshake".to_string());
        }

        // verify master signature against the peer identity we expect
        if let Some(ref peer_id) = self.peer_user_id {
            if !peer_cert.verify(peer_id) {
                return Err("peer device certificate signature invalid".to_string());
            }
        }

        self.peer_device_certificate = Some(peer_cert);

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

        self.connection_id = Some(derive_connection_id(&result.handshake_hash));

        Ok(())
    }

    pub fn new_responder(
        our_device_x25519_priv: &[u8; 32],
        our_cert: DeviceCertificate,
        our_master_pubkey: [u8; 32],
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
            our_device_certificate: our_cert,
            our_master_pubkey: Some(our_master_pubkey),
            peer_device_certificate: None,
            peer_user_id: None,
            peer_master_pubkey: None,
            peer_addr: None,
            connection_id: None,
        })
    }

    pub fn accept_handshake(&mut self, incoming: &[u8]) -> Result<(), String> {
        let peer_payload = self.responder
            .as_mut()
            .ok_or("Session is not a responder")?
            .accept(incoming)?;

        if peer_payload.len() < 32 + 128 + 32 + 7 {
            return Err("handshake payload too short".to_string());
        }

        let pubkey: [u8; 32] = peer_payload[..32]
            .try_into()
            .map_err(|_| "invalid ratchet pubkey length")?;
        self.their_ratchet_dh_pub = Some(pubkey);

        let cert_bytes = peer_payload[32..160].to_vec();
        let peer_cert = DeviceCertificate::from_serialized(cert_bytes)
            .map_err(|e| format!("bad peer device certificate: {e}"))?;

        self.peer_device_certificate = Some(peer_cert);

        let master_pubkey: [u8; 32] = peer_payload[160..192]
            .try_into()
            .map_err(|_| "invalid master pubkey length")?;
        self.peer_master_pubkey = Some(master_pubkey);

        let addr_start = 192;
        let addr_kind = peer_payload[addr_start];
        let peer_addr = match addr_kind {
            4 => {
                if peer_payload.len() < addr_start + 7 {
                    return Err("truncated addr".to_string());
                }
                let octets: [u8; 4] = peer_payload[addr_start+1..addr_start+5].try_into().unwrap();
                let port = u16::from_be_bytes(peer_payload[addr_start+5..addr_start+7].try_into().unwrap());
                SocketAddr::new(std::net::IpAddr::V4(octets.into()), port)
            }
            6 => {
                if peer_payload.len() < addr_start + 19 {
                    return Err("truncated addr".to_string());
                }
                let octets: [u8; 16] = peer_payload[addr_start+1..addr_start+17].try_into().unwrap();
                let port = u16::from_be_bytes(peer_payload[addr_start+17..addr_start+19].try_into().unwrap());
                SocketAddr::new(std::net::IpAddr::V6(octets.into()), port)
            }
            _ => return Err("unknown addr kind".to_string()),
        };
        self.peer_addr = Some(peer_addr);

        Ok(())
    }

    pub fn reply_handshake(&mut self) -> Result<Vec<u8>, String> {
        let ratchet_secret = StaticSecret::random();
        let mut ratchet_pub = PublicKey::from(&ratchet_secret).as_bytes().to_vec();
        ratchet_pub.extend(self.our_device_certificate.serialize().iter());

        self.our_ratchet_dh_priv = Some(*ratchet_secret.as_bytes());

        let (outgoing_message, result) = self.responder
            .take()
            .ok_or("Session is not a responder")?
            .reply(ratchet_pub)?;

        // the Noise-authenticated static key must match the certificate
        let cert_x25519: [u8; 32] = *self.peer_device_certificate
            .as_ref().unwrap()
            .device_x25519_pubkey.as_bytes();
        if cert_x25519 != result.remote_static {
            return Err("peer certificate x25519 key doesn't match handshake".to_string());
        }

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

        let conn_id = derive_connection_id(&result.handshake_hash);
        self.connection_id = Some(conn_id);

        Ok(outgoing_message)
    }

    pub fn connection_id(&self) -> Option<[u8; 16]> {
        self.connection_id
    }

    pub fn is_initiator(&self) -> bool {
        self.initiator.is_some()
    }

    pub fn is_established(&self) -> bool {
        !self.ratchet.is_none()
    }

    // verify the peer's device certificate against a claimed master identity
    pub fn verify_peer(&self, peer_id: &UserID) -> bool {
        self.peer_device_certificate
            .as_ref()
            .map_or(false, |cert| cert.verify(peer_id))
    }

    // the Noise-authenticated remote static key (X25519), available after handshake
    pub fn peer_static(&self) -> Option<[u8; 32]> {
        self.remote_static
    }

    pub fn peer_master_pubkey(&self) -> Option<[u8; 32]> {
        self.peer_master_pubkey
    }

    // the peer's device certificate, available after handshake
    pub fn peer_certificate(&self) -> Option<&DeviceCertificate> {
        self.peer_device_certificate.as_ref()
    }

    pub fn send(&mut self, message: &Message) -> Result<Packet, String> {
        let sender_pk = self.our_master_pubkey
            .ok_or("master pubkey not set")?;

        // prepend sender_pk to the message bytes, then encrypt together
        let mut plaintext = Vec::with_capacity(32 + message.serialize()?.len());
        plaintext.extend_from_slice(&sender_pk);
        plaintext.extend_from_slice(&message.serialize()?);

        let (ciphertext, nonce, our_dh_pub) = self.ratchet
            .as_mut()
            .ok_or("Session not established")?
            .encrypt(&plaintext)
            .map_err(|e| e.to_string())?;

        let conn_id = self.connection_id
            .ok_or("connection ID not set")?;

        let mut data = Vec::with_capacity(12 + 32 + ciphertext.len());
        data.extend_from_slice(&nonce);
        data.extend_from_slice(&our_dh_pub);
        data.extend_from_slice(&ciphertext);

        let mut payload = Payload::new(PayloadTag::Message, data);
        payload.connection_id = conn_id;

        Ok(Packet::new(0, rand::rng().random(), payload))
    }

    pub fn receive(&mut self, packet: &Packet) -> Result<(Message, [u8; 32]), String> {
        if packet.payload.tag != PayloadTag::Message {
            return Err(format!("expected Message payload, got {:?}", packet.payload.tag));
        }

        // [nonce: 12] [dh_pub: 32] [ciphertext], where ciphertext decrypts to [sender_pk: 32] [message]
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

        if plaintext.len() < 32 {
            return Err("plaintext too short for sender pk".to_string());
        }

        let sender_pk: [u8; 32] = plaintext[..32]
            .try_into()
            .map_err(|_| "bad sender pk")?;
        let msg = Message::from_serialized(plaintext[32..].to_vec())
            .map_err(|e| e.to_string())?;

        Ok((msg, sender_pk))
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

    pub fn peer_addr(&self) -> Option<SocketAddr> {
        return self.peer_addr
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