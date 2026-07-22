use std::net::SocketAddr;

use crate::network::registry::RelayRegistry;
use crate::protocol::packet::{Packet, PacketFlag};

pub struct RelayFrame {
    pub dest_id: u128,
    pub payload: Vec<u8>,
}

impl RelayFrame {
    pub fn new(dest_id: u128, payload: Vec<u8>) -> Self {
        Self { dest_id, payload }
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(16 + self.payload.len());
        bytes.extend_from_slice(&self.dest_id.to_be_bytes());
        bytes.extend_from_slice(&self.payload);
        bytes
    }

    pub fn from_serialized(mut bytes: Vec<u8>) -> Result<Self, &'static str> {
        if bytes.len() < 16 {
            return Err("relay frame too short");
        }
        let id_bytes: [u8; 16] = bytes.drain(..16)
            .collect::<Vec<u8>>()
            .try_into()
            .map_err(|_| "failed to parse dest id")?;
        let dest_id = u128::from_be_bytes(id_bytes);

        Ok(RelayFrame {
            dest_id,
            payload: bytes,
        })
    }
}

pub struct RelayForwarder {
    registry: RelayRegistry,
}

impl RelayForwarder {
    pub fn new(registry: RelayRegistry) -> Self {
        Self { registry }
    }

    // parse a RelayFrame, look up the destination, reconstruct the
    // inner packet. returns None if the frame is malformed or the
    // destination is unknown. the caller sends the packet through
    // the normal outbound channel and confirms if AckRequired.
    pub fn resolve(&self, outer: &Packet) -> Option<(Packet, SocketAddr)> {
        let frame = RelayFrame::from_serialized(outer.payload.data.clone()).ok()?;
        let entry = self.registry.lookup(frame.dest_id)?;
        let inner = Packet::from_serialized(frame.payload).ok()?;
        Some((inner, entry.address))
    }

    // after resolve+send succeeds, the caller confirms the outer
    // packet if the sender asked for it.
    pub fn should_confirm(&self, outer: &Packet) -> bool {
        outer.header.flags.contains(PacketFlag::AckRequired)
    }
}
