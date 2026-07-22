use std::net::SocketAddr;

use crate::dht::node::DhtNode;
use crate::network::registry::RelayRegistry;
use ed25519_dalek::SigningKey;

use crate::protocol::packet::PacketFlag;
use crate::protocol::payload::PayloadTag;
use crate::transport::reliable::ReliableTransport;

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

pub struct RelayNode {
    transport: ReliableTransport,
    registry: RelayRegistry,
    dht_node: Option<DhtNode>,
}

impl RelayNode {
    pub fn bind(port: u16, registry: RelayRegistry, signing_key: Option<SigningKey>) -> Result<Self, std::io::Error> {
        let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
        let transport = ReliableTransport::bind(addr, signing_key)?;
        Ok(Self {
            transport,
            registry,
            dht_node: None,
        })
    }

    pub fn enable_dht(&mut self, node_id: crate::dht::node_id::NodeID, addr: SocketAddr) {
        self.dht_node = Some(DhtNode::new(node_id, addr));
    }

    pub fn run(&mut self) -> ! {
        loop {
            let (packet, sender) = match self.transport.recv() {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("relay recv error: {e}");
                    continue;
                }
            };

            match packet.payload.tag {
                PayloadTag::RelayFrame => self.handle_relay_frame(&packet, sender),
                PayloadTag::DhtOperation => {
                    if let Some(ref mut dht) = self.dht_node {
                        dht.handle(&packet, sender, &self.transport);
                    }
                }
                _ => {}
            }
        }
    }

    fn handle_relay_frame(&mut self, packet: &crate::protocol::packet::Packet, sender: SocketAddr) {
        let frame = match RelayFrame::from_serialized(packet.payload.data.clone()) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("bad relay frame: {e}");
                return;
            }
        };

        if let Some(entry) = self.registry.lookup(frame.dest_id) {
            let result = self.transport.socket().send_to(&frame.payload, entry.address);
            if result.is_ok() && packet.header.flags.contains(PacketFlag::AckRequired) {
                self.transport.confirm(packet.header.id, sender);
            }
        }
    }
}
