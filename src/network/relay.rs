use std::net::SocketAddr;

use crate::network::registry::RelayRegistry;
use crate::protocol::payload::{Payload, PayloadTag};
use crate::transport::udp::UdpTransport;

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
    transport: UdpTransport,
    registry: RelayRegistry,
}

impl RelayNode {
    pub fn bind(port: u16, registry: RelayRegistry) -> Result<Self, std::io::Error> {
        let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
        let transport = UdpTransport::bind(addr)?;
        Ok(Self { transport, registry })
    }

    pub fn run(&self) -> ! {
        loop {
            let (packet, _sender) = match self.transport.recv_from() {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("relay recv error: {e}");
                    continue;
                }
            };

            if packet.payload.tag != PayloadTag::RelayFrame {
                continue;
            }

            let frame = match RelayFrame::from_serialized(packet.payload.data) {
                Ok(f) => f,
                Err(e) => {
                    eprintln!("bad relay frame: {e}");
                    continue;
                }
            };

            if let Some(entry) = self.registry.lookup(frame.dest_id) {
                let _ = self.transport.send_to_bytes(&frame.payload, entry.address);
            }
        }
    }
}