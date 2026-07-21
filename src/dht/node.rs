use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Instant;
use rand::RngExt;

use crate::dht::protocol::DhtOperation;
use crate::dht::routing;
use crate::dht::{node_id::NodeID, routing::RoutingTable};
use crate::protocol::packet::Packet;
use crate::protocol::payload::{Payload, PayloadTag};
use crate::transport::reliable::ReliableTransport;

pub struct DhtNode {
    pub id: NodeID,
    pub addr: SocketAddr,
    pub routing: RoutingTable,
    pub store: HashMap<[u8; 32], (Vec<u8>, Instant)>,   // key -> (value, expires_at)
}

impl DhtNode {
    pub fn new(id: NodeID, addr: SocketAddr) -> Self {
        DhtNode {
            id,
            addr,
            routing: RoutingTable::new(id),
            store: HashMap::new(),
        }
    }

    pub fn handle(
        &mut self,
        packet: &Packet,
        sender: SocketAddr,
        transport: &ReliableTransport,
    ) {
        let op = match DhtOperation::from_serialized(packet.payload.data.clone()) {
            Ok(op) => op,
            Err(_) => return,
        };

        self.routing.add_node(op.sender_id(), sender);

        match op {
            DhtOperation::Ping { .. } => {
                let pong = DhtOperation::Pong {
                    sender_id: self.id,
                };
                self.send(pong, sender, transport);
            }
            DhtOperation::Pong { .. } => {}
            DhtOperation::FindNode { target_id, .. } => {
                let nodes = self.routing.closest_nodes(&target_id, routing::K);
                let response = DhtOperation::Nodes {
                    sender_id: self.id,
                    nodes,
                };
                self.send(response, sender, transport);
            }
            DhtOperation::Nodes { nodes, .. } => {
                for (id, addr) in nodes {
                    self.routing.add_node(id, addr);
                }
            }
            DhtOperation::Store { key, value, ttl_seconds, .. } => {
                let expires = Instant::now()
                    .checked_add(std::time::Duration::from_secs(ttl_seconds as u64))
                    .unwrap_or(Instant::now());
                self.store.insert(key, (value, expires));
                let ack = DhtOperation::StoreAck {
                    sender_id: self.id,
                    key,
                };
                self.send(ack, sender, transport);
            }
            DhtOperation::StoreAck { .. } => {}
            DhtOperation::FindValue { key, .. } => {
                let now = Instant::now();
                let value = self
                    .store
                    .get(&key)
                    .filter(|(_, expires)| *expires > now)
                    .map(|(v, _)| v.clone());
                let closest = self.routing.closest_nodes(&NodeID { id: key }, routing::K);
                let response = DhtOperation::Value {
                    sender_id: self.id,
                    key,
                    value,
                    closest_nodes: closest,
                };
                self.send(response, sender, transport);
            }
            DhtOperation::Value { closest_nodes, .. } => {
                for (id, addr) in closest_nodes {
                    self.routing.add_node(id, addr);
                }
            }
        }
    }

    fn send(&self, op: DhtOperation, dest: SocketAddr, transport: &ReliableTransport) {
        let data = op.serialize();
        let payload = Payload::new(PayloadTag::DhtOperation, data);
        let pkt = Packet::new(1, 0, rand::rng().random(), [0u8; 12], payload);
        let _ = transport.send(&pkt, dest);
    }
}