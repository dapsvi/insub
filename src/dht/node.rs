use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Instant;
use rand::RngExt;

use crate::dht::protocol::DhtOperation;
use crate::dht::routing;
use crate::dht::{node_id::NodeID, routing::RoutingTable};
use crate::protocol::packet::{Packet, PacketFlag};
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

        let sid = op.sender_id();

        match op {
            // server queries: answer first, then add sender to routing
            DhtOperation::Ping { .. } => {
                let _ = self.routing.add_node(sid, sender);
                let pong = DhtOperation::Pong {
                    sender_id: self.id,
                };
                self.send(pong, sender, transport);
            }
            DhtOperation::FindNode { target_id, .. } => {
                let nodes: Vec<_> = self.routing.closest_nodes(&target_id, routing::K)
                    .into_iter()
                    .filter(|(id, _)| *id != sid)
                    .collect();
                let response = DhtOperation::Nodes {
                    sender_id: self.id,
                    nodes,
                };
                self.send(response, sender, transport);
                let _ = self.routing.add_node(sid, sender);
            }
            DhtOperation::FindValue { key, .. } => {
                let now = Instant::now();
                let value = self
                    .store
                    .get(&key)
                    .filter(|(_, expires)| *expires > now)
                    .map(|(v, _)| v.clone());
                let closest: Vec<_> = self.routing.closest_nodes(&NodeID { id: key }, routing::K)
                    .into_iter()
                    .filter(|(id, _)| *id != sid)
                    .collect();
                let response = DhtOperation::Value {
                    sender_id: self.id,
                    key,
                    value,
                    closest_nodes: closest,
                };
                self.send(response, sender, transport);
                let _ = self.routing.add_node(sid, sender);
            }
            DhtOperation::Store { key, value, ttl_seconds, .. } => {
                let _ = self.routing.add_node(sid, sender);
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
            // response types: add sender to routing
            DhtOperation::Pong { .. } => {
                let _ = self.routing.add_node(sid, sender);
            }
            DhtOperation::Nodes { nodes, .. } => {
                let _ = self.routing.add_node(sid, sender);
                for (id, addr) in nodes {
                    let _ = self.routing.add_node(id, addr);
                }
            }
            DhtOperation::StoreAck { .. } => {
                let _ = self.routing.add_node(sid, sender);
            }
            DhtOperation::Value { closest_nodes, .. } => {
                let _ = self.routing.add_node(sid, sender);
                for (id, addr) in closest_nodes {
                    self.routing.add_node(id, addr);
                }
            }
        }
        if packet.header.flags.contains(PacketFlag::AckRequired) {
            transport.confirm(packet.header.id, sender);
        }
    }

    // like handle, but returns the response for the caller to send
    // used when the DhtNode doesn't own the transport
    pub fn process(&mut self, packet: &Packet, sender: SocketAddr) -> Option<(DhtOperation, SocketAddr)> {
        let op = DhtOperation::from_serialized(packet.payload.data.clone()).ok()?;
        let sid = op.sender_id();

        match op {
            DhtOperation::Ping { .. } => {
                let _ = self.routing.add_node(sid, sender);
                let pong = DhtOperation::Pong { sender_id: self.id };
                Some((pong, sender))
            }
            DhtOperation::FindNode { target_id, .. } => {
                let nodes: Vec<_> = self.routing.closest_nodes(&target_id, routing::K)
                    .into_iter()
                    .filter(|(id, _)| *id != sid)
                    .collect();
                let response = DhtOperation::Nodes { sender_id: self.id, nodes };
                let _ = self.routing.add_node(sid, sender);
                Some((response, sender))
            }
            DhtOperation::FindValue { key, .. } => {
                let now = Instant::now();
                let value = self.store.get(&key)
                    .filter(|(_, expires)| *expires > now)
                    .map(|(v, _)| v.clone());
                let closest: Vec<_> = self.routing.closest_nodes(&NodeID { id: key }, routing::K)
                    .into_iter()
                    .filter(|(id, _)| *id != sid)
                    .collect();
                let response = DhtOperation::Value { sender_id: self.id, key, value, closest_nodes: closest };
                let _ = self.routing.add_node(sid, sender);
                Some((response, sender))
            }
            DhtOperation::Store { key, value, ttl_seconds, .. } => {
                let _ = self.routing.add_node(sid, sender);
                let expires = Instant::now()
                    .checked_add(std::time::Duration::from_secs(ttl_seconds as u64))
                    .unwrap_or(Instant::now());
                self.store.insert(key, (value, expires));
                let ack = DhtOperation::StoreAck { sender_id: self.id, key };
                Some((ack, sender))
            }
            // response types: just learn the sender
            DhtOperation::Pong { .. } => { let _ = self.routing.add_node(sid, sender); None }
            DhtOperation::Nodes { nodes, .. } => {
                let _ = self.routing.add_node(sid, sender);
                for (id, addr) in nodes { self.routing.add_node(id, addr); }
                None
            }
            DhtOperation::StoreAck { .. } => { let _ = self.routing.add_node(sid, sender); None }
            DhtOperation::Value { closest_nodes, .. } => {
                let _ = self.routing.add_node(sid, sender);
                for (id, addr) in closest_nodes { self.routing.add_node(id, addr); }
                None
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