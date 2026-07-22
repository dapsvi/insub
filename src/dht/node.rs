use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Instant;

use crate::dht::protocol::DhtOperation;
use crate::dht::routing;
use crate::dht::{node_id::NodeID, routing::RoutingTable};
use crate::protocol::packet::Packet;

pub struct DhtNode {
    pub id: NodeID,
    pub addr: SocketAddr,
    pub store: HashMap<[u8; 32], (Vec<u8>, Instant)>,   // key -> (value, expires_at)
}

impl DhtNode {
    pub fn new(id: NodeID, addr: SocketAddr) -> Self {
        DhtNode {
            id,
            addr,
            store: HashMap::new(),
        }
    }

    // parse+dispatch used by tick_server
    // takes the shared routing table so the server learns nodes
    // from incoming requests and can answer closest_nodes queries.
    pub fn process(&mut self, packet: &Packet, sender: SocketAddr, routing: &mut RoutingTable) -> Option<(DhtOperation, SocketAddr)> {
        let op = DhtOperation::from_serialized(packet.payload.data.clone()).ok()?;
        self.process_op(&op, sender, routing)
    }

    // shared logic: takes a parsed op, returns an optional response to send.
    // both handle() and process() route through here.
    fn process_op(&mut self, op: &DhtOperation, sender: SocketAddr, routing: &mut RoutingTable) -> Option<(DhtOperation, SocketAddr)> {
        let sid = op.sender_id();

        match op {
            DhtOperation::Ping { .. } => {
                let _ = routing.add_node(sid, sender);
                Some((DhtOperation::Pong { sender_id: self.id }, sender))
            }
            DhtOperation::FindNode { target_id, .. } => {
                let nodes: Vec<_> = routing.closest_nodes(target_id, routing::K)
                    .into_iter()
                    .filter(|(id, _)| *id != sid)
                    .collect();
                let _ = routing.add_node(sid, sender);
                Some((DhtOperation::Nodes { sender_id: self.id, nodes }, sender))
            }
            DhtOperation::FindValue { key, .. } => {
                let now = Instant::now();
                let value = self.store.get(key)
                    .filter(|(_, expires)| *expires > now)
                    .map(|(v, _)| v.clone());
                let closest: Vec<_> = routing.closest_nodes(&NodeID { id: *key }, routing::K)
                    .into_iter()
                    .filter(|(id, _)| *id != sid)
                    .collect();
                let _ = routing.add_node(sid, sender);
                Some((DhtOperation::Value { sender_id: self.id, key: *key, value, closest_nodes: closest }, sender))
            }
            DhtOperation::Store { key, value, ttl_seconds, .. } => {
                let _ = routing.add_node(sid, sender);
                let expires = Instant::now()
                    .checked_add(std::time::Duration::from_secs(*ttl_seconds as u64))
                    .unwrap_or(Instant::now());
                self.store.insert(*key, (value.clone(), expires));
                Some((DhtOperation::StoreAck { sender_id: self.id, key: *key }, sender))
            }
            // response types: learn the sender, no response needed
            DhtOperation::Pong { .. } => { let _ = routing.add_node(sid, sender); None }
            DhtOperation::Nodes { nodes, .. } => {
                let _ = routing.add_node(sid, sender);
                for (id, addr) in nodes { routing.add_node(*id, *addr); }
                None
            }
            DhtOperation::StoreAck { .. } => { let _ = routing.add_node(sid, sender); None }
            DhtOperation::Value { closest_nodes, .. } => {
                let _ = routing.add_node(sid, sender);
                for (id, addr) in closest_nodes { routing.add_node(*id, *addr); }
                None
            }
        }
    }
}