use std::collections::HashSet;
use std::net::SocketAddr;

use crate::dht::node_id::NodeID;
use crate::dht::protocol::DhtOperation;
use crate::dht::routing::{self, RoutingTable};

pub struct PendingLookup {
    pub target: NodeID,
    pub find_value_key: Option<[u8; 32]>,
    pub shortlist: Vec<(NodeID, SocketAddr)>,
    pub queried: HashSet<NodeID>,
    pub found_value: Option<Vec<u8>>,
}

impl PendingLookup {
    // pick the closest node to target that we haven't queried yet,
    // then mark it as queried and return it so the caller sends a
    // FindNode/FindValue to it or returns None if all nodes exhausted.
    fn next_query(&mut self) -> Option<(NodeID, SocketAddr)> {
        self.shortlist
            .iter()
            .filter(|(id, _)| !self.queried.contains(id))
            .min_by_key(|(id, _)| self.target.distance(id).to_vec())
            .cloned()
            .map(|(id, addr)| {
                self.queried.insert(id);
                (id, addr)
            })
    }
}

pub struct DhtClient {
    pub id: NodeID,
    pending: Option<PendingLookup>,
}

impl DhtClient {
    pub fn new(id: NodeID) -> Self {
        DhtClient { id, pending: None }
    }

    // bootstrap into the DHT. seeds are address-only (no NodeID known yet)
    // so they get empty [0u8;32] IDs. we ask them "which nodes are closest to me?"
    // and their responses give us NodeIDs to populate our routing table
    pub fn start_join(&mut self, seeds: &[SocketAddr], _routing: &mut RoutingTable) -> Option<(DhtOperation, SocketAddr)> {
        // build the initial shortlist from seed addresses with empty IDs
        let mut shortlist = Vec::new();
        for seed in seeds {
            shortlist.push((NodeID { id: [0u8; 32] }, *seed));
        }

        let mut pending = PendingLookup {
            target: self.id,
            find_value_key: None,
            shortlist,
            queried: HashSet::new(),
            found_value: None,
        };

        // pick the first seed to query
        let next = pending.next_query();
        self.pending = Some(pending);

        match next {
            Some((_id, addr)) => {
                // ask the seed for the nodes closest to us
                let op = DhtOperation::FindNode { sender_id: self.id, target_id: self.id };
                Some((op, addr))
            }
            None => None,
        }
    }

    // start an iterative FIND_NODE for target, the initial candidates come
    // from the routing table (unlike start_join which uses seed addresses)
    // each response feeds new nodes into the shortlist via handle_response,
    // and the lookup ends when the K closest nodes have all been queried
    pub fn start_lookup_node(&mut self, target: NodeID, routing: &RoutingTable) -> Option<(DhtOperation, SocketAddr)> {
        let shortlist = routing.closest_nodes(&target, routing::K);
        let mut pending = PendingLookup {
            target,
            find_value_key: None,
            shortlist,
            queried: HashSet::new(),
            found_value: None,
        };

        let next_query = pending.next_query();
        match next_query {
            Some((_, addr)) => {
                self.pending = Some(pending);
                let op = DhtOperation::FindNode { sender_id: self.id, target_id: target };
                Some((op, addr))
            }
            None => {
                self.pending = Some(pending);
                None
            }
        }
    }

    pub fn start_find_value(&mut self, key: [u8; 32], routing: &RoutingTable) -> Option<(DhtOperation, SocketAddr)> {
        let target = NodeID { id: key };
        let shortlist = routing.closest_nodes(&target, routing::K);
        let mut pending = PendingLookup {
            target,
            find_value_key: Some(key),
            shortlist,
            queried: HashSet::new(),
            found_value: None,
        };

        let next_query = pending.next_query();
        match next_query {
            Some((_, addr)) => {
                self.pending = Some(pending);
                let op = DhtOperation::FindValue { sender_id: self.id, key };
                Some((op, addr))
            }
            None => {
                self.pending = Some(pending);
                None
            }
        }
    }

    pub fn handle_response(&mut self, op: DhtOperation, routing: &mut RoutingTable) -> (Option<(DhtOperation, SocketAddr)>, bool) {
        let mut pending = match self.pending.take() {
            Some(p) => p,
            None => return (None, true),
        };

        match op {
            DhtOperation::Nodes { nodes, .. } => {
                for (id, addr) in nodes {
                    let _ = routing.add_node(id, addr);
                    pending.shortlist.push((id, addr));
                }
            }
            DhtOperation::Value { value, closest_nodes, .. } => {
                for (id, addr) in closest_nodes {
                    let _ = routing.add_node(id, addr);
                    pending.shortlist.push((id, addr));
                }
                if value.is_some() {
                    pending.found_value = value;
                    self.pending = Some(pending);
                    return (None, true);
                }
            }
            // ignore unexpected ops
            _ => {}
        }

        // re-sort by distance to target, keep the K closest
        pending.shortlist.sort_by_key(|(id, _)| pending.target.distance(id).to_vec());
        pending.shortlist.truncate(routing::K);

        let next = pending.next_query();
        match next {
            Some((_, addr)) => {
                let op = match pending.find_value_key {
                    Some(key) => DhtOperation::FindValue { sender_id: self.id, key },
                    None => DhtOperation::FindNode { sender_id: self.id, target_id: pending.target },
                };
                self.pending = Some(pending);
                (Some((op, addr)), false)
            }
            None => {
                self.pending = Some(pending);
                (None, true)
            }
        }
    }

    pub fn result(&self) -> Option<&PendingLookup> {
        self.pending.as_ref()
    }
}