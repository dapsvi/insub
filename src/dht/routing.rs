use std::net::SocketAddr;

use crate::dht::node_id::NodeID;

pub const K: usize = 20;

pub struct RoutingTable {
    local_id: NodeID,
    buckets: Vec<Vec<(NodeID, SocketAddr)>>,
}

impl RoutingTable {
    pub fn new(local_id: NodeID) -> Self {
        let mut buckets = Vec::with_capacity(256);
        for _ in 0..256 {
            buckets.push(Vec::new());
        }
        RoutingTable { local_id, buckets }
    }

    fn bucket(&self, node: &NodeID) -> usize {
        self.local_id
            .leading_zero_bits(node)
            .unwrap_or(255)
    }

    pub fn add_node(&mut self, node: NodeID, addr: SocketAddr) {
        if node == self.local_id {
            return;
        }
        let bucket_index = self.bucket(&node);
        let bucket = &mut self.buckets[bucket_index];

        if let Some(pos) = bucket.iter().position(|(n, _)| *n == node) {
            bucket.remove(pos);
            bucket.push((node, addr));
            return;
        }

        if bucket.len() < K {
            bucket.push((node, addr));
        }
    }

    pub fn remove_node(&mut self, node: &NodeID) {
        let bucket_index = self.bucket(node);
        self.buckets[bucket_index]
            .retain(|(n, _)| *n != *node);
    }

    pub fn closest_nodes(&self, target: &NodeID, n: usize) -> Vec<(NodeID, SocketAddr)> {
        let mut candidates = Vec::new();
        let start = self.bucket(target);

        candidates.extend(self.buckets[start].iter().cloned());

        let mut above = start.wrapping_sub(1);
        let mut below = start + 1;
        while (above < 256 || below < 256) && candidates.len() < n {
            if above < 256 {
                candidates.extend(self.buckets[above].iter().cloned());
                above = above.wrapping_sub(1);
            }
            if below < 256 {
                candidates.extend(self.buckets[below].iter().cloned());
                below += 1;
            }
        }

        candidates.sort_by_key(|(node, _)| {
            let dist = target.distance(node);
            dist.to_vec()
        });
        candidates.truncate(n);
        candidates
    }
}
