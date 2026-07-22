use std::net::SocketAddr;
use std::time::{Duration, Instant};

use crate::dht::node_id::NodeID;

pub const K: usize = 20;
const PING_COOLDOWN: Duration = Duration::from_secs(60);
const STALE_THRESHOLD: Duration = Duration::from_secs(120);

struct Entry {
    id: NodeID,
    addr: SocketAddr,
    last_seen: Instant,             // last time we got any response from this node
    last_pinged: Option<Instant>,   // last time we sent a ping to it
}

struct Bucket {
    active: Vec<Entry>,
    candidates: Vec<Entry>,
}

impl Bucket {
    fn new() -> Self {
        Bucket { active: Vec::with_capacity(K), candidates: Vec::with_capacity(K) }
    }

    fn entry_position(list: &[Entry], id: &NodeID) -> Option<usize> {
        list.iter().position(|e| e.id == *id)
    }
}

pub struct RoutingTable {
    local_id: NodeID,
    buckets: Vec<Bucket>,
}

impl RoutingTable {
    pub fn new(local_id: NodeID) -> Self {
        let mut buckets = Vec::with_capacity(256);
        for _ in 0..256 {
            buckets.push(Bucket::new());
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

        let idx = self.bucket(&node);
        let bucket = &mut self.buckets[idx];
        let now = Instant::now();

        // already in active
        if let Some(pos) = Bucket::entry_position(&bucket.active, &node) {
            bucket.active.remove(pos);
            bucket.active.push(Entry { id: node, addr, last_seen: now, last_pinged: None });
            return;
        }

        // already in candidates
        if let Some(pos) = Bucket::entry_position(&bucket.candidates, &node) {
            bucket.candidates.remove(pos);
            bucket.candidates.push(Entry { id: node, addr, last_seen: now, last_pinged: None });
            return;
        }

        let entry = Entry { id: node, addr, last_seen: now, last_pinged: None };

        if bucket.active.len() < K {
            bucket.active.push(entry);
        } else if bucket.candidates.len() < K {
            bucket.candidates.push(entry);
        }
        // else: both full, silently dropped
    }

    pub fn remove_node(&mut self, node: &NodeID) {
        let idx = self.bucket(node);
        let bucket = &mut self.buckets[idx];
        bucket.active.retain(|e| e.id != *node);
        bucket.candidates.retain(|e| e.id != *node);
    }

    // return the address of the oldest active entry in the target bucket
    // that hasn't been pinged recently, and mark it as pinged
    pub fn needs_ping(&mut self, target: &NodeID) -> Option<(NodeID, SocketAddr)> {
        let idx = self.bucket(target);
        let bucket = &mut self.buckets[idx];
        let now = Instant::now();

        let oldest = bucket
            .active
            .iter_mut()
            .filter(|e| e.last_pinged.map_or(true, |t| now.duration_since(t) > PING_COOLDOWN))
            .min_by_key(|e| e.last_seen);

        if let Some(entry) = oldest {
            entry.last_pinged = Some(now);
            return Some((entry.id, entry.addr));
        }

        None
    }

    // called when we receive a Pong (or any response) from a node
    pub fn mark_alive(&mut self, node: &NodeID, addr: SocketAddr) {
        let idx = self.bucket(node);
        let bucket = &mut self.buckets[idx];
        let now = Instant::now();

        // update active entry
        if let Some(pos) = Bucket::entry_position(&bucket.active, node) {
            bucket.active.remove(pos);
            bucket.active.push(Entry { id: *node, addr, last_seen: now, last_pinged: None });
            return;
        }

        // update candidate entry
        if let Some(pos) = Bucket::entry_position(&bucket.candidates, node) {
            bucket.candidates.remove(pos);
            bucket.candidates.push(Entry { id: *node, addr, last_seen: now, last_pinged: None });
        }
    }

    // move stale active entries (pinged but no pong within STALE_THRESHOLD)
    // down to the candidate list, and promote the freshest candidate up.
    // also drop stale candidates.
    pub fn evict_stale(&mut self) {
        let now = Instant::now();

        for bucket in &mut self.buckets {
            // drop stale candidates
            bucket.candidates.retain(|e| {
                now.duration_since(e.last_seen) < STALE_THRESHOLD
            });

            // move stale active entries to candidates
            let mut i = 0;
            while i < bucket.active.len() {
                let is_stale = bucket.active[i].last_pinged
                    .map_or(false, |pinged| now.duration_since(pinged) > STALE_THRESHOLD
                        && bucket.active[i].last_seen < pinged);

                if is_stale {
                    let stale = bucket.active.remove(i);
                    if bucket.candidates.len() < K {
                        bucket.candidates.push(stale);
                    }
                } else {
                    i += 1;
                }
            }

            // promote freshest candidates to fill active up to K
            while bucket.active.len() < K && !bucket.candidates.is_empty() {
                let best_idx = bucket
                    .candidates
                    .iter()
                    .enumerate()
                    .max_by_key(|(_, e)| e.last_seen)
                    .map(|(i, _)| i);

                if let Some(idx) = best_idx {
                    let entry = bucket.candidates.remove(idx);
                    bucket.active.push(entry);
                }
            }
        }
    }

    pub fn closest_nodes(&self, target: &NodeID, n: usize) -> Vec<(NodeID, SocketAddr)> {
        let mut out = Vec::new();
        let start = self.bucket(target);

        for e in &self.buckets[start].active {
            out.push((e.id, e.addr));
        }

        let mut above = start.wrapping_sub(1);
        let mut below = start + 1;
        while (above < 256 || below < 256) && out.len() < n {
            if above < 256 {
                for e in &self.buckets[above].active {
                    out.push((e.id, e.addr));
                }
                above = above.wrapping_sub(1);
            }
            if below < 256 {
                for e in &self.buckets[below].active {
                    out.push((e.id, e.addr));
                }
                below += 1;
            }
        }

        out.sort_by_key(|(id, _)| target.distance(id).to_vec());
        out.truncate(n);
        out
    }
}
