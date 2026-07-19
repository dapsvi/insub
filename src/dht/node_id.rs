use sha2::{Digest, Sha256};

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct NodeID {
    pub id: [u8; 32],
}

impl NodeID {
    pub fn from_pubkey(pubkey: &[u8; 32]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(pubkey);
        hasher.update(b"dht_node_id");
        let bytes: [u8; 32] = hasher.finalize().into();
        NodeID { id: bytes }
    }

    // XOR distance in Kademlia keyspace
    pub fn distance(&self, other: &NodeID) -> [u8; 32] {
        let mut dist = [0u8; 32];
        for i in 0..32 {
            dist[i] = self.id[i] ^ other.id[i];
        }
        dist
    }

    // index of the first differing bit (0 = MSB of id[0]) and returns None if the two IDs are identical.
    pub fn leading_zero_bits(&self, other: &NodeID) -> Option<usize> {
        let dist = self.distance(other);
        for (i, byte) in dist.iter().enumerate() {
            if *byte != 0 {
                return Some(i * 8 + byte.leading_zeros() as usize);
            }
        }
        None
    }
}

impl std::fmt::Display for NodeID {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.id))
    }
}
