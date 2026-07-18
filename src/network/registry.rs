use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

use sha2::{Digest, Sha256};

pub struct RelayEntry {
    pub id: u128,
    pub pubkey: [u8; 32],
    pub address: SocketAddr,
}

pub fn derive_id(pubkey: &[u8; 32]) -> u128 {
    let mut hasher = Sha256::new();
    hasher.update(pubkey);
    hasher.update("relay_id");

    let result = hasher.finalize();
    let id_bytes: [u8; 16] = result[..16].try_into().unwrap();
    u128::from_be_bytes(id_bytes)
}

impl RelayEntry {
    pub fn new(id: u128, pubkey: [u8; 32], address: SocketAddr) -> Result<Self, String> {
        let entry = RelayEntry { id: id, pubkey, address };
        // verify the ID
        if id != derive_id(&pubkey) {
            return Err("Invalid ID".to_string())
        }
        Ok(entry)
    }

    pub fn serialize(&self) -> Vec<u8> {
        let addr_size = match self.address {
            SocketAddr::V4(_) => 1 + 4 + 2,  // type + ipv4 + port
            SocketAddr::V6(_) => 1 + 16 + 2, // type + ipv6 + port
        };
        let mut bytes = Vec::with_capacity(128/8 + 32 + addr_size);
        bytes.extend_from_slice(&self.id.to_be_bytes());
        bytes.extend_from_slice(&self.pubkey);

        match self.address {
            SocketAddr::V4(addr) => {
                bytes.push(4); // IPv4 marker
                bytes.extend_from_slice(&addr.ip().octets());
                bytes.extend_from_slice(&addr.port().to_be_bytes());
            }
            SocketAddr::V6(addr) => {
                bytes.push(6); // IPv6 marker
                bytes.extend_from_slice(&addr.ip().octets());
                bytes.extend_from_slice(&addr.port().to_be_bytes());
            }
        };

        bytes
    }

    pub fn from_serialized(bytes: Vec<u8>) -> Result<Self, String> {
        let id_bytes = bytes[..16].try_into().unwrap();
        let id = u128::from_be_bytes(id_bytes);

        let pubkey: [u8; 32] = bytes[16..48].try_into().unwrap();

        let address_marker = bytes[48];
        let address_bytes = bytes[49..].to_vec();
        let address = match address_marker {
            4 => {
                // IPv4 expects exactly 6 bytes: 4 for IP + 2 for port
                if address_bytes.len() != 6 {
                    return Err("Invalid IPv4 address length".to_string());
                }

                // Extract the 4 IP bytes
                let ip = Ipv4Addr::new(
                    address_bytes[0], 
                    address_bytes[1], 
                    address_bytes[2], 
                    address_bytes[3]
                );

                // Extract the 2 port bytes (big-endian)
                let port = u16::from_be_bytes([address_bytes[4], address_bytes[5]]);

                SocketAddr::V4(SocketAddrV4::new(ip, port))
            },
            6 => {
                // IPv6 expects exactly 18 bytes: 16 for IP + 2 for port
                if address_bytes.len() != 18 {
                    return Err("Invalid IPv6 address length".to_string());
                }
                
                // Extract the 16 IP bytes
                let ip_bytes: [u8; 16] = address_bytes[..16].try_into()
                    .map_err(|_| "Failed to parse IPv6 IP bytes".to_string())?;
                    
                let ip = Ipv6Addr::from(ip_bytes);
                
                // Extract the 2 port bytes
                let port = u16::from_be_bytes([address_bytes[16], address_bytes[17]]);
                
                // Note: SocketAddrV6::new also requires flowinfo and scope_id, which we set to 0 as they weren't serialized.
                SocketAddr::V6(SocketAddrV6::new(ip, port, 0, 0))
            },
            _ => {
                return Err("Invalid address marker".to_string());
            }
        };

        Ok(RelayEntry { id, pubkey, address })
    }
}

pub struct RelayRegistry {
    registry: Vec<RelayEntry>,
}

impl RelayRegistry {
    pub fn new() -> Self {
        RelayRegistry {
            registry: Vec::new(),
        }
    }

    pub fn add(&mut self, entry: RelayEntry) {
        self.registry.push(entry);
    }

    pub fn lookup(&self, id: u128) -> Option<&RelayEntry> {
        self.registry.iter().find(|entry| entry.id == id)
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&(self.registry.len() as u32).to_be_bytes());
        for entry in &self.registry {
            let entry_bytes = entry.serialize();
            bytes.extend_from_slice(&(entry_bytes.len() as u32).to_be_bytes());
            bytes.extend_from_slice(&entry_bytes);
        }
        bytes
    }

    pub fn from_serialized(mut bytes: Vec<u8>) -> Result<Self, String> {
        if bytes.len() < 4 {
            return Err("registry too short".to_string());
        }
        let count = u32::from_be_bytes(bytes.drain(..4).collect::<Vec<u8>>().try_into().unwrap()) as usize;

        let mut registry = Vec::with_capacity(count);
        for _ in 0..count {
            if bytes.len() < 4 {
                return Err("truncated entry length prefix".to_string());
            }
            let entry_len = u32::from_be_bytes(bytes.drain(..4).collect::<Vec<u8>>().try_into().unwrap()) as usize;
            if bytes.len() < entry_len {
                return Err("truncated entry bytes".to_string());
            }
            let entry_bytes = bytes.drain(..entry_len).collect::<Vec<u8>>();
            let entry = RelayEntry::from_serialized(entry_bytes)?;
            registry.push(entry);
        }

        Ok(RelayRegistry { registry })
    }

    pub fn remove(&mut self, id: u128) {
        self.registry.retain(|entry| entry.id != id);
    }
}

pub struct RelayAnnouncement {
    signature: [u8; 64],
    entry: RelayEntry,
}

pub struct PeerId {
    pub id: u128,
}

impl PeerId {
    pub fn from_master_pubkey(pubkey: &[u8; 32]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(pubkey);
        hasher.update(b"peer_id");

        let result = hasher.finalize();
        let id_bytes: [u8; 16] = result[..16].try_into().unwrap();
        let id = u128::from_be_bytes(id_bytes);

        PeerId { id }
    }
}