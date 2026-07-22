use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

use crate::dht::node_id::NodeID;
use crate::protocol::wire::take_bytes;

pub const MAX_VALUE_SIZE: usize = 1024; // TODO

pub enum DhtOperation {
    Ping { sender_id: NodeID },
    Pong { sender_id: NodeID },
    FindNode { sender_id: NodeID, target_id: NodeID },
    Nodes { sender_id: NodeID, nodes: Vec<(NodeID, SocketAddr)> },
    Store { sender_id: NodeID, key: [u8; 32], value: Vec<u8>, ttl_seconds: u32 },
    StoreAck { sender_id: NodeID, key: [u8; 32] },
    FindValue { sender_id: NodeID, key: [u8; 32] },
    Value { sender_id: NodeID, key: [u8; 32], value: Option<Vec<u8>>, closest_nodes: Vec<(NodeID, SocketAddr)> },
}

impl DhtOperation {
    pub fn sender_id(&self) -> NodeID {
        match self {
            Self::Ping { sender_id, .. } => *sender_id,
            Self::Pong { sender_id, .. } => *sender_id,
            Self::FindNode { sender_id, .. } => *sender_id,
            Self::Nodes { sender_id, .. } => *sender_id,
            Self::Store { sender_id, .. } => *sender_id,
            Self::StoreAck { sender_id, .. } => *sender_id,
            Self::FindValue { sender_id, .. } => *sender_id,
            Self::Value { sender_id, .. } => *sender_id,
        }
    }

    fn tag(&self) -> u8 {
        match self {
            DhtOperation::Ping { .. }       => 1,
            DhtOperation::Pong { .. }       => 2,
            DhtOperation::FindNode { .. }   => 3,
            DhtOperation::Nodes { .. }      => 4,
            DhtOperation::Store { .. }      => 5,
            DhtOperation::StoreAck { .. }   => 6,
            DhtOperation::FindValue { .. }  => 7,
            DhtOperation::Value { .. }      => 8,
        }
    }

    fn read_address(bytes: &mut Vec<u8>) -> Result<SocketAddr, String> {
        if bytes.is_empty() {
            return Err("truncated address".to_string());
        }
        let addr_type = bytes.remove(0);
        match addr_type {
            4 => {
                let addr_bytes = take_bytes::<6>(bytes)?;
                let ip = Ipv4Addr::new(addr_bytes[0], addr_bytes[1], addr_bytes[2], addr_bytes[3]);
                let port = u16::from_be_bytes([addr_bytes[4], addr_bytes[5]]);
                Ok(SocketAddr::V4(SocketAddrV4::new(ip, port)))
            }
            6 => {
                let addr_bytes = take_bytes::<18>(bytes)?;
                let mut ip_bytes = [0u8; 16];
                ip_bytes.copy_from_slice(&addr_bytes[..16]);
                let ip = Ipv6Addr::from(ip_bytes);
                let port = u16::from_be_bytes([addr_bytes[16], addr_bytes[17]]);
                Ok(SocketAddr::V6(SocketAddrV6::new(ip, port, 0, 0)))
            }
            _ => Err(format!("unknown address type: {addr_type}")),
        }
    }

    fn write_address(addr: &SocketAddr) -> Vec<u8> {
        let mut buf = Vec::new();
        match addr {
            SocketAddr::V4(a) => {
                buf.push(4);
                buf.extend_from_slice(&a.ip().octets());
                buf.extend_from_slice(&a.port().to_be_bytes());
            }
            SocketAddr::V6(a) => {
                buf.push(6);
                buf.extend_from_slice(&a.ip().octets());
                buf.extend_from_slice(&a.port().to_be_bytes());
            }
        }
        buf
    }

    fn read_nodes(bytes: &mut Vec<u8>) -> Result<Vec<(NodeID, SocketAddr)>, String> {
        if bytes.len() < 2 { return Err("truncated node count".to_string()); }
        let count = u16::from_be_bytes([bytes.remove(0), bytes.remove(0)]) as usize;
        let mut nodes = Vec::with_capacity(count);
        for _ in 0..count {
            let id_bytes = take_bytes::<32>(bytes)?;
            let node_id = NodeID { id: id_bytes };
            let addr = Self::read_address(bytes)?;
            nodes.push((node_id, addr));
        }
        Ok(nodes)
    }

    fn write_nodes(nodes: &[(NodeID, SocketAddr)]) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&(nodes.len() as u16).to_be_bytes());
        for (id, addr) in nodes {
            buf.extend_from_slice(&id.id);
            buf.extend_from_slice(&Self::write_address(addr));
        }
        buf
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = vec![self.tag()];
        match self {
            DhtOperation::Ping { sender_id } => {
                buf.extend_from_slice(&sender_id.id);
            }
            DhtOperation::Pong { sender_id } => {
                buf.extend_from_slice(&sender_id.id);
            }
            DhtOperation::FindNode { sender_id, target_id } => {
                buf.extend_from_slice(&sender_id.id);
                buf.extend_from_slice(&target_id.id);
            }
            DhtOperation::Nodes { sender_id, nodes } => {
                buf.extend_from_slice(&sender_id.id);
                buf.extend_from_slice(&Self::write_nodes(nodes));
            }
            DhtOperation::Store { sender_id, key, value, ttl_seconds } => {
                buf.extend_from_slice(&sender_id.id);
                buf.extend_from_slice(key);
                buf.extend_from_slice(&ttl_seconds.to_be_bytes());
                buf.extend_from_slice(&(value.len() as u16).to_be_bytes());
                buf.extend_from_slice(value);
            }
            DhtOperation::StoreAck { sender_id, key } => {
                buf.extend_from_slice(&sender_id.id);
                buf.extend_from_slice(key);
            }
            DhtOperation::FindValue { sender_id, key } => {
                buf.extend_from_slice(&sender_id.id);
                buf.extend_from_slice(key);
            }
            DhtOperation::Value { sender_id, key, value, closest_nodes } => {
                buf.extend_from_slice(&sender_id.id);
                buf.extend_from_slice(key);
                match value {
                    Some(v) => {
                        buf.push(1);
                        buf.extend_from_slice(&(v.len() as u16).to_be_bytes());
                        buf.extend_from_slice(v);
                    }
                    None => { buf.push(0); }
                }
                buf.extend_from_slice(&Self::write_nodes(closest_nodes));
            }
        }
        buf
    }

    pub fn from_serialized(mut bytes: Vec<u8>) -> Result<Self, String> {
        if bytes.is_empty() {
            return Err("empty dht packet".to_string());
        }
        let tag = bytes.remove(0);

        fn read_id(bytes: &mut Vec<u8>) -> Result<NodeID, String> {
            Ok(NodeID { id: take_bytes(bytes)? })
        }

        fn read_key(bytes: &mut Vec<u8>) -> Result<[u8; 32], String> {
            take_bytes(bytes)
        }

        match tag {
            1 => Ok(DhtOperation::Ping { sender_id: read_id(&mut bytes)? }),
            2 => Ok(DhtOperation::Pong { sender_id: read_id(&mut bytes)? }),
            3 => {
                let sender_id = read_id(&mut bytes)?;
                let target_id = read_id(&mut bytes)?;
                Ok(DhtOperation::FindNode { sender_id, target_id })
            }
            4 => {
                let sender_id = read_id(&mut bytes)?;
                let nodes = DhtOperation::read_nodes(&mut bytes)?;
                Ok(DhtOperation::Nodes { sender_id, nodes })
            }
            5 => {
                let sender_id = read_id(&mut bytes)?;
                let key = read_key(&mut bytes)?;
                let ttl_bytes = take_bytes::<4>(&mut bytes)?;
                let ttl_seconds = u32::from_be_bytes(ttl_bytes);
                let value_len = u16::from_be_bytes([bytes.remove(0), bytes.remove(0)]) as usize;
                if bytes.len() < value_len { return Err("truncated value".to_string()); }
                let value = bytes.drain(..value_len).collect();
                Ok(DhtOperation::Store { sender_id, key, value, ttl_seconds })
            }
            6 => {
                let sender_id = read_id(&mut bytes)?;
                let key = read_key(&mut bytes)?;
                Ok(DhtOperation::StoreAck { sender_id, key })
            }
            7 => {
                let sender_id = read_id(&mut bytes)?;
                let key = read_key(&mut bytes)?;
                Ok(DhtOperation::FindValue { sender_id, key })
            }
            8 => {
                let sender_id = read_id(&mut bytes)?;
                let key = read_key(&mut bytes)?;
                if bytes.is_empty() { return Err("truncated value packet".to_string()); }
                let has_value = bytes.remove(0);
                let value = if has_value == 1 {
                    if bytes.len() < 2 { return Err("truncated value length".to_string()); }
                    let vlen = u16::from_be_bytes([bytes.remove(0), bytes.remove(0)]) as usize;
                    if bytes.len() < vlen { return Err("truncated value".to_string()); }
                    Some(bytes.drain(..vlen).collect())
                } else {
                    None
                };
                let closest_nodes = DhtOperation::read_nodes(&mut bytes)?;
                Ok(DhtOperation::Value { sender_id, key, value, closest_nodes })
            }
            _ => Err(format!("unknown dht packet tag: {tag}")),
        }
    }
}
