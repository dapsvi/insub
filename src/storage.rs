use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use ed25519_dalek::VerifyingKey;

fn write_addr(addr: &SocketAddr, out: &mut Vec<u8>) {
    match addr.ip() {
        IpAddr::V4(v4) => {
            out.push(4);
            out.extend_from_slice(&v4.octets());
        }
        IpAddr::V6(v6) => {
            out.push(6);
            out.extend_from_slice(&v6.octets());
        }
    }
    out.extend_from_slice(&addr.port().to_be_bytes());
}

fn read_addr(bytes: &[u8], cursor: &mut usize) -> Result<SocketAddr, String> {
    if *cursor >= bytes.len() {
        return Err("truncated at addr kind".to_string());
    }
    let kind = bytes[*cursor];
    *cursor += 1;

    match kind {
        4 => {
            if bytes.len() < *cursor + 6 {
                return Err("truncated at IPv4 addr".to_string());
            }
            let octets: [u8; 4] = bytes[*cursor..*cursor + 4].try_into().unwrap();
            let port = u16::from_be_bytes(bytes[*cursor + 4..*cursor + 6].try_into().unwrap());
            *cursor += 6;
            Ok(SocketAddr::new(IpAddr::V4(octets.into()), port))
        }
        6 => {
            if bytes.len() < *cursor + 18 {
                return Err("truncated at IPv6 addr".to_string());
            }
            let octets: [u8; 16] = bytes[*cursor..*cursor + 16].try_into().unwrap();
            let port = u16::from_be_bytes(bytes[*cursor + 16..*cursor + 18].try_into().unwrap());
            *cursor += 18;
            Ok(SocketAddr::new(IpAddr::V6(octets.into()), port))
        }
        other => Err(format!("unknown addr kind: {}", other)),
    }
}

// TOFU peer keys: HashMap<SocketAddr, VerifyingKey>
pub fn serialize_peer_keys(map: &HashMap<SocketAddr, VerifyingKey>) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&(map.len() as u32).to_be_bytes());
    for (addr, vk) in map {
        write_addr(addr, &mut out);
        out.extend_from_slice(vk.as_bytes());
    }
    out
}

pub fn deserialize_peer_keys(bytes: &[u8]) -> Result<HashMap<SocketAddr, VerifyingKey>, String> {
    if bytes.len() < 4 {
        return Err("peer keys too short".to_string());
    }
    let count = u32::from_be_bytes(bytes[..4].try_into().unwrap()) as usize;
    let mut cursor = 4;
    let mut map = HashMap::with_capacity(count);

    for _ in 0..count {
        let addr = read_addr(bytes, &mut cursor)?;
        if bytes.len() < cursor + 32 {
            return Err("truncated at pubkey".to_string());
        }
        let pk_bytes: [u8; 32] = bytes[cursor..cursor + 32].try_into().unwrap();
        cursor += 32;
        let vk = VerifyingKey::from_bytes(&pk_bytes)
            .map_err(|e| format!("bad verifying key: {e}"))?;
        map.insert(addr, vk);
    }

    Ok(map)
}

// pk_to_addr: HashMap<[u8; 32], SocketAddr>
pub fn serialize_pk_to_addr(map: &HashMap<[u8; 32], SocketAddr>) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&(map.len() as u32).to_be_bytes());
    for (pk, addr) in map {
        out.extend_from_slice(pk);
        write_addr(addr, &mut out);
    }
    out
}

pub fn deserialize_pk_to_addr(bytes: &[u8]) -> Result<HashMap<[u8; 32], SocketAddr>, String> {
    if bytes.len() < 4 {
        return Err("pk_to_addr too short".to_string());
    }
    let count = u32::from_be_bytes(bytes[..4].try_into().unwrap()) as usize;
    let mut cursor = 4;
    let mut map = HashMap::with_capacity(count);

    for _ in 0..count {
        if bytes.len() < cursor + 32 {
            return Err("truncated at pubkey".to_string());
        }
        let pk: [u8; 32] = bytes[cursor..cursor + 32].try_into().unwrap();
        cursor += 32;
        let addr = read_addr(bytes, &mut cursor)?;
        map.insert(pk, addr);
    }

    Ok(map)
}
