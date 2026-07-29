use std::net::{IpAddr, SocketAddr};

use crate::identity::devices::DeviceList;

// published record telling peers how to reach this device through a relay and how to verify its handshake
#[derive(Clone)]
pub struct ContactRecord {
    // certificate linking this device's keys to the master identity
    pub device_list: DeviceList,
    // address of the relay this device is registered with
    pub relay_addr: SocketAddr,
    // the device's ID on that relay (for RelayFrame::new)
    pub relay_id: u128,
}

impl ContactRecord {
    pub fn new(
        device_list: DeviceList,
        relay_addr: SocketAddr,
        relay_id: u128,
    ) -> Self {
        Self { device_list, relay_addr, relay_id }
    }

    // [list_len: u16 BE] [list_bytes] [addr_kind: u8] [addr: 4|16] [port: u16] [relay_id: u128]
    pub fn serialize(&self) -> Vec<u8> {
        let list_bytes = self.device_list.serialize();
        let addr_bytes = match self.relay_addr.ip() {
            IpAddr::V4(v4) => {
                let mut b = Vec::with_capacity(7);
                b.push(0x04);
                b.extend_from_slice(&v4.octets());
                b.extend_from_slice(&self.relay_addr.port().to_be_bytes());
                b
            }
            IpAddr::V6(v6) => {
                let mut b = Vec::with_capacity(19);
                b.push(0x06);
                b.extend_from_slice(&v6.octets());
                b.extend_from_slice(&self.relay_addr.port().to_be_bytes());
                b
            }
        };

        let mut bytes = Vec::with_capacity(2 + list_bytes.len() + addr_bytes.len() + 16);
        bytes.extend_from_slice(&(list_bytes.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&list_bytes);
        bytes.extend_from_slice(&addr_bytes);
        bytes.extend_from_slice(&self.relay_id.to_be_bytes());
        bytes
    }

    pub fn from_serialized(bytes: Vec<u8>) -> Result<Self, String> {
        if bytes.len() < 2 + 128 + 7 + 16 {
            return Err("contact record too short".to_string());
        }

        let list_len = u16::from_be_bytes([bytes[0], bytes[1]]) as usize;
        if bytes.len() < 2 + list_len {
            return Err("contact record truncated at device list".to_string());
        }
        let list_bytes = bytes[2..2 + list_len].to_vec();
        let device_list = DeviceList::from_serialized(list_bytes)
            .map_err(|e| format!("bad device list: {e}"))?;

        let cursor = 2 + list_len;
        let addr_kind = bytes[cursor];
        let addr_start = cursor + 1;

        let (relay_addr, relay_start) = match addr_kind {
            0x04 => {
                if bytes.len() < addr_start + 6 {
                    return Err("contact record truncated at IPv4 addr".to_string());
                }
                let octets: [u8; 4] = bytes[addr_start..addr_start + 4].try_into().unwrap();
                let port = u16::from_be_bytes(
                    bytes[addr_start + 4..addr_start + 6].try_into().unwrap(),
                );
                (SocketAddr::new(IpAddr::V4(octets.into()), port), addr_start + 6)
            }
            0x06 => {
                if bytes.len() < addr_start + 18 {
                    return Err("contact record truncated at IPv6 addr".to_string());
                }
                let octets: [u8; 16] = bytes[addr_start..addr_start + 16].try_into().unwrap();
                let port = u16::from_be_bytes(
                    bytes[addr_start + 16..addr_start + 18].try_into().unwrap(),
                );
                (SocketAddr::new(IpAddr::V6(octets.into()), port), addr_start + 18)
            }
            other => return Err(format!("unknown addr kind: 0x{other:02x}")),
        };

        if bytes.len() < relay_start + 16 {
            return Err("contact record truncated at relay id".to_string());
        }

        let relay_id = u128::from_be_bytes(
            bytes[relay_start..relay_start + 16].try_into().unwrap(),
        );

        Ok(Self { device_list, relay_addr, relay_id })
    }
}