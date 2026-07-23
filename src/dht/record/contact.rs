use std::net::{IpAddr, SocketAddr};

use crate::identity::certificates::DeviceCertificate;

// published record telling peers how to reach this device through a relay and how to verify its handshake
pub struct ContactRecord {
    // certificate linking this device's keys to the master identity
    pub device_cert: DeviceCertificate,
    // address of the relay this device is registered with
    pub relay_addr: SocketAddr,
    // the device's ID on that relay (for RelayFrame::new)
    pub relay_id: u128,
}

impl ContactRecord {
    // convenience: the X25519 public key from the device certificate
    pub fn device_x25519_pub(&self) -> &[u8; 32] {
        self.device_cert.device_x25519_pubkey.as_bytes()
    }

    pub fn new(
        device_cert: DeviceCertificate,
        relay_addr: SocketAddr,
        relay_id: u128,
    ) -> Self {
        Self { device_cert, relay_addr, relay_id }
    }

    // format: [x25519_pub: 32] [cert: 128] [addr_kind: u8] [addr: 4|16] [port: u16] [relay_id: u128]
    pub fn serialize(&self) -> Vec<u8> {
        let cert_bytes = self.device_cert.serialize();
        let addr_bytes = match self.relay_addr.ip() {
            IpAddr::V4(v4) => {
                let mut b = Vec::with_capacity(7);
                b.push(0x04); // IPv4
                b.extend_from_slice(&v4.octets());
                b.extend_from_slice(&self.relay_addr.port().to_be_bytes());
                b
            }
            IpAddr::V6(v6) => {
                let mut b = Vec::with_capacity(19);
                b.push(0x06); // IPv6
                b.extend_from_slice(&v6.octets());
                b.extend_from_slice(&self.relay_addr.port().to_be_bytes());
                b
            }
        };

        let mut bytes = Vec::with_capacity(128 + addr_bytes.len() + 16);
        bytes.extend_from_slice(&cert_bytes);
        bytes.extend_from_slice(&addr_bytes);
        bytes.extend_from_slice(&self.relay_id.to_be_bytes());
        bytes
    }

    pub fn from_serialized(bytes: Vec<u8>) -> Result<Self, String> {
        // minimum: 128 (cert) + 7 (IPv4 addr) + 16 (relay_id) = 151
        if bytes.len() < 151 {
            return Err("contact record too short".to_string());
        }

        let cert_bytes = bytes[..128].to_vec();
        let device_cert = DeviceCertificate::from_serialized(cert_bytes)
            .map_err(|e| format!("bad device cert: {e}"))?;

        let addr_kind = bytes[128];
        let addr_start = 129;

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

        Ok(Self { device_cert, relay_addr, relay_id })
    }
}