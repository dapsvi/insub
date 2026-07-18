use std::net::{SocketAddr, UdpSocket};

use crate::protocol::packet::Packet;

pub struct UdpTransport {
    socket: UdpSocket,
}

impl UdpTransport {
    pub fn bind(addr: SocketAddr) -> Result<Self, std::io::Error> {
        let socket = UdpSocket::bind(addr)?;
        Ok(Self { socket })
    }

    // raw bytes (handshake phase)

    pub fn send_to_bytes(&self, data: &[u8], dest: SocketAddr) -> Result<usize, std::io::Error> {
        self.socket.send_to(data, dest)
    }

    pub fn recv_bytes(&self) -> Result<(Vec<u8>, SocketAddr), std::io::Error> {
        let mut buf = [0u8; 65536];
        let (len, sender) = self.socket.recv_from(&mut buf)?;
        Ok((buf[..len].to_vec(), sender))
    }

    // packets (messaging phase)

    pub fn send_to(&self, packet: &Packet, dest: SocketAddr) -> Result<usize, std::io::Error> {
        self.socket.send_to(&packet.serialize(), dest)
    }

    pub fn recv_from(&self) -> Result<(Packet, SocketAddr), std::io::Error> {
        let mut buf = [0u8; 65536];
        let (len, sender) = self.socket.recv_from(&mut buf)?;
        let packet = Packet::from_serialized(buf[..len].to_vec())
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        Ok((packet, sender))
    }
}
