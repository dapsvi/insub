use std::net::{SocketAddr, UdpSocket};

pub struct UdpTransport {
    socket: UdpSocket,
}

impl UdpTransport {
    pub fn bind(addr: SocketAddr) -> Result<Self, std::io::Error> {
        let socket = UdpSocket::bind(addr)?;
        Ok(Self { socket })
    }

    pub fn send_to(&self, data: &[u8], dest: SocketAddr) -> Result<usize, std::io::Error> {
        self.socket.send_to(data, dest)
    }

    pub fn recv_from(&self) -> Result<(Vec<u8>, SocketAddr), std::io::Error> {
        let mut buf = [0u8; 65536];
        let (len, sender) = self.socket.recv_from(&mut buf)?;
        Ok((buf[..len].to_vec(), sender))
    }
}
