use std::collections::HashMap;
use std::net::{SocketAddr, UdpSocket};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use crate::protocol::packet::{flag_to_int, Packet, PacketFlag, PacketFlags};
use crate::protocol::payload::{Payload, PayloadTag};

const MAX_RETRIES: u8 = 5;
const RETRY_DELAY: Duration = Duration::from_secs(2);
const RECV_TIMEOUT: Duration = Duration::from_millis(500);

struct Pending {
    serialized: Vec<u8>,
    dest: SocketAddr,
    retries: u8,
    last_sent: Instant,
}

// Reliable UDP transport with ack/retransmission
pub struct ReliableTransport {
    socket: UdpSocket,
    pending: Arc<Mutex<HashMap<u128, Pending>>>,
    recv_rx: mpsc::Receiver<Packet>,
}

impl ReliableTransport {
    // Bind to a socket and start the recv thread.
    pub fn bind(addr: SocketAddr) -> Result<Self, std::io::Error> {
        let socket = UdpSocket::bind(addr)?;
        let recv_socket = socket.try_clone()?;
        let pending = Arc::new(Mutex::new(HashMap::<u128, Pending>::new()));
        let pending_clone = pending.clone();

        recv_socket.set_read_timeout(Some(RECV_TIMEOUT))?;

        let (tx, rx) = mpsc::channel();

        thread::spawn(move || {
            let mut buf = [0u8; 65536];
            let mut seen: HashMap<u128, Instant> = HashMap::new();
            let dedup_ttl = Duration::from_secs(300); // 5 min
            let max_seen = 1024;

            loop {
                match recv_socket.recv_from(&mut buf) {
                    Ok((len, sender)) => {
                        let packet = match Packet::from_serialized(buf[..len].to_vec()) {
                            Ok(p) => p,
                            Err(_) => continue,
                        };

                        if packet.header.flags.contains(PacketFlag::Ack) {
                            pending_clone.lock().unwrap().remove(&packet.header.id);
                            continue;
                        }

                        if packet.header.flags.contains(PacketFlag::AckRequired) {
                            let ack_flags = PacketFlags::from_int(flag_to_int(PacketFlag::Ack));
                            let ack = Packet::new(
                                packet.header.version,
                                ack_flags.to_int(),
                                packet.header.id,
                                [0u8; 12],
                                Payload::new(PayloadTag::KeepAlive, vec![]),
                            );
                            let _ = recv_socket.send_to(&ack.serialize(), sender);
                        }

                        // dedup: if we already saw this ID, skip forwarding
                        let now = Instant::now();
                        if let Some(first_seen) = seen.get(&packet.header.id) {
                            if now.duration_since(*first_seen) < dedup_ttl {
                                continue; // duplicate, already forwarded
                            }
                        }

                        // prune old entries, evict oldest if over cap
                        if seen.len() >= max_seen {
                            seen.retain(|_id, ts| now.duration_since(*ts) < dedup_ttl);
                        }
                        if seen.len() >= max_seen {
                            // still full, drop the oldest entry
                            let oldest_key = seen
                                .iter()
                                .min_by_key(|(_, ts)| *ts)
                                .map(|(id, _)| *id);
                            if let Some(key) = oldest_key {
                                seen.remove(&key);
                            }
                        }

                        seen.insert(packet.header.id, now);

                        if tx.send(packet).is_err() {
                            break;
                        }
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        // recv timed out so check pending retransmissions
                        let mut pend = pending_clone.lock().unwrap();
                        let now = Instant::now();
                        pend.retain(|_id, entry| {
                            if entry.retries >= MAX_RETRIES {
                                return false; // give up
                            }
                            if now.duration_since(entry.last_sent) > RETRY_DELAY {
                                entry.last_sent = now;
                                entry.retries += 1;
                                let _ = recv_socket.send_to(&entry.serialized, entry.dest);
                            }
                            true
                        });
                    }
                    Err(_) => break,
                }
            }
        });

        Ok(Self {
            socket,
            pending,
            recv_rx: rx,
        })
    }

    // send a Packet reliably (sets AckRequired)
    pub fn send(&self, packet: &Packet, dest: SocketAddr) -> Result<(), std::io::Error> {
        let mut flags = packet.header.flags.to_int();
        flags |= flag_to_int(PacketFlag::AckRequired);

        let reliable_packet = Packet::new(
            packet.header.version,
            flags,
            packet.header.id,
            packet.header.nonce,
            packet.payload.clone(),
        );

        let serialized = reliable_packet.serialize();
        self.socket.send_to(&serialized, dest)?;

        self.pending.lock().unwrap().insert(
            packet.header.id,
            Pending {
                serialized,
                dest,
                retries: 0,
                last_sent: Instant::now(),
            },
        );

        Ok(())
    }

    // block until a data Packet arrives
    pub fn recv(&self) -> Result<Packet, String> {
        self.recv_rx
            .recv()
            .map_err(|_| "recv thread died".to_string())
    }

    // expose the underlying socket for unreliable sends (handshake phase)
    pub fn socket(&self) -> &UdpSocket {
        &self.socket
    }
}
