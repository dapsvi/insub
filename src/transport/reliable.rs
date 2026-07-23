use std::collections::HashMap;
use std::net::{SocketAddr, UdpSocket};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

use crate::protocol::packet::{flag_to_int, Packet, PacketFlag, PacketFlags};
use crate::protocol::payload::{Payload, PayloadTag};
use crate::transport::fragment::{self, Reassembler};

const MAX_RETRIES: u8 = 5;
const RETRY_DELAY: Duration = Duration::from_secs(2);
const RECV_TIMEOUT: Duration = Duration::from_millis(500);

struct Pending {
    serialized: Vec<u8>,
    dest: SocketAddr,
    retries: u8,
    last_sent: Instant,
}

// Reliable UDP transport with ack/retransmission.
// Acks are Ed25519-signed to prevent forgery by relays.
pub struct ReliableTransport {
    socket: UdpSocket,
    pending: Arc<Mutex<HashMap<u128, Pending>>>,
    recv_rx: mpsc::Receiver<(Packet, SocketAddr)>,
    signing_key: Option<SigningKey>,
    peer_keys: Arc<Mutex<HashMap<SocketAddr, VerifyingKey>>>,
    reassembler: Arc<Mutex<Reassembler>>,
}

impl ReliableTransport {
    // Bind to a socket and start the recv thread.
    // signing_key is the local Ed25519 key used to sign outgoing Acks.
    pub fn bind(addr: SocketAddr, signing_key: Option<SigningKey>) -> Result<Self, std::io::Error> {
        let socket = UdpSocket::bind(addr)?;
        let recv_socket = socket.try_clone()?;
        let pending = Arc::new(Mutex::new(HashMap::<u128, Pending>::new()));
        let pending_clone = pending.clone();
        let peer_keys = Arc::new(Mutex::new(HashMap::<SocketAddr, VerifyingKey>::new()));
        let peer_keys_clone = peer_keys.clone();
        let reassembler = Arc::new(Mutex::new(Reassembler::new()));
        let reassembler_clone = reassembler.clone();

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
                        let mut packet = match Packet::from_serialized(buf[..len].to_vec()) {
                            Ok(p) => p,
                            Err(_) => continue,
                        };

                        // reassemble fragments before anything else
                        if packet.payload.fragment_id != 0 {
                            let mut reasm = reassembler_clone.lock().unwrap();
                            packet = match reasm.feed(&packet, sender) {
                                Some(complete) => complete,
                                None => continue, // fragment stored, not complete yet
                            };
                        }

                        if packet.header.flags.contains(PacketFlag::Ack) {
                            let mut pending = pending_clone.lock().unwrap();
                            let should_remove = verify_ack(
                                &packet,
                                &pending,
                                &peer_keys_clone,
                                sender,
                            );
                            if should_remove {
                                pending.remove(&packet.header.id);
                            }
                            continue;
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

                        if tx.send((packet, sender)).is_err() {
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
                        // drop stale fragment reassemblies
                        reassembler_clone.lock().unwrap().evict_stale();
                    }
                    Err(_) => break,
                }
            }
        });

        Ok(Self {
            socket,
            pending,
            recv_rx: rx,
            signing_key,
            peer_keys,
            reassembler,
        })
    }

    // send a Packet reliably (sets AckRequired) and fragments large packets
    pub fn send(&self, packet: &Packet, dest: SocketAddr) -> Result<(), std::io::Error> {
        for mut frag in fragment::split_packet(packet) {
            // add AckRequired to each fragment
            let mut flags = frag.header.flags.to_int();
            flags |= flag_to_int(PacketFlag::AckRequired);
            frag.header.flags = PacketFlags::from_int(flags);

            let serialized = frag.serialize();
            self.socket.send_to(&serialized, dest)?;

            self.pending.lock().unwrap().insert(
                frag.header.id,
                Pending {
                    serialized,
                    dest,
                    retries: 0,
                    last_sent: Instant::now(),
                },
            );
        }

        Ok(())
    }

    // send an Ack for a received packet. call this from the application
    // layer after the packet has been successfully handled or forwarded,
    // not on raw socket receive. if a signing key is configured, the Ack
    // carries pubkey || signature so the sender can verify it.
    pub fn confirm(&self, id: u128, dest: SocketAddr) {
        let payload = match &self.signing_key {
            Some(key) => {
                let mut data = Vec::with_capacity(96);
                data.extend_from_slice(key.verifying_key().as_bytes());
                data.extend_from_slice(&key.sign(&id.to_be_bytes()).to_bytes());
                data
            }
            None => vec![],
        };
        let ack_flags = PacketFlags::from_int(flag_to_int(PacketFlag::Ack));
        let ack = Packet::new(
            ack_flags.to_int(),
            id,
            Payload::new(PayloadTag::KeepAlive, payload),
        );
        let _ = self.socket.send_to(&ack.serialize(), dest);
    }

    pub fn recv(&self) -> Result<(Packet, SocketAddr), String> {
        self.recv_rx
            .recv()
            .map_err(|_| "recv thread died".to_string())
    }

    pub fn recv_timeout(&self, timeout: Duration) -> Result<(Packet, SocketAddr), String> {
        self.recv_rx
            .recv_timeout(timeout)
            .map_err(|_| "recv timed out or thread died".to_string())
    }

    // expose the underlying socket for unreliable sends (handshake phase)
    pub fn socket(&self) -> &UdpSocket {
        &self.socket
    }

    // store the expected Ed25519 pubkey for a peer so that its signed Acks
    // can be verified from the first exchange onward (avoids TOFU).
    pub fn set_peer_pubkey(&self, addr: SocketAddr, pubkey: VerifyingKey) {
        self.peer_keys.lock().unwrap().insert(addr, pubkey);
    }
}

// examine an incoming Ack and decide whether to accept it.
// returns true if the pending entry should be removed.
fn verify_ack(
    packet: &Packet,
    pending: &HashMap<u128, Pending>,
    peer_keys: &Mutex<HashMap<SocketAddr, VerifyingKey>>,
    sender: SocketAddr,
) -> bool {
    let entry = match pending.get(&packet.header.id) {
        Some(e) => e,
        None => return false,
    };

    // only accept Acks from the address we sent to
    if entry.dest != sender {
        return false;
    }

    // unsigned Ack (backwards compat or no signing key configured)
    if packet.payload.data.len() < 96 {
        return true;
    }

    // signed Ack: pubkey (32) || signature (64)
    let pubkey_bytes: [u8; 32] = match packet.payload.data[..32].try_into() {
        Ok(b) => b,
        Err(_) => return false,
    };
    let sig_bytes: [u8; 64] = match packet.payload.data[32..96].try_into() {
        Ok(b) => b,
        Err(_) => return false,
    };

    let vk = match VerifyingKey::from_bytes(&pubkey_bytes) {
        Ok(k) => k,
        Err(_) => return false,
    };
    let sig = Signature::from_bytes(&sig_bytes);

    let mut keys = peer_keys.lock().unwrap();

    // if we already know this peer's pubkey, verify against it
    if let Some(expected) = keys.get(&sender) {
        return expected.verify(&packet.header.id.to_be_bytes(), &sig).is_ok();
    }

    // TOFU: first signed Ack from this address, store the pubkey
    keys.insert(sender, vk);
    true
}
