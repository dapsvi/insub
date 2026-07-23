use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::mpsc::{Receiver, SendError};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::Duration;

use ed25519_dalek::SigningKey;
use rand::RngExt;

use crate::dht::client::DhtClient;
use crate::dht::node::DhtNode;
use crate::dht::node_id::NodeID;
use crate::dht::protocol::DhtOperation;
use crate::dht::routing::RoutingTable;
use crate::network::registry::RelayRegistry;
use crate::network::relay::RelayForwarder;
use crate::identity::certificates::DeviceCertificate;
use crate::identity::identity::UserID;
use crate::protocol::message::Message;
use crate::protocol::payload::{Payload, PayloadTag};
use crate::protocol::packet::{Packet, PacketFlag};
use crate::protocol::session::Session;
use crate::transport::reliable::ReliableTransport;

// FIFO queue shared between producer and consumer.
// rejected items are pushed back to the end so they don't block newer items at the front.
pub struct PacketPile {
    inner: Arc<Mutex<VecDeque<(Packet, SocketAddr)>>>,
}

impl PacketPile {
    fn new() -> Self {
        PacketPile { inner: Arc::new(Mutex::new(VecDeque::new())) }
    }

    fn push(&self, item: (Packet, SocketAddr)) {
        self.inner.lock().unwrap().push_back(item);
    }

    fn pop_timeout(&self, timeout: Duration) -> Option<(Packet, SocketAddr)> {
        let deadline = std::time::Instant::now() + timeout;
        loop {
            {
                let mut pile = self.inner.lock().unwrap();
                if let Some(item) = pile.pop_front() {
                    return Some(item);
                }
            }
            if std::time::Instant::now() >= deadline {
                return None;
            }
            thread::sleep(Duration::from_millis(50));
        }
    }
}

impl Clone for PacketPile {
    fn clone(&self) -> Self {
        PacketPile { inner: self.inner.clone() }
    }
}

pub struct Runtime {
    routing: RoutingTable,
    client: DhtClient,
    server: Option<DhtNode>,
    id: NodeID,
    address: SocketAddr,

    dht_pile: PacketPile,
    relay_pile: PacketPile,
    handshake_pile: PacketPile,
    message_pile: PacketPile,
    relay_fwd: Option<RelayForwarder>,
    session: Option<Session>,
    device_x25519_priv: [u8; 32],
    peer_pubkey: Option<[u8; 32]>,
    out_tx: mpsc::Sender<(Packet, SocketAddr)>,
    ack_tx: mpsc::Sender<(u128, SocketAddr)>,
    msg_tx: Option<mpsc::Sender<Message>>,
}

impl Runtime {
    pub fn bind(id: NodeID, addr: SocketAddr, signing_key: Option<SigningKey>, device_x25519_priv: [u8; 32]) -> Result<Self, String> {
        let transport = ReliableTransport::bind(addr, signing_key)
            .map_err(|err| format!("Couldn't bind to address : {err}"))?;

        let dht_pile = PacketPile::new();
        let relay_pile = PacketPile::new();
        let handshake_pile = PacketPile::new();
        let message_pile = PacketPile::new();
        let (out_tx, out_rx) = mpsc::channel::<(Packet, SocketAddr)>();
        let (ack_tx, ack_rx) = mpsc::channel::<(u128, SocketAddr)>();

        // sorting thread: reads from transport, dispatches to piles.
        // also handles outbound sends and acks so the Runtime
        // never touches the transport directly.
        let sort_dht = dht_pile.clone();
        let sort_relay = relay_pile.clone();
        let sort_handshake = handshake_pile.clone();
        let sort_message = message_pile.clone();
        
        thread::spawn(move || loop {
            while let Ok((packet, dest)) = out_rx.try_recv() {
                let _ = transport.send(&packet, dest);
            }
            while let Ok((id, dest)) = ack_rx.try_recv() {
                transport.confirm(id, dest);
            }

            match transport.recv_timeout(Duration::from_millis(500)) {
                Ok((packet, sender)) => {
                    match packet.payload.tag {
                        PayloadTag::DhtOperation => sort_dht.push((packet, sender)),
                        PayloadTag::RelayFrame => sort_relay.push((packet, sender)),
                        PayloadTag::Handshake => sort_handshake.push((packet, sender)),
                        PayloadTag::Message => sort_message.push((packet, sender)),
                        _ => {}
                    }
                }
                Err(_) => {}
            }
        });

        Ok(Runtime {
            routing: RoutingTable::new(id),
            client: DhtClient::new(id),
            server: None,
            id,
            address: addr,
            dht_pile,
            relay_pile,
            handshake_pile,
            message_pile,
            relay_fwd: None,
            session: None,
            device_x25519_priv,
            peer_pubkey: None,
            out_tx,
            ack_tx,
            msg_tx: None,
        })
    }

    pub fn enable_server(&mut self) {
        self.server = Some(DhtNode::new(self.id, self.address));
    }

    pub fn enable_relay(&mut self, registry: RelayRegistry) {
        self.relay_fwd = Some(RelayForwarder::new(registry));
    }

    pub fn enable_session_initiator(
        &mut self,
        peer_device_x25519_pub: &[u8; 32],
        device_cert: DeviceCertificate,
        peer_user_id: UserID,
    ) -> Result<Receiver<Message>, String> {
        let (msg_tx, msg_rx) = mpsc::channel::<Message>();
        self.session = Some(Session::new_initiator(
            &self.device_x25519_priv,
            peer_device_x25519_pub,
            device_cert,
            peer_user_id,
        )?);
        self.msg_tx = Some(msg_tx);
        self.peer_pubkey = Some(*peer_device_x25519_pub);
        Ok(msg_rx)
    }

    pub fn enable_session_responder(
        &mut self,
        device_cert: DeviceCertificate,
    ) -> Result<Receiver<Message>, String> {
        let (msg_tx, msg_rx) = mpsc::channel::<Message>();
        self.session = Some(Session::new_responder(
            &self.device_x25519_priv,
            device_cert,
        )?);
        self.msg_tx = Some(msg_tx);
        Ok(msg_rx)
    }

    // DHT section

    pub fn join(&mut self, seeds: &[SocketAddr]) -> Result<(), String> {
        let mut next = self.client.start_join(seeds, &mut self.routing);

        while let Some((op, addr)) = next {
            self.send_dht_op(&op, addr);
            let (response, sender) = self.recv_dht(addr)?;
            if let Some((_ping_id, ping_addr)) = self.routing.add_node(response.sender_id(), sender) {
                let ping = DhtOperation::Ping { sender_id: self.id };
                self.send_dht_op(&ping, ping_addr);
            }

            let (maybe_next, done) = self.client.handle_response(response, &mut self.routing);

            if done {
                break;
            }

            next = maybe_next;
        }

        Ok(())
    }

    pub fn lookup_node(&mut self, target: NodeID) -> Result<Vec<(NodeID, SocketAddr)>, String> {
        let mut next = self.client.start_lookup_node(target, &self.routing);

        while let Some((op, addr)) = next {
            self.send_dht_op(&op, addr);
            let (response, sender) = self.recv_dht(addr)?;
            if let Some((_ping_id, ping_addr)) = self.routing.add_node(response.sender_id(), sender) {
                let ping = DhtOperation::Ping { sender_id: self.id };
                self.send_dht_op(&ping, ping_addr);
            }

            let (maybe_next, done) = self.client.handle_response(response, &mut self.routing);

            if done {
                break;
            }

            next = maybe_next;
        }

        let result = self.client.result().ok_or("no lookup result")?;
        Ok(result.shortlist.clone())
    }

    pub fn find_value(&mut self, key: [u8; 32]) -> Result<(Option<Vec<u8>>, Vec<(NodeID, SocketAddr)>), String> {
        let mut next = self.client.start_find_value(key, &self.routing);

        while let Some((op, addr)) = next {
            self.send_dht_op(&op, addr);
            let (response, sender) = self.recv_dht(addr)?;
            if let Some((_ping_id, ping_addr)) = self.routing.add_node(response.sender_id(), sender) {
                let ping = DhtOperation::Ping { sender_id: self.id };
                self.send_dht_op(&ping, ping_addr);
            }

            let (maybe_next, done) = self.client.handle_response(response, &mut self.routing);

            if done {
                break;
            }

            next = maybe_next;
        }

        let result = self.client.result().ok_or("no lookup result")?;
        Ok((result.found_value.clone(), result.shortlist.clone()))
    }

    pub fn store(&mut self, key: [u8; 32], value: Vec<u8>, ttl: u32) -> Result<(), String> {
        let target = NodeID { id: key };
        let closest = self.lookup_node(target)?;

        if closest.is_empty() {
            return Err("store failed: no nodes known to store to".to_string());
        }

        for (_, addr) in &closest {
            let op = DhtOperation::Store {
                sender_id: self.id,
                key,
                value: value.clone(),
                ttl_seconds: ttl,
            };
            self.send_dht_op(&op, *addr);
        }

        Ok(())
    }

    // pull from dht_pile until we get a response-type packet from the
    // expected address. server queries and wrong-sender packets go back
    // onto the pile for later dispatch by run().
    fn recv_dht(&self, expected: SocketAddr) -> Result<(DhtOperation, SocketAddr), String> {
        let deadline = std::time::Instant::now() + Duration::from_secs(5);

        loop {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                return Err("dht recv timed out".to_string());
            }

            let (packet, sender) = self.dht_pile
                .pop_timeout(remaining)
                .ok_or("dht recv timed out")?;

            // wrong sender, or it's a packet the client shouldn't consume
            if sender != expected || skip_in_lookup(&packet) {
                self.dht_pile.push((packet, sender));
                continue;
            }

            let op = DhtOperation::from_serialized(packet.payload.data)
                .map_err(|e| format!("bad dht response: {e}"))?;
            if packet.header.flags.contains(PacketFlag::AckRequired) {
                let _ = self.confirm(packet.header.id, sender);
            }
            return Ok((op, sender));
        }
    }

    pub fn serve_forever(&mut self) {
        loop {
            self.tick_server();
            self.tick_relay();
            self.tick_handshake();
            self.tick_message();
        }
    }

    pub fn tick_server(&mut self) {
        let item = self.dht_pile.pop_timeout(Duration::from_millis(100));
        if let Some((packet, sender)) = item {
            let is_valid = DhtOperation::from_serialized(packet.payload.data.clone()).is_ok();
            if let Some(ref mut srv) = self.server {
                if let Some((response, dest)) = srv.process(&packet, sender, &mut self.routing) {
                    self.send_dht_op(&response, dest);
                }
            }
            if is_valid && packet.header.flags.contains(PacketFlag::AckRequired) {
                let _ = self.confirm(packet.header.id, sender);
            }
        }
        self.routing.evict_stale();
    }

    fn tick_relay(&mut self) {
        let fwd = match self.relay_fwd.as_ref() {
            Some(f) => f,
            None => return,
        };
        let item = self.relay_pile.pop_timeout(Duration::from_millis(100));
        if let Some((packet, sender)) = item {
            if let Some((inner, dest)) = fwd.resolve(&packet) {
                let _ = self.out_tx.send((inner, dest));
                if fwd.should_confirm(&packet) {
                    let _ = self.confirm(packet.header.id, sender);
                }
            }
        }
    }

    fn send_dht_op(&self, op: &DhtOperation, dest: SocketAddr) {
        let payload = Payload::new(PayloadTag::DhtOperation, op.serialize());
        let pkt = Packet::new(0, rand::rng().random(), payload);
        let _ = self.out_tx.send((pkt, dest));
    }

    fn confirm(&self, id: u128, dest: SocketAddr) -> Result<(), SendError<(u128, SocketAddr)>> {
        self.ack_tx.send((id, dest))
    }

    fn tick_handshake(&mut self) {
        let session = match self.session.as_mut() {
            Some(s) if !s.is_established() => s,
            _ => return,            // no session or already done
        };

        let (packet, sender) = match self.handshake_pile.pop_timeout(Duration::from_millis(100)) {
            Some(item) => item,
            None => return,
        };

        if session.is_initiator() {
            // we already called initiate_handshake, this packet is the response
            let _ = session.complete_handshake(&packet.payload.data);
        } else{
            // we're the responder: accept the hello, send our reply
            if session.accept_handshake(&packet.payload.data).is_ok() {
                if let Ok(reply) = session.reply_handshake() {
                    let payload = Payload::new(PayloadTag::Handshake, reply);
                    let pkt = Packet::new(0, rand::rng().random(), payload);
                    let _ = self.out_tx.send((pkt, sender));
                }
            }
        }

        if packet.header.flags.contains(PacketFlag::AckRequired) {
            let _ = self.confirm(packet.header.id, sender);
        }
    }

    pub fn initiate_handshake(&mut self, dest: SocketAddr) -> Result<(), String> {
        let bytes = self.session.as_mut()
            .unwrap()
            .initiate_handshake()?;

        let payload = Payload::new(PayloadTag::Handshake, bytes);
        let pkt = Packet::new(0, rand::rng().random(), payload);
        let _ = self.out_tx.send((pkt, dest));

        Ok(())
    }

    fn tick_message(&mut self) {
        if self.session.is_none() {
            return
        }
        if !self.session.as_ref().unwrap().is_established() {
            return
        }

        let (packet, sender) = match self.message_pile.pop_timeout(Duration::from_millis(100)) {
            Some(item) => item,
            None => return,
        };
        let msg = match self.session.as_mut().unwrap().receive(&packet) {
            Ok(m) => m,
            Err(_) => return,
        };
        let _ = self.msg_tx.as_ref().unwrap().send(msg);

        if packet.header.flags.contains(PacketFlag::AckRequired) {
            let _ = self.confirm(packet.header.id, sender);
        }
    }

    pub fn send_message(&mut self, msg: Message, dest: SocketAddr) {
        let pkt = match self.session.as_mut().unwrap().send(&msg) {
            Ok(p) => p,
            Err(_) => return,
        };
        let _ = self.out_tx.send((pkt, dest));
    }
}

// return true if the packet should NOT be consumed by the client lookup.
// server queries (1,3,5,7) and irrelevant responses (2,6) go back on the pile.
fn skip_in_lookup(packet: &Packet) -> bool {
    let data = &packet.payload.data;
    if data.is_empty() {
        return false;
    }
    matches!(data[0], 1 | 2 | 3 | 5 | 6 | 7)  // Ping, Pong, FindNode, Store, StoreAck, FindValue
}