use std::collections::{HashMap, HashSet, VecDeque};
use std::net::SocketAddr;
use std::sync::mpsc::{Receiver, SendError};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::Duration;

use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::RngExt;
use sha2::{Sha256, Digest};
use crate::dht::client::DhtClient;
use crate::dht::node::DhtNode;
use crate::dht::node_id::NodeID;
use crate::dht::protocol::DhtOperation;
use crate::dht::record::contact::ContactRecord;
use crate::dht::record::record::{Record, RecordTag};
use crate::dht::routing::RoutingTable;
use crate::network::registry::{self, RelayRegistry};
use crate::network::relay::{RelayForwarder, RelayFrame};
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
    sessions: HashMap<[u8; 16], Session>,
    pending_sessions: HashMap<[u8; 16], (Session, Option<[u8; 32]>)>,
    conn_to_pk: HashMap<[u8; 16], [u8; 32]>,
    pk_to_conn: HashMap<[u8; 32], [u8; 16]>,
    pk_to_addr: HashMap<[u8; 32], SocketAddr>,
    seen_tags: HashSet<[u8; 16]>,
    device_x25519_priv: [u8; 32],

    out_tx: mpsc::Sender<(Packet, SocketAddr)>,
    ack_tx: mpsc::Sender<(u128, SocketAddr)>,
    msg_tx: mpsc::Sender<(Message, [u8; 32])>,
    msg_rx: Option<mpsc::Receiver<(Message, [u8; 32])>>,

    master_pubkey: Option<[u8; 32]>,
    device_cert: Option<DeviceCertificate>,
    peer_keys: Arc<Mutex<HashMap<SocketAddr, VerifyingKey>>>,

    relay_addr: Option<SocketAddr>,
}

impl Runtime {
    pub fn bind(id: NodeID, addr: SocketAddr, signing_key: Option<SigningKey>, device_x25519_priv: [u8; 32]) -> Result<Self, String> {
        let peer_keys = Arc::new(Mutex::new(HashMap::<SocketAddr, VerifyingKey>::new()));

        let transport = ReliableTransport::bind(addr, signing_key, peer_keys.clone())
            .map_err(|err| format!("Couldn't bind to address : {err}"))?;

        let dht_pile = PacketPile::new();
        let relay_pile = PacketPile::new();
        let handshake_pile = PacketPile::new();
        let message_pile = PacketPile::new();
        let (out_tx, out_rx) = mpsc::channel::<(Packet, SocketAddr)>();
        let (ack_tx, ack_rx) = mpsc::channel::<(u128, SocketAddr)>();
        let (msg_tx, msg_rx) = mpsc::channel::<(Message, [u8; 32])>();
        let actual_addr = transport.local_addr().unwrap_or(addr);

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
            address: actual_addr,
            dht_pile,
            relay_pile,
            handshake_pile,
            message_pile,
            relay_fwd: None,
            sessions: HashMap::new(),
            pending_sessions: HashMap::new(),
            conn_to_pk: HashMap::new(),
            pk_to_conn: HashMap::new(),
            pk_to_addr: HashMap::new(),
            seen_tags: HashSet::new(),
            device_x25519_priv,
            out_tx,
            ack_tx,
            msg_tx,
            msg_rx: Some(msg_rx),
            master_pubkey: None,
            device_cert: None,
            peer_keys,
            relay_addr: None,
        })
    }

    pub fn enable_server(&mut self) {
        self.server = Some(DhtNode::new(self.id, self.address));
    }

    pub fn enable_relay(&mut self, registry: RelayRegistry) {
        self.relay_fwd = Some(RelayForwarder::new(registry));
    }

    pub fn set_master_pubkey(&mut self, pk: [u8; 32]) {
        self.master_pubkey = Some(pk);
    }

    pub fn set_device_cert(&mut self, cert: DeviceCertificate) {
        self.device_cert = Some(cert);
    }

    pub fn set_relay(&mut self, addr: SocketAddr) {
        self.relay_addr = Some(addr);
    }

    pub fn subscribe(&mut self) -> Receiver<(Message, [u8; 32])> {
        self.msg_rx.take().expect("already subscribed")
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.address
    }

    pub fn set_peer_addr(&mut self, pk: [u8; 32], addr: SocketAddr) {
        self.pk_to_addr.insert(pk, addr);
    }

    fn send_packet(&self, pkt: Packet, relay_addr: SocketAddr, relay_id: u128) -> Result<(), String> {
        let frame = RelayFrame::new(relay_id, pkt.serialize());
        let wrapped = Packet::new(
            0,
            rand::rng().random(),
            Payload::new(PayloadTag::RelayFrame, frame.serialize()),
        );
        eprintln!("Sending packet to {}", relay_addr);
        let _ = self.out_tx.send((wrapped, relay_addr));
        Ok(())
    }

    pub fn enable_session_initiator(
        &mut self,
        peer_device_x25519_pub: &[u8; 32],
        peer_user_id: UserID,
    ) -> Result<[u8; 16], String> {
        let our_master_pubkey = self.master_pubkey
            .ok_or("master pubkey not set")?;

        let peer_pk = peer_user_id.public_key.to_bytes();
        let device_cert = self.device_cert.clone().ok_or("No device certificate available".to_string())?;
        let session = Session::new_initiator(
            &self.device_x25519_priv,
            peer_device_x25519_pub,
            device_cert,
            our_master_pubkey,
            peer_user_id,
        )?;

        let mut tag = [0u8; 16];
        tag.copy_from_slice(&rand::rng().random::<u128>().to_be_bytes());
        self.pending_sessions.insert(tag, (session, Some(peer_pk)));
        Ok(tag)
    }

    fn spawn_responder(&mut self) -> Result<Session, String> {
        let cert = self.device_cert.clone()
            .ok_or("device cert not set")?;
        let master_pk = self.master_pubkey
            .ok_or("master pubkey not set")?;
        Session::new_responder(&self.device_x25519_priv, cert, master_pk)
    }

    // DHT section

    pub fn join(&mut self, seeds: &[SocketAddr]) -> Result<(), String> {
        let mut next = self.client.start_join(seeds, &mut self.routing);

        // only query the seed directly; skip iterative lookups that fan out
        // to stale nodes lingering in the seed's routing table
        let mut queries = 0;
        while let Some((op, addr)) = next {
            if queries > 0 {
                break;
            }
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
            queries += 1;
        }

        Ok(())
    }

    pub fn lookup_node(&mut self, target: NodeID) -> Result<Vec<(NodeID, SocketAddr)>, String> {
        let mut next = self.client.start_lookup_node(target, &self.routing);

        let mut queries = 0;
        while let Some((op, addr)) = next {
            if queries > 1 {
                break;
            }
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
            queries += 1;
        }

        let result = self.client.result().ok_or("no lookup result")?;
        Ok(result.shortlist.clone())
    }

    pub fn find_value(&mut self, key: [u8; 32]) -> Result<(Option<Vec<u8>>, Vec<(NodeID, SocketAddr)>), String> {
        let mut next = self.client.start_find_value(key, &self.routing);

        let mut queries = 0;
        while let Some((op, addr)) = next {
            if queries > 2 {
                break;
            }
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
            queries += 1;
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

    // contact records (DHT publish and lookup)

    fn contact_key_for(master_pubkey: &[u8; 32]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"contact");
        hasher.update(master_pubkey);
        hasher.finalize().into()
    }

    pub fn publish_contact(
        &mut self,
        relay_addr: SocketAddr,
        relay_id: u128,
        ttl: u32,
    ) -> Result<(), String> {
        let cert = self.device_cert.as_ref()
            .ok_or("device cert not set")?;
        let contact = ContactRecord::new(cert.clone(), relay_addr, relay_id);
        let record = Record::new(RecordTag::Contact, contact.serialize());
        let master = self.master_pubkey
            .ok_or("master pubkey not set")?;
        let key = Self::contact_key_for(&master);
        self.store(key, record.serialize(), ttl)
    }

    pub fn find_contact(&mut self, master_pubkey: &[u8; 32]) -> Result<ContactRecord, String> {
        let key = Self::contact_key_for(master_pubkey);
        let (value, _) = self.find_value(key)?;
        let data = value.ok_or("no contact record found")?;
        let record = Record::from_serialized(data)?;
        if record.tag != RecordTag::Contact {
            return Err("unexpected record type".to_string());
        }
        ContactRecord::from_serialized(record.data)
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
        loop {
            let item = self.dht_pile.pop_timeout(Duration::from_millis(100));
            match item {
                Some((packet, sender)) => {
                    if self.server.is_some() {
                        if let Ok(op) = DhtOperation::from_serialized(packet.payload.data.clone()) {
                            match &op {
                                DhtOperation::Ping { .. } => eprintln!("[dht] Ping from {sender}"),
                                DhtOperation::FindNode { target_id, .. } => eprintln!("[dht] FindNode from {sender} for {:02x?}", &target_id.id[..4]),
                                DhtOperation::FindValue { key, .. } => eprintln!("[dht] FindValue from {sender} for {:02x?}", &key[..4]),
                                DhtOperation::Store { key, .. } => eprintln!("[dht] Store from {sender} for {:02x?}", &key[..4]),
                                _ => {}
                            }
                            if let Some(ref mut srv) = self.server {
                                if let Some((response, dest)) = srv.process(&packet, sender, &mut self.routing) {
                                    self.send_dht_op(&response, dest);
                                }
                            }
                        }
                    }
                    if packet.header.flags.contains(PacketFlag::AckRequired) {
                        let _ = self.confirm(packet.header.id, sender);
                    }
                }
                None => break,
            }
        }
        self.routing.evict_stale();
    }

    pub fn tick_relay(&mut self) {
        if self.relay_fwd.is_none() {
            return;
        }
        let item = self.relay_pile.pop_timeout(Duration::from_millis(100));
        let (packet, sender) = match item {
            Some(item) => item,
            None => return,
        };

        if let Ok(frame) = RelayFrame::from_serialized(packet.payload.data.clone()) {
            let my_id = self.master_pubkey.map(|pk| registry::derive_id(&pk));
            if Some(frame.dest_id) == my_id {
                if let Ok(inner) = Packet::from_serialized(frame.payload) {
                    match inner.payload.tag {
                        PayloadTag::DhtOperation => self.dht_pile.push((inner, sender)),
                        PayloadTag::Handshake => self.handshake_pile.push((inner, sender)),
                        PayloadTag::Message => self.message_pile.push((inner, sender)),
                        _ => {}
                    }
                }
                if packet.header.flags.contains(PacketFlag::AckRequired) {
                    let _ = self.confirm(packet.header.id, sender);
                }
                return;
            }
        }

        let fwd = self.relay_fwd.as_ref().unwrap();
        if let Some((inner, dest)) = fwd.resolve(&packet) {
            let _ = self.out_tx.send((inner, dest));
            if fwd.should_confirm(&packet) {
                let _ = self.confirm(packet.header.id, sender);
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

    pub fn tick_handshake(&mut self) {
        let (packet, sender) = match self.handshake_pile.pop_timeout(Duration::from_millis(100)) {
            Some(item) => item,
            None => return,
        };

        let tag: [u8; 16] = packet.payload.connection_id;

        eprintln!("Received handshake packet from {}, tag {:?}", sender, &tag[..4]);

        // try pending initiators first (look up by echoed tag)
        let mut promoted = None;
        let mut reply_pkt: Option<(Packet, SocketAddr, [u8; 32])> = None;

        if let Some((session, peer_pk_opt)) = self.pending_sessions.get_mut(&tag) {
            if session.is_initiator() {
                if let Ok(()) = session.complete_handshake(&packet.payload.data) {
                    eprintln!("Handshake successfully completed as initiator");
                    if let Some(conn_id) = session.connection_id() {
                        if let Some(cert) = session.peer_certificate() {
                            self.peer_keys.lock().unwrap().insert(sender, cert.device_ed25519_pubkey);
                        }
                        let peer_pk = peer_pk_opt.ok_or("").unwrap_or([0u8; 32]);
                        promoted = Some((tag, conn_id, peer_pk));
                    }
                }
            }
        }

        if promoted.is_none() {
            if self.seen_tags.contains(&tag) {
                return;
            }
            if let Ok(mut session) = self.spawn_responder() {
                if session.accept_handshake(&packet.payload.data).is_ok() {
                    let peer_pk = session.peer_master_pubkey().unwrap_or([0u8; 32]);

                    if let Some(addr) = session.peer_addr() {
                        self.pk_to_addr.insert(peer_pk, addr);
                    }
                    eprintln!("Handshake successfully accepted as responder, peer pk {}, peer address {}", hex::encode(peer_pk), self.pk_to_addr[&peer_pk]);

                    if let Ok(reply) = session.reply_handshake() {
                        eprintln!("preparing handshake reply...");
                        let mut payload = Payload::new(PayloadTag::Handshake, reply);
                        payload.connection_id = tag;
                        let pkt = Packet::new(0, rand::rng().random(), payload);
                        let addr = self.pk_to_addr.get(&peer_pk).copied()
                            .unwrap_or(sender);
                        reply_pkt = Some((pkt, addr, peer_pk));
                        eprintln!("reply packet prepared");
                    }

                    if let Some(conn_id) = session.connection_id() {
                        if let Some(cert) = session.peer_certificate() {
                            self.peer_keys.lock().unwrap().insert(sender, cert.device_ed25519_pubkey);
                        }
                        self.conn_to_pk.insert(conn_id, peer_pk);
                        self.pk_to_conn.entry(peer_pk).or_insert(conn_id);
                        self.sessions.insert(conn_id, session);
                        self.seen_tags.insert(tag);
                    }
                }
            }
        }

        if let Some((tag, conn_id, peer_pk)) = promoted {
            if let Some((session, _)) = self.pending_sessions.remove(&tag) {
                self.conn_to_pk.insert(conn_id, peer_pk);
                self.pk_to_conn.insert(peer_pk, conn_id);
                self.sessions.insert(conn_id, session);
            }
        }

        // send any deferred reply
        if let Some((pkt, addr, peer_pk)) = reply_pkt {
            let relay_id = registry::derive_id(&peer_pk);
            let _ = self.send_packet(pkt, addr, relay_id);
        }

        if packet.header.flags.contains(PacketFlag::AckRequired) {
            let _ = self.confirm(packet.header.id, sender);
        }
    }

    pub fn first_active_conn_id(&self) -> Option<[u8; 16]> {
        for (conn_id, session) in &self.sessions {
            if session.is_established() {
                return Some(*conn_id);
            }
        }
        None
    }

    pub fn session_established(&self, conn_id: &[u8; 16]) -> bool {
        self.sessions.get(conn_id).map_or(false, |s| s.is_established())
    }

    pub fn initiate_handshake(&mut self, tag: [u8; 16]) -> Result<(), String> {
        let our_addr = self.local_addr();
        let (bytes, peer_pk) = {
            let (session, peer_pk_opt) = self.pending_sessions.get_mut(&tag)
                .ok_or("unknown pending tag")?;
            let peer_pk = *peer_pk_opt.as_ref()
                .ok_or("initiator must have peer_pk")?;
            let bytes = session.initiate_handshake(our_addr)?;
            (bytes, peer_pk)
        };

        let mut payload = Payload::new(PayloadTag::Handshake, bytes);
        payload.connection_id = tag;
        let pkt = Packet::new(0, rand::rng().random(), payload);
        let addr = *self.pk_to_addr.get(&peer_pk)
            .ok_or("peer address not set")?;
        let relay_id = registry::derive_id(&peer_pk);
        eprintln!("sending handshake to {}", addr);
        self.send_packet(pkt, addr, relay_id)
    }

    pub fn tick_message(&mut self) {
        let (packet, sender) = match self.message_pile.pop_timeout(Duration::from_millis(100)) {
            Some(item) => item,
            None => return,
        };


        let conn_id = packet.payload.connection_id;
        let session = match self.sessions.get_mut(&conn_id) {
            Some(s) => s,
            None => return,
        };
        let (msg, sender_pk) = match session.receive(&packet) {
            Ok(m) => m,
            Err(_) => return,
        };
        let _ = self.msg_tx.send((msg, sender_pk));

        if packet.header.flags.contains(PacketFlag::AckRequired) {
            let _ = self.confirm(packet.header.id, sender);
        }
    }

    pub fn send_message(&mut self, msg: Message, peer_pk: [u8; 32]) -> Result<(), String> {
        let conn_id = *self.pk_to_conn.get(&peer_pk)
            .ok_or("no session for peer")?;
        let addr = *self.pk_to_addr.get(&peer_pk)
            .ok_or("no address for peer")?;
        let relay_id = registry::derive_id(&peer_pk);
        let pkt = self.sessions.get_mut(&conn_id).unwrap().send(&msg)
            .map_err(|e| format!("session send: {e}"))?;
        self.send_packet(pkt, addr, relay_id)
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