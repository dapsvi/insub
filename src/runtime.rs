use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::Duration;

use crate::dht::client::DhtClient;
use crate::dht::node::DhtNode;
use crate::dht::node_id::NodeID;
use crate::dht::protocol::DhtOperation;
use crate::dht::routing::RoutingTable;
use crate::protocol::payload::{Payload, PayloadTag};
use crate::protocol::packet::Packet;
use crate::transport::reliable::ReliableTransport;
use rand::RngExt;

// FIFO queue shared between producer and consumer.
// rejected items are pushed back to the end so they don't
// block newer items at the front.
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
    out_tx: mpsc::Sender<(Packet, SocketAddr)>,
}

impl Runtime {
    pub fn bind(id: NodeID, addr: SocketAddr) -> Result<Self, String> {
        let transport = ReliableTransport::bind(addr)
            .map_err(|err| format!("Couldn't bind to address : {err}"))?;

        let dht_pile = PacketPile::new();
        let relay_pile = PacketPile::new();
        let handshake_pile = PacketPile::new();
        let message_pile = PacketPile::new();
        let (out_tx, out_rx) = mpsc::channel::<(Packet, SocketAddr)>();

        // sorting thread: reads from transport, dispatches to piles.
        // also handles outbound sends through out_rx so the Runtime
        // never touches the transport directly.
        let sort_dht = dht_pile.clone();
        let sort_relay = relay_pile.clone();
        let sort_handshake = handshake_pile.clone();
        let sort_message = message_pile.clone();
        thread::spawn(move || loop {
            while let Ok((packet, dest)) = out_rx.try_recv() {
                let _ = transport.send(&packet, dest);
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
            out_tx,
        })
    }

    pub fn enable_server(&mut self) {
        self.server = Some(DhtNode::new(self.id, self.address));
    }

    // DHT section

    pub fn join(&mut self, seeds: &[SocketAddr]) -> Result<(), String> {
        let mut next = self.client.start_join(seeds, &mut self.routing);

        while let Some((op, addr)) = next {
            self.send_dht_op(&op, addr);
            let (response, sender) = self.recv_dht(addr)?;
            self.routing.add_node(response.sender_id(), sender);

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
            self.routing.add_node(response.sender_id(), sender);

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
            self.routing.add_node(response.sender_id(), sender);

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
        loop {
            let (packet, sender) = self.dht_pile
                .pop_timeout(Duration::from_secs(5))
                .ok_or("dht recv timed out")?;

            // wrong sender, or it's a packet the client shouldn't consume
            if sender != expected || skip_in_lookup(&packet) {
                self.dht_pile.push((packet, sender));
                continue;
            }

            let op = DhtOperation::from_serialized(packet.payload.data)
                .map_err(|e| format!("bad dht response: {e}"))?;
            return Ok((op, sender));
        }
    }

    pub fn tick_server(&mut self) {
        let item = self.dht_pile.pop_timeout(Duration::from_millis(100));
        if let Some((packet, sender)) = item {
            if let Some(ref mut srv) = self.server {
                if let Some((response, dest)) = srv.process(&packet, sender) {
                    self.send_dht_op(&response, dest);
                }
            }
        }
    }

    pub fn serve_forever(&mut self) {
        loop {
            self.tick_server();
        }
    }

    fn send_dht_op(&self, op: &DhtOperation, dest: SocketAddr) {
        let payload = Payload::new(PayloadTag::DhtOperation, op.serialize());
        let pkt = Packet::new(1, 0, rand::rng().random(), [0u8; 12], payload);
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