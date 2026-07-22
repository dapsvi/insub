pub mod crypto;
pub mod protocol;
pub mod identity;
pub mod transport;
pub mod network;
pub mod dht;
pub mod runtime;

use std::net::SocketAddr;
use std::path::Path;
use std::thread;
use std::time::Duration;

use dht::node_id::NodeID;
use identity::identity::MasterKeyPair;
use identity::keychain::Keychain;
use network::relay::RelayNode;
use network::registry::{self, RelayEntry, RelayRegistry};
use network::relay::RelayFrame;
use protocol::message::Message;
use protocol::packet::Packet;
use protocol::payload::{Payload, PayloadTag};
use protocol::session::Session;
use rand::RngExt;
use runtime::Runtime;
use transport::udp::UdpTransport;
use x25519_dalek::{PublicKey, StaticSecret};

fn relay_wrap(dest_id: u128, inner_packet: &Packet) -> Packet {
    let frame = RelayFrame::new(dest_id, inner_packet.serialize());
    let payload = Payload::new(PayloadTag::RelayFrame, frame.serialize());
    Packet::new(1, 0, rand::rng().random(), [0u8; 12], payload)
}

fn main() {
    let password = Some("test-password");

    // ----- identities -----
    let (alice_master, _) = MasterKeyPair::new();
    let (bob_master, _) = MasterKeyPair::new();

    // ----- device keychains -----
    let (_, alice_mnemonic) = Keychain::new(Path::new("/tmp/insub-alice.keychain"), password).unwrap();
    let alice_keychain = Keychain::load(Path::new("/tmp/insub-alice.keychain"), password).unwrap();
    println!("[alice] device mnemonic: {}", alice_mnemonic);

    let (_, bob_mnemonic) = Keychain::new(Path::new("/tmp/insub-bob.keychain"), password).unwrap();
    let bob_keychain = Keychain::load(Path::new("/tmp/insub-bob.keychain"), password).unwrap();
    println!("[bob] device mnemonic: {}", bob_mnemonic);

    let bob_device_pub = PublicKey::from(&StaticSecret::from(bob_keychain.device_x25519_priv));

    // ----- relay IDs -----
    let alice_id = registry::derive_id(&alice_master.public_key.to_bytes());
    let bob_id = registry::derive_id(&bob_master.public_key.to_bytes());

    let alice_addr: SocketAddr = "127.0.0.1:9000".parse().unwrap();
    let bob_addr: SocketAddr = "127.0.0.1:9001".parse().unwrap();
    let relay_addr: SocketAddr = "127.0.0.1:8000".parse().unwrap();

    // ----- DHT: multi-relay network -----
    println!("--- DHT multi-relay network ---");
    const NUM_RELAYS: usize = 3;
    let mut relay_ids = Vec::new();
    let mut relay_addrs = Vec::new();
    for i in 0..NUM_RELAYS {
        let (m, _) = MasterKeyPair::new();
        relay_ids.push(NodeID::from_pubkey(&m.public_key.to_bytes()));
        relay_addrs.push(format!("127.0.0.1:{}", 8000 + i).parse::<SocketAddr>().unwrap());
    }

    // start relay 0 as the seed
    let mut relay0 = Runtime::bind(relay_ids[0], relay_addrs[0]).unwrap();
    relay0.enable_server();
    let _r0 = thread::spawn(move || { relay0.serve_forever(); });
    thread::sleep(Duration::from_millis(100));

    // relays 1..N join the network
    for i in 1..NUM_RELAYS {
        let mut r = Runtime::bind(relay_ids[i], relay_addrs[i]).unwrap();
        r.enable_server();
        r.join(&[relay_addrs[0]]).unwrap();
        println!("[relay-{i}] joined via relay-0");

        thread::spawn(move || { r.serve_forever(); });
        thread::sleep(Duration::from_millis(50));
    }

    // leaf: join via relay 0, store and find
    let leaf_addr: SocketAddr = "127.0.0.1:9100".parse().unwrap();
    let leaf_id = NodeID::from_pubkey(&alice_master.public_key.to_bytes());
    let mut leaf = Runtime::bind(leaf_id, leaf_addr).unwrap();
    leaf.join(&[relay_addrs[0]]).unwrap();
    println!("[leaf] joined network");

    let dht_key: [u8; 32] = {
        let mut k = [0u8; 32];
        k[..11].copy_from_slice(b"network-key");
        k
    };
    leaf.store(dht_key, b"stored on the DHT network".to_vec(), 300).unwrap();
    println!("[leaf] stored value across {NUM_RELAYS} relays");

    let (found, _) = leaf.find_value(dht_key).unwrap();
    assert_eq!(found, Some(b"stored on the DHT network".to_vec()));
    println!("[leaf] found value back");

    println!("[dht] multi-relay tests passed");

    // ----- relay forwarding + messaging -----
    println!("--- messaging test ---");

    let mut registry = RelayRegistry::new();
    registry.add(
        RelayEntry::new(alice_id, alice_master.public_key.to_bytes(), alice_addr).unwrap(),
    );
    registry.add(
        RelayEntry::new(bob_id, bob_master.public_key.to_bytes(), bob_addr).unwrap(),
    );

    let mut relay_node = RelayNode::bind(8070, registry).unwrap();
    let _relay = thread::spawn(move || relay_node.run());
    thread::sleep(Duration::from_millis(100));

    let alice_thread = thread::spawn(move || {
        let udp = UdpTransport::bind(alice_addr).unwrap();
        let mut session = Session::new_initiator(
            &alice_keychain.device_x25519_priv,
            bob_device_pub.as_bytes(),
        ).unwrap();

        let msg1 = session.initiate_handshake().unwrap();
        let hp = Payload::new(PayloadTag::Handshake, msg1);
        let hpkt = Packet::new(1, 0, rand::rng().random(), [0u8; 12], hp);
        udp.send_to(&relay_wrap(bob_id, &hpkt), relay_addr).unwrap();

        let (resp, _) = udp.recv_from().unwrap();
        session.complete_handshake(&resp.payload.data).unwrap();
        println!("[alice] handshake complete");

        let msg = Message::new("hello from alice".to_string(), None);
        let mpkt = session.send(&msg).unwrap();
        udp.send_to(&relay_wrap(bob_id, &mpkt), relay_addr).unwrap();

        let (rpkt, _) = udp.recv_from().unwrap();
        let reply = session.receive(&rpkt).unwrap();
        println!("[alice] received: {}", reply.content);
        assert_eq!(reply.reply_to.unwrap(), msg.id);

        let _ = std::fs::remove_file("/tmp/insub-alice.keychain");
    });

    let bob_thread = thread::spawn(move || {
        let udp = UdpTransport::bind(bob_addr).unwrap();
        let mut session = Session::new_responder(&bob_keychain.device_x25519_priv).unwrap();

        let (pkt, _) = udp.recv_from().unwrap();
        session.accept_handshake(&pkt.payload.data).unwrap();

        let msg2 = session.reply_handshake().unwrap();
        let hp = Payload::new(PayloadTag::Handshake, msg2);
        let hpkt = Packet::new(1, 0, rand::rng().random(), [0u8; 12], hp);
        udp.send_to(&relay_wrap(alice_id, &hpkt), relay_addr).unwrap();
        println!("[bob] handshake complete");

        let (mpkt, _) = udp.recv_from().unwrap();
        let received = session.receive(&mpkt).unwrap();
        println!("[bob] received: {}", received.content);

        let reply = Message::new("got it!".to_string(), Some(received.id));
        let rpkt = session.send(&reply).unwrap();
        udp.send_to(&relay_wrap(alice_id, &rpkt), relay_addr).unwrap();

        let _ = std::fs::remove_file("/tmp/insub-bob.keychain");
    });

    alice_thread.join().unwrap();
    bob_thread.join().unwrap();

    println!("ok");
}
