pub mod crypto;
pub mod protocol;
pub mod identity;
pub mod transport;
pub mod network;
pub mod dht;

use std::net::SocketAddr;
use std::path::Path;
use std::thread;
use std::time::Duration;

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
use transport::udp::UdpTransport;
use x25519_dalek::{PublicKey, StaticSecret};

fn relay_wrap(dest_id: u128, inner_packet: &Packet) -> Packet {
    let frame = RelayFrame::new(dest_id, inner_packet.serialize());
    let payload = Payload::new(PayloadTag::RelayFrame, frame.serialize());
    Packet::new(1, 0, rand::rng().random(), [0u8; 12], payload)
}

fn main() {
    let password = Some("test-password");

    // ----- identities (master keys) -----
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

    // ----- pre-seed relay registry -----
    let mut registry = RelayRegistry::new();
    registry.add(
        RelayEntry::new(alice_id, alice_master.public_key.to_bytes(), alice_addr).unwrap(),
    );
    registry.add(
        RelayEntry::new(bob_id, bob_master.public_key.to_bytes(), bob_addr).unwrap(),
    );

    // ----- start relay -----
    let relay_node = RelayNode::bind(8000, registry).unwrap();
    thread::spawn(move || relay_node.run());
    thread::sleep(Duration::from_millis(100));

    // ----- alice thread -----
    let alice_thread = thread::spawn(move || {
        let udp = UdpTransport::bind(alice_addr).unwrap();
        let mut session = Session::new_initiator(
            &alice_keychain.device_x25519_priv,
            bob_device_pub.as_bytes(),
        )
        .unwrap();

        let msg1 = session.initiate_handshake().unwrap();
        let handshake_payload = Payload::new(PayloadTag::Handshake, msg1);
        let handshake_pkt = Packet::new(1, 0, rand::rng().random(), [0u8; 12], handshake_payload);
        udp.send_to(&relay_wrap(bob_id, &handshake_pkt), relay_addr)
            .unwrap();

        let (resp_pkt, _) = udp.recv_from().unwrap();
        session.complete_handshake(&resp_pkt.payload.data).unwrap();
        println!("[alice] handshake complete");

        let msg = Message::new("hello from alice through the relay".to_string(), None);
        let msg_pkt = session.send(&msg).unwrap();
        udp.send_to(&relay_wrap(bob_id, &msg_pkt), relay_addr)
            .unwrap();

        let (reply_pkt, _) = udp.recv_from().unwrap();
        let reply = session.receive(&reply_pkt).unwrap();
        println!("[alice] received: {}", reply.content);
        assert_eq!(reply.reply_to.unwrap(), msg.id);
    });

    // ----- bob thread -----
    let bob_thread = thread::spawn(move || {
        let udp = UdpTransport::bind(bob_addr).unwrap();
        let mut session = Session::new_responder(&bob_keychain.device_x25519_priv).unwrap();

        let (msg1_pkt, _) = udp.recv_from().unwrap();
        session.accept_handshake(&msg1_pkt.payload.data).unwrap();

        let msg2 = session.reply_handshake().unwrap();
        let handshake_payload = Payload::new(PayloadTag::Handshake, msg2);
        let handshake_pkt = Packet::new(1, 0, rand::rng().random(), [0u8; 12], handshake_payload);
        udp.send_to(&relay_wrap(alice_id, &handshake_pkt), relay_addr)
            .unwrap();
        println!("[bob] handshake complete");

        let (msg_pkt, _) = udp.recv_from().unwrap();
        let received = session.receive(&msg_pkt).unwrap();
        println!("[bob] received: {}", received.content);

        let reply = Message::new(
            "got it through the relay".to_string(),
            Some(received.id),
        );
        let reply_pkt = session.send(&reply).unwrap();
        udp.send_to(&relay_wrap(alice_id, &reply_pkt), relay_addr)
            .unwrap();
    });

    alice_thread.join().unwrap();
    bob_thread.join().unwrap();

    println!("ok");
}
