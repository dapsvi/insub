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

use ed25519_dalek::{SigningKey, VerifyingKey};
use dht::node_id::NodeID;
use identity::certificates::DeviceCertificate;
use identity::identity::{MasterKeyPair, UserID};
use identity::keychain::Keychain;
use network::registry::{self, RelayEntry, RelayRegistry};
use network::relay::RelayFrame;
use protocol::message::Message;
use protocol::packet::Packet;
use protocol::payload::{Payload, PayloadTag};
use protocol::session::Session;
use rand::RngExt;
use runtime::Runtime;
use transport::udp::UdpTransport;
use x25519_dalek::PublicKey;

fn relay_wrap(dest_id: u128, inner_packet: &Packet) -> Packet {
    let frame = RelayFrame::new(dest_id, inner_packet.serialize());
    let payload = Payload::new(PayloadTag::RelayFrame, frame.serialize());
    Packet::new(0, rand::rng().random(), payload)
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

    // ----- device certificates -----
    let alice_cert = DeviceCertificate::new(
        &alice_master,
        VerifyingKey::from_bytes(&alice_keychain.device_ed25519_pub).unwrap(),
        PublicKey::from(alice_keychain.device_x25519_pub),
    );
    let bob_cert = DeviceCertificate::new(
        &bob_master,
        VerifyingKey::from_bytes(&bob_keychain.device_ed25519_pub).unwrap(),
        PublicKey::from(bob_keychain.device_x25519_pub),
    );
    let alice_user_id = UserID::from(&alice_master);
    let bob_user_id = UserID::from(&bob_master);

    // ----- relay IDs -----
    let alice_id = registry::derive_id(&alice_master.public_key.to_bytes());
    let bob_id = registry::derive_id(&bob_master.public_key.to_bytes());

    let alice_addr: SocketAddr = "127.0.0.1:9000".parse().unwrap();
    let bob_addr: SocketAddr = "127.0.0.1:9001".parse().unwrap();
    let relay_addr: SocketAddr = "127.0.0.1:8070".parse().unwrap();
    let alice_dht_addr: SocketAddr = "127.0.0.1:9002".parse().unwrap();
    let bob_dht_addr: SocketAddr = "127.0.0.1:9003".parse().unwrap();

    // ----- DHT: multi-relay network -----
    println!("--- DHT multi-relay network ---");
    const NUM_RELAYS: usize = 3;
    let mut relay_ids = Vec::new();
    let mut relay_addrs = Vec::new();
    let mut relay_keys = Vec::new();
    for i in 0..NUM_RELAYS {
        let (m, _) = MasterKeyPair::new();
        relay_ids.push(NodeID::from_pubkey(&m.public_key.to_bytes()));
        relay_addrs.push(format!("127.0.0.1:{}", 8000 + i).parse::<SocketAddr>().unwrap());
        relay_keys.push(Some(SigningKey::from_bytes(&m.to_bytes())));
    }

    // start relay 0 as the seed
    let mut relay0 = Runtime::bind(relay_ids[0], relay_addrs[0], relay_keys.remove(0), [0u8; 32]).unwrap();
    relay0.enable_server();
    let _r0 = thread::spawn(move || { relay0.serve_forever(); });
    thread::sleep(Duration::from_millis(100));

    // relays 1..N join the network
    for i in 1..NUM_RELAYS {
        let mut r = Runtime::bind(relay_ids[i], relay_addrs[i], relay_keys.remove(0), [0u8; 32]).unwrap();
        r.enable_server();
        r.join(&[relay_addrs[0]]).unwrap();
        println!("[relay-{i}] joined via relay-0");

        thread::spawn(move || { r.serve_forever(); });
        thread::sleep(Duration::from_millis(50));
    }

    // leaf: join via relay 0, store and find. uses its own identity
    // and runs a server so it stays reachable for later DHT lookups.
    let (leaf_master, _) = MasterKeyPair::new();
    let leaf_addr: SocketAddr = "127.0.0.1:9100".parse().unwrap();
    let leaf_id = NodeID::from_pubkey(&leaf_master.public_key.to_bytes());
    let leaf_sk = Some(SigningKey::from_bytes(&leaf_master.to_bytes()));
    let mut leaf = Runtime::bind(leaf_id, leaf_addr, leaf_sk, [0u8; 32]).unwrap();
    leaf.enable_server();
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

    // keep the leaf serving so it stays reachable in the DHT routing table
    let _leaf = thread::spawn(move || leaf.serve_forever());
    thread::sleep(Duration::from_millis(50));

    println!("[dht] multi-relay tests passed");

    // ----- relay forwarding + contact discovery + messaging -----
    println!("--- contact discovery and messaging test ---");

    // shared relay: DHT server (joins the network) + relay forwarding
    let mut registry = RelayRegistry::new();
    registry.add(
        RelayEntry::new(alice_id, alice_master.public_key.to_bytes(), alice_addr).unwrap(),
    );
    registry.add(
        RelayEntry::new(bob_id, bob_master.public_key.to_bytes(), bob_addr).unwrap(),
    );

    let (msg_relay_master, _) = MasterKeyPair::new();
    let msg_relay_id = NodeID::from_pubkey(&msg_relay_master.public_key.to_bytes());
    let msg_relay_sk = Some(SigningKey::from_bytes(&msg_relay_master.to_bytes()));
    let mut msg_relay = Runtime::bind(msg_relay_id, relay_addr, msg_relay_sk, [0u8; 32]).unwrap();
    msg_relay.enable_server();
    msg_relay.enable_relay(registry);
    msg_relay.join(&[relay_addrs[0]]).unwrap();
    let _relay = thread::spawn(move || msg_relay.serve_forever());
    thread::sleep(Duration::from_millis(100));

    // Alice: DHT node that publishes her contact, then keeps serving
    let alice_dht_sk = Some(SigningKey::from_bytes(&alice_master.to_bytes()));
    let mut alice_dht = Runtime::bind(
        NodeID::from_pubkey(&alice_master.public_key.to_bytes()),
        alice_dht_addr,
        alice_dht_sk,
        alice_keychain.device_x25519_priv,
    ).unwrap();
    alice_dht.set_master_pubkey(alice_master.public_key.to_bytes());
    alice_dht.set_device_cert(alice_cert.clone());
    alice_dht.enable_server();
    alice_dht.join(&[relay_addrs[0]]).unwrap();
    alice_dht.publish_contact(relay_addr, alice_id, 300).unwrap();
    println!("[alice] contact published");
    let _alice_dht = thread::spawn(move || alice_dht.serve_forever());
    thread::sleep(Duration::from_millis(50));

    // Bob: DHT node, looks up Alice, then keeps serving
    let bob_dht_sk = Some(SigningKey::from_bytes(&bob_master.to_bytes()));
    let mut bob_dht = Runtime::bind(
        NodeID::from_pubkey(&bob_master.public_key.to_bytes()),
        bob_dht_addr,
        bob_dht_sk,
        bob_keychain.device_x25519_priv,
    ).unwrap();
    bob_dht.set_master_pubkey(bob_master.public_key.to_bytes());
    bob_dht.set_device_cert(bob_cert.clone());
    bob_dht.enable_server();
    bob_dht.join(&[relay_addrs[0]]).unwrap();

    let alice_contact = bob_dht.find_contact(&alice_master.public_key.to_bytes()).unwrap();
    println!("[bob] found alice's contact (relay={})", alice_contact.relay_addr);

    // verify the discovered cert matches what we expect
    let cert_x25519: [u8; 32] = *alice_contact.device_cert.device_x25519_pubkey.as_bytes();
    assert_eq!(cert_x25519, alice_keychain.device_x25519_pub);
    assert!(alice_contact.device_cert.verify(&alice_user_id));
    println!("[bob] alice's cert verified");

    // Bob keeps serving DHT queries for other nodes
    let _bob_dht = thread::spawn(move || bob_dht.serve_forever());
    thread::sleep(Duration::from_millis(50));

    // Messaging through relay using discovered contact info
    let alice_thread = thread::spawn(move || {
        let udp = UdpTransport::bind(alice_addr).unwrap();
        let mut session = Session::new_responder(
            &alice_keychain.device_x25519_priv,
            alice_cert,
        ).unwrap();

        let (pkt, _) = udp.recv_from().unwrap();
        session.accept_handshake(&pkt.payload.data).unwrap();

        let msg2 = session.reply_handshake().unwrap();
        let hp = Payload::new(PayloadTag::Handshake, msg2);
        let hpkt = Packet::new(0, rand::rng().random(), hp);
        udp.send_to(&relay_wrap(bob_id, &hpkt), relay_addr).unwrap();

        // verify Bob's device certificate against his master identity
        assert!(session.verify_peer(&bob_user_id), "bob's cert should be valid");
        println!("[alice] handshake complete (cert verified)");

        let (mpkt, _) = udp.recv_from().unwrap();
        let received = session.receive(&mpkt).unwrap();
        println!("[alice] received: {}", received.content);

        let reply = Message::new("got it!".to_string(), Some(received.id));
        let rpkt = session.send(&reply).unwrap();
        udp.send_to(&relay_wrap(bob_id, &rpkt), relay_addr).unwrap();

        let _ = std::fs::remove_file("/tmp/insub-alice.keychain");
    });

    let bob_thread = thread::spawn(move || {
        let udp = UdpTransport::bind(bob_addr).unwrap();
        let mut session = Session::new_initiator(
            &bob_keychain.device_x25519_priv,
            alice_contact.device_x25519_pub(),
            bob_cert,
            alice_user_id,
        ).unwrap();

        let msg1 = session.initiate_handshake().unwrap();
        let hp = Payload::new(PayloadTag::Handshake, msg1);
        let hpkt = Packet::new(0, rand::rng().random(), hp);
        udp.send_to(&relay_wrap(alice_contact.relay_id, &hpkt), alice_contact.relay_addr).unwrap();

        let (resp, _) = udp.recv_from().unwrap();
        session.complete_handshake(&resp.payload.data).unwrap();
        println!("[bob] handshake complete");

        let msg = Message::new("hello from bob".to_string(), None);
        let mpkt = session.send(&msg).unwrap();
        udp.send_to(&relay_wrap(alice_contact.relay_id, &mpkt), alice_contact.relay_addr).unwrap();

        let (rpkt, _) = udp.recv_from().unwrap();
        let reply = session.receive(&rpkt).unwrap();
        println!("[bob] received: {}", reply.content);
        assert_eq!(reply.reply_to.unwrap(), msg.id);

        let _ = std::fs::remove_file("/tmp/insub-bob.keychain");
    });

    alice_thread.join().unwrap();
    bob_thread.join().unwrap();

    println!("ok");
}
