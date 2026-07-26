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
use protocol::message::Message;
use runtime::Runtime;
use x25519_dalek::PublicKey;

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
    let _bob_user_id = UserID::from(&bob_master);

    // ----- relay IDs -----
    let alice_id = registry::derive_id(&alice_master.public_key.to_bytes());
    let bob_id = registry::derive_id(&bob_master.public_key.to_bytes());

    let alice_addr: SocketAddr = "127.0.0.1:9000".parse().unwrap();
    let bob_addr: SocketAddr = "127.0.0.1:9001".parse().unwrap();

    // ----- DHT relay + contact discovery + messaging -----
    println!("--- DHT relay + messaging test ---");

    // single DHT relay node that also does relay forwarding
    let (dht_master, _) = MasterKeyPair::new();
    let dht_addr: SocketAddr = "127.0.0.1:8000".parse().unwrap();
    let dht_id = NodeID::from_pubkey(&dht_master.public_key.to_bytes());
    let dht_sk = Some(SigningKey::from_bytes(&dht_master.to_bytes()));

    let mut registry = RelayRegistry::new();
    registry.add(
        RelayEntry::new(alice_id, alice_master.public_key.to_bytes(), alice_addr).unwrap(),
    );
    registry.add(
        RelayEntry::new(bob_id, bob_master.public_key.to_bytes(), bob_addr).unwrap(),
    );

    let mut dht_relay = Runtime::bind(dht_id, dht_addr, dht_sk, [0u8; 32]).unwrap();
    dht_relay.enable_server();
    dht_relay.enable_relay(registry);
    let _dht_relay = thread::spawn(move || dht_relay.serve_forever());
    thread::sleep(Duration::from_millis(200));

    let dht_seed = dht_addr;

    // Alice: single Runtime for DHT + messaging
    let alice_sk = Some(SigningKey::from_bytes(&alice_master.to_bytes()));
    let mut alice = Runtime::bind(
        NodeID::from_pubkey(&alice_master.public_key.to_bytes()),
        alice_addr,
        alice_sk,
        alice_keychain.device_x25519_priv,
    ).unwrap();
    alice.set_master_pubkey(alice_master.public_key.to_bytes());
    alice.set_device_cert(alice_cert.clone());
    alice.enable_server();
    alice.join(&[dht_seed]).unwrap();
    alice.publish_contact(dht_addr, alice_id, 300).unwrap();
    println!("[alice] contact published");

    alice.set_relay(dht_addr);
    let alice_msg_rx = alice.enable_session_responder(alice_cert).unwrap();

    // spawn Alice's pump thread BEFORE Bob joins so Alice can respond
    // to DHT queries from Bob's lookup
    let alice_thread = thread::spawn(move || {
        loop {
            alice.tick_server();
            alice.tick_relay();
            alice.tick_handshake();
            alice.tick_message();

            if let Ok(msg) = alice_msg_rx.try_recv() {
                println!("[alice] received: {}", msg.content);
                let reply = Message::new("got it!".to_string(), Some(msg.id));
                alice.send_message(reply);
                for _ in 0..5 {
                    alice.tick_server();
                    alice.tick_relay();
                    alice.tick_handshake();
                    alice.tick_message();
                }
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }

        let _ = std::fs::remove_file("/tmp/insub-alice.keychain");
    });

    // let Alice's pump thread start before Bob queries the DHT
    thread::sleep(Duration::from_millis(100));

    // Bob: single Runtime for DHT + messaging
    let bob_sk = Some(SigningKey::from_bytes(&bob_master.to_bytes()));
    let mut bob = Runtime::bind(
        NodeID::from_pubkey(&bob_master.public_key.to_bytes()),
        bob_addr,
        bob_sk,
        bob_keychain.device_x25519_priv,
    ).unwrap();
    bob.set_master_pubkey(bob_master.public_key.to_bytes());
    bob.set_device_cert(bob_cert.clone());
    bob.enable_server();
    bob.join(&[dht_seed]).unwrap();

    let alice_contact = bob.find_contact(&alice_master.public_key.to_bytes()).unwrap();
    println!("[bob] found alice's contact (relay={})", alice_contact.relay_addr);

    let cert_x25519: [u8; 32] = *alice_contact.device_cert.device_x25519_pubkey.as_bytes();
    assert_eq!(cert_x25519, alice_keychain.device_x25519_pub);
    assert!(alice_contact.device_cert.verify(&alice_user_id));
    println!("[bob] alice's cert verified");

    bob.set_relay(alice_contact.relay_addr);
    bob.set_peer_master_pubkey(alice_master.public_key.to_bytes());
    let bob_msg_rx = bob.enable_session_initiator(
        alice_contact.device_x25519_pub(),
        bob_cert.clone(),
        alice_user_id,
    ).unwrap();
    bob.initiate_handshake().unwrap();

    // Bob: pump until session established, then send message and wait for reply
    let bob_thread = thread::spawn(move || {
        let mut sent = false;
        let mut iteration = 0u64;
        loop {
            bob.tick_server();
            bob.tick_relay();
            bob.tick_handshake();
            bob.tick_message();

            if let Ok(msg) = bob_msg_rx.try_recv() {
                println!("[bob] received: {}", msg.content);
                break;
            }

            if !sent && bob.session_established() {
                println!("[bob] session established, sending message");
                let msg = Message::new("hello from bob".to_string(), None);
                bob.send_message(msg);
                sent = true;
            }
            iteration += 1;
            if iteration % 50 == 0 {
                println!("[bob] pump {} (established={})", iteration, bob.session_established());
            }
            thread::sleep(Duration::from_millis(50));
        }

        let _ = std::fs::remove_file("/tmp/insub-bob.keychain");
    });

    alice_thread.join().unwrap();
    bob_thread.join().unwrap();

    println!("ok");
}
