pub mod crypto;
pub mod protocol;
pub mod identity;
pub mod transport;

use identity::identity::MasterKeyPair;
use protocol::message::Message;
use protocol::packet::Packet;
use protocol::session::Session;
use transport::udp::UdpTransport;
use x25519_dalek::{PublicKey, StaticSecret};

fn main() {
    // ----- identities -----
    let (alice_master, _alice_mnemonic) = MasterKeyPair::new();
    let (bob_master, _bob_mnemonic) = MasterKeyPair::new();

    // ----- device X25519 static keys -----
    let alice_device_x25519 = StaticSecret::random();
    let bob_device_x25519 = StaticSecret::random();
    let bob_device_x25519_pub = PublicKey::from(&bob_device_x25519);

    // ----- transport -----
    let alice_udp = UdpTransport::bind("127.0.0.1:9000".parse().unwrap()).unwrap();
    let bob_udp = UdpTransport::bind("127.0.0.1:9001".parse().unwrap()).unwrap();

    // ----- handshake -----
    let mut alice_session = Session::new_initiator(
        alice_device_x25519.as_bytes(),
        bob_device_x25519_pub.as_bytes(),
    )
    .unwrap();

    let msg1 = alice_session.initiate_handshake().unwrap();
    alice_udp
        .send_to(&msg1, "127.0.0.1:9001".parse().unwrap())
        .unwrap();

    let (msg1_bytes, alice_addr) = bob_udp.recv_from().unwrap();
    let mut bob_session = Session::new_responder(bob_device_x25519.as_bytes()).unwrap();
    bob_session.accept_handshake(&msg1_bytes).unwrap();
    let msg2 = bob_session.reply_handshake().unwrap();
    bob_udp.send_to(&msg2, alice_addr).unwrap();

    let (msg2_bytes, _) = alice_udp.recv_from().unwrap();
    alice_session.complete_handshake(&msg2_bytes).unwrap();

    println!("handshake complete");
    assert!(alice_session.is_established());
    assert!(bob_session.is_established());

    // ----- messaging (alice to bob) -----
    let message = Message::new("hello from alice".to_string(), None);
    let packet = alice_session.send(&message).unwrap();
    alice_udp
        .send_to(&packet.serialize(), "127.0.0.1:9001".parse().unwrap())
        .unwrap();

    let (packet_bytes, _) = bob_udp.recv_from().unwrap();
    let received_packet = Packet::from_serialized(packet_bytes).unwrap();
    let received_message = bob_session.receive(&received_packet).unwrap();
    println!("bob received: {}", received_message.content);
    assert_eq!(received_message.content, "hello from alice");

    // ----- bob replies -----
    let reply = Message::new("hey alice".to_string(), Some(received_message.id));
    let reply_packet = bob_session.send(&reply).unwrap();
    bob_udp
        .send_to(&reply_packet.serialize(), alice_addr)
        .unwrap();

    let (reply_bytes, _) = alice_udp.recv_from().unwrap();
    let received_reply = Packet::from_serialized(reply_bytes).unwrap();
    let decrypted_reply = alice_session.receive(&received_reply).unwrap();
    println!("alice received: {}", decrypted_reply.content);
    assert_eq!(decrypted_reply.content, "hey alice");
    assert_eq!(decrypted_reply.reply_to.unwrap(), message.id);

    // ----- safety numbers match -----
    let alice_safety = alice_session
        .safety_number(
            &alice_master.public_key.to_bytes(),
            &bob_master.public_key.to_bytes(),
        )
        .unwrap();
    let bob_safety = bob_session
        .safety_number(
            &bob_master.public_key.to_bytes(),
            &alice_master.public_key.to_bytes(),
        )
        .unwrap();
    assert_eq!(alice_safety, bob_safety);
    println!("safety numbers match");

    println!("ok");
}
