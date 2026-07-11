mod identity;
mod exchange;
mod cipher;
mod message;

use identity::{MasterKeyPair, UserID};
use exchange::EphemeralExchangeKeyPair;
use message::Message;

// little tests
fn main() {
    // 1. create two identities
    let (alice_keypair, _alice_mnemonic) = MasterKeyPair::new();
    let (bob_keypair, _bob_mnemonic) = MasterKeyPair::new();

    // 2. derive UserIDs
    let alice_userid = UserID::from(&alice_keypair);
    let _bob_userid = UserID::from(&bob_keypair);

    let plaintext = "Hello Bob, this is Alice.";

    // 3. Alice sends, Bob opens
    {
        let mut alice_exchange = EphemeralExchangeKeyPair::new();
        let bob_exchange = EphemeralExchangeKeyPair::new();

        let message = Message::new(
            &alice_keypair,
            &mut alice_exchange,
            &bob_exchange.public_key,
            plaintext,
        ).expect("Alice failed to build the message");

        println!("original plaintext : {}", plaintext);
        println!("ciphertext (hex)    : {}", hex::encode(&message.ciphertext));

        let mut bob_exchange = bob_exchange;
        let decrypted = message
            .open(&mut bob_exchange, &alice_userid)
            .expect("Bob failed to open the message");

        println!("Bob decrypted       : {}", decrypted);
        assert_eq!(decrypted, plaintext);
        println!("successful");
        println!();
    }

    // 4. serialization and deserialization
    {
        let mut alice_exchange = EphemeralExchangeKeyPair::new();
        let bob_exchange = EphemeralExchangeKeyPair::new();

        let message = Message::new(
            &alice_keypair,
            &mut alice_exchange,
            &bob_exchange.public_key,
            plaintext,
        ).expect("Alice failed to build the message");

        let serialized = message.serialize().expect("serialization failed");
        println!("serialized message ({} bytes, hex) :", serialized.len());
        println!("{}", hex::encode(&serialized));

        let deserialized = Message::from_serialized(serialized)
            .expect("deserialization failed");

        let mut bob_exchange = bob_exchange;
        let decrypted = deserialized
            .open(&mut bob_exchange, &alice_userid)
            .expect("Bob failed to open the deserialized message");

        assert_eq!(decrypted, plaintext);
        println!("deserialized message opened correctly");
        println!();
    }

    // 5. tampered ciphertext should be rejected
    {
        let mut alice_exchange = EphemeralExchangeKeyPair::new();
        let bob_exchange = EphemeralExchangeKeyPair::new();

        let mut tampered = Message::new(
            &alice_keypair,
            &mut alice_exchange,
            &bob_exchange.public_key,
            plaintext,
        ).expect("build failed");

        tampered.ciphertext[0] ^= 0xFF;

        let mut bob_exchange = bob_exchange;
        match tampered.open(&mut bob_exchange, &alice_userid) {
            Ok(_) => println!("tampered ciphertext was accepted, this should not happen"),
            Err(e) => println!("tampered ciphertext correctly rejected : {}", e),
        }
    }

    // 6. tampered signature should be rejected
    {
        let mut alice_exchange = EphemeralExchangeKeyPair::new();
        let bob_exchange = EphemeralExchangeKeyPair::new();

        let mut tampered = Message::new(
            &alice_keypair,
            &mut alice_exchange,
            &bob_exchange.public_key,
            plaintext,
        ).expect("build failed");

        let mut sig_bytes = tampered.signature.to_bytes();
        sig_bytes[0] ^= 0xFF;
        tampered.signature = ed25519_dalek::Signature::from_bytes(&sig_bytes);

        let mut bob_exchange = bob_exchange;
        match tampered.open(&mut bob_exchange, &alice_userid) {
            Ok(_) => println!("tampered signature was accepted, this should not happen"),
            Err(e) => println!("tampered signature correctly rejected : {}", e),
        }
    }

    // 7. wrong recipient should not be able to open the message
    {
        let mut alice_exchange = EphemeralExchangeKeyPair::new();
        let bob_exchange = EphemeralExchangeKeyPair::new();
        let mut eve_exchange = EphemeralExchangeKeyPair::new();

        let message_to_bob = Message::new(
            &alice_keypair,
            &mut alice_exchange,
            &bob_exchange.public_key,
            plaintext,
        ).expect("build failed");

        match message_to_bob.open(&mut eve_exchange, &alice_userid) {
            Ok(text) => println!("Eve decrypted the message, this should not happen : {}", text),
            Err(e) => println!("Eve correctly failed to decrypt : {}", e),
        }
    }

    // 8. tampered serialized bytes should fail to deserialize or fail to open
    {
        let mut alice_exchange = EphemeralExchangeKeyPair::new();
        let bob_exchange = EphemeralExchangeKeyPair::new();

        let message = Message::new(
            &alice_keypair,
            &mut alice_exchange,
            &bob_exchange.public_key,
            plaintext,
        ).expect("build failed");

        let mut serialized = message.serialize().expect("serialization failed");
        // flip a byte inside the ciphertext portion
        let last = serialized.len() - 1;
        serialized[last] ^= 0xFF;

        let mut bob_exchange = bob_exchange;
        match Message::from_serialized(serialized) {
            Ok(deserialized) => match deserialized.open(&mut bob_exchange, &alice_userid) {
                Ok(_) => println!("tampered serialized message was accepted, this should not happen"),
                Err(e) => println!("tampered serialized message correctly rejected on open : {}", e),
            },
            Err(e) => println!("tampered serialized message correctly rejected on deserialize : {}", e),
        }
    }
}