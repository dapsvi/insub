pub mod crypto;
pub mod protocol;
pub mod identity;
pub mod transport;
pub mod network;
pub mod dht;
pub mod runtime;

use std::collections::HashMap;
use std::io::{self, BufRead, Write};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use ed25519_dalek::{SigningKey, VerifyingKey};
use dht::node_id::NodeID;
use identity::certificates::DeviceCertificate;
use identity::devices::DeviceList;
use identity::identity::{MasterKeyPair, UserID};
use identity::keychain::Keychain;
use network::registry::{self, RelayEntry, RelayRegistry};
use protocol::message::Message;
use runtime::Runtime;
use x25519_dalek::PublicKey;

fn hex_pk(input: &str) -> Option<[u8; 32]> {
    let stripped = input.strip_prefix("0x").unwrap_or(input);
    let bytes = hex::decode(stripped).ok()?;
    bytes.try_into().ok()
}

struct Peer {
    pk: [u8; 32],
    conn_id: Option<[u8; 16]>,
}

enum Cmd {
    Connect([u8; 32]),
    Send(String),
    Quit,
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(|a| a.as_str()) == Some("--batch") {
        let count: usize = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(1);
        run_batch_relays(count);
        return;
    }
    run_interactive();
}

fn run_batch_relays(count: usize) {
    let base = 8000u16;
    let seed: SocketAddr = format!("127.0.0.1:{base}").parse().unwrap();
    let seed_id = NodeID::from_pubkey(&[0xAAu8; 32]);
    let sk = Some(SigningKey::from_bytes(&[0xBBu8; 32]));

    let mut r0 = Runtime::bind(seed_id, seed, sk, [0u8; 32]).unwrap();
    r0.enable_server();
    thread::spawn(move || r0.serve_forever());
    thread::sleep(Duration::from_millis(100));

    for i in 1..count {
        let addr: SocketAddr = format!("127.0.0.1:{}", base + i as u16).parse().unwrap();
        let id = NodeID::from_pubkey(&[0xCC + i as u8; 32]);
        let sk = Some(SigningKey::from_bytes(&[0xDD + i as u8; 32]));
        let mut r = Runtime::bind(id, addr, sk, [0u8; 32]).unwrap();
        r.enable_server();
        r.join(&[seed]).unwrap();
        println!("relay-{i} at {addr}");
        thread::spawn(move || r.serve_forever());
        thread::sleep(Duration::from_millis(20));
    }
    println!("{count} relays running. Ctrl-C to stop.");
    loop { thread::sleep(Duration::from_secs(3600)); }
}

fn run_interactive() {
    let seed: SocketAddr = "127.0.0.1:8000".parse().unwrap();

    eprintln!("creating master keypair...");
    let (master, mnemonic) = MasterKeyPair::new();
    let master_pk = master.public_key.to_bytes();
    let node_id = NodeID::from_pubkey(&master_pk);
    let sk = Some(SigningKey::from_bytes(&master.to_bytes()));

    eprintln!("creating the keychain...");
    let keychain_path = Path::new("/tmp/insub-cli.keychain");
    let password = Some("insub-cli");
    let (keychain, _) = Keychain::new(keychain_path, password).unwrap();

    eprintln!("creating the device certificate...");
    let cert = DeviceCertificate::new(
        &master,
        VerifyingKey::from_bytes(&keychain.device_ed25519_pub).unwrap(),
        PublicKey::from(keychain.device_x25519_pub),
    );
    let x25519_priv = keychain.device_x25519_priv;
    let our_pk = master_pk;
    let our_id = registry::derive_id(&our_pk);

    let bind_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();

    eprintln!("creating the runtime...");
    let mut rt = Runtime::bind(node_id, bind_addr, sk, x25519_priv).unwrap();
    let actual_addr = rt.local_addr();
    rt.enable_server();
    rt.set_master_pubkey(our_pk);

    let mut device_list = DeviceList::new(&master);
    device_list.add_device(&master, cert.clone()).ok();

    rt.set_device_cert(cert);

    eprintln!("creating the relay registry...");
    let mut reg = RelayRegistry::new();
    reg.add(RelayEntry::new(our_id, our_pk, actual_addr).unwrap());
    rt.enable_relay(reg);

    let mut joined = false;
    eprintln!("attempting to join the DHT...");
    for attempt in 0..5 {
        match rt.join(&[seed]) {
            Ok(()) => { joined = true; break; }
            Err(e) => {
                if attempt < 4 {
                    eprintln!("join attempt {} failed: {e}, retrying...", attempt + 1);
                    thread::sleep(Duration::from_millis(500));
                } else {
                    eprintln!("could not join DHT at {seed} after 5 attempts: {e}");
                }
            }
        }
    }
    if !joined { return; }
    match rt.publish_contact(device_list, actual_addr, our_id, 3600) {
        Err(e) => { eprintln!("could not publish contact: {e}") },
        Ok(_) => {},
    }

    println!("insub cli");
    println!("  pubkey:   {}", hex::encode(our_pk));
    println!("  mnemonic: {}", mnemonic.to_string());
    println!("  addr:     {actual_addr}  seed: {seed}");
    println!();

    let msg_rx = rt.subscribe();
    let (cmd_tx, cmd_rx) = mpsc::channel::<Cmd>();

    thread::spawn(move || {
        let stdin = io::stdin();
        let mut buf = String::new();
        println!("type a hex pubkey to connect, then messages to send, /quit to exit");
        loop {
            buf.clear();
            print!("> ");
            io::stdout().flush().unwrap();
            if stdin.lock().read_line(&mut buf).is_err() { break; }
            let line = buf.trim().to_string();
            if line.is_empty() { continue; }
            if line == "/quit" || line == "/q" {
                let _ = cmd_tx.send(Cmd::Quit);
                break;
            }
            if let Some(pk) = hex_pk(&line) {
                let _ = cmd_tx.send(Cmd::Connect(pk));
            } else {
                let _ = cmd_tx.send(Cmd::Send(line));
            }
        }
    });

    let mut peers: HashMap<[u8; 32], Peer> = HashMap::new();
    let mut current: Option<[u8; 32]> = None;

    let mut dirty = true;
    loop {
        rt.tick_server();
        rt.tick_relay();
        rt.tick_handshake();
        rt.tick_message();

        while let Ok((msg, sender_pk)) = msg_rx.try_recv() {
            let label = peers.get(&sender_pk)
                .map(|_| hex::encode(&sender_pk[..4]))
                .unwrap_or_else(|| hex::encode(sender_pk));
            println!("\r[{}] {}", label, msg.content);
            dirty = true;
        }

        match cmd_rx.try_recv() {
            Ok(Cmd::Quit) => break,
            Ok(Cmd::Connect(pk)) => {
                if pk == our_pk {
                    println!("\rthat is your own pubkey");
                } else if let Some(_) = peers.get(&pk) {
                    current = Some(pk);
                    println!("\rswitched to {}", hex::encode(&pk[..4]));
                } else {
                    println!("\rlooking up {} ...", hex::encode(&pk[..4]));
                    match rt.find_contact(&pk) {
                        Ok(contact) => {
                            let x25519 = *contact.device_list.devices[0].device_x25519_pubkey.as_bytes();
                            let relay_addr = contact.relay_addr;
                            let peer_id = UserID { public_key: VerifyingKey::from_bytes(&pk).unwrap() };
                            rt.set_peer_addr(pk, relay_addr);
                            match rt.enable_session_initiator(&x25519, peer_id) {
                                Ok(tag) => {
                                    if let Err(e) = rt.initiate_handshake(tag) {
                                        println!("\rhandshake failed: {e}");
                                    } else {
                                        peers.insert(pk, Peer { pk, conn_id: None });
                                        current = Some(pk);
                                        println!("\rhandshake sent to {}", hex::encode(&pk[..4]));
                                    }
                                }
                                Err(e) => println!("\rsession failed: {e}"),
                            }
                        }
                        Err(e) => println!("\rcontact not found: {e}"),
                    }
                }
                dirty = true;
            }
            Ok(Cmd::Send(text)) => {
                if let Some(pk) = current {
                    if let Some(peer) = peers.get(&pk) {
                        if let Some(conn_id) = peer.conn_id.or_else(|| rt.first_active_conn_id()) {
                            let msg = Message::new(text.clone(), None);
                            if let Err(e) = rt.send_message(msg, pk) {
                                println!("\rsend failed: {e}");
                            }
                            peers.get_mut(&pk).unwrap().conn_id = Some(conn_id);
                        } else {
                            println!("\rsession not established yet");
                        }
                    }
                } else {
                    println!("\rno peer selected");
                }
                dirty = true;
            }
            Err(mpsc::TryRecvError::Empty) => {}
            Err(_) => break,
        }

        if dirty {
            print_prompt(current.as_ref().and_then(|pk| peers.get(pk)));
            dirty = false;
        }
        thread::sleep(Duration::from_millis(50));
    }

    let _ = std::fs::remove_file("/tmp/insub-cli.keychain");
    println!("bye");
}

fn print_prompt(peer: Option<&Peer>) {
    if let Some(p) = peer {
        print!("[{}]> ", hex::encode(&p.pk[..4]));
    } else {
        print!("> ");
    }
    io::stdout().flush().unwrap();
}
