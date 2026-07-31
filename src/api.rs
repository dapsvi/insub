use std::collections::HashMap;
use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{mpsc, Arc, Mutex};
use std::thread;

use bip39::Mnemonic;
use ed25519_dalek::{SigningKey, VerifyingKey};
use x25519_dalek::PublicKey;

use crate::dht::node_id::NodeID;
use crate::identity::certificates::DeviceCertificate;
use crate::identity::devices::DeviceList;
use crate::identity::identity::{MasterKeyPair, UserID};
use crate::identity::keychain::Keychain;
use crate::network::registry::{self, RelayEntry, RelayRegistry};
use crate::protocol::message::Message;
use crate::runtime::Runtime;

pub struct Client {
    rt: Arc<Mutex<Runtime>>,
    our_pk: [u8; 32],
    device_cert: DeviceCertificate,
    device_list: DeviceList,
    registry: RelayRegistry,
    peers: HashMap<[u8; 32], PeerInfo>,
    storage_dir: PathBuf,
    seeds: Vec<SocketAddr>,
    msg_rx: mpsc::Receiver<(Message, [u8; 32])>,
    sess_rx: mpsc::Receiver<([u8; 32], [u8; 32])>,
}

pub struct PeerInfo {
    pk: [u8; 32],
    device_list: DeviceList,
    conn_ids: Vec<[u8; 16]>,
}

pub enum Event {
    MessageReceived     { from: [u8; 32], content: String },
    SessionEstablished  { peer: [u8; 32], safety_number: [u8; 32] },
    SessionFailed       { peer: [u8; 32], reason: String },
    ContactFound        { peer: [u8; 32] },
    ContactFailed       { peer: [u8; 32], reason: String },
    DeviceListUpdated   { peer: [u8; 32] },
}

impl Client {
    pub fn new(storage_dir: PathBuf, seeds: Vec<SocketAddr>, password: Option<&str>) -> Result<(Self, Mnemonic), String> {
        fs::create_dir_all(&storage_dir)
            .map_err(|e| format!("cannot create storage dir: {e}"))?;

        let (master, mnemonic) = MasterKeyPair::new();
        let our_pk = master.public_key.to_bytes();

        eprintln!("mnemonic: {}", mnemonic.to_string());

        let keychain = Keychain::from_mnemonic(&mnemonic, password);
        keychain.save(&storage_dir.join("keychain"), password)?;

        let cert = DeviceCertificate::new(
            &master,
            VerifyingKey::from_bytes(&keychain.device_ed25519_pub).unwrap(),
            PublicKey::from(keychain.device_x25519_pub),
        );

        let mut device_list = DeviceList::new(&master);
        device_list.add_device(&master, cert.clone())
            .map_err(|e| format!("failed to add device: {e}"))?;

        let our_id = registry::derive_id(&our_pk);
        let bind_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let node_id = NodeID::from_pubkey(&our_pk);
        let x25519_priv = keychain.device_x25519_priv;

        let mut rt = Runtime::bind(
            node_id,
            bind_addr,
            Some(SigningKey::from_bytes(&master.to_bytes())),
            x25519_priv,
        )?;

        let actual_addr = rt.local_addr();
        rt.enable_server();
        rt.set_master_pubkey(our_pk);
        rt.set_device_cert(cert.clone());

        let mut reg = RelayRegistry::new();
        reg.add(RelayEntry::new(our_id, our_pk, actual_addr)
            .map_err(|e| format!("invalid relay entry: {e}"))?);
        rt.enable_relay(reg.clone());

        let peer_state_path = storage_dir.join("peer_state");
        if peer_state_path.exists() {
            let _ = rt.load_peer_state(&peer_state_path);
        }

        let msg_rx = rt.subscribe();
        let sess_rx = rt.subscribe_sessions();
        let rt = Arc::new(Mutex::new(rt));

        // background tick loop
        let rt_bg = rt.clone();
        thread::spawn(move || loop {
            rt_bg.lock().unwrap().tick();
            thread::sleep(std::time::Duration::from_millis(50));
        });

        let client = Client {
            rt,
            our_pk,
            device_cert: cert,
            device_list,
            registry: reg,
            peers: HashMap::new(),
            storage_dir,
            seeds,
            msg_rx,
            sess_rx,
        };
        client.save()?;

        Ok((client, mnemonic))
    }

    pub fn open(storage_dir: PathBuf, seeds: Vec<SocketAddr>, password: Option<&str>) -> Result<Self, String> {
        let device_cert = DeviceCertificate::open(&storage_dir.join("device_cert"))?;
        let registry = RelayRegistry::open(&storage_dir.join("registry"))?;
        let device_list = DeviceList::open(&storage_dir.join("device_list"))?;
        let keychain = Keychain::load(&storage_dir.join("keychain"), password)?;

        let our_pk_bytes = fs::read(&storage_dir.join("our_pk"))
            .map_err(|e| format!("cannot read our_pk: {e}"))?;
        let our_pk: [u8; 32] = our_pk_bytes.try_into()
            .map_err(|_| "invalid our_pk length".to_string())?;

        let node_id = NodeID::from_pubkey(&our_pk);
        let bind_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();

        let mut rt = Runtime::bind(
            node_id,
            bind_addr,
            Some(SigningKey::from_bytes(&keychain.device_ed25519_priv)),
            keychain.device_x25519_priv,
        )?;

        rt.enable_server();
        rt.set_master_pubkey(our_pk);
        rt.set_device_cert(device_cert.clone());
        rt.enable_relay(registry.clone());

        let peer_state_path = storage_dir.join("peer_state");
        if peer_state_path.exists() {
            let _ = rt.load_peer_state(&peer_state_path);
        }

        let msg_rx = rt.subscribe();
        let sess_rx = rt.subscribe_sessions();
        let rt = Arc::new(Mutex::new(rt));

        let rt_bg = rt.clone();
        thread::spawn(move || loop {
            rt_bg.lock().unwrap().tick();
            thread::sleep(std::time::Duration::from_millis(50));
        });

        Ok(Client {
            rt,
            our_pk,
            device_cert,
            device_list,
            registry,
            peers: HashMap::new(),
            storage_dir,
            seeds,
            msg_rx,
            sess_rx,
        })
    }

    pub fn from_mnemonic(mnemonic: Mnemonic, storage_dir: PathBuf, seeds: Vec<SocketAddr>, password: Option<&str>) -> Result<Self, String> {
        fs::create_dir_all(&storage_dir)
            .map_err(|e| format!("cannot create storage dir: {e}"))?;

        let master = MasterKeyPair::from_mnemonic(&mnemonic, password);
        let our_pk = master.public_key.to_bytes();

        // fresh device keys for this new device
        let keychain = Keychain::from_mnemonic(&mnemonic, password);
        keychain.save(&storage_dir.join("keychain"), password)?;

        let cert = DeviceCertificate::new(
            &master,
            VerifyingKey::from_bytes(&keychain.device_ed25519_pub).unwrap(),
            PublicKey::from(keychain.device_x25519_pub),
        );

        let our_id = registry::derive_id(&our_pk);
        let bind_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let node_id = NodeID::from_pubkey(&our_pk);

        let mut rt = Runtime::bind(
            node_id,
            bind_addr,
            Some(SigningKey::from_bytes(&keychain.device_ed25519_priv)),
            keychain.device_x25519_priv,
        )?;

        let actual_addr = rt.local_addr();
        rt.enable_server();
        rt.set_master_pubkey(our_pk);
        rt.set_device_cert(cert.clone());

        // join DHT so we can fetch the existing device list
        for attempt in 0..5 {
            match rt.join(&seeds) {
                Ok(()) => break,
                Err(_) if attempt < 4 => {
                    std::thread::sleep(std::time::Duration::from_millis(500));
                    continue;
                }
                Err(e) => return Err(format!("cannot join DHT: {e}")),
            }
        }

        // fetch existing device list published by another device, or start fresh
        let mut device_list = match rt.find_contact(&our_pk) {
            Ok(contact) => contact.device_list,
            Err(_) => DeviceList::new(&master),
        };

        // add this device if not already in the list
        if !device_list.contains_active(&cert.device_ed25519_pubkey) {
            device_list.add_device(&master, cert.clone())
                .map_err(|e| format!("failed to add device: {e}"))?;
        }

        // publish updated list so other peers see the new device
        rt.publish_contact(device_list.clone(), actual_addr, our_id, 3600)?;

        let mut reg = RelayRegistry::new();
        reg.add(RelayEntry::new(our_id, our_pk, actual_addr)
            .map_err(|e| format!("invalid relay entry: {e}"))?);
        rt.enable_relay(reg.clone());

        let peer_state_path = storage_dir.join("peer_state");
        if peer_state_path.exists() {
            let _ = rt.load_peer_state(&peer_state_path);
        }

        let msg_rx = rt.subscribe();
        let sess_rx = rt.subscribe_sessions();
        let rt = Arc::new(Mutex::new(rt));

        let rt_bg = rt.clone();
        thread::spawn(move || loop {
            rt_bg.lock().unwrap().tick();
            thread::sleep(std::time::Duration::from_millis(50));
        });

        let client = Client {
            rt,
            our_pk,
            device_cert: cert,
            device_list,
            registry: reg,
            peers: HashMap::new(),
            storage_dir,
            seeds,
            msg_rx,
            sess_rx,
        };
        client.save()?;

        Ok(client)
    }

    pub fn save(&self) -> Result<(), String> {
        fs::write(&self.storage_dir.join("our_pk"), &self.our_pk)
            .map_err(|e| format!("cannot save our_pk: {e}"))?;
        self.device_cert.save(&self.storage_dir.join("device_cert"))?;
        self.registry.save(&self.storage_dir.join("registry"))?;
        self.device_list.save(&self.storage_dir.join("device_list"))?;

        self.rt.lock().unwrap().save_peer_state(&self.storage_dir.join("peer_state"))
    }

    pub fn add_device(&mut self, mnemonic: Mnemonic) -> Result<(), String> {
        let master = MasterKeyPair::from_mnemonic(&mnemonic, None);
        let our_pk = master.public_key.to_bytes();

        if our_pk != self.our_pk {
            return Err("mnemonic does not match this identity".to_string());
        }

        let keychain = Keychain::from_mnemonic(&mnemonic, None);
        let device_index = self.device_list.devices.len();
        keychain.save(&self.storage_dir.join(format!("keychain_{device_index}")), None)?;

        let cert = DeviceCertificate::new(
            &master,
            VerifyingKey::from_bytes(&keychain.device_ed25519_pub).unwrap(),
            PublicKey::from(keychain.device_x25519_pub),
        );

        // fetch latest device list from DHT in case another device modified it
        let mut rt = self.rt.lock().unwrap();
        let mut list = match rt.find_contact(&our_pk) {
            Ok(contact) => contact.device_list,
            Err(_) => self.device_list.clone(),
        };

        if !list.contains_active(&cert.device_ed25519_pubkey) {
            list.add_device(&master, cert)
                .map_err(|e| format!("failed to add device: {e}"))?;
        }
        list.sequence += 1;

        let relay_addr = rt.local_addr();
        let relay_id = registry::derive_id(&our_pk);
        rt.publish_contact(list.clone(), relay_addr, relay_id, 3600)?;
        drop(rt);

        self.device_list = list.clone();
        list.save(&self.storage_dir.join("device_list"))
    }

    pub fn revoke_device(&mut self, mnemonic: Mnemonic, index: usize) -> Result<(), String> {
        let master = MasterKeyPair::from_mnemonic(&mnemonic, None);
        let our_pk = master.public_key.to_bytes();

        if our_pk != self.our_pk {
            return Err("mnemonic does not match this identity".to_string());
        }

        let mut rt = self.rt.lock().unwrap();
        let mut list = match rt.find_contact(&our_pk) {
            Ok(contact) => contact.device_list,
            Err(_) => self.device_list.clone(),
        };

        if index >= list.devices.len() {
            return Err(format!("device index {index} out of range ({} devices)", list.devices.len()));
        }

        let device_key = list.devices[index].device_ed25519_pubkey;
        list.remove_device(&master, &device_key)
            .map_err(|e| format!("failed to remove device: {e}"))?;
        list.sequence += 1;

        let relay_addr = rt.local_addr();
        let relay_id = registry::derive_id(&our_pk);
        rt.publish_contact(list.clone(), relay_addr, relay_id, 3600)?;
        drop(rt);

        self.device_list = list.clone();
        list.save(&self.storage_dir.join("device_list"))
    }

    pub fn connect(&mut self) -> Result<(), String> {
        for attempt in 0..5 {
            match self.rt.lock().unwrap().join(&self.seeds) {
                Ok(()) => break,
                Err(_) if attempt < 4 => {
                    std::thread::sleep(std::time::Duration::from_millis(500));
                    continue;
                }
                Err(e) => return Err(format!("cannot join DHT: {e}")),
            }
        }

        let mut rt = self.rt.lock().unwrap();
        let relay_addr = rt.local_addr();
        let relay_id = registry::derive_id(&self.our_pk);
        rt.publish_contact(self.device_list.clone(), relay_addr, relay_id, 3600)
    }

    pub fn poll(&mut self) -> Vec<Event> {
        let mut events = Vec::new();

        while let Ok((msg, sender_pk)) = self.msg_rx.try_recv() {
            events.push(Event::MessageReceived {
                from: sender_pk,
                content: msg.content,
            });
        }

        while let Ok((peer_pk, safety)) = self.sess_rx.try_recv() {
            events.push(Event::SessionEstablished {
                peer: peer_pk,
                safety_number: safety,
            });
        }

        events
    }

    pub fn contact(&mut self, pk: [u8; 32]) -> Result<(), String> {
        let user_id = UserID {
            public_key: VerifyingKey::from_bytes(&pk).unwrap(),
        };

        let mut rt = self.rt.lock().unwrap();
        let contact = rt.find_contact(&pk)?;

        let x25519 = *contact.device_list.devices[0].device_x25519_pubkey.as_bytes();
        let relay_addr = contact.relay_addr;
        rt.set_peer_addr(pk, relay_addr);

        let tag = rt.enable_session_initiator(&x25519, user_id)?;
        rt.initiate_handshake(tag)?;

        let peer_info = PeerInfo {
            pk,
            device_list: contact.device_list,
            conn_ids: Vec::new(),
        };
        self.peers.insert(pk, peer_info);

        Ok(())
    }

    pub fn send(&mut self, to: [u8; 32], text: &str) -> Result<(), String> {
        if !self.peers.contains_key(&to) {
            return Err("unknown peer, call contact() first".to_string());
        }
        let msg = Message::new(text.into(), None);
        self.rt.lock().unwrap().send_message(msg, to)
    }

    pub fn safety_number(&self, peer: [u8; 32]) -> Result<[u8; 32], String> {
        let rt = self.rt.lock().unwrap();
        for (conn_id, pk) in rt.active_conn_ids() {
            if pk == peer {
                return rt.session_safety_number(&conn_id, &self.our_pk, &peer)
                    .ok_or_else(|| "safety number not available".to_string());
            }
        }
        Err("no active session for peer".to_string())
    }
}