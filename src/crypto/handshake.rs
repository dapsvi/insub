use snow::{Builder, HandshakeState, TransportState};

const PROTOCOL: &str = "Noise_IK_25519_ChaChaPoly_SHA256";

pub struct Initiator {
    handshake: Option<HandshakeState>,
}

pub struct Responder {
    handshake: Option<HandshakeState>,
}

pub struct HandshakeResult {
    pub transport: TransportState,
    pub handshake_hash: [u8; 32],
    pub remote_static: [u8; 32],
}

impl Initiator {
    pub fn new(our_static_priv: &[u8], peer_static_pub: &[u8]) -> Result<Self, String> {
        let parsed = PROTOCOL
            .parse()
            .map_err(|e| format!("invalid protocol name: {e}"))?;

        let builder = Builder::new(parsed);

        // pass our static private key to the builder
        let builder = builder
            .local_private_key(our_static_priv)
            .map_err(|e| format!("invalid local static key: {e}"))?;

        // pass the peer's static public key to the builder
        let builder = builder
            .remote_public_key(peer_static_pub)
            .map_err(|e| format!("invalid remote static key: {e}"))?;

        // build the handshake initiator
        let handshake = builder
            .build_initiator()
            .map_err(|e| format!("failed to build initiator: {e}"))?;

        Ok(Self {
            handshake: Some(handshake),
        })
    }

    /// build the first handshake message to send to the responder
    pub fn initiate(&mut self) -> Result<Vec<u8>, String> {
        let handshake = self
            .handshake
            .as_mut()
            .ok_or("handshake already completed")?;

        let mut outgoing_message = vec![0u8; 1024];
        let written = handshake
            .write_message(&[], &mut outgoing_message)
            .map_err(|e| format!("handshake initiation failed: {e}"))?;
        outgoing_message.truncate(written);
        Ok(outgoing_message)
    }

    /// process the responder's reply and finish the handshake
    pub fn finish(&mut self, response: &[u8]) -> Result<HandshakeResult, String> {
        let mut handshake = self
            .handshake
            .take()
            .ok_or("handshake already completed")?;

        handshake
            .read_message(response, &mut [])
            .map_err(|e| format!("handshake response failed: {e}"))?;

        let handshake_hash = copy_handshake_hash(&handshake);

        let transport = handshake
            .into_transport_mode()
            .map_err(|e| format!("transition to transport mode failed: {e}"))?;

        let remote_static_bytes = transport
            .get_remote_static()
            .ok_or("remote static key not available after handshake")?;
        let mut remote_static = [0u8; 32];
        remote_static.copy_from_slice(remote_static_bytes);

        Ok(HandshakeResult {
            transport,
            handshake_hash,
            remote_static,
        })
    }
}

impl Responder {
    // create a Noise_IK responder, only our own static key is needed as the initiator's identity is discovered during the handshake
    pub fn new(our_static_priv: &[u8]) -> Result<Self, String> {
        let parsed = PROTOCOL
            .parse()
            .map_err(|e| format!("invalid protocol name: {e}"))?;

        let builder = Builder::new(parsed);

        // pass our static private key to the builder
        let builder = builder
            .local_private_key(our_static_priv)
            .map_err(|e| format!("invalid local static key: {e}"))?;

        // build the handshake responder directly because we don't know yet the initiator
        let handshake = builder
            .build_responder()
            .map_err(|e| format!("failed to build responder: {e}"))?;

        Ok(Self {
            handshake: Some(handshake),
        })
    }

    // process the first handshake message from an initiator
    pub fn accept(&mut self, incoming_message: &[u8]) -> Result<(), String> {
        let handshake = self
            .handshake
            .as_mut()
            .ok_or("handshake already completed")?;

        handshake
            .read_message(incoming_message, &mut [])
            .map_err(|e| format!("handshake accept failed: {e}"))?;
        Ok(())
    }

    // build the second/final handshake message and finish
    pub fn reply(&mut self) -> Result<(Vec<u8>, HandshakeResult), String> {
        let mut handshake = self
            .handshake
            .take()
            .ok_or("handshake already completed")?;

        let mut outgoing_message = vec![0u8; 1024];
        let written_length = handshake
            .write_message(&[], &mut outgoing_message)
            .map_err(|e| format!("handshake reply failed: {e}"))?;
        outgoing_message.truncate(written_length);

        let handshake_hash = copy_handshake_hash(&handshake);

        let transport = handshake
            .into_transport_mode()
            .map_err(|e| format!("transition to transport mode failed: {e}"))?;

        let remote_static_bytes = transport
            .get_remote_static()
            .ok_or("remote static key not available after handshake")?;
        let mut remote_static = [0u8; 32];
        remote_static.copy_from_slice(remote_static_bytes);

        Ok((
            outgoing_message,
            HandshakeResult {
                transport,
                handshake_hash,
                remote_static,
            },
        ))
    }
}

fn copy_handshake_hash(handshake: &HandshakeState) -> [u8; 32] {
    let mut hash = [0u8; 32];
    hash.copy_from_slice(handshake.get_handshake_hash());
    hash
}
