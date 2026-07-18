pub struct RelayFrame {
    pub dest_id: u128,
    pub payload: Vec<u8>,
}

impl RelayFrame {
    pub fn serialize(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(16 + self.payload.len());
        bytes.extend_from_slice(&self.dest_id.to_be_bytes());
        bytes.extend_from_slice(&self.payload);
        bytes
    }

    pub fn from_serialized(mut bytes: Vec<u8>) -> Result<Self, &'static str> {
        if bytes.len() < 16 {
            return Err("relay frame too short");
        }
        let id_bytes: [u8; 16] = bytes.drain(..16)
            .collect::<Vec<u8>>()
            .try_into()
            .map_err(|_| "failed to parse dest id")?;
        let dest_id = u128::from_be_bytes(id_bytes);

        Ok(RelayFrame {
            dest_id,
            payload: bytes,
        })
    }
}