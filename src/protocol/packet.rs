use crate::protocol::payload::Payload;

pub enum PacketFlag {
    AckRequired,        // 0x01
    Ack,                // 0x02
    Fragmented,         // 0x04
    LastFragment,       // 0x08
}

pub fn flag_to_int(flag: PacketFlag) -> u32 {
    let int: u32 = match flag {
        PacketFlag::AckRequired     => 0b00000001,
        PacketFlag::Ack             => 0b00000010,
        PacketFlag::Fragmented      => 0b00000100,
        PacketFlag::LastFragment    => 0b00001000,
    };
    int
}

pub struct PacketFlags {
    pub flags: u32,
}

impl PacketFlags {
    pub fn to_int(&self) -> u32 {
        self.flags
    }

    pub fn from_int(flags: u32) -> PacketFlags {
        PacketFlags { flags }
    }

    pub fn contains(&self, flag: PacketFlag) -> bool {
        self.flags & flag_to_int(flag) != 0
    }

    pub fn set(&mut self, flag: PacketFlag) {
        self.flags |= flag_to_int(flag);
    }
}

pub struct PacketHeader {
    pub version: u64,
    pub flags: PacketFlags,
    pub id: u128,
    pub nonce: [u8; 12],
}

pub struct Packet {
    pub header: PacketHeader,
    pub payload: Payload,
}

impl Packet {
    pub fn new(version: u64, flags: u32, id: u128, nonce: [u8; 12], payload: Payload) -> Packet {
        let header = PacketHeader {
            version,
            flags: PacketFlags { flags },
            id,
            nonce,
        };
        Packet { header, payload }
    }

    pub fn serialize(&self) -> Vec<u8> {
        let payload_bytes = self.payload.serialize();
        let total_length = 8 + 4 + 16 + 12 + payload_bytes.len();
        let mut serialized = Vec::with_capacity(total_length);

        serialized.extend_from_slice(&self.header.version.to_be_bytes());
        serialized.extend_from_slice(&self.header.flags.to_int().to_be_bytes());
        serialized.extend_from_slice(&self.header.id.to_be_bytes());
        serialized.extend_from_slice(&self.header.nonce);
        serialized.extend_from_slice(&payload_bytes);

        serialized
    }

    pub fn from_serialized(mut serialized: Vec<u8>) -> Result<Packet, &'static str> {
        let version_bytes = serialized.drain(0..8)
            .collect::<Vec<u8>>()
            .try_into()
            .map_err(|_| "Failed to parse packet version")?;
        let version = u64::from_be_bytes(version_bytes);

        let flags_bytes = serialized.drain(0..4)
            .collect::<Vec<u8>>()
            .try_into()
            .map_err(|_| "Failed to parse packet flags")?;
        let flags = u32::from_be_bytes(flags_bytes);

        let id_bytes = serialized.drain(0..16)
            .collect::<Vec<u8>>()
            .try_into()
            .map_err(|_| "Failed to parse packet ID")?;
        let id = u128::from_be_bytes(id_bytes);

        let nonce: [u8; 12] = serialized.drain(0..12)
            .collect::<Vec<u8>>()
            .try_into()
            .map_err(|_| "Failed to parse packet nonce")?;

        let payload = Payload::from_serialized(serialized)
            .map_err(|_| "Failed to parse payload")?;

        Ok(Packet {
            header: PacketHeader {
                version,
                flags: PacketFlags::from_int(flags),
                id,
                nonce,
            },
            payload,
        })
    }
}
