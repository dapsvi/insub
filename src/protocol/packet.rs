pub enum PacketFlag {
    AckRequired,        // 0x1
    Ack,                // 0x2
    Fragmented,         // 0x4
    LastFragment,       // 0x8
}

pub fn flag_to_int(flag: PacketFlag) -> u16 {
    let int: u16 = match flag {
        PacketFlag::AckRequired     => 0b0001,
        PacketFlag::Ack             => 0b0010,
        PacketFlag::Fragmented      => 0b0100,
        PacketFlag::LastFragment    => 0b1000,
    };
    int
}

pub struct PacketFlags {
    pub flags: u16,
}

impl PacketFlags {
    pub fn to_int(&self) -> u16 {
        self.flags
    }

    pub fn from_int(flags: u16) -> PacketFlags {
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
    pub payload: Vec<u8>,
}

impl Packet {
    pub fn new(version: u64, flags: u16, id: u128, nonce: [u8; 12], payload: Vec<u8>) -> Packet {
        let header = PacketHeader{
            version,
            flags: PacketFlags { flags },
            id,
            nonce,
        };
        
        Packet{
            header,
            payload,
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        // serialization will store the packet in this order :
        // 1. version           (64 bits = 8 bytes)
        // 2. flags             (16 bits = 2 bytes)
        // 3. id                (128 bits = 16 bytes)
        // 4. nonce             (12 bytes)
        // 5. payload           (rest of the vector)
        let total_length = 8 + 2 + 16 + 12 + self.payload.len();
        let mut serialized = Vec::with_capacity(total_length);

        serialized.extend_from_slice(&self.header.version.to_be_bytes());
        serialized.extend_from_slice(&self.header.flags.to_int().to_be_bytes());
        serialized.extend_from_slice(&self.header.id.to_be_bytes());
        serialized.extend_from_slice(&self.header.nonce);
        serialized.extend_from_slice(&self.payload);

        serialized
    }

    pub fn from_serialized(mut serialized: Vec<u8>) -> Result<Packet, &'static str> {
        let version_bytes = serialized.drain(0..8)
            .collect::<Vec<u8>>()
            .try_into()
            .map_err(|_| "Failed to parse packet version")?;
        let version = u64::from_be_bytes(version_bytes);

        let flags_bytes = serialized.drain(0..2)
            .collect::<Vec<u8>>()
            .try_into()
            .map_err(|_| "Failed to parse packet flags")?;
        let flags = u16::from_be_bytes(flags_bytes);

        let id_bytes = serialized.drain(0..16)
            .collect::<Vec<u8>>()
            .try_into()
            .map_err(|_| "Failed to parse packet ID")?;
        let id = u128::from_be_bytes(id_bytes);

        let nonce: [u8; 12] = serialized.drain(0..12)
            .collect::<Vec<u8>>()
            .try_into()
            .map_err(|_| "Failed to parse packet nonce")?;

        let payload = serialized;  // rest of the packet

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