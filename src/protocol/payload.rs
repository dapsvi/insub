#[derive(Copy, Clone, PartialEq, Debug)]
pub enum PayloadTag {
    Handshake       = 0x01,
    Message         = 0x02,
    DhtQuery        = 0x03,
    DhtResponse     = 0x04,
    RelayFrame      = 0x05,
    FileChunk       = 0x06, // unused yet
    KeepAlive       = 0x07, // unused yet
    Dummy           = 0x08, // unused yet
    DhtOperation    = 0x09,
}

impl PayloadTag {
    pub fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0x01 => Some(Self::Handshake),
            0x02 => Some(Self::Message),
            0x03 => Some(Self::DhtQuery),
            0x04 => Some(Self::DhtResponse),
            0x05 => Some(Self::RelayFrame),
            0x06 => Some(Self::FileChunk),
            0x07 => Some(Self::KeepAlive),
            0x08 => Some(Self::Dummy),
            0x09 => Some(Self::DhtOperation),
            _ => None,
        }
    }

    pub fn to_byte(&self) -> u8 {
        match self {
            Self::Handshake     => 0x01,
            Self::Message       => 0x02,
            Self::DhtQuery      => 0x03,
            Self::DhtResponse   => 0x04,
            Self::RelayFrame    => 0x05,
            Self::FileChunk     => 0x06,
            Self::KeepAlive     => 0x07,
            Self::Dummy         => 0x08,
            Self::DhtOperation  => 0x09,
        }
    }
}

#[derive(Clone)]
pub struct Payload {
    pub tag: PayloadTag,
    pub data: Vec<u8>,
}

impl Payload {
    pub fn new(tag: PayloadTag, data: Vec<u8>) -> Self {
        Self { tag, data }
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(1 + self.data.len());
        bytes.push(self.tag.to_byte());
        bytes.extend_from_slice(&self.data);
        bytes
    }

    pub fn from_serialized(mut bytes: Vec<u8>) -> Result<Self, String> {
        if bytes.is_empty() {
            return Err("payload too short".to_string());
        }
        let tag_byte = bytes.remove(0);
        let tag = PayloadTag::from_byte(tag_byte)
            .ok_or_else(|| format!("unknown payload tag: 0x{tag_byte:02x}"))?;
        Ok(Payload { tag, data: bytes })
    }
}