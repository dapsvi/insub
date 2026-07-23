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
    pub fragment_id: u128,
    pub fragment_index: u8,
    pub fragment_total: u8,
}

impl Payload {
    pub fn new(tag: PayloadTag, data: Vec<u8>) -> Self {
        Self { tag, data, fragment_id: 0, fragment_index: 0, fragment_total: 0 }
    }

    pub fn new_fragment(tag: PayloadTag, data: Vec<u8>, fragment_id: u128, fragment_index: u8, fragment_total: u8) -> Self {
        Self { tag, data, fragment_id, fragment_index, fragment_total}
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(1 + 16 + 1 + 1 + self.data.len());
        bytes.push(self.tag.to_byte());
        bytes.extend_from_slice(&self.fragment_id.to_be_bytes());
        bytes.push(self.fragment_index);
        bytes.push(self.fragment_total);
        bytes.extend_from_slice(&self.data);
        bytes
    }

    pub fn from_serialized(bytes: Vec<u8>) -> Result<Self, String> {
        if bytes.len() < 19 {
            return Err("payload too short".to_string());
        }
        let tag_byte = bytes[0];
        let tag = PayloadTag::from_byte(tag_byte)
            .ok_or_else(|| format!("unknown payload tag: 0x{tag_byte:02x}"))?;

        let fragment_id = u128::from_be_bytes(bytes[1..17].try_into().unwrap());
        let fragment_index = bytes[17];
        let fragment_total = bytes[18];
        let data = bytes[19..].to_vec();

        Ok(Payload { tag, data, fragment_id, fragment_index, fragment_total })
    }
}