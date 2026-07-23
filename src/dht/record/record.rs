pub const MAX_RECORD_SIZE: usize = 1024;

#[derive(Copy, Clone, PartialEq, Debug)]
pub enum RecordTag {
    Contact = 0x01,
}

impl RecordTag {
    pub fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0x01 => Some(Self::Contact),
            _ => None,
        }
    }

    pub fn to_byte(&self) -> u8 {
        match self {
            Self::Contact => 0x01,
        }
    }
}

#[derive(Clone)]
pub struct Record {
    pub tag: RecordTag,
    pub data: Vec<u8>,
}

impl Record {
    pub fn new(tag: RecordTag, data: Vec<u8>) -> Self {
        Self { tag, data }
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(1 + self.data.len());
        bytes.push(self.tag.to_byte());
        bytes.extend_from_slice(&self.data);
        bytes
    }

    pub fn from_serialized(bytes: Vec<u8>) -> Result<Self, String> {
        if bytes.len() < 2 {
            return Err("record too short".to_string());
        }
        let tag_byte = bytes[0];
        let tag = RecordTag::from_byte(tag_byte)
            .ok_or_else(|| format!("unknown record tag: 0x{tag_byte:02x}"))?;
        let data = bytes[1..].to_vec();

        if data.len() > MAX_RECORD_SIZE {
            return Err("record exceeds max size".to_string());
        }

        Ok(Record { tag, data })
    }
}