use rand::RngExt;
use std::time::{SystemTime, UNIX_EPOCH};

fn generate_id() -> u128 {
    rand::rng().random()
}

fn now_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

// struct containing all the data that a message contains
pub struct Message {
    pub id: u128,
    pub content: String,
    pub timestamp: u64,
    pub reply_to: Option<u128>,
}

impl Message {
    pub fn new(content: String, reply_to: Option<u128>) -> Message {
        let id = generate_id();
        let timestamp = now_timestamp();

        Message { id, content, timestamp, reply_to }
    }

    pub fn serialize(&self) -> Result<Vec<u8>, &'static str> {
        // serialization will store the message in this order :
        // 1. id                (128 bits = 16 bytes)
        // 2. timestamp         (64 bits = 8 bytes)
        // 3. reply_to          (128 bits = 16 bytes)
        // 5. content           (rest of the array)
        let total_length = 16 + 8 + 16 + self.content.as_bytes().len();
        let mut serialized = Vec::with_capacity(total_length);
        serialized.extend_from_slice(&self.id.to_be_bytes());
        serialized.extend_from_slice(&self.timestamp.to_be_bytes());
        serialized.extend_from_slice(&self.reply_to.unwrap_or(0).to_be_bytes());
        serialized.extend_from_slice(&self.content.as_bytes());
        Ok(serialized)
    }

    pub fn from_serialized(mut serialized: Vec<u8>) -> Result<Message, &'static str> {
        // cf self.serialize()
        let id_bytes = serialized.drain(0..16)
            .collect::<Vec<u8>>()
            .try_into()
            .map_err(|_| "Failed to parse message ID")?;
        let id = u128::from_be_bytes(id_bytes);

        let timestamp_bytes = serialized.drain(0..8)
            .collect::<Vec<u8>>()
            .try_into()
            .map_err(|_| "Failed to parse message timestamp")?;
        let timestamp = u64::from_be_bytes(timestamp_bytes);

        let reply_to_bytes = serialized.drain(0..16)
            .collect::<Vec<u8>>()
            .try_into()
            .map_err(|_| "Failed to parse message reply")?;
        let reply_to = u128::from_be_bytes(reply_to_bytes);
        let reply_to = if reply_to == 0 {
            None
        } else {
            Some(reply_to)
        };

        let content_bytes = serialized;
        let content = String::from_utf8(content_bytes)
            .map_err(|_| "invalid UTF-8 in message content")?;

        Ok(Message { id, content, timestamp, reply_to })
    }
}