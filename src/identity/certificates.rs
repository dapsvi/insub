use ed25519_dalek::{Signature, VerifyingKey};
use x25519_dalek::PublicKey;

use crate::identity::identity::{MasterKeyPair, UserID};

pub struct DeviceCertificate {
    pub device_ed25519_pubkey: VerifyingKey,
    pub device_x25519_pubkey: PublicKey,
    pub master_signature: Signature,
}

impl DeviceCertificate {
    pub fn new(
        master: &MasterKeyPair,
        device_ed25519_pubkey: VerifyingKey,
        device_x25519_pubkey: PublicKey,
    ) -> DeviceCertificate {
        let bytes = Self::signed_data(device_ed25519_pubkey, device_x25519_pubkey);
        let master_signature = master.sign(&bytes);
        DeviceCertificate {
            device_ed25519_pubkey,
            device_x25519_pubkey,
            master_signature,
        }
    }

    pub fn verify(&self, master_identity: &UserID) -> bool {
        let bytes = Self::signed_data(self.device_ed25519_pubkey, self.device_x25519_pubkey);
        master_identity.verify(&bytes, &self.master_signature)
    }

    fn signed_data(device_ed25519_pubkey: VerifyingKey, device_x25519_pubkey: PublicKey) -> Vec<u8> {
        let mut bytes: Vec<u8> = Vec::with_capacity(64);    // 2 times 32 bytes (2 keys)
        bytes.extend_from_slice(&device_ed25519_pubkey.to_bytes());
        bytes.extend_from_slice(&device_x25519_pubkey.to_bytes());
        bytes
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut bytes: Vec<u8> = Vec::with_capacity(128); // 32 (key) + 32 (key) + 64 (signature)
        bytes.extend_from_slice(&self.device_ed25519_pubkey.to_bytes());
        bytes.extend_from_slice(&self.device_x25519_pubkey.to_bytes());
        bytes.extend_from_slice(&self.master_signature.to_bytes());
        bytes
    }

    pub fn from_serialized(mut bytes: Vec<u8>) -> Result<DeviceCertificate, &'static str> {
        let device_ed25519_pubkey_bytes = bytes.drain(0..32)
            .collect::<Vec<u8>>()
            .try_into()
            .map_err(|_| "Failed to parse device certificate verifying key")?;
        let device_ed25519_pubkey = VerifyingKey::from_bytes(&device_ed25519_pubkey_bytes)
            .map_err(|_| "Failed to create VerifyingKey object")?;

        let device_x25519_pubkey_bytes: [u8; 32] = bytes.drain(0..32)
            .collect::<Vec<u8>>()
            .try_into()
            .map_err(|_| "Failed to parse device certificate public key")?;
        let device_x25519_pubkey = PublicKey::try_from(device_x25519_pubkey_bytes)
            .map_err(|_| "Failed to create PublicKey object")?;

        let master_signature_bytes = bytes.drain(0..64)
            .collect::<Vec<u8>>()
            .try_into()
            .map_err(|_| "Failed to parse sender identity key")?;
        let master_signature = Signature::from_bytes(&master_signature_bytes);

        Ok(DeviceCertificate {
            device_ed25519_pubkey,
            device_x25519_pubkey,
            master_signature
        })
    }
}