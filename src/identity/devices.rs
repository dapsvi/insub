use ed25519_dalek::{Signature, VerifyingKey};

use crate::identity::certificates::DeviceCertificate;
use crate::crypto::identity::{UserID, MasterKeyPair};

const MAX_DEVICES: usize = 5;

pub struct DeviceList {
    pub sequence: u64,
    pub devices: Vec<DeviceCertificate>,
    pub master_signature: Signature,
}

impl DeviceList {
    pub fn contains_active(&self, device_pubkey: &VerifyingKey) -> bool {
        self.devices
            .iter()
            .any(|d| d.device_ed25519_pubkey == *device_pubkey)
    }


    pub fn signed_data(sequence: u64, devices: &Vec<DeviceCertificate>) -> Vec<u8> {
        let mut bytes: Vec<u8> = Vec::with_capacity(devices.len() + 8); // 8 extra bytes (64 bits) for the sequence
        bytes.extend_from_slice(&sequence.to_be_bytes());
        for device in devices.iter() {
            bytes.extend_from_slice(&device.serialize());
        };

        bytes
    }

    pub fn sign_data(sequence: u64, devices: &Vec<DeviceCertificate>, master: &MasterKeyPair) -> Signature {
        let bytes = Self::signed_data(sequence, &devices);
        master.sign(&bytes)
    }

    pub fn verify(&self, master_identity: &UserID) -> bool {
        let bytes = Self::signed_data(self.sequence, &self.devices);
        master_identity.verify(&bytes, &self.master_signature)
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(8 + 64 + 128*self.devices.len());
        bytes.extend_from_slice(&self.sequence.to_be_bytes());
        bytes.extend_from_slice(&self.master_signature.to_bytes());
        for device in self.devices.iter() {
            bytes.extend_from_slice(&device.serialize());
        }

        bytes
    }

    pub fn from_serialized(mut bytes: Vec<u8>) -> Result<DeviceList, &'static str> {
        if bytes.len() < 8+64 {
            return Err("Couldn't parse devices list")
        }
        let sequence_bytes = bytes.drain(0..8)
            .collect::<Vec<u8>>()
            .try_into()
            .map_err(|_| "Failed to parse device certificate's sequence")?;
        let sequence = u64::from_be_bytes(sequence_bytes);

        let master_signature_bytes = bytes.drain(0..64)
            .collect::<Vec<u8>>()
            .try_into()
            .map_err(|_| "Failed to parse device certificate's master signature")?;
        let master_signature = Signature::from_bytes(&master_signature_bytes);

        let mut devices = Vec::new();
        let remaining_len = bytes.len();

        if remaining_len % 128 != 0 {
            return Err("Invalid device list length: not a multiple of 128 bytes");
        }

        let num_devices = remaining_len / 128;

        if num_devices > MAX_DEVICES {
            return Err("Too many devices")
        }
        
        for _ in 0..num_devices {
            let device_bytes = bytes.drain(0..128).collect::<Vec<u8>>();
            
            let device = DeviceCertificate::from_serialized(device_bytes)
                .map_err(|_| "Failed to parse individual device")?;
            
            devices.push(device);
        }

        Ok(DeviceList {
            sequence,
            master_signature,
            devices,
        })
    }

    pub fn new(master: &MasterKeyPair) -> DeviceList {
        DeviceList {
            sequence: 0,
            devices: Vec::new(),
            master_signature: Self::sign_data(0, &Vec::new(), master)
        }
    }

    pub fn add_device(
        &mut self,
        master: &MasterKeyPair,
        new_cert: DeviceCertificate,
    ) -> Result<(), &'static str> {
        if self.devices.len() >= MAX_DEVICES {
            return Err("Device limit reached");
        }

        self.sequence += 1;
        self.devices.push(new_cert);
        self.master_signature = Self::sign_data(self.sequence, &self.devices, master);

        Ok(())
    }

    pub fn remove_device(
        &mut self,
        master: &MasterKeyPair,
        device_pubkey: &VerifyingKey,
    ) -> Result<(), &'static str> {
        let position = self.devices.iter().position(|d| &d.device_ed25519_pubkey == device_pubkey)
            .ok_or("Unknown certificate")?;

        self.sequence += 1;
        self.devices.swap_remove(position);
        self.master_signature = Self::sign_data(self.sequence, &self.devices, master);

        Ok(())
    }
}