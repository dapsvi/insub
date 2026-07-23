use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Instant;

use rand::RngExt;

use crate::protocol::packet::{Packet, PacketFlag, flag_to_int};
use crate::protocol::payload::Payload;

// max payload-data bytes per fragment before splitting.
const MAX_CHUNK: usize = 1200;
// time after which an uncompleted fragmented packet is dropped
const ENTRY_TIMEOUT: u64 = 60;

pub fn split_packet(packet: &Packet) -> Vec<Packet> {
    let serialized = packet.serialize();
    let total = ((serialized.len() + MAX_CHUNK - 1) / MAX_CHUNK) as u8;

    if total <= 1 {
        return vec![packet.clone()];
    }

    let fragment_id = packet.header.id;
    let mut fragments = Vec::with_capacity(total as usize);

    for (i, chunk) in serialized.chunks(MAX_CHUNK).enumerate() {
        let idx = i as u8;
        let is_last = idx + 1 == total;

        let flags = if is_last {
            flag_to_int(PacketFlag::Fragmented) | flag_to_int(PacketFlag::LastFragment)
        } else {
            flag_to_int(PacketFlag::Fragmented)
        };

        fragments.push(Packet::new(
            flags,
            rand::rng().random(),   // unique per-fragment id for dedup
            Payload::new_fragment(
                packet.payload.tag,
                chunk.to_vec(),
                fragment_id,
                idx,
                total,
            ),
        ));
    }

    fragments
}

pub struct Reassembler {
    pub pending: HashMap<(u128, SocketAddr), PendingReassembly>
}

pub struct PendingReassembly {
    total: u8,
    chunks: Vec<Option<Vec<u8>>>,
    started: Instant,
}

impl Reassembler {
    pub fn new() -> Self {
        Self { pending: HashMap::new() }
    }

    pub fn feed(&mut self, packet: &Packet, sender: SocketAddr) -> Option<Packet> {
        let fragment_id = packet.payload.fragment_id;
        if fragment_id == 0 {
            return Some(packet.clone())
        }

        let index = packet.payload.fragment_index;
        let total = packet.payload.fragment_total;
        let pr = self.pending.entry((fragment_id, sender))
            .or_insert_with(|| PendingReassembly::new(total));


        if pr.total != total {
            pr.total = total;
            pr.chunks = vec![None; total as usize];
            pr.started = Instant::now();
        }

        pr.chunks[index as usize] = Some(packet.payload.data.clone());
        let assembled = pr.is_full()?;

        // assembled bytes are the original packet's full serialized form
        Packet::from_serialized(assembled).ok()
    }

    pub fn evict_stale(&mut self) {
        self.pending.retain(|_, pr| pr.started.elapsed().as_secs() < ENTRY_TIMEOUT);
    }
}

impl PendingReassembly {
    pub fn new(total: u8) -> Self {
        Self { total, chunks: vec![None; total as usize], started: Instant::now() }
    }

    pub fn is_full(&self) -> Option<Vec<u8>> {
        let mut data: Vec<u8> = vec![];
        for chunk in self.chunks.iter() {
            if chunk.is_none() {
                return None;
            }
            data.extend(chunk.clone().as_mut().unwrap().iter());
        }
        Some(data)
    }
}