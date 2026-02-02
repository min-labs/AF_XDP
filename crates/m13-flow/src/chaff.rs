#![forbid(unsafe_code)]

extern crate alloc;
use alloc::vec::Vec;
use m13_core::{M13Header, PacketType, M13_MAGIC};
use rand_core::{RngCore, CryptoRng};

/// Generates a Chaff Packet (Spec §10.3.2).
/// The payload is cryptographic noise.
/// The header marks it as 'Data' to an observer, preventing filtering.
pub fn generate_chaff<R: RngCore + CryptoRng>(
    size: usize,
    gen_id: u16,
    rng: &mut R
) -> (M13Header, Vec<u8>) {
    let mut payload = alloc::vec![0u8; size];
    rng.fill_bytes(&mut payload);

    let header = M13Header {
        magic: M13_MAGIC,
        version: 1,
        // Chaff masquerades as Data to defeat Deep Packet Inspection
        packet_type: PacketType::Data, 
        gen_id,
        // Random Symbol ID prevents replay detection logic from blocking it too early
        symbol_id: rng.next_u32(), 
        payload_len: size as u16,
        recoder_rank: 0,
        reserved: 0xFF, // Internal Marker: "Ignore Me"
        auth_tag: [0u8; 16], 
    };

    (header, payload)
}