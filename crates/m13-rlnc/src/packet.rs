#![forbid(unsafe_code)]
extern crate alloc;
use alloc::vec::Vec;
use m13_math::GfSymbol;
use zeroize::Zeroize;

/// The RLNC Packet Structure (In-Memory).
/// Maps to wire format: [ GEV | Payload ]
#[derive(Clone, Debug, Zeroize)]
pub struct RlncPacket {
    pub gen_id: u16,
    pub gev: Vec<GfSymbol>, // Global Encoding Vector (Size K)
    pub payload: Vec<u8>,   // Data
}