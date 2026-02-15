// M13 NODE — ENGINE: PROTOCOL MODULE
// Wire format, fragmentation, and frame builders.
// Zero-share: independent copy from Hub.

use std::mem;
use std::net::UdpSocket;
use bytemuck::{Pod, Zeroable};

// ============================================================================
// WIRE CONSTANTS
// ============================================================================

/// IEEE 802.1 Local Experimental EtherType for M13 raw Ethernet frames.
pub const ETH_P_M13: u16 = 0x88B5;
/// Wire protocol magic byte. Stored in M13Header.signature[0].
pub const M13_WIRE_MAGIC: u8 = 0xD1;
/// Wire protocol version. Phase 1 = 0x01.
pub const M13_WIRE_VERSION: u8 = 0x01;

/// IEEE 802.3 Ethernet header. 14 bytes on wire: dst(6) + src(6) + ethertype(2).
#[repr(C, packed)] #[derive(Copy, Clone, Pod, Zeroable)]
pub struct EthernetHeader { pub dst: [u8; 6], pub src: [u8; 6], pub ethertype: u16 }

/// M13 wire protocol header. 48 bytes. Carried after EthernetHeader.
/// signature[0]=magic(0xD1), signature[1]=version(0x01), [2..32]=reserved(Phase 2 crypto).
#[repr(C, packed)] #[derive(Copy, Clone, Pod, Zeroable)]
pub struct M13Header {
    pub signature: [u8; 32], pub seq_id: u64, pub flags: u8,
    pub payload_len: u32, pub padding: [u8; 3],
}
const _: () = assert!(mem::size_of::<M13Header>() == 48);

pub const ETH_HDR_SIZE: usize = mem::size_of::<EthernetHeader>();
pub const M13_HDR_SIZE: usize = mem::size_of::<M13Header>();

pub const FLAG_CONTROL: u8   = 0x80;
pub const FLAG_TUNNEL: u8    = 0x20;
pub const FLAG_HANDSHAKE: u8 = 0x02;
pub const FLAG_FRAGMENT: u8  = 0x01;

/// Handshake timeout: 5 seconds to complete 3-message exchange
pub const HANDSHAKE_TIMEOUT_NS: u64 = 5_000_000_000;
/// Rekey after 2^32 frames under one session key
pub const REKEY_FRAME_LIMIT: u64 = 1u64 << 32;
/// Rekey after 1 hour under one session key
pub const REKEY_TIME_LIMIT_NS: u64 = 3_600_000_000_000;

// PQC handshake sub-types (first byte of handshake payload)
pub const HS_CLIENT_HELLO: u8 = 0x01;
pub const HS_SERVER_HELLO: u8 = 0x02;
pub const HS_FINISHED: u8     = 0x03;

// Direction bytes for AEAD nonce (prevents reflection attacks)
pub const DIR_NODE_TO_HUB: u8 = 0x01;

// ============================================================================
// FRAME BUILDER
// ============================================================================
pub fn build_m13_frame(src_mac: &[u8; 6], dst_mac: &[u8; 6], seq: u64, flags: u8) -> [u8; 62] {
    let mut frame = [0u8; 62];
    frame[0..6].copy_from_slice(dst_mac);
    frame[6..12].copy_from_slice(src_mac);
    frame[12] = (ETH_P_M13 >> 8) as u8;
    frame[13] = (ETH_P_M13 & 0xFF) as u8;
    frame[14] = M13_WIRE_MAGIC;
    frame[15] = M13_WIRE_VERSION;
    frame[46..54].copy_from_slice(&seq.to_le_bytes());
    frame[54] = flags;
    frame
}

pub fn build_echo_frame(rx_frame: &[u8], new_seq: u64) -> Option<Vec<u8>> {
    if rx_frame.len() < ETH_HDR_SIZE + M13_HDR_SIZE { return None; }
    let mut echo = rx_frame.to_vec();
    // Swap dst/src MAC
    let (dst, src) = echo.split_at_mut(6);
    let mut tmp = [0u8; 6];
    tmp.copy_from_slice(&dst[..6]);
    dst[..6].copy_from_slice(&src[..6]);
    src[..6].copy_from_slice(&tmp);
    // Stamp our seq
    echo[46..54].copy_from_slice(&new_seq.to_le_bytes());
    Some(echo)
}

/// Read the hardware MAC address of a network interface from sysfs.
/// Returns the 6-byte MAC or a locally-administered random fallback.
pub fn detect_mac(if_name: Option<&str>) -> [u8; 6] {
    if let Some(iface) = if_name {
        let path = format!("/sys/class/net/{}/address", iface);
        if let Ok(contents) = std::fs::read_to_string(&path) {
            let parts: Vec<u8> = contents.trim().split(':')
                .filter_map(|h| u8::from_str_radix(h, 16).ok())
                .collect();
            if parts.len() == 6 {
                eprintln!("[M13-NODE] Detected MAC for {}: {}", iface, contents.trim());
                return [parts[0], parts[1], parts[2], parts[3], parts[4], parts[5]];
            }
        }
    }
    // Generate a random locally-administered MAC (LAA)
    let seed = crate::engine::runtime::clock_ns() & 0xFFFFFFFFFFFF;
    let mac = [
        0x02,
        ((seed >> 8) & 0xFF) as u8,
        ((seed >> 16) & 0xFF) as u8,
        ((seed >> 24) & 0xFF) as u8,
        ((seed >> 32) & 0xFF) as u8,
        ((seed >> 40) & 0xFF) as u8,
    ];
    eprintln!("[M13-NODE] Using generated LAA MAC: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    mac
}

// ============================================================================
// FRAGMENTATION ENGINE (cold path — handshake only)
// ============================================================================

pub const FRAG_HDR_SIZE: usize = 8;

#[repr(C, packed)]
pub struct FragHeader {
    pub frag_msg_id: u16,
    pub frag_index: u8,
    pub frag_total: u8,
    pub frag_offset: u16,
    pub frag_len: u16,
}
const _: () = assert!(mem::size_of::<FragHeader>() == FRAG_HDR_SIZE);

pub struct Assembler { pending: std::collections::HashMap<u16, AssemblyBuf> }
struct AssemblyBuf { buf: Vec<u8>, mask: u16, _total: u8, created_ns: u64 }

impl Assembler {
    pub fn new() -> Self { Assembler { pending: std::collections::HashMap::new() } }

    pub fn feed(&mut self, msg_id: u16, index: u8, total: u8, offset: u16, data: &[u8], now: u64)
        -> Option<Vec<u8>> {
        let entry = self.pending.entry(msg_id).or_insert_with(|| AssemblyBuf {
            buf: Vec::with_capacity(total as usize * 1444),
            mask: 0, _total: total, created_ns: now,
        });
        if index >= 16 || index >= total { return None; }
        if entry.mask & (1 << index) != 0 { return None; }
        let off = offset as usize;
        if off + data.len() > entry.buf.len() { entry.buf.resize(off + data.len(), 0); }
        entry.buf[off..off + data.len()].copy_from_slice(data);
        entry.mask |= 1 << index;
        let need = (1u16 << total) - 1;
        if entry.mask == need { Some(self.pending.remove(&msg_id).unwrap().buf) } else { None }
    }

    pub fn gc(&mut self, now: u64) { self.pending.retain(|_, v| now - v.created_ns < 5_000_000_000); }
}

// ── Fragment Senders (cold path — handshake only) ───────────────────────

use crate::engine::runtime::{TscCal, rdtsc_ns, HexdumpState};

/// Send fragmented handshake payload over UDP.
#[allow(clippy::too_many_arguments)]
pub fn send_fragmented_udp(
    sock: &UdpSocket, src_mac: &[u8; 6], dst_mac: &[u8; 6],
    payload: &[u8], flags: u8, seq: &mut u64,
    hexdump: &mut HexdumpState, cal: &TscCal,
) -> u64 {
    let max_chunk = 1402;
    let total = payload.len().div_ceil(max_chunk);
    let msg_id = (*seq & 0xFFFF) as u16;
    let mut sent = 0u64;
    for i in 0..total {
        let offset = i * max_chunk;
        let chunk_len = (payload.len() - offset).min(max_chunk);
        let flen = ETH_HDR_SIZE + M13_HDR_SIZE + FRAG_HDR_SIZE + chunk_len;
        let mut frame = vec![0u8; flen];
        frame[0..6].copy_from_slice(dst_mac);
        frame[6..12].copy_from_slice(src_mac);
        frame[12] = (ETH_P_M13 >> 8) as u8;
        frame[13] = (ETH_P_M13 & 0xFF) as u8;
        frame[14] = M13_WIRE_MAGIC; frame[15] = M13_WIRE_VERSION;
        frame[46..54].copy_from_slice(&seq.to_le_bytes());
        frame[54] = flags | FLAG_FRAGMENT;
        let fh = ETH_HDR_SIZE + M13_HDR_SIZE;
        frame[fh..fh+2].copy_from_slice(&msg_id.to_le_bytes());
        frame[fh+2] = i as u8; frame[fh+3] = total as u8;
        frame[fh+4..fh+6].copy_from_slice(&(offset as u16).to_le_bytes());
        frame[fh+6..fh+8].copy_from_slice(&(chunk_len as u16).to_le_bytes());
        let dp = fh + FRAG_HDR_SIZE;
        frame[dp..dp+chunk_len].copy_from_slice(&payload[offset..offset+chunk_len]);
        hexdump.dump_tx(&frame, rdtsc_ns(cal));
        if sock.send(&frame).is_ok() { sent += 1; }
        *seq += 1;
    }
    sent
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_sizes() {
        assert_eq!(mem::size_of::<EthernetHeader>(), 14);
        assert_eq!(mem::size_of::<M13Header>(), 48);
        assert_eq!(ETH_HDR_SIZE, 14);
        assert_eq!(M13_HDR_SIZE, 48);
    }

    #[test]
    fn build_frame_magic_and_flags() {
        let src = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
        let dst = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        let frame = build_m13_frame(&src, &dst, 42, FLAG_CONTROL);
        assert_eq!(&frame[0..6], &dst);
        assert_eq!(&frame[6..12], &src);
        assert_eq!(frame[14], M13_WIRE_MAGIC);
        assert_eq!(frame[15], M13_WIRE_VERSION);
        assert_eq!(u64::from_le_bytes(frame[46..54].try_into().unwrap()), 42);
        assert_eq!(frame[54], FLAG_CONTROL);
    }

    #[test]
    fn echo_frame_swaps_macs() {
        let src = [0x02; 6];
        let dst = [0xAA; 6];
        let orig = build_m13_frame(&src, &dst, 1, FLAG_CONTROL);
        let echo = build_echo_frame(&orig, 99).unwrap();
        assert_eq!(&echo[0..6], &src); // dst ← original src
        assert_eq!(&echo[6..12], &dst); // src ← original dst
        assert_eq!(u64::from_le_bytes(echo[46..54].try_into().unwrap()), 99);
    }

    #[test]
    fn echo_frame_rejects_short() {
        let short = [0u8; 10];
        assert!(build_echo_frame(&short, 1).is_none());
    }

    #[test]
    fn single_fragment_completes() {
        let mut asm = Assembler::new();
        let result = asm.feed(1, 0, 1, 0, b"hello", 100);
        assert!(result.is_some());
    }

    #[test]
    fn multi_fragment_reassembly() {
        let mut asm = Assembler::new();
        assert!(asm.feed(42, 0, 3, 0, b"AAAA", 100).is_none());
        assert!(asm.feed(42, 1, 3, 4, b"BBBB", 100).is_none());
        let result = asm.feed(42, 2, 3, 8, b"CC", 100).unwrap();
        assert_eq!(&result[0..4], b"AAAA");
        assert_eq!(&result[4..8], b"BBBB");
        assert_eq!(&result[8..10], b"CC");
    }

    #[test]
    fn duplicate_fragment_ignored() {
        let mut asm = Assembler::new();
        assert!(asm.feed(1, 0, 2, 0, b"A", 100).is_none());
        assert!(asm.feed(1, 0, 2, 0, b"A", 100).is_none()); // dup
        assert!(asm.feed(1, 1, 2, 1, b"B", 100).is_some());
    }

    #[test]
    fn gc_removes_stale() {
        let mut asm = Assembler::new();
        assert!(asm.feed(1, 0, 2, 0, b"X", 100).is_none());
        asm.gc(6_000_000_100); // 6s later > 5s timeout
        assert!(asm.feed(1, 1, 2, 1, b"Y", 6_000_000_200).is_none()); // msg_id 1 was GC'd
    }

    #[test]
    fn out_of_range_rejected() {
        let mut asm = Assembler::new();
        assert!(asm.feed(1, 16, 2, 0, b"bad", 100).is_none());
        assert!(asm.feed(1, 2, 2, 0, b"bad", 100).is_none());
    }
}
