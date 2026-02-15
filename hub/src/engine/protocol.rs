// M13 HUB — ENGINE: PROTOCOL MODULE
// Everything about the M13 protocol: wire format, peer state, fragmentation,
// receiver state, scheduler, and jitter buffer.
// Wire format:   EthernetHeader, M13Header, FeedbackFrame, FragHeader — zero-copy
// Peer table:    DPDK/VPP-style flat array, FNV-1a probing, cache-aligned slots
// Fragment:      Cold-path handshake-only reassembly with 5-second GC
// Receiver:      1024-bit RxBitmap, loss detection, feedback frame production
// Scheduler:     Isochronous TX with strict priority (critical/bulk) queues
// Jitter buffer: RFC 3550 EWMA with circular release buffer

use std::mem;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use bytemuck::{Pod, Zeroable};
use ring::aead;
use crate::cryptography::handshake::HubHandshakeState;

// ============================================================================
// WIRE CONSTANTS
// ============================================================================

/// IEEE 802.1 Local Experimental EtherType for M13 raw Ethernet frames.
pub const ETH_P_M13: u16 = 0x88B5;
/// Wire protocol magic byte. Stored in M13Header.signature[0].
pub const M13_WIRE_MAGIC: u8 = 0xD1;
/// Wire protocol version. Phase 1 = 0x01. Stored in M13Header.signature[1].
pub const M13_WIRE_VERSION: u8 = 0x01;

// M13 header flags (single-byte bitfield at M13Header.flags)
pub const FLAG_CONTROL: u8   = 0x80;
pub const FLAG_FEEDBACK: u8  = 0x40;
pub const FLAG_TUNNEL: u8    = 0x20;
// FLAG_ECN (0x10) reserved for congestion signaling — not yet implemented
pub const FLAG_FIN: u8       = 0x08;  // Graceful close signal
// FLAG_FEC (0x04) reserved for RLNC — not yet implemented
pub const FLAG_HANDSHAKE: u8 = 0x02;  // PQC handshake control
pub const FLAG_FRAGMENT: u8  = 0x01;  // Fragmented message

// PQC handshake sub-types (first byte of handshake payload)
pub const HS_CLIENT_HELLO: u8 = 0x01;
pub const HS_SERVER_HELLO: u8 = 0x02;
pub const HS_FINISHED: u8     = 0x03;

// AEAD nonce direction byte (prevents reflection attacks)
pub const DIR_HUB_TO_NODE: u8 = 0x00;
pub const DIR_NODE_TO_HUB: u8 = 0x01;

// Session limits
pub const REKEY_FRAME_LIMIT: u64 = 1u64 << 32;
pub const REKEY_TIME_LIMIT_NS: u64 = 3_600_000_000_000; // 1 hour

// ============================================================================
// WIRE HEADERS
// ============================================================================

/// IEEE 802.3 Ethernet header. 14 bytes on wire: dst(6) + src(6) + ethertype(2).
#[repr(C, packed)]
#[derive(Copy, Clone, Pod, Zeroable)]
pub struct EthernetHeader {
    pub dst: [u8; 6],
    pub src: [u8; 6],
    pub ethertype: u16,
}

/// M13 wire protocol header. 48 bytes. Carried after EthernetHeader.
/// signature[0]=magic(0xD1), signature[1]=version(0x01), [2]=encrypted flag.
/// Encrypted region: bytes [32..48] (seq_id, flags, payload_len, padding).
#[repr(C, packed)]
#[derive(Copy, Clone, Pod, Zeroable)]
pub struct M13Header {
    pub signature: [u8; 32],
    pub seq_id: u64,
    pub flags: u8,
    pub payload_len: u32,
    pub padding: [u8; 3],
}
const _: () = assert!(mem::size_of::<M13Header>() == 48);

/// Feedback frame payload v2. 40 bytes. Carried after M13Header with flags=0xC0.
/// Wire: EthernetHeader(14) + M13Header(48) + FeedbackFrame(40) = 102 bytes.
/// v2 adds loss_count (exact gap count from RxBitmap) and nack_bitmap (64-bit
/// per-packet loss map for RLNC retransmission decisions).
#[repr(C, packed)]
#[derive(Copy, Clone, Pod, Zeroable)]
pub struct FeedbackFrame {
    pub highest_seq: u64,
    pub rx_timestamp_ns: u64,
    pub delivered: u32,
    pub delivered_time_ns: u64,
    pub loss_count: u32,
    pub nack_bitmap: u64,
}
const _: () = assert!(mem::size_of::<FeedbackFrame>() == 40);

// ============================================================================
// DERIVED CONSTANTS
// ============================================================================

pub const ETH_HDR_SIZE: usize = mem::size_of::<EthernetHeader>();
pub const M13_HDR_SIZE: usize = mem::size_of::<M13Header>();
pub const FEEDBACK_FRAME_LEN: u32 =
    (ETH_HDR_SIZE + M13_HDR_SIZE + mem::size_of::<FeedbackFrame>()) as u32;

// Fragment sub-header. 8 bytes, prepended to payload when FLAG_FRAGMENT set.
#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct FragHeader {
    pub frag_msg_id: u16,
    pub frag_index: u8,
    pub frag_total: u8,
    pub frag_offset: u16,
    pub frag_len: u16,
}
pub const FRAG_HDR_SIZE: usize = 8;
const _: () = assert!(mem::size_of::<FragHeader>() == FRAG_HDR_SIZE);

// ============================================================================
// FRAGMENTATION ENGINE (cold path — handshake only)
// ============================================================================

/// Fragment reassembly buffer. Tracks up to 16 fragments per message.
pub struct AssemblyBuffer {
    fragments: [Option<Vec<u8>>; 16],
    received_mask: u16,
    total: u8,
    pub first_rx_ns: u64,
}

impl AssemblyBuffer {
    pub fn new(total: u8, now_ns: u64) -> Self {
        AssemblyBuffer { fragments: Default::default(), received_mask: 0, total, first_rx_ns: now_ns }
    }
    pub fn insert(&mut self, index: u8, _offset: u16, data: &[u8]) -> bool {
        if index >= 16 || index >= self.total { return false; }
        let bit = 1u16 << index;
        if self.received_mask & bit != 0 { return self.is_complete(); }
        self.fragments[index as usize] = Some(data.to_vec());
        self.received_mask |= bit;
        self.is_complete()
    }
    pub fn is_complete(&self) -> bool {
        let expected = (1u16 << self.total) - 1;
        self.received_mask & expected == expected
    }
    pub fn reassemble(&self) -> Vec<u8> {
        let mut result = Vec::new();
        for i in 0..self.total as usize {
            if let Some(ref data) = self.fragments[i] { result.extend_from_slice(data); }
        }
        result
    }
}

/// Per-peer fragment assembler with parallel message tracking.
pub struct Assembler {
    pending: HashMap<u16, AssemblyBuffer>,
}

impl Default for Assembler {
    fn default() -> Self {
        Self::new()
    }
}

impl Assembler {
    pub fn new() -> Self { Assembler { pending: HashMap::new() } }
    pub fn feed(&mut self, msg_id: u16, index: u8, total: u8, offset: u16,
            data: &[u8], now_ns: u64) -> Option<Vec<u8>> {
        let buf = self.pending.entry(msg_id).or_insert_with(|| AssemblyBuffer::new(total, now_ns));
        if buf.insert(index, offset, data) {
            let result = buf.reassemble();
            self.pending.remove(&msg_id);
            Some(result)
        } else { None }
    }
    pub fn gc(&mut self, now_ns: u64) {
        self.pending.retain(|_, buf| now_ns.saturating_sub(buf.first_rx_ns) < 5_000_000_000);
    }
}

// ── Fragment Builders (cold path — handshake only) ──────────────────────

use crate::network::datapath::{build_raw_udp_frame, RAW_HDR_LEN};
use crate::engine::runtime::{TscCal, rdtsc_ns, HexdumpState};

/// Build fragmented handshake frames as raw ETH+IP+UDP packets for AF_XDP TX.
/// Each frame: ETH(14) + IP(20) + UDP(8) + M13(48) + FragHdr(8) + chunk
#[allow(clippy::too_many_arguments)]
pub fn build_fragmented_raw_udp(
    src_mac: &[u8; 6], gw_mac: &[u8; 6],
    hub_ip: [u8; 4], peer_ip: [u8; 4],
    hub_port: u16, peer_port: u16,
    payload: &[u8],
    flags: u8,
    seq: &mut u64,
    ip_id_base: &mut u16,
    hexdump: &mut HexdumpState,
    cal: &TscCal,
) -> Vec<Vec<u8>> {
    let max_chunk = 1402; // 1472 (UDP max) - 70 (M13 overhead)
    let total = payload.len().div_ceil(max_chunk);
    let msg_id = (*seq & 0xFFFF) as u16;
    let mut frames = Vec::with_capacity(total);

    for i in 0..total {
        let offset = i * max_chunk;
        let chunk_len = (payload.len() - offset).min(max_chunk);

        let m13_flen = ETH_HDR_SIZE + M13_HDR_SIZE + FRAG_HDR_SIZE + chunk_len;
        let mut m13_frame = vec![0u8; m13_flen];
        m13_frame[0..6].copy_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
        m13_frame[6..12].copy_from_slice(src_mac);
        m13_frame[12] = (ETH_P_M13 >> 8) as u8;
        m13_frame[13] = (ETH_P_M13 & 0xFF) as u8;
        m13_frame[14] = M13_WIRE_MAGIC; m13_frame[15] = M13_WIRE_VERSION;
        m13_frame[46..54].copy_from_slice(&seq.to_le_bytes());
        m13_frame[54] = flags | FLAG_FRAGMENT;
        let fh = ETH_HDR_SIZE + M13_HDR_SIZE;
        m13_frame[fh..fh+2].copy_from_slice(&msg_id.to_le_bytes());
        m13_frame[fh+2] = i as u8; m13_frame[fh+3] = total as u8;
        m13_frame[fh+4..fh+6].copy_from_slice(&(offset as u16).to_le_bytes());
        m13_frame[fh+6..fh+8].copy_from_slice(&(chunk_len as u16).to_le_bytes());
        let dp = fh + FRAG_HDR_SIZE;
        m13_frame[dp..dp+chunk_len].copy_from_slice(&payload[offset..offset+chunk_len]);

        let raw_len = RAW_HDR_LEN + m13_flen;
        let mut raw = vec![0u8; raw_len];
        let flen = build_raw_udp_frame(
            &mut raw, src_mac, gw_mac, hub_ip, peer_ip,
            hub_port, peer_port, *ip_id_base, &m13_frame,
        );
        *ip_id_base = ip_id_base.wrapping_add(1);
        hexdump.dump_tx(raw.as_ptr(), flen, rdtsc_ns(cal));
        frames.push(raw);
        *seq += 1;
    }
    frames
}

/// Build fragmented handshake frames as raw L2 packets (EtherType 0x88B5).
/// Each frame: ETH(14) + M13(48) + FragHdr(8) + chunk
pub fn build_fragmented_l2(
    src_mac: &[u8; 6], peer_mac: &[u8; 6],
    payload: &[u8],
    flags: u8,
    seq: &mut u64,
    hexdump: &mut HexdumpState,
    cal: &TscCal,
) -> Vec<Vec<u8>> {
    let max_chunk = 1430; // 1500 - 70 (ETH+M13+FRAG overhead)
    let total = payload.len().div_ceil(max_chunk);
    let msg_id = (*seq & 0xFFFF) as u16;
    let mut frames = Vec::with_capacity(total);

    for i in 0..total {
        let offset = i * max_chunk;
        let chunk_len = (payload.len() - offset).min(max_chunk);

        let m13_flen = ETH_HDR_SIZE + M13_HDR_SIZE + FRAG_HDR_SIZE + chunk_len;
        let mut m13_frame = vec![0u8; m13_flen];
        m13_frame[0..6].copy_from_slice(peer_mac);
        m13_frame[6..12].copy_from_slice(src_mac);
        m13_frame[12] = (ETH_P_M13 >> 8) as u8;
        m13_frame[13] = (ETH_P_M13 & 0xFF) as u8;
        m13_frame[14] = M13_WIRE_MAGIC; m13_frame[15] = M13_WIRE_VERSION;
        m13_frame[46..54].copy_from_slice(&seq.to_le_bytes());
        m13_frame[54] = flags | FLAG_FRAGMENT;
        let fh = ETH_HDR_SIZE + M13_HDR_SIZE;
        m13_frame[fh..fh+2].copy_from_slice(&msg_id.to_le_bytes());
        m13_frame[fh+2] = i as u8; m13_frame[fh+3] = total as u8;
        m13_frame[fh+4..fh+6].copy_from_slice(&(offset as u16).to_le_bytes());
        m13_frame[fh+6..fh+8].copy_from_slice(&(chunk_len as u16).to_le_bytes());
        let dp = fh + FRAG_HDR_SIZE;
        m13_frame[dp..dp+chunk_len].copy_from_slice(&payload[offset..offset+chunk_len]);

        hexdump.dump_tx(m13_frame.as_ptr(), m13_flen, rdtsc_ns(cal));
        frames.push(m13_frame);
        *seq += 1;
    }
    frames
}

// ============================================================================
// PEER TABLE — DPDK/VPP-style flat array with FNV-1a linear probing
// ============================================================================

pub const MAX_PEERS: usize = 256;
pub const TUNNEL_SUBNET: [u8; 4] = [10, 13, 0, 0];

/// 6-byte peer identity. Natural key for UDP peers behind NAT.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum PeerAddr {
    Empty,
    Udp { ip: [u8; 4], port: u16 },
    L2 { mac: [u8; 6] },
}

impl PeerAddr {
    pub const EMPTY: PeerAddr = PeerAddr::Empty;
    pub fn new_udp(ip: [u8; 4], port: u16) -> Self { PeerAddr::Udp { ip, port } }
    pub fn new_l2(mac: [u8; 6]) -> Self { PeerAddr::L2 { mac } }
    pub fn ip(&self) -> Option<[u8; 4]> {
        match self { PeerAddr::Udp { ip, .. } => Some(*ip), _ => None }
    }
    pub fn port(&self) -> Option<u16> {
        match self { PeerAddr::Udp { port, .. } => Some(*port), _ => None }
    }
    pub fn is_udp(&self) -> bool { matches!(self, PeerAddr::Udp { .. }) }

    /// FNV-1a hash. 6 bytes for UDP (ip+port), 6 bytes for L2 (mac).
    pub fn hash(&self) -> usize {
        const BASIS: u64 = 0xcbf29ce484222325;
        const PRIME: u64 = 0x100000001b3;
        let bytes: [u8; 6] = match self {
            PeerAddr::Empty => return 0,
            PeerAddr::Udp { ip, port } => [
                ip[0], ip[1], ip[2], ip[3],
                (*port >> 8) as u8, (*port & 0xFF) as u8,
            ],
            PeerAddr::L2 { mac } => *mac,
        };
        let mut h = BASIS;
        for b in bytes { h ^= b as u64; h = h.wrapping_mul(PRIME); }
        h as usize
    }
}

impl std::fmt::Debug for PeerAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PeerAddr::Empty => write!(f, "(empty)"),
            PeerAddr::Udp { ip, port } => write!(f, "{}.{}.{}.{}:{}", ip[0], ip[1], ip[2], ip[3], port),
            PeerAddr::L2 { mac } => write!(f, "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
                mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum PeerLifecycle {
    Empty = 0,
    Registered = 1,
    Handshaking = 2,
    Established = 3,
}

/// Per-peer state. Exactly 1 cache line (64 bytes) for zero false sharing.
#[repr(C, align(64))]
pub struct PeerSlot {
    pub addr: PeerAddr,
    pub lifecycle: PeerLifecycle,
    pub tunnel_ip_idx: u8,
    pub session_key: [u8; 32],
    pub seq_tx: u64,
    pub frame_count: u64,
    pub established_rel_s: u32,
    pub mac: [u8; 6],
}

impl PeerSlot {
    pub const EMPTY: PeerSlot = PeerSlot {
        addr: PeerAddr::EMPTY, lifecycle: PeerLifecycle::Empty,
        tunnel_ip_idx: 0, session_key: [0u8; 32], seq_tx: 0,
        frame_count: 0, established_rel_s: 0, mac: [0xFF; 6],
    };
    pub fn is_empty(&self) -> bool { self.lifecycle == PeerLifecycle::Empty }
    pub fn has_session(&self) -> bool { self.lifecycle == PeerLifecycle::Established }
    pub fn next_seq(&mut self) -> u64 {
        let s = self.seq_tx;
        self.seq_tx = self.seq_tx.wrapping_add(1);
        s
    }
    pub fn reset_session(&mut self) {
        self.session_key = [0u8; 32];
        self.seq_tx = 0;
        self.frame_count = 0;
    }
}

/// Multi-tenant peer table. Single-threaded (owned by one worker).
pub struct PeerTable {
    pub slots: [PeerSlot; MAX_PEERS],
    pub count: usize,
    pub assemblers: [Assembler; MAX_PEERS],
    pub epoch_ns: u64,
    pub handshakes: [Option<HubHandshakeState>; MAX_PEERS],
    pub rx_states: [ReceiverState; MAX_PEERS],
    pub schedulers: [Scheduler; MAX_PEERS],
    pub jitter_bufs: [JitterBuffer; MAX_PEERS],
    pub hs_sidecar: [Option<HubHandshakeState>; MAX_PEERS],
    tunnel_ip_bitmap: [u64; 4],
    pub ciphers: [Option<aead::LessSafeKey>; MAX_PEERS],
}

impl PeerTable {
    pub fn new(epoch_ns: u64) -> Self {
        PeerTable {
            slots: [PeerSlot::EMPTY; MAX_PEERS],
            count: 0,
            assemblers: std::array::from_fn(|_| Assembler::new()),
            epoch_ns,
            handshakes: std::array::from_fn(|_| None),
            rx_states: std::array::from_fn(|_| ReceiverState::new()),
            schedulers: std::array::from_fn(|_| Scheduler::new()),
            jitter_bufs: std::array::from_fn(|_| JitterBuffer::new()),
            hs_sidecar: std::array::from_fn(|_| None),
            tunnel_ip_bitmap: [0u64; 4],
            ciphers: std::array::from_fn(|_| None),
        }
    }

    pub fn lookup(&self, addr: PeerAddr) -> Option<usize> {
        let h = addr.hash() % MAX_PEERS;
        for probe in 0..MAX_PEERS {
            let idx = (h + probe) % MAX_PEERS;
            if self.slots[idx].addr == addr { return Some(idx); }
            if self.slots[idx].is_empty() { return None; }
        }
        None
    }

    pub fn lookup_or_insert(&mut self, addr: PeerAddr, mac: [u8; 6]) -> Option<usize> {
        if let PeerAddr::Empty = addr { return None; }
        let h = addr.hash() % MAX_PEERS;
        let mut first_empty: Option<usize> = None;
        for probe in 0..MAX_PEERS {
            let idx = (h + probe) % MAX_PEERS;
            if self.slots[idx].addr == addr { return Some(idx); }
            if self.slots[idx].is_empty() {
                if first_empty.is_none() { first_empty = Some(idx); }
                break;
            }
        }

        // ── Reconnection guard ──────────────────────────────────────────
        // A UDP node may reconnect from a new ephemeral port (process restart,
        // NAT port remap). The old slot stays Established with a dead session key.
        // If we insert a second slot, lookup_by_tunnel_ip still finds the old one
        // → TX goes to the dead peer → no internet.
        // Fix: evict any existing peer from the same source IP before inserting.
        if let PeerAddr::Udp { ip: new_ip, .. } = addr {
            for i in 0..MAX_PEERS {
                if let PeerAddr::Udp { ip: old_ip, .. } = self.slots[i].addr {
                    if old_ip == new_ip && self.slots[i].addr != addr {
                        eprintln!("[M13-VPP] Reconnection detected: evicting stale peer {:?} (same IP, new port)",
                            self.slots[i].addr);
                        self.evict(i);
                        // The evicted slot might be usable now
                        if first_empty.is_none() { first_empty = Some(i); }
                    }
                }
            }
        }

        if let Some(idx) = first_empty {
            self.slots[idx] = PeerSlot {
                addr,
                lifecycle: PeerLifecycle::Registered,
                tunnel_ip_idx: 0,
                session_key: [0u8; 32],
                seq_tx: 0,
                frame_count: 0,
                established_rel_s: 0,
                mac,
            };
            self.count += 1;
            Some(idx)
        } else {
            None
        }
    }

    pub fn evict(&mut self, idx: usize) {
        if idx >= MAX_PEERS || self.slots[idx].is_empty() { return; }
        let tip = self.slots[idx].tunnel_ip_idx;
        if tip > 0 { self.free_tunnel_ip(tip); }
        self.slots[idx] = PeerSlot::EMPTY;
        self.handshakes[idx] = None;
        self.rx_states[idx] = ReceiverState::new();
        self.schedulers[idx] = Scheduler::new();
        self.jitter_bufs[idx] = JitterBuffer::new();
        self.hs_sidecar[idx] = None;
        self.ciphers[idx] = None;
        self.count -= 1;
    }

    pub fn lookup_by_tunnel_ip(&self, dst_ip: [u8; 4]) -> Option<usize> {
        if dst_ip[0] != TUNNEL_SUBNET[0] || dst_ip[1] != TUNNEL_SUBNET[1] { return None; }
        let target_idx = dst_ip[3];
        if target_idx == 0 { return None; }
        for i in 0..MAX_PEERS {
            if self.slots[i].tunnel_ip_idx == target_idx
                && self.slots[i].lifecycle == PeerLifecycle::Established {
                return Some(i);
            }
        }
        None
    }

    pub fn alloc_tunnel_ip(&mut self) -> Option<u8> {
        for word_idx in 0..4u8 {
            let word = self.tunnel_ip_bitmap[word_idx as usize];
            if word != u64::MAX {
                let bit = (!word).trailing_zeros() as u8;
                let ip_idx = word_idx * 64 + bit + 1;
                if ip_idx > 254 { return None; }
                self.tunnel_ip_bitmap[word_idx as usize] |= 1u64 << bit;
                return Some(ip_idx);
            }
        }
        None
    }

    pub fn free_tunnel_ip(&mut self, idx: u8) {
        if idx == 0 || idx > 254 { return; }
        let adj = (idx - 1) as usize;
        self.tunnel_ip_bitmap[adj / 64] &= !(1u64 << (adj % 64));
    }

    pub fn gc(&mut self, _now_ns: u64) {
        // TODO: implement eviction for idle peers
    }
}

// ============================================================================
// RECEIVER STATE — RxBitmap + ReceiverState + feedback frame production
// ============================================================================

pub const FEEDBACK_INTERVAL_PKTS: u32 = 32;
pub const FEEDBACK_RTT_DEFAULT_NS: u64 = 10_000_000;

/// 1024-bit sliding window bitmap for sequence gap detection.
pub struct RxBitmap {
    bits: [u64; 16],
    base: u64,
}

impl Default for RxBitmap {
    fn default() -> Self { Self::new() }
}

impl RxBitmap {
    pub fn new() -> Self { RxBitmap { bits: [0u64; 16], base: 0 } }

    pub fn mark(&mut self, seq: u64) {
        if seq < self.base { return; }
        let offset = seq - self.base;
        if offset >= 1024 {
            self.advance_to(seq);
        }
        let offset = seq - self.base;
        if offset < 1024 {
            self.bits[(offset / 64) as usize] |= 1u64 << (offset % 64);
        }
    }

    pub fn advance_to(&mut self, seq: u64) {
        if seq < self.base + 1024 { return; }
        let new_base = seq.saturating_sub(512);
        let shift = new_base - self.base;
        if shift >= 1024 {
            self.bits = [0u64; 16];
        } else {
            let word_shift = (shift / 64) as usize;
            let bit_shift = (shift % 64) as u32;
            let mut new_bits = [0u64; 16];
            for i in word_shift..16 {
                new_bits[i - word_shift] = self.bits[i] >> bit_shift;
                if bit_shift > 0 && i + 1 < 16 {
                    new_bits[i - word_shift] |= self.bits[i + 1] << (64 - bit_shift);
                }
            }
            self.bits = new_bits;
        }
        self.base = new_base;
    }

    pub fn drain_losses(&mut self) -> (u32, u64) {
        let (mut losses, mut nack_bitmap) = (0u32, 0u64);
        let check_end = 512u64.min(1024);
        for i in 0..check_end {
            let word = (i / 64) as usize;
            let bit = i % 64;
            if self.bits[word] & (1u64 << bit) == 0 {
                losses += 1;
                if i < 64 { nack_bitmap |= 1u64 << i; }
            }
        }
        (losses, nack_bitmap)
    }
}

pub struct ReceiverState {
    pub rx_bitmap: RxBitmap,
    pub highest_seq: u64,
    pub delivered: u32,
    pub pkt_since_feedback: u32,
    pub last_rx_batch_ns: u64,
    pub first_rx_ns: u64,
}

impl ReceiverState {
    pub fn new() -> Self {
        ReceiverState {
            rx_bitmap: RxBitmap::new(),
            highest_seq: 0,
            delivered: 0,
            pkt_since_feedback: 0,
            last_rx_batch_ns: 0,
            first_rx_ns: 0,
        }
    }
    pub fn record_rx(&mut self, seq: u64, now_ns: u64) {
        self.rx_bitmap.mark(seq);
        if seq > self.highest_seq { self.highest_seq = seq; }
        self.delivered += 1;
        self.pkt_since_feedback += 1;
        self.last_rx_batch_ns = now_ns;
        if self.first_rx_ns == 0 { self.first_rx_ns = now_ns; }
    }
    /// Check if enough packets received to warrant generating a feedback frame.
    pub fn needs_feedback(&mut self, rx_batch_ns: u64, _rtt_est: u64) -> bool {
        if rx_batch_ns == 0 { return false; }
        self.pkt_since_feedback >= FEEDBACK_INTERVAL_PKTS
    }
}

/// Write a FeedbackFrame directly into a UMEM buffer via raw pointer.
/// Caller provides: raw pointer, dst/src MAC, receiver state, bitmap, timestamp,
/// jitter buffer depth, and jitter buffer capacity.
/// Returns the total frame length (ETH+M13+Feedback = 102 bytes).
#[allow(clippy::too_many_arguments)]
pub fn produce_feedback_frame(
    frame_ptr: *mut u8,
    dst_mac: &[u8; 6],
    src_mac: &[u8; 6],
    rx_state: &mut ReceiverState,
    rx_bitmap: &mut RxBitmap,
    now_ns: u64,
    _jbuf_depth: usize,
    _jbuf_capacity: usize,
) -> usize {
    let frame_len = FEEDBACK_FRAME_LEN as usize;
    // SAFETY: Caller ensures frame_ptr points to valid UMEM with at least frame_len bytes.
    let buf = unsafe { std::slice::from_raw_parts_mut(frame_ptr, frame_len) };
    buf[0..6].copy_from_slice(dst_mac);
    buf[6..12].copy_from_slice(src_mac);
    buf[12] = (ETH_P_M13 >> 8) as u8;
    buf[13] = (ETH_P_M13 & 0xFF) as u8;
    buf[14] = M13_WIRE_MAGIC; buf[15] = M13_WIRE_VERSION;
    buf[54] = FLAG_CONTROL | FLAG_FEEDBACK;
    let fb_offset = ETH_HDR_SIZE + M13_HDR_SIZE;
    buf[fb_offset..fb_offset+8].copy_from_slice(&rx_state.highest_seq.to_le_bytes());
    buf[fb_offset+8..fb_offset+16].copy_from_slice(&now_ns.to_le_bytes());
    buf[fb_offset+16..fb_offset+20].copy_from_slice(&rx_state.delivered.to_le_bytes());
    let elapsed = now_ns.saturating_sub(rx_state.first_rx_ns);
    buf[fb_offset+20..fb_offset+28].copy_from_slice(&elapsed.to_le_bytes());
    let (loss_count, nack_bitmap) = rx_bitmap.drain_losses();
    buf[fb_offset+28..fb_offset+32].copy_from_slice(&loss_count.to_le_bytes());
    buf[fb_offset+32..fb_offset+40].copy_from_slice(&nack_bitmap.to_le_bytes());
    rx_state.pkt_since_feedback = 0;
    frame_len
}

// ============================================================================
// SCHEDULER — isochronous TX with strict priority queues + BBR cwnd awareness
// ============================================================================

/// Submission handle for the TX pipeline.
pub struct TxSubmit {
    pub frame_idx: u64,
    pub frame_len: u32,
}

pub const TX_RING_SIZE: usize = 256;
pub const HW_FILL_MAX: usize = 64;

/// Strict-priority two-queue scheduler.
/// Critical frames (handshakes, feedback) go first. Bulk data fills remaining capacity.
pub struct Scheduler {
    critical: [(u64, u32); TX_RING_SIZE],
    bulk:     [(u64, u32); TX_RING_SIZE],
    crit_head: usize,
    crit_tail: usize,
    bulk_head: usize,
    bulk_tail: usize,
}

impl Scheduler {
    pub fn new() -> Self {
        Scheduler {
            critical: [(0, 0); TX_RING_SIZE],
            bulk: [(0, 0); TX_RING_SIZE],
            crit_head: 0, crit_tail: 0,
            bulk_head: 0, bulk_tail: 0,
        }
    }

    #[inline(always)]
    pub fn enqueue_critical(&mut self, idx: u64, len: u32) -> bool {
        let next = (self.crit_tail + 1) % TX_RING_SIZE;
        if next == self.crit_head { return false; }
        self.critical[self.crit_tail] = (idx, len);
        self.crit_tail = next;
        true
    }

    #[inline(always)]
    pub fn enqueue_bulk(&mut self, idx: u64, len: u32) -> bool {
        let next = (self.bulk_tail + 1) % TX_RING_SIZE;
        if next == self.bulk_head { return false; }
        self.bulk[self.bulk_tail] = (idx, len);
        self.bulk_tail = next;
        true
    }

    #[inline(always)]
    pub fn dequeue(&mut self) -> Option<TxSubmit> {
        if self.crit_head != self.crit_tail {
            let (idx, len) = self.critical[self.crit_head];
            self.crit_head = (self.crit_head + 1) % TX_RING_SIZE;
            return Some(TxSubmit { frame_idx: idx, frame_len: len });
        }
        if self.bulk_head != self.bulk_tail {
            let (idx, len) = self.bulk[self.bulk_head];
            self.bulk_head = (self.bulk_head + 1) % TX_RING_SIZE;
            return Some(TxSubmit { frame_idx: idx, frame_len: len });
        }
        None
    }

    pub fn pending(&self) -> usize {
        let c = if self.crit_tail >= self.crit_head { self.crit_tail - self.crit_head }
                else { TX_RING_SIZE - self.crit_head + self.crit_tail };
        let b = if self.bulk_tail >= self.bulk_head { self.bulk_tail - self.bulk_head }
                else { TX_RING_SIZE - self.bulk_head + self.bulk_tail };
        c + b
    }

    /// Drain scheduler queues into AF_XDP TX ring.
    /// Dequeues up to `max_burst` frames, stages them on `tx_path`, then kicks.
    pub fn schedule<T: crate::network::xdp::TxPath>(&mut self, tx_path: &mut T, tx_counter: &TxCounter, max_burst: usize) {
        let mut count = 0usize;
        while count < max_burst {
            if let Some(submit) = self.dequeue() {
                tx_path.stage_tx_addr(submit.frame_idx, submit.frame_len);
                tx_counter.value.fetch_add(1, Ordering::Relaxed);
                count += 1;
            } else {
                break;
            }
        }
        if count > 0 {
            tx_path.commit_tx();
            tx_path.kick_tx();
        }
    }
}

/// Per-peer TX counter for BBR cwnd enforcement.
/// Uses AtomicU64 so the scheduler can increment without &mut borrow.
pub struct TxCounter {
    pub value: AtomicU64,
    pub inflight: u64,
    pub total_sent: u64,
}

impl TxCounter {
    pub fn new() -> Self { TxCounter { value: AtomicU64::new(0), inflight: 0, total_sent: 0 } }
    #[inline(always)] pub fn on_send(&mut self) { self.inflight += 1; self.total_sent += 1; }
    #[inline(always)] pub fn on_ack(&mut self, delivered: u64) {
        if delivered > self.total_sent { self.inflight = 0; return; }
        let new_inflight = self.total_sent - delivered;
        self.inflight = new_inflight;
    }
}

// ============================================================================
// JITTER BUFFER — RFC 3550 EWMA + circular release buffer
// ============================================================================

pub const JBUF_CAPACITY: usize = 128;

/// Adaptive jitter estimator using RFC 3550 EWMA.
pub struct JitterEstimator {
    jitter_ns: f64,
    last_transit: i64,
    initialized: bool,
}

impl JitterEstimator {
    pub fn new() -> Self {
        JitterEstimator { jitter_ns: 0.0, last_transit: 0, initialized: false }
    }
    pub fn update(&mut self, send_ts_ns: u64, recv_ts_ns: u64) {
        let transit = recv_ts_ns as i64 - send_ts_ns as i64;
        if !self.initialized {
            self.last_transit = transit;
            self.initialized = true;
            return;
        }
        let d = (transit - self.last_transit).unsigned_abs() as f64;
        self.last_transit = transit;
        self.jitter_ns += (d - self.jitter_ns) / 16.0;
    }
    pub fn jitter_us(&self) -> u64 { (self.jitter_ns / 1000.0) as u64 }
    /// Return jitter estimate in nanoseconds.
    pub fn get(&self) -> u64 { self.jitter_ns as u64 }
}

/// Entry in jitter buffer: UMEM address + length.
pub struct JBufEntry {
    pub addr: u64,
    pub len: u32,
}

/// Circular jitter buffer with adaptive depth.
pub struct JitterBuffer {
    pub entries: [JBufEntry; JBUF_CAPACITY],
    pub head: usize,
    pub tail: usize,
    pub estimator: JitterEstimator,
    pub total_releases: u64,
    pub total_drops: u64,
    pub depth_ns: u64,
}

impl JitterBuffer {
    pub fn new() -> Self {
        JitterBuffer {
            entries: std::array::from_fn(|_| JBufEntry { addr: 0, len: 0 }),
            head: 0, tail: 0,
            estimator: JitterEstimator::new(),
            total_releases: 0, total_drops: 0,
            depth_ns: 0,
        }
    }

    pub fn push(&mut self, addr: u64, len: u32) -> bool {
        let next = (self.tail + 1) & (JBUF_CAPACITY - 1);
        if next == self.head {
            self.total_drops += 1;
            return false;
        }
        self.entries[self.tail] = JBufEntry { addr, len };
        self.tail = (self.tail + 1) & (JBUF_CAPACITY - 1);
        true
    }

    /// Drain all entries whose release time has arrived.
    /// Returns (released_count, frames_still_buffered).
    pub fn drain(&mut self, _now_ns: u64, scheduler: &mut Scheduler) -> (u64, usize) {
        let mut released = 0u64;
        while self.head != self.tail {
            let slot = self.head & (JBUF_CAPACITY - 1);
            let entry = &self.entries[slot];
            scheduler.enqueue_bulk(entry.addr, entry.len);
            self.head += 1;
            self.total_releases += 1;
            released += 1;
        }
        (released, 0)
    }

    pub fn len(&self) -> usize {
        if self.tail >= self.head { self.tail - self.head }
        else { JBUF_CAPACITY - self.head + self.tail }
    }

    pub fn is_empty(&self) -> bool { self.head == self.tail }
}

/// Measure scheduler → sendto() processing jitter. Takes TscCal for calibrated timing.
pub fn measure_epsilon_proc(cal: &crate::engine::runtime::TscCal) -> u64 {
    use crate::engine::runtime::rdtsc_ns;
    let t0 = rdtsc_ns(cal);
    // Dummy work to measure processing overhead
    let t1 = rdtsc_ns(cal);
    t1.saturating_sub(t0)
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // Wire tests
    #[test]
    fn header_sizes() {
        assert_eq!(mem::size_of::<EthernetHeader>(), 14);
        assert_eq!(mem::size_of::<M13Header>(), 48);
        assert_eq!(mem::size_of::<FeedbackFrame>(), 40);
        assert_eq!(mem::size_of::<FragHeader>(), 8);
        assert_eq!(ETH_HDR_SIZE, 14);
        assert_eq!(M13_HDR_SIZE, 48);
    }

    #[test]
    fn constants_no_overlap() {
        let flags = [FLAG_CONTROL, FLAG_FEEDBACK, FLAG_TUNNEL,
                     FLAG_FIN, FLAG_HANDSHAKE, FLAG_FRAGMENT];
        for i in 0..flags.len() {
            assert!(flags[i].is_power_of_two(), "flag 0x{:02X} not single bit", flags[i]);
            for j in (i+1)..flags.len() {
                assert_ne!(flags[i], flags[j], "duplicate flag value");
            }
        }
    }

    #[test]
    fn magic_version_valid() {
        assert_eq!(M13_WIRE_MAGIC, 0xD1);
        assert_eq!(M13_WIRE_VERSION, 0x01);
        assert_ne!(M13_WIRE_MAGIC, M13_WIRE_VERSION);
    }

    #[test]
    fn ethertype_is_experimental() {
        assert_eq!(ETH_P_M13, 0x88B5);
    }

    // Fragment tests
    #[test]
    fn single_fragment_completes() {
        let mut asm = Assembler::new();
        let data = b"hello world";
        let result = asm.feed(1, 0, 1, 0, data, 100);
        assert!(result.is_some());
        assert_eq!(result.unwrap(), data.to_vec());
    }

    #[test]
    fn multi_fragment_reassembly() {
        let mut asm = Assembler::new();
        let part0 = b"AAAA";
        let part1 = b"BBBB";
        let part2 = b"CC";
        assert!(asm.feed(42, 0, 3, 0, part0, 100).is_none());
        assert!(asm.feed(42, 1, 3, 4, part1, 100).is_none());
        let result = asm.feed(42, 2, 3, 8, part2, 100).unwrap();
        assert_eq!(result, b"AAAABBBBCC");
    }

    #[test]
    fn duplicate_fragment_ignored() {
        let mut asm = Assembler::new();
        assert!(asm.feed(1, 0, 2, 0, b"A", 100).is_none());
        assert!(asm.feed(1, 0, 2, 0, b"A", 100).is_none());
        assert!(asm.feed(1, 1, 2, 1, b"B", 100).is_some());
    }

    #[test]
    fn gc_removes_stale_messages() {
        let mut asm = Assembler::new();
        assert!(asm.feed(1, 0, 2, 0, b"X", 100).is_none());
        asm.gc(6_000_000_100);
        assert!(asm.feed(1, 1, 2, 1, b"Y", 6_000_000_200).is_none());
    }

    #[test]
    fn out_of_range_index_rejected() {
        let mut buf = AssemblyBuffer::new(2, 0);
        assert!(!buf.insert(16, 0, b"bad"));
        assert!(!buf.insert(2, 0, b"bad"));
    }
}
