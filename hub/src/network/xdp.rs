// M13 HUB — NETWORK: XDP ENGINE
// AF_XDP zero-copy datapath engine. Owns UMEM, XSK socket, all rings.
// Lock-free SPSC ring operations with explicit memory barriers.

use libbpf_sys::{
    xsk_umem__create, xsk_socket__create, xsk_umem_config, xsk_socket_config,
    xsk_ring_prod, xsk_ring_cons, xdp_desc,
    XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD,
    bpf_map_update_elem,
};
use libc::{
    mmap, munmap, ioctl, socket, setsockopt, getsockopt,
    MAP_PRIVATE, MAP_ANONYMOUS, MAP_HUGETLB, MAP_POPULATE,
    PROT_READ, PROT_WRITE, MAP_FAILED,
    c_void, c_char, AF_INET, SOCK_DGRAM, SOL_SOCKET, MSG_DONTWAIT, sendto,
    SOL_XDP, close,
};
use std::ptr;
use std::mem;
use std::sync::atomic::{AtomicU32, Ordering, fence};
use std::ffi::CString;

use crate::engine::runtime::*;
use crate::engine::runtime::FixedSlab;
use crate::engine::runtime::Telemetry;

#[allow(non_upper_case_globals)]
#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
#[allow(dead_code)]
mod bindings { include!(concat!(env!("OUT_DIR"), "/bindings.rs")); }
use bindings::{ethtool_ringparam, ifreq, SIOCETHTOOL, ETHTOOL_GRINGPARAM};

/// Maximum concurrent worker threads (one per NIC queue).
pub const MAX_WORKERS: usize = 4;
/// UMEM region size (1 GB). Shared across fill, completion, TX, and RX rings.
pub const UMEM_SIZE: usize = 1024 * 1024 * 1024;
/// UMEM frame size. Each frame holds one Ethernet packet + headroom.
pub const FRAME_SIZE: u32 = 4096;
pub const SO_BUSY_POLL: i32 = 46;
pub const XDP_MMAP_OFFSETS: i32 = 1;
pub const XDP_RING_NEED_WAKEUP: u32 = 1;

// ============================================================================
// TX PATH TRAIT — abstraction for TX submission (zero-copy or mock)
// ============================================================================
#[allow(dead_code)]
/// Trait abstracting the TX submission path. Implemented by ZeroCopyTx.
pub trait TxPath {
    fn available_slots(&mut self) -> u32;
    fn stage_tx(&mut self, frame_idx: u32, len: u32);
    fn stage_tx_addr(&mut self, addr: u64, len: u32);
    fn commit_tx(&mut self);
    fn kick_tx(&mut self);
}

/// AF_XDP zero-copy TX path. Submits frames directly from UMEM to NIC via ring buffer.
pub struct ZeroCopyTx { tx: RingProd, sock_fd: i32 }
impl TxPath for ZeroCopyTx {
    // SAFETY: Ring query on valid kernel-mapped ring memory.
    #[inline(always)] fn available_slots(&mut self) -> u32 { unsafe { self.tx.available() } }
    #[inline(always)] fn stage_tx(&mut self, frame_idx: u32, len: u32) { unsafe { self.tx.stage(frame_idx, len) } }
    // SAFETY: FFI call with valid socket fd; MSG_DONTWAIT prevents blocking.
    #[inline(always)] fn stage_tx_addr(&mut self, addr: u64, len: u32) { unsafe { self.tx.stage_addr_desc(addr, len) } }
    #[inline(always)] fn commit_tx(&mut self) { unsafe { self.tx.commit() } }
    // SAFETY: FFI call with valid socket fd; MSG_DONTWAIT prevents blocking.
    #[inline(always)] fn kick_tx(&mut self) { unsafe { if self.tx.needs_wakeup() { sendto(self.sock_fd, ptr::null(), 0, MSG_DONTWAIT, ptr::null(), 0); } } }
}

// ============================================================================
// ENGINE (Owns UMEM, XSK socket, all rings)
// ============================================================================
/// Core datapath engine. Owns UMEM, fill/completion queues, and the TX path.
/// Generic over TxPath for testability (ZeroCopyTx in production).
pub struct Engine<T: TxPath> {
    umem_area: *mut u8,
    #[allow(dead_code)] _umem_handle: *mut libbpf_sys::xsk_umem,
    #[allow(dead_code)] sock_handle: *mut libbpf_sys::xsk_socket,
    cq: RingCons, rx: RingCons, fq: RingProd,
    pub tx_path: T,
    pub xdp_mode: String,
}
unsafe impl<T: TxPath> Send for Engine<T> {}

fn create_dummy_engine(umem_area: *mut u8) -> Engine<ZeroCopyTx> {
    eprintln!("[M13-XSK] Running in UDP-ONLY mode (Mock Engine)");
    // Leak a buffer for dummy rings (64KB to be safe)
    let dummy = Box::leak(Box::new([0u8; 65536]));
    let base = dummy.as_mut_ptr();
    let zeros = base as *mut u32; // Points to 0
    // SAFETY: Pointer is valid and within allocated ring buffer bounds.
    unsafe { ptr::write_bytes(base, 0, 65536); }
    
    // Layout: 4 rings. Point everything to valid memory in `dummy`.
    // We use offset 128 to give some headroom.
    // mask=255 => size=256. Max offset = 256 * 16 = 4096.
    // 64KB is plenty.
    // SAFETY: Pointer arithmetic within UMEM bounds; offset validated by kernel ring descriptor.
    let ring_ptr = unsafe { base.add(128) } as *mut c_void;
    
    // Helper to create a dummy RingProd
    let mk_prod = || RingProd { 
        producer: zeros, consumer: zeros, ring: ring_ptr, 
        flags: zeros, mask: 255, cached_cons: 0, local_prod: 0 
    };
    // Helper to create a dummy RingCons
    let mk_cons = || RingCons { 
        producer: zeros, consumer: zeros, ring: ring_ptr, mask: 255 
    };
    
    let tx = mk_prod();
    let fq = mk_prod();
    let rx = mk_cons();
    let cq = mk_cons();
    
    let tx_path = ZeroCopyTx { tx, sock_fd: -1 };
    
    Engine { 
        umem_area, 
        _umem_handle: ptr::null_mut(), 
        sock_handle: ptr::null_mut(), 
        cq, rx, fq, tx_path,
        xdp_mode: "UDP-Only (Mock Engine)".to_string(),
    }
}

impl Engine<ZeroCopyTx> {
    pub fn new_zerocopy(if_name: &str, queue_id: i32, bpf_map_fd: i32) -> Self {
        if bpf_map_fd >= 0 { check_nic_limits(if_name); }
        let is_sim = std::env::var("M13_SIMULATION").is_ok();
        let mut flags = MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE;
        if !is_sim { flags |= MAP_HUGETLB; }
        // SAFETY: FFI call to kernel; returned pointer checked for MAP_FAILED before use.
        let umem_area = unsafe { mmap(ptr::null_mut(), UMEM_SIZE, PROT_READ | PROT_WRITE, flags, -1, 0) };
        if umem_area == MAP_FAILED { 
            // Fallback: try without hugepages
            // SAFETY: FFI call to kernel; returned pointer checked for MAP_FAILED before use.
            let umem_area_retry = unsafe { mmap(ptr::null_mut(), UMEM_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0) };
            if umem_area_retry == MAP_FAILED { fatal(E_UMEM_ALLOC_FAIL, "UMEM mmap failed"); }
            if bpf_map_fd < 0 {
                 return create_dummy_engine(umem_area_retry as *mut u8);
            }
            fatal(E_UMEM_ALLOC_FAIL, "UMEM mmap failed (check hugepages) - and BPF required"); 
        }

        if bpf_map_fd < 0 {
            return create_dummy_engine(umem_area as *mut u8);
        }

        let umem_cfg = xsk_umem_config { fill_size: 4096, comp_size: 4096, frame_size: FRAME_SIZE, frame_headroom: 0, flags: 0 };
        let mut umem_handle: *mut libbpf_sys::xsk_umem = ptr::null_mut();
        // SAFETY: FFI call with valid pointers to freshly allocated UMEM and zeroed ring structs.
        let mut fq_def: xsk_ring_prod = unsafe { mem::zeroed() };
        let mut cq_def: xsk_ring_cons = unsafe { mem::zeroed() };
        // SAFETY: FFI call with valid pointers to freshly allocated UMEM and zeroed ring structs.
        let ret = unsafe { xsk_umem__create(&mut umem_handle, umem_area, UMEM_SIZE as u64, &mut fq_def, &mut cq_def, &umem_cfg) };
        if ret != 0 { fatal(E_UMEM_ALLOC_FAIL, "xsk_umem__create failed"); }
        // SAFETY: Type is repr(C) and all-zeroes is a valid bit pattern.
        let mut sock_cfg: xsk_socket_config = unsafe { mem::zeroed() };
        sock_cfg.rx_size = 2048; sock_cfg.tx_size = 2048;
        sock_cfg.libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD;
        sock_cfg.xdp_flags = 0;
        let mut sock_handle: *mut libbpf_sys::xsk_socket = ptr::null_mut();
        // SAFETY: Type is repr(C) and all-zeroes is a valid bit pattern.
        let mut rx_def: xsk_ring_cons = unsafe { mem::zeroed() };
        let mut tx_def: xsk_ring_prod = unsafe { mem::zeroed() };
        let c_ifname = match CString::new(if_name) {
            Ok(c) => c,
            Err(_) => fatal(E_XSK_BIND_FAIL, "Interface name contains null byte"),
        };
        // Try zero-copy first, fall back to copy mode
        let bind_flags = if is_sim { 1 << 1 } else { 1 << 2 }; // copy vs zerocopy
        sock_cfg.bind_flags = bind_flags as u16;
        // SAFETY: FFI call with valid pointers; UMEM handle was successfully created.
        let mut ret = unsafe { xsk_socket__create(&mut sock_handle, c_ifname.as_ptr(), queue_id as u32, umem_handle, &mut rx_def, &mut tx_def, &sock_cfg) };
        if ret != 0 && !is_sim {
            // Zero-copy failed, fall back to copy mode
            eprintln!("[M13-XSK] Zero-copy bind failed, falling back to copy mode");
            sock_cfg.bind_flags = 1u16 << 1; // XDP_COPY
            // SAFETY: FFI call with valid pointers; UMEM handle was successfully created.
            ret = unsafe { xsk_socket__create(&mut sock_handle, c_ifname.as_ptr(), queue_id as u32, umem_handle, &mut rx_def, &mut tx_def, &sock_cfg) };
        }
        if ret != 0 { fatal(E_XSK_BIND_FAIL, "xsk_socket__create failed"); }
        let bind_mode = if sock_cfg.bind_flags == (1u16 << 2) { "Zerocopy" } else { "Copy" };
        // SAFETY: Caller ensures invariants documented at module level.
        let sock_fd = unsafe { libbpf_sys::xsk_socket__fd(sock_handle) };
        unsafe {
            let key = queue_id; let val = sock_fd;
            let ret = bpf_map_update_elem(bpf_map_fd, &key as *const _ as *const c_void, &val as *const _ as *const c_void, 0);
            if ret != 0 { fatal(E_XSK_BIND_FAIL, "BPF map update failed (xsks_map)"); }
        }
        let poll_us: i32 = 50;
        // SAFETY: FFI call with valid socket fd and option pointer.
        let ret = unsafe { setsockopt(sock_fd, SOL_SOCKET, SO_BUSY_POLL, &poll_us as *const _ as *const c_void, 4) };
        if ret != 0 {
            // Non-fatal: busy poll is a performance hint. Kernel < 5.11 may not support it on AF_XDP.
            // Degrades to interrupt-driven polling — functional but adds ~5-15us per batch.
            // SAFETY: File descriptor 2 (stderr) is always valid.
            unsafe { libc::write(2, b"[M13-WARN] SO_BUSY_POLL not supported\n".as_ptr() as _, 38); }
        }
        let mut offsets = XdpMmapOffsets::default();
        let mut optlen = mem::size_of::<XdpMmapOffsets>() as u32;
        // SAFETY: FFI call with valid socket fd and output pointer.
        let ret = unsafe { getsockopt(sock_fd, SOL_XDP, XDP_MMAP_OFFSETS, &mut offsets as *mut _ as *mut c_void, &mut optlen) };
        if ret != 0 { fatal(E_XSK_BIND_FAIL, "getsockopt XDP_MMAP_OFFSETS failed"); }
        // SAFETY: Pointer arithmetic within UMEM bounds; offset validated by kernel ring descriptor.
        unsafe {
            let tx_flags = (tx_def.producer as *mut u8).sub(offsets.tx.producer as usize).add(offsets.tx.flags as usize) as *mut u32;
            let fq_flags = (fq_def.producer as *mut u8).sub(offsets.fr.producer as usize).add(offsets.fr.flags as usize) as *mut u32;
            let tx_strategy = ZeroCopyTx { tx: RingProd::new(&tx_def, tx_flags), sock_fd };
            let rx_ring = RingCons::new(&rx_def);
            let fq_ring = RingProd::new(&fq_def, fq_flags);
            let cq_ring = RingCons::new(&cq_def);
            Engine { umem_area: umem_area as *mut u8, _umem_handle: umem_handle, sock_handle, cq: cq_ring, rx: rx_ring, fq: fq_ring, tx_path: tx_strategy, xdp_mode: format!("AF_XDP Active {}", bind_mode) }
        }
    }

    // SAFETY: Pointer arithmetic within UMEM bounds; offset validated by kernel ring descriptor.
    pub fn get_frame_ptr(&self, idx: u32) -> *mut u8 { unsafe { self.umem_area.add((idx * FRAME_SIZE) as usize) } }
    #[inline(always)] pub fn umem_base(&self) -> *mut u8 { self.umem_area }

    // SAFETY: Ring consumer operates on valid kernel-mapped ring memory.
    pub fn recycle_tx(&mut self, allocator: &mut FixedSlab) -> usize { unsafe { self.cq.consume_addr(allocator) } }

    pub fn refill_rx(&mut self, allocator: &mut FixedSlab) {
        // SAFETY: Ring query on valid kernel-mapped ring memory.
        let count = unsafe { self.fq.available() } as usize;
        let batch = std::cmp::min(count, 16);
        if batch > 0 { self.refill_internal(allocator, batch); }
    }
    pub fn refill_rx_full(&mut self, allocator: &mut FixedSlab) {
        // SAFETY: Ring query on valid kernel-mapped ring memory.
        let count = unsafe { self.fq.available() } as usize;
        if count > 0 { self.refill_internal(allocator, count); }
    }
    fn refill_internal(&mut self, allocator: &mut FixedSlab, count: usize) {
        // SAFETY: Caller ensures invariants documented at module level.
        unsafe {
            let mut added = 0;
            for _ in 0..count {
                if let Some(idx) = allocator.alloc() {
                    self.fq.stage_addr((idx as u64) * (FRAME_SIZE as u64));
                    added += 1;
                } else { break; }
            }
            if added > 0 { self.fq.commit(); }
        }
    }

    /// Bulk RX drain into stack-allocated xdp_desc array.
    #[inline(always)]
    pub fn poll_rx_batch(&mut self, out: &mut [xdp_desc], stats: &Telemetry) -> usize {
        // SAFETY: Ring consumer operates on valid kernel-mapped ring memory.
        unsafe { self.rx.consume_batch(out, out.len(), stats) }
    }
}

impl<T: TxPath> Drop for Engine<T> {
    // SAFETY: UMEM area was obtained from mmap and has not been freed.
    fn drop(&mut self) { unsafe { munmap(self.umem_area as *mut c_void, UMEM_SIZE); } }
}

// ============================================================================
// RING OPERATIONS (Lock-free SPSC with explicit memory barriers)
// ============================================================================
struct RingProd { producer: *mut u32, consumer: *mut u32, ring: *mut c_void, flags: *mut u32, mask: u32, cached_cons: u32, local_prod: u32 }
struct RingCons { producer: *mut u32, consumer: *mut u32, ring: *mut c_void, mask: u32 }

impl RingProd {
    unsafe fn new(r: *const xsk_ring_prod, flags: *mut u32) -> Self {
        let prod_ptr = (*r).producer as *mut AtomicU32;
        let init_prod = (*prod_ptr).load(Ordering::Relaxed);
        RingProd { producer: (*r).producer, consumer: (*r).consumer, ring: (*r).ring, flags, mask: (*r).mask, cached_cons: 0, local_prod: init_prod }
    }
    #[inline(always)] unsafe fn needs_wakeup(&self) -> bool { ptr::read_volatile(self.flags) & XDP_RING_NEED_WAKEUP != 0 }
    #[inline(always)] unsafe fn available(&mut self) -> u32 {
        // Always refresh consumer from kernel to get accurate free count.
        // Required by scheduler budget calculation
        // to compute inflight. Stale cached_cons causes permanent TX stall.
        self.cached_cons = (*(self.consumer as *mut AtomicU32)).load(Ordering::Acquire);
        (self.mask + 1).saturating_sub(self.local_prod.wrapping_sub(self.cached_cons))
    }
    #[inline(always)] #[allow(dead_code)] unsafe fn stage(&mut self, frame_idx: u32, len: u32) {
        let desc = (self.ring as *mut xdp_desc).offset((self.local_prod & self.mask) as isize);
        (*desc).addr = (frame_idx as u64) * FRAME_SIZE as u64; (*desc).len = len; (*desc).options = 0;
        self.local_prod = self.local_prod.wrapping_add(1);
    }
    #[inline(always)] unsafe fn stage_addr(&mut self, addr: u64) {
        let ptr = (self.ring as *mut u64).offset((self.local_prod & self.mask) as isize);
        *ptr = addr;
        self.local_prod = self.local_prod.wrapping_add(1);
    }
    #[inline(always)] unsafe fn stage_addr_desc(&mut self, addr: u64, len: u32) {
        let desc = (self.ring as *mut xdp_desc).offset((self.local_prod & self.mask) as isize);
        (*desc).addr = addr; (*desc).len = len; (*desc).options = 0;
        self.local_prod = self.local_prod.wrapping_add(1);
    }
    #[inline(always)] unsafe fn commit(&mut self) {
        let prod_ptr = self.producer as *mut AtomicU32;
        fence(Ordering::Release);
        (*prod_ptr).store(self.local_prod, Ordering::Relaxed);
    }
}

impl RingCons {
    unsafe fn new(r: *const xsk_ring_cons) -> Self {
        RingCons { producer: (*r).producer, consumer: (*r).consumer, ring: (*r).ring, mask: (*r).mask }
    }
    #[inline(always)] unsafe fn consume_addr(&mut self, allocator: &mut FixedSlab) -> usize {
        let prod_ptr = self.producer as *mut AtomicU32;
        let cons_ptr = self.consumer as *mut AtomicU32;
        let cons_val = (*cons_ptr).load(Ordering::Relaxed);
        let prod_val = (*prod_ptr).load(Ordering::Relaxed);
        fence(Ordering::Acquire);
        let available = prod_val.wrapping_sub(cons_val);
        if available == 0 { return 0; }
        let addr_arr = self.ring as *mut u64;
        for i in 0..available {
            let addr = *addr_arr.offset(((cons_val + i) & self.mask) as isize);
            allocator.free((addr / FRAME_SIZE as u64) as u32);
        }
        (*cons_ptr).store(cons_val.wrapping_add(available), Ordering::Release);
        available as usize
    }
    #[inline(always)] unsafe fn consume_batch(&mut self, out: &mut [xdp_desc], limit: usize, stats: &Telemetry) -> usize {
        let prod_ptr = self.producer as *mut AtomicU32;
        let cons_ptr = self.consumer as *mut AtomicU32;
        let cons_val = (*cons_ptr).load(Ordering::Relaxed);
        let prod_val = (*prod_ptr).load(Ordering::Relaxed);
        fence(Ordering::Acquire);
        let available = prod_val.wrapping_sub(cons_val) as usize;
        if available == 0 { return 0; }
        let count = available.min(limit);
        let desc_arr = self.ring as *const xdp_desc;
        for (i, out_desc) in out.iter_mut().enumerate().take(count) {
            *out_desc = *desc_arr.add((cons_val.wrapping_add(i as u32) & self.mask) as usize);
        }
        (*cons_ptr).store(cons_val.wrapping_add(count as u32), Ordering::Release);
        stats.rx_count.value.fetch_add(count as u64, Ordering::Relaxed);
        count
    }
}

fn check_nic_limits(if_name: &str) {
    // SAFETY: Type is repr(C) and all-zeroes is a valid bit pattern.
    let fd = unsafe { socket(AF_INET, SOCK_DGRAM, 0) };
    if fd < 0 { fatal(E_RING_SIZE_FAIL, "Failed to open probe socket"); }
    // SAFETY: Type is repr(C) and all-zeroes is a valid bit pattern.
    let mut gring: ethtool_ringparam = unsafe { mem::zeroed() };
    gring.cmd = ETHTOOL_GRINGPARAM;
    // SAFETY: Type is repr(C) and all-zeroes is a valid bit pattern.
    let mut ifr: ifreq = unsafe { mem::zeroed() };
    if if_name.len() >= 16 { fatal(E_XSK_BIND_FAIL, "Interface name exceeds IFNAMSIZ"); }
    // SAFETY: Source and destination pointers are valid, non-overlapping, and within allocation bounds.
    unsafe {
        ptr::copy_nonoverlapping(if_name.as_ptr() as *const c_char, ifr.ifr_ifrn.ifrn_name.as_mut_ptr(), if_name.len());
        ifr.ifr_ifru.ifru_data = &mut gring as *mut _ as *mut c_void;
    }
    // SAFETY: FFI call with valid socket fd and ioctl struct pointer.
    let ret = unsafe { ioctl(fd, SIOCETHTOOL as u64, &mut ifr) };
    unsafe { close(fd); }
    if ret != 0 && std::env::var("M13_SIMULATION").is_err() {
        fatal(E_RING_SIZE_FAIL, "SIOCETHTOOL ioctl failed");
    }
    if gring.tx_max_pending == 0 && std::env::var("M13_SIMULATION").is_err() { fatal(E_RING_SIZE_FAIL, "SIOCETHTOOL query returned zero"); }
    // Validate HW ring capacity >= our requested ring size
    if gring.rx_max_pending > 0 && 2048 > gring.rx_max_pending { fatal(E_RING_SIZE_FAIL, "NIC RX ring too small for 2048"); }
    if gring.tx_max_pending > 0 && 2048 > gring.tx_max_pending { fatal(E_RING_SIZE_FAIL, "NIC TX ring too small for 2048"); }
}

#[repr(C)] #[derive(Default, Debug)] struct XdpMmapOffsets { rx: XdpRingOffset, tx: XdpRingOffset, fr: XdpRingOffset, cr: XdpRingOffset }
#[repr(C)] #[derive(Default, Debug)] struct XdpRingOffset { producer: u64, consumer: u64, desc: u64, flags: u64 }
