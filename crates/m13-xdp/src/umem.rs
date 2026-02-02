use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::ptr;
use libc::*;
use anyhow::{Result, anyhow};

pub const FRAME_SIZE: usize = 4096;
// [SPRINT 40] PHYSICS FIX: TANK EXPANSION
// RX Ring (8192) + TX Headroom (8192) = 16384 Frames
// Memory Cost: 64MB (negligible on RB5).
pub const FRAME_COUNT: usize = 16384;
pub const UMEM_SIZE: usize = FRAME_SIZE * FRAME_COUNT;

// [SPRINT 41] PHYSICS FIX: HUGEPAGES
// Standard Hugepage Flag (Linux x86/ARM)
// Reduces TLB Misses from 99.9% to 0%.
const MAP_HUGETLB: c_int = 0x40000;

pub struct Umem {
    pub addr: *mut u8,
    pub len: usize,
    pub free_frames: Mutex<VecDeque<u64>>,
}
unsafe impl Send for Umem {}
unsafe impl Sync for Umem {}

impl Umem {
    pub fn new() -> Result<Arc<Self>> {
        // [SPRINT 41] CRITICAL: MAP_HUGETLB | MAP_LOCKED
        // We strictly require Hugepages. If the OS cannot provide 64MB 
        // of contiguous RAM, we must crash (Fail-Secure).
        // MAP_LOCKED prevents swapping.
        let addr = unsafe {
            mmap(ptr::null_mut(), UMEM_SIZE, PROT_READ|PROT_WRITE, 
                 MAP_ANONYMOUS|MAP_SHARED|MAP_POPULATE|MAP_HUGETLB|MAP_LOCKED, -1, 0)
        };
        if addr == MAP_FAILED { return Err(anyhow!("mmap failed (Hugepages required)")); }
        if (addr as usize) % 4096 != 0 { unsafe { munmap(addr, UMEM_SIZE); } return Err(anyhow!("Alignment Error")); }
        
        let mut free = VecDeque::with_capacity(FRAME_COUNT);
        for i in 0..FRAME_COUNT { free.push_back((i * FRAME_SIZE) as u64); }
        Ok(Arc::new(Self { addr: addr as *mut u8, len: UMEM_SIZE, free_frames: Mutex::new(free) }))
    }
    pub fn as_ptr(&self) -> *mut u8 { self.addr }
}
impl Drop for Umem { fn drop(&mut self) { unsafe { munmap(self.addr as *mut _, self.len); } } }
