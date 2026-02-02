#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;
use alloc::boxed::Box;
use alloc::vec::Vec;
use alloc::sync::Arc;
use spin::Mutex;
use zeroize::Zeroize;
use core::ops::{Deref, DerefMut};

// [PHYSICS] 10KB Frame covers Jumbo Frames + Headers
pub const FRAME_SIZE: usize = 10240;

// [PHYSICS] Force 64-byte alignment to match CPU Cache Lines.
// Prevents "Split Loads" where a header read spans two memory fetches.
#[repr(C, align(64))]
#[derive(Zeroize)]
pub struct Frame {
    pub data: [u8; FRAME_SIZE],
    pub len: usize,
}

impl Default for Frame {
    fn default() -> Self {
        Self {
            data: [0u8; FRAME_SIZE],
            len: 0,
        }
    }
}

pub struct SlabAllocator {
    pool: Mutex<Vec<Box<Frame>>>,
}

pub struct FrameLease {
    frame: Option<Box<Frame>>,
    allocator: Arc<SlabAllocator>,
}

impl SlabAllocator {
    pub fn new(capacity: usize) -> Arc<Self> {
        let mut pool = Vec::with_capacity(capacity);
        for _ in 0..capacity {
            let mut frame = Box::new(Frame::default());
            
            // [PHYSICS] Pre-Faulting (Safe Mode)
            // We read-modify-write the start and end of the frame to force 
            // the OS MMU to assign physical RAM pages immediately (Dirty Bit).
            // We use core::hint::black_box to prevent the compiler from 
            // optimizing this away as "Dead Store", achieving the Physics 
            // result without violating the Safety contract.
            
            let start_idx = 0;
            let end_idx = FRAME_SIZE - 1;

            // Force Load -> Obfuscate -> Store
            frame.data[start_idx] = core::hint::black_box(frame.data[start_idx]);
            frame.data[end_idx] = core::hint::black_box(frame.data[end_idx]);

            pool.push(frame);
        }
        Arc::new(Self { pool: Mutex::new(pool) })
    }

    pub fn alloc(self: &Arc<Self>) -> Option<FrameLease> {
        let mut pool = self.pool.lock();
        if let Some(mut frame) = pool.pop() {
            frame.len = 0;
            Some(FrameLease { frame: Some(frame), allocator: self.clone() })
        } else {
            None
        }
    }

    fn release(&self, frame: Box<Frame>) {
        let mut pool = self.pool.lock();
        pool.push(frame);
    }
    
    pub fn available(&self) -> usize {
        self.pool.lock().len()
    }
}

impl Deref for FrameLease {
    type Target = Frame;
    fn deref(&self) -> &Self::Target { self.frame.as_ref().unwrap() }
}

impl DerefMut for FrameLease {
    fn deref_mut(&mut self) -> &mut Self::Target { self.frame.as_mut().unwrap() }
}

impl Drop for FrameLease {
    fn drop(&mut self) {
        if let Some(mut frame) = self.frame.take() {
            frame.zeroize();
            self.allocator.release(frame);
        }
    }
}
