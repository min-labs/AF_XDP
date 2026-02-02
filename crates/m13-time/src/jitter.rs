#![forbid(unsafe_code)]

extern crate alloc;
use alloc::collections::BinaryHeap;
use alloc::vec::Vec;
use core::cmp::Ordering;
use m13_core::{M13Header};

/// Wrapper to order packets by Release Time (Min-Heap behavior).
struct OrderedPacket {
    header: M13Header,
    payload: Vec<u8>,
    release_time_us: u64,
}

impl PartialEq for OrderedPacket {
    fn eq(&self, other: &Self) -> bool {
        self.release_time_us == other.release_time_us
    }
}
impl Eq for OrderedPacket {}

// Rust BinaryHeap is Max-Heap. We reverse order to get Min-Heap.
// Logic: If Self < Other (Time), we return Greater, so Self floats to top.
impl PartialOrd for OrderedPacket {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(other.release_time_us.cmp(&self.release_time_us))
    }
}
impl Ord for OrderedPacket {
    fn cmp(&self, other: &Self) -> Ordering {
        other.release_time_us.cmp(&self.release_time_us)
    }
}

pub struct JitterBuffer {
    /// Fixed Playout Delay (Target Latency).
    /// Calculated as Avg_RTT + 4 * StdDev_RTT.
    buffer_depth_us: u64,
    
    /// The Priority Queue (Earliest Deadline First).
    queue: BinaryHeap<OrderedPacket>,
    
    /// Stats
    pub drop_late_count: u64,
}

impl JitterBuffer {
    pub fn new(buffer_depth_us: u64) -> Self {
        Self {
            buffer_depth_us,
            queue: BinaryHeap::new(),
            drop_late_count: 0,
        }
    }

    /// Push a packet into the buffer.
    /// 
    /// # Arguments
    /// * `origin_time_us` - The PTP timestamp when packet was created (Sender).
    /// * `now_us` - Current local time (Receiver).
    pub fn push(
        &mut self, 
        header: M13Header, 
        payload: Vec<u8>, 
        origin_time_us: u64,
        now_us: u64
    ) {
        let release_time = origin_time_us + self.buffer_depth_us;
        
        // Late Packet Check (Spec §7.2.1)
        // If it's already past the release time, it's poison for the Control Loop.
        if release_time < now_us {
            self.drop_late_count += 1;
            return; 
        }

        self.queue.push(OrderedPacket {
            header,
            payload,
            release_time_us: release_time,
        });
    }

    /// Attempt to pop a packet if its release time has arrived.
    /// Returns None if queue is empty or head is not yet ready.
    pub fn pop(&mut self, now_us: u64) -> Option<(M13Header, Vec<u8>)> {
        // Peek at the earliest packet
        if let Some(pkt) = self.queue.peek() {
            if pkt.release_time_us <= now_us {
                // Time to release!
                let pkt = self.queue.pop().unwrap();
                return Some((pkt.header, pkt.payload));
            }
        }
        None
    }

    pub fn len(&self) -> usize {
        self.queue.len()
    }
}