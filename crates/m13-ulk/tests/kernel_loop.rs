use m13_ulk::{M13Kernel};
use m13_hal::{PhysicalInterface, SecurityModule, PlatformClock, LinkProperties};
use m13_mem::SlabAllocator;
use m13_core::{M13Error};
use std::boxed::Box;
// FIX: Use AtomicU64 for Thread-Safe Mocking
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

// --- MOCKS ---
struct MockPhy;
impl PhysicalInterface for MockPhy {
    fn properties(&self) -> LinkProperties { LinkProperties { mtu: 1500, bandwidth_bps: 0, is_reliable: false } }
    fn send(&mut self, _: &[u8]) -> nb::Result<usize, M13Error> { Ok(0) }
    fn recv<'a>(&mut self, _: &'a mut [u8]) -> nb::Result<usize, M13Error> { Err(nb::Error::WouldBlock) }
}
struct MockSec;
impl SecurityModule for MockSec {
    fn get_random_bytes(&mut self, _: &mut [u8]) -> m13_core::M13Result<()> { Ok(()) }
    fn sign_digest(&mut self, _: &[u8], _: &mut [u8]) -> m13_core::M13Result<usize> { Ok(0) }
    fn panic_and_sanitize(&self) -> ! { panic!("PANIC") }
}

// Thread-safe Mock Clock
struct MockClock { t: Arc<AtomicU64> }
impl MockClock {
    fn new(start: u64) -> Self { Self { t: Arc::new(AtomicU64::new(start)) } }
}
impl PlatformClock for MockClock {
    fn now_us(&self) -> u64 { self.t.load(Ordering::SeqCst) }
    fn ptp_ns(&self) -> Option<u64> { None }
}

#[test]
fn test_kernel_cycle() {
    let slab = SlabAllocator::new(10);
    let clock = Box::new(MockClock::new(1000));
    
    let mut kernel = M13Kernel::new(
        Box::new(MockPhy),
        Box::new(MockSec),
        clock,
        slab
    );
    
    // Run one cycle. Expect false (Idle) because Phy returns WouldBlock.
    let work_done = kernel.poll();
    assert_eq!(work_done, false);
}