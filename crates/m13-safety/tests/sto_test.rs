use m13_safety::{SafetyMonitor};
use m13_hal::{PlatformClock, SecurityModule};
use m13_core::M13Result;
// FIX: Use AtomicU64 instead of Cell for thread safety (Sync)
use std::sync::atomic::{AtomicU64, Ordering};

// Mocks
struct MockClock {
    time_us: AtomicU64 
}

impl MockClock {
    fn advance(&self, us: u64) {
        // FIX: Atomic Fetch-Add is cleaner than load+store
        self.time_us.fetch_add(us, Ordering::SeqCst);
    }
}

impl PlatformClock for MockClock {
    fn now_us(&self) -> u64 {
        // FIX: Atomic Load
        self.time_us.load(Ordering::SeqCst)
    }
    
    fn ptp_ns(&self) -> Option<u64> { None }
}

struct MockHal;
impl SecurityModule for MockHal {
    fn get_random_bytes(&mut self, _: &mut [u8]) -> M13Result<()> { Ok(()) }
    fn sign_digest(&mut self, _: &[u8], _: &mut [u8]) -> M13Result<usize> { Ok(0) }
    
    // Simulate the kill switch
    fn panic_and_sanitize(&self) -> ! {
        panic!("STO_TRIGGERED"); 
    }
}

#[test]
fn test_heartbeat_square_wave() {
    let clock = MockClock { time_us: AtomicU64::new(1_000_000) }; // Start at 1s
    let mut hal = MockHal;
    let mut monitor = SafetyMonitor::new(&clock);

    // t=0ms (relative): High (0/5000 % 2 == 0)
    let s1 = monitor.tick(40.0, &mut hal, &clock).unwrap();
    assert_eq!(s1, true);

    // t=6ms (relative): Low (crossed 5ms boundary)
    clock.advance(6_000);
    let s2 = monitor.tick(40.0, &mut hal, &clock).unwrap();
    assert_eq!(s2, false);
    
    // t=11ms (relative): High (crossed 10ms boundary)
    clock.advance(5_000);
    let s3 = monitor.tick(40.0, &mut hal, &clock).unwrap();
    assert_eq!(s3, true);
}

#[test]
#[should_panic(expected = "STO_TRIGGERED")]
fn test_watchdog_timeout() {
    let clock = MockClock { time_us: AtomicU64::new(1_000_000) };
    let mut hal = MockHal;
    let mut monitor = SafetyMonitor::new(&clock);

    // Healthy tick
    monitor.tick(40.0, &mut hal, &clock).unwrap();
    
    // Freeze for 30ms (Limit is 20ms)
    clock.advance(30_000); 
    
    // Should panic
    let _ = monitor.tick(40.0, &mut hal, &clock);
}

#[test]
#[should_panic(expected = "STO_TRIGGERED")]
fn test_jitter_instability() {
    let clock = MockClock { time_us: AtomicU64::new(1_000_000) };
    let mut hal = MockHal;
    let mut monitor = SafetyMonitor::new(&clock);

    // Feed terrible RTT samples (>1s variance)
    // This will cause calculated buffer depth to explode > 100ms
    for _ in 0..16 {
        monitor.record_rtt(1_000_000); 
        monitor.record_rtt(10_000);
    }

    // 3 Strikes to trip
    let _ = monitor.tick(40.0, &mut hal, &clock);
    let _ = monitor.tick(40.0, &mut hal, &clock);
    let _ = monitor.tick(40.0, &mut hal, &clock); // BOOM
}