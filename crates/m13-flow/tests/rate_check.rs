use m13_flow::{RateEstimator, Pacer};

#[test]
fn test_bbr_logic() {
    let mut bbr = RateEstimator::new();
    
    // 1. Send ACK: 2Mbps
    bbr.on_ack(2_000_000, 50_000, 1_000_000);
    
    // 2. Check Pacing Rate
    // Startup gain ~2.89 -> Expect ~5.78 Mbps
    let rate = bbr.get_pacing_rate_bps(1_000_000);
    assert!(rate > 5_000_000, "Rate {} too low for Startup", rate);
}

#[test]
fn test_chaff_logic() {
    // Floor: 100kbps (12,500 B/s)
    let mut pacer = Pacer::new(100_000);
    
    // FIX: Prime the clock at T=100,000us (0.1s)
    pacer.tick(100_000);
    
    // Advance 1 second (T=1,100,000 us)
    pacer.tick(1_100_000); 
    
    // Should request chaff because tokens > MTU (Idle)
    assert!(pacer.chaff_needed(1000), "Chaff should be requested when bucket is full");
    
    // Consume tokens (Send Real Packet)
    // FIX: Consume 50,000 bytes. 
    // The BBR Startup default (1Mbps * 2.89) creates a burst allowance of ~36KB.
    // Consuming 12.5KB left the bucket positive. We need >36KB to force debt.
    pacer.consume(50_000);
    
    // Should NOT request chaff (Debt)
    assert!(!pacer.chaff_needed(1000), "Chaff should be suppressed when tokens consumed");
}