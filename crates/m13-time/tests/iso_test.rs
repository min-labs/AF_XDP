use m13_time::{JitterBuffer, PhaseMonitor};
use m13_core::{M13Header, PacketType, M13_MAGIC};

fn mock_header() -> M13Header {
    M13Header {
        magic: M13_MAGIC, version: 1, packet_type: PacketType::Data,
        gen_id: 0, symbol_id: 0, payload_len: 0, recoder_rank: 0, reserved: 0,
        auth_tag: [0; 16],
    }
}

#[test]
fn test_jitter_buffer_hold() {
    let depth = 50_000; // 50ms hold
    let mut jb = JitterBuffer::new(depth);
    
    let origin = 1_000_000;
    
    // 1. Push packet (Release target = 1,050,000)
    jb.push(mock_header(), vec![], origin, origin);
    
    // 2. Check Early (Time = 1,040,000) -> Should NOT pop
    assert!(jb.pop(1_040_000).is_none());
    
    // 3. Check On Time (Time = 1,050,000) -> Should pop
    assert!(jb.pop(1_050_000).is_some());
}

#[test]
fn test_late_packet_drop() {
    let depth = 10_000; 
    let mut jb = JitterBuffer::new(depth);
    
    let origin = 1_000_000;
    let now = 1_200_000; // Way past deadline (1,010,000)
    
    // Push packet that is already late
    jb.push(mock_header(), vec![], origin, now);
    
    assert_eq!(jb.drop_late_count, 1);
    assert_eq!(jb.len(), 0);
}

#[test]
fn test_phase_calc() {
    let mut pm = PhaseMonitor::new();
    // Stable RTT ~10ms
    for _ in 0..16 { pm.add_sample(10_000); }
    
    let d = pm.calculate_depth();
    // Mean 10000 + 0 Var + 50 Proc = 10050
    assert!(d >= 10_050 && d < 10_100);
    
    // Jittery RTT (10ms, 20ms alternating)
    let mut pm2 = PhaseMonitor::new();
    for i in 0..16 { 
        if i % 2 == 0 { pm2.add_sample(10_000); } else { pm2.add_sample(20_000); }
    }
    // Mean 15000. Variance 25,000,000. StdDev 5000. 
    // Target = 15000 + (4*5000) + 50 = 35050
    let d2 = pm2.calculate_depth();
    assert!(d2 > 35_000);
}