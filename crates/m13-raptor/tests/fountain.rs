use m13_raptor::{FountainEncoder, FountainDecoder};

#[test]
fn test_fountain_recovery() {
    let data = b"Hello M13 World! This is a test of the Emergency Broadcast System.";
    let symbol_size = 4;
    let gen_id = 1;

    let mut enc = FountainEncoder::new(data, symbol_size, gen_id).unwrap();
    // K = ceil(66 / 4) = 17 packets needed.

    // Allow Decoder to buffer K+5 packets
    let mut dec = FountainDecoder::new(17, symbol_size, gen_id);

    // Simulate Loss: Drop Systematic Packets 0, 2, 5
    // We will supply 3 Repair packets to compensate.
    
    // 1. Send all Systematic except dropped
    // We iterate up to K (0..17)
    for i in 0..17 {
        let (header, payload) = enc.next_packet(); // this advances internal cursor
        
        // Simulating Loss: If index is 0, 2, or 5, we DROP it (don't absorb).
        if i == 0 || i == 2 || i == 5 { continue; }
        
        dec.absorb(&header, &payload).unwrap();
    }
    
    // 2. Send 5 Repair Packets (plus extras to test robustness)
    for _ in 0..5 {
        let (header, payload) = enc.next_packet();
        dec.absorb(&header, &payload).unwrap();
    }
    
    // 3. Decode
    let recovered = dec.decode().expect("Decoder failed (Singular Matrix?)");
    
    // Trim padding and verify
    assert_eq!(&recovered[0..data.len()], data);
}