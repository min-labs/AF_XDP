use m13_rlnc::{Recoder, RlncDecoder};
use rand_core::OsRng;

#[test]
fn test_rank_check_filter() {
    let k = 2;
    let mut recoder = Recoder::new(1, k).unwrap();

    // Packet A: [1, 0 | AA]
    let p_a = vec![1, 0, 0xAA];
    assert!(recoder.absorb(&p_a).unwrap());
    assert_eq!(recoder.current_rank(), 1);

    // Packet B: [1, 0 | AA] (Duplicate)
    // Should be rejected as linearly dependent
    assert_eq!(recoder.absorb(&p_a).unwrap(), false);
    assert_eq!(recoder.current_rank(), 1);

    // Packet C: [0, 1 | BB] (Innovative)
    let p_c = vec![0, 1, 0xBB];
    assert!(recoder.absorb(&p_c).unwrap());
    assert_eq!(recoder.current_rank(), 2);
}

#[test]
fn test_mesh_mixing_recovery() {
    let k = 3;
    let size = 4;
    let mut rng = OsRng;

    // Source Data
    let p1 = vec![1, 0, 0, 10, 10, 10, 10];
    let p2 = vec![0, 1, 0, 20, 20, 20, 20];
    let p3 = vec![0, 0, 1, 30, 30, 30, 30];

    // Relay
    let mut relay = Recoder::new(1, k).unwrap();
    relay.absorb(&p1).unwrap();
    relay.absorb(&p2).unwrap();
    relay.absorb(&p3).unwrap();

    // Receiver
    let mut rx = RlncDecoder::new(1, k, size);
    
    // Mix
    let mut count = 0;
    while !rx.is_complete() && count < 100 {
        let pkt = relay.recode(&mut rng).unwrap();
        rx.absorb(&pkt).unwrap();
        count += 1;
    }
    assert!(rx.is_complete());
    
    // Verify
    let data = rx.decode().unwrap();
    assert_eq!(data[0], vec![10,10,10,10]);
}