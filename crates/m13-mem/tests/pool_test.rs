use m13_mem::SlabAllocator;

#[test]
fn test_alloc_reuse() {
    let slab = SlabAllocator::new(1); // Capacity 1
    
    // 1. Alloc
    {
        let mut lease = slab.alloc().unwrap();
        lease.len = 100;
        lease.data[0] = 0xFF;
        
        assert_eq!(slab.available(), 0);
    } // Drops here, returns to pool
    
    // 2. Alloc Again
    assert_eq!(slab.available(), 1);
    let lease2 = slab.alloc().unwrap();
    
    // 3. Verify Hygiene (Zeroized)
    assert_eq!(lease2.len, 0);
    assert_eq!(lease2.data[0], 0x00, "Data Remanence Detected!");
}

#[test]
fn test_exhaustion() {
    let slab = SlabAllocator::new(2);
    let _l1 = slab.alloc().unwrap();
    let _l2 = slab.alloc().unwrap();
    
    // Pool empty
    assert!(slab.alloc().is_none());
}