use m13_attest::{merkle, PcrBank}; // verify_epoch0 omitted as it requires complex P256 mocking
use sha2::{Sha384, Digest};

#[test]
fn test_merkle_suite_b() {
    let leaf = merkle::merkle_leaf(b"FirmwareV1");
    // Manual Root: H(0x01 || leaf || leaf)
    let mut h = Sha384::new();
    h.update(&[0x01]); h.update(&leaf); h.update(&leaf);
    let root: [u8; 48] = h.finalize().into();

    let proof = vec![leaf];
    assert!(merkle::verify_inclusion_proof(&root, &leaf, 0, &proof).is_ok());
}

#[test]
fn test_pcr_hashing() {
    let bank = PcrBank {
        pcr0_root: [0xAA; 32],
        pcr1_fw: [0xBB; 32],
        pcr2_kernel: [0xCC; 32],
        pcr4_policy: [0xDD; 32],
        pcr7_debug: [0xEE; 32],
    };
    let _digest = bank.digest();
    // Simply ensure it compiles and runs without panic
}