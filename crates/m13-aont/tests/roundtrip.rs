use m13_aont::{AontTransform, PrivacyMode};
use rand_core::OsRng;

#[test]
fn test_mode_b_perfect_secrecy() {
    let payload = b"NuclearCode";
    let seed = 0xCAFEBABE;
    let mut rng = OsRng;

    // 1. Transform
    let enc = AontTransform::transform(
        payload, 
        seed, 
        PrivacyMode::ModeB, 
        &mut rng
    ).unwrap();

    // Verify Expansion
    assert_eq!(enc.len(), payload.len() * 2);

    // 2. Recover
    let dec = AontTransform::recover(
        &enc, 
        seed, 
        PrivacyMode::ModeB
    ).unwrap();

    assert_eq!(payload, dec.as_slice());
}

#[test]
fn test_mode_a_bulk() {
    let payload = b"LargePayloadForVideo";
    let seed = 0x12345678;
    let mut rng = OsRng;

    let enc = AontTransform::transform(
        payload, 
        seed, 
        PrivacyMode::ModeA, 
        &mut rng
    ).unwrap();

    let dec = AontTransform::recover(
        &enc, 
        seed, 
        PrivacyMode::ModeA
    ).unwrap();

    assert_eq!(payload, dec.as_slice());
}