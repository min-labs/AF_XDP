use m13_pqc::{KemKeypair, encapsulate, decapsulate, DsaKeypair, verify};
use rand_core::OsRng;

#[test]
fn test_kem_exchange() {
    let mut rng = OsRng;
    let alice = KemKeypair::generate(&mut rng).unwrap();
    
    // Pass public key as slice (encapsulate handles conversion)
    let (ct, ss_bob) = encapsulate(&alice.public, &mut rng).unwrap();
    
    let ss_alice = decapsulate(&alice, &ct).unwrap();
    assert_eq!(ss_bob, ss_alice);
}

#[test]
fn test_dsa_signing() {
    let mut rng = OsRng;
    let auth = DsaKeypair::generate(&mut rng).unwrap();
    let msg = b"Launch";
    
    let sig = auth.sign(msg, &mut rng).unwrap();
    
    verify(&auth.public, msg, &sig).unwrap();
}

#[test]
fn test_header_serialization() {
    use m13_core::{M13Header, PacketType, M13_MAGIC};
    
    let header = M13Header {
        magic: M13_MAGIC,
        version: 1,
        packet_type: PacketType::Data,
        gen_id: 0x1234,
        symbol_id: 0xDEADBEEF,
        payload_len: 1024,
        recoder_rank: 5,
        reserved: 0,
        auth_tag: [0xAA; 16],
    };
    
    let mut buf = [0u8; 32];
    header.to_bytes(&mut buf).unwrap();
    
    let recovered = M13Header::from_bytes(&buf).unwrap();
    assert_eq!(header, recovered);
}