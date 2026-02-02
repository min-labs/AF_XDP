use m13_core::{M13Header, PacketType, M13_MAGIC};
use m13_cipher::{M13Cipher, SessionKey};

#[test]
fn test_round_trip() {
    let key = SessionKey([0x42; 32]);
    let cipher = M13Cipher::new(&key);

    let mut payload = b"Attack at Dawn".to_vec();
    
    // Create Header (Tag is zero initially)
    let mut header = M13Header {
        magic: M13_MAGIC,
        version: 1,
        packet_type: PacketType::Data,
        gen_id: 1,
        symbol_id: 100,
        payload_len: payload.len() as u16,
        recoder_rank: 0,
        reserved: 0,
        auth_tag: [0u8; 16],
    };

    // Encrypt
    let tag = cipher.encrypt_detached(&header, &mut payload).unwrap();
    assert_ne!(payload, b"Attack at Dawn"); // Ciphertext check

    // Simulate Transmission (Receiver gets header with Tag)
    header.auth_tag = tag;

    // Decrypt
    cipher.decrypt_detached(&header, &mut payload).unwrap();
    assert_eq!(payload, b"Attack at Dawn");
}

#[test]
fn test_aad_tamper() {
    let key = SessionKey([0x42; 32]);
    let cipher = M13Cipher::new(&key);
    let mut payload = b"Secret".to_vec();
    
    let mut header = M13Header {
        magic: M13_MAGIC, version: 1, packet_type: PacketType::Data,
        gen_id: 1, symbol_id: 100, payload_len: 6, recoder_rank: 0, reserved: 0,
        auth_tag: [0u8; 16]
    };

    header.auth_tag = cipher.encrypt_detached(&header, &mut payload).unwrap();

    // Tamper with metadata (Change Symbol ID to replay)
    header.symbol_id = 101; 

    // Decrypt should fail (Poly1305 Auth Fail because AAD changed)
    let res = cipher.decrypt_detached(&header, &mut payload);
    assert!(res.is_err());
}