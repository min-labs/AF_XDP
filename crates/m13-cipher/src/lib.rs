#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;
use alloc::vec::Vec;
use m13_core::{M13Error, M13Result, M13Header};
use chacha20poly1305::{
    aead::{AeadInPlace, KeyInit},
    ChaCha20Poly1305, Key, Nonce, Tag
};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SessionKey(pub [u8; 32]);

pub struct M13Cipher {
    cipher: ChaCha20Poly1305,
}

impl M13Cipher {
    pub fn new(key: &SessionKey) -> Self {
        let key_generic = Key::from_slice(&key.0);
        Self { cipher: ChaCha20Poly1305::new(key_generic) }
    }

    // [FIX] Sprint 27 Nonce Construction
    fn construct_nonce(header: &M13Header) -> Nonce {
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[0..2].copy_from_slice(&header.gen_id.to_be_bytes());
        nonce_bytes[2..6].copy_from_slice(&header.symbol_id.to_be_bytes());
        // Padding zeros for remaining 6 bytes
        *Nonce::from_slice(&nonce_bytes)
    }

    pub fn encrypt_detached(&self, header: &M13Header, payload: &mut [u8]) -> M13Result<[u8; 16]> {
        let nonce = Self::construct_nonce(header);
        let mut aad = [0u8; M13Header::SIZE];
        header.to_bytes(&mut aad).map_err(|_| M13Error::WireFormatError)?;
        aad[16..32].fill(0); 

        let tag = self.cipher.encrypt_in_place_detached(&nonce, &aad, payload)
            .map_err(|_| M13Error::CryptoFailure)?;
            
        let mut tag_bytes = [0u8; 16];
        tag_bytes.copy_from_slice(tag.as_slice());
        Ok(tag_bytes)
    }

    pub fn decrypt_detached(&self, header: &M13Header, payload: &mut [u8]) -> M13Result<()> {
        let nonce = Self::construct_nonce(header);
        let mut aad = [0u8; M13Header::SIZE];
        header.to_bytes(&mut aad).map_err(|_| M13Error::WireFormatError)?;
        aad[16..32].fill(0); 

        let tag = Tag::from_slice(&header.auth_tag);
        self.cipher.decrypt_in_place_detached(&nonce, &aad, payload, tag)
            .map_err(|_| M13Error::AuthFail)
    }
}

pub fn generate_coefficients(seed: u32, gen_id: u16, count: usize) -> Vec<u8> {
    let mut key_bytes = [0u8; 32];
    key_bytes[0..4].copy_from_slice(&seed.to_be_bytes());
    let session_key = SessionKey(key_bytes);
    
    let cipher = M13Cipher::new(&session_key);
    let dummy_header = M13Header {
        magic: m13_core::M13_MAGIC,
        version: 1,
        // [FIX] Changed 'Control' (removed) to 'Data' (valid).
        // This header is only used to churn the RNG state, so type is irrelevant.
        packet_type: m13_core::PacketType::Data, 
        gen_id,
        symbol_id: seed,
        payload_len: 0,
        recoder_rank: 0,
        reserved: 0,
        auth_tag: [0u8; 16],
    };
    
    let mut buffer = alloc::vec![0u8; count];
    cipher.encrypt_detached(&dummy_header, &mut buffer).ok();
    buffer
}
