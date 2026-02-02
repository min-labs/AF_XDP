use m13_cipher::M13Cipher; // [FIX] Removed unused SessionKey
use m13_pqc::KyberKeypair;
use crate::fragment::FragmentAssembler;

pub struct Session {
    pub cipher: Option<M13Cipher>,
    pub ephemeral_key: Option<KyberKeypair>,
    pub tx_sequence: u32,
    pub last_valid_rx_us: u64,
    pub assigned_vip: Option<u32>,
    pub assembler: FragmentAssembler,
}

impl Session {
    pub fn new(now: u64) -> Self {
        Self {
            cipher: None,
            ephemeral_key: None,
            tx_sequence: 1,
            last_valid_rx_us: now,
            assigned_vip: None,
            assembler: FragmentAssembler::new(),
        }
    }
}