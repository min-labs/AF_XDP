#![no_std]
#[cfg(feature = "std")]
extern crate std;

pub const M13_MAGIC: u32 = 0x4D313300;

// [FIX] Primary Constants (Sprint 27 Standard)
pub const KYBER_PUBLIC_KEY_SIZE: usize = 1568; 
pub const KYBER_CIPHERTEXT_SIZE: usize = 1568; 
pub const DILITHIUM_SIGNATURE_SIZE: usize = 4627;

// [FIX] Aliases for Backward Compatibility (Sprint 24)
// These are required by m13-ulk and m13-pqc!
pub const KYBER_PK_LEN_1024: usize = KYBER_PUBLIC_KEY_SIZE;
pub const KYBER_CT_LEN_1024: usize = KYBER_CIPHERTEXT_SIZE;
pub const DILITHIUM_SIG_LEN_87: usize = DILITHIUM_SIGNATURE_SIZE;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PacketType {
    Data = 0x01,
    Ack = 0x02,
    Handshake = 0xF0,
    KeepAlive = 0xFF,
    Coded = 0x10,
    ClientHello = 0x11, 
    HandshakeInit = 0x12,
    HandshakeAuth = 0x13,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C, packed)]
pub struct M13Header {
    pub magic: u32,       
    pub version: u8,      
    pub packet_type: PacketType, 
    pub gen_id: u16,      
    pub symbol_id: u32,   
    pub payload_len: u16, 
    pub recoder_rank: u8, 
    pub reserved: u8,     
    pub auth_tag: [u8; 16], 
}

impl M13Header {
    pub const SIZE: usize = 32;

    pub fn to_bytes(&self, buf: &mut [u8]) -> Result<(), ()> {
        if buf.len() < Self::SIZE { return Err(()); }
        buf[0..4].copy_from_slice(&self.magic.to_be_bytes());
        buf[4] = self.version;
        buf[5] = self.packet_type as u8;
        buf[6..8].copy_from_slice(&self.gen_id.to_be_bytes());
        buf[8..12].copy_from_slice(&self.symbol_id.to_be_bytes());
        buf[12..14].copy_from_slice(&self.payload_len.to_be_bytes());
        buf[14] = self.recoder_rank;
        buf[15] = self.reserved;
        buf[16..32].copy_from_slice(&self.auth_tag);
        Ok(())
    }

    pub fn from_bytes(buf: &[u8]) -> Result<Self, ()> {
        if buf.len() < Self::SIZE { return Err(()); }
        let magic = u32::from_be_bytes(buf[0..4].try_into().unwrap());
        if magic != M13_MAGIC { return Err(()); }
        
        let packet_type = match buf[5] {
            0x01 => PacketType::Data,
            0x02 => PacketType::Ack,
            0xF0 => PacketType::Handshake,
            0xFF => PacketType::KeepAlive,
            0x10 => PacketType::Coded,
            0x11 => PacketType::ClientHello,
            0x12 => PacketType::HandshakeInit,
            0x13 => PacketType::HandshakeAuth,
            _ => return Err(()),
        };

        Ok(Self {
            magic,
            version: buf[4],
            packet_type,
            gen_id: u16::from_be_bytes(buf[6..8].try_into().unwrap()),
            symbol_id: u32::from_be_bytes(buf[8..12].try_into().unwrap()),
            payload_len: u16::from_be_bytes(buf[12..14].try_into().unwrap()),
            recoder_rank: buf[14],
            reserved: buf[15],
            auth_tag: buf[16..32].try_into().unwrap(),
        })
    }
}

pub type M13Result<T> = Result<T, M13Error>;

#[derive(Debug)]
pub enum M13Error {
    Generic,
    InvalidState,
    CryptoFailure,
    AuthFail,
    WireFormatError,
    RngFailure,
    HalError, 
    EntropyExhaustion,
}

impl core::fmt::Display for M13Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for M13Error {}
