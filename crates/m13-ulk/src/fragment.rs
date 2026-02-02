extern crate alloc; // [FIX] Removed #![no_std]
use alloc::vec::Vec;
use m13_core::{M13Result, M13Error};

pub struct FragmentAssembler {
    buffer: Vec<u8>,
    expected_len: usize,
}

impl FragmentAssembler {
    pub fn new() -> Self {
        Self { buffer: Vec::new(), expected_len: 0 }
    }

    pub fn ingest(&mut self, payload: &[u8]) -> M13Result<Option<Vec<u8>>> {
        if payload.len() < 4 { return Err(M13Error::WireFormatError); }
        
        let total_len = u16::from_be_bytes(payload[0..2].try_into().unwrap()) as usize;
        let offset = u16::from_be_bytes(payload[2..4].try_into().unwrap()) as usize;
        let data = &payload[4..];

        if self.buffer.is_empty() {
            self.expected_len = total_len;
            if total_len > 10240 { return Err(M13Error::WireFormatError); }
            self.buffer.resize(total_len, 0);
        }

        if total_len != self.expected_len { 
            self.buffer.clear();
            return Err(M13Error::InvalidState); 
        }
        if offset + data.len() > self.expected_len { return Err(M13Error::WireFormatError); }

        self.buffer[offset..offset+data.len()].copy_from_slice(data);

        if offset + data.len() == self.expected_len {
             let res = self.buffer.clone();
             self.buffer.clear();
             self.expected_len = 0;
             return Ok(Some(res));
        }

        Ok(None)
    }
}
