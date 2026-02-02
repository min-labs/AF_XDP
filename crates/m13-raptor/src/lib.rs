#![no_std]
extern crate alloc;

pub mod encoder;
pub mod decoder;

// Export Logic
pub use encoder::FountainEncoder;
pub use decoder::FountainDecoder;

#[derive(Debug)]
pub enum RaptorError {
    Encoding,
    Decoding,
}

pub type Result<T, E = RaptorError> = core::result::Result<T, E>;