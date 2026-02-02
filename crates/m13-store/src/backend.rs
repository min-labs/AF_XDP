#![forbid(unsafe_code)]
extern crate alloc;
use alloc::vec::Vec;
use m13_core::M13Result;

/// Abstract interface for Non-Volatile Memory (NVM).
/// Implemented by the Node Runtime (Sprint 17).
pub trait StorageBackend: Send + Sync {
    /// Atomically write data to a specific ID/Address.
    /// MUST ensure data is flushed to physical media (fsync) before returning.
    fn write(&mut self, id: u32, data: &[u8]) -> M13Result<()>;

    /// Read data back.
    fn read(&self, id: u32) -> M13Result<Vec<u8>>;

    /// Delete/Trim data.
    fn delete(&mut self, id: u32) -> M13Result<()>;
    
    /// Verify if ID exists.
    fn exists(&self, id: u32) -> bool;
}