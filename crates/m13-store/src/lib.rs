#![no_std]
#[cfg(feature = "std")]
extern crate std;

pub mod backend;
#[cfg(feature = "std")]
pub mod fs_backend;

use alloc::vec::Vec;
use alloc::boxed::Box;
// FIX: Removed unused M13Error import
use m13_core::{M13Result};
use m13_aont::{AontTransform, PrivacyMode};
use backend::StorageBackend;
use zeroize::{Zeroize, ZeroizeOnDrop};
use rand_core::{RngCore, CryptoRng};

extern crate alloc;

/// The Volatile Anchor (Spec §8.3.1).
/// This secret exists ONLY in RAM.
#[derive(Zeroize, ZeroizeOnDrop)]
struct VolatileAnchor {
    seed: u32,
}

pub struct BundleStore<R> {
    backend: Box<dyn StorageBackend>,
    anchor: VolatileAnchor,
    rng: R,
}

impl<R: RngCore + CryptoRng> BundleStore<R> {
    /// Initialize the Store.
    /// Generates a NEW Volatile Seed.
    /// WARNING: Any data on disk from previous boots is now logically erased.
    pub fn new(backend: Box<dyn StorageBackend>, mut rng: R) -> Self {
        let seed = rng.next_u32();
        Self {
            backend,
            anchor: VolatileAnchor { seed },
            rng,
        }
    }

    /// Commit a Bundle (Spec §8.2.1).
    /// Applies Passive Zeroization (AONT Mode A) before writing.
    pub fn commit(&mut self, id: u32, payload: &[u8]) -> M13Result<()> {
        // 1. Transform (Passive Zeroization)
        let transformed = AontTransform::transform(
            payload, 
            self.anchor.seed, 
            PrivacyMode::ModeA, 
            &mut self.rng
        )?;

        // 2. Atomic Write
        self.backend.write(id, &transformed)
    }

    /// Retrieve a Bundle.
    pub fn retrieve(&self, id: u32) -> M13Result<Vec<u8>> {
        // 1. Read from Disk
        let transformed = self.backend.read(id)?;

        // 2. Recover
        // If power was lost, 'self.anchor.seed' is new.
        // Recovery will produce algebraic noise.
        let plaintext = AontTransform::recover(
            &transformed, 
            self.anchor.seed, 
            PrivacyMode::ModeA
        )?;

        Ok(plaintext)
    }

    pub fn release(&mut self, id: u32) -> M13Result<()> {
        self.backend.delete(id)
    }
}

/// Forensic Logger (Spec §7.3.2).
/// Wraps the BundleStore to secure logs.
pub struct ForensicLogger<R> {
    store: BundleStore<R>,
    log_counter: u32,
}

impl<R: RngCore + CryptoRng> ForensicLogger<R> {
    pub fn new(store: BundleStore<R>) -> Self {
        Self { store, log_counter: 0 }
    }

    pub fn log(&mut self, msg: &[u8]) -> M13Result<()> {
        // Use High IDs (0xF000_0000+) for logs
        let id = 0xF000_0000 | self.log_counter;
        self.store.commit(id, msg)?;
        self.log_counter += 1;
        Ok(())
    }
}