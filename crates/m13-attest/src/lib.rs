#![no_std]
#![forbid(unsafe_code)]

pub mod merkle;

use m13_core::{M13Error, M13Result};
use m13_pqc::{verify as verify_pqc, DsaKeypair};
use m13_hal::SecurityModule;
use sha2::{Sha256, Digest};
use zeroize::Zeroize;
use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
use rand_core::{RngCore, CryptoRng};

/// Platform Configuration Registers (§10.1.1).
#[derive(Debug, Clone, PartialEq, Eq, Zeroize)]
pub struct PcrBank {
    pub pcr0_root: [u8; 32],
    pub pcr1_fw: [u8; 32],
    pub pcr2_kernel: [u8; 32],
    pub pcr4_policy: [u8; 32],
    pub pcr7_debug: [u8; 32],
}

impl PcrBank {
    pub fn digest(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(&self.pcr0_root);
        hasher.update(&self.pcr1_fw);
        hasher.update(&self.pcr2_kernel);
        hasher.update(&self.pcr4_policy);
        hasher.update(&self.pcr7_debug);
        hasher.finalize().into()
    }
}

/// The Epoch 0 Composite Frame (§6.3.2).
#[derive(Debug, Clone, Zeroize)]
#[zeroize(drop)]
pub struct Epoch0Frame {
    /// ML-DSA-87 Public Key (2592 bytes).
    pub pqc_pub_key: [u8; 2592],
    
    /// Legacy AIK Public Key (P-256 SEC1).
    pub legacy_aik_pub: [u8; 65], 

    /// The Software State.
    pub pcrs: PcrBank,

    /// Liveness Proof: Sign_PQC(Nonce).
    /// FIXED: Updated to FIPS 204 Standard Size (4627 bytes).
    pub sig_pqc: [u8; 4627],

    /// Binding Proof: Sign_Legacy(PCRs || H(PQC) || Nonce).
    pub sig_legacy: [u8; 256], 
    pub sig_legacy_len: usize,
}

/// PROVER: Generates the binding. Run by the Node.
pub fn generate_attestation<R: RngCore + CryptoRng>(
    nonce: &[u8; 32],
    pqc_id: &DsaKeypair,
    pcrs: PcrBank,
    hal: &mut dyn SecurityModule,
    rng: &mut R
) -> M13Result<Epoch0Frame> {
    // 1. PQC Liveness
    let sig_pqc = pqc_id.sign(nonce, rng)?;

    // 2. Legacy Binding
    let mut hasher = Sha256::new();
    hasher.update(&pcrs.digest()); // State
    hasher.update(&Sha256::digest(&pqc_id.public)); // Identity
    hasher.update(nonce); // Time
    let binding_msg = hasher.finalize();

    let mut sig_legacy = [0u8; 256];
    let len = hal.sign_digest(&binding_msg, &mut sig_legacy)?;

    Ok(Epoch0Frame {
        pqc_pub_key: pqc_id.public,
        legacy_aik_pub: [0u8; 65], // Filled by caller/HAL lookup
        pcrs,
        sig_pqc,
        sig_legacy,
        sig_legacy_len: len,
    })
}

/// VERIFIER: Validates the binding. Run by the Hub.
pub fn verify_epoch0(
    frame: &Epoch0Frame,
    nonce: &[u8; 32],
    golden_pcrs: &PcrBank
) -> M13Result<()> {
    // 1. Verify PCR State (Firmware Integrity)
    if frame.pcrs != *golden_pcrs {
        return Err(M13Error::InvalidState);
    }

    // 2. Verify PQC Liveness (Quantum Proof)
    verify_pqc(&frame.pqc_pub_key, nonce, &frame.sig_pqc)
        .map_err(|_| M13Error::CryptoFailure)?;

    // 3. Verify Legacy Binding (Hardware Proof)
    let mut hasher = Sha256::new();
    hasher.update(&frame.pcrs.digest());
    hasher.update(&Sha256::digest(&frame.pqc_pub_key));
    hasher.update(nonce);
    let binding_msg = hasher.finalize();

    let vk = VerifyingKey::from_sec1_bytes(&frame.legacy_aik_pub)
        .map_err(|_| M13Error::WireFormatError)?;
    
    let sig_bytes = &frame.sig_legacy[..frame.sig_legacy_len];
    let sig = Signature::from_der(sig_bytes)
        .or_else(|_| Signature::from_slice(sig_bytes))
        .map_err(|_| M13Error::WireFormatError)?;

    vk.verify(&binding_msg, &sig)
        .map_err(|_| M13Error::CryptoFailure)
}