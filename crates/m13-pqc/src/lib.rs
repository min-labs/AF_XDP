#![no_std]

use m13_core::{M13Error, M13Result};
use zeroize::{Zeroize, ZeroizeOnDrop};
use rand_core::{RngCore, CryptoRng};
use fips203::{ml_kem_1024, traits::{KeyGen, SerDes, Decaps, Encaps}};
use fips204::{ml_dsa_87, traits::{KeyGen as SignKeyGen, SerDes as SignSerDes, Signer, Verifier}};

pub const KYBER_PUBLIC_KEY_SIZE: usize = ml_kem_1024::EK_LEN;
pub const KYBER_CIPHERTEXT_SIZE: usize = ml_kem_1024::CT_LEN;
pub const DILITHIUM_SIGNATURE_SIZE: usize = ml_dsa_87::SIG_LEN;

pub type KyberKeypair = KemKeypair;

#[derive(Debug, Zeroize, ZeroizeOnDrop)]
pub struct KemKeypair {
    pub public: [u8; ml_kem_1024::EK_LEN],
    pub secret: [u8; ml_kem_1024::DK_LEN],
}

impl KemKeypair {
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> M13Result<Self> {
        let (ek, dk) = ml_kem_1024::KG::try_keygen_with_rng(rng).map_err(|_| M13Error::RngFailure)?;
        Ok(Self { public: ek.into_bytes(), secret: dk.into_bytes() })
    }
}

pub fn kyber_keypair<R: RngCore + CryptoRng>(rng: &mut R) -> KemKeypair {
    KemKeypair::generate(rng).expect("RNG Fail")
}

pub fn kyber_encapsulate<R: RngCore + CryptoRng>(pk_bytes: &[u8], rng: &mut R) -> M13Result<([u8; ml_kem_1024::CT_LEN], [u8; 32])> {
    let pk_array: [u8; ml_kem_1024::EK_LEN] = pk_bytes.try_into().map_err(|_| M13Error::WireFormatError)?;
    let ek = ml_kem_1024::EncapsKey::try_from_bytes(pk_array).map_err(|_| M13Error::WireFormatError)?;
    let (ss, ct) = ek.try_encaps_with_rng(rng).map_err(|_| M13Error::CryptoFailure)?;
    Ok((ct.into_bytes(), ss.into_bytes()))
}

pub fn kyber_decapsulate(keypair: &KemKeypair, ct_bytes: &[u8]) -> M13Result<[u8; 32]> {
    let dk_array: [u8; ml_kem_1024::DK_LEN] = keypair.secret.try_into().map_err(|_| M13Error::WireFormatError)?;
    let dk = ml_kem_1024::DecapsKey::try_from_bytes(dk_array).map_err(|_| M13Error::WireFormatError)?;
    let ct_array: [u8; ml_kem_1024::CT_LEN] = ct_bytes.try_into().map_err(|_| M13Error::WireFormatError)?;
    let ct = ml_kem_1024::CipherText::try_from_bytes(ct_array).map_err(|_| M13Error::WireFormatError)?;
    let ss = dk.try_decaps(&ct).map_err(|_| M13Error::CryptoFailure)?;
    Ok(ss.into_bytes())
}

#[derive(Debug, Zeroize, ZeroizeOnDrop)]
pub struct DsaKeypair {
    pub public: [u8; ml_dsa_87::PK_LEN],
    pub secret: [u8; ml_dsa_87::SK_LEN],
}

impl DsaKeypair {
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> M13Result<Self> {
        let (pk, sk) = ml_dsa_87::KG::try_keygen_with_rng(rng).map_err(|_| M13Error::RngFailure)?;
        Ok(Self { public: pk.into_bytes(), secret: sk.into_bytes() })
    }
}

pub fn dsa_sign(msg: &[u8], sk_bytes: &[u8]) -> [u8; ml_dsa_87::SIG_LEN] {
    let sk_array: [u8; ml_dsa_87::SK_LEN] = sk_bytes.try_into().unwrap();
    let sk = ml_dsa_87::PrivateKey::try_from_bytes(sk_array).unwrap();
    sk.try_sign_with_rng(&mut rand_core::OsRng, msg, b"").unwrap()
}

pub fn dsa_verify(pk_bytes: &[u8], sig_bytes: &[u8], msg: &[u8]) -> M13Result<()> {
    let pk_array: [u8; ml_dsa_87::PK_LEN] = pk_bytes.try_into().map_err(|_| M13Error::WireFormatError)?;
    let pk = ml_dsa_87::PublicKey::try_from_bytes(pk_array).map_err(|_| M13Error::WireFormatError)?;
    let sig_array: [u8; ml_dsa_87::SIG_LEN] = sig_bytes.try_into().map_err(|_| M13Error::WireFormatError)?;
    if pk.verify(msg, &sig_array, b"") { Ok(()) } else { Err(M13Error::CryptoFailure) }
}