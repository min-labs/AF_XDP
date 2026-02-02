#![forbid(unsafe_code)]
use m13_core::{M13Error, M13Result};
use sha2::{Sha384, Digest};

/// SHA-384 Digest Size (48 bytes) for Suite B Compliance (§10.2.1).
pub const HASH_SIZE: usize = 48;
pub type Hash = [u8; HASH_SIZE];

/// Computes the leaf hash. H(0x00 || Data)
pub fn merkle_leaf(data: &[u8]) -> Hash {
    let mut hasher = Sha384::new();
    hasher.update(&[0x00]); // RFC 6962 Leaf Prefix
    hasher.update(data);
    hasher.finalize().into()
}

/// Computes the parent hash. H(0x01 || left || right)
fn merkle_parent(left: &Hash, right: &Hash) -> Hash {
    let mut hasher = Sha384::new();
    hasher.update(&[0x01]); // RFC 6962 Node Prefix
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

/// Verifies a Merkle Inclusion Proof (§10.2.2).
pub fn verify_inclusion_proof(
    root: &Hash,
    leaf: &Hash,
    mut index: usize,
    proof: &[Hash]
) -> M13Result<()> {
    let mut computed = *leaf;

    for sibling in proof {
        if index % 2 == 0 {
            computed = merkle_parent(&computed, sibling);
        } else {
            computed = merkle_parent(sibling, &computed);
        }
        index /= 2;
    }

    if computed == *root {
        Ok(())
    } else {
        Err(M13Error::CryptoFailure)
    }
}