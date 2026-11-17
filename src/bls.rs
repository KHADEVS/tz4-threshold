//! BLS signatures as Tezos tz4 accounts use them: public keys on G1, signatures
//! on G2 (octez `Bls12_381_signature.MinPk`), the proof-of-possession scheme.
//!
//! A threshold signature is the Lagrange combination, at zero, of signature
//! shares made with Shamir shares of the key at the points 1..=n, which is
//! what octez's `threshold_signature_opt` computes. The proof of possession a
//! tz4 reveal carries is built the same way: each member signs the group's
//! public key under the PoP tag with its own share.

use bls12_381::hash_to_curve::{ExpandMsgXmd, HashToCurve};
use bls12_381::{pairing, G1Affine, G1Projective, G2Affine, G2Projective, Scalar};

/// Signatures (octez `MinPk.Pop.sign`).
pub const DST_SIG: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
/// Proofs of possession (octez `MinPk.Pop.pop_prove`).
pub const DST_POP: &[u8] = b"BLS_POP_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

/// The prefix octez puts before an operation's bytes when signing it.
pub const WATERMARK_GENERIC_OPERATION: u8 = 0x03;

pub fn hash_to_g2(message: &[u8], dst: &[u8]) -> G2Projective {
    <G2Projective as HashToCurve<ExpandMsgXmd<sha2::Sha256>>>::hash_to_curve(message, dst)
}

/// One member's share of a signature: its key share times H(message).
pub fn sign_share(share: &Scalar, message: &[u8], dst: &[u8]) -> G2Projective {
    hash_to_g2(message, dst) * share
}

/// One member's share of the group's proof of possession.
pub fn pop_share(share: &Scalar, group_public_key: &G1Affine) -> G2Projective {
    sign_share(share, &group_public_key.to_compressed(), DST_POP)
}

/// The Lagrange coefficients at zero for the points `ids`, in the same order.
/// `None` if a point is zero or repeated.
pub fn lagrange_at_zero(ids: &[u16]) -> Option<Vec<Scalar>> {
    let xs: Vec<Scalar> = ids.iter().map(|&id| Scalar::from(u64::from(id))).collect();
    let zero = Scalar::zero();
    let mut coefficients = Vec::with_capacity(xs.len());
    for (i, xi) in xs.iter().enumerate() {
        if *xi == zero {
            return None;
        }
        let mut numerator = Scalar::one();
        let mut denominator = Scalar::one();
        for (j, xj) in xs.iter().enumerate() {
            if i == j {
                continue;
            }
            if xi == xj {
                return None;
            }
            numerator *= xj;
            denominator *= xj - xi;
        }
        let inverse: Option<Scalar> = denominator.invert().into();
        coefficients.push(numerator * inverse?);
    }
    Some(coefficients)
}

/// Combines signature shares made at the points `ids` into one signature.
pub fn combine(shares: &[(u16, G2Projective)]) -> Option<G2Affine> {
    if shares.len() < 2 {
        return None;
    }
    let ids: Vec<u16> = shares.iter().map(|(id, _)| *id).collect();
    let coefficients = lagrange_at_zero(&ids)?;
    let mut sum = G2Projective::identity();
    for ((_, share), coefficient) in shares.iter().zip(coefficients) {
        sum += share * coefficient;
    }
    Some(G2Affine::from(sum))
}

/// e(g1, signature) == e(public_key, H(message)).
pub fn verify(public_key: &G1Affine, message: &[u8], dst: &[u8], signature: &G2Affine) -> bool {
    if bool::from(public_key.is_identity()) || bool::from(signature.is_identity()) {
        return false;
    }
    let hashed = G2Affine::from(hash_to_g2(message, dst));
    pairing(&G1Affine::generator(), signature) == pairing(public_key, &hashed)
}

/// The public key of a secret scalar.
pub fn public_key(secret: &Scalar) -> G1Affine {
    G1Affine::from(G1Projective::generator() * secret)
}
