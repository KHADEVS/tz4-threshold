//! A frost-core ciphersuite over BLS12-381 G1, used for its DKG only.
//!
//! Tezos' native M-of-N multisig (protocol S onward) is a tz4 address whose
//! BLS secret key is Shamir-shared at the points 1..=n; octez combines
//! signature shares by Lagrange interpolation at zero. frost-core's DKG
//! (Pedersen, with a Schnorr proof of knowledge per participant) produces
//! exactly such shares without anyone ever holding the whole key, so this
//! module only gives it a group to run on. FROST signing is not used: the
//! signatures are BLS (see `bls`).
//!
//! The hashes are this crate's own, domain-separated by `ID`; they only feed
//! the DKG's proof-of-knowledge challenge and the identifier derivation.

use bls12_381::{G1Affine, G1Projective, Scalar};
use frost_core::{Ciphersuite, Field, FieldError, Group, GroupError};
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha256, Sha512};

/// The scalar field of BLS12-381.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ScalarField;

impl Field for ScalarField {
    type Scalar = Scalar;
    type Serialization = [u8; 32];

    fn zero() -> Scalar {
        <Scalar as ff::Field>::ZERO
    }

    fn one() -> Scalar {
        <Scalar as ff::Field>::ONE
    }

    fn invert(scalar: &Scalar) -> Result<Scalar, FieldError> {
        Option::from(scalar.invert()).ok_or(FieldError::InvalidZeroScalar)
    }

    fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Scalar {
        <Scalar as ff::Field>::random(rng)
    }

    /// Little-endian, as `bls12_381` encodes scalars.
    fn serialize(scalar: &Scalar) -> [u8; 32] {
        scalar.to_bytes()
    }

    fn little_endian_serialize(scalar: &Scalar) -> [u8; 32] {
        scalar.to_bytes()
    }

    fn deserialize(buf: &[u8; 32]) -> Result<Scalar, FieldError> {
        Option::from(Scalar::from_bytes(buf)).ok_or(FieldError::MalformedScalar)
    }
}

/// The prime-order subgroup of BLS12-381 G1, where tz4 public keys live.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct G1;

impl Group for G1 {
    type Field = ScalarField;
    type Element = G1Projective;
    type Serialization = [u8; 48];

    /// Elements are always in the prime-order subgroup: `from_compressed`
    /// rejects anything else.
    fn cofactor() -> Scalar {
        <Scalar as ff::Field>::ONE
    }

    fn identity() -> G1Projective {
        G1Projective::identity()
    }

    fn generator() -> G1Projective {
        G1Projective::generator()
    }

    /// The 48-byte compressed encoding, the same as a tz4 public key.
    fn serialize(element: &G1Projective) -> Result<[u8; 48], GroupError> {
        if bool::from(element.is_identity()) {
            return Err(GroupError::InvalidIdentityElement);
        }
        Ok(G1Affine::from(element).to_compressed())
    }

    fn deserialize(buf: &[u8; 48]) -> Result<G1Projective, GroupError> {
        let point: Option<G1Affine> = G1Affine::from_compressed(buf).into();
        let point = point.ok_or(GroupError::MalformedElement)?;
        if bool::from(point.is_identity()) {
            return Err(GroupError::InvalidIdentityElement);
        }
        Ok(point.into())
    }
}

/// The ciphersuite the DKG runs on.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Tz4Dkg;

const ID: &str = "TZ4-THRESHOLD-BLS12381G1-SHA512-DKG-v0";

/// SHA-512 of `ID || tag || m`, reduced into the scalar field.
fn hash_to_scalar(tag: &[u8], m: &[u8]) -> Scalar {
    let mut h = Sha512::new();
    h.update(ID.as_bytes());
    h.update(tag);
    h.update(m);
    let wide: [u8; 64] = h.finalize().into();
    Scalar::from_bytes_wide(&wide)
}

fn hash_32(tag: &[u8], m: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(ID.as_bytes());
    h.update(tag);
    h.update(m);
    h.finalize().into()
}

impl Ciphersuite for Tz4Dkg {
    const ID: &'static str = ID;
    type Group = G1;
    type HashOutput = [u8; 32];
    /// A Schnorr signature: R (48 bytes) then z (32 bytes).
    type SignatureSerialization = [u8; 80];

    fn H1(m: &[u8]) -> Scalar {
        hash_to_scalar(b"rho", m)
    }

    fn H2(m: &[u8]) -> Scalar {
        hash_to_scalar(b"chal", m)
    }

    fn H3(m: &[u8]) -> Scalar {
        hash_to_scalar(b"nonce", m)
    }

    fn H4(m: &[u8]) -> [u8; 32] {
        hash_32(b"msg", m)
    }

    fn H5(m: &[u8]) -> [u8; 32] {
        hash_32(b"com", m)
    }

    fn HDKG(m: &[u8]) -> Option<Scalar> {
        Some(hash_to_scalar(b"dkg", m))
    }

    fn HID(m: &[u8]) -> Option<Scalar> {
        Some(hash_to_scalar(b"id", m))
    }
}
