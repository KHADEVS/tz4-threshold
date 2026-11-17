//! Threshold tz4 accounts on Tezos without a trusted dealer.
//!
//! Tezos' native multisig (protocol S onward) lets one tz4 address be
//! controlled M-of-N, but `octez-client share bls secret key` needs a dealer
//! who generates the whole key and hands out unencrypted shares. This crate
//! makes the shares with a DKG instead (frost-core's, over BLS12-381 G1),
//! then signs operations and the reveal's proof of possession by combining
//! BLS signature shares, as octez's `threshold_signature_opt` does.
//!
//! Prototype: test networks only.

pub mod bls;
pub mod dkg;
pub mod suite;
pub mod tezos;
