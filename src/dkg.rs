//! An M-of-N tz4 group made by frost-core's DKG: nobody ever holds the whole
//! secret key, unlike `octez-client share bls secret key`, which needs a
//! dealer who knows it.
//!
//! `run_in_process` plays every member in one process, for the prototype; a
//! real setup runs `part1`/`part2`/`part3` on each member's own device and
//! carries the packages between them.

use std::collections::BTreeMap;
use std::error::Error;

use bls12_381::{G1Affine, Scalar};
use frost_core::keys::dkg;
use frost_core::Identifier;
use rand_core::OsRng;

use crate::suite::Tz4Dkg;

/// What one member keeps: its point, its share, and the group's key.
#[derive(Clone)]
pub struct Member {
    /// The Shamir point, 1..=n, which octez calls the share's `id`.
    pub id: u16,
    pub share: Scalar,
    pub group_public_key: G1Affine,
}

fn scalar_of(bytes: &[u8]) -> Result<Scalar, Box<dyn Error>> {
    let bytes: [u8; 32] = bytes.try_into().map_err(|_| "a share is not 32 bytes")?;
    Option::from(Scalar::from_bytes(&bytes))
        .ok_or_else(|| "a share is not a canonical scalar".into())
}

fn point_of(bytes: &[u8]) -> Result<G1Affine, Box<dyn Error>> {
    let bytes: [u8; 48] = bytes
        .try_into()
        .map_err(|_| "a public key is not 48 bytes")?;
    Option::from(G1Affine::from_compressed(&bytes))
        .ok_or_else(|| "a public key is not on G1".into())
}

/// Runs the three DKG rounds for `n` members with threshold `t`.
pub fn run_in_process(t: u16, n: u16) -> Result<Vec<Member>, Box<dyn Error>> {
    let ids: Vec<u16> = (1..=n).collect();
    let identifier = |id: u16| Identifier::<Tz4Dkg>::try_from(id);

    let mut round1_secrets = BTreeMap::new();
    let mut round1_packages = BTreeMap::new();
    for &id in &ids {
        let (secret, package) = dkg::part1(identifier(id)?, n, t, OsRng)?;
        round1_secrets.insert(id, secret);
        round1_packages.insert(id, package);
    }

    let mut round2_secrets = BTreeMap::new();
    let mut round2_packages: BTreeMap<u16, BTreeMap<Identifier<Tz4Dkg>, _>> = BTreeMap::new();
    for &id in &ids {
        let others: BTreeMap<_, _> = round1_packages
            .iter()
            .filter(|(&other, _)| other != id)
            .map(|(&other, package)| Ok((identifier(other)?, package.clone())))
            .collect::<Result<_, frost_core::Error<Tz4Dkg>>>()?;
        let secret = round1_secrets.remove(&id).ok_or("missing round 1 secret")?;
        let (secret, outgoing) = dkg::part2(secret, &others)?;
        round2_secrets.insert(id, secret);
        for (recipient, package) in outgoing {
            let recipient_id = ids
                .iter()
                .copied()
                .find(|&candidate| identifier(candidate).ok() == Some(recipient))
                .ok_or("unknown recipient")?;
            round2_packages
                .entry(recipient_id)
                .or_default()
                .insert(identifier(id)?, package);
        }
    }

    let mut members = Vec::new();
    let mut group_key: Option<G1Affine> = None;
    for &id in &ids {
        let others_round1: BTreeMap<_, _> = round1_packages
            .iter()
            .filter(|(&other, _)| other != id)
            .map(|(&other, package)| Ok((identifier(other)?, package.clone())))
            .collect::<Result<_, frost_core::Error<Tz4Dkg>>>()?;
        let received = round2_packages.get(&id).ok_or("no round 2 packages")?;
        let secret = round2_secrets.get(&id).ok_or("missing round 2 secret")?;
        let (key_package, public_package) = dkg::part3(secret, &others_round1, received)?;
        let share = scalar_of(&key_package.signing_share().serialize())?;
        let group_public_key = point_of(&public_package.verifying_key().serialize()?)?;
        if let Some(seen) = group_key {
            if seen != group_public_key {
                return Err("members disagree on the group key".into());
            }
        }
        group_key = Some(group_public_key);
        members.push(Member {
            id,
            share,
            group_public_key,
        });
    }
    Ok(members)
}
