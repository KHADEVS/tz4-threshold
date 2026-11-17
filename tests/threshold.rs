//! A DKG group signs and proves possession with any `t` of its `n` members,
//! and not with fewer.

use bls12_381::{G2Affine, Scalar};
use tz4_threshold::bls::{self, DST_POP, DST_SIG};
use tz4_threshold::dkg::{run_in_process, Member};

fn signature(members: &[&Member], message: &[u8]) -> G2Affine {
    let shares: Vec<_> = members
        .iter()
        .map(|m| (m.id, bls::sign_share(&m.share, message, DST_SIG)))
        .collect();
    bls::combine(&shares).expect("distinct non-zero points")
}

#[test]
fn every_pair_of_a_2_of_3_group_signs_for_the_group_key() {
    let members = run_in_process(2, 3).unwrap();
    let key = members[0].group_public_key;
    assert!(members.iter().all(|m| m.group_public_key == key));
    let message = b"\x03an operation's bytes";
    for (a, b) in [(0, 1), (0, 2), (1, 2)] {
        let sig = signature(&[&members[a], &members[b]], message);
        assert!(bls::verify(&key, message, DST_SIG, &sig), "pair {a},{b}");
        assert!(!bls::verify(&key, b"\x03another operation", DST_SIG, &sig));
    }
}

#[test]
fn the_pairs_produce_the_same_signature() {
    // BLS is deterministic: any t members reconstruct the same group signature.
    let members = run_in_process(2, 3).unwrap();
    let message = b"\x03same bytes";
    let one = signature(&[&members[0], &members[1]], message);
    let two = signature(&[&members[1], &members[2]], message);
    assert_eq!(one, two);
}

#[test]
fn the_group_proves_possession_of_its_key_without_a_dealer() {
    let members = run_in_process(2, 3).unwrap();
    let key = members[0].group_public_key;
    let shares: Vec<_> = [&members[0], &members[2]]
        .iter()
        .map(|m| (m.id, bls::pop_share(&m.share, &key)))
        .collect();
    let proof = bls::combine(&shares).unwrap();
    assert!(bls::verify(&key, &key.to_compressed(), DST_POP, &proof));
    // The same bytes under the signature tag are not a proof.
    assert!(!bls::verify(&key, &key.to_compressed(), DST_SIG, &proof));
}

#[test]
fn one_share_is_not_enough() {
    let members = run_in_process(2, 3).unwrap();
    let key = members[0].group_public_key;
    let message = b"\x03bytes";
    assert!(bls::combine(&[(
        members[0].id,
        bls::sign_share(&members[0].share, message, DST_SIG)
    )])
    .is_none());
    // A share alone does not verify against the group key.
    let alone = G2Affine::from(bls::sign_share(&members[0].share, message, DST_SIG));
    assert!(!bls::verify(&key, message, DST_SIG, &alone));
}

#[test]
fn a_3_of_5_group_needs_three() {
    let members = run_in_process(3, 5).unwrap();
    let key = members[0].group_public_key;
    let message = b"\x03bytes";
    let three = signature(&[&members[0], &members[2], &members[4]], message);
    assert!(bls::verify(&key, message, DST_SIG, &three));
    let two = signature(&[&members[1], &members[3]], message);
    assert!(!bls::verify(&key, message, DST_SIG, &two));
}

#[test]
fn lagrange_rejects_a_repeated_or_zero_point() {
    assert!(bls::lagrange_at_zero(&[1, 1]).is_none());
    assert!(bls::lagrange_at_zero(&[0, 2]).is_none());
    // Interpolating f(x) = 7 + 3x through x = 1, 2 gives f(0) = 7.
    let c = bls::lagrange_at_zero(&[1, 2]).unwrap();
    let f = |x: u64| Scalar::from(7) + Scalar::from(3) * Scalar::from(x);
    assert_eq!(c[0] * f(1) + c[1] * f(2), Scalar::from(7));
}
