# tz4-threshold

Threshold tz4 accounts on Tezos without a trusted dealer.

Since protocol S (Seoul), a tz4 address can be controlled M-of-N natively: its BLS key is Shamir-shared among the members, and any M of them sign for it. Today the shares come from `octez-client share bls secret key`, which needs one party to generate the whole key and hand out unencrypted shares. The [Octez documentation](https://octez.tezos.com/docs/alpha/native_multisig.html) says so, and lists distributed key generation as future work.

This prototype makes the shares with a distributed key generation (DKG) instead, so no one ever holds the whole key, and then uses them exactly as Octez does.

## How it works

- **DKG.** The Zcash Foundation's [`frost-core`](https://github.com/ZcashFoundation/frost) DKG (Pedersen, with a proof of knowledge per member) runs over BLS12-381 G1. Each member ends with a Shamir share of the key at its point `1..=n`, the same shares `share bls secret key` would produce, so Octez's own `threshold_signature_opt` combines them.
- **Reveal.** A tz4 reveal needs a proof of possession. Each member signs the group's public key under the proof-of-possession tag with its share, and any M shares combine into the group's proof.
- **Signing.** Each member signs the operation's bytes (watermark `0x03`) with its share. The shares are combined by Lagrange interpolation at zero.
- **Encoding.** A BLS signature is 96 bytes. The operation carries its first 32 bytes in a trailing `Signature_prefix` content (tag 255, `Bls_prefix` 3) and the last 64 as the usual signature.
- **Separate members.** In `member`/`coord` mode each member runs in its own process and only reads its own folder and a shared exchange folder. Before signing, a member checks that the bytes it is asked to sign encode the operation it is shown, and refuses otherwise.

## Checked on Shadownet

| What | Operation | Level |
| --- | --- | --- |
| Reveal with a threshold proof, then 100 tez sent, signed by members 1 and 3 of a 2-of-3 group | [`opBsxd4z…ZRd4kp`](https://shadownet.tzkt.io/opBsxd4zX9Y912PN2Key8hmQNyFFBcVLpS6VWW6k2modDZRd4kp) | 5,966,985 |
| Same with every member in its own process: proof by members 1 and 2, signature by members 1 and 3, 10 tez sent | [`opCYdLMF…MCZ`](https://shadownet.tzkt.io/opCYdLMFog8Jj5UHxy45fpnPLV5BC9YQkrM7ZraPsJrdmXM9MCZ) | 5,967,113 |

The node also accepts every threshold proof through `/bls/check_proof`, and `/bls/threshold_signatures` combines the members' shares into the same signature as this crate.

## Use

```
cargo build --release

# DKG, one process per member
tz4-threshold member dkg1 --group G --id 1 --t 2 --n 3     # likewise for 2 and 3
tz4-threshold member dkg2 --group G --id 1                 # likewise for 2 and 3
tz4-threshold member dkg3 --group G --id 1                 # likewise for 2 and 3
tz4-threshold coord group --group G                        # every member reports the same tz4

# First spend: the reveal needs a proof of possession
tz4-threshold member pop --group G --id 1                  # and one more member
tz4-threshold coord prepare --group G --rpc URL --to ADDRESS --amount TEZ
tz4-threshold member sign --group G --id 1 --rpc OTHER_URL # and one more member
tz4-threshold coord submit --group G --rpc URL
```

`dkg`, `pop` and `send` do the same in one process, for quick tests.

## Limits

This is a prototype for test networks:

- round 2 packages carry secret shares and are plain files here; on a real channel they must be encrypted to their recipient;
- key shares are stored unencrypted;
- a member checks the bytes by asking a second node to re-encode the operation, not yet by decoding them itself;
- the DKG's ciphersuite (`TZ4-THRESHOLD-BLS12381G1-SHA512-DKG-v0`) is this crate's own and has not been reviewed;
- nothing here is audited.

## License

MIT
