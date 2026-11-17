//! tz4-threshold: a threshold tz4 account on a Tezos test network, made by a
//! DKG and spent with any `t` of its `n` members.
//!
//!   tz4-threshold dkg --t 2 --n 3 [--out state]
//!   tz4-threshold info [--dir state] --rpc URL
//!   tz4-threshold pop [--dir state] --signers 1,3 [--rpc URL]
//!   tz4-threshold send [--dir state] --signers 2,3 --to ADDRESS --amount TEZ --rpc URL
//!
//! Prototype: `dkg` plays every member in one process and the member files
//! hold their shares unencrypted. Test networks and test amounts only.

use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

use bls12_381::{G2Affine, Scalar};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tz4_threshold::bls::{self, DST_SIG, WATERMARK_GENERIC_OPERATION};
use tz4_threshold::dkg;
use tz4_threshold::tezos::{self, Rpc};

#[derive(Serialize, Deserialize)]
struct MemberFile {
    id: u16,
    /// Little-endian scalar, hex. Unencrypted: prototype only.
    share: String,
    group_public_key: String,
    address: String,
}

#[derive(Serialize, Deserialize)]
struct GroupFile {
    threshold: u16,
    members: u16,
    public_key: String,
    address: String,
}

fn option<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .map(String::as_str)
}

fn required<'a>(args: &'a [String], name: &str) -> Result<&'a str, Box<dyn Error>> {
    option(args, name).ok_or_else(|| format!("{name} is required").into())
}

fn dir(args: &[String], name: &str) -> PathBuf {
    PathBuf::from(option(args, name).unwrap_or("state"))
}

fn load_group(dir: &Path) -> Result<GroupFile, Box<dyn Error>> {
    Ok(serde_json::from_str(&fs::read_to_string(
        dir.join("group.json"),
    )?)?)
}

fn load_member(dir: &Path, id: u16) -> Result<(u16, Scalar), Box<dyn Error>> {
    let file: MemberFile =
        serde_json::from_str(&fs::read_to_string(dir.join(format!("member-{id}.json")))?)?;
    let bytes: [u8; 32] = hex::decode(&file.share)?
        .try_into()
        .map_err(|_| "share length")?;
    let share = Option::from(Scalar::from_bytes(&bytes)).ok_or("not a canonical scalar")?;
    Ok((file.id, share))
}

fn signers(args: &[String]) -> Result<Vec<u16>, Box<dyn Error>> {
    required(args, "--signers")?
        .split(',')
        .map(|s| s.trim().parse::<u16>().map_err(|e| e.into()))
        .collect()
}

fn cmd_dkg(args: &[String]) -> Result<(), Box<dyn Error>> {
    let t: u16 = required(args, "--t")?.parse()?;
    let n: u16 = required(args, "--n")?.parse()?;
    let out = dir(args, "--out");
    if out.join("group.json").exists() {
        return Err(format!("{} already holds a group", out.display()).into());
    }
    fs::create_dir_all(&out)?;
    let members = dkg::run_in_process(t, n)?;
    let key = members[0].group_public_key;
    let public_key = tezos::encode_public_key(&key);
    let address = tezos::tz4_address(&key);
    for m in &members {
        let file = MemberFile {
            id: m.id,
            share: hex::encode(m.share.to_bytes()),
            group_public_key: public_key.clone(),
            address: address.clone(),
        };
        fs::write(
            out.join(format!("member-{}.json", m.id)),
            serde_json::to_string_pretty(&file)?,
        )?;
    }
    let group = GroupFile {
        threshold: t,
        members: n,
        public_key: public_key.clone(),
        address: address.clone(),
    };
    fs::write(
        out.join("group.json"),
        serde_json::to_string_pretty(&group)?,
    )?;
    println!("{t}-of-{n} group made by DKG, no dealer");
    println!("  public key {public_key}");
    println!("  address    {address}");
    Ok(())
}

/// The group's proof of possession, combined from the signers' shares.
fn threshold_proof(dir: &Path, group: &GroupFile, ids: &[u16]) -> Result<G2Affine, Box<dyn Error>> {
    let key = tezos::decode_public_key(&group.public_key)?;
    let mut shares = Vec::new();
    for &id in ids {
        let (point, share) = load_member(dir, id)?;
        shares.push((point, bls::pop_share(&share, &key)));
    }
    let proof = bls::combine(&shares).ok_or("need at least two distinct signers")?;
    if !bls::verify(&key, &key.to_compressed(), bls::DST_POP, &proof) {
        return Err(format!(
            "the shares of {ids:?} do not make a valid proof: below the threshold?"
        )
        .into());
    }
    Ok(proof)
}

fn cmd_info(args: &[String]) -> Result<(), Box<dyn Error>> {
    let dir = dir(args, "--dir");
    let group = load_group(&dir)?;
    let rpc = Rpc::new(required(args, "--rpc")?);
    println!("{}-of-{} {}", group.threshold, group.members, group.address);
    println!("  balance  {} mutez", rpc.balance(&group.address)?);
    println!("  revealed {}", rpc.is_revealed(&group.address)?);
    Ok(())
}

fn cmd_pop(args: &[String]) -> Result<(), Box<dyn Error>> {
    let dir = dir(args, "--dir");
    let group = load_group(&dir)?;
    let ids = signers(args)?;
    let proof = tezos::encode_signature(&threshold_proof(&dir, &group, &ids)?);
    println!("proof of possession from members {ids:?}: {proof}");
    println!("  checked here: valid");
    if let Some(url) = option(args, "--rpc") {
        let ok = Rpc::new(url).check_proof(&group.public_key, &proof)?;
        println!(
            "  checked by the node (/bls/check_proof): {}",
            if ok { "valid" } else { "INVALID" }
        );
        if !ok {
            return Err("the node rejects the proof".into());
        }
    }
    Ok(())
}

fn tez_to_mutez(tez: &str) -> Result<u64, Box<dyn Error>> {
    let (whole, frac) = tez.split_once('.').unwrap_or((tez, ""));
    if frac.len() > 6 {
        return Err("at most 6 decimals".into());
    }
    let frac = format!("{frac:0<6}");
    Ok(whole.parse::<u64>()? * 1_000_000 + frac.parse::<u64>()?)
}

fn cmd_send(args: &[String]) -> Result<(), Box<dyn Error>> {
    let dir = dir(args, "--dir");
    let group = load_group(&dir)?;
    let ids = signers(args)?;
    let to = required(args, "--to")?;
    let amount = tez_to_mutez(required(args, "--amount")?)?;
    let rpc = Rpc::new(required(args, "--rpc")?);

    let (branch, protocol) = rpc.head()?;
    let mut counter = rpc.counter(&group.address)?;
    let mut contents: Vec<Value> = Vec::new();
    if !rpc.is_revealed(&group.address)? {
        let proof = tezos::encode_signature(&threshold_proof(&dir, &group, &ids)?);
        counter += 1;
        contents.push(json!({
            "kind": "reveal", "source": group.address, "fee": "5000",
            "counter": counter.to_string(), "gas_limit": "20000", "storage_limit": "0",
            "public_key": group.public_key, "proof": proof
        }));
    }
    counter += 1;
    contents.push(json!({
        "kind": "transaction", "source": group.address, "fee": "5000",
        "counter": counter.to_string(), "gas_limit": "20000", "storage_limit": "300",
        "amount": amount.to_string(), "destination": to
    }));
    let contents = Value::Array(contents);

    let forged = rpc.forge(&branch, &contents)?;
    let mut message = vec![WATERMARK_GENERIC_OPERATION];
    message.extend_from_slice(&forged);

    let key = tezos::decode_public_key(&group.public_key)?;
    let mut shares = Vec::new();
    let mut encoded_shares = Vec::new();
    for &id in &ids {
        let (point, share) = load_member(&dir, id)?;
        let s = bls::sign_share(&share, &message, DST_SIG);
        encoded_shares.push((point, tezos::encode_signature(&G2Affine::from(s))));
        shares.push((point, s));
    }
    let signature = bls::combine(&shares).ok_or("need at least two distinct signers")?;
    if !bls::verify(&key, &message, DST_SIG, &signature) {
        return Err(format!("members {ids:?} do not reach the threshold").into());
    }
    let encoded = tezos::encode_signature(&signature);
    println!("signed by members {ids:?}: {encoded}");

    // Cross-check: octez combines the same shares into the same signature.
    match rpc.threshold_signatures(&group.public_key, &message, &encoded_shares) {
        Ok(Value::String(node)) if node == encoded => println!("  the node's combination matches"),
        Ok(other) => println!("  the node's combination differs: {other}"),
        Err(e) => println!("  the node could not combine: {e}"),
    }

    let applied = rpc.preapply(&protocol, &branch, &contents, &encoded)?;
    let results: Vec<&Value> = applied[0]["contents"]
        .as_array()
        .ok_or("preapply returned no contents")?
        .iter()
        .map(|c| &c["metadata"]["operation_result"])
        .collect();
    for (i, r) in results.iter().enumerate() {
        let status = r["status"].as_str().unwrap_or("?");
        println!("  preapply {i}: {status}");
        if status != "applied" {
            return Err(format!(
                "not injected: operation {i} would be {status}: {}",
                r["errors"]
            )
            .into());
        }
    }
    // A BLS signature is 96 bytes. The operation encoding carries its first
    // 32 bytes in a trailing Signature_prefix content (tag 255, Bls_prefix
    // tag 3) and its last 64 as the usual signature suffix.
    let sig = signature.to_compressed();
    let mut signed = forged.clone();
    signed.extend_from_slice(&[0xff, 0x03]);
    signed.extend_from_slice(&sig[..32]);
    signed.extend_from_slice(&sig[32..]);
    let hash = rpc.inject(&signed)?;
    println!("  injected {hash}");
    Ok(())
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let result = match args.get(1).map(String::as_str) {
        Some("dkg") => cmd_dkg(&args),
        Some("info") => cmd_info(&args),
        Some("pop") => cmd_pop(&args),
        Some("send") => cmd_send(&args),
        _ => Err("usage: tz4-threshold dkg|info|pop|send (see src/main.rs)".into()),
    };
    if let Err(e) = result {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}
