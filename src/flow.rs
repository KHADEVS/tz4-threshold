//! The same group with each member in its own process, exchanging files.
//!
//! A group directory holds one private folder per member (`member-<id>/`)
//! and a shared `exchange/` folder, which stands for whatever carries the
//! messages between devices (files, QR codes). Each member only ever reads
//! its own folder and the exchange: no process sees the whole key.
//!
//!   member dkg1 --group G --id I --t T --n N   round 1: commitment + proof
//!   member dkg2 --group G --id I               round 2: one share per member
//!   member dkg3 --group G --id I               key share and group key
//!   coord  group --group G                     checks every member agrees
//!   coord  prepare --group G --rpc URL --to ADDRESS --amount TEZ
//!   member pop  --group G --id I               share of the proof of possession
//!   member sign --group G --id I [--rpc URL]   share of the operation's signature
//!   coord  submit --group G --rpc URL
//!
//! Prototype: round 2 packages carry secret shares and must be encrypted to
//! their recipient on a real channel; here they are plain files, and the key
//! shares are stored unencrypted. Test networks only.

use std::collections::BTreeMap;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

use bls12_381::{G1Affine, G2Affine, G2Projective, Scalar};
use frost_core::keys::dkg::{self, round1, round2};
use frost_core::Identifier;
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tz4_threshold::bls::{self, DST_POP, DST_SIG, WATERMARK_GENERIC_OPERATION};
use tz4_threshold::suite::Tz4Dkg;
use tz4_threshold::tezos::{self, Rpc};

type Res<T> = Result<T, Box<dyn Error>>;

fn option<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .map(String::as_str)
}

fn required<'a>(args: &'a [String], name: &str) -> Res<&'a str> {
    option(args, name).ok_or_else(|| format!("{name} is required").into())
}

fn group_dir(args: &[String]) -> Res<PathBuf> {
    Ok(PathBuf::from(required(args, "--group")?))
}

fn exchange(group: &Path) -> PathBuf {
    group.join("exchange")
}

fn private(group: &Path, id: u16) -> PathBuf {
    group.join(format!("member-{id}"))
}

fn id_arg(args: &[String]) -> Res<u16> {
    Ok(required(args, "--id")?.parse()?)
}

fn identifier(id: u16) -> Res<Identifier<Tz4Dkg>> {
    Ok(Identifier::try_from(id)?)
}

fn write_hex(path: &Path, bytes: &[u8]) -> Res<()> {
    fs::create_dir_all(path.parent().ok_or("no parent")?)?;
    Ok(fs::write(path, hex::encode(bytes))?)
}

fn read_hex(path: &Path) -> Res<Vec<u8>> {
    Ok(hex::decode(fs::read_to_string(path)?.trim())?)
}

/// What a member keeps after the DKG.
#[derive(Serialize, Deserialize)]
struct KeyFile {
    id: u16,
    threshold: u16,
    members: u16,
    /// Little-endian scalar, hex. Unencrypted: prototype only.
    share: String,
    group_public_key: String,
    address: String,
}

/// What a member publishes after the DKG, for the coordinator to compare.
#[derive(Serialize, Deserialize)]
struct PublicFile {
    id: u16,
    group_public_key: String,
    address: String,
}

#[derive(Serialize, Deserialize)]
struct Params {
    threshold: u16,
    members: u16,
}

fn round1_from_others(
    group: &Path,
    me: u16,
    n: u16,
) -> Res<BTreeMap<Identifier<Tz4Dkg>, round1::Package<Tz4Dkg>>> {
    let mut packages = BTreeMap::new();
    for other in (1..=n).filter(|&o| o != me) {
        let bytes = read_hex(&exchange(group).join(format!("round1-{other}.hex")))
            .map_err(|_| format!("member {other} has not published round 1 yet"))?;
        packages.insert(identifier(other)?, round1::Package::deserialize(&bytes)?);
    }
    Ok(packages)
}

pub fn member(args: &[String]) -> Res<()> {
    match args.get(2).map(String::as_str) {
        Some("dkg1") => dkg1(args),
        Some("dkg2") => dkg2(args),
        Some("dkg3") => dkg3(args),
        Some("pop") => pop(args),
        Some("sign") => sign(args),
        _ => Err("member dkg1|dkg2|dkg3|pop|sign".into()),
    }
}

pub fn coord(args: &[String]) -> Res<()> {
    match args.get(2).map(String::as_str) {
        Some("group") => coord_group(args).map(|_| ()),
        Some("prepare") => prepare(args),
        Some("submit") => submit(args),
        _ => Err("coord group|prepare|submit".into()),
    }
}

fn dkg1(args: &[String]) -> Res<()> {
    let group = group_dir(args)?;
    let id = id_arg(args)?;
    let t: u16 = required(args, "--t")?.parse()?;
    let n: u16 = required(args, "--n")?.parse()?;
    let mine = private(&group, id);
    if mine.join("round1-secret.hex").exists() || mine.join("key.json").exists() {
        return Err(format!("member {id} already started a DKG in {}", group.display()).into());
    }
    let (secret, package) = dkg::part1(identifier(id)?, n, t, OsRng)?;
    write_hex(&mine.join("round1-secret.hex"), &secret.serialize()?)?;
    fs::write(
        mine.join("params.json"),
        serde_json::to_string(&Params {
            threshold: t,
            members: n,
        })?,
    )?;
    write_hex(
        &exchange(&group).join(format!("round1-{id}.hex")),
        &package.serialize()?,
    )?;
    println!("member {id}: round 1 published ({t}-of-{n})");
    Ok(())
}

fn params(group: &Path, id: u16) -> Res<Params> {
    Ok(serde_json::from_str(&fs::read_to_string(
        private(group, id).join("params.json"),
    )?)?)
}

fn dkg2(args: &[String]) -> Res<()> {
    let group = group_dir(args)?;
    let id = id_arg(args)?;
    let p = params(&group, id)?;
    let mine = private(&group, id);
    let secret =
        round1::SecretPackage::<Tz4Dkg>::deserialize(&read_hex(&mine.join("round1-secret.hex"))?)?;
    let others = round1_from_others(&group, id, p.members)?;
    let (secret2, outgoing) = dkg::part2(secret, &others)?;
    write_hex(&mine.join("round2-secret.hex"), &secret2.serialize()?)?;
    fs::remove_file(mine.join("round1-secret.hex"))?;
    for other in (1..=p.members).filter(|&o| o != id) {
        let package = outgoing
            .get(&identifier(other)?)
            .ok_or("missing outgoing package")?;
        // Carries a secret share: encrypt to the recipient on a real channel.
        write_hex(
            &exchange(&group).join(format!("round2-{id}-to-{other}.hex")),
            &package.serialize()?,
        )?;
    }
    println!("member {id}: round 2 sent to the {} others", p.members - 1);
    Ok(())
}

fn dkg3(args: &[String]) -> Res<()> {
    let group = group_dir(args)?;
    let id = id_arg(args)?;
    let p = params(&group, id)?;
    let mine = private(&group, id);
    let secret2 =
        round2::SecretPackage::<Tz4Dkg>::deserialize(&read_hex(&mine.join("round2-secret.hex"))?)?;
    let round1 = round1_from_others(&group, id, p.members)?;
    let mut received = BTreeMap::new();
    for other in (1..=p.members).filter(|&o| o != id) {
        let bytes = read_hex(&exchange(&group).join(format!("round2-{other}-to-{id}.hex")))
            .map_err(|_| format!("member {other} has not sent round 2 yet"))?;
        received.insert(identifier(other)?, round2::Package::deserialize(&bytes)?);
    }
    let (key_package, public_package) = dkg::part3(&secret2, &round1, &received)?;
    fs::remove_file(mine.join("round2-secret.hex"))?;
    let share = key_package.signing_share().serialize();
    let key_bytes: [u8; 48] = public_package
        .verifying_key()
        .serialize()?
        .try_into()
        .map_err(|_| "group key length")?;
    let key = Option::<G1Affine>::from(G1Affine::from_compressed(&key_bytes))
        .ok_or("group key not on G1")?;
    let public_key = tezos::encode_public_key(&key);
    let address = tezos::tz4_address(&key);
    let file = KeyFile {
        id,
        threshold: p.threshold,
        members: p.members,
        share: hex::encode(share),
        group_public_key: public_key.clone(),
        address: address.clone(),
    };
    fs::write(mine.join("key.json"), serde_json::to_string_pretty(&file)?)?;
    let public = PublicFile {
        id,
        group_public_key: public_key,
        address: address.clone(),
    };
    fs::write(
        exchange(&group).join(format!("public-{id}.json")),
        serde_json::to_string_pretty(&public)?,
    )?;
    println!("member {id}: key share kept, group address {address}");
    Ok(())
}

fn load_key(group: &Path, id: u16) -> Res<(KeyFile, Scalar)> {
    let file: KeyFile =
        serde_json::from_str(&fs::read_to_string(private(group, id).join("key.json"))?)?;
    let bytes: [u8; 32] = hex::decode(&file.share)?
        .try_into()
        .map_err(|_| "share length")?;
    let share = Option::from(Scalar::from_bytes(&bytes)).ok_or("share is not canonical")?;
    Ok((file, share))
}

/// Every member that finished must report the same group key.
fn coord_group(args: &[String]) -> Res<PublicFile> {
    let group = group_dir(args)?;
    let mut seen: Option<PublicFile> = None;
    let mut count = 0;
    for entry in fs::read_dir(exchange(&group))? {
        let path = entry?.path();
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if !(name.starts_with("public-") && name.ends_with(".json")) {
            continue;
        }
        let p: PublicFile = serde_json::from_str(&fs::read_to_string(&path)?)?;
        if let Some(s) = &seen {
            if s.group_public_key != p.group_public_key {
                return Err(format!("member {} reports another group key", p.id).into());
            }
        }
        count += 1;
        seen = Some(p);
    }
    let p = seen.ok_or("no member has finished the DKG")?;
    println!(
        "{count} members agree: {} ({})",
        p.address, p.group_public_key
    );
    Ok(p)
}

#[derive(Serialize, Deserialize)]
struct Request {
    group_public_key: String,
    address: String,
    branch: String,
    protocol: String,
    contents: Value,
    forged: String,
}

fn shares_in(dir: &Path, prefix: &str) -> Res<Vec<(u16, G2Projective)>> {
    let mut shares = Vec::new();
    for entry in fs::read_dir(dir)? {
        let path = entry?.path();
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_string();
        if let Some(id) = name
            .strip_prefix(prefix)
            .and_then(|r| r.strip_suffix(".txt"))
        {
            let sig = tezos::decode_signature(fs::read_to_string(&path)?.trim())?;
            shares.push((id.parse()?, G2Projective::from(sig)));
        }
    }
    shares.sort_by_key(|(id, _)| *id);
    Ok(shares)
}

fn pop(args: &[String]) -> Res<()> {
    let group = group_dir(args)?;
    let id = id_arg(args)?;
    let (file, share) = load_key(&group, id)?;
    let key = tezos::decode_public_key(&file.group_public_key)?;
    let s = G2Affine::from(bls::pop_share(&share, &key));
    fs::write(
        exchange(&group).join(format!("pop-share-{id}.txt")),
        tezos::encode_signature(&s),
    )?;
    println!("member {id}: proof-of-possession share published");
    Ok(())
}

fn tez_to_mutez(tez: &str) -> Res<u64> {
    let (whole, frac) = tez.split_once('.').unwrap_or((tez, ""));
    if frac.len() > 6 {
        return Err("at most 6 decimals".into());
    }
    Ok(whole.parse::<u64>()? * 1_000_000 + format!("{frac:0<6}").parse::<u64>()?)
}

fn prepare(args: &[String]) -> Res<()> {
    let group = group_dir(args)?;
    let public = coord_group(args)?;
    let rpc = Rpc::new(required(args, "--rpc")?);
    let to = required(args, "--to")?;
    let amount = tez_to_mutez(required(args, "--amount")?)?;
    let key = tezos::decode_public_key(&public.group_public_key)?;

    let (branch, protocol) = rpc.head()?;
    let mut counter = rpc.counter(&public.address)?;
    let mut contents = Vec::new();
    if !rpc.is_revealed(&public.address)? {
        let shares = shares_in(&exchange(&group), "pop-share-")?;
        let proof = bls::combine(&shares)
            .filter(|p| bls::verify(&key, &key.to_compressed(), DST_POP, p))
            .ok_or("the account is not revealed yet: run `member pop` on enough members first")?;
        let proof = tezos::encode_signature(&proof);
        if !rpc.check_proof(&public.group_public_key, &proof)? {
            return Err("the node rejects the combined proof".into());
        }
        println!(
            "proof of possession combined from members {:?}, accepted by the node",
            shares.iter().map(|s| s.0).collect::<Vec<_>>()
        );
        counter += 1;
        contents.push(json!({
            "kind": "reveal", "source": public.address, "fee": "5000",
            "counter": counter.to_string(), "gas_limit": "20000", "storage_limit": "0",
            "public_key": public.group_public_key, "proof": proof
        }));
    }
    counter += 1;
    contents.push(json!({
        "kind": "transaction", "source": public.address, "fee": "5000",
        "counter": counter.to_string(), "gas_limit": "20000", "storage_limit": "300",
        "amount": amount.to_string(), "destination": to
    }));
    let contents = Value::Array(contents);
    let forged = rpc.forge(&branch, &contents)?;
    let request = Request {
        group_public_key: public.group_public_key,
        address: public.address,
        branch,
        protocol,
        contents,
        forged: hex::encode(forged),
    };
    fs::write(
        exchange(&group).join("request.json"),
        serde_json::to_string_pretty(&request)?,
    )?;
    for entry in fs::read_dir(exchange(&group))? {
        let path = entry?.path();
        if path
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.starts_with("sig-share-"))
        {
            fs::remove_file(path)?;
        }
    }
    println!("request written: {amount} mutez to {to}");
    Ok(())
}

fn sign(args: &[String]) -> Res<()> {
    let group = group_dir(args)?;
    let id = id_arg(args)?;
    let (file, share) = load_key(&group, id)?;
    let request: Request =
        serde_json::from_str(&fs::read_to_string(exchange(&group).join("request.json"))?)?;
    if request.group_public_key != file.group_public_key {
        return Err("the request is for another group".into());
    }
    println!("member {id} is asked to sign:");
    for c in request.contents.as_array().ok_or("no contents")? {
        match c["kind"].as_str() {
            Some("transaction") => println!(
                "  send {} mutez to {} (fee {})",
                c["amount"], c["destination"], c["fee"]
            ),
            Some("reveal") => println!("  reveal the group key (fee {})", c["fee"]),
            other => {
                return Err(format!(
                    "refused: an operation of kind {other:?} this member does not know"
                )
                .into())
            }
        }
        if c["source"].as_str() != Some(file.address.as_str()) {
            return Err("refused: an operation spends from another account".into());
        }
    }
    let forged = hex::decode(&request.forged)?;
    // The coordinator's bytes must be the encoding of what was shown. Here a
    // second node re-forges them; a later version decodes them locally.
    match option(args, "--rpc") {
        Some(url) => {
            let again = Rpc::new(url).forge(&request.branch, &request.contents)?;
            if again != forged {
                return Err("refused: the bytes to sign do not encode the operation shown".into());
            }
            println!("  bytes checked against an independent forge");
        }
        None => println!("  WARNING: bytes not checked (pass --rpc to re-forge them)"),
    }
    let mut message = vec![WATERMARK_GENERIC_OPERATION];
    message.extend_from_slice(&forged);
    let s = G2Affine::from(bls::sign_share(&share, &message, DST_SIG));
    fs::write(
        exchange(&group).join(format!("sig-share-{id}.txt")),
        tezos::encode_signature(&s),
    )?;
    println!("member {id}: signature share published");
    Ok(())
}

fn submit(args: &[String]) -> Res<()> {
    let group = group_dir(args)?;
    let rpc = Rpc::new(required(args, "--rpc")?);
    let request: Request =
        serde_json::from_str(&fs::read_to_string(exchange(&group).join("request.json"))?)?;
    let key = tezos::decode_public_key(&request.group_public_key)?;
    let forged = hex::decode(&request.forged)?;
    let mut message = vec![WATERMARK_GENERIC_OPERATION];
    message.extend_from_slice(&forged);
    let shares = shares_in(&exchange(&group), "sig-share-")?;
    let ids: Vec<u16> = shares.iter().map(|s| s.0).collect();
    let signature = bls::combine(&shares)
        .filter(|s| bls::verify(&key, &message, DST_SIG, s))
        .ok_or_else(|| format!("the shares of members {ids:?} do not make a valid signature"))?;
    let encoded = tezos::encode_signature(&signature);
    println!("signature combined from members {ids:?}");
    let applied = rpc.preapply(
        &request.protocol,
        &request.branch,
        &request.contents,
        &encoded,
    )?;
    for (i, c) in applied[0]["contents"]
        .as_array()
        .ok_or("no preapply contents")?
        .iter()
        .enumerate()
    {
        let r = &c["metadata"]["operation_result"];
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
    let sig = signature.to_compressed();
    let mut signed = forged;
    signed.extend_from_slice(&[0xff, 0x03]);
    signed.extend_from_slice(&sig[..32]);
    signed.extend_from_slice(&sig[32..]);
    println!("  injected {}", rpc.inject(&signed)?);
    Ok(())
}
