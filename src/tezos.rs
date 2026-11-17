//! Tezos encodings for tz4 keys and a small RPC client.
//!
//! Prefixes are octez's (`src/lib_crypto/base58.ml`): tz4 `\006\161\166`,
//! BLpk `\006\149\135\204`, BLsig `\040\171\064\207`.

use std::error::Error;

use blake2::digest::{Update, VariableOutput};
use blake2::Blake2bVar;
use bls12_381::{G1Affine, G2Affine};
use serde_json::{json, Value};

const TZ4: [u8; 3] = [6, 161, 166];
const BLPK: [u8; 4] = [6, 149, 135, 204];
const BLSIG: [u8; 4] = [40, 171, 64, 207];

fn b58check(prefix: &[u8], payload: &[u8]) -> String {
    let mut bytes = prefix.to_vec();
    bytes.extend_from_slice(payload);
    bs58::encode(bytes).with_check().into_string()
}

fn b58check_decode(prefix: &[u8], text: &str, len: usize) -> Result<Vec<u8>, Box<dyn Error>> {
    let bytes = bs58::decode(text).with_check(None).into_vec()?;
    if bytes.len() != prefix.len() + len || &bytes[..prefix.len()] != prefix {
        return Err(format!("{text} has the wrong prefix or length").into());
    }
    Ok(bytes[prefix.len()..].to_vec())
}

/// The tz4 address of a BLS public key: Blake2b-160 of its compressed bytes.
pub fn tz4_address(public_key: &G1Affine) -> String {
    let mut hasher = Blake2bVar::new(20).expect("20 is a valid Blake2b length");
    hasher.update(&public_key.to_compressed());
    let mut hash = [0u8; 20];
    hasher
        .finalize_variable(&mut hash)
        .expect("the buffer is 20 bytes");
    b58check(&TZ4, &hash)
}

pub fn encode_public_key(public_key: &G1Affine) -> String {
    b58check(&BLPK, &public_key.to_compressed())
}

pub fn decode_public_key(text: &str) -> Result<G1Affine, Box<dyn Error>> {
    let bytes: [u8; 48] = b58check_decode(&BLPK, text, 48)?
        .try_into()
        .map_err(|_| "length")?;
    Option::from(G1Affine::from_compressed(&bytes)).ok_or_else(|| "not a G1 point".into())
}

pub fn encode_signature(signature: &G2Affine) -> String {
    b58check(&BLSIG, &signature.to_compressed())
}

pub fn decode_signature(text: &str) -> Result<G2Affine, Box<dyn Error>> {
    let bytes: [u8; 96] = b58check_decode(&BLSIG, text, 96)?
        .try_into()
        .map_err(|_| "length")?;
    Option::from(G2Affine::from_compressed(&bytes)).ok_or_else(|| "not a G2 point".into())
}

/// A Tezos node's RPC.
pub struct Rpc {
    base: String,
}

impl Rpc {
    pub fn new(base: &str) -> Self {
        Rpc {
            base: base.trim_end_matches('/').to_string(),
        }
    }

    pub fn get(&self, path: &str) -> Result<Value, Box<dyn Error>> {
        let response = ureq::get(&format!("{}{path}", self.base)).call();
        Self::body(path, response)
    }

    pub fn post(&self, path: &str, body: &Value) -> Result<Value, Box<dyn Error>> {
        let response = ureq::post(&format!("{}{path}", self.base)).send_json(body.clone());
        Self::body(path, response)
    }

    fn body(
        path: &str,
        response: Result<ureq::Response, ureq::Error>,
    ) -> Result<Value, Box<dyn Error>> {
        match response {
            Ok(r) => Ok(r.into_json()?),
            Err(ureq::Error::Status(code, r)) => {
                let text = r.into_string().unwrap_or_default();
                Err(format!("{path}: HTTP {code}: {text}").into())
            }
            Err(e) => Err(format!("{path}: {e}").into()),
        }
    }

    pub fn head(&self) -> Result<(String, String), Box<dyn Error>> {
        let header = self.get("/chains/main/blocks/head/header")?;
        let hash = header["hash"].as_str().ok_or("no head hash")?.to_string();
        let protocol = header["protocol"]
            .as_str()
            .ok_or("no protocol")?
            .to_string();
        Ok((hash, protocol))
    }

    fn contract(&self, address: &str, field: &str) -> Result<Value, Box<dyn Error>> {
        self.get(&format!(
            "/chains/main/blocks/head/context/contracts/{address}/{field}"
        ))
    }

    pub fn balance(&self, address: &str) -> Result<u64, Box<dyn Error>> {
        Ok(self
            .contract(address, "balance")?
            .as_str()
            .ok_or("no balance")?
            .parse()?)
    }

    pub fn counter(&self, address: &str) -> Result<u64, Box<dyn Error>> {
        Ok(self
            .contract(address, "counter")?
            .as_str()
            .ok_or("no counter")?
            .parse()?)
    }

    pub fn is_revealed(&self, address: &str) -> Result<bool, Box<dyn Error>> {
        Ok(!self.contract(address, "manager_key")?.is_null())
    }

    /// The node's encoding of the operation, as bytes. The co-signers decode
    /// it before signing; nothing here trusts it blindly.
    pub fn forge(&self, branch: &str, contents: &Value) -> Result<Vec<u8>, Box<dyn Error>> {
        let body = json!({ "branch": branch, "contents": contents });
        let hex = self.post("/chains/main/blocks/head/helpers/forge/operations", &body)?;
        Ok(hex::decode(
            hex.as_str().ok_or("forge did not return hex")?,
        )?)
    }

    pub fn preapply(
        &self,
        protocol: &str,
        branch: &str,
        contents: &Value,
        signature: &str,
    ) -> Result<Value, Box<dyn Error>> {
        let body = json!([{ "protocol": protocol, "branch": branch, "contents": contents, "signature": signature }]);
        self.post(
            "/chains/main/blocks/head/helpers/preapply/operations",
            &body,
        )
    }

    pub fn inject(&self, signed: &[u8]) -> Result<String, Box<dyn Error>> {
        let hash = self.post("/injection/operation", &Value::String(hex::encode(signed)))?;
        Ok(hash.as_str().ok_or("no operation hash")?.to_string())
    }

    /// Asks the node to check a proof of possession (octez `/bls/check_proof`).
    pub fn check_proof(&self, public_key: &str, proof: &str) -> Result<bool, Box<dyn Error>> {
        let answer = self.post(
            "/bls/check_proof",
            &json!({ "public_key": public_key, "proof": proof }),
        )?;
        Ok(answer.as_bool().unwrap_or(false))
    }

    /// Asks the node to combine signature shares (octez `/bls/threshold_signatures`).
    pub fn threshold_signatures(
        &self,
        public_key: &str,
        message: &[u8],
        shares: &[(u16, String)],
    ) -> Result<Value, Box<dyn Error>> {
        let shares: Vec<Value> = shares
            .iter()
            .map(|(id, s)| json!({ "id": id, "signature": s }))
            .collect();
        let body = json!({ "public_key": public_key, "message": hex::encode(message), "signature_shares": shares });
        self.post("/bls/threshold_signatures", &body)
    }
}
