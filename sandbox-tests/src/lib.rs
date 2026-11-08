//! Helpers for the M9 sandbox tests (`tests/sandbox.rs`).
//!
//! Every test starts its own local NEAR sandbox and deploys three real wasm files:
//! - `policy_vault.wasm`: the vault contract (`contract/`), initialised with the mock signer;
//! - `mock_signer.wasm`: a stand-in for Chain Signatures (`mock-signer/`), since the MPC network
//!   does not exist in a sandbox;
//! - `test_receiver.wasm`: the `nft_transfer_call` receiver used for the H1 attack (`test-receiver/`).
//!
//! The wasm files are read from `$WASM_DIR` (default: `sandbox-tests/wasm/`); `build-wasm.sh`
//! builds the three and copies them there.

use anyhow::{anyhow, bail, Context, Result};
use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use near_workspaces::network::Sandbox;
use near_workspaces::result::ExecutionFinalResult;
use near_workspaces::types::{Gas, NearToken};
use near_workspaces::{Account, Contract, Worker};
use serde_json::{json, Value};
use sha3::{Digest, Keccak256};
use std::time::Duration;

pub const SEPOLIA: u64 = 11_155_111;
/// The only destination the test policies allow.
pub const DEST: &str = "0x2222222222222222222222222222222222222222";
pub const GWEI: u128 = 1_000_000_000;

pub struct Env {
    pub worker: Worker<Sandbox>,
    pub vault: Contract,
    pub signer: Contract,
    pub receiver: Contract,
    pub alice: Account,
    pub bob: Account,
    pub guardian: Account,
    pub stranger: Account,
}

pub fn wasm(name: &str) -> Result<Vec<u8>> {
    let dir = std::env::var("WASM_DIR")
        .unwrap_or_else(|_| format!("{}/wasm", env!("CARGO_MANIFEST_DIR")));
    let path = format!("{dir}/{name}.wasm");
    std::fs::read(&path).with_context(|| format!("missing {path}; run sandbox-tests/build-wasm.sh first"))
}

/// A fresh sandbox with the three contracts and four funded accounts.
pub async fn setup() -> Result<Env> {
    setup_with_vault_wasm(&wasm("policy_vault")?).await
}

/// Same as `setup`, with a given build of the vault contract (the migration rehearsal deploys the
/// previous build first).
pub async fn setup_with_vault_wasm(vault_wasm: &[u8]) -> Result<Env> {
    let worker = near_workspaces::sandbox().await?;
    let root = worker.root_account()?;
    let signer = deploy(&root, "signer", "mock_signer").await?;
    let vault_account = root
        .create_subaccount("vault")
        .initial_balance(NearToken::from_near(30))
        .transact()
        .await?
        .into_result()?;
    let vault = vault_account.deploy(vault_wasm).await?.into_result()?;
    vault
        .call("new")
        .args_json(json!({ "signer_id": signer.id() }))
        .transact()
        .await?
        .into_result()?;
    let receiver = deploy(&root, "receiver", "test_receiver").await?;
    let mut people = Vec::new();
    for name in ["alice", "bob", "guardian", "stranger"] {
        people.push(
            root.create_subaccount(name)
                .initial_balance(NearToken::from_near(50))
                .transact()
                .await?
                .into_result()?,
        );
    }
    let stranger = people.pop().unwrap();
    let guardian = people.pop().unwrap();
    let bob = people.pop().unwrap();
    let alice = people.pop().unwrap();
    Ok(Env { worker, vault, signer, receiver, alice, bob, guardian, stranger })
}

async fn deploy(root: &Account, name: &str, wasm_name: &str) -> Result<Contract> {
    let account = root
        .create_subaccount(name)
        .initial_balance(NearToken::from_near(30))
        .transact()
        .await?
        .into_result()?;
    Ok(account.deploy(&wasm(wasm_name)?).await?.into_result()?)
}

// ---------- calls and views ----------

pub async fn call(
    who: &Account,
    contract: &Contract,
    method: &str,
    args: Value,
    deposit: NearToken,
    tgas: u64,
) -> Result<ExecutionFinalResult> {
    Ok(who
        .call(contract.id(), method)
        .args_json(args)
        .deposit(deposit)
        .gas(Gas::from_tgas(tgas))
        .transact()
        .await?)
}

pub async fn view(contract: &Contract, method: &str, args: Value) -> Result<Value> {
    Ok(contract.view(method).args_json(args).await?.json()?)
}

pub fn yocto(n: u128) -> NearToken {
    NearToken::from_yoctonear(n)
}

pub fn millinear(n: u128) -> NearToken {
    NearToken::from_millinear(n)
}

/// The call failed and its error mentions `expected`.
pub fn assert_refused(r: &ExecutionFinalResult, expected: &str) {
    let text = format!("{r:?}");
    assert!(r.is_failure(), "expected a failure with {expected:?}, but it succeeded: {:?}", r.logs());
    assert!(text.contains(expected), "expected {expected:?} in the failure, got: {text}");
}

/// The call (and every receipt it created) succeeded.
pub fn assert_ok(r: &ExecutionFinalResult) {
    assert!(r.is_success(), "call failed: {r:?}");
    assert!(r.receipt_failures().is_empty(), "a receipt failed: {:?}", r.receipt_failures());
}

/// NEP-297 events with this name in the logs of a call.
pub fn events(r: &ExecutionFinalResult, name: &str) -> Vec<Value> {
    r.logs()
        .iter()
        .filter_map(|l| l.strip_prefix("EVENT_JSON:"))
        .filter_map(|j| serde_json::from_str::<Value>(j).ok())
        .filter(|e| e["event"] == name)
        .map(|e| e["data"][0].clone())
        .collect()
}

// ---------- vault steps ----------

pub async fn mint(e: &Env, who: &Account) -> Result<String> {
    let r = call(who, &e.vault, "mint_vault", json!({}), millinear(100), 100).await?;
    assert_ok(&r);
    let token: Value = r.json()?;
    Ok(token["token_id"].as_str().ok_or_else(|| anyhow!("no token_id"))?.to_string())
}

/// A Sepolia policy that allows ETH to `DEST` (0.01 ETH a day, up to 50 gwei x 21000 of gas).
pub fn policy(delay_ms: u64, guardian: Option<&Account>) -> Value {
    json!({
        "chain_id": SEPOLIA,
        "delay_ms": delay_ms,
        "guardian": guardian.map(|g| g.id().to_string()),
        "eth_daily_cap": "10000000000000000",
        "max_gas_cost": (21_000 * 50 * GWEI).to_string(),
        "allowed_destinations": [DEST],
        "allowed_spenders": [],
        "tokens": []
    })
}

pub async fn set_policy(e: &Env, who: &Account, token: &str, policy: Value) -> Result<ExecutionFinalResult> {
    call(who, &e.vault, "set_policy", json!({ "token_id": token, "policy": policy }), millinear(50), 100).await
}

/// Sends `value` wei to `DEST` with a 30 gwei fee cap.
pub fn eth_tx(value: u128) -> Value {
    json!({
        "chain_id": SEPOLIA,
        "max_priority_fee_per_gas": GWEI.to_string(),
        "max_fee_per_gas": (30 * GWEI).to_string(),
        "gas_limit": 21000,
        "to": DEST,
        "value": value.to_string(),
        "data": "0x"
    })
}

pub async fn propose(e: &Env, who: &Account, token: &str, value: u128) -> Result<u64> {
    let r = call(who, &e.vault, "propose", json!({ "token_id": token, "tx": eth_tx(value) }), millinear(50), 100).await?;
    assert_ok(&r);
    Ok(r.json()?)
}

pub async fn execute(e: &Env, who: &Account, token: &str, proposal_id: u64) -> Result<ExecutionFinalResult> {
    call(who, &e.vault, "execute_proposal", json!({ "token_id": token, "proposal_id": proposal_id }), millinear(20), 300).await
}

pub async fn start_sale(e: &Env, who: &Account, token: &str, price: Option<NearToken>, buyer: Option<&Account>) -> Result<ExecutionFinalResult> {
    call(
        who,
        &e.vault,
        "start_sale",
        json!({
            "token_id": token,
            "price": price.map(|p| p.as_yoctonear().to_string()),
            "buyer": buyer.map(|b| b.id().to_string()),
        }),
        millinear(10),
        50,
    )
    .await
}

pub async fn set_signer_mode(e: &Env, mode: &str) -> Result<()> {
    let r = call(&e.stranger, &e.signer, "set_mode", json!({ "mode": mode }), yocto(0), 10).await?;
    assert_ok(&r);
    Ok(())
}

pub async fn owner_of(e: &Env, token: &str) -> Result<String> {
    let t = view(&e.vault, "nft_token", json!({ "token_id": token })).await?;
    Ok(t["owner_id"].as_str().unwrap_or_default().to_string())
}

pub async fn balance(a: &Account) -> Result<u128> {
    Ok(a.view_account().await?.balance.as_yoctonear())
}

// ---------- time ----------

pub async fn now_ms(worker: &Worker<Sandbox>) -> Result<u64> {
    Ok(worker.view_block().await?.timestamp() / 1_000_000)
}

/// Moves the sandbox clock forward by at least `ms` with `fast_forward` (it produces blocks
/// without waiting for them), so tests do not sleep through the 10-minute sale delay.
pub async fn advance_ms(worker: &Worker<Sandbox>, ms: u64) -> Result<()> {
    let target = now_ms(worker).await? + ms;
    let mut step: u64 = 50;
    for _ in 0..30 {
        let before = now_ms(worker).await?;
        if before >= target {
            return Ok(());
        }
        worker.fast_forward(step).await?;
        let after = now_ms(worker).await?;
        let per_block = ((after.saturating_sub(before)) / step).max(1);
        step = ((target.saturating_sub(after)) / per_block + 5).clamp(5, 200_000);
    }
    bail!("the sandbox clock did not reach the target")
}

/// Polls `check` every 200 ms until it returns true, at most `secs` seconds.
pub async fn wait_until<F, Fut>(secs: u64, mut check: F) -> Result<()>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<bool>>,
{
    for _ in 0..(secs * 5) {
        if check().await? {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    bail!("condition not met after {secs} s")
}

// ---------- Ethereum checks, independent of the contract ----------

pub fn keccak(data: &[u8]) -> [u8; 32] {
    Keccak256::digest(data).into()
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn unhex(s: &str) -> Result<Vec<u8>> {
    let s = s.trim_start_matches("0x");
    if s.len() % 2 != 0 {
        bail!("odd hex length");
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| anyhow!(e)))
        .collect()
}

/// EVM address of a `secp256k1:<base58 of 64 bytes>` key, as the contract publishes it.
pub fn address_of_key(key: &str) -> Result<String> {
    let b58 = key.strip_prefix("secp256k1:").ok_or_else(|| anyhow!("not a secp256k1 key"))?;
    let raw = base58_decode(b58)?;
    if raw.len() != 64 {
        bail!("key is {} bytes", raw.len());
    }
    Ok(format!("0x{}", hex(&keccak(&raw)[12..])))
}

fn base58_decode(s: &str) -> Result<Vec<u8>> {
    const ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let mut out: Vec<u8> = Vec::new();
    for c in s.bytes() {
        let mut carry = ALPHABET.iter().position(|&a| a == c).ok_or_else(|| anyhow!("bad base58"))? as u32;
        for b in out.iter_mut().rev() {
            carry += (*b as u32) * 58;
            *b = (carry & 0xff) as u8;
            carry >>= 8;
        }
        while carry > 0 {
            out.insert(0, (carry & 0xff) as u8);
            carry >>= 8;
        }
    }
    let zeros = s.bytes().take_while(|&c| c == b'1').count();
    let mut v = vec![0u8; zeros];
    v.extend(out);
    Ok(v)
}

#[derive(Debug, Clone)]
pub enum Rlp {
    Bytes(Vec<u8>),
    List(Vec<Rlp>),
}

impl Rlp {
    pub fn bytes(&self) -> &[u8] {
        match self {
            Rlp::Bytes(b) => b,
            Rlp::List(_) => &[],
        }
    }
    pub fn uint(&self) -> u128 {
        self.bytes().iter().fold(0u128, |acc, b| (acc << 8) | *b as u128)
    }
}

fn rlp_decode_one(data: &[u8]) -> Result<(Rlp, usize)> {
    let p = *data.first().ok_or_else(|| anyhow!("empty rlp"))?;
    let read_len = |n: usize| -> Result<usize> {
        let bytes = data.get(1..1 + n).ok_or_else(|| anyhow!("short rlp"))?;
        Ok(bytes.iter().fold(0usize, |a, b| (a << 8) | *b as usize))
    };
    let (is_list, off, len) = match p {
        0x00..=0x7f => return Ok((Rlp::Bytes(vec![p]), 1)),
        0x80..=0xb7 => (false, 1, (p - 0x80) as usize),
        0xb8..=0xbf => {
            let n = (p - 0xb7) as usize;
            (false, 1 + n, read_len(n)?)
        }
        0xc0..=0xf7 => (true, 1, (p - 0xc0) as usize),
        _ => {
            let n = (p - 0xf7) as usize;
            (true, 1 + n, read_len(n)?)
        }
    };
    let body = data.get(off..off + len).ok_or_else(|| anyhow!("short rlp body"))?;
    if !is_list {
        return Ok((Rlp::Bytes(body.to_vec()), off + len));
    }
    let mut items = Vec::new();
    let mut i = 0;
    while i < body.len() {
        let (item, used) = rlp_decode_one(&body[i..])?;
        items.push(item);
        i += used;
    }
    Ok((Rlp::List(items), off + len))
}

fn rlp_encode(item: &Rlp) -> Vec<u8> {
    fn header(short: u8, len: usize) -> Vec<u8> {
        if len <= 55 {
            vec![short + len as u8]
        } else {
            let be: Vec<u8> = len.to_be_bytes().iter().copied().skip_while(|b| *b == 0).collect();
            let mut h = vec![short + 55 + be.len() as u8];
            h.extend(be);
            h
        }
    }
    match item {
        Rlp::Bytes(b) if b.len() == 1 && b[0] < 0x80 => b.clone(),
        Rlp::Bytes(b) => [header(0x80, b.len()), b.clone()].concat(),
        Rlp::List(items) => {
            let body: Vec<u8> = items.iter().flat_map(rlp_encode).collect();
            [header(0xc0, body.len()), body].concat()
        }
    }
}

/// An EIP-1559 transaction read back from the raw bytes the contract stored.
#[derive(Debug)]
pub struct DecodedTx {
    pub chain_id: u128,
    pub nonce: u128,
    pub to: String,
    pub value: u128,
    /// keccak256(0x02 || rlp(unsigned fields)), recomputed here.
    pub signing_hash: [u8; 32],
    /// Address recovered with k256 (not with NEAR's ecrecover, which the contract used).
    pub from: String,
}

/// Decodes `0x02 || rlp([chain_id, nonce, tip, fee_cap, gas, to, value, data, access_list,
/// y_parity, r, s])`, recomputes the signing hash and recovers the sender.
pub fn decode_signed_tx(raw_hex: &str) -> Result<DecodedTx> {
    let raw = unhex(raw_hex)?;
    if raw.first() != Some(&0x02) {
        bail!("not an EIP-1559 transaction");
    }
    let (Rlp::List(items), used) = rlp_decode_one(&raw[1..])? else { bail!("not a list") };
    if used != raw.len() - 1 || items.len() != 12 {
        bail!("unexpected transaction layout");
    }
    let unsigned = [vec![0x02], rlp_encode(&Rlp::List(items[..9].to_vec()))].concat();
    let signing_hash = keccak(&unsigned);
    let pad = |b: &[u8]| -> [u8; 32] {
        let mut out = [0u8; 32];
        out[32 - b.len()..].copy_from_slice(b);
        out
    };
    let sig = Signature::from_scalars(pad(items[10].bytes()), pad(items[11].bytes()))
        .map_err(|e| anyhow!("bad signature scalars: {e}"))?;
    let recid = RecoveryId::from_byte(items[9].uint() as u8).ok_or_else(|| anyhow!("bad y_parity"))?;
    let key = VerifyingKey::recover_from_prehash(&signing_hash, &sig, recid)
        .map_err(|e| anyhow!("signature does not recover: {e}"))?;
    let point = key.to_encoded_point(false);
    Ok(DecodedTx {
        chain_id: items[0].uint(),
        nonce: items[1].uint(),
        to: format!("0x{}", hex(items[5].bytes())),
        value: items[6].uint(),
        signing_hash,
        from: format!("0x{}", hex(&keccak(&point.as_bytes()[1..])[12..])),
    })
}

/// Checks a stored signed record without trusting the contract: the raw transaction decodes,
/// its hash matches, its signature recovers to the vault address, and its fields are as expected.
pub fn check_signed_record(rec: &Value, vault_address: &str, to: &str, value: u128, nonce: u64) -> Result<()> {
    let raw = rec["signed_tx"].as_str().ok_or_else(|| anyhow!("no signed_tx in {rec}"))?;
    let tx = decode_signed_tx(raw)?;
    assert_eq!(format!("0x{}", hex(&keccak(&unhex(raw)?))), rec["tx_hash"].as_str().unwrap(), "tx_hash");
    assert_eq!(format!("0x{}", hex(&tx.signing_hash)), rec["signing_hash"].as_str().unwrap(), "signing_hash");
    assert_eq!(tx.from, vault_address, "the signature must recover to the vault address");
    assert_eq!(tx.chain_id, SEPOLIA as u128);
    assert_eq!(tx.nonce, nonce as u128);
    assert_eq!(tx.to, to.to_lowercase());
    assert_eq!(tx.value, value);
    Ok(())
}

/// The value a call returned (its last receipt), without consuming the result.
pub fn returned<T: serde::de::DeserializeOwned>(r: &ExecutionFinalResult) -> Result<T> {
    Ok(r.clone().json()?)
}
