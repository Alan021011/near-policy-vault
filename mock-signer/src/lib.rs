//! Test helper, not part of the product (M9): a stand-in for the NEAR Chain Signatures contract
//! (`v1.signer-prod.testnet`) inside the local sandbox, where the MPC network does not exist.
//!
//! It answers the two calls the vault contract makes, with the same argument and answer shapes:
//! - `derived_public_key(path, predecessor, domain_id)` -> `"secp256k1:<base58 of 64 bytes>"`
//! - `sign({ domain_id, path, payload_v2: { Ecdsa: "<64 hex>" } })`
//!   -> `{ "big_r": { "affine_point": "02…" }, "s": { "scalar": "…" }, "recovery_id": 0 }`
//!
//! Keys: the secret key of `(predecessor, path)` is sha256("mock-signer:" + predecessor + "," +
//! path). It is public on purpose: these keys only exist in a throwaway local sandbox.
//!
//! `set_mode` chooses how `sign` answers, to exercise every path of the vault's callback:
//! - "sign" (default): a valid signature, at once.
//! - "hold": like the real MPC network, `sign` yields (`promise_yield_create`) and the answer
//!   arrives later, when anyone calls `release`. If nobody does, the yield times out after about
//!   200 blocks and the request fails, as with the real network.
//! - "wrong_key": a valid signature by another key (the vault must reject it and undo).
//! - "garbage": an answer that is not a signature (the vault must treat it as uncertain).
//! - "fail": the call fails (the vault must treat it as uncertain).

use k256::ecdsa::SigningKey;
use near_sdk::serde::{Deserialize, Serialize};
use near_sdk::serde_json::{self, json};
use near_sdk::{env, near, require, AccountId, CryptoHash, Gas, GasWeight, NearToken};

/// Gas for `on_respond`, the callback that hands a held answer back to the caller.
const GAS_FOR_RESPOND: Gas = Gas::from_tgas(10);
const DATA_ID_REGISTER: u64 = 0;

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(crate = "near_sdk::serde")]
pub enum SignPayload {
    Ecdsa(String),
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(crate = "near_sdk::serde")]
pub struct SignRequest {
    pub domain_id: u64,
    pub path: String,
    pub payload_v2: SignPayload,
}

#[near(serializers = [borsh])]
#[derive(Clone)]
pub struct Held {
    data_id: Vec<u8>,
    answer: String,
}

#[near(contract_state)]
pub struct MockSigner {
    mode: String,
    held: Vec<Held>,
    sign_calls: u64,
}

impl Default for MockSigner {
    fn default() -> Self {
        Self { mode: "sign".into(), held: Vec::new(), sign_calls: 0 }
    }
}

#[near]
impl MockSigner {
    /// Test switch; see the module docs.
    pub fn set_mode(&mut self, mode: String) {
        require!(
            ["sign", "hold", "wrong_key", "garbage", "fail"].contains(&mode.as_str()),
            "unknown mode"
        );
        self.mode = mode;
    }

    pub fn get_mode(&self) -> String {
        self.mode.clone()
    }

    /// Number of `sign` requests received, and how many are held waiting for `release`.
    pub fn stats(&self) -> (u64, u32) {
        (self.sign_calls, self.held.len() as u32)
    }

    /// Same shape as the real contract's view.
    pub fn derived_public_key(
        &self,
        path: String,
        predecessor: Option<AccountId>,
        domain_id: Option<u64>,
    ) -> String {
        require!(domain_id.unwrap_or(0) == 0, "mock signer: only domain 0 (secp256k1)");
        let predecessor = predecessor.unwrap_or_else(env::predecessor_account_id);
        let key = secret_key(&predecessor, &path);
        let point = key.verifying_key().to_encoded_point(false);
        format!("secp256k1:{}", bs58::encode(&point.as_bytes()[1..]).into_string())
    }

    /// Same shape as the real contract's `sign`, which also requires a deposit.
    #[payable]
    pub fn sign(&mut self, request: SignRequest) {
        require!(env::attached_deposit() >= NearToken::from_yoctonear(1), "mock signer: attach a deposit");
        require!(request.domain_id == 0, "mock signer: only domain 0 (secp256k1)");
        self.sign_calls += 1;
        let SignPayload::Ecdsa(hex) = &request.payload_v2;
        let hash: [u8; 32] = parse_hex32(hex).unwrap_or_else(|| env::panic_str("mock signer: payload is not 32 bytes of hex"));
        let caller = env::predecessor_account_id();
        let answer = match self.mode.as_str() {
            "fail" => env::panic_str("mock signer: forced failure"),
            "garbage" => "\"not a signature\"".to_string(),
            "wrong_key" => sign_hash(&secret_key(&caller, &format!("{}-wrong", request.path)), &hash),
            _ => sign_hash(&secret_key(&caller, &request.path), &hash),
        };
        if self.mode == "hold" {
            let index = env::promise_yield_create("on_respond", b"{}", GAS_FOR_RESPOND, GasWeight(0), DATA_ID_REGISTER);
            let data_id = env::read_register(DATA_ID_REGISTER).expect("yield id written by promise_yield_create");
            self.held.push(Held { data_id, answer });
            env::promise_return(index);
        } else {
            env::value_return(answer.as_bytes());
        }
    }

    /// Delivers the oldest held answer (mode "hold"), like the MPC network's `respond`.
    pub fn release(&mut self) -> bool {
        require!(!self.held.is_empty(), "mock signer: nothing held");
        let held = self.held.remove(0);
        let data_id: CryptoHash = held.data_id.try_into().expect("32-byte yield id");
        env::promise_yield_resume(&data_id, held.answer.as_bytes())
    }

    /// Resumed with the answer, or failed if the yield timed out (no `release` in time).
    #[private]
    pub fn on_respond(&mut self) {
        match env::promise_result_checked(0, 4096) {
            Ok(answer) => env::value_return(&answer),
            Err(_) => {
                // The yield timed out: forget it, as the real contract does, and fail the request.
                env::panic_str("mock signer: the signature request timed out")
            }
        }
    }
}

/// sha256("mock-signer:" + predecessor + "," + path), re-hashed in the (astronomically unlikely)
/// case it is not a valid secret key.
fn secret_key(predecessor: &AccountId, path: &str) -> SigningKey {
    let mut seed = env::sha256(format!("mock-signer:{predecessor},{path}").as_bytes());
    loop {
        if let Ok(k) = SigningKey::from_slice(&seed) {
            return k;
        }
        seed = env::sha256(&seed);
    }
}

/// Signs a 32-byte hash and answers in the MPC network's JSON format.
fn sign_hash(key: &SigningKey, hash: &[u8; 32]) -> String {
    let (sig, recid) = key.sign_prehash_recoverable(hash).unwrap_or_else(|_| env::panic_str("mock signer: signing failed"));
    let prefix = if recid.is_y_odd() { "03" } else { "02" };
    let r = hex(&sig.r().to_bytes());
    let s = hex(&sig.s().to_bytes());
    serde_json::to_string(&json!({
        "big_r": { "affine_point": format!("{prefix}{r}").to_uppercase() },
        "s": { "scalar": s.to_uppercase() },
        "recovery_id": recid.to_byte() & 1,
    }))
    .expect("json")
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn parse_hex32(s: &str) -> Option<[u8; 32]> {
    let s = s.trim_start_matches("0x");
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
        out[i] = u8::from_str_radix(std::str::from_utf8(chunk).ok()?, 16).ok()?;
    }
    Some(out)
}
