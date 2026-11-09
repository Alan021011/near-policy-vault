//! near-policy-vault: an NFT that owns an EVM account guarded by a spending policy.
//!
//! Module M3 (this file): a NEP-171 collection where every token is a vault.
//! - Anyone can mint a vault for themselves and pays the storage it uses, plus a fixed
//!   reserve for its transfer record (so transfers never consume the contract's balance).
//! - Token ids are sequential ("0", "1", ...). Each vault's EVM account is derived by
//!   NEAR Chain Signatures from this contract's account id and the path `vault-<token_id>`.
//! - INVARIANT: a token id is never reused. There is no burn. If burning is ever added,
//!   ids must still never be reissued, or two owners would share one EVM account.
//! - Transfers, approvals and enumeration come from `near-contract-standards`, but every
//!   entry point goes through a wrapper here so later modules can add the sale freeze and
//!   the "signature in flight" lock (threats 1 and 5 in docs/THREAT_MODEL.md).
//! - Review fixes (vault note "18 Revisión de M3"):
//!   R1: the library's `nft_transfer` event omits `authorized_id` when an approved account
//!       transfers; this contract keeps its own transfer record and emits a complete event.
//!   R4: the library keeps the storage deposit of cleared approvals; this contract refunds
//!       it to the owner who paid it.
//!
//!
//! Module M4: the contract learns each vault's EVM account from the signer itself.
//! - At mint, the contract calls `derived_public_key(path, predecessor = this contract,
//!   domain_id = 0)` on the Chain Signatures contract (`signer_id`, fixed at init) and, in a
//!   private callback, checks the answer (prefix, base58, 64 bytes) and stores the key and
//!   `keccak256(key)[12..]` as the vault's EVM address. Nobody has to trust an off-chain
//!   script to know where a vault's funds live: `vault_info` returns it.
//! - If that call fails (for example out of gas), the vault stays "unresolved" and anyone can
//!   retry with `resolve_vault_address`. A resolved address is never overwritten.
//!
//! Later modules, each in its own section below: M5 spending policy (`policy.rs`), M6 proposal
//! queue, M7 signing through the MPC network (`on_signed`), M8 two-phase sale (`start_sale`,
//! `buy`), and the general review after M8 (H1: no owner action while a `transfer_call` is
//! unresolved). The threats they address are in docs/THREAT_MODEL.md.

pub mod evm;
pub mod policy;

use std::collections::HashMap;

use near_contract_standards::non_fungible_token::approval::NonFungibleTokenApproval;
use near_contract_standards::non_fungible_token::core::{
    ext_nft_receiver, ext_nft_resolver, NonFungibleTokenCore, NonFungibleTokenResolver,
};
use near_contract_standards::non_fungible_token::enumeration::NonFungibleTokenEnumeration;
use near_contract_standards::non_fungible_token::events::NftMint;
use near_contract_standards::non_fungible_token::metadata::{
    NFTContractMetadata, NonFungibleTokenMetadataProvider, TokenMetadata, NFT_METADATA_SPEC,
};
use near_contract_standards::non_fungible_token::refund_approved_account_ids;
use near_contract_standards::non_fungible_token::{NonFungibleToken, Token, TokenId};
use near_sdk::collections::{LazyOption, LookupMap};
use near_sdk::json_types::U128;
use near_sdk::serde_json::json;
use near_sdk::{
    assert_one_yocto, env, ext_contract, near, require, AccountId, BorshStorageKey, Gas,
    NearToken, PanicOnDefault, Promise, PromiseError, PromiseOrValue,
};

use crate::evm::{keccak256, Eip1559Tx};
use crate::policy::{Policy, Reservation, SpendState};

/// Prefix of the Chain Signatures derivation path of every vault.
pub const VAULT_PATH_PREFIX: &str = "vault-";

/// Chain Signatures domain of secp256k1 (the curve used by Ethereum).
pub const SECP256K1_DOMAIN_ID: u64 = 0;

/// Gas for the signer's `derived_public_key` view and for our callback.
pub const GAS_FOR_DERIVE: Gas = Gas::from_tgas(15);
pub const GAS_FOR_DERIVE_CALLBACK: Gas = Gas::from_tgas(10);

/// The part of the Chain Signatures contract this contract uses (M4: keys, M7: signatures).
#[ext_contract(ext_signer)]
#[allow(dead_code)]
trait ChainSignatures {
    fn derived_public_key(
        &self,
        path: String,
        predecessor: Option<AccountId>,
        domain_id: Option<u64>,
    ) -> String;
    fn sign(&mut self, request: SignRequest) -> SignResponse;
}

// ---------- M7: signing ----------

/// Default deposit attached to the signer's `sign` (measured in A1: 1 yoctoNEAR is accepted).
/// The caller can attach a different one (review S4).
pub const SIGN_DEPOSIT: NearToken = NearToken::from_yoctonear(1);
/// Gas kept for our callback (measured: 2.76 Tgas used); all the remaining gas goes to `sign`.
pub const GAS_FOR_SIGN_CALLBACK: Gas = Gas::from_tgas(20);
/// Least prepaid gas to start a signature (measured: about 14 Tgas in total; review S7). Raised
/// from 60 to 100 Tgas after review M12 (R12-12): a signer call that runs out of gas makes the
/// outcome uncertain, which wastes a nonce and the charge.
pub const MIN_PREPAID_GAS_FOR_SIGNING: Gas = Gas::from_tgas(100);
/// Storage paid at execution for the signed record written later by the callback.
pub const SIGNED_RECORD_RESERVE_BYTES: u64 = 1200;
/// After this long without an answer the owner may abandon a signature (review S2). Far above
/// the MPC network's own timeout (about 200 blocks).
pub const INFLIGHT_TIMEOUT_MS: u64 = 3_600_000;
/// Longest signer answer read by the callback.
pub const MAX_SIGN_RESPONSE_LEN: usize = 4096;
/// `proposal_id` stored in the history for a cancellation (it has no proposal).
pub const CANCEL_PROPOSAL_ID: u64 = u64::MAX;

#[near(serializers = [json])]
#[derive(Clone, Debug, PartialEq)]
pub enum SignPayload {
    /// 32-byte hash as 64 hex characters, no `0x`.
    Ecdsa(String),
}

#[near(serializers = [json])]
#[derive(Clone, Debug, PartialEq)]
pub struct SignRequest {
    pub domain_id: u64,
    pub path: String,
    pub payload_v2: SignPayload,
}

#[near(serializers = [json])]
#[derive(Clone, Debug, PartialEq)]
pub struct AffinePoint {
    /// Compressed point: 02/03 || x, as hex.
    pub affine_point: String,
}

#[near(serializers = [json])]
#[derive(Clone, Debug, PartialEq)]
pub struct Scalar {
    pub scalar: String,
}

/// What the signer returns, e.g. `{"big_r":{"affine_point":"02…"},"s":{"scalar":"…"},"recovery_id":1}`.
#[near(serializers = [json])]
#[derive(Clone, Debug, PartialEq)]
pub struct SignResponse {
    pub big_r: AffinePoint,
    pub s: Scalar,
    pub recovery_id: u8,
}

/// A signature the contract has asked for and not received yet. While it exists the vault
/// cannot sign again and the NFT cannot be transferred (threat 5).
#[near(serializers = [borsh, json])]
#[derive(Clone, Debug, PartialEq)]
pub struct InFlight {
    /// The proposal being signed, or `None` for a cancellation.
    pub proposal: Option<Proposal>,
    pub tx: ProposalTx,
    pub nonce: u64,
    /// `true` if `nonce` was the vault's next nonce (it was advanced); `false` when an earlier
    /// nonce is being signed again (a pinned retry, a replacement or a cancellation).
    pub from_next: bool,
    pub signing_hash: String,
    pub charge: Reservation,
    /// Whether `charge` was actually added to the caps (an identical retry is not charged twice).
    pub charged: bool,
    /// Who paid the storage reserve (refunded if no record is written).
    pub payer: AccountId,
    pub started_ms: u64,
}

/// A nonce for which a signature may exist without the contract knowing it (review S1/S3): the
/// signer failed, answered something unreadable, or the owner abandoned the wait. The nonce is
/// never given to a different transaction automatically; it is filled by re-signing the same
/// proposal (pinned to it), a replacement or a cancellation.
#[near(serializers = [borsh, json])]
#[derive(Clone, Debug, PartialEq)]
pub struct UncertainNonce {
    pub nonce: u64,
    pub signing_hash: String,
    pub since_ms: u64,
}

/// A transaction the MPC network signed for a vault, ready to broadcast by anyone.
#[near(serializers = [borsh, json])]
#[derive(Clone, Debug, PartialEq)]
pub struct SignedRecord {
    pub token_id: TokenId,
    pub proposal_id: u64,
    pub nonce: u64,
    /// The EIP-1559 hash that was signed.
    pub signing_hash: String,
    /// `0x02…`, the raw transaction for `eth_sendRawTransaction`.
    pub signed_tx: String,
    /// keccak256 of the raw transaction: the hash explorers show.
    pub tx_hash: String,
    /// Owner of the vault when it was requested.
    pub owner: AccountId,
    pub signed_ms: u64,
}

/// The only `verify_signature` error that proves the answer cannot move the vault's funds.
pub const WRONG_KEY: &str = "signature does not match the vault key";

/// Checks the signer's answer against the vault's own key and returns `(y_parity, r, s)` with
/// `s` normalized to the lower half (EIP-2). The contract never trusts the MPC answer blindly.
pub fn verify_signature(
    resp: &SignResponse,
    hash: &[u8; 32],
    vault_key: &[u8; 64],
) -> Result<(u8, [u8; 32], [u8; 32]), &'static str> {
    let big_r = policy::parse_hex(&format!("0x{}", resp.big_r.affine_point)).ok_or("big_r is not hex")?;
    if big_r.len() != 33 || (big_r[0] != 2 && big_r[0] != 3) {
        return Err("big_r is not a compressed point");
    }
    let mut r = [0u8; 32];
    r.copy_from_slice(&big_r[1..]);
    let s: [u8; 32] = policy::parse_hex(&format!("0x{}", resp.s.scalar))
        .and_then(|v| v.try_into().ok())
        .ok_or("s is not 32 bytes of hex")?;
    if resp.recovery_id > 1 {
        return Err("recovery_id must be 0 or 1");
    }
    let mut sig = [0u8; 64];
    sig[..32].copy_from_slice(&r);
    sig[32..].copy_from_slice(&s);
    let recovered = env::ecrecover(hash, &sig, resp.recovery_id, false).ok_or("ecrecover failed")?;
    if &recovered != vault_key {
        return Err(WRONG_KEY);
    }
    let (s_low, parity) = evm::normalize_s(&s, resp.recovery_id);
    Ok((parity, r, s_low))
}

/// Storage reserved at mint for the largest possible transfer record of a token
/// (two 64-char account ids, an optional third one, a kind label, two u64 and trie overhead).
pub const TRANSFER_RECORD_RESERVE_BYTES: u64 = 400;

#[near(serializers = [borsh])]
#[derive(BorshStorageKey)]
enum StorageKey {
    OwnerById,
    TokenMetadata,
    Enumeration,
    Approval,
    ContractMetadata,
    TransferInfo,
    Vaults,
    Policies,
    Nonces,
    InFlight,
    Signed,
    SignedVersions,
    Uncertain,
    Pinned,
    VaultChain,
    Sales,
    TransferCalls,
}

/// Fixed-size record (same storage whether resolved or not, so it is paid in full at mint).
#[near(serializers = [borsh])]
#[derive(Clone, Debug, PartialEq)]
pub struct VaultRecord {
    pub resolved: bool,
    /// Uncompressed secp256k1 key without the 0x04 prefix: X (32 bytes) || Y (32 bytes).
    pub public_key: [u8; 64],
    pub evm_address: [u8; 20],
}

impl VaultRecord {
    fn unresolved() -> Self {
        Self { resolved: false, public_key: [0; 64], evm_address: [0; 20] }
    }
}

/// What anyone can read about a vault.
#[near(serializers = [json])]
#[derive(Clone, Debug, PartialEq)]
pub struct VaultInfo {
    pub token_id: TokenId,
    pub path: String,
    /// Chain Signatures contract that derives and signs for this vault.
    pub signer_id: AccountId,
    /// `None` until the signer's answer has been stored.
    pub public_key: Option<String>,
    /// Lowercase `0x…` address, the same on every EVM chain. `None` until resolved.
    pub evm_address: Option<String>,
}

/// Parses the signer's answer: "secp256k1:<base58 of 64 bytes>".
pub fn parse_secp256k1_key(s: &str) -> Option<[u8; 64]> {
    let b58 = s.strip_prefix("secp256k1:")?;
    let bytes = bs58::decode(b58).into_vec().ok()?;
    bytes.try_into().ok()
}

/// Ethereum address of an uncompressed public key: last 20 bytes of keccak256(X || Y).
pub fn evm_address_of(public_key: &[u8; 64]) -> [u8; 20] {
    let h = keccak256(public_key);
    let mut a = [0u8; 20];
    a.copy_from_slice(&h[12..]);
    a
}

fn hex0x(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(2 + bytes.len() * 2);
    s.push_str("0x");
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// The last ownership change of a vault, kept on-chain. The full history is in the
/// `vault_transfer` events (standard `policy_vault`), which, unlike the library's
/// `nft_transfer` event, always include `authorized_id`.
#[near(serializers = [borsh, json])]
#[derive(Clone, Debug, PartialEq)]
pub struct TransferRecord {
    /// "transfer", "transfer_call" or "transfer_call_returned".
    pub kind: String,
    pub from: AccountId,
    pub to: AccountId,
    /// Account that moved the token when it was not the owner (an approved account).
    pub authorized_id: Option<AccountId>,
    pub block_height: u64,
    pub timestamp_ms: u64,
}

#[near(serializers = [borsh, json])]
#[derive(Clone, Debug, Default, PartialEq)]
pub struct TransferInfo {
    /// Number of ownership changes since mint (a returned transfer_call counts twice).
    pub count: u64,
    pub last: Option<TransferRecord>,
}

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct PolicyVault {
    tokens: NonFungibleToken,
    metadata: LazyOption<NFTContractMetadata>,
    next_token_id: u64,
    transfer_info: LookupMap<TokenId, TransferInfo>,
    signer_id: AccountId,
    vaults: LookupMap<TokenId, VaultRecord>,
    policies: LookupMap<TokenId, VaultPolicyState>,
    /// M6: next EVM nonce of each vault's account. Never reset on a sale: it belongs to the
    /// external account, not to the owner. Absent means 0.
    nonces: LookupMap<TokenId, u64>,
    /// M6: proposal ids are unique across all vaults and owners.
    next_proposal_id: u64,
    /// M7: the signature each vault is waiting for, if any.
    inflight: LookupMap<TokenId, InFlight>,
    /// M7: signed transactions. The first version of a nonce is at "<token_id>:<nonce>", later
    /// versions (re-signatures of the same nonce) at "<token_id>:<nonce>#<v>".
    signed: LookupMap<String, SignedRecord>,
    /// M7 review S5: how many versions a nonce has (absent = 1 when a first version exists).
    signed_versions: LookupMap<String, u32>,
    /// M7 review S1/S3: nonces whose signature outcome is unknown, per vault.
    uncertain: LookupMap<TokenId, Vec<UncertainNonce>>,
    /// M7 review S3: proposal id -> the nonce it must be signed with (a retry after an uncertain
    /// outcome produces the identical transaction, so it can never be paid twice).
    pinned: LookupMap<u64, u64>,
    /// General review G2: the EVM chain a vault has signed for. Its nonce counter belongs to that
    /// chain, so the policy can never move to another one. Survives a sale. Vaults that signed
    /// before this field existed get their chain from their signed history.
    vault_chain: LookupMap<TokenId, u64>,
    /// M8: the sale window of each vault, if one was started. No transfer happens without one.
    sales: LookupMap<TokenId, Sale>,
    /// M8 review V1: sale numbers are unique, so a buyer can bind a transfer to the audited sale.
    next_sale_id: u64,
    /// General review H1: vaults sent with `nft_transfer_call` whose transfer has not resolved
    /// yet, with the time it started. Meanwhile the receiver cannot act as owner.
    transfer_calls: LookupMap<TokenId, u64>,
}

/// State layout deployed for the M8 review fixes (commit 7b1a136), used only by `migrate`. Its
/// sale records had no price or buyer; migrating is only safe when no vault has a sale record
/// (checked before deploying).
#[near(serializers = [borsh])]
struct PolicyVaultV10 {
    tokens: NonFungibleToken,
    metadata: LazyOption<NFTContractMetadata>,
    next_token_id: u64,
    transfer_info: LookupMap<TokenId, TransferInfo>,
    signer_id: AccountId,
    vaults: LookupMap<TokenId, VaultRecord>,
    policies: LookupMap<TokenId, VaultPolicyState>,
    nonces: LookupMap<TokenId, u64>,
    next_proposal_id: u64,
    inflight: LookupMap<TokenId, InFlight>,
    signed: LookupMap<String, SignedRecord>,
    signed_versions: LookupMap<String, u32>,
    uncertain: LookupMap<TokenId, Vec<UncertainNonce>>,
    pinned: LookupMap<u64, u64>,
    vault_chain: LookupMap<TokenId, u64>,
    sales: LookupMap<TokenId, Sale>,
    next_sale_id: u64,
}

/// State layout deployed for M8 (commit b539799), kept for reference.
#[allow(dead_code)]
#[near(serializers = [borsh])]
struct PolicyVaultV9 {
    tokens: NonFungibleToken,
    metadata: LazyOption<NFTContractMetadata>,
    next_token_id: u64,
    transfer_info: LookupMap<TokenId, TransferInfo>,
    signer_id: AccountId,
    vaults: LookupMap<TokenId, VaultRecord>,
    policies: LookupMap<TokenId, VaultPolicyState>,
    nonces: LookupMap<TokenId, u64>,
    next_proposal_id: u64,
    inflight: LookupMap<TokenId, InFlight>,
    signed: LookupMap<String, SignedRecord>,
    signed_versions: LookupMap<String, u32>,
    uncertain: LookupMap<TokenId, Vec<UncertainNonce>>,
    pinned: LookupMap<u64, u64>,
    vault_chain: LookupMap<TokenId, u64>,
    sales: LookupMap<TokenId, Sale>,
}

/// State layout deployed for the general-review fixes (commit 22a48bb), kept for reference.
#[allow(dead_code)]
#[near(serializers = [borsh])]
struct PolicyVaultV8 {
    tokens: NonFungibleToken,
    metadata: LazyOption<NFTContractMetadata>,
    next_token_id: u64,
    transfer_info: LookupMap<TokenId, TransferInfo>,
    signer_id: AccountId,
    vaults: LookupMap<TokenId, VaultRecord>,
    policies: LookupMap<TokenId, VaultPolicyState>,
    nonces: LookupMap<TokenId, u64>,
    next_proposal_id: u64,
    inflight: LookupMap<TokenId, InFlight>,
    signed: LookupMap<String, SignedRecord>,
    signed_versions: LookupMap<String, u32>,
    uncertain: LookupMap<TokenId, Vec<UncertainNonce>>,
    pinned: LookupMap<u64, u64>,
    vault_chain: LookupMap<TokenId, u64>,
}

// ---------- M8: two-phase sale ----------

/// How long a sale window stays open once it opens. After that a new sale must be started, so
/// an old sale never leaves the vault transferable for good.
pub const SALE_WINDOW_MS: u64 = 86_400_000;

/// Shortest wait before any sale opens, also for a vault without policy (M8 review V3): if the
/// owner's key leaks, the owner, who still holds it, has this long to cancel the thief's sale.
pub const MIN_SALE_DELAY_MS: u64 = 600_000;

/// Gas kept for `nft_resolve_transfer` (the library keeps 5 Tgas; this contract does more work
/// there: it records the return, refunds storage and releases the transfer_call lock).
pub const GAS_FOR_RESOLVE_TRANSFER: Gas = Gas::from_tgas(20);
/// Least prepaid gas for `nft_transfer_call`, so the resolution always has its gas.
pub const MIN_PREPAID_GAS_FOR_TRANSFER_CALL: Gas = Gas::from_tgas(50);
/// If a transfer_call never resolves (its callback ran out of gas), the lock lapses after this.
/// A resolution cannot be delayed this long: a receipt chain ends within minutes.
pub const TRANSFER_CALL_TIMEOUT_MS: u64 = 3_600_000;

/// A sale window. While it is active (not closed) the vault cannot sign new transactions (only
/// cancellations), so its state is stable for the buyer's audit. Transfers are only possible
/// between `opens_at_ms` and `closes_at_ms`, and the guardian can veto it at any time (threat 16).
#[near(serializers = [borsh, json])]
#[derive(Clone, Debug, PartialEq)]
pub struct Sale {
    /// Unique sale number. A transfer whose `memo` is `sale:<sale_id>` only succeeds during this
    /// very sale (M8 review V1): a buyer or escrow binds the payment to the sale it audited.
    pub sale_id: u64,
    pub started_ms: u64,
    /// Start + max(policy delay, `MIN_SALE_DELAY_MS`).
    pub opens_at_ms: u64,
    pub closes_at_ms: u64,
    /// Owner epoch when it was started; a sale never carries over to a later owner.
    pub owner_epoch: u64,
    /// Price in yoctoNEAR for `buy` (general review H3). `None`: the seller transfers it.
    pub price: Option<U128>,
    /// If set, only this account can `buy`.
    pub buyer: Option<AccountId>,
}

/// State layout deployed for the M7 review fixes (commit a00bed7), kept for reference.
#[allow(dead_code)]
#[near(serializers = [borsh])]
struct PolicyVaultV7 {
    tokens: NonFungibleToken,
    metadata: LazyOption<NFTContractMetadata>,
    next_token_id: u64,
    transfer_info: LookupMap<TokenId, TransferInfo>,
    signer_id: AccountId,
    vaults: LookupMap<TokenId, VaultRecord>,
    policies: LookupMap<TokenId, VaultPolicyState>,
    nonces: LookupMap<TokenId, u64>,
    next_proposal_id: u64,
    inflight: LookupMap<TokenId, InFlight>,
    signed: LookupMap<String, SignedRecord>,
    signed_versions: LookupMap<String, u32>,
    uncertain: LookupMap<TokenId, Vec<UncertainNonce>>,
    pinned: LookupMap<u64, u64>,
}

fn signed_key(token_id: &str, nonce: u64) -> String {
    format!("{token_id}:{nonce}")
}

fn signed_version_key(token_id: &str, nonce: u64, version: u32) -> String {
    if version == 0 {
        signed_key(token_id, nonce)
    } else {
        format!("{token_id}:{nonce}#{version}")
    }
}

// ---------- M5: policy state, inputs and views ----------

/// A loosening policy change waiting for the current delay to pass (the guardian can veto it).
#[near(serializers = [borsh, json])]
#[derive(Clone, Debug, PartialEq)]
pub struct PendingPolicy {
    pub policy: Policy,
    pub apply_after_ms: u64,
}

/// Policy layout before agent mode and NFTs (kept to migrate stored state).
#[near(serializers = [borsh])]
#[derive(Clone)]
pub struct PolicyV1 {
    pub chain_id: u64,
    pub delay_ms: u64,
    pub guardian: Option<AccountId>,
    pub eth_daily_cap: U128,
    pub max_gas_cost: U128,
    pub allowed_destinations: Vec<String>,
    pub allowed_spenders: Vec<String>,
    pub tokens: Vec<policy::TokenRule>,
}

impl From<PolicyV1> for Policy {
    fn from(o: PolicyV1) -> Self {
        Policy {
            chain_id: o.chain_id,
            delay_ms: o.delay_ms,
            guardian: o.guardian,
            eth_daily_cap: o.eth_daily_cap,
            max_gas_cost: o.max_gas_cost,
            allowed_destinations: o.allowed_destinations,
            allowed_spenders: o.allowed_spenders,
            tokens: o.tokens,
            proposer: None,
            nfts: Vec::new(),
        }
    }
}

#[near(serializers = [borsh])]
pub struct PendingPolicyV1 {
    pub policy: PolicyV1,
    pub apply_after_ms: u64,
}

#[near(serializers = [borsh])]
pub struct VaultPolicyStateV1 {
    pub policy: PolicyV1,
    pub pending: Option<PendingPolicyV1>,
    pub spend: SpendState,
    pub proposals: Vec<Proposal>,
}

impl From<VaultPolicyStateV1> for VaultPolicyState {
    fn from(o: VaultPolicyStateV1) -> Self {
        VaultPolicyState {
            policy: o.policy.into(),
            pending: o.pending.map(|p| PendingPolicy { policy: p.policy.into(), apply_after_ms: p.apply_after_ms }),
            spend: o.spend,
            proposals: o.proposals,
        }
    }
}

/// Everything the contract stores about a vault's policy. Removed on every change of owner.
#[near(serializers = [borsh])]
#[derive(Clone, Debug, PartialEq)]
pub struct VaultPolicyState {
    pub policy: Policy,
    pub pending: Option<PendingPolicy>,
    pub spend: SpendState,
    /// M6: queued transactions, oldest first. Lives here so a change of owner clears it too.
    pub proposals: Vec<Proposal>,
}

// ---------- M6: proposals ----------

/// Most proposals a vault may have queued at once.
pub const MAX_QUEUED_PROPOSALS: usize = 8;

/// A transaction as proposed: everything but the nonce, which is assigned when it is signed so
/// that cancelled proposals never leave gaps in the external account's nonces.
#[near(serializers = [borsh, json])]
#[derive(Clone, Debug, PartialEq)]
pub struct ProposalTx {
    pub chain_id: u64,
    pub max_priority_fee_per_gas: U128,
    pub max_fee_per_gas: U128,
    pub gas_limit: u64,
    pub to: String,
    pub value: U128,
    pub data: String,
}

impl ProposalTx {
    pub fn to_tx(&self, nonce: u64) -> Result<Eip1559Tx, String> {
        TxInput {
            chain_id: self.chain_id,
            nonce,
            max_priority_fee_per_gas: self.max_priority_fee_per_gas,
            max_fee_per_gas: self.max_fee_per_gas,
            gas_limit: self.gas_limit,
            to: self.to.clone(),
            value: self.value,
            data: self.data.clone(),
        }
        .to_tx()
    }
}

#[near(serializers = [borsh, json])]
#[derive(Clone, Debug, PartialEq)]
pub struct Proposal {
    pub id: u64,
    /// Ownership changes of the vault when it was proposed (`vault_transfer_info.count`).
    pub owner_epoch: u64,
    pub tx: ProposalTx,
    /// What it holds from the daily caps until it is cancelled, vetoed or signed.
    pub reservation: Reservation,
    pub created_ms: u64,
    pub executable_after_ms: u64,
}

/// Whether a queued proposal could be signed now, and exactly what would be signed.
#[near(serializers = [json])]
#[derive(Clone, Debug, PartialEq)]
pub struct ExecutionCheck {
    pub ready: bool,
    pub reason: Option<String>,
    /// The nonce it would get (the vault's next nonce).
    pub nonce: u64,
    pub signing_hash: Option<String>,
}

#[near(serializers = [json])]
#[derive(Clone, Debug, PartialEq)]
pub struct PolicyView {
    pub token_id: TokenId,
    /// `false` means the vault is locked: nothing can be signed.
    pub has_policy: bool,
    pub policy: Policy,
    pub pending: Option<PendingPolicy>,
    pub spend: SpendState,
}

/// An EIP-1559 transaction as JSON. Large numbers are decimal strings (`U128`).
#[near(serializers = [json])]
#[derive(Clone, Debug, PartialEq)]
pub struct TxInput {
    pub chain_id: u64,
    pub nonce: u64,
    pub max_priority_fee_per_gas: U128,
    pub max_fee_per_gas: U128,
    pub gas_limit: u64,
    /// `0x` + 40 hex characters.
    pub to: String,
    pub value: U128,
    /// `0x` + hex calldata (empty `0x` for a plain transfer).
    pub data: String,
}

/// Longest calldata accepted: ERC-20 `transfer`/`approve` are exactly 68 bytes.
/// Longest calldata the contract signs: an ERC-1155 `safeTransferFrom` with empty data.
pub const MAX_CALLDATA_LEN: usize = 196;

impl TxInput {
    pub fn to_tx(&self) -> Result<Eip1559Tx, String> {
        let to = policy::parse_address(&self.to).ok_or("malformed `to` address")?;
        let data = policy::parse_hex(&self.data).ok_or("malformed `data` hex")?;
        if data.len() > MAX_CALLDATA_LEN {
            return Err("calldata longer than 196 bytes".into());
        }
        Ok(Eip1559Tx {
            chain_id: self.chain_id,
            nonce: self.nonce,
            max_priority_fee_per_gas: self.max_priority_fee_per_gas.0,
            max_fee_per_gas: self.max_fee_per_gas.0,
            gas_limit: self.gas_limit,
            to,
            value: self.value.0,
            data,
        })
    }
}

#[near(serializers = [json])]
#[derive(Clone, Debug, PartialEq)]
pub struct CheckResult {
    pub allowed: bool,
    /// Why the transaction would be refused (`None` when allowed).
    pub reason: Option<String>,
    /// The EIP-1559 hash the contract would ask the network to sign (`None` if unparsable).
    pub signing_hash: Option<String>,
    /// What it would reserve from the daily caps (`None` when refused).
    pub reservation: Option<Reservation>,
}

#[near]
impl PolicyVault {
    /// `signer_id`: the Chain Signatures contract (`v1.signer-prod.testnet` on testnet,
    /// `v1.signer` on mainnet). It cannot be changed afterwards without a code upgrade.
    #[init]
    pub fn new(signer_id: AccountId) -> Self {
        let metadata = NFTContractMetadata {
            spec: NFT_METADATA_SPEC.to_string(),
            name: "NEAR Policy Vault".to_string(),
            symbol: "PVAULT".to_string(),
            icon: None,
            base_uri: None,
            reference: None,
            reference_hash: None,
        };
        Self {
            tokens: NonFungibleToken::new(
                StorageKey::OwnerById,
                env::current_account_id(),
                Some(StorageKey::TokenMetadata),
                Some(StorageKey::Enumeration),
                Some(StorageKey::Approval),
            ),
            metadata: LazyOption::new(StorageKey::ContractMetadata, Some(&metadata)),
            next_token_id: 0,
            transfer_info: LookupMap::new(StorageKey::TransferInfo),
            signer_id,
            vaults: LookupMap::new(StorageKey::Vaults),
            policies: LookupMap::new(StorageKey::Policies),
            nonces: LookupMap::new(StorageKey::Nonces),
            next_proposal_id: 0,
            inflight: LookupMap::new(StorageKey::InFlight),
            signed: LookupMap::new(StorageKey::Signed),
            signed_versions: LookupMap::new(StorageKey::SignedVersions),
            uncertain: LookupMap::new(StorageKey::Uncertain),
            pinned: LookupMap::new(StorageKey::Pinned),
            vault_chain: LookupMap::new(StorageKey::VaultChain),
            sales: LookupMap::new(StorageKey::Sales),
            next_sale_id: 0,
            transfer_calls: LookupMap::new(StorageKey::TransferCalls),
        }
    }

    /// Upgrades the state written by the M8 review deployment. Only the contract account can
    /// call it. Calling it on the current layout fails, because the old layout no longer parses.
    #[private]
    #[init(ignore_state)]
    pub fn migrate() -> Self {
        let old: PolicyVaultV10 = env::state_read().expect("no V10 state to migrate");
        Self {
            tokens: old.tokens,
            metadata: old.metadata,
            next_token_id: old.next_token_id,
            transfer_info: old.transfer_info,
            signer_id: old.signer_id,
            vaults: old.vaults,
            policies: old.policies,
            nonces: old.nonces,
            next_proposal_id: old.next_proposal_id,
            inflight: old.inflight,
            signed: old.signed,
            signed_versions: old.signed_versions,
            uncertain: old.uncertain,
            pinned: old.pinned,
            vault_chain: old.vault_chain,
            sales: old.sales,
            next_sale_id: old.next_sale_id,
            transfer_calls: LookupMap::new(StorageKey::TransferCalls),
        }
    }

    /// Converts stored policies written before agent mode and NFTs (two new Policy fields) to the
    /// current layout, for token ids in [from, from + limit). Only the contract account can call
    /// it. Idempotent: entries already in the current layout are left alone. Returns how many
    /// entries it converted.
    #[private]
    pub fn migrate_policies(&mut self, from: u64, limit: u64) -> u64 {
        use near_sdk::borsh::BorshDeserialize;
        use near_sdk::IntoStorageKey;
        let prefix = StorageKey::Policies.into_storage_key();
        let end = self.next_token_id.min(from.saturating_add(limit));
        let mut converted = 0;
        for id in from..end {
            let mut key = prefix.clone();
            key.extend(near_sdk::borsh::to_vec(&id.to_string()).expect("borsh"));
            let Some(raw) = env::storage_read(&key) else { continue };
            if VaultPolicyState::try_from_slice(&raw).is_ok() {
                continue;
            }
            let old = VaultPolicyStateV1::try_from_slice(&raw)
                .unwrap_or_else(|_| env::panic_str(&format!("policy of token {id} is in neither layout")));
            env::storage_write(&key, &near_sdk::borsh::to_vec(&VaultPolicyState::from(old)).expect("borsh"));
            converted += 1;
        }
        converted
    }

    /// Opens a sale window (M8). Only the owner, with a deposit that covers its storage. The
    /// window opens after max(policy delay, `MIN_SALE_DELAY_MS`), stays open `SALE_WINDOW_MS`,
    /// and the guardian can veto it at any time. While the sale is active the vault cannot sign
    /// new transactions, only cancellations (`cancel_nonce`), so the buyer can audit a stable
    /// state. Not allowed while a signature is in flight. A sale whose window has closed is
    /// replaced (M8 review V2).
    /// - `price` (yoctoNEAR, above 0): anyone, or only `buyer` if given, can then `buy` the vault
    ///   at that price during the window (general review H3). Without a price the seller transfers
    ///   it (`nft_transfer`, ideally bound with `memo: "sale:<id>"`).
    #[payable]
    pub fn start_sale(&mut self, token_id: TokenId, price: Option<U128>, buyer: Option<AccountId>) -> Sale {
        require!(
            env::attached_deposit() >= NearToken::from_yoctonear(1),
            "Requires attached deposit of at least 1 yoctoNEAR"
        );
        let owner = self.assert_owner(&token_id);
        require!(self.active_sale(&token_id).is_none(), "A sale is already active; cancel it first");
        require!(
            self.inflight.get(&token_id).is_none(),
            "A signature is in flight for this vault; start the sale after it completes"
        );
        require!(price.map_or(true, |p| p.0 > 0), "The price must be above 0");
        require!(buyer.is_none() || price.is_some(), "A reserved buyer needs a price");
        require!(buyer.as_ref() != Some(&owner), "The owner cannot be the buyer");
        let now = env::block_timestamp_ms();
        let delay = self.policies.get(&token_id).map(|s| s.policy.delay_ms).unwrap_or(0);
        let opens_at_ms = now.saturating_add(delay.max(MIN_SALE_DELAY_MS));
        let sale = Sale {
            sale_id: self.next_sale_id,
            started_ms: now,
            opens_at_ms,
            closes_at_ms: opens_at_ms.saturating_add(SALE_WINDOW_MS),
            owner_epoch: self.owner_epoch(&token_id),
            price,
            buyer,
        };
        self.next_sale_id += 1;
        let before = env::storage_usage();
        self.sales.insert(&token_id, &sale); // replaces a closed one, if any
        settle_storage(before, &owner);
        emit_policy_event(
            "sale_started",
            &token_id,
            json!({
                "sale_id": sale.sale_id,
                "opens_at_ms": sale.opens_at_ms,
                "closes_at_ms": sale.closes_at_ms,
                "price": sale.price,
                "buyer": sale.buyer,
            }),
        );
        sale
    }

    /// Buys a vault on sale at its price (general review H3). The caller attaches at least the
    /// price (the rest is refunded) and names the `sale_id` it audited: if the seller cancelled
    /// and restarted the sale meanwhile, the purchase fails and the deposit goes back. In one
    /// step the NFT goes to the buyer, the seller's policy and sale end, and the price goes to the
    /// seller. The buyer still runs the audit first (`scripts/sale-audit.mjs`): the contract
    /// cannot read Ethereum.
    #[payable]
    pub fn buy(&mut self, token_id: TokenId, sale_id: u64) {
        let buyer = env::predecessor_account_id();
        let memo = format!("sale:{sale_id}");
        // Same rules as any transfer: open window of this owner, that very sale, no signature in
        // flight, no unresolved transfer_call.
        self.assert_transferable(&token_id, Some(&memo));
        let sale = self.sales.get(&token_id).expect("checked by assert_transferable");
        let price = sale
            .price
            .unwrap_or_else(|| env::panic_str("This sale has no price; the seller transfers the vault"))
            .0;
        if let Some(reserved) = &sale.buyer {
            require!(reserved == &buyer, "This sale is reserved for another buyer");
        }
        let seller = self.owner_of(&token_id);
        require!(buyer != seller, "The owner cannot buy their own vault");
        let attached = env::attached_deposit();
        require!(
            attached.as_yoctonear() >= price,
            format!("Attach the price: {}", NearToken::from_yoctonear(price).exact_amount_display())
        );
        let (old_owner, cleared) = self.tokens.internal_transfer(&seller, &buyer, &token_id, None, Some(memo));
        refund_cleared_approvals(&old_owner, &cleared);
        self.record_transfer(&token_id, "buy", &old_owner, &buyer, None);
        // If the seller's account no longer exists, this transfer fails and the price stays in
        // the contract (documented limit).
        Promise::new(old_owner.clone()).transfer(NearToken::from_yoctonear(price)).detach();
        refund_if_any(&buyer, NearToken::from_yoctonear(attached.as_yoctonear() - price));
        emit_policy_event(
            "sale_bought",
            &token_id,
            json!({ "sale_id": sale_id, "seller": old_owner, "buyer": buyer, "price": U128(price) }),
        );
    }

    /// The owner withdraws a sale; the vault can sign again.
    #[payable]
    pub fn cancel_sale(&mut self, token_id: TokenId) {
        assert_one_yocto();
        let owner = self.assert_owner(&token_id);
        self.drop_sale(&token_id, &owner);
        emit_policy_event("sale_cancelled", &token_id, json!({}));
    }

    /// The guardian of the policy in force vetoes a sale (threat 16: a thief holding the owner's
    /// key cannot move the NFT past the guardian). To get rid of a guardian that vetoes every
    /// sale, the owner replaces it (that waits max(2 x delay, 3 days) and cannot be vetoed).
    #[payable]
    pub fn veto_sale(&mut self, token_id: TokenId) {
        assert_one_yocto();
        let owner = self.owner_of(&token_id);
        let guardian = self.policies.get(&token_id).and_then(|s| s.policy.guardian);
        require!(guardian.as_ref() == Some(&env::predecessor_account_id()), "Only the guardian can veto");
        self.drop_sale(&token_id, &owner);
        emit_policy_event("sale_vetoed", &token_id, json!({ "guardian": env::predecessor_account_id() }));
    }

    pub fn get_sale(&self, token_id: TokenId) -> Option<Sale> {
        require_token_exists(&self.tokens, &token_id);
        self.sales.get(&token_id)
    }

    /// Mints a new vault owned by the caller. The caller attaches a deposit that covers the
    /// storage of the token plus `TRANSFER_RECORD_RESERVE_BYTES`; the rest is refunded.
    #[payable]
    pub fn mint_vault(&mut self) -> Token {
        let initial_storage = env::storage_usage();
        let owner_id = env::predecessor_account_id();
        let token_id = self.next_token_id.to_string();
        self.next_token_id += 1; // never decremented: ids are never reused (see INVARIANT)
        let path = vault_path_for(&token_id);
        let metadata = TokenMetadata {
            title: Some(format!("Policy Vault #{token_id}")),
            description: Some(format!(
                "Vault #{token_id}. Its EVM account is derived by NEAR Chain Signatures from {} with path {}.",
                env::current_account_id(),
                path
            )),
            media: None,
            media_hash: None,
            copies: Some(1),
            issued_at: Some(env::block_timestamp_ms().to_string()),
            expires_at: None,
            starts_at: None,
            updated_at: None,
            extra: None,
            reference: None,
            reference_hash: None,
        };
        // No refund here: this function charges storage itself to include the reserve.
        let token =
            self.tokens.internal_mint_with_refund(token_id, owner_id.clone(), Some(metadata), None);
        self.transfer_info.insert(&token.token_id, &TransferInfo::default());
        // Fixed-size placeholder, so the storage of the resolved record is charged now.
        self.vaults.insert(&token.token_id, &VaultRecord::unresolved());
        NftMint { owner_id: &owner_id, token_ids: &[&token.token_id], memo: None }.emit();

        let storage_used = env::storage_usage() - initial_storage + TRANSFER_RECORD_RESERVE_BYTES;
        let cost = env::storage_byte_cost().saturating_mul(storage_used.into());
        let attached = env::attached_deposit();
        require!(
            cost <= attached,
            format!("Must attach {} to cover storage", cost.exact_amount_display())
        );
        let refund = attached.saturating_sub(cost);
        if refund > NearToken::from_yoctonear(1) {
            Promise::new(owner_id).transfer(refund).detach();
        }
        self.request_derived_key(&token.token_id).detach();
        token
    }

    /// Everything public about a vault, including its EVM address once resolved.
    pub fn vault_info(&self, token_id: TokenId) -> VaultInfo {
        require_token_exists(&self.tokens, &token_id);
        let record = self.vaults.get(&token_id).filter(|r| r.resolved);
        VaultInfo {
            path: vault_path_for(&token_id),
            token_id,
            signer_id: self.signer_id.clone(),
            public_key: record
                .as_ref()
                .map(|r| format!("secp256k1:{}", bs58::encode(r.public_key).into_string())),
            evm_address: record.as_ref().map(|r| hex0x(&r.evm_address)),
        }
    }

    /// Asks the signer again for a vault's key. Use it when the call made at mint failed, or for
    /// vaults minted before the M4 migration (they have no record yet: the caller then pays its
    /// storage and gets the rest back). Fails if the address is already resolved.
    #[payable]
    pub fn resolve_vault_address(&mut self, token_id: TokenId) -> Promise {
        require_token_exists(&self.tokens, &token_id);
        match self.vaults.get(&token_id) {
            Some(r) if r.resolved => env::panic_str("Vault address already resolved"),
            Some(_) => {}
            None => {
                let before = env::storage_usage();
                self.vaults.insert(&token_id, &VaultRecord::unresolved());
                let cost = env::storage_byte_cost()
                    .saturating_mul((env::storage_usage() - before).into());
                let attached = env::attached_deposit();
                require!(
                    cost <= attached,
                    format!("Must attach {} to cover storage", cost.exact_amount_display())
                );
                let refund = attached.saturating_sub(cost);
                if refund > NearToken::from_yoctonear(1) {
                    Promise::new(env::predecessor_account_id()).transfer(refund).detach();
                }
            }
        }
        self.request_derived_key(&token_id)
    }

    /// Callback of the signer's `derived_public_key`. Stores the key only if it parses as a
    /// 64-byte secp256k1 key and the vault is not resolved yet. Returns whether it stored it.
    #[private]
    pub fn on_derived_key(
        &mut self,
        token_id: TokenId,
        #[callback_result] result: Result<String, PromiseError>,
    ) -> bool {
        let Some(mut record) = self.vaults.get(&token_id) else {
            env::log_str(&format!("on_derived_key: no record for token {token_id}"));
            return false;
        };
        if record.resolved {
            env::log_str(&format!("on_derived_key: token {token_id} already resolved, kept"));
            return false;
        }
        let key = match result.as_deref().map(parse_secp256k1_key) {
            Ok(Some(k)) => k,
            Ok(None) => {
                env::log_str(&format!("on_derived_key: malformed key for token {token_id}"));
                return false;
            }
            Err(_) => {
                env::log_str(&format!("on_derived_key: signer call failed for token {token_id}"));
                return false;
            }
        };
        record.resolved = true;
        record.public_key = key;
        record.evm_address = evm_address_of(&key);
        self.vaults.insert(&token_id, &record);
        let event = json!({
            "standard": "policy_vault",
            "version": "1.0.0",
            "event": "vault_address",
            "data": [{ "token_id": token_id, "evm_address": hex0x(&record.evm_address) }]
        });
        env::log_str(&format!("EVENT_JSON:{event}"));
        true
    }

    /// Chain Signatures derivation path of a vault. The EVM address is obtained off-chain with
    /// `derived_public_key(path, predecessor = this contract, domain_id = 0)` on the signer.
    pub fn vault_path(&self, token_id: TokenId) -> String {
        require_token_exists(&self.tokens, &token_id);
        vault_path_for(&token_id)
    }

    /// Number of ownership changes and the last one. `None` only for tokens minted before the
    /// migration that have not moved since.
    pub fn vault_transfer_info(&self, token_id: TokenId) -> Option<TransferInfo> {
        require_token_exists(&self.tokens, &token_id);
        self.transfer_info.get(&token_id)
    }

    fn request_derived_key(&self, token_id: &TokenId) -> Promise {
        ext_signer::ext(self.signer_id.clone())
            .with_static_gas(GAS_FOR_DERIVE)
            .derived_public_key(
                vault_path_for(token_id),
                Some(env::current_account_id()),
                Some(SECP256K1_DOMAIN_ID),
            )
            .then(
                Self::ext(env::current_account_id())
                    .with_static_gas(GAS_FOR_DERIVE_CALLBACK)
                    .on_derived_key(token_id.clone()),
            )
    }

    /// Hook called before any transfer. M7: no transfer while a signature is in flight, so the
    /// callback always sees the owner who asked for it (threat 5). M8: an open sale window of
    /// the current owner, and, if the memo names a sale (`sale:<id>`), that very sale.
    fn assert_transferable(&self, token_id: &TokenId, memo: Option<&str>) {
        require_token_exists(&self.tokens, token_id);
        self.assert_no_transfer_call(token_id);
        require!(
            self.inflight.get(token_id).is_none(),
            "A signature is in flight for this vault; transfer after it completes"
        );
        // M8 (threats 1, 13, 14, 16): every transfer path, by the owner, an approved account or
        // transfer_call, needs an open sale window of the current owner.
        let sale = self
            .sales
            .get(token_id)
            .filter(|s| s.owner_epoch == self.owner_epoch(token_id))
            .unwrap_or_else(|| {
                env::panic_str("Start a sale (start_sale) and wait for it to open before transferring")
            });
        let now = env::block_timestamp_ms();
        require!(now >= sale.opens_at_ms, format!("The sale opens at {} ms", sale.opens_at_ms));
        require!(now < sale.closes_at_ms, "The sale window has closed; start a new sale");
        // M8 review V1: a buyer or escrow that audited sale N transfers with memo "sale:N"; if the
        // seller cancelled and restarted the sale (and could have signed in between), it fails.
        // General review H6: "Sale:N" or "SALE:N" bind too, they are never silently ignored.
        if let Some(bound) = memo.and_then(sale_binding) {
            let id: u64 = bound
                .trim()
                .parse()
                .unwrap_or_else(|_| env::panic_str("Malformed sale binding in memo; use sale:<sale_id>"));
            require!(
                id == sale.sale_id,
                format!("The sale changed since it was audited (audited {id}, current {})", sale.sale_id)
            );
        }
    }

    /// General review H1: during `nft_transfer_call` the receiver owns the vault until the
    /// transfer resolves, and may still hand it back. Until then nobody acts as its owner
    /// (no policy, proposal, signature, cancellation, sale, approval or transfer), so a
    /// receiver cannot spend from a vault and then return it.
    fn assert_no_transfer_call(&self, token_id: &TokenId) {
        if let Some(started) = self.transfer_calls.get(token_id) {
            require!(
                env::block_timestamp_ms() >= started.saturating_add(TRANSFER_CALL_TIMEOUT_MS),
                "A transfer_call is in progress for this vault; wait until it resolves"
            );
        }
    }

    /// The sale of a vault if its window has not closed yet (a closed one no longer freezes the
    /// vault; M8 review V2).
    fn active_sale(&self, token_id: &TokenId) -> Option<Sale> {
        self.sales.get(token_id).filter(|s| env::block_timestamp_ms() < s.closes_at_ms)
    }

    fn drop_sale(&mut self, token_id: &TokenId, owner: &AccountId) {
        let before = env::storage_usage();
        require!(self.sales.remove(token_id).is_some(), "No active sale");
        settle_storage(before, owner);
    }

    fn record_transfer(
        &mut self,
        token_id: &TokenId,
        kind: &str,
        from: &AccountId,
        to: &AccountId,
        authorized_id: Option<AccountId>,
    ) {
        let record = TransferRecord {
            kind: kind.to_string(),
            from: from.clone(),
            to: to.clone(),
            authorized_id,
            block_height: env::block_height(),
            timestamp_ms: env::block_timestamp_ms(),
        };
        let mut info = self.transfer_info.get(token_id).unwrap_or_default();
        info.count += 1;
        info.last = Some(record.clone());
        self.transfer_info.insert(token_id, &info);
        // M5, threat 2: a new owner never inherits the previous owner's policy, pending change
        // or spending windows. This runs on every change of owner, including a transfer_call
        // that comes back (so a receiver cannot leave its own policy behind, threat 13).
        // The freed storage goes back to whoever owned the vault while the policy was set.
        // M8: the sale ends with the transfer (it never carries over to the new owner).
        let before = env::storage_usage();
        let removed_policy = self.policies.remove(token_id).is_some();
        let removed_sale = self.sales.remove(token_id).is_some();
        if removed_policy || removed_sale {
            let freed = before.saturating_sub(env::storage_usage());
            refund_if_any(from, env::storage_byte_cost().saturating_mul(freed.into()));
        }
        let event = json!({
            "standard": "policy_vault",
            "version": "1.0.0",
            "event": "vault_transfer",
            "data": [{
                "token_id": token_id,
                "kind": record.kind,
                "old_owner_id": record.from,
                "new_owner_id": record.to,
                "authorized_id": record.authorized_id,
            }]
        });
        env::log_str(&format!("EVENT_JSON:{event}"));
    }
}

// ---------- M5: policy entry points ----------

#[near]
impl PolicyVault {
    /// Sets the vault's policy. Only the owner, with a deposit of at least 1 yoctoNEAR (so a
    /// function-call key alone cannot do it) that also covers any extra storage.
    /// - If the new policy is not looser than the current one in any respect, or the current
    ///   delay is 0 (for example, the first policy of a locked vault), it applies at once and
    ///   any pending change is dropped. Returns `true`.
    /// - Otherwise it becomes the pending change and applies after the current delay, unless
    ///   the current guardian vetoes it or the owner cancels it. Returns `false`.
    #[payable]
    pub fn set_policy(&mut self, token_id: TokenId, policy: Policy) -> bool {
        require!(
            env::attached_deposit() >= NearToken::from_yoctonear(1),
            "Requires attached deposit of at least 1 yoctoNEAR"
        );
        let owner = self.assert_owner(&token_id);
        let new = policy.normalized().unwrap_or_else(|e| env::panic_str(&e.to_string()));
        self.assert_chain_allowed(&token_id, new.chain_id);
        let before = env::storage_usage();
        let mut st = self.policy_state(&token_id);
        let now = env::block_timestamp_ms();
        st.spend.prune_expired(now);
        // Review P3: replacing or removing an existing guardian always waits the long lock and
        // cannot be vetoed by that guardian, so a lost or hostile guardian cannot freeze the vault.
        let replaces = policy::replaces_guardian(&new, &st.policy);
        let applied =
            !replaces && (policy::is_not_looser(&new, &st.policy) || st.policy.delay_ms == 0);
        let apply_after_ms = if applied {
            st.policy = new;
            st.pending = None;
            now
        } else {
            let wait = if replaces {
                policy::guardian_change_wait_ms(&st.policy)
            } else {
                st.policy.delay_ms
            };
            let at = now.saturating_add(wait);
            st.pending = Some(PendingPolicy { policy: new, apply_after_ms: at });
            at
        };
        self.policies.insert(&token_id, &st);
        settle_storage(before, &owner);
        emit_policy_event("policy_set", &token_id, json!({ "applied": applied, "apply_after_ms": apply_after_ms }));
        applied
    }

    /// Applies a pending change once its delay has passed. Anyone can call it.
    pub fn apply_policy(&mut self, token_id: TokenId) {
        let owner = self.owner_of(&token_id);
        let before = env::storage_usage();
        let mut st = self.policies.get(&token_id).unwrap_or_else(|| env::panic_str("No pending policy"));
        let pending = st.pending.take().unwrap_or_else(|| env::panic_str("No pending policy"));
        require!(env::block_timestamp_ms() >= pending.apply_after_ms, "Pending policy not ready yet");
        // A change queued before the vault's first signature may name another chain.
        self.assert_chain_allowed(&token_id, pending.policy.chain_id);
        st.policy = pending.policy;
        st.spend.prune_expired(env::block_timestamp_ms());
        self.policies.insert(&token_id, &st);
        settle_storage(before, &owner);
        emit_policy_event("policy_applied", &token_id, json!({}));
    }

    /// The owner withdraws a pending change.
    #[payable]
    pub fn cancel_pending_policy(&mut self, token_id: TokenId) {
        assert_one_yocto();
        let owner = self.assert_owner(&token_id);
        self.drop_pending(&token_id, &owner);
        emit_policy_event("policy_cancelled", &token_id, json!({}));
    }

    /// The guardian of the policy in force vetoes a pending change.
    #[payable]
    pub fn veto_pending_policy(&mut self, token_id: TokenId) {
        assert_one_yocto();
        let owner = self.owner_of(&token_id);
        let st = self.policies.get(&token_id).unwrap_or_else(|| env::panic_str("No pending policy"));
        require!(
            st.policy.guardian.as_ref() == Some(&env::predecessor_account_id()),
            "Only the guardian can veto"
        );
        if let Some(p) = &st.pending {
            require!(
                !policy::replaces_guardian(&p.policy, &st.policy),
                "The guardian cannot veto its own replacement"
            );
        }
        self.drop_pending(&token_id, &owner);
        emit_policy_event("policy_vetoed", &token_id, json!({ "guardian": env::predecessor_account_id() }));
    }

    pub fn get_policy(&self, token_id: TokenId) -> PolicyView {
        require_token_exists(&self.tokens, &token_id);
        let stored = self.policies.get(&token_id);
        let has_policy = stored.is_some();
        let st = stored.unwrap_or_else(locked_state);
        PolicyView { token_id, has_policy, policy: st.policy, pending: st.pending, spend: st.spend }
    }

    /// Would the contract sign this transaction now? Read-only: reserves nothing.
    pub fn check_transaction(&self, token_id: TokenId, tx: TxInput) -> CheckResult {
        require_token_exists(&self.tokens, &token_id);
        let refused = |reason: String, hash: Option<String>| CheckResult {
            allowed: false,
            reason: Some(reason),
            signing_hash: hash,
            reservation: None,
        };
        let tx = match tx.to_tx() {
            Ok(t) => t,
            Err(e) => return refused(e, None),
        };
        let hash = Some(hex0x(&tx.signing_hash()));
        let Some(st) = self.policies.get(&token_id) else {
            return refused("vault has no policy (locked)".into(), hash);
        };
        let vault = self.vault_address(&token_id);
        match policy::check_with_vault(&st.policy, &st.spend, &tx, env::block_timestamp_ms(), vault.as_deref()) {
            Ok(r) => CheckResult { allowed: true, reason: None, signing_hash: hash, reservation: Some(r) },
            Err(e) => refused(e.to_string(), hash),
        }
    }
}

impl PolicyVault {
    fn owner_of(&self, token_id: &TokenId) -> AccountId {
        self.tokens.owner_by_id.get(token_id).unwrap_or_else(|| env::panic_str("Token not found"))
    }

    /// The caller must own the vault, and the vault must not be in an unresolved transfer_call
    /// (general review H1).
    fn assert_owner(&self, token_id: &TokenId) -> AccountId {
        let owner = self.owner_of(token_id);
        require!(env::predecessor_account_id() == owner, "Only the vault owner can do this");
        self.assert_no_transfer_call(token_id);
        owner
    }

    /// The caller must own the vault or be the proposer named in its policy (agent mode), and the
    /// vault must not be in an unresolved transfer_call. Returns the caller.
    fn assert_owner_or_proposer(&self, token_id: &TokenId) -> AccountId {
        let caller = env::predecessor_account_id();
        let owner = self.owner_of(token_id);
        let proposer = self.policies.get(token_id).and_then(|s| s.policy.proposer);
        require!(
            caller == owner || proposer.as_ref() == Some(&caller),
            "Only the vault owner or its proposer can do this"
        );
        self.assert_no_transfer_call(token_id);
        caller
    }

    /// The vault's EVM address (`0x` lowercase), once resolved.
    fn vault_address(&self, token_id: &TokenId) -> Option<String> {
        self.vaults.get(token_id).filter(|v| v.resolved).map(|v| hex0x(&v.evm_address))
    }

    fn policy_state(&self, token_id: &TokenId) -> VaultPolicyState {
        self.policies.get(token_id).unwrap_or_else(locked_state)
    }

    fn drop_pending(&mut self, token_id: &TokenId, owner: &AccountId) {
        let before = env::storage_usage();
        let mut st = self.policies.get(token_id).unwrap_or_else(|| env::panic_str("No pending policy"));
        require!(st.pending.take().is_some(), "No pending policy");
        self.policies.insert(token_id, &st);
        settle_storage(before, owner);
    }
}

fn locked_state() -> VaultPolicyState {
    VaultPolicyState {
        policy: Policy::locked(),
        pending: None,
        spend: SpendState::default(),
        proposals: Vec::new(),
    }
}

// ---------- M6: proposal entry points ----------

#[near]
impl PolicyVault {
    /// Queues a transaction. Only the owner, with a deposit of at least 1 yoctoNEAR that also
    /// covers the storage of the proposal. The transaction must pass the policy now, but its
    /// spend is charged to the daily caps only when it is signed (review P1: charging at
    /// proposal time let proposals held across days be signed together above the cap).
    /// It can be signed after the policy's delay (M7). Returns the proposal id.
    #[payable]
    pub fn propose(&mut self, token_id: TokenId, tx: ProposalTx) -> u64 {
        require!(
            env::attached_deposit() >= NearToken::from_yoctonear(1),
            "Requires attached deposit of at least 1 yoctoNEAR"
        );
        let caller = self.assert_owner_or_proposer(&token_id);
        let before = env::storage_usage();
        let mut st = self
            .policies
            .get(&token_id)
            .unwrap_or_else(|| env::panic_str("vault has no policy (locked)"));
        require!(st.proposals.len() < MAX_QUEUED_PROPOSALS, "Too many queued proposals");
        // The nonce does not take part in the policy; 0 is a placeholder.
        let candidate = tx.to_tx(0).unwrap_or_else(|e| env::panic_str(&e));
        let now = env::block_timestamp_ms();
        st.spend.prune_expired(now);
        let vault = self.vault_address(&token_id);
        let reservation = policy::check_with_vault(&st.policy, &st.spend, &candidate, now, vault.as_deref())
            .unwrap_or_else(|e| env::panic_str(&e.to_string()));
        let id = self.next_proposal_id;
        self.next_proposal_id += 1;
        let executable_after_ms = now.saturating_add(st.policy.delay_ms);
        st.proposals.push(Proposal {
            id,
            owner_epoch: self.owner_epoch(&token_id),
            tx,
            reservation,
            created_ms: now,
            executable_after_ms,
        });
        self.policies.insert(&token_id, &st);
        settle_storage(before, &caller);
        emit_policy_event(
            "proposal_created",
            &token_id,
            json!({ "proposal_id": id, "executable_after_ms": executable_after_ms, "by": caller }),
        );
        id
    }

    /// The owner withdraws a queued proposal.
    #[payable]
    pub fn cancel_proposal(&mut self, token_id: TokenId, proposal_id: u64) {
        assert_one_yocto();
        let owner = self.assert_owner(&token_id);
        self.remove_proposal(&token_id, proposal_id, &owner);
        emit_policy_event("proposal_cancelled", &token_id, json!({ "proposal_id": proposal_id }));
    }

    /// The guardian of the policy in force vetoes a queued proposal.
    #[payable]
    pub fn veto_proposal(&mut self, token_id: TokenId, proposal_id: u64) {
        assert_one_yocto();
        let owner = self.owner_of(&token_id);
        let st = self.policies.get(&token_id).unwrap_or_else(|| env::panic_str("Proposal not found"));
        require!(
            st.policy.guardian.as_ref() == Some(&env::predecessor_account_id()),
            "Only the guardian can veto"
        );
        self.remove_proposal(&token_id, proposal_id, &owner);
        emit_policy_event(
            "proposal_vetoed",
            &token_id,
            json!({ "proposal_id": proposal_id, "guardian": env::predecessor_account_id() }),
        );
    }

    pub fn list_proposals(&self, token_id: TokenId) -> Vec<Proposal> {
        require_token_exists(&self.tokens, &token_id);
        self.policies.get(&token_id).map(|s| s.proposals).unwrap_or_default()
    }

    /// The nonce the vault's next signed transaction will carry.
    pub fn get_next_nonce(&self, token_id: TokenId) -> u64 {
        require_token_exists(&self.tokens, &token_id);
        self.nonces.get(&token_id).unwrap_or(0)
    }

    /// Could this proposal be signed now? Read-only; M7's `execute` runs the same checks.
    pub fn check_execution(&self, token_id: TokenId, proposal_id: u64) -> ExecutionCheck {
        require_token_exists(&self.tokens, &token_id);
        let nonce = self.nonces.get(&token_id).unwrap_or(0);
        // General review H4: report the sale freeze, as `execute_proposal` would.
        if self.active_sale(&token_id).is_some() {
            return ExecutionCheck {
                ready: false,
                reason: Some("The vault is frozen for a sale; only cancel_nonce can sign until the sale ends".into()),
                nonce,
                signing_hash: None,
            };
        }
        match self.prepare_execution(&token_id, proposal_id, env::block_timestamp_ms(), None) {
            Ok(prep) => ExecutionCheck {
                ready: true,
                reason: None,
                nonce: prep.tx.nonce,
                signing_hash: Some(hex0x(&prep.tx.signing_hash())),
            },
            Err(reason) => ExecutionCheck { ready: false, reason: Some(reason), nonce, signing_hash: None },
        }
    }
}

// ---------- M7: signing entry points ----------

/// What `prepare_execution` decides for a proposal: the exact transaction (with its nonce), what
/// it charges to the caps, and whether the nonce is the vault's next one.
pub struct PreparedExecution {
    pub tx: Eip1559Tx,
    pub charge: Reservation,
    pub from_next: bool,
}

#[near]
impl PolicyVault {
    /// Signs a ready proposal. Only the owner, with at least 100 Tgas. In one synchronous step it
    /// charges the daily caps, takes the nonce and locks the vault (no second signature, no
    /// transfer) until the MPC answer arrives in `on_signed`.
    /// - Nonce: the vault's next one; a proposal pinned after an uncertain outcome always uses
    ///   its pinned nonce; `replace_nonce` signs it with an earlier, already signed nonce instead
    ///   (to replace a transaction that is stuck, e.g. with too low a fee). Two transactions
    ///   with the same nonce can never both be mined.
    /// - Deposit: storage for the signed record plus `sign_deposit` for the signer (default
    ///   1 yoctoNEAR, review S4); the rest is refunded.
    /// Returns the promise, so the caller sees whether the signature was stored.
    #[payable]
    pub fn execute_proposal(
        &mut self,
        token_id: TokenId,
        proposal_id: u64,
        replace_nonce: Option<u64>,
        sign_deposit: Option<U128>,
    ) -> Promise {
        // The owner, or the policy's proposer (agent mode): either way the proposal already
        // waited the delay and the guardian could veto it.
        let caller = self.assert_owner_or_proposer(&token_id);
        // Review M21 (R21-4): replacing a nonce that was already signed is the owner's call; an
        // agent could otherwise re-sign the owner's nonces and charge the caps again.
        require!(
            replace_nonce.is_none() || caller == self.owner_of(&token_id),
            "Only the vault owner can replace a signed nonce"
        );
        self.assert_can_sign(&token_id);
        // M8: a vault on sale only signs cancellations, so the buyer can audit a stable state.
        require!(
            self.active_sale(&token_id).is_none(),
            "The vault is frozen for a sale; only cancel_nonce can sign until the sale ends"
        );
        let before = env::storage_usage();
        let now = env::block_timestamp_ms();
        let (proposal, prep, charged) = self.commit_execution(&token_id, proposal_id, replace_nonce);
        let signing_hash = hex0x(&prep.tx.signing_hash());
        let f = InFlight {
            tx: proposal.tx.clone(),
            proposal: Some(proposal),
            nonce: prep.tx.nonce,
            from_next: prep.from_next,
            signing_hash,
            charge: prep.charge,
            charged,
            payer: caller,
            started_ms: now,
        };
        self.start_signing(&token_id, f, before, sign_deposit)
    }

    /// Signs a 0-value transfer from the vault to itself with an already signed `nonce`, so
    /// whatever else was signed with that nonce can no longer be mined (threat 1; review S3).
    /// Only the owner. It moves no funds, so it does not wait for the delay; it only has to fit
    /// the gas rules and the ETH cap (the gas is charged). `gas_limit` defaults to 21000.
    #[payable]
    pub fn cancel_nonce(
        &mut self,
        token_id: TokenId,
        nonce: u64,
        max_fee_per_gas: U128,
        max_priority_fee_per_gas: U128,
        gas_limit: Option<u64>,
        sign_deposit: Option<U128>,
    ) -> Promise {
        let owner = self.assert_owner(&token_id);
        self.assert_can_sign(&token_id);
        require!(
            nonce < self.nonces.get(&token_id).unwrap_or(0),
            "Only a nonce that was already signed can be cancelled"
        );
        let before = env::storage_usage();
        let now = env::block_timestamp_ms();
        let mut st = self
            .policies
            .get(&token_id)
            .unwrap_or_else(|| env::panic_str("vault has no policy (locked)"));
        st.spend.prune_expired(now);
        let gas_limit = gas_limit.unwrap_or(policy::MIN_GAS_LIMIT);
        let charge = policy::check_cancel(
            &st.policy,
            &st.spend,
            gas_limit,
            max_fee_per_gas.0,
            max_priority_fee_per_gas.0,
            now,
        )
        .unwrap_or_else(|e| env::panic_str(&e.to_string()));
        st.spend.reserve(&charge, now);
        let chain_id = st.policy.chain_id;
        self.policies.insert(&token_id, &st);
        let own = self.vaults.get(&token_id).expect("checked by assert_can_sign");
        let tx = ProposalTx {
            chain_id,
            max_priority_fee_per_gas,
            max_fee_per_gas,
            gas_limit,
            to: hex0x(&own.evm_address),
            value: U128(0),
            data: "0x".into(),
        };
        let signing_hash = hex0x(&tx.to_tx(nonce).expect("built from valid fields").signing_hash());
        let f = InFlight {
            proposal: None,
            tx,
            nonce,
            from_next: false,
            signing_hash,
            charge,
            charged: true,
            payer: owner,
            started_ms: now,
        };
        self.start_signing(&token_id, f, before, sign_deposit)
    }

    /// Callback of the signer's `sign`. Reads the answer by hand and never panics (review S1).
    /// Only accepts the answer for the signature currently in flight (`signing_hash`).
    /// - Readable and it recovers to the vault key: stores the signed transaction.
    /// - Readable but it does not recover to the vault key: it cannot move the vault's funds, so
    ///   everything is undone (caps, nonce, queue).
    /// - Signer failed or answer unreadable: a valid signature might exist, so the outcome is
    ///   "uncertain": the nonce stays used, the charge stays, and the proposal goes back to the
    ///   queue pinned to that nonce (review S3).
    /// Returns whether a signature was stored.
    #[private]
    pub fn on_signed(&mut self, token_id: TokenId, signing_hash: String) -> bool {
        match self.inflight.get(&token_id) {
            Some(f) if f.signing_hash == signing_hash => {}
            _ => {
                env::log_str(&format!("on_signed: stale or unknown answer for token {token_id}"));
                return false;
            }
        }
        let f = self.inflight.remove(&token_id).expect("checked above");
        let resp = match env::promise_result_checked(0, MAX_SIGN_RESPONSE_LEN) {
            Err(_) => {
                self.mark_uncertain(&token_id, &f, "signer call failed");
                return false;
            }
            Ok(bytes) => match near_sdk::serde_json::from_slice::<SignResponse>(&bytes) {
                Ok(r) => r,
                Err(_) => {
                    self.mark_uncertain(&token_id, &f, "unreadable signer answer");
                    return false;
                }
            },
        };
        let vault = self.vaults.get(&token_id).filter(|v| v.resolved);
        let hash: Option<[u8; 32]> = policy::parse_hex(&f.signing_hash).and_then(|v| v.try_into().ok());
        let (Some(vault), Some(hash), Ok(tx)) = (vault, hash, f.tx.to_tx(f.nonce)) else {
            self.mark_uncertain(&token_id, &f, "stored data unreadable");
            return false;
        };
        match verify_signature(&resp, &hash, &vault.public_key) {
            Ok((parity, r, s)) => {
                self.store_signed(&token_id, &f, &tx, parity, &r, &s);
                true
            }
            // Only a signature that recovers to another key provably cannot move the vault's
            // funds, so only then is everything undone.
            Err(reason) if reason == WRONG_KEY => {
                self.reject_signature(&token_id, &f, reason);
                false
            }
            // Review M12 (R12-5): any other problem (a format the contract does not expect, such
            // as recovery_id 27/28 or an uncompressed point) may hide a valid signature, so the
            // outcome is uncertain: the nonce stays used and the charge stays.
            Err(reason) => {
                self.mark_uncertain(&token_id, &f, reason);
                false
            }
        }
    }

    /// The owner stops waiting for a signature that never got an answer (review S2). Only after
    /// `INFLIGHT_TIMEOUT_MS`. The outcome is treated as uncertain: the nonce is not reused for a
    /// different transaction.
    pub fn abandon_signature(&mut self, token_id: TokenId) {
        self.assert_owner(&token_id);
        let f = self.inflight.get(&token_id).unwrap_or_else(|| env::panic_str("No signature in flight"));
        require!(
            env::block_timestamp_ms() >= f.started_ms.saturating_add(INFLIGHT_TIMEOUT_MS),
            "The signature may still arrive; wait for the timeout"
        );
        self.inflight.remove(&token_id);
        self.mark_uncertain(&token_id, &f, "abandoned after timeout");
    }

    /// The signature a vault is waiting for, if any.
    pub fn get_inflight(&self, token_id: TokenId) -> Option<InFlight> {
        require_token_exists(&self.tokens, &token_id);
        self.inflight.get(&token_id)
    }

    /// The EVM chain this vault has signed for (`None` if it never signed). Its policy can only
    /// use this chain, also after a sale (general review G2).
    pub fn get_vault_chain(&self, token_id: TokenId) -> Option<u64> {
        require_token_exists(&self.tokens, &token_id);
        self.vault_chain_of(&token_id)
    }

    /// Nonces of a vault whose signature outcome is unknown.
    pub fn get_uncertain(&self, token_id: TokenId) -> Vec<UncertainNonce> {
        require_token_exists(&self.tokens, &token_id);
        self.uncertain.get(&token_id).unwrap_or_default()
    }

    /// The latest signed version of a nonce.
    pub fn get_signed(&self, token_id: TokenId, nonce: u64) -> Option<SignedRecord> {
        require_token_exists(&self.tokens, &token_id);
        self.signed_versions_of(&token_id, nonce).pop()
    }

    /// Every signed version of a nonce, oldest first (review S5).
    pub fn get_signed_versions(&self, token_id: TokenId, nonce: u64) -> Vec<SignedRecord> {
        require_token_exists(&self.tokens, &token_id);
        self.signed_versions_of(&token_id, nonce)
    }

    /// Signed transactions of a vault, every version, by nonce from `from_nonce` (default 0),
    /// at most `limit` records (default 20, max 100). A buyer compares these with the external
    /// account's nonce (M8).
    pub fn list_signed(&self, token_id: TokenId, from_nonce: Option<u64>, limit: Option<u64>) -> Vec<SignedRecord> {
        require_token_exists(&self.tokens, &token_id);
        let next = self.nonces.get(&token_id).unwrap_or(0);
        let max = limit.unwrap_or(20).min(100) as usize;
        (from_nonce.unwrap_or(0)..next)
            .flat_map(|n| self.signed_versions_of(&token_id, n))
            .take(max)
            .collect()
    }
}

impl PolicyVault {
    /// The chain the vault's nonce counter belongs to: recorded at the first signature, or, for
    /// vaults that signed before it was recorded, read from their oldest signed transaction.
    fn vault_chain_of(&self, token_id: &TokenId) -> Option<u64> {
        if let Some(c) = self.vault_chain.get(token_id) {
            return Some(c);
        }
        let next = self.nonces.get(token_id).unwrap_or(0);
        (0..next).find_map(|n| {
            self.signed_versions_of(token_id, n)
                .first()
                .and_then(|r| policy::parse_hex(&r.signed_tx))
                .and_then(|raw| evm::chain_id_of_signed(&raw))
        })
    }

    fn assert_chain_allowed(&self, token_id: &TokenId, chain_id: u64) {
        if let Some(c) = self.vault_chain_of(token_id) {
            require!(
                chain_id == c,
                format!("This vault has signed on chain {c}; its policy must keep chain_id {c}")
            );
        }
    }

    fn assert_can_sign(&self, token_id: &TokenId) {
        require!(
            env::prepaid_gas() >= MIN_PREPAID_GAS_FOR_SIGNING,
            "Attach at least 100 Tgas to sign"
        );
        require!(self.inflight.get(token_id).is_none(), "A signature is already in flight for this vault");
        require!(
            self.vaults.get(token_id).map(|v| v.resolved).unwrap_or(false),
            "Vault address not resolved yet; call resolve_vault_address first"
        );
    }

    /// Records the signature in flight, settles the storage deposit and calls the signer.
    fn start_signing(&mut self, token_id: &TokenId, f: InFlight, before: u64, sign_deposit: Option<U128>) -> Promise {
        // Review M21 (R21-1): a deposit below the minimum makes the signer refuse, which leaves the
        // nonce uncertain and the cap charged; never forward less than the minimum.
        let deposit = sign_deposit.map(|d| NearToken::from_yoctonear(d.0)).unwrap_or(SIGN_DEPOSIT).max(SIGN_DEPOSIT);
        // G2: the first signature fixes the vault's chain (its nonce counter belongs to it).
        if self.vault_chain.get(token_id).is_none() {
            self.vault_chain.insert(token_id, &f.tx.chain_id);
        }
        self.inflight.insert(token_id, &f);
        // Storage: whatever this call added, plus the record the callback will write.
        let added = env::storage_usage().saturating_sub(before) + SIGNED_RECORD_RESERVE_BYTES;
        let cost = env::storage_byte_cost().saturating_mul(added.into());
        let attached = env::attached_deposit();
        require!(
            cost.saturating_add(deposit) <= attached,
            format!(
                "Must attach {} to cover storage and the signer deposit",
                cost.saturating_add(deposit).exact_amount_display()
            )
        );
        refund_if_any(&f.payer, attached.saturating_sub(cost).saturating_sub(deposit));
        emit_policy_event(
            "signature_requested",
            token_id,
            json!({
                "kind": if f.proposal.is_some() { "proposal" } else { "cancel" },
                "proposal_id": f.proposal.as_ref().map(|p| p.id),
                "nonce": f.nonce,
                "signing_hash": f.signing_hash,
            }),
        );
        ext_signer::ext(self.signer_id.clone())
            .with_attached_deposit(deposit)
            .with_unused_gas_weight(1)
            .sign(SignRequest {
                domain_id: SECP256K1_DOMAIN_ID,
                path: vault_path_for(token_id),
                payload_v2: SignPayload::Ecdsa(f.signing_hash.trim_start_matches("0x").to_string()),
            })
            .then(
                Self::ext(env::current_account_id())
                    .with_static_gas(GAS_FOR_SIGN_CALLBACK)
                    .with_unused_gas_weight(0)
                    .on_signed(token_id.clone(), f.signing_hash.clone()),
            )
    }

    fn signed_versions_of(&self, token_id: &str, nonce: u64) -> Vec<SignedRecord> {
        let key0 = signed_key(token_id, nonce);
        if self.signed.get(&key0).is_none() {
            return Vec::new();
        }
        let count = self.signed_versions.get(&key0).unwrap_or(1);
        (0..count).filter_map(|v| self.signed.get(&signed_version_key(token_id, nonce, v))).collect()
    }

    fn is_uncertain(&self, token_id: &TokenId, nonce: u64, signing_hash: &str) -> bool {
        self.uncertain
            .get(token_id)
            .map(|v| v.iter().any(|u| u.nonce == nonce && u.signing_hash == signing_hash))
            .unwrap_or(false)
    }

    fn nonce_is_uncertain(&self, token_id: &TokenId, nonce: u64) -> bool {
        self.uncertain.get(token_id).map(|v| v.iter().any(|u| u.nonce == nonce)).unwrap_or(false)
    }

    fn store_signed(&mut self, token_id: &TokenId, f: &InFlight, tx: &Eip1559Tx, parity: u8, r: &[u8; 32], s: &[u8; 32]) {
        let raw = tx.rlp_signed(parity, r, s);
        let record = SignedRecord {
            token_id: token_id.clone(),
            proposal_id: f.proposal.as_ref().map(|p| p.id).unwrap_or(CANCEL_PROPOSAL_ID),
            nonce: f.nonce,
            signing_hash: f.signing_hash.clone(),
            signed_tx: hex0x(&raw),
            tx_hash: hex0x(&keccak256(&raw)),
            owner: f.payer.clone(),
            signed_ms: env::block_timestamp_ms(),
        };
        let key0 = signed_key(token_id, f.nonce);
        let version = if self.signed.get(&key0).is_some() { self.signed_versions.get(&key0).unwrap_or(1) } else { 0 };
        self.signed.insert(&signed_version_key(token_id, f.nonce, version), &record);
        if version > 0 {
            self.signed_versions.insert(&key0, &(version + 1));
        }
        // The nonce now has a known signature: it is no longer a gap to fill.
        if let Some(mut list) = self.uncertain.get(token_id) {
            list.retain(|u| u.nonce != f.nonce);
            if list.is_empty() {
                self.uncertain.remove(token_id);
            } else {
                self.uncertain.insert(token_id, &list);
            }
        }
        emit_policy_event(
            "transaction_signed",
            token_id,
            json!({
                "kind": if f.proposal.is_some() { "proposal" } else { "cancel" },
                "proposal_id": f.proposal.as_ref().map(|p| p.id),
                "nonce": record.nonce,
                "version": version,
                "tx_hash": record.tx_hash,
                "signed_tx": record.signed_tx,
            }),
        );
    }

    /// Puts a proposal back at the front of the queue (if it still belongs to this owner and
    /// there is room), optionally pinned to a nonce.
    fn requeue(&mut self, token_id: &TokenId, f: &InFlight, pin: Option<u64>) -> bool {
        let Some(p) = &f.proposal else { return false };
        let Some(mut st) = self.policies.get(token_id) else { return false };
        // Review M21 (R21-3): room for one more than the limit, so a full queue (for example filled
        // by an agent while the signature was in flight) never drops the proposal.
        if p.owner_epoch != self.owner_epoch(token_id) || st.proposals.len() > MAX_QUEUED_PROPOSALS {
            return false;
        }
        st.proposals.insert(0, p.clone());
        self.policies.insert(token_id, &st);
        if let Some(n) = pin {
            self.pinned.insert(&p.id, &n);
        }
        true
    }

    /// The signature may exist: keep the nonce used and the charge, never give the nonce to a
    /// different transaction automatically, and put the proposal back pinned to that nonce, so
    /// a retry produces the identical transaction. The storage reserve pays for this bookkeeping.
    fn mark_uncertain(&mut self, token_id: &TokenId, f: &InFlight, reason: &str) {
        let mut list = self.uncertain.get(token_id).unwrap_or_default();
        if !list.iter().any(|u| u.nonce == f.nonce && u.signing_hash == f.signing_hash) {
            list.push(UncertainNonce {
                nonce: f.nonce,
                signing_hash: f.signing_hash.clone(),
                since_ms: env::block_timestamp_ms(),
            });
            self.uncertain.insert(token_id, &list);
        }
        let requeued = self.requeue(token_id, f, Some(f.nonce));
        emit_policy_event(
            "signature_uncertain",
            token_id,
            json!({
                "kind": if f.proposal.is_some() { "proposal" } else { "cancel" },
                "proposal_id": f.proposal.as_ref().map(|p| p.id),
                "nonce": f.nonce,
                "reason": reason,
                "requeued": requeued,
            }),
        );
    }

    /// A readable answer that does not recover to the vault key cannot move the vault's funds:
    /// undo everything (caps, nonce if it was the next one, queue) and refund the reserve.
    fn reject_signature(&mut self, token_id: &TokenId, f: &InFlight, reason: &str) {
        if f.charged {
            if let Some(mut st) = self.policies.get(token_id) {
                st.spend.release(&f.charge);
                self.policies.insert(token_id, &st);
            }
        }
        if f.from_next {
            self.nonces.insert(token_id, &f.nonce);
        }
        let pin = (!f.from_next && self.nonce_is_uncertain(token_id, f.nonce)).then_some(f.nonce);
        let requeued = self.requeue(token_id, f, pin);
        refund_if_any(
            &f.payer,
            env::storage_byte_cost().saturating_mul(SIGNED_RECORD_RESERVE_BYTES.into()),
        );
        emit_policy_event(
            "signature_failed",
            token_id,
            json!({
                "kind": if f.proposal.is_some() { "proposal" } else { "cancel" },
                "proposal_id": f.proposal.as_ref().map(|p| p.id),
                "nonce": f.nonce,
                "reason": reason,
                "requeued": requeued,
            }),
        );
    }
}

impl PolicyVault {
    /// Owner epoch: how many times the vault has changed owner. A proposal is only valid for
    /// the epoch it was made in (defense in depth: the queue is also cleared on every change).
    fn owner_epoch(&self, token_id: &TokenId) -> u64 {
        self.transfer_info.get(token_id).map(|i| i.count).unwrap_or(0)
    }

    fn remove_proposal(&mut self, token_id: &TokenId, proposal_id: u64, owner: &AccountId) -> Proposal {
        let before = env::storage_usage();
        let mut st = self.policies.get(token_id).unwrap_or_else(|| env::panic_str("Proposal not found"));
        let i = st
            .proposals
            .iter()
            .position(|p| p.id == proposal_id)
            .unwrap_or_else(|| env::panic_str("Proposal not found"));
        let p = st.proposals.remove(i);
        self.policies.insert(token_id, &st);
        self.pinned.remove(&proposal_id);
        settle_storage(before, owner);
        p
    }

    /// The transaction that would be signed for a proposal at `now_ms`, with its nonce, and what
    /// it would charge to the caps, or why not. Checks: the proposal exists, it belongs to the
    /// current owner epoch, both its own delay and the current policy's delay have passed since
    /// it was made (review P4), its nonce is valid (pinned, a replacement below the next nonce,
    /// or the next one), and it passes the policy in force against what has already been
    /// signed in the current windows.
    fn prepare_execution(
        &self,
        token_id: &TokenId,
        proposal_id: u64,
        now_ms: u64,
        replace_nonce: Option<u64>,
    ) -> Result<PreparedExecution, String> {
        let st = self.policies.get(token_id).ok_or("Proposal not found")?;
        let p = st.proposals.iter().find(|p| p.id == proposal_id).ok_or("Proposal not found")?;
        if p.owner_epoch != self.owner_epoch(token_id) {
            return Err("Proposal belongs to a previous owner".into());
        }
        let ready_at = p.executable_after_ms.max(p.created_ms.saturating_add(st.policy.delay_ms));
        if now_ms < ready_at {
            return Err("Proposal delay has not passed yet".into());
        }
        let next = self.nonces.get(token_id).unwrap_or(0);
        let (nonce, from_next) = match (self.pinned.get(&proposal_id), replace_nonce) {
            (Some(pin), Some(r)) if r != pin => return Err(format!("Proposal is pinned to nonce {pin}")),
            (Some(pin), _) => (pin, false),
            (None, Some(r)) if r >= next => {
                return Err("replace_nonce must be a nonce that was already signed".into())
            }
            (None, Some(r)) => (r, false),
            (None, None) => (next, true),
        };
        let tx = p.tx.to_tx(nonce)?;
        let vault = self.vault_address(token_id);
        // Review M21 (R21-1): an identical retry of an uncertain nonce is not charged again
        // (commit_execution), so it is checked against the windows without its own earlier
        // charge; otherwise a vault more than half way to its cap could never retry.
        let mut spend = st.spend.clone();
        if self.is_uncertain(token_id, nonce, &hex0x(&tx.signing_hash())) {
            if let Ok(own) = policy::check_with_vault(&st.policy, &policy::SpendState::default(), &tx, now_ms, vault.as_deref()) {
                spend.release(&own);
            }
        }
        let charge = policy::check_with_vault(&st.policy, &spend, &tx, now_ms, vault.as_deref())
            .map_err(|e| format!("Policy now refuses it: {e}"))?;
        Ok(PreparedExecution { tx, charge, from_next })
    }

    /// Takes a ready proposal out of the queue for signing: charges its spend to the current
    /// windows (except an identical retry of an uncertain nonce, which cannot be paid twice),
    /// gives it its nonce and advances the next nonce if that was the one used. One
    /// synchronous step, so two executions can never both fit under the cap (threat 6).
    /// Returns the proposal, the prepared execution and whether the charge was applied.
    fn commit_execution(
        &mut self,
        token_id: &TokenId,
        proposal_id: u64,
        replace_nonce: Option<u64>,
    ) -> (Proposal, PreparedExecution, bool) {
        let now = env::block_timestamp_ms();
        let prep = self
            .prepare_execution(token_id, proposal_id, now, replace_nonce)
            .unwrap_or_else(|e| env::panic_str(&e));
        let charged = !self.is_uncertain(token_id, prep.tx.nonce, &hex0x(&prep.tx.signing_hash()));
        let mut st = self.policies.get(token_id).expect("checked by prepare_execution");
        st.spend.prune_expired(now);
        if charged {
            st.spend.reserve(&prep.charge, now);
        }
        let i = st.proposals.iter().position(|p| p.id == proposal_id).expect("checked");
        let p = st.proposals.remove(i);
        self.policies.insert(token_id, &st);
        self.pinned.remove(&proposal_id);
        if prep.from_next {
            self.nonces.insert(token_id, &(prep.tx.nonce + 1));
        }
        (p, prep, charged)
    }
}

fn emit_policy_event(event: &str, token_id: &TokenId, extra: near_sdk::serde_json::Value) {
    let mut data = json!({ "token_id": token_id });
    if let (Some(d), Some(e)) = (data.as_object_mut(), extra.as_object()) {
        d.extend(e.clone());
    }
    let ev = json!({ "standard": "policy_vault", "version": "1.0.0", "event": event, "data": [data] });
    env::log_str(&format!("EVENT_JSON:{ev}"));
}

fn refund_if_any(to: &AccountId, amount: NearToken) {
    if amount > NearToken::from_yoctonear(1) {
        Promise::new(to.clone()).transfer(amount).detach();
    }
}

/// Charges the caller for storage this call added (from the attached deposit, refunding the
/// rest), or gives the storage it freed back to `freed_to` (the vault owner, who paid for it).
fn settle_storage(before: u64, freed_to: &AccountId) {
    let after = env::storage_usage();
    let price = env::storage_byte_cost();
    let attached = env::attached_deposit();
    let caller = env::predecessor_account_id();
    if after > before {
        let cost = price.saturating_mul((after - before).into());
        require!(
            cost <= attached,
            format!("Must attach {} to cover storage", cost.exact_amount_display())
        );
        refund_if_any(&caller, attached.saturating_sub(cost));
    } else {
        refund_if_any(freed_to, price.saturating_mul((before - after).into()));
        refund_if_any(&caller, attached);
    }
}

/// The text after `sale:` in a memo, whatever its capitals, or `None` if the memo binds no sale.
fn sale_binding(memo: &str) -> Option<&str> {
    let m = memo.trim();
    m.get(..5).filter(|p| p.eq_ignore_ascii_case("sale:")).map(|_| &m[5..])
}

fn vault_path_for(token_id: &str) -> String {
    format!("{VAULT_PATH_PREFIX}{token_id}")
}

fn require_token_exists(tokens: &NonFungibleToken, token_id: &TokenId) {
    if tokens.owner_by_id.get(token_id).is_none() {
        env::panic_str("Token not found");
    }
}

/// Refunds the storage deposit of approvals that a transfer cleared (R4).
fn refund_cleared_approvals(owner: &AccountId, approvals: &Option<HashMap<AccountId, u64>>) {
    if let Some(a) = approvals {
        if !a.is_empty() {
            refund_approved_account_ids(owner.clone(), a).detach();
        }
    }
}

#[near]
impl NonFungibleTokenCore for PolicyVault {
    /// Same checks as the library's `nft_transfer` (it is exactly `assert_one_yocto` plus
    /// `internal_transfer`), but keeps the cleared approvals to refund them and records who
    /// moved the token.
    #[payable]
    fn nft_transfer(
        &mut self,
        receiver_id: AccountId,
        token_id: TokenId,
        approval_id: Option<u64>,
        memo: Option<String>,
    ) {
        assert_one_yocto();
        self.assert_transferable(&token_id, memo.as_deref());
        let sender_id = env::predecessor_account_id();
        let (old_owner, cleared) =
            self.tokens.internal_transfer(&sender_id, &receiver_id, &token_id, approval_id, memo);
        refund_cleared_approvals(&old_owner, &cleared);
        let authorized = (sender_id != old_owner).then_some(sender_id);
        self.record_transfer(&token_id, "transfer", &old_owner, &receiver_id, authorized);
    }

    /// Same steps as the library's `nft_transfer_call` (transfer, call `nft_on_transfer` with all
    /// the remaining gas, then `nft_resolve_transfer`), with two changes: the resolution gets
    /// `GAS_FOR_RESOLVE_TRANSFER` instead of 5 Tgas, and the vault is locked for owner actions
    /// until it resolves (general review H1), so the receiver cannot spend and hand it back.
    #[payable]
    fn nft_transfer_call(
        &mut self,
        receiver_id: AccountId,
        token_id: TokenId,
        approval_id: Option<u64>,
        memo: Option<String>,
        msg: String,
    ) -> PromiseOrValue<bool> {
        assert_one_yocto();
        require!(
            env::prepaid_gas() >= MIN_PREPAID_GAS_FOR_TRANSFER_CALL,
            "Attach at least 50 Tgas to nft_transfer_call"
        );
        self.assert_transferable(&token_id, memo.as_deref());
        let sender_id = env::predecessor_account_id();
        let (old_owner, old_approvals) =
            self.tokens.internal_transfer(&sender_id, &receiver_id, &token_id, approval_id, memo);
        let authorized = (sender_id != old_owner).then_some(sender_id.clone());
        self.record_transfer(&token_id, "transfer_call", &old_owner, &receiver_id, authorized);
        self.transfer_calls.insert(&token_id, &env::block_timestamp_ms());
        ext_nft_receiver::ext(receiver_id.clone())
            .with_unused_gas_weight(1)
            .nft_on_transfer(sender_id, old_owner.clone(), token_id.clone(), msg)
            .then(
                ext_nft_resolver::ext(env::current_account_id())
                    .with_static_gas(GAS_FOR_RESOLVE_TRANSFER)
                    .with_unused_gas_weight(0)
                    .nft_resolve_transfer(old_owner, receiver_id, token_id, old_approvals),
            )
            .into()
    }

    fn nft_token(&self, token_id: TokenId) -> Option<Token> {
        self.tokens.nft_token(token_id)
    }
}

#[near]
impl NonFungibleTokenResolver for PolicyVault {
    /// Returns true if the receiver kept the token. In that case the previous owner's cleared
    /// approvals are refunded (R4; the library refunds them only when the token is burned).
    /// If the token went back, the library restores those approvals and this contract records
    /// the return.
    #[private]
    fn nft_resolve_transfer(
        &mut self,
        previous_owner_id: AccountId,
        receiver_id: AccountId,
        token_id: TokenId,
        approved_account_ids: Option<HashMap<AccountId, u64>>,
    ) -> bool {
        // H1: the transfer_call has resolved; whoever owns the vault now can act again.
        self.transfer_calls.remove(&token_id);
        let cleared = approved_account_ids.clone();
        let kept = self.tokens.nft_resolve_transfer(
            previous_owner_id.clone(),
            receiver_id.clone(),
            token_id.clone(),
            approved_account_ids,
        );
        if kept {
            refund_cleared_approvals(&previous_owner_id, &cleared);
        } else {
            self.record_transfer(
                &token_id,
                "transfer_call_returned",
                &receiver_id,
                &previous_owner_id,
                None,
            );
        }
        kept
    }
}

#[near]
impl NonFungibleTokenApproval for PolicyVault {
    #[payable]
    fn nft_approve(
        &mut self,
        token_id: TokenId,
        account_id: AccountId,
        msg: Option<String>,
    ) -> Option<Promise> {
        require_token_exists(&self.tokens, &token_id);
        self.assert_no_transfer_call(&token_id);
        self.tokens.nft_approve(token_id, account_id, msg)
    }

    #[payable]
    fn nft_revoke(&mut self, token_id: TokenId, account_id: AccountId) {
        require_token_exists(&self.tokens, &token_id);
        self.assert_no_transfer_call(&token_id);
        self.tokens.nft_revoke(token_id, account_id)
    }

    #[payable]
    fn nft_revoke_all(&mut self, token_id: TokenId) {
        require_token_exists(&self.tokens, &token_id);
        self.assert_no_transfer_call(&token_id);
        self.tokens.nft_revoke_all(token_id)
    }

    fn nft_is_approved(
        &self,
        token_id: TokenId,
        approved_account_id: AccountId,
        approval_id: Option<u64>,
    ) -> bool {
        self.tokens.nft_is_approved(token_id, approved_account_id, approval_id)
    }
}

#[near]
impl NonFungibleTokenEnumeration for PolicyVault {
    fn nft_total_supply(&self) -> U128 {
        self.tokens.nft_total_supply()
    }

    fn nft_tokens(&self, from_index: Option<U128>, limit: Option<u64>) -> Vec<Token> {
        self.tokens.nft_tokens(from_index, limit)
    }

    fn nft_supply_for_owner(&self, account_id: AccountId) -> U128 {
        self.tokens.nft_supply_for_owner(account_id)
    }

    fn nft_tokens_for_owner(
        &self,
        account_id: AccountId,
        from_index: Option<U128>,
        limit: Option<u64>,
    ) -> Vec<Token> {
        self.tokens.nft_tokens_for_owner(account_id, from_index, limit)
    }
}

#[near]
impl NonFungibleTokenMetadataProvider for PolicyVault {
    fn nft_metadata(&self) -> NFTContractMetadata {
        self.metadata.get().expect("metadata is set at init")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use near_contract_standards::non_fungible_token::bytes_for_approved_account_id;
    use near_sdk::mock::MockAction;
    use near_sdk::test_utils::{accounts, get_created_receipts, get_logs, VMContextBuilder};
    use near_sdk::testing_env;

    const STORAGE_DEPOSIT: NearToken = NearToken::from_millinear(100); // 0.1 NEAR, refunded excess
    const ONE_YOCTO: NearToken = NearToken::from_yoctonear(1);

    fn signer() -> AccountId {
        "v1.signer-prod.testnet".parse().unwrap()
    }

    /// Real answer of v1.signer-prod.testnet for path vault-0 and predecessor
    /// m3.alan-vault-2026.testnet (queried on 2026-11-05). Its address was computed
    /// independently with viem (scripts/derive-address.mjs).
    const VAULT0_KEY: &str = "secp256k1:4yjHrZfCB7ieEjybG2ydzAeWxn6EyeUd81Uv6TiYzW3WBcjRH27cZRVWxvTu3EujBSnJ9SJspDu5BVJWk2aoqdJp";
    const VAULT0_ADDRESS: &str = "0xb4bbbae0c0e057f0d85233d9394088e449d5b843";

    /// Most tests are about something other than the sale: this opens an always-open sale
    /// window for vault 0 of its current owner. The real sale flow is tested in the M8 tests.
    fn open_sale(c: &mut PolicyVault) {
        let epoch = c.owner_epoch(&"0".to_string());
        c.sales.insert(
            &"0".to_string(),
            &Sale { sale_id: 9_999, started_ms: 0, opens_at_ms: 0, closes_at_ms: u64::MAX, owner_epoch: epoch, price: None, buyer: None },
        );
    }

    fn ctx(predecessor: AccountId, deposit: NearToken) {
        let mut b = VMContextBuilder::new();
        b.current_account_id("vault.testnet".parse().unwrap())
            .predecessor_account_id(predecessor)
            .attached_deposit(deposit);
        testing_env!(b.build());
    }

    fn setup_with_vault(owner: AccountId) -> PolicyVault {
        ctx(accounts(0), NearToken::from_yoctonear(0));
        let mut c = PolicyVault::new(signer());
        ctx(owner, STORAGE_DEPOSIT);
        c.mint_vault();
        c
    }

    /// All NEAR transfers created by the last call, as (receiver, amount).
    fn transfers() -> Vec<(AccountId, NearToken)> {
        get_created_receipts()
            .into_iter()
            .flat_map(|r| {
                let to = r.receiver_id.clone();
                r.actions.into_iter().filter_map(move |a| match a {
                    MockAction::Transfer { deposit, .. } => Some((to.clone(), deposit)),
                    _ => None,
                })
            })
            .collect()
    }

    fn vault_events() -> Vec<String> {
        get_logs().into_iter().filter(|l| l.contains("\"vault_transfer\"")).collect()
    }

    fn approve(c: &mut PolicyVault, owner: &AccountId, who: &AccountId) {
        ctx(owner.clone(), STORAGE_DEPOSIT);
        c.nft_approve("0".to_string(), who.clone(), None);
    }

    // ---------- mint ----------

    #[test]
    fn mint_gives_sequential_ids_owner_and_path() {
        let alice = accounts(1);
        let mut c = setup_with_vault(alice.clone());
        ctx(alice.clone(), STORAGE_DEPOSIT);
        let second = c.mint_vault();
        assert_eq!(second.token_id, "1");
        let first = c.nft_token("0".to_string()).unwrap();
        assert_eq!(first.owner_id, alice);
        assert_eq!(c.vault_path("0".to_string()), "vault-0");
        assert_eq!(c.vault_path("1".to_string()), "vault-1");
        assert_eq!(c.nft_total_supply(), U128(2));
        assert_eq!(c.nft_tokens_for_owner(alice, None, None).len(), 2);
    }

    #[test]
    fn mint_emits_nep171_event() {
        let _c = setup_with_vault(accounts(1));
        let logs = get_logs();
        assert!(
            logs.iter().any(|l| l.starts_with("EVENT_JSON:") && l.contains("\"nft_mint\"")),
            "no nft_mint event in {logs:?}"
        );
    }

    #[test]
    #[should_panic(expected = "to cover storage")]
    fn mint_without_storage_deposit_fails() {
        ctx(accounts(0), NearToken::from_yoctonear(0));
        let mut c = PolicyVault::new(signer());
        ctx(accounts(1), NearToken::from_yoctonear(0));
        c.mint_vault();
    }

    /// R3: the minter gets back exactly the deposit minus storage (token + reserve).
    #[test]
    fn mint_refunds_the_excess_to_the_minter() {
        ctx(accounts(0), NearToken::from_yoctonear(0));
        let mut c = PolicyVault::new(signer());
        ctx(accounts(1), STORAGE_DEPOSIT);
        let before = env::storage_usage();
        c.mint_vault();
        let used = env::storage_usage() - before + TRANSFER_RECORD_RESERVE_BYTES;
        let expected = STORAGE_DEPOSIT.saturating_sub(env::storage_byte_cost().saturating_mul(used.into()));
        let t = transfers();
        assert_eq!(t, vec![(accounts(1), expected)], "refund must go to the minter, exact amount");
    }

    /// R6: ids keep increasing whatever happens to existing tokens.
    #[test]
    fn token_ids_are_never_reused() {
        let (alice, bob) = (accounts(1), accounts(2));
        let mut c = setup_with_vault(alice.clone());
        ctx(alice.clone(), ONE_YOCTO);
        open_sale(&mut c);
        c.nft_transfer(bob.clone(), "0".to_string(), None, None);
        ctx(bob.clone(), STORAGE_DEPOSIT);
        assert_eq!(c.mint_vault().token_id, "1");
        ctx(alice, STORAGE_DEPOSIT);
        assert_eq!(c.mint_vault().token_id, "2");
    }

    #[test]
    fn token_description_does_not_claim_signing() {
        let c = setup_with_vault(accounts(1));
        let d = c.nft_token("0".to_string()).unwrap().metadata.unwrap().description.unwrap();
        assert!(d.contains("path vault-0"), "{d}");
        assert!(!d.to_lowercase().contains("controls"), "R7: description overclaims: {d}");
    }

    // ---------- transfer ----------

    #[test]
    fn owner_transfer_changes_owner_and_emits_event() {
        let (alice, bob) = (accounts(1), accounts(2));
        let mut c = setup_with_vault(alice.clone());
        ctx(alice.clone(), ONE_YOCTO);
        open_sale(&mut c);
        c.nft_transfer(bob.clone(), "0".to_string(), None, None);
        assert_eq!(c.nft_token("0".to_string()).unwrap().owner_id, bob);
        assert_eq!(c.nft_supply_for_owner(alice), U128(0));
        assert!(get_logs().iter().any(|l| l.contains("\"nft_transfer\"")));
    }

    #[test]
    #[should_panic(expected = "Requires attached deposit of exactly 1 yoctoNEAR")]
    fn transfer_without_one_yocto_fails() {
        let alice = accounts(1);
        let mut c = setup_with_vault(alice.clone());
        ctx(alice, NearToken::from_yoctonear(0));
        open_sale(&mut c);
        c.nft_transfer(accounts(2), "0".to_string(), None, None);
    }

    #[test]
    #[should_panic(expected = "Sender not approved")]
    fn stranger_cannot_transfer() {
        let mut c = setup_with_vault(accounts(1));
        ctx(accounts(3), ONE_YOCTO);
        open_sale(&mut c);
        c.nft_transfer(accounts(3), "0".to_string(), None, None);
    }

    #[test]
    #[should_panic(expected = "Token not found")]
    fn transfer_of_missing_token_fails() {
        let mut c = setup_with_vault(accounts(1));
        ctx(accounts(1), ONE_YOCTO);
        open_sale(&mut c);
        c.nft_transfer(accounts(2), "99".to_string(), None, None);
    }

    /// R3
    #[test]
    #[should_panic(expected = "Current and next owner must differ")]
    fn transfer_to_self_fails() {
        let alice = accounts(1);
        let mut c = setup_with_vault(alice.clone());
        ctx(alice.clone(), ONE_YOCTO);
        open_sale(&mut c);
        c.nft_transfer(alice, "0".to_string(), None, None);
    }

    // ---------- R1: own transfer record and complete event ----------

    #[test]
    fn library_event_lacks_authorized_id_but_ours_has_it() {
        let (alice, bob, carol) = (accounts(1), accounts(2), accounts(3));
        let mut c = setup_with_vault(alice.clone());
        approve(&mut c, &alice, &bob);
        ctx(bob.clone(), ONE_YOCTO);
        open_sale(&mut c);
        c.nft_transfer(carol.clone(), "0".to_string(), None, None);

        let lib_event = get_logs().into_iter().find(|l| l.contains("\"nft_transfer\"")).unwrap();
        // Documents the upstream bug in near-contract-standards 5.30.0. If this assertion starts
        // failing, the library was fixed and R1's workaround can be reconsidered.
        assert!(!lib_event.contains("authorized_id"), "library now emits authorized_id: {lib_event}");

        let ours = vault_events();
        assert_eq!(ours.len(), 1);
        assert!(ours[0].contains(&format!("\"authorized_id\":\"{bob}\"")), "{}", ours[0]);

        let info = c.vault_transfer_info("0".to_string()).unwrap();
        assert_eq!(info.count, 1);
        let last = info.last.unwrap();
        assert_eq!((last.kind.as_str(), &last.from, &last.to), ("transfer", &alice, &carol));
        assert_eq!(last.authorized_id, Some(bob));
    }

    #[test]
    fn owner_transfer_records_no_authorized_id() {
        let (alice, bob) = (accounts(1), accounts(2));
        let mut c = setup_with_vault(alice.clone());
        ctx(alice, ONE_YOCTO);
        open_sale(&mut c);
        c.nft_transfer(bob, "0".to_string(), None, None);
        let ours = vault_events();
        assert!(ours[0].contains("\"authorized_id\":null"), "{}", ours[0]);
        assert_eq!(c.vault_transfer_info("0".to_string()).unwrap().last.unwrap().authorized_id, None);
    }

    #[test]
    fn new_vault_has_empty_transfer_record() {
        let c = setup_with_vault(accounts(1));
        assert_eq!(c.vault_transfer_info("0".to_string()), Some(TransferInfo::default()));
    }

    // ---------- approvals ----------

    #[test]
    fn transfer_clears_approvals() {
        let (alice, bob, carol) = (accounts(1), accounts(2), accounts(3));
        let mut c = setup_with_vault(alice.clone());
        approve(&mut c, &alice, &bob);
        assert!(c.nft_is_approved("0".to_string(), bob.clone(), None));
        ctx(alice, ONE_YOCTO);
        open_sale(&mut c);
        c.nft_transfer(carol, "0".to_string(), None, None);
        assert!(
            !c.nft_is_approved("0".to_string(), bob, None),
            "an approval from the previous owner survived the transfer"
        );
    }

    #[test]
    #[should_panic(expected = "Sender not approved")]
    fn approval_of_previous_owner_cannot_move_token_after_sale() {
        let (alice, bob, carol) = (accounts(1), accounts(2), accounts(3));
        let mut c = setup_with_vault(alice.clone());
        approve(&mut c, &alice, &bob);
        ctx(alice.clone(), ONE_YOCTO);
        open_sale(&mut c);
        c.nft_transfer(carol, "0".to_string(), None, None);
        // bob was approved by alice; carol now owns the vault, so bob must be rejected.
        ctx(bob, ONE_YOCTO);
        open_sale(&mut c);
        c.nft_transfer(alice, "0".to_string(), None, None);
    }

    #[test]
    fn approved_account_can_transfer_once() {
        let (alice, bob, carol) = (accounts(1), accounts(2), accounts(3));
        let mut c = setup_with_vault(alice.clone());
        approve(&mut c, &alice, &bob);
        ctx(bob.clone(), ONE_YOCTO);
        open_sale(&mut c);
        c.nft_transfer(carol.clone(), "0".to_string(), Some(1), None);
        assert_eq!(c.nft_token("0".to_string()).unwrap().owner_id, carol);
        assert!(!c.nft_is_approved("0".to_string(), bob, None));
    }

    #[test]
    #[should_panic(expected = "Predecessor must be token owner.")]
    fn only_owner_can_approve() {
        let mut c = setup_with_vault(accounts(1));
        ctx(accounts(2), STORAGE_DEPOSIT);
        c.nft_approve("0".to_string(), accounts(2), None);
    }

    /// R4: the storage paid for approvals goes back to the owner who paid it.
    #[test]
    fn transfer_refunds_cleared_approvals_to_previous_owner() {
        let (alice, bob, carol, danny) = (accounts(1), accounts(2), accounts(3), accounts(4));
        let mut c = setup_with_vault(alice.clone());
        approve(&mut c, &alice, &bob);
        approve(&mut c, &alice, &danny);
        ctx(alice.clone(), ONE_YOCTO);
        let sale_refund = sale_storage_cost(&mut c);
        c.nft_transfer(carol, "0".to_string(), None, None);
        let bytes = bytes_for_approved_account_id(&bob) + bytes_for_approved_account_id(&danny);
        let expected = env::storage_byte_cost().saturating_mul(bytes.into());
        // The approvals' deposit (R4) and the sale record's deposit (M8) both go back to alice.
        assert_eq!(transfers(), vec![(alice.clone(), expected), (alice, sale_refund)]);
    }

    #[test]
    fn transfer_without_approvals_refunds_only_the_sale_record() {
        let (alice, bob) = (accounts(1), accounts(2));
        let mut c = setup_with_vault(alice.clone());
        ctx(alice.clone(), ONE_YOCTO);
        let sale_refund = sale_storage_cost(&mut c);
        c.nft_transfer(bob, "0".to_string(), None, None);
        assert_eq!(transfers(), vec![(alice, sale_refund)]);
    }

    /// Opens a sale for vault 0 and returns what its record costs in storage (refunded to the
    /// seller when the transfer ends the sale).
    fn sale_storage_cost(c: &mut PolicyVault) -> NearToken {
        let before = env::storage_usage();
        open_sale(c);
        env::storage_byte_cost().saturating_mul((env::storage_usage() - before).into())
    }

    /// R3
    #[test]
    fn revoke_removes_one_approval() {
        let (alice, bob, carol) = (accounts(1), accounts(2), accounts(3));
        let mut c = setup_with_vault(alice.clone());
        approve(&mut c, &alice, &bob);
        approve(&mut c, &alice, &carol);
        ctx(alice, ONE_YOCTO);
        c.nft_revoke("0".to_string(), bob.clone());
        assert!(!c.nft_is_approved("0".to_string(), bob, None));
        assert!(c.nft_is_approved("0".to_string(), carol, None));
    }

    /// R3
    #[test]
    fn revoke_all_removes_every_approval() {
        let (alice, bob, carol) = (accounts(1), accounts(2), accounts(3));
        let mut c = setup_with_vault(alice.clone());
        approve(&mut c, &alice, &bob);
        approve(&mut c, &alice, &carol);
        ctx(alice, ONE_YOCTO);
        c.nft_revoke_all("0".to_string());
        assert!(!c.nft_is_approved("0".to_string(), bob, None));
        assert!(!c.nft_is_approved("0".to_string(), carol, None));
    }

    /// R3
    #[test]
    #[should_panic(expected = "Requires attached deposit of exactly 1 yoctoNEAR")]
    fn revoke_requires_one_yocto() {
        let (alice, bob) = (accounts(1), accounts(2));
        let mut c = setup_with_vault(alice.clone());
        approve(&mut c, &alice, &bob);
        ctx(alice, NearToken::from_yoctonear(0));
        c.nft_revoke("0".to_string(), bob);
    }

    #[test]
    #[should_panic(expected = "Token not found")]
    fn vault_path_of_missing_token_fails() {
        let c = setup_with_vault(accounts(1));
        c.vault_path("7".to_string());
    }

    // ---------- M4: vault address from the signer ----------

    fn function_calls() -> Vec<(AccountId, String, String)> {
        get_created_receipts()
            .into_iter()
            .flat_map(|r| {
                let to = r.receiver_id.clone();
                r.actions.into_iter().filter_map(move |a| match a {
                    MockAction::FunctionCallWeight { method_name, args, .. } => Some((
                        to.clone(),
                        String::from_utf8(method_name).unwrap(),
                        String::from_utf8(args).unwrap(),
                    )),
                    _ => None,
                })
            })
            .collect()
    }

    #[test]
    fn parse_and_address_match_viem_for_real_vault0_key() {
        let key = parse_secp256k1_key(VAULT0_KEY).expect("real key must parse");
        assert_eq!(hex0x(&evm_address_of(&key)), VAULT0_ADDRESS);
    }

    #[test]
    fn parse_rejects_malformed_keys() {
        assert!(parse_secp256k1_key("ed25519:4yjHrZfCB7ieEjybG2ydzAeWxn6E").is_none());
        assert!(parse_secp256k1_key("secp256k1:0OIl").is_none(), "not base58");
        assert!(parse_secp256k1_key("secp256k1:4yjHrZfCB7ieEjy").is_none(), "too short");
        let long = format!("{}11", VAULT0_KEY);
        assert!(parse_secp256k1_key(&long).is_none(), "too long");
    }

    #[test]
    fn mint_asks_the_signer_for_this_vaults_key() {
        let _c = setup_with_vault(accounts(1));
        let calls = function_calls();
        let to_signer: Vec<_> = calls.iter().filter(|(to, _, _)| *to == signer()).collect();
        assert_eq!(to_signer.len(), 1, "{calls:?}");
        let (_, method, args) = to_signer[0];
        assert_eq!(method, "derived_public_key");
        let args: near_sdk::serde_json::Value = near_sdk::serde_json::from_str(args).unwrap();
        assert_eq!(args["path"], "vault-0");
        assert_eq!(args["predecessor"], "vault.testnet");
        assert_eq!(args["domain_id"], 0);
        assert!(calls.iter().any(|(_, m, _)| m == "on_derived_key"), "callback missing");
    }

    #[test]
    fn new_vault_is_unresolved_until_the_signer_answers() {
        let c = setup_with_vault(accounts(1));
        let info = c.vault_info("0".to_string());
        assert_eq!(info.path, "vault-0");
        assert_eq!(info.signer_id, signer());
        assert_eq!((info.public_key, info.evm_address), (None, None));
    }

    #[test]
    fn callback_stores_key_address_and_emits_event() {
        let mut c = setup_with_vault(accounts(1));
        assert!(c.on_derived_key("0".to_string(), Ok(VAULT0_KEY.to_string())));
        let info = c.vault_info("0".to_string());
        assert_eq!(info.public_key.as_deref(), Some(VAULT0_KEY));
        assert_eq!(info.evm_address.as_deref(), Some(VAULT0_ADDRESS));
        assert!(get_logs().iter().any(|l| l.contains("\"vault_address\"") && l.contains(VAULT0_ADDRESS)));
    }

    #[test]
    fn failed_or_malformed_answer_leaves_vault_unresolved() {
        let mut c = setup_with_vault(accounts(1));
        assert!(!c.on_derived_key("0".to_string(), Err(PromiseError::Failed)));
        assert!(!c.on_derived_key("0".to_string(), Ok("secp256k1:garbage0".to_string())));
        assert_eq!(c.vault_info("0".to_string()).evm_address, None);
    }

    #[test]
    fn resolved_address_is_never_overwritten() {
        let mut c = setup_with_vault(accounts(1));
        assert!(c.on_derived_key("0".to_string(), Ok(VAULT0_KEY.to_string())));
        // A different valid key arriving later (e.g. a stale retry) must not replace it.
        let other = format!("secp256k1:{}", bs58::encode([7u8; 64]).into_string());
        assert!(!c.on_derived_key("0".to_string(), Ok(other)));
        assert_eq!(c.vault_info("0".to_string()).evm_address.as_deref(), Some(VAULT0_ADDRESS));
    }

    #[test]
    #[should_panic(expected = "Vault address already resolved")]
    fn resolve_on_resolved_vault_fails() {
        let mut c = setup_with_vault(accounts(1));
        c.on_derived_key("0".to_string(), Ok(VAULT0_KEY.to_string()));
        ctx(accounts(2), NearToken::from_yoctonear(0));
        let _ = c.resolve_vault_address("0".to_string());
    }

    #[test]
    fn resolve_retries_an_unresolved_vault() {
        let mut c = setup_with_vault(accounts(1));
        ctx(accounts(2), NearToken::from_yoctonear(0)); // anyone may retry, no deposit needed
        let _ = c.resolve_vault_address("0".to_string());
        assert!(function_calls().iter().any(|(to, m, _)| *to == signer() && m == "derived_public_key"));
    }

    #[test]
    #[should_panic(expected = "Token not found")]
    fn vault_info_of_missing_token_fails() {
        let c = setup_with_vault(accounts(1));
        c.vault_info("9".to_string());
    }

    #[test]
    fn resolving_does_not_grow_storage() {
        // The placeholder written at mint is fixed-size, so its storage was already paid.
        let mut c = setup_with_vault(accounts(1));
        let before = env::storage_usage();
        c.on_derived_key("0".to_string(), Ok(VAULT0_KEY.to_string()));
        assert_eq!(env::storage_usage(), before, "resolving changed storage size");
    }

    // ---------- M5: policy in the contract ----------

    const HOUR_MS: u64 = 3_600_000;
    const T0_MS: u64 = 1_800_000_000_000;
    const DEST: &str = "0x1111111111111111111111111111111111111111";
    const POLICY_DEPOSIT: NearToken = NearToken::from_millinear(50);

    fn ctx_at(predecessor: AccountId, deposit: NearToken, ms: u64) {
        let mut b = VMContextBuilder::new();
        b.current_account_id("vault.testnet".parse().unwrap())
            .predecessor_account_id(predecessor)
            .attached_deposit(deposit)
            .block_timestamp(ms * 1_000_000);
        testing_env!(b.build());
    }

    fn guardian() -> AccountId {
        accounts(4)
    }

    fn test_policy(cap_wei: u128) -> Policy {
        Policy {
            chain_id: 11155111,
            delay_ms: HOUR_MS,
            guardian: Some(guardian()),
            eth_daily_cap: U128(cap_wei),
            max_gas_cost: U128(21_000 * 50_000_000_000),
            allowed_destinations: vec![DEST.into()],
            allowed_spenders: vec![],
            tokens: vec![],
            proposer: None,
            nfts: vec![],
        }
    }

    fn tx_input(value: u128) -> TxInput {
        TxInput {
            chain_id: 11155111,
            nonce: 0,
            max_priority_fee_per_gas: U128(1_000_000_000),
            max_fee_per_gas: U128(20_000_000_000),
            gas_limit: 21_000,
            to: DEST.into(),
            value: U128(value),
            data: "0x".into(),
        }
    }

    /// Vault 0 owned by `alice` with `test_policy(0.1 ETH)` in force.
    fn vault_with_policy() -> (PolicyVault, AccountId) {
        let alice = accounts(1);
        let mut c = setup_with_vault(alice.clone());
        ctx_at(alice.clone(), POLICY_DEPOSIT, T0_MS);
        assert!(c.set_policy("0".into(), test_policy(100_000_000_000_000_000)), "first policy must apply at once");
        (c, alice)
    }

    #[test]
    fn new_vault_is_locked() {
        let c = setup_with_vault(accounts(1));
        let v = c.get_policy("0".into());
        assert!(!v.has_policy);
        let r = c.check_transaction("0".into(), tx_input(1));
        assert!(!r.allowed);
        assert_eq!(r.reason.as_deref(), Some("vault has no policy (locked)"));
    }

    #[test]
    fn first_policy_applies_at_once_and_charges_storage() {
        let (c, alice) = vault_with_policy();
        let v = c.get_policy("0".into());
        assert!(v.has_policy && v.pending.is_none());
        assert_eq!(v.policy.guardian, Some(guardian()));
        let t = transfers();
        assert_eq!(t.len(), 1, "excess deposit refunded once: {t:?}");
        assert_eq!(t[0].0, alice);
        assert!(t[0].1 < POLICY_DEPOSIT, "storage must have been charged");
    }

    #[test]
    #[should_panic(expected = "Only the vault owner can do this")]
    fn stranger_cannot_set_policy() {
        let mut c = setup_with_vault(accounts(1));
        ctx_at(accounts(2), POLICY_DEPOSIT, T0_MS);
        c.set_policy("0".into(), test_policy(1));
    }

    #[test]
    #[should_panic(expected = "Requires attached deposit of at least 1 yoctoNEAR")]
    fn set_policy_needs_a_deposit() {
        let mut c = setup_with_vault(accounts(1));
        ctx_at(accounts(1), NearToken::from_yoctonear(0), T0_MS);
        c.set_policy("0".into(), test_policy(1));
    }

    #[test]
    #[should_panic(expected = "invalid policy: chain_id must not be 0")]
    fn invalid_policy_is_rejected() {
        let mut c = setup_with_vault(accounts(1));
        ctx_at(accounts(1), POLICY_DEPOSIT, T0_MS);
        let mut p = test_policy(1);
        p.chain_id = 0;
        c.set_policy("0".into(), p);
    }

    #[test]
    #[should_panic(expected = "to cover storage")]
    fn set_policy_without_enough_for_storage_fails() {
        let mut c = setup_with_vault(accounts(1));
        ctx_at(accounts(1), NearToken::from_yoctonear(1), T0_MS);
        c.set_policy("0".into(), test_policy(1));
    }

    #[test]
    fn loosening_waits_the_delay_then_applies() {
        let (mut c, alice) = vault_with_policy();
        ctx_at(alice, POLICY_DEPOSIT, T0_MS + 10);
        assert!(!c.set_policy("0".into(), test_policy(10_u128.pow(18))), "raising the cap must wait");
        let v = c.get_policy("0".into());
        assert_eq!(v.policy.eth_daily_cap.0, 100_000_000_000_000_000, "old cap still in force");
        assert_eq!(v.pending.as_ref().unwrap().apply_after_ms, T0_MS + 10 + HOUR_MS);
        // anyone may apply it once the delay has passed
        ctx_at(accounts(3), NearToken::from_yoctonear(0), T0_MS + 10 + HOUR_MS);
        c.apply_policy("0".into());
        let v = c.get_policy("0".into());
        assert_eq!(v.policy.eth_daily_cap.0, 10_u128.pow(18));
        assert!(v.pending.is_none());
    }

    #[test]
    #[should_panic(expected = "Pending policy not ready yet")]
    fn pending_policy_cannot_apply_early() {
        let (mut c, alice) = vault_with_policy();
        ctx_at(alice, POLICY_DEPOSIT, T0_MS + 10);
        c.set_policy("0".into(), test_policy(10_u128.pow(18)));
        ctx_at(accounts(3), NearToken::from_yoctonear(0), T0_MS + 10 + HOUR_MS - 1);
        c.apply_policy("0".into());
    }

    #[test]
    fn tightening_applies_at_once_and_drops_pending() {
        let (mut c, alice) = vault_with_policy();
        ctx_at(alice.clone(), POLICY_DEPOSIT, T0_MS + 10);
        c.set_policy("0".into(), test_policy(10_u128.pow(18)));
        ctx_at(alice, POLICY_DEPOSIT, T0_MS + 20);
        assert!(c.set_policy("0".into(), test_policy(1)), "lowering the cap applies at once");
        let v = c.get_policy("0".into());
        assert_eq!(v.policy.eth_daily_cap.0, 1);
        assert!(v.pending.is_none());
    }

    #[test]
    fn removing_the_guardian_is_a_loosening() {
        let (mut c, alice) = vault_with_policy();
        ctx_at(alice, POLICY_DEPOSIT, T0_MS + 10);
        let mut p = test_policy(100_000_000_000_000_000);
        p.guardian = None;
        assert!(!c.set_policy("0".into(), p));
        assert_eq!(c.get_policy("0".into()).policy.guardian, Some(guardian()));
    }

    #[test]
    fn guardian_vetoes_a_pending_change_and_owner_gets_storage_back() {
        let (mut c, alice) = vault_with_policy();
        ctx_at(alice.clone(), POLICY_DEPOSIT, T0_MS + 10);
        c.set_policy("0".into(), test_policy(10_u128.pow(18)));
        ctx_at(guardian(), ONE_YOCTO, T0_MS + 20);
        c.veto_pending_policy("0".into());
        assert!(c.get_policy("0".into()).pending.is_none());
        let t = transfers();
        assert!(t.iter().any(|(to, _)| *to == alice), "freed storage must go to the owner: {t:?}");
        assert!(get_logs().iter().any(|l| l.contains("\"policy_vetoed\"")));
    }

    #[test]
    #[should_panic(expected = "Only the guardian can veto")]
    fn stranger_cannot_veto() {
        let (mut c, alice) = vault_with_policy();
        ctx_at(alice, POLICY_DEPOSIT, T0_MS + 10);
        c.set_policy("0".into(), test_policy(10_u128.pow(18)));
        ctx_at(accounts(3), ONE_YOCTO, T0_MS + 20);
        c.veto_pending_policy("0".into());
    }

    #[test]
    #[should_panic(expected = "Only the guardian can veto")]
    fn owner_cannot_veto_as_guardian() {
        let (mut c, alice) = vault_with_policy();
        ctx_at(alice.clone(), POLICY_DEPOSIT, T0_MS + 10);
        c.set_policy("0".into(), test_policy(10_u128.pow(18)));
        ctx_at(alice, ONE_YOCTO, T0_MS + 20);
        c.veto_pending_policy("0".into());
    }

    #[test]
    fn owner_cancels_a_pending_change() {
        let (mut c, alice) = vault_with_policy();
        ctx_at(alice.clone(), POLICY_DEPOSIT, T0_MS + 10);
        c.set_policy("0".into(), test_policy(10_u128.pow(18)));
        ctx_at(alice, ONE_YOCTO, T0_MS + 20);
        c.cancel_pending_policy("0".into());
        assert!(c.get_policy("0".into()).pending.is_none());
    }

    #[test]
    fn check_transaction_allows_and_returns_the_signing_hash() {
        let (c, _) = vault_with_policy();
        let input = tx_input(10_000_000_000_000_000);
        let r = c.check_transaction("0".into(), input.clone());
        assert!(r.allowed, "{r:?}");
        let expected = hex0x(&input.to_tx().unwrap().signing_hash());
        assert_eq!(r.signing_hash.as_deref(), Some(expected.as_str()));
        assert_eq!(r.reservation.unwrap().eth.0, 10_000_000_000_000_000 + 20_000_000_000 * 21_000);
    }

    #[test]
    fn check_transaction_explains_refusals() {
        let (c, _) = vault_with_policy();
        let mut stranger = tx_input(1);
        stranger.to = "0x2222222222222222222222222222222222222222".into();
        let mut bad_hex = tx_input(1);
        bad_hex.data = "0xzz".into();
        let mut too_long = tx_input(0);
        too_long.data = format!("0x{}", "00".repeat(197));
        let cases = [
            (tx_input(10_u128.pow(18)), "ETH daily cap exceeded"),
            (stranger, "destination not allowed"),
            (bad_hex, "malformed `data` hex"),
            (too_long, "calldata longer than 196 bytes"),
        ];
        for (input, reason) in cases {
            let r = c.check_transaction("0".into(), input);
            assert!(!r.allowed);
            assert_eq!(r.reason.as_deref(), Some(reason));
        }
    }

    #[test]
    fn transfer_clears_policy_and_refunds_its_storage_to_the_seller() {
        let (mut c, alice) = vault_with_policy();
        ctx_at(alice.clone(), ONE_YOCTO, T0_MS + 10);
        open_sale(&mut c);
        c.nft_transfer(accounts(2), "0".into(), None, None);
        assert!(!c.get_policy("0".into()).has_policy, "buyer must receive a locked vault");
        let t = transfers();
        assert!(t.iter().any(|(to, amount)| *to == alice && *amount > NearToken::from_yoctonear(0)), "{t:?}");
    }

    // ---------- General review H1: no owner action while a transfer_call is unresolved ----------

    /// Alice (with a policy and an open sale) sends vault 0 to bob with `nft_transfer_call`.
    fn transfer_call_to_bob() -> (PolicyVault, AccountId, AccountId) {
        let (mut c, alice) = vault_with_policy();
        let bob = accounts(2);
        open_sale(&mut c);
        ctx_at(alice.clone(), ONE_YOCTO, T0_MS);
        let _ = c.nft_transfer_call(bob.clone(), "0".into(), None, None, "x".into());
        assert_eq!(c.nft_token("0".into()).unwrap().owner_id, bob);
        (c, alice, bob)
    }

    /// Runs `nft_resolve_transfer` as the runtime does, with the receiver's answer
    /// (`true` = give it back, `false` = keep it).
    fn resolve(c: &mut PolicyVault, previous: &AccountId, receiver: &AccountId, give_back: bool, ms: u64) -> bool {
        let mut b = VMContextBuilder::new();
        b.current_account_id("vault.testnet".parse().unwrap())
            .predecessor_account_id("vault.testnet".parse().unwrap())
            .block_timestamp(ms * 1_000_000);
        let answer = if give_back { b"true".to_vec() } else { b"false".to_vec() };
        testing_env!(
            b.build(),
            near_sdk::test_vm_config(),
            near_sdk::RuntimeFeesConfig::test(),
            Default::default(),
            vec![near_sdk::PromiseResult::Successful(answer)]
        );
        c.nft_resolve_transfer(previous.clone(), receiver.clone(), "0".into(), Some(HashMap::new()))
    }

    /// The attack found in the review: the receiver sets a policy with delay 0 (applied at once
    /// on a locked vault) to sign a payment before handing the vault back. It fails at the start.
    #[test]
    #[should_panic(expected = "A transfer_call is in progress for this vault; wait until it resolves")]
    fn a_transfer_call_receiver_cannot_set_a_policy_before_it_resolves() {
        let (mut c, _, bob) = transfer_call_to_bob();
        let mut p = test_policy(1);
        p.delay_ms = 0;
        ctx_at(bob, POLICY_DEPOSIT, T0_MS + 1);
        c.set_policy("0".into(), p);
    }

    #[test]
    #[should_panic(expected = "A transfer_call is in progress for this vault; wait until it resolves")]
    fn a_transfer_call_receiver_cannot_start_a_sale_before_it_resolves() {
        let (mut c, _, bob) = transfer_call_to_bob();
        ctx_at(bob, NearToken::from_millinear(10), T0_MS + 1);
        c.start_sale("0".into(), None, None);
    }

    #[test]
    #[should_panic(expected = "A transfer_call is in progress for this vault; wait until it resolves")]
    fn a_transfer_call_receiver_cannot_approve_before_it_resolves() {
        let (mut c, _, bob) = transfer_call_to_bob();
        ctx_at(bob, NearToken::from_millinear(10), T0_MS + 1);
        let _ = c.nft_approve("0".into(), accounts(3), None);
    }

    #[test]
    #[should_panic(expected = "A transfer_call is in progress for this vault; wait until it resolves")]
    fn a_transfer_call_receiver_cannot_pass_the_vault_on_before_it_resolves() {
        let (mut c, _, bob) = transfer_call_to_bob();
        open_sale(&mut c);
        ctx_at(bob, ONE_YOCTO, T0_MS + 1);
        c.nft_transfer(accounts(3), "0".into(), None, None);
    }

    #[test]
    fn a_receiver_that_keeps_the_vault_owns_it_normally() {
        let (mut c, alice, bob) = transfer_call_to_bob();
        assert!(resolve(&mut c, &alice, &bob, false, T0_MS + 2));
        assert_eq!(c.nft_token("0".into()).unwrap().owner_id, bob);
        ctx_at(bob, POLICY_DEPOSIT, T0_MS + 3);
        assert!(c.set_policy("0".into(), test_policy(1)));
    }

    /// A returned vault comes back without the sender's policy (it ended on the way out, and the
    /// sender got that storage back) and without the lock.
    #[test]
    fn a_returned_vault_comes_back_without_policy_and_unlocked() {
        let (mut c, alice, bob) = transfer_call_to_bob();
        assert!(transfers().iter().any(|(to, _)| *to == alice), "alice got her policy's storage back");
        assert!(!resolve(&mut c, &alice, &bob, true, T0_MS + 2));
        assert_eq!(c.nft_token("0".into()).unwrap().owner_id, alice);
        assert!(!c.get_policy("0".into()).has_policy);
        ctx_at(alice, POLICY_DEPOSIT, T0_MS + 3);
        assert!(c.set_policy("0".into(), test_policy(1)));
    }

    /// If the resolution never runs (its callback ran out of gas, so the receiver keeps the vault),
    /// the lock lapses after an hour.
    #[test]
    fn the_transfer_call_lock_lapses_if_it_never_resolves() {
        let (mut c, _, bob) = transfer_call_to_bob();
        ctx_at(bob, POLICY_DEPOSIT, T0_MS + TRANSFER_CALL_TIMEOUT_MS);
        assert!(c.set_policy("0".into(), test_policy(1)));
    }

    #[test]
    #[should_panic(expected = "Attach at least 50 Tgas to nft_transfer_call")]
    fn transfer_call_needs_gas_for_its_resolution() {
        let alice = accounts(1);
        let mut c = setup_with_vault(alice.clone());
        open_sale(&mut c);
        let mut b = VMContextBuilder::new();
        b.current_account_id("vault.testnet".parse().unwrap())
            .predecessor_account_id(alice)
            .attached_deposit(ONE_YOCTO)
            .prepaid_gas(Gas::from_tgas(30));
        testing_env!(b.build());
        let _ = c.nft_transfer_call(accounts(2), "0".into(), None, None, "x".into());
    }

    /// The resolution gets 20 Tgas, not the library's 5.
    #[test]
    fn transfer_call_gives_its_resolution_enough_gas() {
        let (_, _, _) = transfer_call_to_bob();
        let receipts = get_created_receipts();
        let resolve_gas = receipts
            .iter()
            .flat_map(|r| r.actions.iter())
            .find_map(|a| match a {
                MockAction::FunctionCallWeight { method_name, prepaid_gas, .. } if method_name == b"nft_resolve_transfer" => Some(*prepaid_gas),
                _ => None,
            })
            .expect("a resolve call");
        assert_eq!(resolve_gas, GAS_FOR_RESOLVE_TRANSFER);
    }

    // ---------- M6: proposals ----------

    const ONE_HUNDREDTH_ETH: u128 = 10_000_000_000_000_000;
    const GAS_RESERVE: u128 = 20_000_000_000 * 21_000;

    fn ptx(value: u128) -> ProposalTx {
        let t = tx_input(value);
        ProposalTx {
            chain_id: t.chain_id,
            max_priority_fee_per_gas: t.max_priority_fee_per_gas,
            max_fee_per_gas: t.max_fee_per_gas,
            gas_limit: t.gas_limit,
            to: t.to,
            value: t.value,
            data: t.data,
        }
    }

    fn propose_as(c: &mut PolicyVault, who: &AccountId, value: u128, ms: u64) -> u64 {
        ctx_at(who.clone(), POLICY_DEPOSIT, ms);
        c.propose("0".into(), ptx(value))
    }

    #[test]
    fn propose_queues_without_charging_the_cap() {
        let (mut c, alice) = vault_with_policy();
        let id = propose_as(&mut c, &alice, 4 * ONE_HUNDREDTH_ETH, T0_MS + 10);
        let q = c.list_proposals("0".into());
        assert_eq!(q.len(), 1);
        assert_eq!(q[0].id, id);
        assert_eq!(q[0].executable_after_ms, T0_MS + 10 + HOUR_MS);
        assert_eq!(q[0].reservation.eth.0, 4 * ONE_HUNDREDTH_ETH + GAS_RESERVE, "what it will charge");
        assert_eq!(c.get_policy("0".into()).spend.eth.spent.0, 0, "charged only when signed (P1)");
        assert!(get_logs().iter().any(|l| l.contains("\"proposal_created\"")));
    }

    /// Review P1, the exact scenario that broke the cap: proposals made on different days.
    #[test]
    fn proposals_held_across_days_cannot_be_signed_together_above_the_cap() {
        let (mut c, alice) = vault_with_policy(); // cap 0.1 ETH, delay 1 h
        let a = propose_as(&mut c, &alice, 9 * ONE_HUNDREDTH_ETH, T0_MS + 10);
        let b = propose_as(&mut c, &alice, 9 * ONE_HUNDREDTH_ETH, T0_MS + 10 + policy::DAY_MS);
        ctx_at(alice, NearToken::from_yoctonear(0), T0_MS + 10 + policy::DAY_MS + HOUR_MS);
        assert!(c.check_execution("0".into(), a).ready);
        c.commit_execution(&"0".to_string(), a, None);
        let rb = c.check_execution("0".into(), b);
        assert!(!rb.ready, "0.18 ETH signed in one window with a 0.1 cap");
        assert_eq!(rb.reason.as_deref(), Some("Policy now refuses it: ETH daily cap exceeded"));
    }

    #[test]
    fn signing_charges_the_cap_and_advances_the_nonce() {
        let (mut c, alice) = vault_with_policy();
        let a = propose_as(&mut c, &alice, ONE_HUNDREDTH_ETH, T0_MS + 10);
        let b = propose_as(&mut c, &alice, ONE_HUNDREDTH_ETH, T0_MS + 11);
        ctx_at(alice, NearToken::from_yoctonear(0), T0_MS + 11 + HOUR_MS);
        let (p, prep, _) = c.commit_execution(&"0".to_string(), a, None);
        let (tx, charge) = (prep.tx, prep.charge);
        assert_eq!((p.id, tx.nonce), (a, 0));
        assert_eq!(c.get_policy("0".into()).spend.eth.spent.0, charge.eth.0);
        assert_eq!(c.get_next_nonce("0".into()), 1);
        assert_eq!(c.list_proposals("0".into()).len(), 1, "signed proposal leaves the queue");
        let rb = c.check_execution("0".into(), b);
        assert!(rb.ready);
        assert_eq!(rb.nonce, 1, "the next one gets the next nonce");
    }

    #[test]
    #[should_panic(expected = "Proposal delay has not passed yet")]
    fn commit_respects_the_delay() {
        let (mut c, alice) = vault_with_policy();
        let a = propose_as(&mut c, &alice, 1, T0_MS + 10);
        ctx_at(alice, NearToken::from_yoctonear(0), T0_MS + 10 + HOUR_MS - 1);
        c.commit_execution(&"0".to_string(), a, None);
    }

    /// Review P4.
    #[test]
    fn raising_the_delay_also_holds_queued_proposals() {
        let (mut c, alice) = vault_with_policy(); // delay 1 h
        let a = propose_as(&mut c, &alice, 1, T0_MS + 10);
        let mut slower = test_policy(100_000_000_000_000_000);
        slower.delay_ms = 2 * HOUR_MS;
        ctx_at(alice, POLICY_DEPOSIT, T0_MS + 20);
        assert!(c.set_policy("0".into(), slower), "a longer delay is a tightening");
        ctx_at(accounts(3), NearToken::from_yoctonear(0), T0_MS + 10 + HOUR_MS);
        assert!(!c.check_execution("0".into(), a).ready, "old delay no longer enough");
        ctx_at(accounts(3), NearToken::from_yoctonear(0), T0_MS + 10 + 2 * HOUR_MS);
        assert!(c.check_execution("0".into(), a).ready);
    }

    /// Review P2 at contract level.
    #[test]
    fn unminable_transactions_are_refused() {
        let (c, _) = vault_with_policy();
        let mut t = tx_input(1);
        t.gas_limit = 0;
        assert_eq!(c.check_transaction("0".into(), t).reason.as_deref(), Some("gas_limit below 21000"));
        let mut t = tx_input(1);
        t.max_fee_per_gas = U128(0);
        t.max_priority_fee_per_gas = U128(0);
        assert_eq!(c.check_transaction("0".into(), t).reason.as_deref(), Some("max_fee_per_gas must be above 0"));
    }

    // ---------- review P3: the guardian cannot freeze the vault ----------

    fn without_guardian() -> Policy {
        let mut p = test_policy(100_000_000_000_000_000);
        p.guardian = None;
        p
    }

    #[test]
    #[should_panic(expected = "The guardian cannot veto its own replacement")]
    fn guardian_cannot_veto_its_own_replacement() {
        let (mut c, alice) = vault_with_policy();
        ctx_at(alice, POLICY_DEPOSIT, T0_MS + 10);
        assert!(!c.set_policy("0".into(), without_guardian()));
        ctx_at(guardian(), ONE_YOCTO, T0_MS + 20);
        c.veto_pending_policy("0".into());
    }

    #[test]
    fn guardian_replacement_waits_the_long_lock() {
        let (mut c, alice) = vault_with_policy(); // delay 1 h -> lock is 3 days
        ctx_at(alice, POLICY_DEPOSIT, T0_MS + 10);
        c.set_policy("0".into(), without_guardian());
        let at = c.get_policy("0".into()).pending.unwrap().apply_after_ms;
        assert_eq!(at, T0_MS + 10 + policy::GUARDIAN_CHANGE_MIN_MS);
        ctx_at(accounts(3), NearToken::from_yoctonear(0), T0_MS + 10 + 2 * HOUR_MS);
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| c.apply_policy("0".into()))).is_err(), "applied after the normal delay");
        ctx_at(accounts(3), NearToken::from_yoctonear(0), at);
        c.apply_policy("0".into());
        assert_eq!(c.get_policy("0".into()).policy.guardian, None);
    }

    #[test]
    fn guardian_replacement_waits_even_with_zero_delay() {
        let alice = accounts(1);
        let mut c = setup_with_vault(alice.clone());
        let mut fast = test_policy(1);
        fast.delay_ms = 0;
        ctx_at(alice.clone(), POLICY_DEPOSIT, T0_MS);
        assert!(c.set_policy("0".into(), fast));
        let mut no_g = test_policy(1);
        no_g.delay_ms = 0;
        no_g.guardian = None;
        ctx_at(alice, POLICY_DEPOSIT, T0_MS + 10);
        assert!(!c.set_policy("0".into(), no_g), "delay 0 must not let the guardian go at once");
        assert_eq!(c.get_policy("0".into()).pending.unwrap().apply_after_ms, T0_MS + 10 + policy::GUARDIAN_CHANGE_MIN_MS);
    }

    #[test]
    fn owner_can_cancel_a_guardian_replacement() {
        let (mut c, alice) = vault_with_policy();
        ctx_at(alice.clone(), POLICY_DEPOSIT, T0_MS + 10);
        c.set_policy("0".into(), without_guardian());
        ctx_at(alice, ONE_YOCTO, T0_MS + 20);
        c.cancel_pending_policy("0".into());
        let v = c.get_policy("0".into());
        assert!(v.pending.is_none());
        assert_eq!(v.policy.guardian, Some(guardian()));
    }

    #[test]
    fn proposal_ids_are_unique() {
        let (mut c, alice) = vault_with_policy();
        let a = propose_as(&mut c, &alice, 1, T0_MS + 10);
        let b = propose_as(&mut c, &alice, 1, T0_MS + 11);
        assert_eq!((a, b), (0, 1));
    }

    #[test]
    #[should_panic(expected = "vault has no policy (locked)")]
    fn locked_vault_cannot_propose() {
        let mut c = setup_with_vault(accounts(1));
        propose_as(&mut c, &accounts(1), 1, T0_MS);
    }

    #[test]
    #[should_panic(expected = "Only the vault owner or its proposer can do this")]
    fn stranger_cannot_propose() {
        let (mut c, _) = vault_with_policy();
        propose_as(&mut c, &accounts(3), 1, T0_MS + 10);
    }

    #[test]
    #[should_panic(expected = "destination not allowed")]
    fn proposal_must_pass_the_policy() {
        let (mut c, alice) = vault_with_policy();
        ctx_at(alice, POLICY_DEPOSIT, T0_MS + 10);
        let mut t = ptx(1);
        t.to = "0x2222222222222222222222222222222222222222".into();
        c.propose("0".into(), t);
    }

    #[test]
    fn several_proposals_may_queue_beyond_the_cap() {
        // The cap is enforced when signing (P1), so the queue may hold more than one day's cap.
        let (mut c, alice) = vault_with_policy();
        propose_as(&mut c, &alice, 6 * ONE_HUNDREDTH_ETH, T0_MS + 10);
        propose_as(&mut c, &alice, 6 * ONE_HUNDREDTH_ETH, T0_MS + 11); // 0.12 > 0.1 queued
        assert_eq!(c.list_proposals("0".into()).len(), 2);
    }

    /// Review P5: precise assertion on who gets the freed storage.
    #[test]
    fn cancel_removes_the_proposal_and_refunds_its_storage_to_the_owner() {
        let (mut c, alice) = vault_with_policy();
        let id = propose_as(&mut c, &alice, 6 * ONE_HUNDREDTH_ETH, T0_MS + 10);
        ctx_at(alice.clone(), ONE_YOCTO, T0_MS + 11);
        c.cancel_proposal("0".into(), id);
        let t = transfers();
        assert_eq!(t.len(), 1, "{t:?}");
        assert_eq!(t[0].0, alice);
        assert!(t[0].1 > NearToken::from_yoctonear(1), "{t:?}");
        assert!(c.list_proposals("0".into()).is_empty());
    }

    #[test]
    fn guardian_veto_removes_the_proposal_and_refunds_the_owner() {
        let (mut c, alice) = vault_with_policy();
        let id = propose_as(&mut c, &alice, 6 * ONE_HUNDREDTH_ETH, T0_MS + 10);
        ctx_at(guardian(), ONE_YOCTO, T0_MS + 11);
        c.veto_proposal("0".into(), id);
        assert!(c.list_proposals("0".into()).is_empty());
        let t = transfers();
        assert_eq!(t.len(), 1, "{t:?}");
        assert_eq!(t[0].0, alice, "freed storage goes to the owner, not the guardian");
    }

    #[test]
    #[should_panic(expected = "Only the guardian can veto")]
    fn stranger_cannot_veto_a_proposal() {
        let (mut c, alice) = vault_with_policy();
        let id = propose_as(&mut c, &alice, 1, T0_MS + 10);
        ctx_at(accounts(3), ONE_YOCTO, T0_MS + 11);
        c.veto_proposal("0".into(), id);
    }

    #[test]
    #[should_panic(expected = "Only the vault owner can do this")]
    fn guardian_cannot_cancel_as_owner() {
        let (mut c, alice) = vault_with_policy();
        let id = propose_as(&mut c, &alice, 1, T0_MS + 10);
        ctx_at(guardian(), ONE_YOCTO, T0_MS + 11);
        c.cancel_proposal("0".into(), id);
    }

    #[test]
    #[should_panic(expected = "Proposal not found")]
    fn cancel_of_unknown_proposal_fails() {
        let (mut c, alice) = vault_with_policy();
        ctx_at(alice, ONE_YOCTO, T0_MS + 11);
        c.cancel_proposal("0".into(), 42);
    }

    #[test]
    #[should_panic(expected = "Too many queued proposals")]
    fn queue_is_bounded() {
        let (mut c, alice) = vault_with_policy();
        for i in 0..=MAX_QUEUED_PROPOSALS as u64 {
            propose_as(&mut c, &alice, 1, T0_MS + 10 + i);
        }
    }

    #[test]
    fn execution_waits_the_delay_then_reports_nonce_and_hash() {
        let (mut c, alice) = vault_with_policy();
        let id = propose_as(&mut c, &alice, 4 * ONE_HUNDREDTH_ETH, T0_MS + 10);
        ctx_at(accounts(3), NearToken::from_yoctonear(0), T0_MS + 10 + HOUR_MS - 1);
        let early = c.check_execution("0".into(), id);
        assert!(!early.ready);
        assert_eq!(early.reason.as_deref(), Some("Proposal delay has not passed yet"));
        ctx_at(accounts(3), NearToken::from_yoctonear(0), T0_MS + 10 + HOUR_MS);
        let ok = c.check_execution("0".into(), id);
        assert!(ok.ready, "{ok:?}");
        assert_eq!(ok.nonce, 0);
        let expected = hex0x(&ptx(4 * ONE_HUNDREDTH_ETH).to_tx(0).unwrap().signing_hash());
        assert_eq!(ok.signing_hash.as_deref(), Some(expected.as_str()));
    }

    #[test]
    fn tightening_the_policy_also_stops_queued_proposals() {
        let (mut c, alice) = vault_with_policy();
        let id = propose_as(&mut c, &alice, 4 * ONE_HUNDREDTH_ETH, T0_MS + 10);
        ctx_at(alice, POLICY_DEPOSIT, T0_MS + 20);
        assert!(c.set_policy("0".into(), test_policy(ONE_HUNDREDTH_ETH)), "lowering the cap applies at once");
        ctx_at(accounts(3), NearToken::from_yoctonear(0), T0_MS + 10 + HOUR_MS);
        let r = c.check_execution("0".into(), id);
        assert!(!r.ready);
        assert_eq!(r.reason.as_deref(), Some("Policy now refuses it: ETH daily cap exceeded"));
    }

    #[test]
    fn proposal_from_a_previous_owner_epoch_is_refused() {
        // The queue is cleared on every change of owner; this checks the second line of defense
        // by moving the epoch while a proposal is still queued.
        let (mut c, alice) = vault_with_policy();
        let id = propose_as(&mut c, &alice, 1, T0_MS + 10);
        let mut info = c.transfer_info.get(&"0".to_string()).unwrap_or_default();
        info.count += 1;
        c.transfer_info.insert(&"0".to_string(), &info);
        ctx_at(accounts(3), NearToken::from_yoctonear(0), T0_MS + 10 + HOUR_MS);
        let r = c.check_execution("0".into(), id);
        assert_eq!(r.reason.as_deref(), Some("Proposal belongs to a previous owner"));
    }

    #[test]
    fn transfer_clears_the_queue() {
        let (mut c, alice) = vault_with_policy();
        propose_as(&mut c, &alice, 1, T0_MS + 10);
        ctx_at(alice, ONE_YOCTO, T0_MS + 20);
        open_sale(&mut c);
        c.nft_transfer(accounts(2), "0".into(), None, None);
        assert!(c.list_proposals("0".into()).is_empty());
        assert_eq!(c.get_next_nonce("0".into()), 0);
    }

    // ---------- M7: signing, with the real A1 signature from the MPC network ----------

    /// Key the testnet signer derived for (alan-vault-2026.testnet, "ethereum-1"); its address
    /// 0x8812…8d11 sent the A1 transaction, signed by the MPC network and mined on Sepolia.
    const A1_KEY: &str = "secp256k1:3YaBgZYkJKteg4ACKrmjkmwCWhzDJiEgstzpEJNNvkb5Kf6YJhe7dHxDqFx3gsaMnKhemeB6YPj42s2ejdqxPhiU";
    const A1_ADDR: &str = "0x881294c1b52d631ab43fa2bd23d691209b548d11";
    const A1_HASH: &str = "0x2ffcfe7987e5ff1810ccdf565de03ee53ceeac8427d84a361d2c058a991c97b2";
    const A1_RAW: &str = "0x02f87583aa36a780843b9aca008506fc23ac0082520894881294c1b52d631ab43fa2bd23d691209b548d1187038d7ea4c6800080c001a04057bd4e77d6989afeabbb8eaef7cbe4554cc0eb036393d05a6195347cbf1d98a03a85fc21be896c6b5c90c09b479f75806a2b0933b1994876b1a7bb6c25733809";
    const A1_TX_HASH: &str = "0xfe6d501e202d703ed56ef3978b6c6f666379fbe87d9d0c456683cd22741a45b1";
    const EXEC_DEPOSIT: NearToken = NearToken::from_millinear(20);

    /// Delivers a signer answer to `on_signed` the way the runtime does: as the promise result.
    fn answer(c: &mut PolicyVault, result: near_sdk::PromiseResult) -> bool {
        let hash = c.get_inflight("0".into()).map(|f| f.signing_hash).unwrap_or_default();
        let mut b = VMContextBuilder::new();
        b.current_account_id("vault.testnet".parse().unwrap())
            .predecessor_account_id("vault.testnet".parse().unwrap())
            .block_timestamp((T0_MS + 10 + HOUR_MS + 5) * 1_000_000);
        testing_env!(
            b.build(),
            near_sdk::test_vm_config(),
            near_sdk::RuntimeFeesConfig::test(),
            Default::default(),
            vec![result]
        );
        c.on_signed("0".into(), hash)
    }

    fn ok(resp: &SignResponse) -> near_sdk::PromiseResult {
        near_sdk::PromiseResult::Successful(near_sdk::serde_json::to_vec(resp).unwrap())
    }

    fn a1_response() -> SignResponse {
        SignResponse {
            big_r: AffinePoint { affine_point: "024057bd4e77d6989afeabbb8eaef7cbe4554cc0eb036393d05a6195347cbf1d98".into() },
            s: Scalar { scalar: "3a85fc21be896c6b5c90c09b479f75806a2b0933b1994876b1a7bb6c25733809".into() },
            recovery_id: 1,
        }
    }

    fn a1_ptx() -> ProposalTx {
        ProposalTx {
            chain_id: 11155111,
            max_priority_fee_per_gas: U128(1_000_000_000),
            max_fee_per_gas: U128(30_000_000_000),
            gas_limit: 21_000,
            to: A1_ADDR.into(),
            value: U128(1_000_000_000_000_000),
            data: "0x".into(),
        }
    }

    /// Vault 0 whose key is the A1 key, a policy that allows the A1 transaction, the A1
    /// transaction proposed, and the clock past the delay. Returns (contract, owner, proposal id).
    fn ready_a1_proposal() -> (PolicyVault, AccountId, u64) {
        let alice = accounts(1);
        let mut c = setup_with_vault(alice.clone());
        assert!(c.on_derived_key("0".into(), Ok(A1_KEY.into())));
        assert_eq!(c.vault_info("0".into()).evm_address.as_deref(), Some(A1_ADDR));
        let mut p = test_policy(100_000_000_000_000_000);
        p.allowed_destinations = vec![A1_ADDR.into()];
        ctx_at(alice.clone(), POLICY_DEPOSIT, T0_MS);
        c.set_policy("0".into(), p);
        ctx_at(alice.clone(), POLICY_DEPOSIT, T0_MS + 10);
        let id = c.propose("0".into(), a1_ptx());
        ctx_at(alice.clone(), EXEC_DEPOSIT, T0_MS + 10 + HOUR_MS);
        (c, alice, id)
    }

    // ---------- agent mode (after M12) ----------

    /// The A1 vault with `agent` named as the proposer of its policy.
    fn a1_with_agent() -> (PolicyVault, AccountId, AccountId) {
        let alice = accounts(1);
        let agent = accounts(3);
        let mut c = setup_with_vault(alice.clone());
        assert!(c.on_derived_key("0".into(), Ok(A1_KEY.into())));
        let mut p = test_policy(100_000_000_000_000_000);
        p.allowed_destinations = vec![A1_ADDR.into()];
        p.proposer = Some(agent.clone());
        ctx_at(alice.clone(), POLICY_DEPOSIT, T0_MS);
        assert!(c.set_policy("0".into(), p), "first policy of a locked vault applies at once");
        (c, alice, agent)
    }

    #[test]
    fn the_agent_proposes_and_signs_after_the_delay() {
        let (mut c, _, agent) = a1_with_agent();
        ctx_at(agent.clone(), POLICY_DEPOSIT, T0_MS + 10);
        let id = c.propose("0".into(), a1_ptx());
        ctx_at(agent.clone(), EXEC_DEPOSIT, T0_MS + 10 + HOUR_MS);
        let _ = c.execute_proposal("0".into(), id, None, None);
        assert_eq!(c.get_inflight("0".into()).expect("in flight").payer, agent, "the agent pays the signature");
        assert!(answer(&mut c, ok(&a1_response())));
        assert!(c.get_signed("0".into(), 0).is_some());
    }

    #[test]
    #[should_panic(expected = "Proposal delay has not passed yet")]
    fn the_agent_waits_the_delay_too() {
        let (mut c, _, agent) = a1_with_agent();
        ctx_at(agent.clone(), POLICY_DEPOSIT, T0_MS + 10);
        let id = c.propose("0".into(), a1_ptx());
        ctx_at(agent, EXEC_DEPOSIT, T0_MS + 20);
        let _ = c.execute_proposal("0".into(), id, None, None);
    }

    #[test]
    fn the_guardian_vetoes_an_agent_proposal() {
        let (mut c, _, agent) = a1_with_agent();
        ctx_at(agent, POLICY_DEPOSIT, T0_MS + 10);
        let id = c.propose("0".into(), a1_ptx());
        ctx_at(guardian(), ONE_YOCTO, T0_MS + 20);
        c.veto_proposal("0".into(), id);
        assert!(c.list_proposals("0".into()).is_empty());
    }

    #[test]
    #[should_panic(expected = "Only the vault owner can do this")]
    fn the_agent_cannot_change_the_policy() {
        let (mut c, _, agent) = a1_with_agent();
        ctx_at(agent, POLICY_DEPOSIT, T0_MS + 10);
        c.set_policy("0".into(), test_policy(1));
    }

    #[test]
    #[should_panic(expected = "Only the vault owner can do this")]
    fn the_agent_cannot_start_a_sale() {
        let (mut c, _, agent) = a1_with_agent();
        ctx_at(agent, POLICY_DEPOSIT, T0_MS + 10);
        let _ = c.start_sale("0".into(), None, None);
    }

    #[test]
    #[should_panic(expected = "Only the vault owner can do this")]
    fn the_agent_cannot_cancel_a_nonce() {
        let (mut c, _, agent) = a1_with_agent();
        ctx_at(agent, EXEC_DEPOSIT, T0_MS + 10);
        let _ = c.cancel_nonce("0".into(), 0, U128(30_000_000_000), U128(1_000_000_000), None, None);
    }

    #[test]
    #[should_panic(expected = "Only the vault owner can do this")]
    fn the_agent_cannot_cancel_the_owners_proposal() {
        let (mut c, alice, agent) = a1_with_agent();
        ctx_at(alice, POLICY_DEPOSIT, T0_MS + 10);
        let id = c.propose("0".into(), a1_ptx());
        ctx_at(agent, ONE_YOCTO, T0_MS + 20);
        c.cancel_proposal("0".into(), id);
    }

    #[test]
    #[should_panic(expected = "Sender not approved")]
    fn the_agent_cannot_transfer_the_vault() {
        let (mut c, _, agent) = a1_with_agent();
        open_sale(&mut c);
        ctx_at(agent, ONE_YOCTO, T0_MS + 10);
        c.nft_transfer(accounts(2), "0".into(), None, None);
    }

    #[test]
    fn naming_an_agent_waits_the_delay_and_removing_it_is_immediate() {
        let alice = accounts(1);
        let mut c = setup_with_vault(alice.clone());
        ctx_at(alice.clone(), POLICY_DEPOSIT, T0_MS);
        assert!(c.set_policy("0".into(), test_policy(1_000)));
        let mut with_agent = test_policy(1_000);
        with_agent.proposer = Some(accounts(3));
        ctx_at(alice.clone(), POLICY_DEPOSIT, T0_MS + 10);
        assert!(!c.set_policy("0".into(), with_agent.clone()), "a new agent is a loosening");
        assert!(c.get_policy("0".into()).policy.proposer.is_none(), "not yet");
        ctx_at(accounts(5), NearToken::from_yoctonear(0), T0_MS + 10 + HOUR_MS);
        c.apply_policy("0".into());
        assert_eq!(c.get_policy("0".into()).policy.proposer, Some(accounts(3)));
        ctx_at(alice, POLICY_DEPOSIT, T0_MS + 20 + HOUR_MS);
        assert!(c.set_policy("0".into(), test_policy(1_000)), "removing the agent tightens");
    }

    #[test]
    #[should_panic(expected = "Only the vault owner or its proposer can do this")]
    fn a_sale_removes_the_agent() {
        let (mut c, alice, agent) = a1_with_agent();
        open_sale(&mut c);
        ctx_at(alice, ONE_YOCTO, T0_MS + 10);
        c.nft_transfer(accounts(2), "0".into(), None, None);
        ctx_at(agent, POLICY_DEPOSIT, T0_MS + 20);
        let _ = c.propose("0".into(), a1_ptx());
    }

    // ---------- migration of stored policies (after M12) ----------

    #[test]
    fn stored_policies_from_before_agent_mode_are_migrated() {
        use near_sdk::IntoStorageKey;
        let alice = accounts(1);
        let mut c = setup_with_vault(alice);
        let old = VaultPolicyStateV1 {
            policy: PolicyV1 {
                chain_id: 11155111,
                delay_ms: HOUR_MS,
                guardian: Some(guardian()),
                eth_daily_cap: U128(5),
                max_gas_cost: U128(7),
                allowed_destinations: vec![DEST.into()],
                allowed_spenders: vec![],
                tokens: vec![],
            },
            pending: Some(PendingPolicyV1 {
                policy: PolicyV1 {
                    chain_id: 11155111,
                    delay_ms: 0,
                    guardian: None,
                    eth_daily_cap: U128(9),
                    max_gas_cost: U128(7),
                    allowed_destinations: vec![],
                    allowed_spenders: vec![],
                    tokens: vec![],
                },
                apply_after_ms: 42,
            }),
            spend: SpendState::default(),
            proposals: vec![],
        };
        let mut key = StorageKey::Policies.into_storage_key();
        key.extend(near_sdk::borsh::to_vec(&"0".to_string()).unwrap());
        env::storage_write(&key, &near_sdk::borsh::to_vec(&old).unwrap());
        assert_eq!(c.migrate_policies(0, 10), 1);
        let p = c.get_policy("0".into());
        assert!(p.has_policy);
        assert_eq!((p.policy.delay_ms, p.policy.eth_daily_cap.0, p.policy.proposer.clone()), (HOUR_MS, 5, None));
        assert!(p.policy.nfts.is_empty());
        let pending = p.pending.expect("pending kept");
        assert_eq!((pending.apply_after_ms, pending.policy.eth_daily_cap.0), (42, 9));
        assert_eq!(c.migrate_policies(0, 10), 0, "idempotent: nothing left to convert");
    }

    #[test]
    fn execute_asks_the_signer_for_exactly_the_validated_hash() {
        let (mut c, _, id) = ready_a1_proposal();
        let _ = c.execute_proposal("0".into(), id, None, None);
        let f = c.get_inflight("0".into()).expect("in flight");
        assert_eq!((f.nonce, f.signing_hash.as_str()), (0, A1_HASH));
        let calls = function_calls();
        let (_, _, args) = calls.iter().find(|(to, m, _)| *to == signer() && m == "sign").expect("sign call");
        let v: near_sdk::serde_json::Value = near_sdk::serde_json::from_str(args).unwrap();
        assert_eq!(v["request"]["domain_id"], 0);
        assert_eq!(v["request"]["path"], "vault-0");
        assert_eq!(v["request"]["payload_v2"]["Ecdsa"], A1_HASH.trim_start_matches("0x"));
        assert!(calls.iter().any(|(_, m, _)| m == "on_signed"), "callback missing");
        assert_eq!(c.get_next_nonce("0".into()), 1);
        assert!(c.list_proposals("0".into()).is_empty());
        assert!(c.get_policy("0".into()).spend.eth.spent.0 > 0, "cap charged at signing");
    }

    #[test]
    fn real_mpc_signature_is_verified_and_the_mined_transaction_is_stored() {
        let (mut c, alice, id) = ready_a1_proposal();
        let _ = c.execute_proposal("0".into(), id, None, None);
        assert!(answer(&mut c, ok(&a1_response())));
        let rec = c.get_signed("0".into(), 0).expect("signed record");
        assert_eq!(rec.signed_tx, A1_RAW, "byte-identical to the transaction mined on Sepolia");
        assert_eq!(rec.tx_hash, A1_TX_HASH);
        assert_eq!((rec.owner, rec.proposal_id), (alice, id));
        assert!(c.get_inflight("0".into()).is_none(), "lock released");
        assert_eq!(c.list_signed("0".into(), None, None).len(), 1);
        assert!(get_logs().iter().any(|l| l.contains("\"transaction_signed\"") && l.contains(A1_TX_HASH)));
    }

    fn assert_rolled_back(c: &PolicyVault, id: u64, reason: &str) {
        assert!(c.get_inflight("0".into()).is_none(), "lock released");
        assert!(c.get_signed("0".into(), 0).is_none(), "nothing stored");
        assert_eq!(c.get_next_nonce("0".into()), 0, "nonce restored");
        assert_eq!(c.get_policy("0".into()).spend.eth.spent.0, 0, "cap released");
        assert_eq!(c.list_proposals("0".into()).iter().map(|p| p.id).collect::<Vec<_>>(), vec![id], "requeued");
        let ev = get_logs().into_iter().find(|l| l.contains("\"signature_failed\"")).expect("event");
        assert!(ev.contains(reason), "{ev}");
        assert!(transfers().iter().any(|(to, _)| *to == accounts(1)), "storage reserve refunded");
    }

    #[test]
    fn tampered_signature_is_rejected_and_everything_is_undone() {
        let (mut c, _, id) = ready_a1_proposal();
        let _ = c.execute_proposal("0".into(), id, None, None);
        let mut bad = a1_response();
        bad.s.scalar = "3a85fc21be896c6b5c90c09b479f75806a2b0933b1994876b1a7bb6c25733808".into();
        assert!(!answer(&mut c, ok(&bad)));
        assert_rolled_back(&c, id, "does not match the vault key");
    }

    #[test]
    fn signature_for_another_key_is_rejected() {
        // A valid signature, but the vault's key is different (vault-0 of the M4 tests).
        let (mut c, _, id) = ready_a1_proposal();
        let _ = c.execute_proposal("0".into(), id, None, None);
        let mut v = c.vaults.get(&"0".to_string()).unwrap();
        v.public_key = parse_secp256k1_key(VAULT0_KEY).unwrap();
        c.vaults.insert(&"0".to_string(), &v);
        assert!(!answer(&mut c, ok(&a1_response())));
        assert_rolled_back(&c, id, "does not match the vault key");
    }

    #[test]
    fn signer_failure_is_uncertain_not_undone() {
        // Review S3: a failed promise does not prove that no signature exists.
        let (mut c, _, id) = ready_a1_proposal();
        let _ = c.execute_proposal("0".into(), id, None, None);
        let spent = c.get_policy("0".into()).spend.eth.spent.0;
        assert!(!answer(&mut c, near_sdk::PromiseResult::Failed));
        assert_uncertain(&c, id, 0, spent, "signer call failed");
    }

    /// After an uncertain outcome: lock released, nonce stays used, charge kept, proposal back
    /// in the queue pinned to that nonce, nothing stored, and an event.
    fn assert_uncertain(c: &PolicyVault, id: u64, nonce: u64, spent: u128, reason: &str) {
        assert!(c.get_inflight("0".into()).is_none(), "lock released");
        assert!(c.get_signed("0".into(), nonce).is_none(), "nothing stored");
        assert_eq!(c.get_next_nonce("0".into()), nonce + 1, "nonce NOT reused");
        assert_eq!(c.get_policy("0".into()).spend.eth.spent.0, spent, "charge kept");
        assert_eq!(c.list_proposals("0".into()).iter().map(|p| p.id).collect::<Vec<_>>(), vec![id], "requeued");
        assert_eq!(c.pinned.get(&id), Some(nonce), "pinned to its nonce");
        assert_eq!(c.get_uncertain("0".into()).iter().map(|u| u.nonce).collect::<Vec<_>>(), vec![nonce]);
        let ev = get_logs().into_iter().find(|l| l.contains("\"signature_uncertain\"")).expect("event");
        assert!(ev.contains(reason), "{ev}");
    }

    /// Review S1: an answer in another format used to make the callback panic before our code,
    /// leaving the vault locked forever.
    fn assert_unreadable_answer_is_uncertain(weird: &[u8]) {
        let (mut c, _, id) = ready_a1_proposal();
        let _ = c.execute_proposal("0".into(), id, None, None);
        let spent = c.get_policy("0".into()).spend.eth.spent.0;
        assert!(!answer(&mut c, near_sdk::PromiseResult::Successful(weird.to_vec())));
        assert_uncertain(&c, id, 0, spent, "unreadable signer answer");
    }

    #[test]
    fn answer_in_another_scheme_does_not_lock_the_vault() {
        assert_unreadable_answer_is_uncertain(br#"{"scheme":"Ed25519","signature":[1,2,3]}"#);
    }

    #[test]
    fn answer_that_is_not_json_does_not_lock_the_vault() {
        assert_unreadable_answer_is_uncertain(b"not json at all");
    }

    #[test]
    fn answer_with_wrong_types_does_not_lock_the_vault() {
        assert_unreadable_answer_is_uncertain(br#"{"big_r":{"affine_point":7},"s":{"scalar":"00"},"recovery_id":1}"#);
    }

    /// Review S3: retrying a pinned proposal produces the identical transaction at the same
    /// nonce, is not charged twice, and fills the gap.
    #[test]
    fn retry_after_uncertain_uses_the_same_nonce_and_is_not_charged_twice() {
        let (mut c, alice, id) = ready_a1_proposal();
        let _ = c.execute_proposal("0".into(), id, None, None);
        answer(&mut c, near_sdk::PromiseResult::Failed);
        let spent = c.get_policy("0".into()).spend.eth.spent.0;
        let check = c.check_execution("0".into(), id);
        assert_eq!((check.ready, check.nonce), (true, 0), "{check:?}");
        ctx_at(alice, EXEC_DEPOSIT, T0_MS + 20 + HOUR_MS);
        let _ = c.execute_proposal("0".into(), id, None, None);
        let f = c.get_inflight("0".into()).unwrap();
        assert_eq!((f.nonce, f.from_next, f.charged, f.signing_hash.as_str()), (0, false, false, A1_HASH));
        assert_eq!(c.get_policy("0".into()).spend.eth.spent.0, spent, "not charged twice");
        assert!(answer(&mut c, ok(&a1_response())));
        assert_eq!(c.get_signed("0".into(), 0).unwrap().signed_tx, A1_RAW);
        assert!(c.get_uncertain("0".into()).is_empty(), "gap filled");
        assert_eq!(c.get_next_nonce("0".into()), 1);
    }

    #[test]
    #[should_panic(expected = "Proposal is pinned to nonce 0")]
    fn a_pinned_proposal_cannot_be_moved_to_another_nonce() {
        let (mut c, alice, id) = ready_a1_proposal();
        let _ = c.execute_proposal("0".into(), id, None, None);
        answer(&mut c, near_sdk::PromiseResult::Failed);
        ctx_at(alice, EXEC_DEPOSIT, T0_MS + 20 + HOUR_MS);
        let _ = c.execute_proposal("0".into(), id, Some(1), None);
    }

    /// Review S5: signing the same nonce again keeps every version.
    #[test]
    fn replacing_a_nonce_keeps_every_version() {
        let (mut c, alice, id) = ready_a1_proposal();
        let _ = c.execute_proposal("0".into(), id, None, None);
        assert!(answer(&mut c, ok(&a1_response())));
        ctx_at(alice.clone(), POLICY_DEPOSIT, T0_MS + 30);
        let id2 = c.propose("0".into(), a1_ptx()); // same fields, so the A1 signature fits nonce 0 again
        ctx_at(alice, EXEC_DEPOSIT, T0_MS + 30 + HOUR_MS);
        let _ = c.execute_proposal("0".into(), id2, Some(0), None);
        let f = c.get_inflight("0".into()).unwrap();
        assert_eq!((f.nonce, f.from_next), (0, false));
        assert!(answer(&mut c, ok(&a1_response())));
        let versions = c.get_signed_versions("0".into(), 0);
        assert_eq!(versions.iter().map(|r| r.proposal_id).collect::<Vec<_>>(), vec![id, id2]);
        assert_eq!(c.get_signed("0".into(), 0).unwrap().proposal_id, id2, "latest version");
        assert_eq!(c.list_signed("0".into(), None, None).len(), 2);
        assert_eq!(c.get_next_nonce("0".into()), 1, "a replacement does not advance the nonce");
    }

    #[test]
    #[should_panic(expected = "replace_nonce must be a nonce that was already signed")]
    fn replace_nonce_must_be_already_signed() {
        let (mut c, _, id) = ready_a1_proposal();
        let _ = c.execute_proposal("0".into(), id, Some(0), None); // nothing signed yet
    }

    /// Threat 1 building block: a cancellation is a 0-value self-transfer with the same nonce.
    #[test]
    fn cancel_nonce_signs_a_self_transfer_with_that_nonce() {
        let (mut c, alice, id) = ready_a1_proposal();
        let _ = c.execute_proposal("0".into(), id, None, None);
        assert!(answer(&mut c, ok(&a1_response())));
        let spent = c.get_policy("0".into()).spend.eth.spent.0;
        ctx_at(alice, EXEC_DEPOSIT, T0_MS + 20 + HOUR_MS); // no delay needed
        let _ = c.cancel_nonce("0".into(), 0, U128(40_000_000_000), U128(2_000_000_000), None, None);
        let f = c.get_inflight("0".into()).expect("in flight");
        assert!(f.proposal.is_none());
        assert_eq!((f.nonce, f.from_next), (0, false));
        assert_eq!((f.tx.to.as_str(), f.tx.value.0, f.tx.data.as_str(), f.tx.gas_limit), (A1_ADDR, 0, "0x", 21_000));
        assert_eq!(c.get_policy("0".into()).spend.eth.spent.0, spent + 40_000_000_000 * 21_000, "only gas charged");
        assert_eq!(c.get_next_nonce("0".into()), 1);
        // The A1 signature is for another hash, so it is rejected and the charge is released.
        assert!(!answer(&mut c, ok(&a1_response())));
        assert_eq!(c.get_policy("0".into()).spend.eth.spent.0, spent);
        assert_eq!(c.get_next_nonce("0".into()), 1, "a cancellation never touches the next nonce");
    }

    #[test]
    #[should_panic(expected = "Only a nonce that was already signed can be cancelled")]
    fn cannot_cancel_a_nonce_never_signed() {
        let (mut c, alice, _) = ready_a1_proposal();
        ctx_at(alice, EXEC_DEPOSIT, T0_MS + 20 + HOUR_MS);
        let _ = c.cancel_nonce("0".into(), 0, U128(1_000_000_000), U128(1_000_000_000), None, None);
    }

    #[test]
    #[should_panic(expected = "Only the vault owner can do this")]
    fn stranger_cannot_cancel_a_nonce() {
        let (mut c, _, id) = ready_a1_proposal();
        let _ = c.execute_proposal("0".into(), id, None, None);
        answer(&mut c, ok(&a1_response()));
        ctx_at(accounts(3), EXEC_DEPOSIT, T0_MS + 20 + HOUR_MS);
        let _ = c.cancel_nonce("0".into(), 0, U128(1_000_000_000), U128(1_000_000_000), None, None);
    }

    /// Review S2: a signature that never gets an answer can be abandoned after the timeout.
    #[test]
    fn abandon_only_after_the_timeout_and_as_uncertain() {
        let (mut c, alice, id) = ready_a1_proposal();
        let _ = c.execute_proposal("0".into(), id, None, None);
        let spent = c.get_policy("0".into()).spend.eth.spent.0;
        ctx_at(alice.clone(), NearToken::from_yoctonear(0), T0_MS + 10 + HOUR_MS + INFLIGHT_TIMEOUT_MS - 1);
        let early = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| c.abandon_signature("0".into())));
        assert!(early.is_err(), "abandoned before the timeout");
        ctx_at(alice, NearToken::from_yoctonear(0), T0_MS + 10 + HOUR_MS + INFLIGHT_TIMEOUT_MS);
        c.abandon_signature("0".into());
        assert_uncertain(&c, id, 0, spent, "abandoned after timeout");
    }

    #[test]
    fn a_stale_answer_cannot_land_on_another_signature() {
        let (mut c, _, id) = ready_a1_proposal();
        let _ = c.execute_proposal("0".into(), id, None, None);
        // An answer that names a different hash is ignored and the lock stays.
        let mut b = VMContextBuilder::new();
        b.current_account_id("vault.testnet".parse().unwrap()).predecessor_account_id("vault.testnet".parse().unwrap());
        testing_env!(b.build(), near_sdk::test_vm_config(), near_sdk::RuntimeFeesConfig::test(), Default::default(), vec![ok(&a1_response())]);
        assert!(!c.on_signed("0".into(), "0xdeadbeef".into()));
        assert!(c.get_inflight("0".into()).is_some(), "the real signature is still awaited");
    }

    /// Review S7.
    #[test]
    #[should_panic(expected = "Attach at least 100 Tgas to sign")]
    fn signing_needs_enough_gas() {
        let (mut c, alice, id) = ready_a1_proposal();
        let mut b = VMContextBuilder::new();
        b.current_account_id("vault.testnet".parse().unwrap())
            .predecessor_account_id(alice)
            .attached_deposit(EXEC_DEPOSIT)
            .prepaid_gas(Gas::from_tgas(90))
            .block_timestamp((T0_MS + 10 + HOUR_MS) * 1_000_000);
        testing_env!(b.build());
        let _ = c.execute_proposal("0".into(), id, None, None);
    }

    /// Review S4: the signer deposit can be raised by the caller.
    #[test]
    fn sign_deposit_is_forwarded() {
        let (mut c, _, id) = ready_a1_proposal();
        let _ = c.execute_proposal("0".into(), id, None, Some(U128(5)));
        let deposit = get_created_receipts()
            .into_iter()
            .filter(|r| r.receiver_id == signer())
            .flat_map(|r| r.actions)
            .find_map(|a| match a {
                MockAction::FunctionCallWeight { method_name, attached_deposit, .. } if method_name == b"sign" => Some(attached_deposit),
                _ => None,
            });
        assert_eq!(deposit, Some(NearToken::from_yoctonear(5)));
    }

    /// Review S6: the largest signed record fits the storage reserved for it.
    #[test]
    fn largest_signed_record_fits_the_reserve() {
        let long_account: AccountId = format!("{}.testnet", "a".repeat(56)).parse().unwrap();
        let record = SignedRecord {
            token_id: u64::MAX.to_string(),
            proposal_id: u64::MAX,
            nonce: u64::MAX,
            signing_hash: format!("0x{}", "ab".repeat(32)),
            // an ERC-20 call with the largest fields: about 190 bytes raw
            signed_tx: format!("0x{}", "cd".repeat(200)),
            tx_hash: format!("0x{}", "ef".repeat(32)),
            owner: long_account,
            signed_ms: u64::MAX,
        };
        let key = signed_version_key(&record.token_id, record.nonce, u32::MAX);
        let bytes = near_sdk::borsh::to_vec(&record).unwrap().len() + near_sdk::borsh::to_vec(&key).unwrap().len() + 40 + 1;
        assert!((bytes as u64) <= SIGNED_RECORD_RESERVE_BYTES, "record needs {bytes} bytes");
    }

    /// Review M12 (R12-5): an answer in a format the contract does not expect may still hide a
    /// valid signature (the signer has it), so it is uncertain, never undone.
    #[test]
    fn malformed_answer_is_uncertain_not_undone() {
        let (mut c, _, id) = ready_a1_proposal();
        let _ = c.execute_proposal("0".into(), id, None, None);
        let spent = c.get_policy("0".into()).spend.eth.spent.0;
        let mut bad = a1_response();
        bad.big_r.affine_point = "054057bd4e77d6989afeabbb8eaef7cbe4554cc0eb036393d05a6195347cbf1d98".into();
        assert!(!answer(&mut c, ok(&bad)));
        assert_uncertain(&c, id, 0, spent, "not a compressed point");
    }

    /// Review M12 (R12-5): the real A1 signature with `recovery_id` written as 28 (Ethereum's
    /// 27/28 style) is a valid signature in another format: uncertain, the nonce stays used.
    #[test]
    fn valid_signature_in_another_format_is_uncertain() {
        let (mut c, _, id) = ready_a1_proposal();
        let _ = c.execute_proposal("0".into(), id, None, None);
        let spent = c.get_policy("0".into()).spend.eth.spent.0;
        let mut v28 = a1_response();
        v28.recovery_id += 27;
        assert!(!answer(&mut c, ok(&v28)));
        assert_uncertain(&c, id, 0, spent, "recovery_id must be 0 or 1");
    }

    #[test]
    #[should_panic(expected = "A signature is already in flight for this vault")]
    fn only_one_signature_in_flight() {
        let (mut c, alice, id) = ready_a1_proposal();
        ctx_at(alice.clone(), POLICY_DEPOSIT, T0_MS + 20);
        let id2 = c.propose("0".into(), a1_ptx());
        let _ = id;
        ctx_at(alice.clone(), EXEC_DEPOSIT, T0_MS + 20 + HOUR_MS);
        let _ = c.execute_proposal("0".into(), id, None, None);
        let _ = c.execute_proposal("0".into(), id2, None, None);
    }

    #[test]
    #[should_panic(expected = "A signature is in flight for this vault; transfer after it completes")]
    fn no_transfer_while_a_signature_is_in_flight() {
        let (mut c, alice, id) = ready_a1_proposal();
        let _ = c.execute_proposal("0".into(), id, None, None);
        ctx_at(alice, ONE_YOCTO, T0_MS + 20 + HOUR_MS);
        open_sale(&mut c);
        c.nft_transfer(accounts(2), "0".into(), None, None);
    }

    #[test]
    fn after_signing_the_vault_can_be_sold_and_keeps_its_nonce_and_history() {
        let (mut c, alice, id) = ready_a1_proposal();
        let _ = c.execute_proposal("0".into(), id, None, None);
        answer(&mut c, ok(&a1_response()));
        ctx_at(alice, ONE_YOCTO, T0_MS + 30 + HOUR_MS);
        open_sale(&mut c);
        c.nft_transfer(accounts(2), "0".into(), None, None);
        assert_eq!(c.get_next_nonce("0".into()), 1, "the external account's nonce survives the sale");
        assert_eq!(c.list_signed("0".into(), None, None).len(), 1, "the buyer can audit past signatures");
    }

    #[test]
    #[should_panic(expected = "Only the vault owner or its proposer can do this")]
    fn stranger_cannot_execute() {
        let (mut c, _, id) = ready_a1_proposal();
        ctx_at(accounts(3), EXEC_DEPOSIT, T0_MS + 10 + HOUR_MS);
        let _ = c.execute_proposal("0".into(), id, None, None);
    }

    #[test]
    #[should_panic(expected = "Proposal delay has not passed yet")]
    fn execute_respects_the_delay() {
        let (mut c, alice, id) = ready_a1_proposal();
        ctx_at(alice, EXEC_DEPOSIT, T0_MS + 10 + HOUR_MS - 1);
        let _ = c.execute_proposal("0".into(), id, None, None);
    }

    #[test]
    #[should_panic(expected = "to cover storage and the signer deposit")]
    fn execute_needs_a_deposit() {
        let (mut c, alice, id) = ready_a1_proposal();
        ctx_at(alice, ONE_YOCTO, T0_MS + 10 + HOUR_MS);
        let _ = c.execute_proposal("0".into(), id, None, None);
    }

    #[test]
    #[should_panic(expected = "Vault address not resolved yet")]
    fn execute_needs_a_resolved_vault() {
        let (mut c, alice) = vault_with_policy(); // vault key never resolved
        let id = propose_as(&mut c, &alice, 1, T0_MS + 10);
        ctx_at(alice, EXEC_DEPOSIT, T0_MS + 10 + HOUR_MS);
        let _ = c.execute_proposal("0".into(), id, None, None);
    }

    // ---------- general review G2: a vault keeps the chain it signed for ----------

    fn mainnet_policy() -> Policy {
        let mut p = test_policy(100_000_000_000_000_000);
        p.chain_id = 1;
        p.allowed_destinations = vec![A1_ADDR.into()];
        p
    }

    #[test]
    fn the_first_signature_fixes_the_vault_chain() {
        let (mut c, _, id) = ready_a1_proposal();
        assert_eq!(c.get_vault_chain("0".into()), None, "nothing signed yet");
        let _ = c.execute_proposal("0".into(), id, None, None);
        assert_eq!(c.get_vault_chain("0".into()), Some(11155111), "fixed when signing starts");
    }

    #[test]
    #[should_panic(expected = "This vault has signed on chain 11155111; its policy must keep chain_id 11155111")]
    fn after_signing_the_policy_cannot_move_to_another_chain() {
        let (mut c, alice, id) = ready_a1_proposal();
        let _ = c.execute_proposal("0".into(), id, None, None);
        answer(&mut c, ok(&a1_response()));
        ctx_at(alice, POLICY_DEPOSIT, T0_MS + 100 + HOUR_MS);
        c.set_policy("0".into(), mainnet_policy());
    }

    #[test]
    #[should_panic(expected = "This vault has signed on chain 11155111")]
    fn a_pending_change_to_another_chain_cannot_apply_after_signing() {
        let (mut c, alice, id) = ready_a1_proposal();
        ctx_at(alice.clone(), POLICY_DEPOSIT, T0_MS + 20);
        assert!(!c.set_policy("0".into(), mainnet_policy()), "queued before any signature");
        ctx_at(alice.clone(), EXEC_DEPOSIT, T0_MS + 10 + HOUR_MS);
        let _ = c.execute_proposal("0".into(), id, None, None);
        answer(&mut c, ok(&a1_response()));
        ctx_at(alice, NearToken::from_yoctonear(0), T0_MS + 20 + HOUR_MS);
        c.apply_policy("0".into());
    }

    #[test]
    #[should_panic(expected = "This vault has signed on chain 11155111")]
    fn the_chain_survives_a_sale() {
        let (mut c, alice, id) = ready_a1_proposal();
        let _ = c.execute_proposal("0".into(), id, None, None);
        answer(&mut c, ok(&a1_response()));
        ctx_at(alice, ONE_YOCTO, T0_MS + 100 + HOUR_MS);
        open_sale(&mut c);
        c.nft_transfer(accounts(2), "0".into(), None, None);
        ctx_at(accounts(2), POLICY_DEPOSIT, T0_MS + 101 + HOUR_MS);
        c.set_policy("0".into(), mainnet_policy()); // the buyer's first policy, other chain
    }

    #[test]
    fn the_buyer_can_set_a_policy_on_the_same_chain() {
        let (mut c, alice, id) = ready_a1_proposal();
        let _ = c.execute_proposal("0".into(), id, None, None);
        answer(&mut c, ok(&a1_response()));
        ctx_at(alice, ONE_YOCTO, T0_MS + 100 + HOUR_MS);
        open_sale(&mut c);
        c.nft_transfer(accounts(2), "0".into(), None, None);
        ctx_at(accounts(2), POLICY_DEPOSIT, T0_MS + 101 + HOUR_MS);
        assert!(c.set_policy("0".into(), test_policy(1)));
    }

    #[test]
    fn vaults_that_signed_before_the_lock_read_their_chain_from_history() {
        let (mut c, _, id) = ready_a1_proposal();
        let _ = c.execute_proposal("0".into(), id, None, None);
        answer(&mut c, ok(&a1_response()));
        c.vault_chain.remove(&"0".to_string()); // as if signed before this field existed
        assert_eq!(c.get_vault_chain("0".into()), Some(11155111));
    }

    // ---------- M8: two-phase sale ----------

    const SALE_DEPOSIT: NearToken = NearToken::from_millinear(10);

    fn start_sale_as(c: &mut PolicyVault, who: &AccountId, ms: u64) -> Sale {
        ctx_at(who.clone(), SALE_DEPOSIT, ms);
        c.start_sale("0".into(), None, None)
    }

    fn transfer_as(c: &mut PolicyVault, who: &AccountId, to: AccountId, ms: u64) {
        ctx_at(who.clone(), ONE_YOCTO, ms);
        c.nft_transfer(to, "0".into(), None, None);
    }

    #[test]
    #[should_panic(expected = "Start a sale (start_sale) and wait for it to open before transferring")]
    fn transfer_without_a_sale_fails() {
        let mut c = setup_with_vault(accounts(1));
        transfer_as(&mut c, &accounts(1), accounts(2), T0_MS);
    }

    #[test]
    fn a_vault_without_policy_waits_the_minimum_and_the_transfer_ends_it() {
        let (alice, bob) = (accounts(1), accounts(2));
        let mut c = setup_with_vault(alice.clone());
        let sale = start_sale_as(&mut c, &alice, T0_MS);
        let opens = T0_MS + MIN_SALE_DELAY_MS;
        assert_eq!((sale.opens_at_ms, sale.closes_at_ms), (opens, opens + SALE_WINDOW_MS));
        transfer_as(&mut c, &alice, bob.clone(), opens);
        assert_eq!(c.nft_token("0".into()).unwrap().owner_id, bob);
        assert!(c.get_sale("0".into()).is_none(), "the sale never carries over to the buyer");
    }

    /// M8 review V3: even without a policy, a sale waits 10 minutes.
    #[test]
    #[should_panic(expected = "The sale opens at")]
    fn a_vault_without_policy_cannot_be_sold_at_once() {
        let alice = accounts(1);
        let mut c = setup_with_vault(alice.clone());
        start_sale_as(&mut c, &alice, T0_MS);
        transfer_as(&mut c, &alice, accounts(2), T0_MS + MIN_SALE_DELAY_MS - 1);
    }

    /// M8 review V3: a thief who copied the owner's key starts a sale; the owner, who still holds
    /// the key, cancels it during the minimum wait.
    #[test]
    #[should_panic(expected = "Start a sale (start_sale) and wait for it to open")]
    fn the_owner_cancels_a_thiefs_sale_during_the_minimum_wait() {
        let alice = accounts(1); // both the thief and the owner sign as alice
        let mut c = setup_with_vault(alice.clone());
        start_sale_as(&mut c, &alice, T0_MS); // the thief
        ctx_at(alice.clone(), ONE_YOCTO, T0_MS + 60_000);
        c.cancel_sale("0".into()); // the owner, a minute later
        transfer_as(&mut c, &alice, accounts(5), T0_MS + MIN_SALE_DELAY_MS);
    }

    /// M8 review V1: a buyer binds the transfer to the sale it audited.
    #[test]
    fn a_transfer_bound_to_the_audited_sale_succeeds() {
        let alice = accounts(1);
        let mut c = setup_with_vault(alice.clone());
        let sale = start_sale_as(&mut c, &alice, T0_MS);
        ctx_at(alice, ONE_YOCTO, sale.opens_at_ms);
        c.nft_transfer(accounts(2), "0".into(), None, Some(format!("sale:{}", sale.sale_id)));
        assert_eq!(c.nft_token("0".into()).unwrap().owner_id, accounts(2));
    }

    /// M8 review V1: the seller cancelled the audited sale, could have signed something, and
    /// started a new one: the bound transfer fails.
    #[test]
    #[should_panic(expected = "The sale changed since it was audited (audited 0, current 1)")]
    fn a_transfer_bound_to_an_old_sale_fails() {
        let alice = accounts(1);
        let mut c = setup_with_vault(alice.clone());
        let audited = start_sale_as(&mut c, &alice, T0_MS);
        ctx_at(alice.clone(), ONE_YOCTO, T0_MS + 1);
        c.cancel_sale("0".into());
        let current = start_sale_as(&mut c, &alice, T0_MS + 2);
        assert_eq!((audited.sale_id, current.sale_id), (0, 1), "sale ids are unique");
        ctx_at(alice, ONE_YOCTO, current.opens_at_ms);
        c.nft_transfer(accounts(2), "0".into(), None, Some(format!("sale:{}", audited.sale_id)));
    }

    #[test]
    #[should_panic(expected = "Malformed sale binding in memo")]
    fn a_malformed_sale_binding_fails() {
        let alice = accounts(1);
        let mut c = setup_with_vault(alice.clone());
        let sale = start_sale_as(&mut c, &alice, T0_MS);
        ctx_at(alice, ONE_YOCTO, sale.opens_at_ms);
        c.nft_transfer(accounts(2), "0".into(), None, Some("sale:abc".into()));
    }

    #[test]
    fn a_memo_that_names_no_sale_is_just_a_memo() {
        let alice = accounts(1);
        let mut c = setup_with_vault(alice.clone());
        let sale = start_sale_as(&mut c, &alice, T0_MS);
        ctx_at(alice, ONE_YOCTO, sale.opens_at_ms);
        c.nft_transfer(accounts(2), "0".into(), None, Some("thanks for the deal".into()));
        assert_eq!(c.nft_token("0".into()).unwrap().owner_id, accounts(2));
    }

    /// M8 review V2: once its window has closed, a sale no longer freezes the vault...
    #[test]
    fn a_closed_sale_no_longer_freezes_the_vault() {
        let (mut c, alice, id) = ready_a1_proposal();
        let sale = start_sale_as(&mut c, &alice, T0_MS + 10 + HOUR_MS);
        ctx_at(alice, EXEC_DEPOSIT, sale.closes_at_ms);
        let _ = c.execute_proposal("0".into(), id, None, None);
        assert!(c.get_inflight("0".into()).is_some(), "signing works again");
    }

    /// ...and a new sale can replace it without cancelling it first.
    #[test]
    fn a_new_sale_replaces_a_closed_one() {
        let alice = accounts(1);
        let mut c = setup_with_vault(alice.clone());
        let old = start_sale_as(&mut c, &alice, T0_MS);
        let new = start_sale_as(&mut c, &alice, old.closes_at_ms);
        assert_eq!(new.sale_id, old.sale_id + 1);
        assert_eq!(c.get_sale("0".into()).unwrap(), new);
    }

    /// M8 review V6.
    #[test]
    #[should_panic(expected = "A signature is in flight for this vault; transfer after it completes")]
    fn no_transfer_while_a_cancellation_is_in_flight_during_a_sale() {
        let (mut c, alice, id) = ready_a1_proposal();
        let _ = c.execute_proposal("0".into(), id, None, None);
        answer(&mut c, ok(&a1_response()));
        let sale = start_sale_as(&mut c, &alice, T0_MS + 20 + HOUR_MS);
        ctx_at(alice.clone(), EXEC_DEPOSIT, T0_MS + 20 + HOUR_MS);
        let _ = c.cancel_nonce("0".into(), 0, U128(40_000_000_000), U128(2_000_000_000), None, None);
        transfer_as(&mut c, &alice, accounts(2), sale.opens_at_ms);
    }

    #[test]
    #[should_panic(expected = "The sale opens at")]
    fn the_sale_waits_the_policy_delay() {
        let (mut c, alice) = vault_with_policy(); // delay 1 h
        start_sale_as(&mut c, &alice, T0_MS + 10);
        transfer_as(&mut c, &alice, accounts(2), T0_MS + 10 + HOUR_MS - 1);
    }

    #[test]
    fn after_the_delay_the_sale_is_open() {
        let (mut c, alice) = vault_with_policy();
        let sale = start_sale_as(&mut c, &alice, T0_MS + 10);
        assert_eq!(sale.opens_at_ms, T0_MS + 10 + HOUR_MS);
        transfer_as(&mut c, &alice, accounts(2), T0_MS + 10 + HOUR_MS);
        assert_eq!(c.nft_token("0".into()).unwrap().owner_id, accounts(2));
    }

    /// Threat 16: someone holding the owner's key starts a sale; the guardian stops it.
    #[test]
    #[should_panic(expected = "Start a sale (start_sale) and wait for it to open")]
    fn the_guardian_vetoes_a_sale_started_with_a_stolen_key() {
        let (mut c, alice) = vault_with_policy();
        start_sale_as(&mut c, &alice, T0_MS + 10);
        ctx_at(guardian(), ONE_YOCTO, T0_MS + 20);
        c.veto_sale("0".into());
        assert!(get_logs().iter().any(|l| l.contains("\"sale_vetoed\"")));
        transfer_as(&mut c, &alice, accounts(3), T0_MS + 10 + HOUR_MS);
    }

    #[test]
    #[should_panic(expected = "Only the guardian can veto")]
    fn a_stranger_cannot_veto_a_sale() {
        let (mut c, alice) = vault_with_policy();
        start_sale_as(&mut c, &alice, T0_MS + 10);
        ctx_at(accounts(3), ONE_YOCTO, T0_MS + 20);
        c.veto_sale("0".into());
    }

    #[test]
    fn the_owner_cancels_a_sale_and_gets_its_storage_back() {
        let (mut c, alice) = vault_with_policy();
        start_sale_as(&mut c, &alice, T0_MS + 10);
        ctx_at(alice.clone(), ONE_YOCTO, T0_MS + 20);
        c.cancel_sale("0".into());
        assert!(c.get_sale("0".into()).is_none());
        assert!(transfers().iter().any(|(to, _)| *to == alice));
    }

    #[test]
    #[should_panic(expected = "The sale window has closed; start a new sale")]
    fn the_sale_window_closes() {
        let alice = accounts(1);
        let mut c = setup_with_vault(alice.clone());
        let sale = start_sale_as(&mut c, &alice, T0_MS);
        transfer_as(&mut c, &alice, accounts(2), sale.closes_at_ms);
    }

    #[test]
    #[should_panic(expected = "A sale is already active; cancel it first")]
    fn only_one_sale_at_a_time() {
        let alice = accounts(1);
        let mut c = setup_with_vault(alice.clone());
        start_sale_as(&mut c, &alice, T0_MS);
        start_sale_as(&mut c, &alice, T0_MS + 1);
    }

    #[test]
    #[should_panic(expected = "Only the vault owner can do this")]
    fn a_stranger_cannot_start_a_sale() {
        let mut c = setup_with_vault(accounts(1));
        start_sale_as(&mut c, &accounts(3), T0_MS);
    }

    /// Threat 14: an approved marketplace also needs an open sale.
    #[test]
    #[should_panic(expected = "Start a sale (start_sale) and wait for it to open")]
    fn an_approved_marketplace_needs_an_open_sale() {
        let (alice, market) = (accounts(1), accounts(2));
        let mut c = setup_with_vault(alice.clone());
        approve(&mut c, &alice, &market);
        transfer_as(&mut c, &market, accounts(3), T0_MS);
    }

    #[test]
    fn an_approved_marketplace_transfers_during_the_sale() {
        let (alice, market) = (accounts(1), accounts(2));
        let mut c = setup_with_vault(alice.clone());
        approve(&mut c, &alice, &market);
        let sale = start_sale_as(&mut c, &alice, T0_MS);
        transfer_as(&mut c, &market, accounts(3), sale.opens_at_ms);
        assert_eq!(c.nft_token("0".into()).unwrap().owner_id, accounts(3));
    }

    /// Threat 13: transfer_call needs the sale too.
    #[test]
    #[should_panic(expected = "Start a sale (start_sale) and wait for it to open")]
    fn transfer_call_needs_an_open_sale() {
        let alice = accounts(1);
        let mut c = setup_with_vault(alice.clone());
        ctx_at(alice, ONE_YOCTO, T0_MS);
        let _ = c.nft_transfer_call(accounts(2), "0".into(), None, None, "x".into());
    }

    /// Threat 1: during the sale the vault signs no new payment...
    #[test]
    #[should_panic(expected = "The vault is frozen for a sale; only cancel_nonce can sign until the sale ends")]
    fn a_vault_on_sale_signs_no_new_payment() {
        let (mut c, alice, id) = ready_a1_proposal();
        start_sale_as(&mut c, &alice, T0_MS + 10 + HOUR_MS);
        ctx_at(alice, EXEC_DEPOSIT, T0_MS + 10 + HOUR_MS);
        let _ = c.execute_proposal("0".into(), id, None, None);
    }

    /// ...but the seller can still cancel a pending signature, so the buyer gets a clean vault.
    #[test]
    fn a_vault_on_sale_can_cancel_a_pending_signature() {
        let (mut c, alice, id) = ready_a1_proposal();
        let _ = c.execute_proposal("0".into(), id, None, None);
        assert!(answer(&mut c, ok(&a1_response()))); // nonce 0 signed, never broadcast
        start_sale_as(&mut c, &alice, T0_MS + 20 + HOUR_MS);
        ctx_at(alice, EXEC_DEPOSIT, T0_MS + 20 + HOUR_MS);
        let _ = c.cancel_nonce("0".into(), 0, U128(40_000_000_000), U128(2_000_000_000), None, None);
        let f = c.get_inflight("0".into()).expect("cancellation in flight");
        assert!(f.proposal.is_none());
        assert_eq!(f.nonce, 0);
    }

    #[test]
    #[should_panic(expected = "A signature is in flight for this vault; start the sale after it completes")]
    fn no_sale_while_a_signature_is_in_flight() {
        let (mut c, alice, id) = ready_a1_proposal();
        let _ = c.execute_proposal("0".into(), id, None, None);
        start_sale_as(&mut c, &alice, T0_MS + 20 + HOUR_MS);
    }

    #[test]
    #[should_panic(expected = "Start a sale (start_sale) and wait for it to open")]
    fn a_sale_never_carries_over_to_a_later_owner() {
        let alice = accounts(1);
        let mut c = setup_with_vault(alice.clone());
        start_sale_as(&mut c, &alice, T0_MS);
        let mut info = c.transfer_info.get(&"0".to_string()).unwrap_or_default();
        info.count += 1; // as if the owner had changed since the sale was started
        c.transfer_info.insert(&"0".to_string(), &info);
        transfer_as(&mut c, &alice, accounts(2), T0_MS);
    }

    #[test]
    fn contract_metadata_follows_nep177() {
        let c = setup_with_vault(accounts(1));
        let m = c.nft_metadata();
        assert_eq!(m.spec, NFT_METADATA_SPEC);
        assert_eq!(m.symbol, "PVAULT");
    }

    // ---------- General review H3: buy at the sale price ----------

    const PRICE: NearToken = NearToken::from_near(2);

    /// Vault 0 of alice, with a policy (delay 1 h) and a sale at `PRICE`, optionally reserved.
    fn sale_with_price(buyer: Option<AccountId>) -> (PolicyVault, AccountId, Sale) {
        let (mut c, alice) = vault_with_policy();
        ctx_at(alice.clone(), SALE_DEPOSIT, T0_MS + 1);
        let sale = c.start_sale("0".into(), Some(U128(PRICE.as_yoctonear())), buyer);
        (c, alice, sale)
    }

    fn buy_as(c: &mut PolicyVault, who: &AccountId, deposit: NearToken, sale_id: u64, ms: u64) {
        ctx_at(who.clone(), deposit, ms);
        c.buy("0".into(), sale_id);
    }

    #[test]
    fn a_buyer_pays_the_price_and_gets_a_clean_vault() {
        let (mut c, alice, sale) = sale_with_price(None);
        let bob = accounts(2);
        buy_as(&mut c, &bob, PRICE, sale.sale_id, sale.opens_at_ms);
        assert_eq!(c.nft_token("0".into()).unwrap().owner_id, bob);
        assert!(!c.get_policy("0".into()).has_policy);
        assert_eq!(c.get_sale("0".into()), None);
        let t = transfers();
        assert!(t.iter().any(|(to, amount)| *to == alice && *amount == PRICE), "the seller is paid: {t:?}");
        assert!(get_logs().iter().any(|l| l.contains("\"sale_bought\"")));
        assert_eq!(c.vault_transfer_info("0".into()).unwrap().last.unwrap().kind, "buy");
    }

    #[test]
    fn a_buyer_who_attaches_too_much_gets_the_rest_back() {
        let (mut c, _, sale) = sale_with_price(None);
        let bob = accounts(2);
        buy_as(&mut c, &bob, NearToken::from_near(3), sale.sale_id, sale.opens_at_ms);
        assert!(transfers().iter().any(|(to, amount)| *to == bob && *amount == NearToken::from_near(1)));
    }

    #[test]
    #[should_panic(expected = "Attach the price")]
    fn a_buyer_who_attaches_less_than_the_price_fails() {
        let (mut c, _, sale) = sale_with_price(None);
        buy_as(&mut c, &accounts(2), NearToken::from_near(1), sale.sale_id, sale.opens_at_ms);
    }

    #[test]
    #[should_panic(expected = "The sale opens at")]
    fn nobody_buys_before_the_sale_opens() {
        let (mut c, _, sale) = sale_with_price(None);
        buy_as(&mut c, &accounts(2), PRICE, sale.sale_id, sale.opens_at_ms - 1);
    }

    /// Threat 23 closed on-chain: the buyer names the sale it audited. If the seller cancelled it,
    /// signed something and started another, the purchase fails and the deposit goes back.
    #[test]
    #[should_panic(expected = "The sale changed since it was audited")]
    fn a_purchase_of_an_older_sale_fails() {
        let (mut c, alice, first) = sale_with_price(None);
        ctx_at(alice.clone(), ONE_YOCTO, T0_MS + 2);
        c.cancel_sale("0".into());
        ctx_at(alice, SALE_DEPOSIT, T0_MS + 3);
        let second = c.start_sale("0".into(), Some(U128(PRICE.as_yoctonear())), None);
        buy_as(&mut c, &accounts(2), PRICE, first.sale_id, second.opens_at_ms);
    }

    #[test]
    #[should_panic(expected = "This sale has no price; the seller transfers the vault")]
    fn a_sale_without_price_cannot_be_bought() {
        let (mut c, alice) = vault_with_policy();
        let sale = start_sale_as(&mut c, &alice, T0_MS + 1);
        buy_as(&mut c, &accounts(2), PRICE, sale.sale_id, sale.opens_at_ms);
    }

    #[test]
    #[should_panic(expected = "This sale is reserved for another buyer")]
    fn a_reserved_sale_refuses_other_buyers() {
        let (mut c, _, sale) = sale_with_price(Some(accounts(2)));
        buy_as(&mut c, &accounts(3), PRICE, sale.sale_id, sale.opens_at_ms);
    }

    #[test]
    fn a_reserved_sale_sells_to_its_buyer() {
        let (mut c, _, sale) = sale_with_price(Some(accounts(2)));
        buy_as(&mut c, &accounts(2), PRICE, sale.sale_id, sale.opens_at_ms);
        assert_eq!(c.nft_token("0".into()).unwrap().owner_id, accounts(2));
    }

    #[test]
    #[should_panic(expected = "The owner cannot buy their own vault")]
    fn the_owner_cannot_buy_their_own_vault() {
        let (mut c, alice, sale) = sale_with_price(None);
        buy_as(&mut c, &alice, PRICE, sale.sale_id, sale.opens_at_ms);
    }

    #[test]
    #[should_panic(expected = "The price must be above 0")]
    fn a_sale_price_of_zero_is_refused() {
        let (mut c, alice) = vault_with_policy();
        ctx_at(alice, SALE_DEPOSIT, T0_MS + 1);
        c.start_sale("0".into(), Some(U128(0)), None);
    }

    #[test]
    #[should_panic(expected = "The owner cannot be the buyer")]
    fn the_owner_cannot_reserve_the_sale_for_themselves() {
        let (mut c, alice) = vault_with_policy();
        ctx_at(alice.clone(), SALE_DEPOSIT, T0_MS + 1);
        c.start_sale("0".into(), Some(U128(PRICE.as_yoctonear())), Some(alice));
    }

    #[test]
    #[should_panic(expected = "A reserved buyer needs a price")]
    fn a_reserved_buyer_needs_a_price() {
        let (mut c, alice) = vault_with_policy();
        ctx_at(alice, SALE_DEPOSIT, T0_MS + 1);
        c.start_sale("0".into(), None, Some(accounts(2)));
    }

    /// Threat 16: the guardian's veto also stops a purchase.
    #[test]
    #[should_panic(expected = "Start a sale (start_sale) and wait for it to open before transferring")]
    fn a_vetoed_sale_cannot_be_bought() {
        let (mut c, _, sale) = sale_with_price(None);
        ctx_at(guardian(), ONE_YOCTO, T0_MS + 2);
        c.veto_sale("0".into());
        buy_as(&mut c, &accounts(2), PRICE, sale.sale_id, sale.opens_at_ms);
    }

    #[test]
    #[should_panic(expected = "A signature is in flight for this vault; transfer after it completes")]
    fn no_purchase_while_a_cancellation_is_in_flight() {
        let (mut c, alice, id) = ready_a1_proposal();
        let _ = c.execute_proposal("0".into(), id, None, None);
        answer(&mut c, ok(&a1_response()));
        ctx_at(alice.clone(), SALE_DEPOSIT, T0_MS + 20 + HOUR_MS);
        let sale = c.start_sale("0".into(), Some(U128(PRICE.as_yoctonear())), None);
        ctx_at(alice, EXEC_DEPOSIT, T0_MS + 20 + HOUR_MS);
        let _ = c.cancel_nonce("0".into(), 0, U128(40_000_000_000), U128(2_000_000_000), None, None);
        buy_as(&mut c, &accounts(2), PRICE, sale.sale_id, sale.opens_at_ms);
    }

    // ---------- General review H4 and H6 ----------

    #[test]
    fn check_execution_reports_the_sale_freeze() {
        let (mut c, alice, id) = ready_a1_proposal();
        start_sale_as(&mut c, &alice, T0_MS + 10 + HOUR_MS);
        let e = c.check_execution("0".into(), id);
        assert!(!e.ready);
        assert_eq!(
            e.reason.as_deref(),
            Some("The vault is frozen for a sale; only cancel_nonce can sign until the sale ends")
        );
    }

    #[test]
    #[should_panic(expected = "The sale changed since it was audited (audited 5, current 9999)")]
    fn a_binding_in_capitals_is_still_checked() {
        let alice = accounts(1);
        let mut c = setup_with_vault(alice.clone());
        open_sale(&mut c);
        ctx_at(alice, ONE_YOCTO, T0_MS);
        c.nft_transfer(accounts(2), "0".into(), None, Some("SALE:5".into()));
    }

    #[test]
    fn a_binding_in_capitals_to_the_current_sale_succeeds() {
        let alice = accounts(1);
        let mut c = setup_with_vault(alice.clone());
        open_sale(&mut c);
        ctx_at(alice, ONE_YOCTO, T0_MS);
        c.nft_transfer(accounts(2), "0".into(), None, Some(" Sale: 9999 ".into()));
        assert_eq!(c.nft_token("0".into()).unwrap().owner_id, accounts(2));
    }

    // ---------- Review M21: the reviewer's tests, turned around to check the fixes ----------
    fn m21_ptx(value: u128) -> ProposalTx {
        let mut p = a1_ptx();
        p.value = U128(value);
        p
    }

    fn forwarded_sign_deposit() -> Option<NearToken> {
        get_created_receipts()
            .into_iter()
            .filter(|r| r.receiver_id == signer())
            .flat_map(|r| r.actions)
            .find_map(|a| match a {
                MockAction::FunctionCallWeight { method_name, attached_deposit, .. } if method_name == b"sign" => Some(attached_deposit),
                _ => None,
            })
    }

    /// R21-1 (a): a sign_deposit below the minimum is raised to the minimum, so the signer never
    /// refuses for lack of deposit.
    #[test]
    fn a_zero_sign_deposit_is_raised_to_the_minimum() {
        let (mut c, _, agent) = a1_with_agent();
        ctx_at(agent.clone(), POLICY_DEPOSIT, T0_MS + 10);
        let id = c.propose("0".into(), m21_ptx(1));
        ctx_at(agent, EXEC_DEPOSIT, T0_MS + 10 + HOUR_MS);
        let _ = c.execute_proposal("0".into(), id, None, Some(U128(0)));
        assert_eq!(forwarded_sign_deposit(), Some(SIGN_DEPOSIT));
    }

    /// R21-1 (b): after an uncertain outcome, the identical retry is checked without its own
    /// earlier charge, so a vault more than half way to its cap can still retry (and it is not
    /// charged twice).
    #[test]
    fn an_uncertain_retry_is_not_blocked_by_its_own_charge() {
        let (mut c, alice, agent) = a1_with_agent();
        ctx_at(agent.clone(), POLICY_DEPOSIT, T0_MS + 10);
        let id = c.propose("0".into(), m21_ptx(60_000_000_000_000_000)); // 0.06 ETH of a 0.1 ETH cap
        ctx_at(agent, EXEC_DEPOSIT, T0_MS + 10 + HOUR_MS);
        let _ = c.execute_proposal("0".into(), id, None, None);
        assert!(!answer(&mut c, near_sdk::PromiseResult::Failed)); // uncertain: nonce and charge kept
        let spent = c.get_policy("0".into()).spend.eth.spent.0;
        assert!(spent > 60_000_000_000_000_000);
        ctx_at(alice, EXEC_DEPOSIT, T0_MS + 20 + HOUR_MS);
        let check = c.check_execution("0".into(), id);
        assert!(check.ready, "the identical retry can run: {:?}", check.reason);
        let _ = c.execute_proposal("0".into(), id, None, None);
        let f = c.get_inflight("0".into()).expect("retry in flight");
        assert_eq!((f.nonce, f.charged), (0, false), "same nonce, not charged again");
        assert_eq!(c.get_policy("0".into()).spend.eth.spent.0, spent);
    }

    /// R21-3: a proposal put back after a failed signature is kept even if the queue was filled
    /// while it was in flight.
    #[test]
    fn a_full_queue_never_drops_a_proposal_after_a_failed_signature() {
        let (mut c, alice, agent) = a1_with_agent();
        ctx_at(alice.clone(), POLICY_DEPOSIT, T0_MS + 10);
        let id = c.propose("0".into(), m21_ptx(50_000_000_000_000_000));
        ctx_at(alice, EXEC_DEPOSIT, T0_MS + 10 + HOUR_MS);
        let _ = c.execute_proposal("0".into(), id, None, None);
        for i in 0..MAX_QUEUED_PROPOSALS as u64 {
            ctx_at(agent.clone(), POLICY_DEPOSIT, T0_MS + 10 + HOUR_MS + 1 + i);
            c.propose("0".into(), m21_ptx(1));
        }
        assert!(!answer(&mut c, near_sdk::PromiseResult::Failed));
        assert!(c.list_proposals("0".into()).iter().any(|p| p.id == id), "the owner's proposal is back");
        assert_eq!(c.pinned.get(&id), Some(0), "pinned to its uncertain nonce");
    }

    /// R21-4: only the owner can re-sign a nonce that was already signed.
    #[test]
    #[should_panic(expected = "Only the vault owner can replace a signed nonce")]
    fn the_agent_cannot_replace_a_signed_nonce() {
        let (mut c, alice, agent) = a1_with_agent();
        ctx_at(alice.clone(), POLICY_DEPOSIT, T0_MS + 10);
        let id = c.propose("0".into(), a1_ptx());
        ctx_at(alice, EXEC_DEPOSIT, T0_MS + 10 + HOUR_MS);
        let _ = c.execute_proposal("0".into(), id, None, None);
        assert!(answer(&mut c, ok(&a1_response())));
        ctx_at(agent.clone(), POLICY_DEPOSIT, T0_MS + 30);
        let id2 = c.propose("0".into(), m21_ptx(2_000_000_000_000_000));
        ctx_at(agent, EXEC_DEPOSIT, T0_MS + 30 + HOUR_MS);
        let _ = c.execute_proposal("0".into(), id2, Some(0), None);
    }

    /// R21-5: the agent cannot also be the guardian.
    #[test]
    #[should_panic(expected = "the agent cannot be the guardian")]
    fn the_agent_cannot_be_the_guardian() {
        let alice = accounts(1);
        let mut c = setup_with_vault(alice.clone());
        let mut p = test_policy(1_000);
        p.proposer = Some(guardian());
        ctx_at(alice, POLICY_DEPOSIT, T0_MS);
        c.set_policy("0".into(), p);
    }

    /// R21-6: the largest possible ERC-1155 signed record fits the storage reserved for it.
    #[test]
    fn the_largest_erc1155_signed_record_fits_the_reserve() {
        let long_account: AccountId = format!("{}.testnet", "a".repeat(56)).parse().unwrap();
        // type + list header + chain + nonce + 2 fees + gas + to + value + data (header + 196) + y + r + s
        let max_raw = 1 + 3 + 9 + 9 + 17 + 17 + 9 + 21 + 17 + 3 + 196 + 1 + 1 + 33 + 33;
        let record = SignedRecord {
            token_id: u64::MAX.to_string(),
            proposal_id: u64::MAX,
            nonce: u64::MAX,
            signing_hash: format!("0x{}", "ab".repeat(32)),
            signed_tx: format!("0x{}", "cd".repeat(max_raw)),
            tx_hash: format!("0x{}", "ef".repeat(32)),
            owner: long_account,
            signed_ms: u64::MAX,
        };
        let key = signed_version_key(&record.token_id, record.nonce, u32::MAX);
        let bytes = near_sdk::borsh::to_vec(&record).unwrap().len() + near_sdk::borsh::to_vec(&key).unwrap().len() + 40 + 1;
        assert!((bytes as u64) <= SIGNED_RECORD_RESERVE_BYTES, "record needs {bytes} bytes");
    }
}
