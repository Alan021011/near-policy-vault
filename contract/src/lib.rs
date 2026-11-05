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
//! Not here yet: policy, proposals, MPC signing, two-phase sale.

pub mod evm;
pub mod policy;

use std::collections::HashMap;

use near_contract_standards::non_fungible_token::approval::NonFungibleTokenApproval;
use near_contract_standards::non_fungible_token::core::{
    NonFungibleTokenCore, NonFungibleTokenResolver,
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

/// Deposit attached to the signer's `sign` (measured in A1: 1 yoctoNEAR is accepted).
pub const SIGN_DEPOSIT: NearToken = NearToken::from_yoctonear(1);
/// Gas kept for our callback; all the remaining gas goes to `sign`.
pub const GAS_FOR_SIGN_CALLBACK: Gas = Gas::from_tgas(20);
/// Storage paid at execution for the signed record written later by the callback.
pub const SIGNED_RECORD_RESERVE_BYTES: u64 = 1000;

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
    pub proposal: Proposal,
    pub nonce: u64,
    pub signing_hash: String,
    pub charge: Reservation,
    /// Who paid the storage reserve (refunded if the signature fails).
    pub payer: AccountId,
    pub started_ms: u64,
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
        return Err("signature does not match the vault key");
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
    /// M7: every signed transaction, keyed by "<token_id>:<nonce>".
    signed: LookupMap<String, SignedRecord>,
}

/// State layout deployed for M6 (commits 7a95f8a and 9944426), used only by `migrate`.
#[near(serializers = [borsh])]
struct PolicyVaultV5 {
    tokens: NonFungibleToken,
    metadata: LazyOption<NFTContractMetadata>,
    next_token_id: u64,
    transfer_info: LookupMap<TokenId, TransferInfo>,
    signer_id: AccountId,
    vaults: LookupMap<TokenId, VaultRecord>,
    policies: LookupMap<TokenId, VaultPolicyState>,
    nonces: LookupMap<TokenId, u64>,
    next_proposal_id: u64,
}

fn signed_key(token_id: &str, nonce: u64) -> String {
    format!("{token_id}:{nonce}")
}

// ---------- M5: policy state, inputs and views ----------

/// A loosening policy change waiting for the current delay to pass (the guardian can veto it).
#[near(serializers = [borsh, json])]
#[derive(Clone, Debug, PartialEq)]
pub struct PendingPolicy {
    pub policy: Policy,
    pub apply_after_ms: u64,
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
pub const MAX_CALLDATA_LEN: usize = 68;

impl TxInput {
    pub fn to_tx(&self) -> Result<Eip1559Tx, String> {
        let to = policy::parse_address(&self.to).ok_or("malformed `to` address")?;
        let data = policy::parse_hex(&self.data).ok_or("malformed `data` hex")?;
        if data.len() > MAX_CALLDATA_LEN {
            return Err("calldata longer than 68 bytes".into());
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
        }
    }

    /// Upgrades the state written by the M6 deployment. Only the contract account can call it.
    /// Calling it on the current layout fails, because the old layout no longer parses.
    #[private]
    #[init(ignore_state)]
    pub fn migrate() -> Self {
        let old: PolicyVaultV5 = env::state_read().expect("no V5 state to migrate");
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
            inflight: LookupMap::new(StorageKey::InFlight),
            signed: LookupMap::new(StorageKey::Signed),
        }
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
    /// callback always sees the owner who asked for it (threat 5). M8 adds the sale freeze.
    fn assert_transferable(&self, token_id: &TokenId) {
        require_token_exists(&self.tokens, token_id);
        require!(
            self.inflight.get(token_id).is_none(),
            "A signature is in flight for this vault; transfer after it completes"
        );
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
        let before = env::storage_usage();
        if self.policies.remove(token_id).is_some() {
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
        match policy::check(&st.policy, &st.spend, &tx, env::block_timestamp_ms()) {
            Ok(r) => CheckResult { allowed: true, reason: None, signing_hash: hash, reservation: Some(r) },
            Err(e) => refused(e.to_string(), hash),
        }
    }
}

impl PolicyVault {
    fn owner_of(&self, token_id: &TokenId) -> AccountId {
        self.tokens.owner_by_id.get(token_id).unwrap_or_else(|| env::panic_str("Token not found"))
    }

    fn assert_owner(&self, token_id: &TokenId) -> AccountId {
        let owner = self.owner_of(token_id);
        require!(env::predecessor_account_id() == owner, "Only the vault owner can do this");
        owner
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
        let owner = self.assert_owner(&token_id);
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
        let reservation = policy::check(&st.policy, &st.spend, &candidate, now)
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
        settle_storage(before, &owner);
        emit_policy_event(
            "proposal_created",
            &token_id,
            json!({ "proposal_id": id, "executable_after_ms": executable_after_ms }),
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
        match self.prepare_execution(&token_id, proposal_id, env::block_timestamp_ms()) {
            Ok((tx, _)) => ExecutionCheck {
                ready: true,
                reason: None,
                nonce,
                signing_hash: Some(hex0x(&tx.signing_hash())),
            },
            Err(reason) => ExecutionCheck { ready: false, reason: Some(reason), nonce, signing_hash: None },
        }
    }
}

// ---------- M7: signing entry points ----------

#[near]
impl PolicyVault {
    /// Signs a ready proposal. Only the owner. In one synchronous step it charges the daily
    /// caps, takes the vault's next nonce and locks the vault (no second signature, no
    /// transfer) until the MPC answer arrives in `on_signed`. The deposit must cover
    /// `SIGNED_RECORD_RESERVE_BYTES` of storage plus 1 yoctoNEAR for the signer; the rest is
    /// refunded. Returns the promise, so the caller sees whether the signature was stored.
    #[payable]
    pub fn execute_proposal(&mut self, token_id: TokenId, proposal_id: u64) -> Promise {
        let owner = self.assert_owner(&token_id);
        require!(self.inflight.get(&token_id).is_none(), "A signature is already in flight for this vault");
        require!(
            self.vaults.get(&token_id).map(|v| v.resolved).unwrap_or(false),
            "Vault address not resolved yet; call resolve_vault_address first"
        );
        let before = env::storage_usage();
        let (proposal, tx, charge) = self.commit_execution(&token_id, proposal_id);
        let hash = tx.signing_hash();
        let hash_hex = hex0x(&hash);
        self.inflight.insert(
            &token_id,
            &InFlight {
                proposal: proposal.clone(),
                nonce: tx.nonce,
                signing_hash: hash_hex.clone(),
                charge,
                payer: owner.clone(),
                started_ms: env::block_timestamp_ms(),
            },
        );
        // Storage: whatever this call added, plus the record the callback will write.
        let added = env::storage_usage().saturating_sub(before) + SIGNED_RECORD_RESERVE_BYTES;
        let cost = env::storage_byte_cost().saturating_mul(added.into());
        let attached = env::attached_deposit();
        require!(
            cost.saturating_add(SIGN_DEPOSIT) <= attached,
            format!(
                "Must attach {} to cover storage and the signer deposit",
                cost.saturating_add(SIGN_DEPOSIT).exact_amount_display()
            )
        );
        refund_if_any(&owner, attached.saturating_sub(cost).saturating_sub(SIGN_DEPOSIT));
        emit_policy_event(
            "signature_requested",
            &token_id,
            json!({ "proposal_id": proposal.id, "nonce": tx.nonce, "signing_hash": hash_hex }),
        );
        let hex_no_prefix = hash_hex.trim_start_matches("0x").to_string();
        ext_signer::ext(self.signer_id.clone())
            .with_attached_deposit(SIGN_DEPOSIT)
            .with_unused_gas_weight(1)
            .sign(SignRequest {
                domain_id: SECP256K1_DOMAIN_ID,
                path: vault_path_for(&token_id),
                payload_v2: SignPayload::Ecdsa(hex_no_prefix),
            })
            .then(
                Self::ext(env::current_account_id())
                    .with_static_gas(GAS_FOR_SIGN_CALLBACK)
                    .with_unused_gas_weight(0)
                    .on_signed(token_id),
            )
    }

    /// Callback of the signer's `sign`. Never panics: on success it stores the signed
    /// transaction; on any failure (signer error, malformed answer, wrong key) it undoes the
    /// execution (releases the caps, restores the nonce, puts the proposal back in the queue)
    /// and refunds the storage reserve. Returns whether a signature was stored.
    #[private]
    pub fn on_signed(
        &mut self,
        token_id: TokenId,
        #[callback_result] result: Result<SignResponse, PromiseError>,
    ) -> bool {
        let Some(f) = self.inflight.remove(&token_id) else {
            env::log_str(&format!("on_signed: nothing in flight for token {token_id}"));
            return false;
        };
        let outcome = self.check_signer_answer(&token_id, &f, result);
        match outcome {
            Ok((parity, r, s)) => {
                let Ok(tx) = f.proposal.tx.to_tx(f.nonce) else {
                    self.undo_execution(&token_id, &f, "stored proposal no longer parses");
                    return false;
                };
                let raw = tx.rlp_signed(parity, &r, &s);
                let record = SignedRecord {
                    token_id: token_id.clone(),
                    proposal_id: f.proposal.id,
                    nonce: f.nonce,
                    signing_hash: f.signing_hash.clone(),
                    signed_tx: hex0x(&raw),
                    tx_hash: hex0x(&keccak256(&raw)),
                    owner: f.payer.clone(),
                    signed_ms: env::block_timestamp_ms(),
                };
                self.signed.insert(&signed_key(&token_id, f.nonce), &record);
                emit_policy_event(
                    "transaction_signed",
                    &token_id,
                    json!({
                        "proposal_id": record.proposal_id,
                        "nonce": record.nonce,
                        "tx_hash": record.tx_hash,
                        "signed_tx": record.signed_tx,
                    }),
                );
                true
            }
            Err(reason) => {
                self.undo_execution(&token_id, &f, reason);
                false
            }
        }
    }

    /// The signature a vault is waiting for, if any.
    pub fn get_inflight(&self, token_id: TokenId) -> Option<InFlight> {
        require_token_exists(&self.tokens, &token_id);
        self.inflight.get(&token_id)
    }

    pub fn get_signed(&self, token_id: TokenId, nonce: u64) -> Option<SignedRecord> {
        require_token_exists(&self.tokens, &token_id);
        self.signed.get(&signed_key(&token_id, nonce))
    }

    /// Signed transactions of a vault by nonce, from `from_nonce` (default 0), at most `limit`
    /// (default 20). A buyer compares these with the external account's nonce (M8).
    pub fn list_signed(&self, token_id: TokenId, from_nonce: Option<u64>, limit: Option<u64>) -> Vec<SignedRecord> {
        require_token_exists(&self.tokens, &token_id);
        let next = self.nonces.get(&token_id).unwrap_or(0);
        let from = from_nonce.unwrap_or(0);
        (from..next)
            .take(limit.unwrap_or(20).min(100) as usize)
            .filter_map(|n| self.signed.get(&signed_key(&token_id, n)))
            .collect()
    }
}

impl PolicyVault {
    fn check_signer_answer(
        &self,
        token_id: &TokenId,
        f: &InFlight,
        result: Result<SignResponse, PromiseError>,
    ) -> Result<(u8, [u8; 32], [u8; 32]), &'static str> {
        let resp = result.map_err(|_| "signer call failed")?;
        let vault = self.vaults.get(token_id).filter(|v| v.resolved).ok_or("vault key unknown")?;
        let hash: [u8; 32] = policy::parse_hex(&f.signing_hash)
            .and_then(|v| v.try_into().ok())
            .ok_or("stored hash malformed")?;
        verify_signature(&resp, &hash, &vault.public_key)
    }

    /// Reverts `commit_execution` after a failed signature. Safe because only one signature
    /// per vault can be in flight and the NFT cannot change owner meanwhile.
    fn undo_execution(&mut self, token_id: &TokenId, f: &InFlight, reason: &str) {
        let mut requeued = false;
        if let Some(mut st) = self.policies.get(token_id) {
            st.spend.release(&f.charge);
            if f.proposal.owner_epoch == self.owner_epoch(token_id) && st.proposals.len() < MAX_QUEUED_PROPOSALS {
                st.proposals.insert(0, f.proposal.clone());
                requeued = true;
            }
            self.policies.insert(token_id, &st);
        }
        self.nonces.insert(token_id, &f.nonce);
        refund_if_any(
            &f.payer,
            env::storage_byte_cost().saturating_mul(SIGNED_RECORD_RESERVE_BYTES.into()),
        );
        emit_policy_event(
            "signature_failed",
            token_id,
            json!({ "proposal_id": f.proposal.id, "nonce": f.nonce, "reason": reason, "requeued": requeued }),
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
        settle_storage(before, owner);
        p
    }

    /// The transaction that would be signed for a proposal at `now_ms`, with the vault's next
    /// nonce, and what it would charge to the caps, or why not. Checks: the proposal exists, it
    /// belongs to the current owner epoch, both its own delay and the current policy's delay
    /// have passed since it was made (review P4: raising the delay also holds queued
    /// proposals), and it passes the policy in force against what has already been signed in
    /// the current windows.
    fn prepare_execution(
        &self,
        token_id: &TokenId,
        proposal_id: u64,
        now_ms: u64,
    ) -> Result<(Eip1559Tx, Reservation), String> {
        let st = self.policies.get(token_id).ok_or("Proposal not found")?;
        let p = st.proposals.iter().find(|p| p.id == proposal_id).ok_or("Proposal not found")?;
        if p.owner_epoch != self.owner_epoch(token_id) {
            return Err("Proposal belongs to a previous owner".into());
        }
        let ready_at = p.executable_after_ms.max(p.created_ms.saturating_add(st.policy.delay_ms));
        if now_ms < ready_at {
            return Err("Proposal delay has not passed yet".into());
        }
        let nonce = self.nonces.get(token_id).unwrap_or(0);
        let tx = p.tx.to_tx(nonce)?;
        let charge = policy::check(&st.policy, &st.spend, &tx, now_ms)
            .map_err(|e| format!("Policy now refuses it: {e}"))?;
        Ok((tx, charge))
    }

    /// Takes a ready proposal out of the queue for signing: charges its spend to the current
    /// windows, gives the vault's next nonce to it and advances that nonce. All in one
    /// synchronous step, so two executions can never both fit under the cap (threat 6).
    /// M7 calls this before asking the MPC network to sign, and must undo it (release the
    /// charge, restore the nonce) if the signature fails, while no other signature is in flight.
    fn commit_execution(&mut self, token_id: &TokenId, proposal_id: u64) -> (Proposal, Eip1559Tx, Reservation) {
        let now = env::block_timestamp_ms();
        let (tx, charge) =
            self.prepare_execution(token_id, proposal_id, now).unwrap_or_else(|e| env::panic_str(&e));
        let mut st = self.policies.get(token_id).expect("checked by prepare_execution");
        st.spend.prune_expired(now);
        st.spend.reserve(&charge, now);
        let i = st.proposals.iter().position(|p| p.id == proposal_id).expect("checked");
        let p = st.proposals.remove(i);
        self.policies.insert(token_id, &st);
        self.nonces.insert(token_id, &(tx.nonce + 1));
        (p, tx, charge)
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
        self.assert_transferable(&token_id);
        let sender_id = env::predecessor_account_id();
        let (old_owner, cleared) =
            self.tokens.internal_transfer(&sender_id, &receiver_id, &token_id, approval_id, memo);
        refund_cleared_approvals(&old_owner, &cleared);
        let authorized = (sender_id != old_owner).then_some(sender_id);
        self.record_transfer(&token_id, "transfer", &old_owner, &receiver_id, authorized);
    }

    #[payable]
    fn nft_transfer_call(
        &mut self,
        receiver_id: AccountId,
        token_id: TokenId,
        approval_id: Option<u64>,
        memo: Option<String>,
        msg: String,
    ) -> PromiseOrValue<bool> {
        self.assert_transferable(&token_id);
        let old_owner = self.tokens.owner_by_id.get(&token_id).expect("checked above");
        let sender_id = env::predecessor_account_id();
        let result =
            self.tokens.nft_transfer_call(receiver_id.clone(), token_id.clone(), approval_id, memo, msg);
        // Reached only if the library's checks passed and the owner is now `receiver_id`.
        let authorized = (sender_id != old_owner).then_some(sender_id);
        self.record_transfer(&token_id, "transfer_call", &old_owner, &receiver_id, authorized);
        result
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
        self.tokens.nft_approve(token_id, account_id, msg)
    }

    #[payable]
    fn nft_revoke(&mut self, token_id: TokenId, account_id: AccountId) {
        self.tokens.nft_revoke(token_id, account_id)
    }

    #[payable]
    fn nft_revoke_all(&mut self, token_id: TokenId) {
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
        c.nft_transfer(accounts(2), "0".to_string(), None, None);
    }

    #[test]
    #[should_panic(expected = "Sender not approved")]
    fn stranger_cannot_transfer() {
        let mut c = setup_with_vault(accounts(1));
        ctx(accounts(3), ONE_YOCTO);
        c.nft_transfer(accounts(3), "0".to_string(), None, None);
    }

    #[test]
    #[should_panic(expected = "Token not found")]
    fn transfer_of_missing_token_fails() {
        let mut c = setup_with_vault(accounts(1));
        ctx(accounts(1), ONE_YOCTO);
        c.nft_transfer(accounts(2), "99".to_string(), None, None);
    }

    /// R3
    #[test]
    #[should_panic(expected = "Current and next owner must differ")]
    fn transfer_to_self_fails() {
        let alice = accounts(1);
        let mut c = setup_with_vault(alice.clone());
        ctx(alice.clone(), ONE_YOCTO);
        c.nft_transfer(alice, "0".to_string(), None, None);
    }

    // ---------- R1: own transfer record and complete event ----------

    #[test]
    fn library_event_lacks_authorized_id_but_ours_has_it() {
        let (alice, bob, carol) = (accounts(1), accounts(2), accounts(3));
        let mut c = setup_with_vault(alice.clone());
        approve(&mut c, &alice, &bob);
        ctx(bob.clone(), ONE_YOCTO);
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
        c.nft_transfer(carol, "0".to_string(), None, None);
        // bob was approved by alice; carol now owns the vault, so bob must be rejected.
        ctx(bob, ONE_YOCTO);
        c.nft_transfer(alice, "0".to_string(), None, None);
    }

    #[test]
    fn approved_account_can_transfer_once() {
        let (alice, bob, carol) = (accounts(1), accounts(2), accounts(3));
        let mut c = setup_with_vault(alice.clone());
        approve(&mut c, &alice, &bob);
        ctx(bob.clone(), ONE_YOCTO);
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
        c.nft_transfer(carol, "0".to_string(), None, None);
        let bytes = bytes_for_approved_account_id(&bob) + bytes_for_approved_account_id(&danny);
        let expected = env::storage_byte_cost().saturating_mul(bytes.into());
        assert_eq!(transfers(), vec![(alice, expected)]);
    }

    #[test]
    fn transfer_without_approvals_refunds_nothing() {
        let (alice, bob) = (accounts(1), accounts(2));
        let mut c = setup_with_vault(alice.clone());
        ctx(alice, ONE_YOCTO);
        c.nft_transfer(bob, "0".to_string(), None, None);
        assert!(transfers().is_empty());
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
        too_long.data = format!("0x{}", "00".repeat(69));
        let cases = [
            (tx_input(10_u128.pow(18)), "ETH daily cap exceeded"),
            (stranger, "destination not allowed"),
            (bad_hex, "malformed `data` hex"),
            (too_long, "calldata longer than 68 bytes"),
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
        c.nft_transfer(accounts(2), "0".into(), None, None);
        assert!(!c.get_policy("0".into()).has_policy, "buyer must receive a locked vault");
        let t = transfers();
        assert!(t.iter().any(|(to, amount)| *to == alice && *amount > NearToken::from_yoctonear(0)), "{t:?}");
    }

    #[test]
    fn transfer_call_that_comes_back_clears_the_receivers_policy() {
        let (alice, bob) = (accounts(1), accounts(2));
        let mut c = setup_with_vault(alice.clone());
        ctx_at(alice.clone(), ONE_YOCTO, T0_MS);
        let _ = c.nft_transfer_call(bob.clone(), "0".into(), None, None, "x".into());
        // During the call bob owns the vault and sets his own policy...
        ctx_at(bob.clone(), POLICY_DEPOSIT, T0_MS + 1);
        assert!(c.set_policy("0".into(), test_policy(1)));
        // ...then the receiver asks to return the token (nft_on_transfer returned true).
        let mut b = VMContextBuilder::new();
        b.current_account_id("vault.testnet".parse().unwrap())
            .predecessor_account_id("vault.testnet".parse().unwrap())
            .block_timestamp((T0_MS + 2) * 1_000_000);
        testing_env!(
            b.build(),
            near_sdk::test_vm_config(),
            near_sdk::RuntimeFeesConfig::test(),
            Default::default(),
            vec![near_sdk::PromiseResult::Successful(b"true".to_vec())]
        );
        assert!(!c.nft_resolve_transfer(alice.clone(), bob.clone(), "0".into(), Some(HashMap::new())));
        assert_eq!(c.nft_token("0".into()).unwrap().owner_id, alice);
        assert!(!c.get_policy("0".into()).has_policy, "the receiver's policy survived the return");
        assert!(transfers().iter().any(|(to, _)| *to == bob), "bob paid for that storage");
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
        c.commit_execution(&"0".to_string(), a);
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
        let (p, tx, charge) = c.commit_execution(&"0".to_string(), a);
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
        c.commit_execution(&"0".to_string(), a);
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
    #[should_panic(expected = "Only the vault owner can do this")]
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

    #[test]
    fn execute_asks_the_signer_for_exactly_the_validated_hash() {
        let (mut c, _, id) = ready_a1_proposal();
        let _ = c.execute_proposal("0".into(), id);
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
        let _ = c.execute_proposal("0".into(), id);
        assert!(c.on_signed("0".into(), Ok(a1_response())));
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
        let _ = c.execute_proposal("0".into(), id);
        let mut bad = a1_response();
        bad.s.scalar = "3a85fc21be896c6b5c90c09b479f75806a2b0933b1994876b1a7bb6c25733808".into();
        assert!(!c.on_signed("0".into(), Ok(bad)));
        assert_rolled_back(&c, id, "does not match the vault key");
    }

    #[test]
    fn signature_for_another_key_is_rejected() {
        // A valid signature, but the vault's key is different (vault-0 of the M4 tests).
        let (mut c, _, id) = ready_a1_proposal();
        let _ = c.execute_proposal("0".into(), id);
        let mut v = c.vaults.get(&"0".to_string()).unwrap();
        v.public_key = parse_secp256k1_key(VAULT0_KEY).unwrap();
        c.vaults.insert(&"0".to_string(), &v);
        assert!(!c.on_signed("0".into(), Ok(a1_response())));
        assert_rolled_back(&c, id, "does not match the vault key");
    }

    #[test]
    fn signer_failure_is_undone() {
        let (mut c, _, id) = ready_a1_proposal();
        let _ = c.execute_proposal("0".into(), id);
        assert!(!c.on_signed("0".into(), Err(PromiseError::Failed)));
        assert_rolled_back(&c, id, "signer call failed");
    }

    #[test]
    fn malformed_answer_is_undone() {
        let (mut c, _, id) = ready_a1_proposal();
        let _ = c.execute_proposal("0".into(), id);
        let mut bad = a1_response();
        bad.big_r.affine_point = "054057bd4e77d6989afeabbb8eaef7cbe4554cc0eb036393d05a6195347cbf1d98".into();
        assert!(!c.on_signed("0".into(), Ok(bad)));
        assert_rolled_back(&c, id, "not a compressed point");
    }

    #[test]
    #[should_panic(expected = "A signature is already in flight for this vault")]
    fn only_one_signature_in_flight() {
        let (mut c, alice, id) = ready_a1_proposal();
        ctx_at(alice.clone(), POLICY_DEPOSIT, T0_MS + 20);
        let id2 = c.propose("0".into(), a1_ptx());
        let _ = id;
        ctx_at(alice.clone(), EXEC_DEPOSIT, T0_MS + 20 + HOUR_MS);
        let _ = c.execute_proposal("0".into(), id);
        let _ = c.execute_proposal("0".into(), id2);
    }

    #[test]
    #[should_panic(expected = "A signature is in flight for this vault; transfer after it completes")]
    fn no_transfer_while_a_signature_is_in_flight() {
        let (mut c, alice, id) = ready_a1_proposal();
        let _ = c.execute_proposal("0".into(), id);
        ctx_at(alice, ONE_YOCTO, T0_MS + 20 + HOUR_MS);
        c.nft_transfer(accounts(2), "0".into(), None, None);
    }

    #[test]
    fn after_signing_the_vault_can_be_sold_and_keeps_its_nonce_and_history() {
        let (mut c, alice, id) = ready_a1_proposal();
        let _ = c.execute_proposal("0".into(), id);
        c.on_signed("0".into(), Ok(a1_response()));
        ctx_at(alice, ONE_YOCTO, T0_MS + 30 + HOUR_MS);
        c.nft_transfer(accounts(2), "0".into(), None, None);
        assert_eq!(c.get_next_nonce("0".into()), 1, "the external account's nonce survives the sale");
        assert_eq!(c.list_signed("0".into(), None, None).len(), 1, "the buyer can audit past signatures");
    }

    #[test]
    #[should_panic(expected = "Only the vault owner can do this")]
    fn stranger_cannot_execute() {
        let (mut c, _, id) = ready_a1_proposal();
        ctx_at(accounts(3), EXEC_DEPOSIT, T0_MS + 10 + HOUR_MS);
        let _ = c.execute_proposal("0".into(), id);
    }

    #[test]
    #[should_panic(expected = "Proposal delay has not passed yet")]
    fn execute_respects_the_delay() {
        let (mut c, alice, id) = ready_a1_proposal();
        ctx_at(alice, EXEC_DEPOSIT, T0_MS + 10 + HOUR_MS - 1);
        let _ = c.execute_proposal("0".into(), id);
    }

    #[test]
    #[should_panic(expected = "to cover storage and the signer deposit")]
    fn execute_needs_a_deposit() {
        let (mut c, alice, id) = ready_a1_proposal();
        ctx_at(alice, ONE_YOCTO, T0_MS + 10 + HOUR_MS);
        let _ = c.execute_proposal("0".into(), id);
    }

    #[test]
    #[should_panic(expected = "Vault address not resolved yet")]
    fn execute_needs_a_resolved_vault() {
        let (mut c, alice) = vault_with_policy(); // vault key never resolved
        let id = propose_as(&mut c, &alice, 1, T0_MS + 10);
        ctx_at(alice, EXEC_DEPOSIT, T0_MS + 10 + HOUR_MS);
        let _ = c.execute_proposal("0".into(), id);
    }

    #[test]
    fn contract_metadata_follows_nep177() {
        let c = setup_with_vault(accounts(1));
        let m = c.nft_metadata();
        assert_eq!(m.spec, NFT_METADATA_SPEC);
        assert_eq!(m.symbol, "PVAULT");
    }
}
