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
//! Not here yet: policy, proposals, MPC signing, two-phase sale.

pub mod evm;

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
    assert_one_yocto, env, near, require, AccountId, BorshStorageKey, NearToken, PanicOnDefault,
    Promise, PromiseOrValue,
};

/// Prefix of the Chain Signatures derivation path of every vault.
pub const VAULT_PATH_PREFIX: &str = "vault-";

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
}

/// State layout of the first deployment (commit 5a4ad3c), used only by `migrate`.
#[near(serializers = [borsh])]
struct PolicyVaultV1 {
    tokens: NonFungibleToken,
    metadata: LazyOption<NFTContractMetadata>,
    next_token_id: u64,
}

#[near]
impl PolicyVault {
    #[init]
    pub fn new() -> Self {
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
        }
    }

    /// Upgrades the state written by the first deployment. Only the contract account can call
    /// it. Calling it on the current layout fails, because the old layout no longer parses.
    #[private]
    #[init(ignore_state)]
    pub fn migrate() -> Self {
        let old: PolicyVaultV1 = env::state_read().expect("no V1 state to migrate");
        Self {
            tokens: old.tokens,
            metadata: old.metadata,
            next_token_id: old.next_token_id,
            transfer_info: LookupMap::new(StorageKey::TransferInfo),
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
        token
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

    /// Hook called before any transfer. Only checks existence in M3: M8 adds the sale freeze
    /// and the lock while a signature is in flight.
    fn assert_transferable(&self, token_id: &TokenId) {
        require_token_exists(&self.tokens, token_id);
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

    fn ctx(predecessor: AccountId, deposit: NearToken) {
        let mut b = VMContextBuilder::new();
        b.current_account_id("vault.testnet".parse().unwrap())
            .predecessor_account_id(predecessor)
            .attached_deposit(deposit);
        testing_env!(b.build());
    }

    fn setup_with_vault(owner: AccountId) -> PolicyVault {
        ctx(accounts(0), NearToken::from_yoctonear(0));
        let mut c = PolicyVault::new();
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
        let mut c = PolicyVault::new();
        ctx(accounts(1), NearToken::from_yoctonear(0));
        c.mint_vault();
    }

    /// R3: the minter gets back exactly the deposit minus storage (token + reserve).
    #[test]
    fn mint_refunds_the_excess_to_the_minter() {
        ctx(accounts(0), NearToken::from_yoctonear(0));
        let mut c = PolicyVault::new();
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

    #[test]
    fn contract_metadata_follows_nep177() {
        let c = setup_with_vault(accounts(1));
        let m = c.nft_metadata();
        assert_eq!(m.spec, NFT_METADATA_SPEC);
        assert_eq!(m.symbol, "PVAULT");
    }
}
