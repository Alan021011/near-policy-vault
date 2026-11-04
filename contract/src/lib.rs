//! near-policy-vault: an NFT that owns an EVM account guarded by a spending policy.
//!
//! Module M3 (this file): a NEP-171 collection where every token is a vault.
//! - Anyone can mint a vault for themselves and pays the storage it uses.
//! - Token ids are sequential ("0", "1", ...). Each vault's EVM account is derived by
//!   NEAR Chain Signatures from this contract's account id and the path `vault-<token_id>`.
//! - Transfers, approvals and enumeration come from `near-contract-standards`, but every
//!   entry point goes through a wrapper here so later modules can add the sale freeze and
//!   the "signature in flight" lock (threats 1 and 5 in docs/THREAT_MODEL.md).
//!
//! Not here yet: policy, proposals, MPC signing, two-phase sale.

pub mod evm;

use std::collections::HashMap;

use near_contract_standards::non_fungible_token::approval::NonFungibleTokenApproval;
use near_contract_standards::non_fungible_token::core::{
    NonFungibleTokenCore, NonFungibleTokenResolver,
};
use near_contract_standards::non_fungible_token::enumeration::NonFungibleTokenEnumeration;
use near_contract_standards::non_fungible_token::metadata::{
    NFTContractMetadata, NonFungibleTokenMetadataProvider, TokenMetadata, NFT_METADATA_SPEC,
};
use near_contract_standards::non_fungible_token::{NonFungibleToken, Token, TokenId};
use near_sdk::collections::LazyOption;
use near_sdk::json_types::U128;
use near_sdk::{env, near, AccountId, BorshStorageKey, PanicOnDefault, Promise, PromiseOrValue};

/// Prefix of the Chain Signatures derivation path of every vault.
pub const VAULT_PATH_PREFIX: &str = "vault-";

#[near(serializers = [borsh])]
#[derive(BorshStorageKey)]
enum StorageKey {
    OwnerById,
    TokenMetadata,
    Enumeration,
    Approval,
    ContractMetadata,
}

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct PolicyVault {
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
        }
    }

    /// Mints a new vault owned by the caller. The caller attaches a deposit that covers the
    /// storage of the token; the rest is refunded.
    #[payable]
    pub fn mint_vault(&mut self) -> Token {
        let owner_id = env::predecessor_account_id();
        let token_id = self.next_token_id.to_string();
        self.next_token_id += 1;
        let path = vault_path_for(&token_id);
        let metadata = TokenMetadata {
            title: Some(format!("Policy Vault #{token_id}")),
            description: Some(format!(
                "Controls the EVM account derived by NEAR Chain Signatures from {} with path {}.",
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
        self.tokens.internal_mint(token_id, owner_id, Some(metadata))
    }

    /// Chain Signatures derivation path of a vault. The EVM address is obtained off-chain with
    /// `derived_public_key(path, predecessor = this contract, domain_id = 0)` on the signer.
    pub fn vault_path(&self, token_id: TokenId) -> String {
        require_token_exists(&self.tokens, &token_id);
        vault_path_for(&token_id)
    }

    /// Hook called before any transfer. Empty in M3 on purpose: M8 adds the sale freeze and
    /// the lock while a signature is in flight.
    fn assert_transferable(&self, token_id: &TokenId) {
        require_token_exists(&self.tokens, token_id);
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

#[near]
impl NonFungibleTokenCore for PolicyVault {
    #[payable]
    fn nft_transfer(
        &mut self,
        receiver_id: AccountId,
        token_id: TokenId,
        approval_id: Option<u64>,
        memo: Option<String>,
    ) {
        self.assert_transferable(&token_id);
        self.tokens.nft_transfer(receiver_id, token_id, approval_id, memo)
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
        self.tokens.nft_transfer_call(receiver_id, token_id, approval_id, memo, msg)
    }

    fn nft_token(&self, token_id: TokenId) -> Option<Token> {
        self.tokens.nft_token(token_id)
    }
}

#[near]
impl NonFungibleTokenResolver for PolicyVault {
    #[private]
    fn nft_resolve_transfer(
        &mut self,
        previous_owner_id: AccountId,
        receiver_id: AccountId,
        token_id: TokenId,
        approved_account_ids: Option<HashMap<AccountId, u64>>,
    ) -> bool {
        self.tokens.nft_resolve_transfer(previous_owner_id, receiver_id, token_id, approved_account_ids)
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
    use near_sdk::test_utils::{accounts, get_logs, VMContextBuilder};
    use near_sdk::{testing_env, NearToken};

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

    #[test]
    fn transfer_clears_approvals() {
        let (alice, bob, carol) = (accounts(1), accounts(2), accounts(3));
        let mut c = setup_with_vault(alice.clone());
        ctx(alice.clone(), STORAGE_DEPOSIT);
        c.nft_approve("0".to_string(), bob.clone(), None);
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
        ctx(alice.clone(), STORAGE_DEPOSIT);
        c.nft_approve("0".to_string(), bob.clone(), None);
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
        ctx(alice, STORAGE_DEPOSIT);
        c.nft_approve("0".to_string(), bob.clone(), None);
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
