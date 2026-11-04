//! Test helper, not part of the product: a receiver for `nft_transfer_call`.
//! - msg "return": asks the NFT contract to give the token back (returns true).
//! - msg "panic":  fails, which the NFT contract must also treat as "give it back".
//! - anything else: keeps the token (returns false).

use near_contract_standards::non_fungible_token::core::NonFungibleTokenReceiver;
use near_contract_standards::non_fungible_token::TokenId;
use near_sdk::{env, near, AccountId, PromiseOrValue};

#[near(contract_state)]
#[derive(Default)]
pub struct TestReceiver {}

#[near]
impl NonFungibleTokenReceiver for TestReceiver {
    fn nft_on_transfer(
        &mut self,
        sender_id: AccountId,
        previous_owner_id: AccountId,
        token_id: TokenId,
        msg: String,
    ) -> PromiseOrValue<bool> {
        env::log_str(&format!(
            "nft_on_transfer token={token_id} sender={sender_id} previous_owner={previous_owner_id} msg={msg}"
        ));
        match msg.as_str() {
            "return" => PromiseOrValue::Value(true),
            "panic" => env::panic_str("test receiver: forced failure"),
            _ => PromiseOrValue::Value(false),
        }
    }
}
