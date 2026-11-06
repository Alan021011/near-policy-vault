//! Test helper, not part of the product: a receiver for `nft_transfer_call`.
//! - msg "return": asks the NFT contract to give the token back (returns true).
//! - msg "panic":  fails, which the NFT contract must also treat as "give it back".
//! - msg "act":    the attack from the general review after M8 (H1). While it owns the vault,
//!                 before the transfer resolves, it tries to act as owner: it sets a policy with
//!                 delay 0 on the vault (the first step to sign a payment), logs whether the
//!                 vault contract refused it, and then gives the token back.
//! - anything else: keeps the token (returns false).

use near_contract_standards::non_fungible_token::core::NonFungibleTokenReceiver;
use near_contract_standards::non_fungible_token::TokenId;
use near_sdk::serde_json::json;
use near_sdk::{env, near, AccountId, Gas, NearToken, Promise, PromiseOrValue};

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
            "act" => {
                let policy = json!({
                    "chain_id": 11155111u64,
                    "delay_ms": 0u64,
                    "guardian": null,
                    "eth_daily_cap": "1000000000000000000",
                    "max_gas_cost": "1000000000000000",
                    "allowed_destinations": ["0x1111111111111111111111111111111111111111"],
                    "allowed_spenders": [],
                    "tokens": []
                });
                let args = json!({ "token_id": token_id, "policy": policy }).to_string().into_bytes();
                Promise::new(env::predecessor_account_id())
                    .function_call("set_policy".to_string(), args, NearToken::from_millinear(50), Gas::from_tgas(20))
                    .then(Self::ext(env::current_account_id()).with_static_gas(Gas::from_tgas(5)).after_act())
                    .into()
            }
            _ => PromiseOrValue::Value(false),
        }
    }
}

#[near]
impl TestReceiver {
    /// Logs the outcome of the attempt and asks for the token to be given back.
    #[private]
    pub fn after_act(&self) -> bool {
        match env::promise_result_checked(0, 100) {
            Ok(_) => env::log_str("test receiver: set_policy ACCEPTED during transfer_call"),
            Err(_) => env::log_str("test receiver: set_policy REFUSED during transfer_call"),
        }
        true
    }
}
