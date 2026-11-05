//! Spending policy of a vault (module M5). Pure logic: no storage, no `env`.
//!
//! The contract stores one `Policy` per vault and asks `check` whether a candidate EIP-1559
//! transaction may be signed. `check` looks only at fields the contract has validated and
//! classified itself (see `evm.rs`); it never trusts a hash or a "kind" supplied by a caller.
//!
//! Rules, in the order they are checked (the first failure is reported):
//! 1. `chain_id` must be the vault's chain (threat 12).
//! 2. `max_priority_fee_per_gas <= max_fee_per_gas`, and the worst-case gas cost
//!    `max_fee_per_gas * gas_limit` must not exceed `max_gas_cost`.
//! 3. The calldata must be one of the three allowed shapes:
//!    - empty: a plain ETH transfer, `to` must be an allowed destination;
//!    - ERC-20 `transfer(recipient, amount)`: `to` must be an allowed token, `value` must be 0,
//!      the recipient an allowed destination, the amount within the token's daily cap;
//!    - ERC-20 `approve(spender, amount)`: `to` an allowed token, `value` 0, the spender an
//!      allowed spender, the amount at most the token's `max_approval` (threat 7: a cap, not
//!      just a check for 2^256-1).
//!    Amounts must fit in 128 bits; anything larger is rejected.
//! 4. The ETH spend of the transaction, `value + max_fee_per_gas * gas_limit`, must fit in the
//!    ETH daily cap.
//!
//! Daily caps use a fixed 24-hour window that starts at the first reservation and restarts
//! when it expires. Worst case across a window boundary is twice the cap; this is documented
//! in the threat model. Reservations are made when a transaction is proposed and released if
//! it is cancelled or vetoed (module M6).
//!
//! Changing a policy: `is_not_looser(new, old)` decides whether a change may apply at once
//! (it only tightens) or must wait the current delay, during which the guardian can veto it.

use std::fmt;

use near_sdk::json_types::U128;
use near_sdk::{near, AccountId};

use crate::evm::{classify, Address, CallKind, Eip1559Tx};

pub const DAY_MS: u64 = 86_400_000;
/// Smallest gas limit of any EVM transaction (a plain transfer). Below it a transaction can
/// never be mined, and signing it would burn a nonce and jam the account (review P2).
pub const MIN_GAS_LIMIT: u64 = 21_000;
/// Shortest wait for replacing or removing a guardian, whatever the delay (review P3).
pub const GUARDIAN_CHANGE_MIN_MS: u64 = 3 * DAY_MS;
/// Longest delay a policy may ask for (30 days), so a typo cannot lock a vault for years.
pub const MAX_DELAY_MS: u64 = 30 * DAY_MS;
/// Bound on every list in a policy, to keep storage and gas predictable.
pub const MAX_LIST_LEN: usize = 32;

/// Rules for one ERC-20 token contract.
#[near(serializers = [borsh, json])]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TokenRule {
    /// Token contract address, `0x` + 40 lowercase hex characters.
    pub contract: String,
    /// Maximum amount moved with `transfer` per 24-hour window (token base units).
    pub daily_cap: U128,
    /// Maximum amount of a single `approve` (token base units).
    pub max_approval: U128,
}

#[near(serializers = [borsh, json])]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Policy {
    /// The only EVM chain this vault signs for.
    pub chain_id: u64,
    /// Time between proposing and executing a transaction, and the time a loosening policy
    /// change waits before it applies.
    pub delay_ms: u64,
    /// Account that can veto a queued transaction or a pending policy change.
    pub guardian: Option<AccountId>,
    /// Maximum ETH spend per 24-hour window, in wei. Spend = value + worst-case gas cost.
    pub eth_daily_cap: U128,
    /// Maximum `max_fee_per_gas * gas_limit` of a single transaction, in wei.
    pub max_gas_cost: U128,
    /// Recipients allowed for ETH transfers and ERC-20 `transfer`.
    pub allowed_destinations: Vec<String>,
    /// Spenders allowed in ERC-20 `approve`.
    pub allowed_spenders: Vec<String>,
    /// ERC-20 contracts the vault may call, with their caps.
    pub tokens: Vec<TokenRule>,
}

impl Policy {
    /// The policy of a vault that has none: nothing can be signed.
    pub fn locked() -> Self {
        Self {
            chain_id: 0,
            delay_ms: 0,
            guardian: None,
            eth_daily_cap: U128(0),
            max_gas_cost: U128(0),
            allowed_destinations: Vec::new(),
            allowed_spenders: Vec::new(),
            tokens: Vec::new(),
        }
    }

    /// Validates a policy supplied by an owner and lowercases its addresses.
    pub fn normalized(mut self) -> Result<Self, PolicyError> {
        use PolicyError::InvalidPolicy;
        if self.chain_id == 0 {
            return Err(InvalidPolicy("chain_id must not be 0"));
        }
        if self.delay_ms > MAX_DELAY_MS {
            return Err(InvalidPolicy("delay_ms above 30 days"));
        }
        if self.allowed_destinations.len() > MAX_LIST_LEN
            || self.allowed_spenders.len() > MAX_LIST_LEN
            || self.tokens.len() > MAX_LIST_LEN
        {
            return Err(InvalidPolicy("a list has more than 32 entries"));
        }
        for a in self.allowed_destinations.iter_mut().chain(self.allowed_spenders.iter_mut()) {
            *a = normalize_address(a).ok_or(InvalidPolicy("malformed address"))?;
        }
        for t in self.tokens.iter_mut() {
            t.contract = normalize_address(&t.contract).ok_or(InvalidPolicy("malformed token address"))?;
        }
        if has_duplicates(&self.allowed_destinations) || has_duplicates(&self.allowed_spenders) {
            return Err(InvalidPolicy("duplicate address"));
        }
        let contracts: Vec<String> = self.tokens.iter().map(|t| t.contract.clone()).collect();
        if has_duplicates(&contracts) {
            return Err(InvalidPolicy("duplicate token"));
        }
        Ok(self)
    }

    fn token(&self, contract: &str) -> Option<&TokenRule> {
        self.tokens.iter().find(|t| t.contract == contract)
    }
}

/// Why a transaction or a policy was refused. The text is what the contract panics with.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PolicyError {
    WrongChain,
    GasLimitTooLow,
    ZeroFee,
    FeeOrder,
    GasCostTooHigh,
    DestinationNotAllowed,
    TokenNotAllowed,
    SpenderNotAllowed,
    ValueWithCalldata,
    AmountTooLarge,
    ApprovalTooHigh,
    TokenCapExceeded,
    EthCapExceeded,
    CalldataNotAllowed,
    Overflow,
    InvalidPolicy(&'static str),
}

impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::WrongChain => "chain_id is not the vault's chain",
            Self::GasLimitTooLow => "gas_limit below 21000",
            Self::ZeroFee => "max_fee_per_gas must be above 0",
            Self::FeeOrder => "max_priority_fee_per_gas above max_fee_per_gas",
            Self::GasCostTooHigh => "max_fee_per_gas * gas_limit above max_gas_cost",
            Self::DestinationNotAllowed => "destination not allowed",
            Self::TokenNotAllowed => "token contract not allowed",
            Self::SpenderNotAllowed => "spender not allowed",
            Self::ValueWithCalldata => "value must be 0 for a token call",
            Self::AmountTooLarge => "amount does not fit in 128 bits",
            Self::ApprovalTooHigh => "approval above the token's max_approval",
            Self::TokenCapExceeded => "token daily cap exceeded",
            Self::EthCapExceeded => "ETH daily cap exceeded",
            Self::CalldataNotAllowed => "calldata is not a plain transfer, ERC-20 transfer or approve",
            Self::Overflow => "arithmetic overflow",
            Self::InvalidPolicy(why) => return write!(f, "invalid policy: {why}"),
        };
        f.write_str(s)
    }
}

/// A fixed 24-hour spending window.
#[near(serializers = [borsh, json])]
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Window {
    pub start_ms: u64,
    pub spent: U128,
}

impl Window {
    fn rolled(&self, now_ms: u64) -> Window {
        if now_ms >= self.start_ms.saturating_add(DAY_MS) {
            Window { start_ms: now_ms, spent: U128(0) }
        } else {
            self.clone()
        }
    }

    pub fn remaining(&self, cap: u128, now_ms: u64) -> u128 {
        cap.saturating_sub(self.rolled(now_ms).spent.0)
    }

    pub fn reserve(&mut self, amount: u128, now_ms: u64) {
        *self = self.rolled(now_ms);
        self.spent = U128(self.spent.0.saturating_add(amount));
    }

    /// Gives back a reservation. If the window has restarted since, the amount is released
    /// against the new window (saturating at 0), which is the conservative side.
    pub fn release(&mut self, amount: u128) {
        self.spent = U128(self.spent.0.saturating_sub(amount));
    }
}

#[near(serializers = [borsh, json])]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TokenWindow {
    pub contract: String,
    pub window: Window,
}

/// Current reservations of a vault.
#[near(serializers = [borsh, json])]
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SpendState {
    pub eth: Window,
    pub tokens: Vec<TokenWindow>,
}

impl SpendState {
    fn token_window(&self, contract: &str) -> Window {
        self.tokens.iter().find(|t| t.contract == contract).map(|t| t.window.clone()).unwrap_or_default()
    }

    fn token_window_mut(&mut self, contract: &str) -> &mut Window {
        if let Some(i) = self.tokens.iter().position(|t| t.contract == contract) {
            return &mut self.tokens[i].window;
        }
        self.tokens.push(TokenWindow { contract: contract.to_string(), window: Window::default() });
        &mut self.tokens.last_mut().expect("just pushed").window
    }

    pub fn reserve(&mut self, r: &Reservation, now_ms: u64) {
        self.eth.reserve(r.eth.0, now_ms);
        if let Some(c) = &r.token_contract {
            self.token_window_mut(c).reserve(r.token_amount.0, now_ms);
        }
    }

    pub fn release(&mut self, r: &Reservation) {
        self.eth.release(r.eth.0);
        if let Some(c) = &r.token_contract {
            self.token_window_mut(c).release(r.token_amount.0);
        }
    }

    /// Drops token windows whose 24 hours are over (review P6). Active windows are kept even
    /// for tokens no longer in the policy, so removing and re-adding a token the same day does
    /// not give a fresh cap.
    pub fn prune_expired(&mut self, now_ms: u64) {
        self.tokens.retain(|t| now_ms < t.window.start_ms.saturating_add(DAY_MS));
    }
}

/// What a transaction consumes from the caps if it is queued.
#[near(serializers = [borsh, json])]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reservation {
    /// value + max_fee_per_gas * gas_limit, in wei.
    pub eth: U128,
    pub token_contract: Option<String>,
    pub token_amount: U128,
}

/// Decides whether `tx` may be signed under `policy` given the current reservations.
pub fn check(
    policy: &Policy,
    spend: &SpendState,
    tx: &Eip1559Tx,
    now_ms: u64,
) -> Result<Reservation, PolicyError> {
    use PolicyError::*;
    if tx.chain_id != policy.chain_id {
        return Err(WrongChain);
    }
    if tx.gas_limit < MIN_GAS_LIMIT {
        return Err(GasLimitTooLow);
    }
    if tx.max_fee_per_gas == 0 {
        return Err(ZeroFee);
    }
    if tx.max_priority_fee_per_gas > tx.max_fee_per_gas {
        return Err(FeeOrder);
    }
    let gas_cost = tx.max_fee_per_gas.checked_mul(tx.gas_limit as u128).ok_or(GasCostTooHigh)?;
    if gas_cost > policy.max_gas_cost.0 {
        return Err(GasCostTooHigh);
    }
    let to = address_hex(&tx.to);

    let (eth, token) = match classify(&tx.data) {
        CallKind::PlainTransfer => {
            if !policy.allowed_destinations.contains(&to) {
                return Err(DestinationNotAllowed);
            }
            (tx.value.checked_add(gas_cost).ok_or(Overflow)?, None)
        }
        CallKind::Erc20Transfer { recipient, amount } => {
            if tx.value != 0 {
                return Err(ValueWithCalldata);
            }
            let rule = policy.token(&to).ok_or(TokenNotAllowed)?;
            if !policy.allowed_destinations.contains(&address_hex(&recipient)) {
                return Err(DestinationNotAllowed);
            }
            let amount = u128_from_word(&amount).ok_or(AmountTooLarge)?;
            if amount > spend.token_window(&to).remaining(rule.daily_cap.0, now_ms) {
                return Err(TokenCapExceeded);
            }
            (gas_cost, Some((to.clone(), amount)))
        }
        CallKind::Erc20Approve { spender, amount } => {
            if tx.value != 0 {
                return Err(ValueWithCalldata);
            }
            let rule = policy.token(&to).ok_or(TokenNotAllowed)?;
            if !policy.allowed_spenders.contains(&address_hex(&spender)) {
                return Err(SpenderNotAllowed);
            }
            let amount = u128_from_word(&amount).ok_or(AmountTooLarge)?;
            if amount > rule.max_approval.0 {
                return Err(ApprovalTooHigh);
            }
            (gas_cost, None)
        }
        CallKind::Unknown => return Err(CalldataNotAllowed),
    };

    if eth > spend.eth.remaining(policy.eth_daily_cap.0, now_ms) {
        return Err(EthCapExceeded);
    }
    Ok(Reservation {
        eth: U128(eth),
        token_contract: token.as_ref().map(|(c, _)| c.clone()),
        token_amount: U128(token.map(|(_, a)| a).unwrap_or(0)),
    })
}

/// `true` when `new` is at most as permissive as `old` in every dimension, so it may apply at
/// once. Anything else (a higher cap, a shorter delay, a changed or removed guardian, a new
/// address or token, another chain) is a loosening and must wait `old.delay_ms`.
pub fn is_not_looser(new: &Policy, old: &Policy) -> bool {
    let guardian_ok = match (&old.guardian, &new.guardian) {
        (None, _) => true,
        (Some(g), Some(h)) => g == h,
        (Some(_), None) => false,
    };
    new.chain_id == old.chain_id
        && new.delay_ms >= old.delay_ms
        && guardian_ok
        && new.eth_daily_cap.0 <= old.eth_daily_cap.0
        && new.max_gas_cost.0 <= old.max_gas_cost.0
        && is_subset(&new.allowed_destinations, &old.allowed_destinations)
        && is_subset(&new.allowed_spenders, &old.allowed_spenders)
        && new.tokens.iter().all(|t| {
            old.token(&t.contract)
                .map(|o| t.daily_cap.0 <= o.daily_cap.0 && t.max_approval.0 <= o.max_approval.0)
                .unwrap_or(false)
        })
}

/// `true` when a change would replace or remove a guardian that exists today. Such a change
/// cannot be vetoed by that guardian and waits `guardian_change_wait_ms` (review P3).
pub fn replaces_guardian(new: &Policy, old: &Policy) -> bool {
    old.guardian.is_some() && new.guardian != old.guardian
}

/// Wait before a guardian replacement applies: twice the delay, and never under 3 days.
pub fn guardian_change_wait_ms(old: &Policy) -> u64 {
    old.delay_ms.saturating_mul(2).max(GUARDIAN_CHANGE_MIN_MS)
}

// ---------- helpers ----------

pub fn address_hex(a: &Address) -> String {
    let mut s = String::with_capacity(42);
    s.push_str("0x");
    for b in a {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Accepts `0x` + 40 hex characters in any case; returns the lowercase form.
pub fn normalize_address(s: &str) -> Option<String> {
    parse_address(s).map(|a| address_hex(&a))
}

pub fn parse_address(s: &str) -> Option<Address> {
    let bytes = parse_hex(s)?;
    bytes.try_into().ok()
}

pub fn parse_hex(s: &str) -> Option<Vec<u8>> {
    let h = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X"))?;
    if h.len() % 2 != 0 {
        return None;
    }
    (0..h.len()).step_by(2).map(|i| u8::from_str_radix(&h[i..i + 2], 16).ok()).collect()
}

/// A 32-byte big-endian word as u128, or `None` if any of the 16 high bytes is set.
fn u128_from_word(w: &[u8; 32]) -> Option<u128> {
    if w[..16].iter().any(|b| *b != 0) {
        return None;
    }
    let mut lo = [0u8; 16];
    lo.copy_from_slice(&w[16..]);
    Some(u128::from_be_bytes(lo))
}

fn is_subset(a: &[String], b: &[String]) -> bool {
    a.iter().all(|x| b.contains(x))
}

fn has_duplicates(v: &[String]) -> bool {
    (1..v.len()).any(|i| v[i..].contains(&v[i - 1]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evm::{SEL_ERC20_APPROVE, SEL_ERC20_TRANSFER};

    const CHAIN: u64 = 11155111;
    const DEST: &str = "0x1111111111111111111111111111111111111111";
    const OTHER: &str = "0x2222222222222222222222222222222222222222";
    const TOKEN: &str = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const SPENDER: &str = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const GWEI: u128 = 1_000_000_000;
    const ETH: u128 = 1_000_000_000_000_000_000;
    const NOW: u64 = 1_700_000_000_000;

    fn addr(s: &str) -> Address {
        parse_address(s).unwrap()
    }

    fn policy() -> Policy {
        Policy {
            chain_id: CHAIN,
            delay_ms: 3_600_000,
            guardian: Some("guardian.testnet".parse().unwrap()),
            eth_daily_cap: U128(ETH / 10), // 0.1 ETH
            max_gas_cost: U128(21_000 * 50 * GWEI), // 0.00105 ETH
            allowed_destinations: vec![DEST.into()],
            allowed_spenders: vec![SPENDER.into()],
            tokens: vec![TokenRule {
                contract: TOKEN.into(),
                daily_cap: U128(1_000_000),
                max_approval: U128(500_000),
            }],
        }
    }

    fn eth_tx(to: &str, value: u128) -> Eip1559Tx {
        Eip1559Tx {
            chain_id: CHAIN,
            nonce: 0,
            max_priority_fee_per_gas: GWEI,
            max_fee_per_gas: 20 * GWEI,
            gas_limit: 21_000,
            to: addr(to),
            value,
            data: vec![],
        }
    }

    fn word(v: u128) -> [u8; 32] {
        let mut w = [0u8; 32];
        w[16..].copy_from_slice(&v.to_be_bytes());
        w
    }

    fn calldata(selector: [u8; 4], a: &str, amount: [u8; 32]) -> Vec<u8> {
        let mut d = selector.to_vec();
        d.extend_from_slice(&[0u8; 12]);
        d.extend_from_slice(&addr(a));
        d.extend_from_slice(&amount);
        d
    }

    fn token_tx(selector: [u8; 4], target: &str, amount: [u8; 32]) -> Eip1559Tx {
        let mut tx = eth_tx(TOKEN, 0);
        tx.data = calldata(selector, target, amount);
        tx
    }

    fn gas_cost(tx: &Eip1559Tx) -> u128 {
        tx.max_fee_per_gas * tx.gas_limit as u128
    }

    // ---------- allowed shapes ----------

    #[test]
    fn plain_transfer_within_policy_reserves_value_plus_gas() {
        let tx = eth_tx(DEST, ETH / 100);
        let r = check(&policy(), &SpendState::default(), &tx, NOW).unwrap();
        assert_eq!(r.eth.0, ETH / 100 + gas_cost(&tx));
        assert_eq!(r.token_contract, None);
    }

    #[test]
    fn erc20_transfer_within_policy_reserves_token_and_gas() {
        let tx = token_tx(SEL_ERC20_TRANSFER, DEST, word(400_000));
        let r = check(&policy(), &SpendState::default(), &tx, NOW).unwrap();
        assert_eq!(r.eth.0, gas_cost(&tx));
        assert_eq!(r.token_contract.as_deref(), Some(TOKEN));
        assert_eq!(r.token_amount.0, 400_000);
    }

    #[test]
    fn erc20_approve_within_cap_is_allowed_and_reserves_no_token() {
        let tx = token_tx(SEL_ERC20_APPROVE, SPENDER, word(500_000));
        let r = check(&policy(), &SpendState::default(), &tx, NOW).unwrap();
        assert_eq!(r.token_contract, None);
        assert_eq!(r.token_amount.0, 0);
    }

    // ---------- every refusal, one by one ----------

    #[test]
    fn refusals() {
        use PolicyError::*;
        let p = policy();
        let s = SpendState::default();
        let mut wrong_chain = eth_tx(DEST, 1);
        wrong_chain.chain_id = 1;
        let mut fee_order = eth_tx(DEST, 1);
        fee_order.max_priority_fee_per_gas = fee_order.max_fee_per_gas + 1;
        let mut gas_high = eth_tx(DEST, 1);
        gas_high.gas_limit = 22_000; // 22_000 * 20 gwei > 21_000 * 50 gwei? no: 440k vs 1050k gwei
        gas_high.max_fee_per_gas = 51 * GWEI; // 22_000 * 51 gwei = 1_122_000 gwei > cap
        let mut gas_overflow = eth_tx(DEST, 1);
        gas_overflow.max_fee_per_gas = u128::MAX; // u128::MAX * 21_000 overflows
        gas_overflow.gas_limit = MIN_GAS_LIMIT;
        let mut value_with_data = token_tx(SEL_ERC20_TRANSFER, DEST, word(1));
        value_with_data.value = 1;
        let mut token_not_allowed = token_tx(SEL_ERC20_TRANSFER, DEST, word(1));
        token_not_allowed.to = addr(OTHER);
        let mut unknown = eth_tx(DEST, 0);
        unknown.data = vec![0xde, 0xad, 0xbe, 0xef];
        let mut over_eth_cap = eth_tx(DEST, ETH / 10);
        over_eth_cap.value = ETH / 10; // value alone equals the cap; plus gas it exceeds
        let mut max_uint = [0xffu8; 32];
        let mut two_pow_255 = [0u8; 32];
        two_pow_255[0] = 0x80;
        max_uint[31] = 0xff;

        let mut gas_low = eth_tx(DEST, 1);
        gas_low.gas_limit = MIN_GAS_LIMIT - 1;
        let mut zero_fee = eth_tx(DEST, 1);
        zero_fee.max_fee_per_gas = 0;
        zero_fee.max_priority_fee_per_gas = 0;

        let cases: Vec<(&str, Eip1559Tx, PolicyError)> = vec![
            ("wrong chain", wrong_chain, WrongChain),
            ("gas limit below 21000 (unminable)", gas_low, GasLimitTooLow),
            ("zero max fee (unminable)", zero_fee, ZeroFee),
            ("priority fee above max fee", fee_order, FeeOrder),
            ("gas cost above max", gas_high, GasCostTooHigh),
            ("gas cost overflows", gas_overflow, GasCostTooHigh),
            ("eth to a stranger", eth_tx(OTHER, 1), DestinationNotAllowed),
            ("eth to the token contract", eth_tx(TOKEN, 1), DestinationNotAllowed),
            ("eth above daily cap", over_eth_cap, EthCapExceeded),
            ("token call carrying value", value_with_data, ValueWithCalldata),
            ("unknown token", token_not_allowed, TokenNotAllowed),
            ("token transfer to a stranger", token_tx(SEL_ERC20_TRANSFER, OTHER, word(1)), DestinationNotAllowed),
            ("token transfer above daily cap", token_tx(SEL_ERC20_TRANSFER, DEST, word(1_000_001)), TokenCapExceeded),
            ("token amount beyond 128 bits", token_tx(SEL_ERC20_TRANSFER, DEST, two_pow_255), AmountTooLarge),
            ("approve to a stranger", token_tx(SEL_ERC20_APPROVE, OTHER, word(1)), SpenderNotAllowed),
            ("approve above max_approval", token_tx(SEL_ERC20_APPROVE, SPENDER, word(500_001)), ApprovalTooHigh),
            ("unlimited approve (2^256-1)", token_tx(SEL_ERC20_APPROVE, SPENDER, max_uint), AmountTooLarge),
            ("almost unlimited approve (2^255)", token_tx(SEL_ERC20_APPROVE, SPENDER, two_pow_255), AmountTooLarge),
            ("arbitrary calldata", unknown, CalldataNotAllowed),
        ];
        for (name, tx, expected) in cases {
            assert_eq!(check(&p, &s, &tx, NOW), Err(expected), "case: {name}");
        }
    }

    #[test]
    fn locked_policy_refuses_everything() {
        let p = Policy::locked();
        let tx = eth_tx(DEST, 0);
        assert_eq!(check(&p, &SpendState::default(), &tx, NOW), Err(PolicyError::WrongChain));
        let mut p0 = policy();
        p0.eth_daily_cap = U128(0);
        assert_eq!(check(&p0, &SpendState::default(), &eth_tx(DEST, 0), NOW), Err(PolicyError::EthCapExceeded));
    }

    // ---------- windows ----------

    #[test]
    fn eth_cap_accumulates_and_resets_after_24h() {
        let p = policy();
        let mut s = SpendState::default();
        let tx = eth_tx(DEST, ETH / 25); // 0.04 ETH + gas; two fit in 0.1, three do not
        let r = check(&p, &s, &tx, NOW).unwrap();
        s.reserve(&r, NOW);
        let r = check(&p, &s, &tx, NOW + 1).unwrap();
        s.reserve(&r, NOW + 1);
        assert_eq!(check(&p, &s, &tx, NOW + 2), Err(PolicyError::EthCapExceeded));
        // release one and it fits again
        s.release(&r);
        assert!(check(&p, &s, &tx, NOW + 3).is_ok());
        s.reserve(&r, NOW + 3);
        // a new day: the window restarts
        assert!(check(&p, &s, &tx, NOW + DAY_MS).is_ok());
        assert_eq!(check(&p, &s, &tx, NOW + DAY_MS - 1), Err(PolicyError::EthCapExceeded));
    }

    #[test]
    fn token_cap_is_per_token_and_independent_of_eth() {
        let p = policy();
        let mut s = SpendState::default();
        let tx = token_tx(SEL_ERC20_TRANSFER, DEST, word(600_000));
        s.reserve(&check(&p, &s, &tx, NOW).unwrap(), NOW);
        assert_eq!(check(&p, &s, &tx, NOW), Err(PolicyError::TokenCapExceeded));
        // ETH cap only took the gas, so a plain transfer still fits
        assert!(check(&p, &s, &eth_tx(DEST, ETH / 20), NOW).is_ok());
        assert_eq!(s.tokens.len(), 1);
        assert_eq!(s.tokens[0].window.spent.0, 600_000);
    }

    #[test]
    fn prune_drops_only_expired_token_windows() {
        let p = policy();
        let mut s = SpendState::default();
        let tx = token_tx(SEL_ERC20_TRANSFER, DEST, word(10));
        s.reserve(&check(&p, &s, &tx, NOW).unwrap(), NOW);
        s.prune_expired(NOW + DAY_MS - 1);
        assert_eq!(s.tokens.len(), 1, "an active window must stay");
        s.prune_expired(NOW + DAY_MS);
        assert!(s.tokens.is_empty(), "an expired window must go");
    }

    #[test]
    fn guardian_replacement_rules() {
        let old = policy(); // delay 1 h, guardian set
        let mut removed = policy();
        removed.guardian = None;
        let mut changed = policy();
        changed.guardian = Some("other.testnet".parse().unwrap());
        assert!(replaces_guardian(&removed, &old));
        assert!(replaces_guardian(&changed, &old));
        assert!(!replaces_guardian(&old.clone(), &old));
        let mut no_guardian = policy();
        no_guardian.guardian = None;
        assert!(!replaces_guardian(&old, &no_guardian), "adding a guardian is not a replacement");
        assert_eq!(guardian_change_wait_ms(&old), GUARDIAN_CHANGE_MIN_MS, "short delays still wait 3 days");
        let mut slow = policy();
        slow.delay_ms = 2 * DAY_MS;
        assert_eq!(guardian_change_wait_ms(&slow), 4 * DAY_MS, "long delays wait twice the delay");
    }

    #[test]
    fn release_saturates_at_zero() {
        let mut w = Window::default();
        w.reserve(5, NOW);
        w.release(10);
        assert_eq!(w.spent.0, 0);
    }

    // ---------- policy validation and comparison ----------

    #[test]
    fn normalized_lowercases_and_validates() {
        let mut p = policy();
        p.allowed_destinations = vec!["0x1111111111111111111111111111111111111111".to_uppercase().replace("0X", "0x")];
        let n = p.normalized().unwrap();
        assert_eq!(n.allowed_destinations, vec![DEST.to_string()]);

        let bad = |f: fn(&mut Policy)| {
            let mut p = policy();
            f(&mut p);
            p.normalized().err()
        };
        assert!(matches!(bad(|p| p.chain_id = 0), Some(PolicyError::InvalidPolicy(_))));
        assert!(matches!(bad(|p| p.delay_ms = MAX_DELAY_MS + 1), Some(PolicyError::InvalidPolicy(_))));
        assert!(matches!(bad(|p| p.allowed_destinations.push("0x12".into())), Some(PolicyError::InvalidPolicy(_))));
        assert!(matches!(bad(|p| p.allowed_destinations.push(DEST.to_uppercase().replace("0X", "0x"))), Some(PolicyError::InvalidPolicy("duplicate address"))));
        assert!(matches!(bad(|p| p.tokens.push(p.tokens[0].clone())), Some(PolicyError::InvalidPolicy("duplicate token"))));
        assert!(matches!(bad(|p| p.allowed_spenders = vec!["0x".to_string() + &"11".repeat(20); 33]), Some(PolicyError::InvalidPolicy(_))));
    }

    #[test]
    fn tightening_is_recognized_and_loosening_is_not() {
        let old = policy();
        let same = old.clone();
        assert!(is_not_looser(&same, &old));

        let tighter = |f: fn(&mut Policy)| {
            let mut p = policy();
            f(&mut p);
            is_not_looser(&p, &old)
        };
        assert!(tighter(|p| p.eth_daily_cap = U128(1)));
        assert!(tighter(|p| p.max_gas_cost = U128(1)));
        assert!(tighter(|p| p.delay_ms += 1));
        assert!(tighter(|p| p.allowed_destinations.clear()));
        assert!(tighter(|p| p.allowed_spenders.clear()));
        assert!(tighter(|p| p.tokens.clear()));
        assert!(tighter(|p| p.tokens[0].max_approval = U128(1)));
        assert!(tighter(|p| p.tokens[0].daily_cap = U128(1)));

        assert!(!tighter(|p| p.eth_daily_cap = U128(ETH)));
        assert!(!tighter(|p| p.max_gas_cost.0 += 1));
        assert!(!tighter(|p| p.delay_ms -= 1));
        assert!(!tighter(|p| p.guardian = None));
        assert!(!tighter(|p| p.guardian = Some("other.testnet".parse().unwrap())));
        assert!(!tighter(|p| p.allowed_destinations.push(OTHER.into())));
        assert!(!tighter(|p| p.allowed_spenders.push(OTHER.into())));
        assert!(!tighter(|p| p.tokens[0].daily_cap.0 += 1));
        assert!(!tighter(|p| p.tokens[0].max_approval.0 += 1));
        assert!(!tighter(|p| p.tokens.push(TokenRule { contract: OTHER.into(), daily_cap: U128(1), max_approval: U128(1) })));
        assert!(!tighter(|p| p.chain_id = 1));

        // adding a guardian where there was none is a tightening
        let mut no_guardian = policy();
        no_guardian.guardian = None;
        assert!(is_not_looser(&policy(), &no_guardian));
        // any real policy is looser than the locked one (so a first policy waits locked.delay = 0)
        assert!(!is_not_looser(&policy(), &Policy::locked()));
    }

    #[test]
    fn hex_helpers() {
        assert_eq!(parse_hex("0x"), Some(vec![]));
        assert_eq!(parse_hex("0x0a"), Some(vec![10]));
        assert_eq!(parse_hex("0x0"), None);
        assert_eq!(parse_hex("0a"), None);
        assert_eq!(parse_hex("0xzz"), None);
        assert_eq!(normalize_address(&DEST.to_uppercase().replace("0X", "0x")), Some(DEST.to_string()));
        assert_eq!(normalize_address("0x1111"), None);
        assert_eq!(u128_from_word(&word(u128::MAX)), Some(u128::MAX));
        let mut w = word(0);
        w[15] = 1;
        assert_eq!(u128_from_word(&w), None);
    }
}
