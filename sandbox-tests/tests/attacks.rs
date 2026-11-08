//! M10: the attack suite. Every attack from `docs/THREAT_MODEL.md` that the contract itself can
//! stop is tried against the real wasm in one local sandbox, and each must be BLOCKED with the
//! contract's own reason. The test prints the table and fails if any attack gets through.
//!
//! Run: `cargo test --test attacks -- --nocapture` in `sandbox-tests/` (after `./build-wasm.sh`),
//! or `npm run attack` in `scripts/`.
//!
//! Not here, because the contract cannot stop them on its own: threat 7 (approvals already mined
//! on Ethereum: the buyer's audit, `scripts/sale-audit.mjs`), 8 (trust in the MPC network),
//! 9 (upgrade keys), 10 (fees on Ethereum) and 15 (token ids are never reused: unit test).
//! Threat 22 (a sale window that closed a day ago) is covered by unit tests: moving the sandbox
//! clock 24 hours takes about 45 minutes (it runs about 30 times faster than real time).

use near_workspaces::result::ExecutionFinalResult;
use near_workspaces::types::{Gas, NearToken};
use sandbox_tests::*;
use serde_json::{json, Value};

const TOKEN: &str = "0x3333333333333333333333333333333333333333";
const SPENDER: &str = "0x5555555555555555555555555555555555555555";
const SELLER_EVM: &str = "0x4444444444444444444444444444444444444444";
const OTHER: &str = "0x9999999999999999999999999999999999999999";
const ETH_4: u128 = 4_000_000_000_000_000; // 0.004 ETH
const NFT: &str = "0x6666666666666666666666666666666666666666";

struct Suite {
    rows: Vec<(String, String, Result<String, String>)>,
}

impl Suite {
    fn add(&mut self, threat: &str, attack: &str, outcome: Result<String, String>) {
        let mark = if outcome.is_ok() { "BLOCKED" } else { "GOT THROUGH" };
        println!("{mark:<12} [{threat:>6}] {attack}");
        self.rows.push((threat.into(), attack.into(), outcome));
    }

    /// The call must fail with `reason` (the contract's own message).
    fn refused(&mut self, threat: &str, attack: &str, r: &ExecutionFinalResult, reason: &str) {
        let text = format!("{r:?}");
        let outcome = if r.is_failure() && text.contains(reason) {
            Ok(reason.to_string())
        } else if r.is_failure() {
            Err(format!("refused, but not for the expected reason {reason:?}: {}", short(&text)))
        } else {
            Err("the call succeeded".into())
        };
        self.add(threat, attack, outcome);
    }

    fn check(&mut self, threat: &str, attack: &str, ok: bool, evidence: &str) {
        self.add(threat, attack, if ok { Ok(evidence.into()) } else { Err(format!("the protection did not hold (expected: {evidence})")) });
    }
}

fn short(s: &str) -> String {
    match s.find("Smart contract panicked: ") {
        Some(i) => s[i..].chars().take(160).collect(),
        None => s.chars().take(300).collect(),
    }
}

fn word_addr(a: &str) -> String {
    format!("{:0>64}", a.trim_start_matches("0x"))
}

fn word_u128(v: u128) -> String {
    format!("{v:064x}")
}

/// An ERC-20 style call: selector + address + amount (68 bytes).
fn erc20(selector: &str, addr: &str, amount_word: &str) -> String {
    format!("0x{selector}{}{amount_word}", word_addr(addr))
}

fn tx(to: &str, value: u128, data: &str, gas_limit: u64, max_fee_gwei: u128) -> Value {
    json!({
        "chain_id": SEPOLIA,
        "max_priority_fee_per_gas": GWEI.to_string(),
        "max_fee_per_gas": (max_fee_gwei * GWEI).to_string(),
        "gas_limit": gas_limit,
        "to": to,
        "value": value.to_string(),
        "data": data
    })
}

/// The attack vault's policy: 0.01 ETH a day to DEST, one token (1000 a day, approvals up to 500
/// to SPENDER), 60-second delay, a guardian.
fn attack_policy(e: &Env, chain_id: u64, extra_destination: Option<&str>, guardian: Option<&near_workspaces::Account>) -> Value {
    let mut destinations = vec![DEST.to_string()];
    destinations.extend(extra_destination.map(str::to_string));
    json!({
        "chain_id": chain_id,
        "delay_ms": 60_000,
        "guardian": guardian.unwrap_or(&e.guardian).id(),
        "eth_daily_cap": "10000000000000000",
        "max_gas_cost": (100_000 * 50 * GWEI).to_string(),
        "allowed_destinations": destinations,
        "allowed_spenders": [SPENDER],
        "tokens": [{ "contract": TOKEN, "daily_cap": "1000", "max_approval": "500" }]
    })
}

async fn propose_tx(e: &Env, who: &near_workspaces::Account, t: &str, tx: Value) -> anyhow::Result<ExecutionFinalResult> {
    call(who, &e.vault, "propose", json!({ "token_id": t, "tx": tx }), millinear(50), 100).await
}

#[tokio::test]
async fn attack_suite() -> anyhow::Result<()> {
    let e = setup().await?;
    let mut s = Suite { rows: Vec::new() };
    println!("\nAttack suite against the vault contract (local NEAR sandbox)\n");

    // ---------- vault A: a funded-looking vault with a policy, owned by Alice ----------
    let a = mint(&e, &e.alice).await?;
    assert_ok(&set_policy(&e, &e.alice, &a, attack_policy(&e, SEPOLIA, None, None)).await?);
    // Vault D: the same policy, for the repeated-approvals attack (review M12, R12-3).
    let dv = mint(&e, &e.alice).await?;
    assert_ok(&set_policy(&e, &e.alice, &dv, attack_policy(&e, SEPOLIA, None, None)).await?);
    let mut approvals = Vec::new();
    for _ in 0..3 {
        let r = propose_tx(&e, &e.alice, &dv, tx(TOKEN, 0, &erc20("095ea7b3", SPENDER, &word_u128(500)), 60_000, 30)).await?;
        assert_ok(&r);
        approvals.push(returned::<u64>(&r)?);
    }

    // Someone who is not the owner.
    let r = set_policy(&e, &e.stranger, &a, policy(0, None)).await?;
    s.refused("auth", "a stranger sets a policy on someone else's vault", &r, "Only the vault owner can do this");
    let r = propose_tx(&e, &e.stranger, &a, eth_tx(1)).await?;
    s.refused("auth", "a stranger proposes a payment from someone else's vault", &r, "Only the vault owner or its proposer can do this");
    let r = call(&e.stranger, &e.vault, "on_signed", json!({ "token_id": a, "signing_hash": "0x00" }), yocto(0), 30).await?;
    s.refused("4", "anyone calls the signing callback to inject a signature", &r, "Method on_signed is private");
    let r = call(&e.stranger, &e.vault, "on_derived_key", json!({ "token_id": a }), yocto(0), 30).await?;
    s.refused("4", "anyone calls the key callback to replace the vault's address", &r, "Method on_derived_key is private");

    // Transactions the policy must refuse (checked when proposed).
    let r = propose_tx(&e, &e.alice, &a, tx(OTHER, ETH_4, "0x", 21_000, 30)).await?;
    s.refused("policy", "send ETH to an address that is not allowed", &r, "destination not allowed");
    let mut other_chain = tx(DEST, ETH_4, "0x", 21_000, 30);
    other_chain["chain_id"] = json!(1);
    let r = propose_tx(&e, &e.alice, &a, other_chain).await?;
    s.refused("12", "sign for another chain (replay on mainnet)", &r, "chain_id is not the vault's chain");
    let r = propose_tx(&e, &e.alice, &a, tx(TOKEN, 0, &erc20("39509351", SPENDER, &word_u128(100)), 60_000, 30)).await?;
    s.refused("3", "increaseAllowance instead of approve (unknown calldata)", &r, "calldata is not a plain transfer, ERC-20 transfer or approve");
    let r = propose_tx(&e, &e.alice, &a, tx(TOKEN, 0, &erc20("095ea7b3", SPENDER, &"f".repeat(64)), 60_000, 30)).await?;
    s.refused("3", "unlimited approval (2^256 - 1)", &r, "amount does not fit in 128 bits");
    let r = propose_tx(&e, &e.alice, &a, tx(TOKEN, 0, &erc20("095ea7b3", SPENDER, &word_u128(501)), 60_000, 30)).await?;
    s.refused("3", "approval above the token's max_approval", &r, "approval above the token's max_approval");
    let r = propose_tx(&e, &e.alice, &a, tx(TOKEN, 0, &erc20("095ea7b3", OTHER, &word_u128(10)), 60_000, 30)).await?;
    s.refused("3", "approval to a spender that is not allowed", &r, "spender not allowed");
    let r = propose_tx(&e, &e.alice, &a, tx(OTHER, 0, &erc20("a9059cbb", DEST, &word_u128(10)), 60_000, 30)).await?;
    s.refused("3", "transfer of a token the policy does not list", &r, "token contract not allowed");
    let r = propose_tx(&e, &e.alice, &a, tx(TOKEN, 0, &erc20("a9059cbb", OTHER, &word_u128(10)), 60_000, 30)).await?;
    s.refused("policy", "token transfer to an address that is not allowed", &r, "destination not allowed");
    let r = propose_tx(&e, &e.alice, &a, tx(TOKEN, 1, &erc20("a9059cbb", DEST, &word_u128(10)), 60_000, 30)).await?;
    s.refused("3", "token call that also sends ETH", &r, "value must be 0 for a token call");
    let r = propose_tx(&e, &e.alice, &a, tx(TOKEN, 0, &erc20("a9059cbb", DEST, &word_u128(1001)), 60_000, 30)).await?;
    s.refused("policy", "token transfer above its daily cap", &r, "token daily cap exceeded");
    let r = propose_tx(&e, &e.alice, &a, tx(DEST, 20_000_000_000_000_000, "0x", 21_000, 30)).await?;
    s.refused("policy", "ETH payment above the daily cap", &r, "ETH daily cap exceeded");
    let r = propose_tx(&e, &e.alice, &a, tx(DEST, ETH_4, "0x", 20_000, 30)).await?;
    s.refused("10", "a gas limit too low to ever be mined", &r, "gas_limit below 21000");
    let r = propose_tx(&e, &e.alice, &a, tx(DEST, ETH_4, "0x", 21_000, 0)).await?;
    s.refused("10", "a zero fee (stuck transaction)", &r, "max_fee_per_gas must be above 0");
    let r = propose_tx(&e, &e.alice, &a, tx(DEST, ETH_4, "0x", 21_000, 1_000)).await?;
    s.refused("policy", "a fee that burns the vault's ETH as gas", &r, "max_fee_per_gas * gas_limit above max_gas_cost");

    // Three valid payments of 0.004 ETH; together they exceed the 0.01 ETH cap.
    let mut ids = Vec::new();
    for _ in 0..3 {
        ids.push(propose(&e, &e.alice, &a, ETH_4).await?);
    }
    let r = call(&e.stranger, &e.vault, "veto_proposal", json!({ "token_id": a, "proposal_id": ids[0] }), yocto(1), 30).await?;
    s.refused("auth", "a stranger vetoes a proposal (only the guardian can)", &r, "Only the guardian can veto");
    let r = execute(&e, &e.alice, &a, ids[0]).await?;
    s.refused("policy", "sign before the delay (no time for the guardian)", &r, "Proposal delay has not passed yet");

    // Loosening the policy waits the delay; meanwhile the new destination is not allowed.
    let r = set_policy(&e, &e.alice, &a, attack_policy(&e, SEPOLIA, Some(SELLER_EVM), None)).await?;
    let applied: bool = returned(&r)?;
    s.check("17", "a looser policy (the seller's own address) applies at once", !applied, "it became a pending change that waits the delay");
    let r = propose_tx(&e, &e.alice, &a, tx(SELLER_EVM, ETH_4, "0x", 21_000, 30)).await?;
    s.refused("2", "pay the seller's own address before the change applies", &r, "destination not allowed");
    let r = call(&e.stranger, &e.vault, "apply_policy", json!({ "token_id": a }), yocto(0), 30).await?;
    s.refused("17", "apply the looser policy early", &r, "Pending policy not ready yet");
    assert_ok(&call(&e.alice, &e.vault, "cancel_pending_policy", json!({ "token_id": a }), yocto(1), 30).await?);

    // A hostile guardian cannot block its own replacement.
    assert_ok(&set_policy(&e, &e.alice, &a, attack_policy(&e, SEPOLIA, None, Some(&e.bob))).await?);
    let r = call(&e.guardian, &e.vault, "veto_pending_policy", json!({ "token_id": a }), yocto(1), 30).await?;
    s.refused("18", "a hostile guardian vetoes its own replacement", &r, "The guardian cannot veto its own replacement");
    assert_ok(&call(&e.alice, &e.vault, "cancel_pending_policy", json!({ "token_id": a }), yocto(1), 30).await?);

    // The cap is charged when signing: the third payment is refused.
    advance_ms(&e.worker, 61_000).await?;
    assert!(returned::<bool>(&execute(&e, &e.alice, &dv, approvals[0]).await?)?);
    assert!(returned::<bool>(&execute(&e, &e.alice, &dv, approvals[1]).await?)?);
    let r = execute(&e, &e.alice, &dv, approvals[2]).await?;
    s.refused("3", "approve the same spender again and again to pull more than the token cap", &r, "token daily cap exceeded");
    assert!(returned::<bool>(&execute(&e, &e.alice, &a, ids[0]).await?)?);
    assert!(returned::<bool>(&execute(&e, &e.alice, &a, ids[1]).await?)?);
    let r = execute(&e, &e.alice, &a, ids[2]).await?;
    s.refused("6", "sign queued payments that together exceed the daily cap", &r, "ETH daily cap exceeded");

    // After signing on Sepolia, the vault's nonce belongs to Sepolia.
    let r = set_policy(&e, &e.alice, &a, attack_policy(&e, 1, None, None)).await?;
    s.refused("21", "move the policy to mainnet after signing on Sepolia", &r, "its policy must keep chain_id 11155111");
    let cancel = json!({ "token_id": a, "nonce": 99, "max_fee_per_gas": (30 * GWEI).to_string(), "max_priority_fee_per_gas": GWEI.to_string() });
    let r = call(&e.alice, &e.vault, "cancel_nonce", cancel, millinear(20), 300).await?;
    s.refused("policy", "sign a 'cancellation' for a nonce that was never used", &r, "Only a nonce that was already signed can be cancelled");

    // Moving the NFT without a sale (stolen key, approved marketplace).
    let r = call(&e.alice, &e.vault, "nft_transfer", json!({ "receiver_id": e.stranger.id(), "token_id": a }), yocto(1), 30).await?;
    s.refused("16", "a thief with the owner's key transfers the NFT", &r, "Start a sale (start_sale) and wait for it to open before transferring");
    assert_ok(&call(&e.alice, &e.vault, "nft_approve", json!({ "token_id": a, "account_id": e.bob.id() }), millinear(10), 30).await?);
    let r = call(&e.bob, &e.vault, "nft_transfer", json!({ "receiver_id": e.bob.id(), "token_id": a }), yocto(1), 30).await?;
    s.refused("14", "an approved marketplace moves the NFT outside a sale", &r, "Start a sale (start_sale) and wait for it to open before transferring");

    // A sale freezes the vault and makes everyone wait.
    assert_ok(&start_sale(&e, &e.alice, &a, None, None).await?);
    let r = execute(&e, &e.alice, &a, ids[2]).await?;
    s.refused("1", "sign a payment during the sale, to broadcast after selling", &r, "The vault is frozen for a sale");
    let r = call(&e.alice, &e.vault, "nft_transfer", json!({ "receiver_id": e.stranger.id(), "token_id": a }), yocto(1), 30).await?;
    s.refused("16", "a thief starts a sale and transfers at once", &r, "The sale opens at");
    let r = call(&e.guardian, &e.vault, "veto_sale", json!({ "token_id": a }), yocto(1), 30).await?;
    let gone = view(&e.vault, "get_sale", json!({ "token_id": a })).await?.is_null();
    s.check("16", "the thief's sale survives the guardian", r.is_success() && gone, "the guardian vetoed it");

    // The buyer pays only for the sale it audited.
    let price = NearToken::from_near(2);
    let r = start_sale(&e, &e.alice, &a, Some(price), Some(&e.bob)).await?;
    let audited = returned::<Value>(&r)?["sale_id"].as_u64().unwrap();
    assert_ok(&call(&e.alice, &e.vault, "cancel_sale", json!({ "token_id": a }), yocto(1), 30).await?);
    assert_ok(&start_sale(&e, &e.alice, &a, Some(price), Some(&e.bob)).await?);
    advance_ms(&e.worker, 601_000).await?;
    let buy = |who: &near_workspaces::Account, id: u64, deposit: NearToken| {
        let (who, vault, a) = (who.clone(), e.vault.clone(), a.clone());
        async move { call(&who, &vault, "buy", json!({ "token_id": a, "sale_id": id }), deposit, 50).await }
    };
    let r = buy(&e.bob, audited, price).await?;
    s.refused("23", "the seller restarts the sale after the buyer audited it", &r, "The sale changed since it was audited");
    let r = buy(&e.stranger, audited + 1, price).await?;
    s.refused("sale", "a stranger buys a sale reserved for another buyer", &r, "This sale is reserved for another buyer");
    let r = buy(&e.bob, audited + 1, NearToken::from_near(1)).await?;
    s.refused("sale", "the buyer underpays", &r, "Attach the price");

    // ---------- vault B: signing outcomes ----------
    let b = mint(&e, &e.alice).await?;
    assert_ok(&set_policy(&e, &e.alice, &b, policy(0, None)).await?);
    let pb = propose(&e, &e.alice, &b, 1_000).await?;
    set_signer_mode(&e, "hold").await?;
    let pending = e
        .alice
        .call(e.vault.id(), "execute_proposal")
        .args_json(json!({ "token_id": b, "proposal_id": pb }))
        .deposit(millinear(20))
        .gas(Gas::from_tgas(300))
        .transact_async()
        .await?;
    wait_until(60, || async { Ok(view(&e.signer, "stats", json!({})).await?[1] == json!(1)) }).await?;
    let r = call(&e.alice, &e.vault, "nft_transfer", json!({ "receiver_id": e.bob.id(), "token_id": b }), yocto(1), 30).await?;
    s.refused("5", "transfer the NFT while its signature is in flight", &r, "A signature is in flight for this vault; transfer after it completes");
    let r = start_sale(&e, &e.alice, &b, None, None).await?;
    s.refused("5", "start a sale while a signature is in flight", &r, "A signature is in flight for this vault; start the sale after it completes");
    assert_ok(&call(&e.stranger, &e.signer, "release", json!({}), yocto(0), 50).await?);
    let _ = pending.await?;

    // Each step uses its own proposal, so an attack that gets through does not stop the suite.
    let stored_bool = |r: &ExecutionFinalResult| returned::<bool>(r).unwrap_or(false);
    let pb2 = propose(&e, &e.alice, &b, 1_000).await?;
    let pb3 = propose(&e, &e.alice, &b, 1_000).await?;
    set_signer_mode(&e, "wrong_key").await?;
    let r = execute(&e, &e.alice, &b, pb2).await?;
    let stored = view(&e.vault, "get_signed", json!({ "token_id": b, "nonce": 1 })).await?;
    s.check("8", "the signer answers with a signature by another key", !stored_bool(&r) && stored.is_null(), "rejected by ecrecover, nothing stored, nonce given back");
    set_signer_mode(&e, "garbage").await?;
    let spent = |v: Value| v["spend"]["eth"]["spent"].as_str().unwrap_or("0").parse::<u128>().unwrap_or(0);
    let r = execute(&e, &e.alice, &b, pb3).await?;
    let inflight = view(&e.vault, "get_inflight", json!({ "token_id": b })).await?;
    s.check("19", "an unreadable signer answer locks the vault forever", r.is_success() && !stored_bool(&r) && inflight.is_null(), "the vault is unlocked, the nonce is marked uncertain");
    let charged = spent(view(&e.vault, "get_policy", json!({ "token_id": b })).await?);
    set_signer_mode(&e, "sign").await?;
    let r = execute(&e, &e.alice, &b, pb3).await?;
    let after = spent(view(&e.vault, "get_policy", json!({ "token_id": b })).await?);
    s.check("20", "the retry after an uncertain answer is charged twice", stored_bool(&r) && after == charged, "signed at the same nonce, charged once");
    // Review M12 (R12-5): a valid signature in another format (recovery_id 27/28) must not give
    // the nonce back, because the signer holds a signature that can be mined.
    let pb4 = propose(&e, &e.alice, &b, 1_000).await?;
    let next_before = view(&e.vault, "get_next_nonce", json!({ "token_id": b })).await?.as_u64().unwrap();
    set_signer_mode(&e, "v28").await?;
    let r = execute(&e, &e.alice, &b, pb4).await?;
    let next_after = view(&e.vault, "get_next_nonce", json!({ "token_id": b })).await?.as_u64().unwrap();
    let uncertain = view(&e.vault, "get_uncertain", json!({ "token_id": b })).await?;
    let kept = uncertain.as_array().map(|u| u.iter().any(|x| x["nonce"] == json!(next_before))).unwrap_or(false);
    s.check("19", "the signer changes its answer format and the nonce is handed out again", !stored_bool(&r) && next_after == next_before + 1 && kept, "the nonce stays used and is marked uncertain");
    set_signer_mode(&e, "sign").await?;

    // ---------- vault C: nft_transfer_call ----------
    let c = mint(&e, &e.alice).await?;
    assert_ok(&start_sale(&e, &e.alice, &c, None, None).await?);
    advance_ms(&e.worker, 601_000).await?;
    let transfer_call = |msg: &str, tgas: u64| {
        let (alice, vault, receiver, c, msg) = (e.alice.clone(), e.vault.clone(), e.receiver.clone(), c.clone(), msg.to_string());
        async move {
            call(&alice, &vault, "nft_transfer_call", json!({ "receiver_id": receiver.id(), "token_id": c, "msg": msg }), yocto(1), tgas).await
        }
    };
    let r = transfer_call("act", 40).await?;
    s.refused("13", "transfer_call with too little gas to resolve", &r, "Attach at least 50 Tgas to nft_transfer_call");
    let r = transfer_call("act", 200).await?;
    let refused = r.logs().iter().any(|l| l.contains("set_policy REFUSED during transfer_call"));
    let back = owner_of(&e, &c).await? == e.alice.id().to_string();
    s.check("13", "the transfer_call receiver acts as owner, then returns the NFT", refused && back, "its set_policy was refused and the NFT came back");

    // ---------- vault E: agent mode and NFTs (after M12) ----------
    // Bob is the agent (proposer); the guardian keeps its veto; one NFT a day from collection NFT.
    let ev = mint(&e, &e.alice).await?;
    let ev_addr = view(&e.vault, "vault_info", json!({ "token_id": ev })).await?["evm_address"].as_str().unwrap().to_string();
    let mut agent_policy = policy(0, Some(&e.guardian));
    agent_policy["proposer"] = json!(e.bob.id());
    agent_policy["nfts"] = json!([{ "contract": NFT, "daily_count": "1" }]);
    assert_ok(&set_policy(&e, &e.alice, &ev, agent_policy).await?);
    let r = set_policy(&e, &e.bob, &ev, policy(0, None)).await?;
    s.refused("agent", "the agent removes the guardian from its own policy", &r, "Only the vault owner can do this");
    let r = start_sale(&e, &e.bob, &ev, None, None).await?;
    s.refused("agent", "the agent puts the vault on sale", &r, "Only the vault owner can do this");
    let r = call(&e.stranger, &e.vault, "propose", json!({ "token_id": ev, "tx": eth_tx(1_000) }), millinear(50), 100).await?;
    s.refused("auth", "someone who is neither owner nor agent proposes", &r, "Only the vault owner or its proposer can do this");
    let nft_tx = |from: &str| {
        let data = format!("0x42842e0e{}{}{}", word_addr(from), word_addr(DEST), word_u128(7));
        tx(NFT, 0, &data, 30_000, 30)
    };
    let r = propose_tx(&e, &e.bob, &ev, nft_tx(OTHER)).await?;
    s.refused("3", "send an NFT the vault does not own (from another address)", &r, "an NFT transfer must send from the vault's own address");
    let n1 = returned::<u64>(&propose_tx(&e, &e.bob, &ev, nft_tx(&ev_addr)).await?)?;
    let n2 = returned::<u64>(&propose_tx(&e, &e.bob, &ev, nft_tx(&ev_addr)).await?)?;
    assert!(returned::<bool>(&execute(&e, &e.bob, &ev, n1).await?)?, "the agent signs the first NFT transfer");
    let r = execute(&e, &e.bob, &ev, n2).await?;
    s.refused("6", "the agent sends more NFTs than the daily count", &r, "NFT daily count exceeded");

    // ---------- summary ----------
    let blocked = s.rows.iter().filter(|r| r.2.is_ok()).count();
    println!("\n{blocked}/{} attacks blocked", s.rows.len());
    for (threat, attack, outcome) in &s.rows {
        if let Err(why) = outcome {
            println!("GOT THROUGH [{threat}] {attack}: {why}");
        }
    }
    assert_eq!(blocked, s.rows.len(), "some attacks got through");
    Ok(())
}
