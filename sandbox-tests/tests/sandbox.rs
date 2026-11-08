//! M9: the vault's asynchronous flows in a real local NEAR sandbox (real wasm, real
//! cross-contract promises and callbacks, real yield/resume), with a mock Chain Signatures
//! contract in place of the MPC network. Unit tests (`contract/src/lib.rs`) simulate these
//! flows by hand; here the NEAR runtime runs them.
//!
//! Run: `./build-wasm.sh && cargo test` in `sandbox-tests/` (Linux or macOS; WSL on Windows).

use near_workspaces::types::NearToken;
use sandbox_tests::*;
use serde_json::{json, Value};

const VALUE: u128 = 100_000_000_000_000; // 0.0001 ETH

/// M4: at mint, the contract asks the signer for the vault's key in a cross-contract call and
/// publishes the EVM address in the callback.
#[tokio::test]
async fn mint_learns_the_vault_address_from_the_signer() -> anyhow::Result<()> {
    let e = setup().await?;
    let t = mint(&e, &e.alice).await?;
    let info = view(&e.vault, "vault_info", json!({ "token_id": t })).await?;
    let key = view(
        &e.signer,
        "derived_public_key",
        json!({ "path": format!("vault-{t}"), "predecessor": e.vault.id(), "domain_id": 0 }),
    )
    .await?;
    assert_eq!(info["public_key"], key, "the stored key is the signer's key for this vault");
    assert_eq!(info["evm_address"].as_str().unwrap(), address_of_key(key.as_str().unwrap())?);
    // Each vault has its own key.
    let t2 = mint(&e, &e.bob).await?;
    let info2 = view(&e.vault, "vault_info", json!({ "token_id": t2 })).await?;
    assert_ne!(info["evm_address"], info2["evm_address"]);
    Ok(())
}

/// M5-M7: policy, proposal, delay, signature. The stored transaction is checked here with an
/// independent decoder and k256, not with the contract's own code.
#[tokio::test]
async fn a_proposal_is_signed_after_its_delay() -> anyhow::Result<()> {
    let e = setup().await?;
    let t = mint(&e, &e.alice).await?;
    let vault_address = view(&e.vault, "vault_info", json!({ "token_id": t })).await?["evm_address"].clone();
    let vault_address = vault_address.as_str().unwrap();

    assert_ok(&set_policy(&e, &e.alice, &t, policy(60_000, Some(&e.guardian))).await?);
    let r = set_policy(&e, &e.stranger, &t, policy(0, None)).await?;
    assert_refused(&r, "Only the vault owner can do this");

    let pid = propose(&e, &e.alice, &t, VALUE).await?;
    assert_refused(&execute(&e, &e.alice, &t, pid).await?, "Proposal delay has not passed yet");
    assert_refused(&execute(&e, &e.stranger, &t, pid).await?, "Only the vault owner or its proposer can do this");

    advance_ms(&e.worker, 61_000).await?;
    let r = execute(&e, &e.alice, &t, pid).await?;
    assert_ok(&r);
    assert!(returned::<bool>(&r)?, "on_signed stored the signature");
    assert_eq!(events(&r, "transaction_signed").len(), 1);

    let rec = view(&e.vault, "get_signed", json!({ "token_id": t, "nonce": 0 })).await?;
    check_signed_record(&rec, vault_address, DEST, VALUE, 0)?;
    assert_eq!(view(&e.vault, "get_next_nonce", json!({ "token_id": t })).await?, json!(1));
    assert_eq!(view(&e.vault, "get_inflight", json!({ "token_id": t })).await?, Value::Null);
    let spent = view(&e.vault, "get_policy", json!({ "token_id": t })).await?["spend"]["eth"]["spent"].clone();
    assert!(spent.as_str().unwrap().parse::<u128>()? >= VALUE, "the cap was charged at signing: {spent}");
    Ok(())
}

/// Threat 5: while the signer has not answered (the MPC network takes several blocks), the
/// vault cannot sign again, be put on sale or be transferred. The mock signer holds its answer
/// with yield/resume, exactly like the real network.
#[tokio::test]
async fn a_signature_in_flight_locks_the_vault() -> anyhow::Result<()> {
    let e = setup().await?;
    let t = mint(&e, &e.alice).await?;
    let vault_address = view(&e.vault, "vault_info", json!({ "token_id": t })).await?["evm_address"]
        .as_str()
        .unwrap()
        .to_string();
    assert_ok(&set_policy(&e, &e.alice, &t, policy(0, None)).await?);
    let p1 = propose(&e, &e.alice, &t, VALUE).await?;
    let p2 = propose(&e, &e.alice, &t, VALUE).await?;
    set_signer_mode(&e, "hold").await?;

    let pending = e
        .alice
        .call(e.vault.id(), "execute_proposal")
        .args_json(json!({ "token_id": t, "proposal_id": p1 }))
        .deposit(millinear(20))
        .gas(near_workspaces::types::Gas::from_tgas(300))
        .transact_async()
        .await?;
    wait_until(60, || async { Ok(view(&e.signer, "stats", json!({})).await?[1] == json!(1)) }).await?;

    let inflight = view(&e.vault, "get_inflight", json!({ "token_id": t })).await?;
    assert_eq!(inflight["nonce"], json!(0), "the nonce is taken while the answer is pending");
    assert_refused(&execute(&e, &e.alice, &t, p2).await?, "A signature is already in flight for this vault");
    assert_refused(
        &start_sale(&e, &e.alice, &t, None, None).await?,
        "A signature is in flight for this vault; start the sale after it completes",
    );
    let r = call(&e.alice, &e.vault, "nft_transfer", json!({ "receiver_id": e.bob.id(), "token_id": t }), yocto(1), 30).await?;
    assert_refused(&r, "A signature is in flight for this vault; transfer after it completes");

    // The network answers: the callback verifies and stores the signature, the lock is released.
    assert_ok(&call(&e.stranger, &e.signer, "release", json!({}), yocto(0), 50).await?);
    let r = pending.await?;
    assert_ok(&r);
    assert!(returned::<bool>(&r)?);
    assert_eq!(view(&e.vault, "get_inflight", json!({ "token_id": t })).await?, Value::Null);
    let rec = view(&e.vault, "get_signed", json!({ "token_id": t, "nonce": 0 })).await?;
    check_signed_record(&rec, &vault_address, DEST, VALUE, 0)?;

    set_signer_mode(&e, "sign").await?;
    let r = execute(&e, &e.alice, &t, p2).await?;
    assert_ok(&r);
    assert!(returned::<bool>(&r)?, "after the lock, the next proposal signs with nonce 1");
    let rec = view(&e.vault, "get_signed", json!({ "token_id": t, "nonce": 1 })).await?;
    check_signed_record(&rec, &vault_address, DEST, VALUE, 1)?;
    Ok(())
}

/// Review S1/S3: every bad answer is handled in the callback without paying twice.
/// - a signature by another key is rejected and everything is undone;
/// - an unreadable answer or a failed call leaves the nonce "uncertain": it stays used and the
///   proposal goes back to the queue pinned to it, so a retry signs the identical transaction.
#[tokio::test]
async fn bad_signer_answers_never_double_spend() -> anyhow::Result<()> {
    let e = setup().await?;
    let t = mint(&e, &e.alice).await?;
    let vault_address = view(&e.vault, "vault_info", json!({ "token_id": t })).await?["evm_address"]
        .as_str()
        .unwrap()
        .to_string();
    assert_ok(&set_policy(&e, &e.alice, &t, policy(0, None)).await?);
    let spent = |v: Value| v["spend"]["eth"]["spent"].as_str().unwrap_or("0").parse::<u128>().unwrap();

    // Another key: rejected, undone.
    let pid = propose(&e, &e.alice, &t, VALUE).await?;
    set_signer_mode(&e, "wrong_key").await?;
    let r = execute(&e, &e.alice, &t, pid).await?;
    assert_ok(&r);
    assert!(!returned::<bool>(&r)?);
    let failed = events(&r, "signature_failed");
    assert_eq!(failed[0]["reason"], json!("signature does not match the vault key"));
    assert_eq!(view(&e.vault, "get_next_nonce", json!({ "token_id": t })).await?, json!(0));
    assert_eq!(spent(view(&e.vault, "get_policy", json!({ "token_id": t })).await?), 0);
    assert_eq!(view(&e.vault, "list_proposals", json!({ "token_id": t })).await?[0]["id"], json!(pid));

    // Unreadable answer: uncertain, nonce 0 kept, charge kept.
    set_signer_mode(&e, "garbage").await?;
    let r = execute(&e, &e.alice, &t, pid).await?;
    assert!(!returned::<bool>(&r)?);
    assert_eq!(events(&r, "signature_uncertain")[0]["reason"], json!("unreadable signer answer"));
    assert_eq!(view(&e.vault, "get_next_nonce", json!({ "token_id": t })).await?, json!(1));
    let uncertain = view(&e.vault, "get_uncertain", json!({ "token_id": t })).await?;
    assert_eq!(uncertain.as_array().unwrap().len(), 1);
    assert_eq!(uncertain[0]["nonce"], json!(0));
    let charged = spent(view(&e.vault, "get_policy", json!({ "token_id": t })).await?);
    assert!(charged >= VALUE);

    // Failed call: also uncertain, and the retry keeps nonce 0 (no second transaction).
    set_signer_mode(&e, "fail").await?;
    let r = execute(&e, &e.alice, &t, pid).await?;
    assert!(!returned::<bool>(&r)?);
    assert_eq!(events(&r, "signature_uncertain")[0]["reason"], json!("signer call failed"));
    assert_eq!(view(&e.vault, "get_next_nonce", json!({ "token_id": t })).await?, json!(1));
    assert_eq!(spent(view(&e.vault, "get_policy", json!({ "token_id": t })).await?), charged, "not charged twice");

    // The signer works again: the pinned proposal signs nonce 0, and nonce 0 is no longer uncertain.
    set_signer_mode(&e, "sign").await?;
    let r = execute(&e, &e.alice, &t, pid).await?;
    assert!(returned::<bool>(&r)?);
    let rec = view(&e.vault, "get_signed", json!({ "token_id": t, "nonce": 0 })).await?;
    check_signed_record(&rec, &vault_address, DEST, VALUE, 0)?;
    assert_eq!(view(&e.vault, "get_uncertain", json!({ "token_id": t })).await?, json!([]));
    assert_eq!(view(&e.vault, "get_next_nonce", json!({ "token_id": t })).await?, json!(1));
    assert_eq!(spent(view(&e.vault, "get_policy", json!({ "token_id": t })).await?), charged, "still charged once");
    Ok(())
}

/// If the MPC network never answers, the yield times out (about 200 blocks) and the callback
/// sees a failed call: the nonce becomes uncertain and the vault unlocks. A late answer after
/// that is ignored.
#[tokio::test]
async fn a_signer_timeout_unlocks_the_vault() -> anyhow::Result<()> {
    let e = setup().await?;
    let t = mint(&e, &e.alice).await?;
    assert_ok(&set_policy(&e, &e.alice, &t, policy(0, None)).await?);
    let pid = propose(&e, &e.alice, &t, VALUE).await?;
    set_signer_mode(&e, "hold").await?;
    let pending = e
        .alice
        .call(e.vault.id(), "execute_proposal")
        .args_json(json!({ "token_id": t, "proposal_id": pid }))
        .deposit(millinear(20))
        .gas(near_workspaces::types::Gas::from_tgas(300))
        .transact_async()
        .await?;
    wait_until(60, || async { Ok(view(&e.signer, "stats", json!({})).await?[1] == json!(1)) }).await?;
    e.worker.fast_forward(250).await?;
    let r = tokio::time::timeout(std::time::Duration::from_secs(180), pending).await??;
    assert!(!returned::<bool>(&r)?, "no signature was stored");
    assert_eq!(events(&r, "signature_uncertain")[0]["reason"], json!("signer call failed"));
    assert_eq!(view(&e.vault, "get_inflight", json!({ "token_id": t })).await?, Value::Null);
    assert_eq!(view(&e.vault, "get_uncertain", json!({ "token_id": t })).await?[0]["nonce"], json!(0));
    // The held answer arrives too late: the yield no longer exists.
    let r = call(&e.stranger, &e.signer, "release", json!({}), yocto(0), 50).await?;
    assert_ok(&r);
    assert!(!returned::<bool>(&r)?, "resuming a timed-out yield does nothing");
    assert_eq!(view(&e.vault, "get_signed", json!({ "token_id": t, "nonce": 0 })).await?, Value::Null);
    Ok(())
}

/// M8 + H3: guardian veto, the sale freeze, the 10-minute minimum, and `buy` paying the seller
/// in the same transaction that moves the NFT.
#[tokio::test]
async fn a_sale_is_bought_on_chain() -> anyhow::Result<()> {
    let e = setup().await?;
    let t = mint(&e, &e.alice).await?;
    assert_ok(&set_policy(&e, &e.alice, &t, policy(60_000, Some(&e.guardian))).await?);
    let pid = propose(&e, &e.alice, &t, VALUE).await?;

    // The guardian vetoes a first sale (threat 16).
    assert_ok(&start_sale(&e, &e.alice, &t, None, None).await?);
    assert_refused(&call(&e.stranger, &e.vault, "veto_sale", json!({ "token_id": t }), yocto(1), 30).await?, "Only the guardian can veto");
    assert_ok(&call(&e.guardian, &e.vault, "veto_sale", json!({ "token_id": t }), yocto(1), 30).await?);
    assert_eq!(view(&e.vault, "get_sale", json!({ "token_id": t })).await?, Value::Null);

    // A sale at 2 NEAR reserved for Bob.
    let price = NearToken::from_near(2);
    let r = start_sale(&e, &e.alice, &t, Some(price), Some(&e.bob)).await?;
    assert_ok(&r);
    let sale: Value = r.json()?;
    let sale_id = sale["sale_id"].as_u64().unwrap();

    // Frozen: the ready proposal cannot be signed during the sale.
    advance_ms(&e.worker, 61_000).await?;
    assert_refused(&execute(&e, &e.alice, &t, pid).await?, "The vault is frozen for a sale");
    let check = view(&e.vault, "check_execution", json!({ "token_id": t, "proposal_id": pid })).await?;
    assert_eq!(check["ready"], json!(false));

    let buy = |who: &near_workspaces::Account, id: u64, deposit: NearToken| {
        let (who, vault, t) = (who.clone(), e.vault.clone(), t.clone());
        async move { call(&who, &vault, "buy", json!({ "token_id": t, "sale_id": id }), deposit, 50).await }
    };
    assert_refused(&buy(&e.bob, sale_id, price).await?, "The sale opens at");
    advance_ms(&e.worker, 600_000).await?;
    assert_refused(&buy(&e.stranger, sale_id, price).await?, "This sale is reserved for another buyer");
    assert_refused(&buy(&e.bob, sale_id + 1, price).await?, "The sale changed since it was audited");
    assert_refused(&buy(&e.bob, sale_id, NearToken::from_near(1)).await?, "Attach the price");

    let (alice_before, bob_before) = (balance(&e.alice).await?, balance(&e.bob).await?);
    let r = buy(&e.bob, sale_id, NearToken::from_millinear(2500)).await?;
    assert_ok(&r);
    assert_eq!(events(&r, "sale_bought").len(), 1);
    assert_eq!(owner_of(&e, &t).await?, e.bob.id().to_string());
    let alice_gain = balance(&e.alice).await? - alice_before;
    let bob_cost = bob_before - balance(&e.bob).await?;
    let near = NearToken::from_near(1).as_yoctonear();
    assert!(alice_gain >= 2 * near && alice_gain < 2 * near + near / 10, "seller got the price: {alice_gain}");
    assert!(bob_cost >= 2 * near && bob_cost < 2 * near + near / 50, "buyer paid the price, the rest came back: {bob_cost}");

    // Bob gets a clean vault, and Alice can no longer act on it.
    let p = view(&e.vault, "get_policy", json!({ "token_id": t })).await?;
    assert_eq!(p["has_policy"], json!(false));
    assert_eq!(view(&e.vault, "list_proposals", json!({ "token_id": t })).await?, json!([]));
    assert_eq!(view(&e.vault, "get_sale", json!({ "token_id": t })).await?, Value::Null);
    assert_refused(&set_policy(&e, &e.alice, &t, policy(0, None)).await?, "Only the vault owner can do this");
    assert_ok(&set_policy(&e, &e.bob, &t, policy(0, None)).await?);
    Ok(())
}

/// General review H1, with the real receiver contract: during `nft_transfer_call` the receiver
/// owns the vault for a few blocks, tries to set a policy (the first step to spend), is refused,
/// and the vault goes back to its owner. Also the "panic" (returned) and "keep" paths.
#[tokio::test]
async fn a_transfer_call_receiver_cannot_act_as_owner() -> anyhow::Result<()> {
    let e = setup().await?;
    let t = mint(&e, &e.alice).await?;
    let transfer_call = |msg: &str, tgas: u64| {
        let (alice, vault, receiver, t, msg) = (e.alice.clone(), e.vault.clone(), e.receiver.clone(), t.clone(), msg.to_string());
        async move {
            call(&alice, &vault, "nft_transfer_call", json!({ "receiver_id": receiver.id(), "token_id": t, "msg": msg }), yocto(1), tgas).await
        }
    };
    let open_sale = || async {
        assert_ok(&start_sale(&e, &e.alice, &t, None, None).await?);
        advance_ms(&e.worker, 601_000).await
    };

    open_sale().await?;
    assert_refused(&transfer_call("act", 40).await?, "Attach at least 50 Tgas to nft_transfer_call");

    let r = transfer_call("act", 200).await?;
    assert!(r.is_success(), "{r:?}");
    // Exactly one receipt failed: the receiver's set_policy, refused by the vault's lock.
    let failed = r.receipt_failures();
    assert_eq!(failed.len(), 1, "{failed:?}");
    assert_eq!(failed[0].executor_id, *e.vault.id(), "the vault refused it");
    assert!(
        format!("{:?}", failed[0]).contains("A transfer_call is in progress for this vault; wait until it resolves"),
        "{failed:?}"
    );
    assert!(!returned::<bool>(&r)?, "the receiver gave it back");
    assert!(
        r.logs().iter().any(|l| l.contains("test receiver: set_policy REFUSED during transfer_call")),
        "logs: {:?}",
        r.logs()
    );
    assert_eq!(owner_of(&e, &t).await?, e.alice.id().to_string());
    assert_eq!(view(&e.vault, "get_policy", json!({ "token_id": t })).await?["has_policy"], json!(false));
    let info = view(&e.vault, "vault_transfer_info", json!({ "token_id": t })).await?;
    assert_eq!(info["last"]["kind"], json!("transfer_call_returned"));

    // The lock was released at resolution: Alice can act again (a new sale, since a returned
    // transfer changes the owner epoch twice).
    open_sale().await?;
    let r = transfer_call("panic", 200).await?;
    assert!(!returned::<bool>(&r)?, "a failing receiver also gives it back");
    assert_eq!(owner_of(&e, &t).await?, e.alice.id().to_string());

    open_sale().await?;
    let r = transfer_call("keep", 200).await?;
    assert_ok(&r);
    assert!(returned::<bool>(&r)?);
    assert_eq!(owner_of(&e, &t).await?, e.receiver.id().to_string());
    Ok(())
}

/// Agent mode (after M12): an agent account named in the policy proposes and signs within the
/// policy, after the delay; the guardian vetoes one of its proposals; a sale removes the agent.
#[tokio::test]
async fn an_agent_spends_within_the_policy_and_the_guardian_can_veto() -> anyhow::Result<()> {
    let e = setup().await?;
    let t = mint(&e, &e.alice).await?;
    let vault_address = view(&e.vault, "vault_info", json!({ "token_id": t })).await?["evm_address"]
        .as_str()
        .unwrap()
        .to_string();
    let mut p = policy(60_000, Some(&e.guardian));
    p["proposer"] = json!(e.bob.id());
    assert_ok(&set_policy(&e, &e.alice, &t, p).await?);

    let vetoed = propose(&e, &e.bob, &t, VALUE).await?;
    let kept = propose(&e, &e.bob, &t, VALUE).await?;
    assert_ok(&call(&e.guardian, &e.vault, "veto_proposal", json!({ "token_id": t, "proposal_id": vetoed }), yocto(1), 30).await?);
    assert_refused(&execute(&e, &e.bob, &t, kept).await?, "Proposal delay has not passed yet");
    advance_ms(&e.worker, 61_000).await?;
    let r = execute(&e, &e.bob, &t, kept).await?;
    assert_ok(&r);
    assert!(returned::<bool>(&r)?, "the agent's proposal was signed");
    let rec = view(&e.vault, "get_signed", json!({ "token_id": t, "nonce": 0 })).await?;
    check_signed_record(&rec, &vault_address, DEST, VALUE, 0)?;
    assert_refused(&set_policy(&e, &e.bob, &t, policy(0, None)).await?, "Only the vault owner can do this");

    // A sale ends the agent's rights with the seller's policy.
    assert_ok(&start_sale(&e, &e.alice, &t, None, None).await?);
    advance_ms(&e.worker, 601_000).await?;
    assert_ok(&call(&e.alice, &e.vault, "nft_transfer", json!({ "receiver_id": e.stranger.id(), "token_id": t }), yocto(1), 30).await?);
    let r = call(&e.bob, &e.vault, "propose", json!({ "token_id": t, "tx": eth_tx(VALUE) }), millinear(50), 100).await?;
    assert_refused(&r, "Only the vault owner or its proposer can do this");
    Ok(())
}

/// Threat 1: during a sale the vault only signs cancellations. `cancel_nonce` signs a 0-value
/// transfer to itself with an already used nonce, so the earlier transaction can never be mined.
#[tokio::test]
async fn cancel_nonce_signs_during_a_sale() -> anyhow::Result<()> {
    let e = setup().await?;
    let t = mint(&e, &e.alice).await?;
    let vault_address = view(&e.vault, "vault_info", json!({ "token_id": t })).await?["evm_address"]
        .as_str()
        .unwrap()
        .to_string();
    assert_ok(&set_policy(&e, &e.alice, &t, policy(0, None)).await?);
    let pid = propose(&e, &e.alice, &t, VALUE).await?;
    assert!(execute(&e, &e.alice, &t, pid).await?.json::<bool>()?);
    assert_ok(&start_sale(&e, &e.alice, &t, None, None).await?);

    let cancel = json!({
        "token_id": t,
        "nonce": 0,
        "max_fee_per_gas": (40 * GWEI).to_string(),
        "max_priority_fee_per_gas": (2 * GWEI).to_string(),
    });
    let r = call(&e.alice, &e.vault, "cancel_nonce", cancel, millinear(20), 300).await?;
    assert_ok(&r);
    assert!(returned::<bool>(&r)?);
    let versions = view(&e.vault, "get_signed_versions", json!({ "token_id": t, "nonce": 0 })).await?;
    let versions = versions.as_array().unwrap();
    assert_eq!(versions.len(), 2, "the payment and its cancellation share nonce 0");
    check_signed_record(&versions[0], &vault_address, DEST, VALUE, 0)?;
    check_signed_record(&versions[1], &vault_address, &vault_address, 0, 0)?;
    Ok(())
}
