//! Rehearsal of an upgrade with a state migration, in the sandbox: deploy the previous build of
//! the contract (`$PREV_WASM`), store policies (one with a pending change and a queued proposal),
//! deploy the current build to the same account, run `migrate_policies`, and check that every
//! vault reads and works as before. Skipped when `PREV_WASM` is not set (CI does not keep old
//! builds); run it by hand before every migration:
//!
//!     PREV_WASM=/path/to/previous/policy_vault.wasm cargo test --test migration -- --nocapture

use sandbox_tests::*;
use serde_json::json;

#[tokio::test]
async fn upgrade_and_migrate_policies() -> anyhow::Result<()> {
    let Ok(prev) = std::env::var("PREV_WASM") else {
        println!("PREV_WASM not set: migration rehearsal skipped");
        return Ok(());
    };
    let e = setup_with_vault_wasm(&std::fs::read(&prev)?).await?;

    // State written by the previous build.
    let a = mint(&e, &e.alice).await?;
    assert_ok(&set_policy(&e, &e.alice, &a, policy(0, Some(&e.guardian))).await?);
    let pid = propose(&e, &e.alice, &a, 1_000).await?;
    let b = mint(&e, &e.bob).await?;
    assert_ok(&set_policy(&e, &e.bob, &b, policy(60_000, Some(&e.guardian))).await?);
    let mut looser = policy(60_000, Some(&e.guardian));
    looser["eth_daily_cap"] = json!("20000000000000000");
    assert_ok(&set_policy(&e, &e.bob, &b, looser).await?); // stays pending
    let _locked = mint(&e, &e.stranger).await?; // a vault with no policy

    // Upgrade in place, then convert the stored policies.
    let res = e.vault.as_account().deploy(&wasm("policy_vault")?).await?;
    assert!(res.is_success(), "redeploy failed");
    let r = e.vault.call("migrate_policies").args_json(json!({ "from": 0, "limit": 100 })).transact().await?;
    assert_ok(&r);
    assert_eq!(returned::<u64>(&r)?, 2, "two stored policies converted");
    let again = e.vault.call("migrate_policies").args_json(json!({ "from": 0, "limit": 100 })).transact().await?;
    assert_eq!(returned::<u64>(&again)?, 0, "idempotent");

    // Everything reads and works as before.
    let pa = view(&e.vault, "get_policy", json!({ "token_id": a })).await?;
    assert_eq!(pa["policy"]["proposer"], json!(null));
    assert_eq!(pa["policy"]["nfts"], json!([]));
    assert_eq!(view(&e.vault, "list_proposals", json!({ "token_id": a })).await?[0]["id"], json!(pid));
    let pb = view(&e.vault, "get_policy", json!({ "token_id": b })).await?;
    assert_eq!(pb["pending"]["policy"]["eth_daily_cap"], json!("20000000000000000"), "the pending change survived");
    let r = execute(&e, &e.alice, &a, pid).await?;
    assert_ok(&r);
    assert!(returned::<bool>(&r)?, "a proposal queued before the upgrade is signed after it");
    let r = call(&e.stranger, &e.vault, "migrate_policies", json!({ "from": 0, "limit": 100 }), yocto(0), 50).await?;
    assert_refused(&r, "is private");
    println!("migration rehearsal passed");
    Ok(())
}
