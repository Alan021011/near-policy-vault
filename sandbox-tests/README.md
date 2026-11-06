# Sandbox tests (M9)

Integration tests that run the vault's asynchronous flows in a **local NEAR sandbox**: the real
wasm of the contract, real cross-contract promises and callbacks, real `yield`/`resume`. No testnet
account, no Sepolia ETH, no waiting: the sandbox clock is moved forward with `fast_forward`.

The unit tests in `contract/src/lib.rs` simulate these flows by hand (they feed the callback a
prepared result). The live scripts in `scripts/` run them on testnet and Sepolia, but need funded
accounts and 10–15 minutes each. These tests sit in between: anyone can run them with one command.

## What runs

| Contract | Source | Role |
|---|---|---|
| `policy_vault.wasm` | `contract/` | The product, built from this source. On the author's machine (Windows, Rust 1.99.1, cargo-near 0.22.0) it is byte-identical to the testnet deployment (`sha256 27e7b8ae…`) and the tests were run on those bytes; other machines (e.g. the CI runner) produce different bytes until the reproducible Docker build lands. |
| `mock_signer.wasm` | `mock-signer/` | Stands in for Chain Signatures (`v1.signer-prod.testnet`), which does not exist in a sandbox. Same call and answer shapes. It can answer at once, **hold its answer with yield/resume like the real MPC network**, sign with the wrong key, answer garbage or fail. |
| `test_receiver.wasm` | `test-receiver/` | The `nft_transfer_call` receiver used for the H1 attack. |

## Tests (`tests/sandbox.rs`)

| Test | What it shows |
|---|---|
| `mint_learns_the_vault_address_from_the_signer` | M4: the address comes from the signer through a cross-contract call and its callback. |
| `a_proposal_is_signed_after_its_delay` | M5–M7: policy, proposal, delay, signature. The stored raw transaction is decoded and its signature recovered **here, with k256**, not with the contract's own code. |
| `a_signature_in_flight_locks_the_vault` | Threat 5: while the signer holds its answer, the vault cannot sign again, start a sale or be transferred. |
| `bad_signer_answers_never_double_spend` | Review S1/S3: wrong key → everything undone; unreadable answer or failed call → nonce "uncertain", retry signs the identical transaction, the cap is charged once. |
| `a_signer_timeout_unlocks_the_vault` | The MPC network never answers: the yield times out, the nonce becomes uncertain, the vault unlocks, a late answer is ignored. |
| `a_sale_is_bought_on_chain` | M8 + H3: guardian veto, sale freeze, 10-minute minimum, reserved buyer, stale `sale_id`, and `buy` paying the seller in the same transaction. |
| `a_transfer_call_receiver_cannot_act_as_owner` | H1: the receiver tries to set a policy while it owns the vault and is refused; returned, failed and kept paths. |
| `cancel_nonce_signs_during_a_sale` | Threat 1: during a sale only cancellations sign; the cancellation reuses the nonce of the earlier payment. |

Negative control (run once by hand): a contract built with four rules removed (no `transfer_call`
lock, transfer allowed with a signature in flight, any key accepted, `buy` not paying the seller)
fails exactly the four matching tests and passes the other four.

## What these tests do not cover

- **The real MPC network.** The mock signer has the same interface, but its keys are not the
  network's. Real signing is covered by the live scripts (`scripts/m7-*.mjs`, README steps 9–12),
  where transactions signed by the contract were mined on Sepolia.
- **Ethereum.** Nothing is broadcast here; the stored raw transactions are decoded and their
  signatures recovered, but mining is covered by the live scripts.
- **Gas on testnet.** The sandbox runs the same runtime (nearcore 2.14.0), but the mock signer's
  gas use is not the MPC contract's.

## Run

The NEAR sandbox runs on Linux (x86_64, aarch64) and macOS (arm64). On Windows, use WSL.
Needs Rust and [cargo-near](https://github.com/near/cargo-near); `near-workspaces` downloads the
sandbox binary (nearcore 2.14.0, ~35 MB) on the first run.

```bash
./build-wasm.sh          # builds the three contracts into sandbox-tests/wasm/
cargo test -- --test-threads=4
```

Each test starts its own sandbox, so they are independent. The same steps run on every push in
GitHub Actions (`.github/workflows/tests.yml`).

**Never deploy `mock-signer` next to real funds:** its keys are derived from public data on purpose.
