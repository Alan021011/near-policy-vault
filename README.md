# near-policy-vault

> **Status: work in progress.** The signing path (A1), the NFT base contract (M3) the per-vault EVM address (M4), the spending policy (M5) and the proposal queue (M6) run on testnet; the spending policy and the sale protection are not built yet.
> Built for the NEAR HACKATHON 2026, track `nfts` (also aiming at `security` and `open` only if they work end to end).

An NFT that **owns an account on another chain** and can only move its funds under a spending policy enforced by a NEAR contract.

## The idea

- Each NFT is a vault. Its EVM address is derived with NEAR Chain Signatures from the contract account and the path `vault-<token_id>`.
- The contract only asks the network to sign a transaction if it satisfies the vault's policy: daily cap, allowed destinations, a delay with cancel, a guardian veto, and no unlimited token approvals.
- The contract **computes the signing hash itself** from fields it has validated. It never signs a hash supplied by a caller.
- Selling the NFT hands over the vault without handing over any private key. The sale runs in two phases so a seller cannot keep a pre-signed transaction (see `docs/THREAT_MODEL.md`, threat 1).

## What exists today

| Piece | State |
|---|---|
| Threat model (`docs/THREAT_MODEL.md`) | 15 threats; approved by the author, updated after the M3 review. Most mitigations are still planned |
| EIP-1559 signing hash and RLP encoder (`contract/src/evm.rs`) | Compiles; 9 unit tests pass; matches viem on 19 golden vectors (negative control checked) |
| Chain Signatures on testnet (`scripts/a1-prepare.mjs`, `a1-verify.mjs`) | `sign` called from a NEAR account with a 1 yoctoNEAR deposit; returned signature recovers the derived address (checked with viem). **Broadcast to Sepolia and confirmed** (tx 0xfe6d501e202d703ed56ef3978b6c6f666379fbe87d9d0c456683cd22741a45b1, block 12064522, status success; `scripts/a1-broadcast.mjs`). Called from a NEAR account, not yet from a contract. These A1 scripts record a one-off run: the signature is hard-coded and nonce 0 is spent, so they cannot be re-run as they are |
| NFT base contract, NEP-171/177/178/181 (`contract/src/lib.rs`) | Anyone mints a vault for themselves; path `vault-<id>`. 25 unit tests pass (negative controls checked). Deployed on testnet at `m3.alan-vault-2026.testnet` and upgraded in place with `migrate`. `scripts/m3-testnet-check.mjs` passes 16/16 live checks (approved transfers, `nft_transfer_call` kept / returned / receiver panic, approval refunds). Vault 0 has EVM address `0xb4bbbae0c0e057f0d85233d9394088e449d5b843` (derived, unfunded) |
| Vault EVM address published by the contract (M4) | At mint the contract asks the Chain Signatures contract (`v1.signer-prod.testnet`) for `derived_public_key(vault-<id>, predecessor = contract, domain 0)`, checks the answer in a private callback and stores the key and the address; `vault_info` returns them. 11 unit tests (incl. the real testnet key of vault 0), negative control checked. `scripts/m4-testnet-check.mjs`: 12/12 live checks, every vault equals an independent derivation |
| Spending policy (M5, `contract/src/policy.rs`) | Per vault: chain, ETH daily cap (value + worst-case gas), max gas cost, allowed destinations, allowed spenders, ERC-20 tokens with daily cap and **max approval**, delay and guardian. Loosening waits the delay and can be vetoed by the guardian; tightening applies at once; any change of owner deletes the policy. `check_transaction` returns allowed / reason / the exact signing hash. 29 unit tests, negative controls checked. `scripts/m5-testnet-check.mjs`: 22/22 live checks (signing hash equals viem) |
| Proposal queue (M6) | `propose` checks the policy and reserves the spend; the transaction waits the delay; the owner cancels or the guardian vetoes (reservation released); at most 8 queued. The EVM nonce is assigned at signing time, so cancelled proposals leave no gaps; `get_next_nonce` never resets on a sale. `check_execution` re-checks the current policy and the owner epoch and returns the exact hash to sign. 16 unit tests, negative controls checked. `scripts/m6-testnet-check.mjs`: 15/15 live checks |
| MPC signing from the contract (M7), two-phase sale (M8) | Not started |
| Web page, attack suite | Not started |

## How to verify (will be filled in as pieces land)

Each step follows the pattern "run X, expect Y". Nothing is claimed until it has been run.

1. Regenerate the reference vectors with viem:
   `cd scripts && npm ci && node gen-vectors.mjs`
   Expect: `wrote 19 vectors to .../vectors/eip1559_signing_hash.tsv` and `git status` shows no change (the committed vectors are reproduced exactly). `npm ci` installs the exact versions in `package-lock.json`.
2. Run the Rust tests:
   `cd contract && cargo test`
   Expect: 90 unit tests (9 EVM helpers, 11 policy, 70 contract) and `rust_signing_hash_matches_viem` pass. If you change one character in a vector, that test fails with the case name.
   On Windows, `contract/.cargo/config.toml` sets `AWS_LC_SYS_PREBUILT_NASM=1` so NASM is not needed.
3. Build the contract:
   `cd contract && cargo near build non-reproducible-wasm --no-abi`
   Expect: `policy_vault.wasm` is produced (ABI generation is skipped because it fails on Windows hosts).
4. Check the deployed NFT contract on testnet (needs the NEAR CLI and keys for an owner account and the contract account; `test-receiver/` is a helper contract deployed at the third account):
   `cd scripts && node m3-testnet-check.mjs <owner>.testnet <vault-contract>.testnet <receiver>.testnet`
   Expect: 16 `PASS` lines and `ALL CHECKS PASSED`.
5. Check that the contract publishes the right EVM address for every vault:
   `cd scripts && node m4-testnet-check.mjs <owner>.testnet <vault-contract>.testnet`
   Expect: one `PASS` per vault comparing `vault_info` with an independent derivation (signer query + viem), the private-callback attack rejected, and `ALL CHECKS PASSED`.
6. Check the spending policy on testnet (about 2 minutes; the third account acts as guardian):
   `cd scripts && node m5-testnet-check.mjs <owner>.testnet <vault-contract>.testnet <guardian>.testnet`
   Expect: 22 `PASS` lines and `ALL CHECKS PASSED`.
7. Check the proposal queue on testnet (about 2 minutes):
   `cd scripts && node m6-testnet-check.mjs <owner>.testnet <vault-contract>.testnet <guardian>.testnet`
   Expect: 15 `PASS` lines and `ALL CHECKS PASSED`.
8. Check that the deployed code is this repository's code: compare the SHA-256 printed by step 3 with the `code_hash` of the contract account (`near account view-account-summary m3.alan-vault-2026.testnet network-config testnet now`, or the RPC `view_account`, which gives it in base58).
   The contract currently deployed (M6) has SHA-256 `c4ecef5281fa91f698e5cb5a9e0fce302d7f8e49bab92bfe7ae6ae2b6fda7650`, equal to the local build of the M6 commit. On 2026-11-05 a fresh clone of the previous commit also built byte-identical to what was deployed then (`01b4939a…`). Both were on the author's machine and toolchain (Rust 1.99.1, cargo-near 0.22.0); a byte-identical build on any machine needs `cargo near build reproducible-wasm` (Docker), planned before submission.

## Known limits

See `docs/THREAT_MODEL.md`. Residual risks that this design does not remove: trust in the MPC network, and whoever controls the contract's upgrade keys.

- **Upgrade key (threat 9).** Today the contract account keeps a full-access key, so its owner can replace the code (this is how `migrate` was deployed). Before the final submission the plan is to delete that key so the code can no longer change, and to show it here with `near account view-account-summary` ("0 full access keys"). Until then, treat the contract as upgradable by its deployer.
- **Stolen owner key (threat 16, open).** Today a thief with the owner's NEAR key could transfer the NFT and set a fresh policy at once, skipping the delay and the guardian. The contract cannot sign yet, so nothing is at risk now; the two-phase sale (M8) must make transfers wait the delay and be vetoable by the guardian.
- **Daily windows.** Caps use fixed 24-hour windows, so up to twice a cap can be spent across a window boundary.
- **Signer contract.** The Chain Signatures contract is fixed at init (`signer_id`). Whoever deploys chooses it, and changing it needs a code upgrade (threat 9).
- **Token ids are never reused.** Each vault's EVM account depends only on its id. There is no burn; adding one must never reissue an id, or two owners would share one account.
- **Library event gap.** `near-contract-standards` 5.30.0 emits `nft_transfer` without `authorized_id` when an approved account transfers. This contract also emits `vault_transfer` (standard `policy_vault`) with that field and keeps the last transfer on-chain (`vault_transfer_info`).
- **Approval deposits.** The library keeps the storage deposit of approvals cleared by a transfer; this contract refunds it to the previous owner.
