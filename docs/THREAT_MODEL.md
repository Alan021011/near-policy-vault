# Threat model (v1.3)

Approved by the author on 2026-11-04 before any contract code was written; updated on 2026-11-05 after the M3 review. "Planned" means a mitigation exists on paper only; "Partial" says which part is tested. Updated again on 2026-11-05 after M5 (spending policy) and M6 (proposal queue). The contract cannot sign anything yet (M6-M7), so no funds are at risk today; the two-phase sale (M8) is not built, so threats 1, 5 and 16 are still unmitigated in code.

## Assets and actors

- **Asset:** funds held at the EVM address derived for each NFT.
- **Owner:** the current holder of the NFT. **Seller / buyer:** the old and new owner around a sale.
- **Guardian:** one NEAR account per vault that can veto a queued transaction.
- **MPC network:** the NEAR Chain Signatures signers (8 nodes according to the NEAR documentation).

## Core rule: validate what you sign

The contract stores the transaction fields (chain id, nonce, fees, gas limit, destination, value, data), checks the policy on those fields and computes the EIP-1559 signing hash itself. A caller never supplies a hash. Only plain ETH transfers and ERC-20 `transfer` / `approve` calls are ever built. Message signing (permits, EIP-712) and EIP-7702 authorizations are never produced.

## Threats

| # | Threat | Planned mitigation | State |
|---|---|---|---|
| 1 | **Pre-signed transaction.** The seller obtains a valid signature, sells the NFT and broadcasts the transaction afterwards | Two-phase sale: `start_sale` freezes new signatures; the buyer audits the external-chain nonce against the contract's `next_nonce`; if a signed transaction is outstanding, a cancel transaction with the same nonce is signed; only then does `nft_transfer` succeed | Planned |
| 2 | The seller adds themself as an allowed destination and drains the cap before selling | Every change of owner deletes the policy, its pending change and its spending windows; the daily cap bounds the damage | Partial: policy and queue reset tested (unit + testnet) |
| 3 | Misreading of calldata lets a dangerous approval through | Hash is built from validated fields; golden tests compare the Rust hash with viem for the same fields | Partial: the hash matches viem on 19 vectors and the strict classifier is unit-tested; the policy that uses them is not built |
| 4 | A bug makes the contract sign something it should not | A single signing path; an attack suite that tries each bypass; manual review | Planned |
| 5 | The `sign` callback sees a different owner than the one who requested it | Each proposal records the owner epoch; transfers are blocked while a signature is in flight | Partial: proposals carry the owner epoch and are refused for a previous owner (unit test); the transfer lock while signing is M8 |
| 6 | Race on the daily cap | Reserve the amount when proposing; release it on veto, cancel or invalidation. Windows are fixed 24 h: across a window boundary up to 2x the cap can be spent (declared) | Partial: proposals reserve their spend and release it on cancel/veto (unit + testnet) |
| 7 | Permissions the seller left on the external chain | Only approvals to allowed spenders up to the token's `max_approval` can be signed; amounts above 128 bits are refused, so 2^256-1 and 2^255 both fail | Partial: `check_transaction` refuses them on testnet; signing is M7 |
| 8 | Trust in the MPC network | Not solved; declared | Residual |
| 9 | Whoever controls the contract account can change the contract | Today the deployer keeps a full-access key (used for `migrate`). Before submission: delete it and show "0 full access keys"; declared in the README | Pending (documented) |
| 10 | Stuck nonce or missing gas on the external chain | The nonce is assigned at signing time (cancelled proposals leave no gaps); fees are fixed when proposing, so a proposal with stale fees must be cancelled and proposed again; the cancel transaction in threat 1 helps | Residual |
| 11 | EIP-7702 authorizations or message signatures obtained from the contract | The contract never builds them | Planned |
| 12 | Replay across chains | `chain_id` is inside the EIP-1559 hash, so a signature for one chain is invalid on another. The derivation path (`vault-<id>`) is the same for every EVM chain, so each vault has the same address everywhere; the policy must fix which chain ids a vault may sign for | Partial: `chain_id` in the hash is tested against viem; the per-vault chain rule is not built |
| 13 | During `nft_transfer_call` the receiver owns the NFT for a moment and may hand it back | The sale freeze and the "signature in flight" lock must treat a pending `transfer_call` as a transfer; ownership changes are recorded (`vault_transfer_info`) | Partial: behaviour checked on testnet (kept, returned, receiver panic); the locks are not built |
| 14 | An approved account (e.g. a marketplace) moves the NFT | Every transfer path, by the owner or by an approved account, goes through the same wrapper where the locks will live; approvals are cleared on transfer and their deposit refunded | Partial: wrapper and clearing tested; the locks are not built |
| 15 | A token id is reused, so two owners share one EVM account | Ids are sequential and never reissued; there is no burn | Tested (unit test) |
| 16 | **Stolen owner key.** A thief with the owner's NEAR key transfers the NFT to an account of theirs; the transfer clears the policy and the first policy of a locked vault applies at once, so the delay and the guardian are skipped | M8: a transfer must wait the current delay and be vetoable by the guardian (sale phase), so the guardian also protects against theft of the NFT | **Open** (found while building M5) |
| 17 | A loosening policy change applies without anyone noticing | Loosening waits the current delay; the guardian of the policy in force can veto; tightening applies at once; changes emit events | Partial: tested on testnet (veto, early apply refused, apply after delay) |

## Out of scope

Legal status of selling an account, front-ends other than the reference page, chains other than one EVM test network, Bitcoin (one signature per UTXO).
