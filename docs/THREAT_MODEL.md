# Threat model (v1, design stage)

Approved by the author on 2026-11-04 before any contract code was written. **Nothing below has been tested yet.** "Planned" means a mitigation exists on paper only.

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
| 2 | The seller adds themself as an allowed destination and drains the cap before selling | Transfer resets allowed destinations, guardian and queue; the daily cap bounds the damage | Planned |
| 3 | Misreading of calldata lets a dangerous approval through | Hash is built from validated fields; golden tests compare the Rust hash with viem for the same fields | Planned |
| 4 | A bug makes the contract sign something it should not | A single signing path; an attack suite that tries each bypass; manual review | Planned |
| 5 | The `sign` callback sees a different owner than the one who requested it | Each proposal records the owner epoch; transfers are blocked while a signature is in flight | Planned |
| 6 | Race on the daily cap | Reserve the amount when proposing; release it on veto, cancel or invalidation | Planned |
| 7 | Permissions the seller left on the external chain | Only approvals to allowed spenders with a finite amount can ever be signed; the signing history is public so a buyer can audit it | Partial |
| 8 | Trust in the MPC network | Not solved; declared | Residual |
| 9 | Whoever controls the contract account can change the contract | Deploy to an account with no upgrade keys (decision pending) and declare it | Pending |
| 10 | Stuck nonce or missing gas on the external chain | Documented; the cancel transaction in threat 1 helps | Residual |
| 11 | EIP-7702 authorizations or message signatures obtained from the contract | The contract never builds them | Planned |
| 12 | Replay across chains | `chain_id` is inside the hash; one derivation path per chain | Planned |

## Out of scope

Legal status of selling an account, front-ends other than the reference page, chains other than one EVM test network, Bitcoin (one signature per UTXO).
