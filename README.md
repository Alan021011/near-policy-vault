# near-policy-vault

> **Status: design stage. Nothing here has been tested on a live network yet.**
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
| Threat model | Written and approved by the author (design stage) |
| EIP-1559 signing hash and RLP encoder (`contract/src/evm.rs`) | Compiles; 9 unit tests pass; matches viem on 19 golden vectors (negative control checked) |
| Chain Signatures on testnet (`scripts/a1-prepare.mjs`, `a1-verify.mjs`) | `sign` called from a NEAR account with a 1 yoctoNEAR deposit; returned signature recovers the derived address (checked with viem). **Broadcast to Sepolia and confirmed** (tx 0xfe6d501e202d703ed56ef3978b6c6f666379fbe87d9d0c456683cd22741a45b1, block 12064522, status success; `scripts/a1-broadcast.mjs`). Called from a NEAR account, not yet from a contract |
| NFT contract, policy, MPC integration | Not started |
| Web page, attack suite | Not started |

## How to verify (will be filled in as pieces land)

Each step follows the pattern "run X, expect Y". Nothing is claimed until it has been run.

1. Regenerate the reference vectors with viem:
   `cd scripts && npm install && node gen-vectors.mjs`
   Expect: `wrote 19 vectors to .../vectors/eip1559_signing_hash.tsv`.
2. Run the Rust tests:
   `cd contract && cargo test`
   Expect: 9 unit tests and the `rust_signing_hash_matches_viem` test pass. If you change one character in a vector, that test fails with the case name.

## Known limits

See `docs/THREAT_MODEL.md`. Residual risks that this design does not remove: trust in the MPC network, and whoever controls the contract's upgrade keys.
