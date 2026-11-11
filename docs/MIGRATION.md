# If a bug is found in the locked contract

The vault contract (`m3.alan-vault-2026.testnet`) has no access keys: nobody, the author included, can change its code. That is what makes its rules trustworthy, and it also means **a bug cannot be fixed in place**. This page says what happens then. It describes a procedure; it has not been needed or rehearsed end to end.

What a next contract would change is designed in [V2.md](V2.md).

## What a fix looks like
1. A corrected contract (v2) is built reproducibly, reviewed and deployed at a **new account**, then locked the same way.
2. The web page and the README point new vaults to v2, and say clearly which version a vault belongs to.
3. Vaults on v1 keep working exactly as before: the bug does not stop the contract, it is a rule that should be different.

## How an owner moves a vault's assets from v1 to v2
No migration function is needed: the current rules already allow it, through the normal path.
1. The owner mints a vault on v2 and copies its new Ethereum address.
2. On the v1 vault, the owner adds that address to the **approved recipients** (and, for tokens or NFTs, the token or collection). This is a looser rule: it **waits the vault's waiting time, and the guardian can veto it**, which is the protection against a thief using the same path.
3. The owner (or the agent) requests payments to the new address: ETH, ERC-20 transfers and NFT transfers, each within the vault's daily limits. A large balance takes several days, or the owner raises the daily limit first (also a looser rule: it waits and can be vetoed).
4. When the v1 vault is empty, the owner removes the agent and keeps or hands over the v1 NFT; it no longer controls anything of value.

## What can block this, and the answer
| Situation | What happens |
|---|---|
| A handover is open on the v1 vault | The vault only signs cancellations; the owner stops the handover first |
| A signature is in flight or uncertain | It ends with the signer's answer or a timeout; an uncertain payment is retried with the same nonce or cancelled with `cancel_nonce` |
| The bug is in the policy check itself and blocks every payment | Assets stay in the v1 vault; the owner keeps control of the NFT, but no payment can leave until a way around the bug exists. This is the residual risk of an immutable contract |
| The bug lets someone spend more than the rules say | The guardian's veto and the waiting time are the first line; owners should lower their limits (a stricter rule applies at once) until they have moved their assets |

## How owners would be told
This is a testnet project without a user list. A real deployment would need a notice on the web page, an entry in the repository, and alerts to guardians (`scripts/guardian-alerts.mjs` already notifies about waiting payments and rule changes, not about advisories).
