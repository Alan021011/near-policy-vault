// Broadcasts a transaction the vault contract has signed (M10). Anyone can do it: the signed raw
// transaction is public in the contract (`get_signed_versions`), so no key is needed.
//
// Before sending, it decodes the transaction, recovers the sender with viem and checks that it is
// the vault's own address (`vault_info`), and compares the nonce with the vault account's nonce on
// its chain. A nonce that is already used is reported instead of sent (if the mined transaction is
// this very one, it says so).
//
// Usage: node broadcast.mjs <vault-contract> <token_id> <nonce> [--version <n>] [--eth-rpc <url>]
//   --version: which signed version of that nonce (default: the latest; a cancellation made with
//              `cancel_nonce` is a later version of the same nonce).
// Exit code 0 = mined (or already mined), 1 = error, 2 = the nonce was used by another transaction.
import { parseTransaction, recoverTransactionAddress } from 'viem';

const NEAR_RPC = process.env.NEAR_RPC || 'https://rpc.testnet.near.org';
const DEFAULT_ETH_RPC = { 11155111: 'https://ethereum-sepolia-rpc.publicnode.com', 560048: 'https://ethereum-hoodi-rpc.publicnode.com' };
const EXPLORER = { 11155111: 'https://sepolia.etherscan.io/tx/', 560048: 'https://hoodi.etherscan.io/tx/' };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const args = process.argv.slice(2);
const flag = (name) => {
  const i = args.indexOf(name);
  return i >= 0 ? args.splice(i, 2)[1] : undefined;
};
const versionArg = flag('--version');
const ethRpcArg = flag('--eth-rpc');
const [CONTRACT, TOKEN_ID, NONCE] = args;
if (NONCE === undefined) {
  console.error('usage: node broadcast.mjs <vault-contract> <token_id> <nonce> [--version <n>] [--eth-rpc <url>]');
  process.exit(1);
}

async function nearView(method, params, attempt = 1) {
  try {
    const res = await fetch(NEAR_RPC, { method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'query', params: { request_type: 'call_function',
        finality: 'final', account_id: CONTRACT, method_name: method,
        args_base64: Buffer.from(JSON.stringify(params)).toString('base64') } }) });
    if (res.status === 429 || res.status >= 500) throw new Error(`HTTP ${res.status}`);
    const j = await res.json();
    if (j.error) throw new Error(JSON.stringify(j.error));
    return JSON.parse(Buffer.from(j.result.result).toString());
  } catch (e) {
    if (attempt >= 5) throw e;
    await sleep(2000 * attempt);
    return nearView(method, params, attempt + 1);
  }
}

async function eth(rpc, method, params) {
  const j = await fetch(rpc, { method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }) }).then((r) => r.json());
  if (j.error) throw new Error(j.error.message);
  return j.result;
}

const versions = await nearView('get_signed_versions', { token_id: TOKEN_ID, nonce: Number(NONCE) });
if (versions.length === 0) {
  console.error(`vault ${TOKEN_ID} has no signed transaction with nonce ${NONCE}`);
  process.exit(1);
}
const index = versionArg === undefined ? versions.length - 1 : Number(versionArg);
const rec = versions[index];
if (!rec) {
  console.error(`nonce ${NONCE} has ${versions.length} signed version(s); --version ${versionArg} does not exist`);
  process.exit(1);
}
const vaultAddress = (await nearView('vault_info', { token_id: TOKEN_ID })).evm_address;
const tx = parseTransaction(rec.signed_tx);
const from = (await recoverTransactionAddress({ serializedTransaction: rec.signed_tx })).toLowerCase();
// A cancellation has proposal_id u64::MAX, which JSON.parse rounds; anything that large is one.
const kind = rec.proposal_id > 1e18 ? 'cancellation (cancel_nonce)' : `proposal ${rec.proposal_id}`;
console.log(`vault ${TOKEN_ID} (${vaultAddress}), nonce ${NONCE}, version ${index} of ${versions.length} (${kind})`);
console.log(`  chain ${tx.chainId}, to ${tx.to}, value ${tx.value ?? 0n} wei, data ${tx.data ?? '0x'}`);
console.log(`  tx hash ${rec.tx_hash}`);
if (from !== vaultAddress) {
  console.error(`the signature recovers to ${from}, not to the vault address: not sending`);
  process.exit(1);
}
const rpc = ethRpcArg || DEFAULT_ETH_RPC[tx.chainId];
if (!rpc) {
  console.error(`no default RPC for chain ${tx.chainId}; pass --eth-rpc <url>`);
  process.exit(1);
}
const link = (h) => (EXPLORER[tx.chainId] ? EXPLORER[tx.chainId] + h : h);

const minedNonce = Number(BigInt(await eth(rpc, 'eth_getTransactionCount', [vaultAddress, 'latest'])));
if (minedNonce > Number(NONCE)) {
  const known = await eth(rpc, 'eth_getTransactionReceipt', [rec.tx_hash]);
  if (known) {
    console.log(`already mined (status ${known.status === '0x1' ? 'success' : 'reverted'}): ${link(rec.tx_hash)}`);
    process.exit(0);
  }
  console.log(`nonce ${NONCE} is already used on chain ${tx.chainId} by another transaction (the account is at nonce ${minedNonce}); this one can never be mined`);
  process.exit(2);
}
if (minedNonce < Number(NONCE)) {
  console.log(`note: the vault account is at nonce ${minedNonce}; nonces ${minedNonce}..${Number(NONCE) - 1} must be mined first, so this one waits in the mempool`);
}

let hash;
try {
  hash = await eth(rpc, 'eth_sendRawTransaction', [rec.signed_tx]);
} catch (e) {
  if (!/already known/i.test(e.message)) throw e;
  hash = rec.tx_hash;
}
console.log(`sent ${hash}, waiting for it to be mined...`);
for (let i = 0; i < 60; i++) {
  const r = await eth(rpc, 'eth_getTransactionReceipt', [hash]);
  if (r) {
    console.log(`mined in block ${Number(BigInt(r.blockNumber))}, status ${r.status === '0x1' ? 'success' : 'reverted'}: ${link(hash)}`);
    process.exit(r.status === '0x1' ? 0 : 1);
  }
  await sleep(5000);
}
console.log(`not mined after 5 minutes (it may still be): ${link(hash)}`);
process.exit(1);
