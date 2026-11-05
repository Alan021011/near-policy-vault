// Buyer's audit before taking a vault (M8, threat 1). The contract cannot read Ethereum, so this
// script does the one check it cannot: compare the vault account's nonce on the external chain
// with the contract's next nonce.
//
// Every signature the contract ever produced uses a nonce below `get_next_nonce`. If the external
// account has already used all of them (its mined nonce equals the contract's next nonce), no
// signature the seller may have kept can ever be mined again. Otherwise each nonce in
// [mined nonce, next nonce) has a signed transaction that could still go through, and the seller
// should cancel it (`cancel_nonce`, allowed during the sale) before the buyer pays.
//
// Usage: node sale-audit.mjs <vault-contract> <token_id> [--eth-rpc <url>]
// Exit code 0 = SAFE, 2 = NOT SAFE.
import { fileURLToPath } from 'node:url';

const NEAR_RPC = process.env.NEAR_RPC || 'https://rpc.testnet.near.org';
const DEFAULT_ETH_RPC = { 11155111: 'https://ethereum-sepolia-rpc.publicnode.com', 560048: 'https://ethereum-hoodi-rpc.publicnode.com' };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function nearView(contract, method, args, attempt = 1) {
  try {
    const res = await fetch(NEAR_RPC, { method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'query', params: { request_type: 'call_function',
        finality: 'final', account_id: contract, method_name: method,
        args_base64: Buffer.from(JSON.stringify(args)).toString('base64') } }) });
    if (res.status === 429 || res.status >= 500) throw new Error(`HTTP ${res.status}`);
    const j = await res.json();
    if (j.error) throw new Error(JSON.stringify(j.error));
    return JSON.parse(Buffer.from(j.result.result).toString());
  } catch (e) {
    if (attempt >= 5) throw e;
    await sleep(2000 * attempt);
    return nearView(contract, method, args, attempt + 1);
  }
}

async function ethNonce(rpc, address, tag) {
  const j = await fetch(rpc, { method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'eth_getTransactionCount', params: [address, tag] }) }).then((r) => r.json());
  if (j.error) throw new Error(j.error.message);
  return Number(BigInt(j.result));
}

/** Returns { safe, lines[], outstanding[], ... } for a vault. */
export async function audit(contract, tokenId, ethRpc) {
  const lines = [];
  const problems = [];
  const owner = (await nearView(contract, 'nft_token', { token_id: tokenId }))?.owner_id;
  const info = await nearView(contract, 'vault_info', { token_id: tokenId });
  const chain = await nearView(contract, 'get_vault_chain', { token_id: tokenId });
  const next = await nearView(contract, 'get_next_nonce', { token_id: tokenId });
  const uncertain = await nearView(contract, 'get_uncertain', { token_id: tokenId });
  const inflight = await nearView(contract, 'get_inflight', { token_id: tokenId });
  const sale = await nearView(contract, 'get_sale', { token_id: tokenId });
  lines.push(`vault ${tokenId} of ${contract}, owner ${owner}`);
  lines.push(`EVM address ${info.evm_address ?? '(not resolved)'}, chain ${chain ?? '(never signed)'}`);

  if (inflight) problems.push(`a signature is in flight (nonce ${inflight.nonce}); wait for it to finish`);
  const now = Date.now();
  if (!sale) problems.push('no sale is active: the owner must call start_sale');
  else if (now < sale.opens_at_ms) lines.push(`sale opens in ${Math.ceil((sale.opens_at_ms - now) / 1000)} s (the guardian can still veto it)`);
  else if (now >= sale.closes_at_ms) problems.push('the sale window has closed');
  else lines.push(`sale ${sale.sale_id} open until ${new Date(sale.closes_at_ms).toISOString()}`);
  if (sale) lines.push(`bind the purchase to this sale: transfer with memo "sale:${sale.sale_id}" (it fails if the seller restarts the sale)`);

  let mined = 0;
  let outstanding = [];
  if (next > 0) {
    const rpc = ethRpc || DEFAULT_ETH_RPC[chain];
    if (!rpc) throw new Error(`no RPC known for chain ${chain}; pass --eth-rpc`);
    mined = await ethNonce(rpc, info.evm_address, 'latest');
    const pending = await ethNonce(rpc, info.evm_address, 'pending');
    lines.push(`nonces: contract next = ${next}, mined on chain = ${mined}, pending in mempool = ${pending}`);
    for (let n = mined; n < next; n++) {
      const versions = await nearView(contract, 'get_signed_versions', { token_id: tokenId, nonce: n });
      outstanding.push({ nonce: n, versions });
      const kinds = versions.map((v) => (v.proposal_id > 1e18 ? 'cancellation' : `payment (proposal ${v.proposal_id})`));
      problems.push(`nonce ${n} is signed but not mined: ${kinds.join(', ') || 'outcome unknown'} — the seller should cancel_nonce(${n}) and the cancellation must be mined`);
    }
  } else {
    lines.push('the vault never signed anything');
  }
  const openUncertain = uncertain.filter((u) => u.nonce >= mined);
  for (const u of openUncertain) {
    if (!outstanding.some((o) => o.nonce === u.nonce)) problems.push(`nonce ${u.nonce} has an uncertain signature`);
  }
  return { safe: problems.length === 0, lines, problems, outstanding, mined, next, owner, sale };
}

const isMain = process.argv[1] && fileURLToPath(import.meta.url).toLowerCase() === process.argv[1].toLowerCase();
if (isMain) {
  const [contract, tokenId] = process.argv.slice(2);
  if (!tokenId) throw new Error('usage: node sale-audit.mjs <vault-contract> <token_id> [--eth-rpc <url>]');
  const i = process.argv.indexOf('--eth-rpc');
  const r = await audit(contract, tokenId, i > 0 ? process.argv[i + 1] : undefined);
  for (const l of r.lines) console.log('  ' + l);
  for (const p of r.problems) console.log('  ! ' + p);
  console.log(r.safe
    ? `SAFE for sale ${r.sale.sale_id}: no signature the seller holds can still be mined. Pay only through a transfer bound to "sale:${r.sale.sale_id}".`
    : 'NOT SAFE: see the points above');
  process.exit(r.safe ? 0 : 2);
}
