// Re-checks, against the chains, every live proof the README cites (the same list as the web
// page's Verify tab: web/src/evidence.json). For a judge or an AI reviewer: one command, no keys,
// no wallet, no npm install (Node 18+).
//
//   node scripts/evidence.mjs
//
// It checks: the deployed contract's code hash equals the published reproducible build, the
// contract account has no access keys, the source commit it publishes; every cited Sepolia
// transaction has a successful receipt; every cited NEAR transaction ended as claimed (the agent's
// refused requests failed, the vetoes and the key deletion succeeded). Exit code 0 only if all match.
import { readFileSync } from 'node:fs';

const data = JSON.parse(readFileSync(new URL('../web/src/evidence.json', import.meta.url), 'utf8'));
const NEAR_RPC = process.env.NEAR_RPC || 'https://rpc.testnet.fastnear.com';
const NEAR_ARCHIVAL = process.env.NEAR_ARCHIVAL_RPC || 'https://archival-rpc.testnet.fastnear.com';
const ETH_RPCS = (process.env.ETH_RPC || 'https://ethereum-sepolia-rpc.publicnode.com,https://sepolia.drpc.org').split(',');
const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function rpc(url, method, params) {
  const j = await fetch(url, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }) }).then((r) => r.json());
  if (j.error) throw new Error(j.error.cause?.name || j.error.message || JSON.stringify(j.error));
  return j.result;
}
const b58hex = (s) => { let n = 0n; for (const c of s) n = n * 58n + BigInt(B58.indexOf(c)); return n.toString(16).padStart(64, '0'); };

let pass = 0, fail = 0;
const line = (ok, what, detail) => { ok ? pass++ : fail++; console.log(`${ok ? 'PASS' : 'FAIL'}  ${what}${detail ? `  — ${detail}` : ''}`); };

// 1. The contract
const acct = await rpc(NEAR_RPC, 'query', { request_type: 'view_account', finality: 'final', account_id: data.contract });
const hash = b58hex(acct.code_hash);
line(hash === data.expected_code, 'deployed code equals the published reproducible build', hash);
const keys = await rpc(NEAR_RPC, 'query', { request_type: 'view_access_key_list', finality: 'final', account_id: data.contract });
line(keys.keys.length === 0, 'the contract account has no access keys (nobody can change the code)', `${keys.keys.length} key(s)`);
const meta = await rpc(NEAR_RPC, 'query', { request_type: 'call_function', finality: 'final', account_id: data.contract, method_name: 'contract_source_metadata', args_base64: '' })
  .then((r) => JSON.parse(Buffer.from(r.result).toString())).catch(() => null);
line(!!meta?.link, 'the contract publishes its source commit and build image', meta ? `${meta.link} · ${meta.build_info?.build_environment?.split('@')[0]}` : 'missing');

// 2. Sepolia receipts (public nodes sometimes answer null: retry, then try another RPC)
console.log(`\nSepolia transactions (${data.eth.length})`);
for (const p of data.eth) {
  let rc = null;
  for (let i = 0; i < 8 && !rc; i++) {
    rc = await rpc(ETH_RPCS[i % ETH_RPCS.length], 'eth_getTransactionReceipt', [p.hash]).catch(() => null);
    if (!rc) await sleep(400);
  }
  line(rc?.status === '0x1', p.what, rc ? `${p.hash.slice(0, 12)}… block ${parseInt(rc.blockNumber, 16)}` : `${p.hash} not found`);
}

// 3. NEAR outcomes (old transactions need an archival node)
console.log(`\nNEAR decisions (${data.near.length})`);
for (const p of data.near) {
  const r = await rpc(NEAR_ARCHIVAL, 'tx', { tx_hash: p.hash, sender_account_id: p.sender, wait_until: 'NONE' }).catch((e) => ({ error: e.message }));
  const outcome = r?.status ? (r.status.Failure ? 'failure' : 'success') : null;
  line(outcome === p.expect, p.what, outcome ? `${p.hash.slice(0, 10)}… ${outcome}` : `could not read ${p.hash} (${r?.error ?? 'no status'})`);
}

console.log(`\n${pass} of ${pass + fail} checks match the chain${fail ? '' : ' — ALL EVIDENCE CONFIRMED'}`);
process.exit(fail ? 1 : 0);
