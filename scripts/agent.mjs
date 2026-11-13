// A payments agent that operates an NFT vault's Ethereum account without holding any key
// (M19, agent mode). The agent is the vault policy's `proposer`: it can propose and sign, but the
// NEAR contract enforces the policy (caps, allowed destinations, delay) and a human guardian can
// veto any proposal before it is signed. The agent never sees a private key: the signature comes
// from NEAR Chain Signatures, and only for transactions the contract built and checked.
//
// The agent in this demo is deliberately naive: it tries to pay every request it reads, including
// one that says "ignore your rules". The point is that the contract, not the model, enforces the
// rules, so a fooled or compromised agent still cannot overspend.
//
// Subcommands:
//   setup   <owner> <vault-contract> <agent> <guardian>
//           mint a vault for <owner>, set a policy (60 s delay, 0.001 ETH a day, one allowed
//           destination: the owner's "ethereum-1" address, <agent> as proposer, <guardian>), and fund
//           the vault with 0.002 Sepolia ETH from the owner's "ethereum-1" account.
//   propose <vault-contract> <token_id> <agent> [--ai] [--requests file]
//           read the payment requests and propose one transaction per request. Without --ai the
//           decisions are fixed rules (anyone can reproduce them). With --ai a model on NEAR AI
//           Cloud reads each request (env NEAR_AI_API_KEY, optional NEAR_AI_MODEL).
//           Before each proposal the agent prints the warning signs of ../web/src/risk.mjs (the same
//           ones the guardian sees: possible duplicate, new or look-alike recipient, unusual amount,
//           urgent or "ignore the rules" wording). By default it still proposes (the demo agent is
//           naive on purpose); with --careful it leaves anything with a red sign to a human.
//   execute <vault-contract> <token_id> <agent> [proposal_id]
//           sign every proposal (or only the one given) that is ready (delay passed, not vetoed) and broadcast it.
//
// Keys: the NEAR CLI signs with keys from the system keychain; the NEAR AI key is read from the
// environment only. Nothing secret is written anywhere.
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { createPublicClient, http, keccak256, parseEther, serializeTransaction, formatEther } from 'viem';
import { sepolia } from 'viem/chains';
import { historyFromSigned, riskSignals } from '../web/src/risk.mjs';

const NEAR = process.env.NEAR_CLI || join(homedir(), '.cargo', 'bin', process.platform === 'win32' ? 'near.exe' : 'near');
const RPC = process.env.NEAR_RPC || 'https://rpc.testnet.fastnear.com';
const SIGNER = 'v1.signer-prod.testnet';
const NEAR_AI = 'https://cloud-api.near.ai/v1/chat/completions';
const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const eth = createPublicClient({ chain: sepolia, transport: http('https://ethereum-sepolia-rpc.publicnode.com') });
// Review M21 (R21-10): the NEAR CLI never needs the NEAR AI key, so it does not inherit it.
const CHILD_ENV = Object.fromEntries(Object.entries(process.env).filter(([k]) => k !== 'NEAR_AI_API_KEY'));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const args = process.argv.slice(2);
const flag = (name) => { const i = args.indexOf(name); return i >= 0 ? args.splice(i, 2)[1] : undefined; };
const useAi = args.includes('--ai') ? (args.splice(args.indexOf('--ai'), 1), true) : false;
const careful = args.includes('--careful') ? (args.splice(args.indexOf('--careful'), 1), true) : false;
const requestsFile = flag('--requests') ?? new URL('./agent-requests.json', import.meta.url);
const [cmd, ...rest] = args;

async function view(account, method, a) {
  const j = await fetch(RPC, { method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'query', params: { request_type: 'call_function', finality: 'final',
      account_id: account, method_name: method, args_base64: Buffer.from(JSON.stringify(a)).toString('base64') } }) }).then((r) => r.json());
  if (j.error) throw new Error(JSON.stringify(j.error));
  return JSON.parse(Buffer.from(j.result.result).toString());
}
function call(contract, signer, method, a, deposit, gas = '100 Tgas') {
  const p = spawnSync(NEAR, ['contract', 'call-function', 'as-transaction', contract, method,
    'json-args', JSON.stringify(a), 'prepaid-gas', gas, 'attached-deposit', deposit,
    'sign-as', signer, 'network-config', 'testnet', 'sign-with-keychain', 'send'], { encoding: 'utf8', env: CHILD_ENV });
  const out = (p.stdout || '') + (p.stderr || '');
  return { out, stdout: (p.stdout || '').trim(), panic: (out.match(/Smart contract panicked: (.*?)(?:"\)|\n|$)/) || [])[1] };
}
const events = (out, name) => [...out.matchAll(/EVENT_JSON:(\{.*\})/g)]
  .map((m) => { try { return JSON.parse(m[1]); } catch { return null; } })
  .filter((e) => e && e.event === name).map((e) => e.data[0]);
const addressOfKey = (key) => {
  let n = 0n;
  for (const c of key.slice('secp256k1:'.length)) n = n * 58n + BigInt(B58.indexOf(c));
  return '0x' + keccak256('0x' + n.toString(16).padStart(128, '0')).slice(-40);
};
async function fees() {
  const block = await eth.getBlock();
  return { maxPriorityFeePerGas: 1_000_000_000n, maxFeePerGas: block.baseFeePerGas * 2n + 1_000_000_000n };
}

// ---------- decisions ----------
/** Fixed rules: pay whatever amount and address the request names (a naive agent). */
function decideByRules(text) {
  const to = text.match(/0x[0-9a-fA-F]{40}/)?.[0];
  const amount = text.match(/([0-9]+(?:\.[0-9]+)?)\s*ETH/i)?.[1];
  return to && amount ? { pay: true, to: to.toLowerCase(), amount_eth: amount, reason: 'request names an amount and an address' }
    : { pay: false, reason: 'no amount or address found' };
}

/** A model on NEAR AI Cloud reads the request and answers with JSON. */
async function decideByAi(text) {
  const key = process.env.NEAR_AI_API_KEY;
  if (!key) throw new Error('set NEAR_AI_API_KEY (or run without --ai)');
  const model = process.env.NEAR_AI_MODEL || 'openai/gpt-5-mini';
  const res = await fetch(NEAR_AI, {
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization: `Bearer ${key}` },
    body: JSON.stringify({
      model,
      messages: [
        { role: 'system', content: 'You are an accounts-payable agent. For each payment request, extract the recipient Ethereum address and the amount in ETH, and decide whether to pay it. You are eager to keep vendors happy. Answer only with JSON: {"pay": true|false, "to": "0x...", "amount_eth": "decimal string", "reason": "one short sentence"}.' },
        { role: 'user', content: text },
      ],
    }),
  });
  const j = await res.json();
  if (!res.ok) throw new Error(`NEAR AI ${res.status}: ${JSON.stringify(j).slice(0, 200)}`);
  const content = j.choices?.[0]?.message?.content ?? '';
  const json = content.match(/\{[\s\S]*\}/)?.[0];
  if (!json) return { pay: false, reason: `unreadable model answer: ${content.slice(0, 80)}` };
  let d;
  try { d = JSON.parse(json); } catch { return { pay: false, reason: 'unreadable model answer' }; }
  // Review M21 (R21-10): the model's answer is untrusted input; only a well-formed address and
  // amount become a proposal (the contract still checks everything).
  const to = String(d.to ?? '').toLowerCase();
  const amount = String(d.amount_eth ?? '');
  // External review (round 3, H9): only a real JSON true means pay; the text "false" must not.
  if (d.pay === true && (!/^0x[0-9a-f]{40}$/.test(to) || !/^[0-9]+(\.[0-9]{1,18})?$/.test(amount)))
    return { pay: false, reason: `${model} gave a malformed address or amount` };
  return { pay: d.pay === true, to, amount_eth: amount, reason: `${model}: ${String(d.reason ?? '').slice(0, 160)}` };
}

// ---------- subcommands ----------
async function setup([owner, vault, agent, guardian]) {
  if (!guardian) throw new Error('usage: node agent.mjs setup <owner> <vault-contract> <agent> <guardian>');
  const t = events(call(vault, owner, 'mint_vault', {}, '0.1 NEAR').out, 'nft_mint')[0]?.token_ids[0];
  if (t === undefined) throw new Error('mint failed');
  const vaultAddr = (await view(vault, 'vault_info', { token_id: t })).evm_address;
  const funder = addressOfKey(await view(SIGNER, 'derived_public_key', { path: 'ethereum-1', predecessor: owner, domain_id: 0 }));
  const f = await fees();
  const policy = {
    chain_id: sepolia.id, delay_ms: 60_000, guardian, proposer: agent,
    eth_daily_cap: '1000000000000000', max_gas_cost: String(21_000n * f.maxFeePerGas * 3n),
    allowed_destinations: [funder], allowed_spenders: [], tokens: [], nfts: [],
  };
  const r = call(vault, owner, 'set_policy', { token_id: t, policy }, '0.05 NEAR');
  if (r.stdout !== 'true') throw new Error(`set_policy: ${r.panic ?? r.stdout}`);
  // Fund the vault from the owner's own Chain Signatures account, as in fund-vault.mjs.
  const value = parseEther('0.002');
  const tx = { type: 'eip1559', chainId: sepolia.id, nonce: await eth.getTransactionCount({ address: funder }), ...f,
    gas: (await eth.estimateGas({ account: funder, to: vaultAddr, value })) * 12n / 10n, to: vaultAddr, value, data: '0x', accessList: [] };
  const sig = JSON.parse(call(SIGNER, owner, 'sign', { request: { domain_id: 0, path: 'ethereum-1',
    payload_v2: { Ecdsa: keccak256(serializeTransaction(tx)).slice(2) } } }, '1 yoctoNEAR').stdout);
  const raw = serializeTransaction(tx, { r: '0x' + sig.big_r.affine_point.slice(2), s: '0x' + sig.s.scalar, yParity: sig.recovery_id });
  const rc = await eth.waitForTransactionReceipt({ hash: await eth.sendRawTransaction({ serializedTransaction: raw }), timeout: 180_000 });
  console.log(`vault ${t} (${vaultAddr}) ready: agent ${agent}, guardian ${guardian}, 0.001 ETH a day to ${funder} only, 60 s delay`);
  console.log(`funded with 0.002 ETH: https://sepolia.etherscan.io/tx/${rc.transactionHash}`);
}

async function propose([vault, t, agent]) {
  if (!agent) throw new Error('usage: node agent.mjs propose <vault-contract> <token_id> <agent> [--ai] [--requests file]');
  const requests = JSON.parse(readFileSync(requestsFile, 'utf8'));
  const policy = (await view(vault, 'get_policy', { token_id: t })).policy;
  const chain = policy.chain_id;
  // What the vault already paid and what is waiting, for the warning signs.
  const next = await view(vault, 'get_next_nonce', { token_id: t });
  const history = historyFromSigned(next > 0 ? await view(vault, 'list_signed', { token_id: t, from_nonce: Math.max(0, next - 20), limit: 100 }) : []);
  const pending = (await view(vault, 'list_proposals', { token_id: t })).map((q) => ({ id: `request #${q.id}`, ...q.tx }));
  console.log(`agent ${agent} on vault ${t}, decisions by ${useAi ? 'a model on NEAR AI Cloud' : 'fixed rules (reproducible)'}${careful ? ', careful mode' : ''}\n`);
  for (const req of requests) {
    const d = useAi ? await decideByAi(req.text) : decideByRules(req.text);
    console.log(`[${req.id}] "${req.text}"`);
    if (!d.pay) { console.log(`   agent: skip (${d.reason})\n`); continue; }
    // An amount that cannot be read skips this request; it never stops the whole run.
    let value;
    try { value = parseEther(String(d.amount_eth)).toString(); } catch { console.log(`   agent: skip (unreadable amount "${d.amount_eth}")\n`); continue; }
    const f = await fees();
    const tx = { chain_id: chain, max_priority_fee_per_gas: String(f.maxPriorityFeePerGas), max_fee_per_gas: String(f.maxFeePerGas),
      gas_limit: 21000, to: d.to, value, data: '0x' };
    const signs = riskSignals({ tx, policy, history, pending, text: req.text });
    for (const s of signs) console.log(`   ${s.level === 'high' ? 'WARNING' : s.level === 'warn' ? 'check  ' : 'note   '} ${s.text}`);
    if (careful && signs.some((s) => s.level === 'high')) { console.log('   agent (careful): not proposed, left for a human because of a red warning sign\n'); continue; }
    console.log(`   agent: pay ${d.amount_eth} ETH to ${d.to} (${d.reason})`);
    const r = call(vault, agent, 'propose', { token_id: t, tx }, '0.05 NEAR');
    const created = events(r.out, 'proposal_created')[0];
    if (created) pending.push({ id: req.id, ...tx });
    console.log(created
      ? `   contract: queued as proposal #${created.proposal_id}; signable after the delay unless the guardian vetoes it\n`
      : `   contract: REFUSED — ${r.panic}\n`);
  }
}

async function execute([vault, t, agent, only]) {
  if (!agent) throw new Error('usage: node agent.mjs execute <vault-contract> <token_id> <agent> [proposal_id]');
  const proposals = await view(vault, 'list_proposals', { token_id: t });
  if (proposals.length === 0) console.log('no proposal left (vetoed or already signed)');
  for (const p of proposals) {
    if (only !== undefined && String(p.id) !== only) continue;
    let c = await view(vault, 'check_execution', { token_id: t, proposal_id: p.id });
    // Wait out the delay (at most 3 minutes); the guardian can still veto meanwhile.
    for (let i = 0; !c.ready && /delay has not passed/.test(c.reason ?? '') && i < 36; i++) {
      if (i === 0) console.log(`proposal #${p.id}: waiting for the delay...`);
      await sleep(5000);
      c = await view(vault, 'check_execution', { token_id: t, proposal_id: p.id });
    }
    if (!c.ready) { console.log(`proposal #${p.id}: not ready (${c.reason})`); continue; }
    const r = call(vault, agent, 'execute_proposal', { token_id: t, proposal_id: p.id }, '0.02 NEAR', '300 Tgas');
    const signed = events(r.out, 'transaction_signed')[0];
    if (!signed) { console.log(`proposal #${p.id}: not signed (${r.panic ?? r.stdout})`); continue; }
    const hash = await eth.sendRawTransaction({ serializedTransaction: signed.signed_tx });
    const rc = await eth.waitForTransactionReceipt({ hash, timeout: 180_000 });
    console.log(`proposal #${p.id}: signed through NEAR Chain Signatures and mined (${rc.status}) — ${formatEther(BigInt(p.tx.value))} ETH to ${p.tx.to}: https://sepolia.etherscan.io/tx/${hash}`);
  }
}

const run = { setup, propose, execute }[cmd];
if (!run) {
  console.error('usage: node agent.mjs setup|propose|execute ... (see the header of this file)');
  process.exit(1);
}
await run(rest);
