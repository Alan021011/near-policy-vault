// Attacks written by someone else (M41, part 3): invoices from another AI or a person who did not see
// the warning signs. Each one is asked, read-only, to the live contract on benchmark vault 79, and the
// warning signs are run on what gets through, exactly as in run.mjs.
//
//   node bench/external.mjs <attacks.json> [--source "who wrote them"] [--save]
//
// attacks.json: a JSON array of { "text": "...", "technique": "...", "to": "0x...", "amount_eth": "..." }.
// Without --save it only prints; with --save it writes bench/external-attacks.json (the input, with its
// source) and bench/results-external.md. No key, no wallet.
import { readFileSync, writeFileSync } from 'node:fs';
import { parseEther, formatEther } from 'viem';
import { riskSignals } from '../../web/src/risk.mjs';

const args = process.argv.slice(2);
const flag = (n) => { const i = args.indexOf(n); return i >= 0 ? args.splice(i, 2)[1] : undefined; };
const source = flag('--source') ?? 'unknown';
const save = args.includes('--save') ? (args.splice(args.indexOf('--save'), 1), true) : false;
const [file] = args;
if (!file) { console.error('usage: node bench/external.mjs <attacks.json> [--source "..."] [--save]'); process.exit(1); }

const ds = JSON.parse(readFileSync(new URL('./invoices.json', import.meta.url), 'utf8'));
let raw = readFileSync(file, 'utf8').trim();
raw = raw.replace(/^```(?:json)?\s*/i, '').replace(/```\s*$/, ''); // tolerate a pasted code fence
const attacks = JSON.parse(raw);
if (!Array.isArray(attacks) || !attacks.length) throw new Error('the file must be a JSON array of invoices');

const RPCS = ['https://rpc.testnet.fastnear.com', 'https://test.rpc.fastnear.com', 'https://near-testnet.lava.build'];
let turn = 0;
async function view(method, a) {
  for (let i = 1; ; i++) {
    try {
      const j = await fetch(RPCS[turn++ % RPCS.length], { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'query',
        params: { request_type: 'call_function', finality: 'final', account_id: ds.vault.contract, method_name: method, args_base64: Buffer.from(JSON.stringify(a)).toString('base64') } }) }).then((r) => r.json());
      if (j.error) throw new Error(JSON.stringify(j.error).slice(0, 200));
      return JSON.parse(Buffer.from(j.result.result).toString());
    } catch (e) {
      if (i >= 10) throw e;
      await new Promise((r) => setTimeout(r, 800 * i));
    }
  }
}
// The same naive reading as the agent without AI: the address and amount the text names.
const naive = (text) => ({ to: text.match(/0x[0-9a-fA-F]{40}/)?.[0]?.toLowerCase(), amount: text.match(/([0-9]+(?:\.[0-9]+)?)\s*ETH/i)?.[1] });

const live = await view('get_policy', { token_id: ds.vault.token_id });
const nonce = await view('get_next_nonce', { token_id: ds.vault.token_id });
const history = ds.history.map((h) => ({ to: h.to, value: parseEther(h.eth).toString(), data: '0x', ms: h.ms }));
const rows = [];
for (const [i, a] of attacks.entries()) {
  const d = naive(String(a.text ?? ''));
  if (!d.to || !d.amount) { rows.push({ i, a, skipped: 'no address or amount the agent can read' }); continue; }
  const tx = { chain_id: ds.expected_policy.chain_id, nonce, ...ds.fees, to: d.to, value: parseEther(d.amount).toString(), data: '0x' };
  const c = await view('check_transaction', { token_id: ds.vault.token_id, tx });
  const signs = riskSignals({ tx, policy: live.policy, history, pending: [], text: a.text, now: ds.now_ms });
  rows.push({ i, a, tx, wei: BigInt(tx.value), allowed: c.allowed, reason: c.reason, signs, red: signs.some((s) => s.level === 'high'), flagged: signs.some((s) => s.level !== 'info') });
}

const ok = rows.filter((r) => !r.skipped);
const through = ok.filter((r) => r.allowed);
const sum = (xs) => xs.reduce((s, r) => s + r.wei, 0n);
const eth = (w) => `${Number(formatEther(w)).toFixed(5)} ETH`;
const md = [];
md.push(`# Attacks written by someone else: ${source}`);
md.push('');
md.push(`${attacks.length} invoices; ${ok.length} name an address and an amount the agent can read. Checked read-only by the live contract \`${ds.vault.contract}\` (vault ${ds.vault.token_id}); the warning signs are the same as in the main benchmark (the author of these attacks did not see them).`);
md.push('');
md.push('| | Count | ETH |');
md.push('|---|---|---|');
md.push(`| Paid by a naive agent with no protection | ${ok.length} | ${eth(sum(ok))} |`);
md.push(`| Blocked by the contract | ${ok.length - through.length} | ${eth(sum(ok.filter((r) => !r.allowed)))} |`);
md.push(`| Through the contract (inside the rules) | ${through.length} | ${eth(sum(through))} |`);
md.push(`| …of those, with a red sign / amber only / no sign | ${through.filter((r) => r.red).length} / ${through.filter((r) => r.flagged && !r.red).length} / ${through.filter((r) => !r.flagged).length} | ${eth(sum(through.filter((r) => !r.flagged)))} with no sign |`);
md.push('');
md.push('| # | Technique | Contract | Signs |');
md.push('|---|---|---|---|');
for (const r of rows) md.push(`| ${r.i + 1} | ${String(r.a.technique ?? '').replace(/\|/g, '/')} | ${r.skipped ? `skipped: ${r.skipped}` : r.allowed ? 'allowed' : `refused: ${r.reason}`} | ${r.skipped ? '' : r.signs.filter((s) => s.level !== 'info').map((s) => `${s.level}:${s.code}`).join(', ') || 'none'} |`);
console.log(md.join('\n'));
if (save) {
  writeFileSync(new URL('./external-attacks.json', import.meta.url), JSON.stringify({ source, attacks }, null, 2) + '\n');
  writeFileSync(new URL('./results-external.md', import.meta.url), md.join('\n') + '\n');
  console.log('\nsaved bench/external-attacks.json and bench/results-external.md');
}
