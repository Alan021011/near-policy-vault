// Guardian Monitoring & Alerts (M23). Watches vaults a guardian protects and sends a Telegram
// message when something needs the guardian's attention: a payment waiting (with the time left to
// stop it), a looser rule change waiting, a handover started, and when a waiting payment leaves the
// queue (signed, vetoed or cancelled). Each message links to the vault page, where the guardian
// stops it with their own wallet.
//
// It only reads public contract state: it holds no NEAR key and cannot sign, veto or change
// anything. Alerts are best effort (only while this script runs); the web page is always the
// source of truth. It checks every few seconds, so it works with short waiting times.
//
// Each payment alert carries the warning signs of web/src/risk.mjs (possible duplicate, new or
// look-alike recipient, unusual amount...), the same ones the web page shows. They only advise.
//
// Usage:
//   TELEGRAM_BOT_TOKEN=... node guardian-alerts.mjs <vault-contract> --guardian <account>
//   TELEGRAM_BOT_TOKEN=... node guardian-alerts.mjs <vault-contract> --vaults 78,77
// Optional: TELEGRAM_CHAT_ID (otherwise the chat that last sent /start to the bot), --every 4
// (seconds), --test (send one test message and exit). The token is read from the environment
// only and never printed.

import { historyFromSigned, riskSignals } from '../web/src/risk.mjs';

const args = process.argv.slice(2);
const flag = (name) => { const i = args.indexOf(name); return i >= 0 ? args.splice(i, 2)[1] : undefined; };
const has = (name) => (args.includes(name) ? (args.splice(args.indexOf(name), 1), true) : false);
const guardian = flag('--guardian');
const vaultList = flag('--vaults');
const every = Number(flag('--every') ?? 4) * 1000;
const testOnly = has('--test');
const [contract] = args;

const TOKEN = process.env.TELEGRAM_BOT_TOKEN;
const RPC = process.env.NEAR_RPC || 'https://rpc.testnet.fastnear.com';
const SITE = 'https://alan021011.github.io/near-policy-vault/';
const DEFAULT_CONTRACT = 'm3.alan-vault-2026.testnet';
if (!TOKEN) { console.error('Set TELEGRAM_BOT_TOKEN (environment variable).'); process.exit(1); }
if (!contract) { console.error('usage: node guardian-alerts.mjs <vault-contract> (--guardian <account> | --vaults 78,77) [--test]'); process.exit(1); }

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const short = (a) => (a && a.length > 12 ? `${a.slice(0, 6)}…${a.slice(-4)}` : a);
const link = (id) => `${SITE}${contract === DEFAULT_CONTRACT ? '' : `?contract=${contract}`}#/vault/${id}`;
const eth = (wei) => {
  const s = BigInt(wei).toString().padStart(19, '0');
  const v = `${s.slice(0, -18)}.${s.slice(-18)}`.replace(/\.?0+$/, '');
  return `${v || '0'} ETH`;
};
const inTime = (ms) => {
  const s = Math.max(0, Math.round((ms - Date.now()) / 1000));
  return s >= 3600 ? `${Math.floor(s / 3600)} h ${Math.floor((s % 3600) / 60)} min` : s >= 60 ? `${Math.floor(s / 60)} min ${s % 60} s` : `${s} s`;
};

async function view(method, a) {
  for (let i = 1; ; i++) {
    try {
      const j = await fetch(RPC, { method: 'POST', headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'query', params: { request_type: 'call_function', finality: 'optimistic',
          account_id: contract, method_name: method, args_base64: Buffer.from(JSON.stringify(a)).toString('base64') } }) }).then((r) => r.json());
      if (j.error) throw new Error(JSON.stringify(j.error).slice(0, 200));
      return JSON.parse(Buffer.from(j.result.result).toString());
    } catch (e) {
      if (i >= 4) throw e;
      await sleep(700 * i);
    }
  }
}

/** What a queued transaction does, in plain words (same reading as the web page). */
function describe(tx) {
  const d = tx.data ?? '0x';
  const word = (i) => d.slice(10 + 64 * i, 10 + 64 * (i + 1));
  const addr = (i) => '0x' + word(i).slice(24);
  const num = (i) => BigInt('0x' + (word(i) || '0'));
  if (d === '0x') return `${eth(tx.value)} to ${short(tx.to)}`;
  if (d.startsWith('0x42842e0e') || d.startsWith('0xf242432a')) return `NFT #${num(2)} from collection ${short(tx.to)} to ${short(addr(1))}`;
  if (d.startsWith('0xa9059cbb')) return `${num(1)} units of token ${short(tx.to)} to ${short(addr(0))}`;
  if (d.startsWith('0x095ea7b3')) return `a permission for ${short(addr(0))} on token ${short(tx.to)}`;
  return `a call to ${short(tx.to)}`;
}

// ---------- Telegram ----------
let chatId = process.env.TELEGRAM_CHAT_ID;
async function tg(method, body) {
  const r = await fetch(`https://api.telegram.org/bot${TOKEN}/${method}`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
  const j = await r.json();
  if (!j.ok) throw new Error(`Telegram ${method}: ${j.description ?? r.status}`);
  return j.result;
}
async function findChat() {
  if (chatId) return chatId;
  const updates = await tg('getUpdates', {});
  const priv = updates.map((u) => u.message?.chat).filter((c) => c && c.type === 'private');
  if (!priv.length) throw new Error('No chat yet: open your bot in Telegram and send /start, then run again.');
  chatId = String(priv[priv.length - 1].id);
  return chatId;
}
async function send(text) {
  for (let i = 1; i <= 4; i++) {
    try {
      await tg('sendMessage', { chat_id: await findChat(), text, disable_web_page_preview: true });
      return true;
    } catch (e) {
      console.error(`send failed (try ${i}/4): ${e.message}`);
      await sleep(1500 * i);
    }
  }
  return false;
}

// ---------- which vaults ----------
async function guardedVaults() {
  if (vaultList) return vaultList.split(',').map((s) => s.trim()).filter(Boolean);
  const total = Number(await view('nft_total_supply', {}));
  const out = [];
  for (let from = 0; from < total; from += 50) {
    const page = await view('nft_tokens', { from_index: String(from), limit: 50 });
    for (const t of page) {
      const p = await view('get_policy', { token_id: t.token_id });
      if (p.policy.guardian === guardian) out.push(t.token_id);
    }
  }
  return out;
}

// ---------- watch ----------
const seen = new Set();
const waiting = new Map(); // `${vault}|${proposal}` -> description
const SIGN_ICON = { high: '🔴', warn: '🟠', info: '⚪' };
/** The warning signs of one waiting payment, as message lines. */
async function signsFor(id, p, proposals, policy) {
  try {
    const next = await view('get_next_nonce', { token_id: id });
    const signed = next > 0 ? await view('list_signed', { token_id: id, from_nonce: Math.max(0, next - 20), limit: 100 }) : [];
    const signs = riskSignals({ tx: p.tx, policy: policy.policy, history: historyFromSigned(signed),
      pending: proposals.filter((q) => q.id < p.id).map((q) => ({ id: `request #${q.id}`, ...q.tx })) });
    return signs.length
      ? `\nWarning signs (advice only, the contract decides):\n${signs.map((x) => `${SIGN_ICON[x.level]} ${x.text}`).join('\n')}`
      : '\nNo warning signs: a usual amount to a usual recipient.';
  } catch (e) {
    return `\n(warning signs unavailable: ${String(e.message).slice(0, 80)})`;
  }
}

async function check(id) {
  const [proposals, policy, sale] = await Promise.all([view('list_proposals', { token_id: id }), view('get_policy', { token_id: id }), view('get_sale', { token_id: id })]);
  const now = new Set();
  for (const p of proposals) {
    const key = `${id}|${p.id}`;
    now.add(key);
    if (!waiting.has(key)) {
      const what = describe(p.tx);
      waiting.set(key, what);
      const left = p.executable_after_ms > Date.now() ? `It can be sent in ${inTime(p.executable_after_ms)} unless you stop it.` : 'Its waiting time is over: it can be sent now unless you stop it.';
      await send(`⚠️ Vault #${id}: a payment is waiting\n${what} (request #${p.id})\n${left}${await signsFor(id, p, proposals, policy)}\nOpen: ${link(id)}`);
    }
  }
  for (const [key, what] of waiting) {
    if (key.startsWith(`${id}|`) && !now.has(key)) {
      waiting.delete(key);
      await send(`✓ Vault #${id}: the waiting payment ${what} left the queue (sent, stopped or cancelled).\nDetails: ${link(id)}`);
    }
  }
  if (policy.pending && !seen.has(`${id}|policy|${policy.pending.apply_after_ms}`)) {
    seen.add(`${id}|policy|${policy.pending.apply_after_ms}`);
    const np = policy.pending.policy;
    await send(`⚠️ Vault #${id}: a looser rule change is waiting\nDaily limit ${eth(np.eth_daily_cap)}, waiting time ${np.delay_ms / 1000} s, guardian ${np.guardian ?? 'none'}, agent ${np.proposer ?? 'none'}, ${np.allowed_destinations.length} approved address(es).\nIt applies in ${inTime(policy.pending.apply_after_ms)} unless you stop it.\nOpen: ${link(id)}`);
  }
  if (sale && Date.now() < sale.closes_at_ms && !seen.has(`${id}|sale|${sale.sale_id}`)) {
    seen.add(`${id}|sale|${sale.sale_id}`);
    await send(`⚠️ Vault #${id}: a handover started (#${sale.sale_id})\nThe NFT, and the account with it, can change owner when the window opens in ${inTime(sale.opens_at_ms)}, unless you stop it.\nOpen: ${link(id)}`);
  }
}

if (testOnly) {
  const ok = await send(`✅ Policy Vault guardian alerts are connected.\nYou will get a message here when a vault you guard has a payment, a rule change or a handover waiting.\nThis bot only notifies: it holds no key and cannot act for you.`);
  console.log(ok ? 'test message sent' : 'test message NOT sent');
  process.exit(ok ? 0 : 1);
}

let vaults = await guardedVaults();
console.log(`watching ${vaults.length} vault(s) on ${contract}: ${vaults.join(', ') || '(none)'} — every ${every / 1000} s`);
await send(`👀 Watching ${vaults.length} vault(s) on ${contract}: ${vaults.map((v) => `#${v}`).join(', ') || 'none'}.`);
let lastScan = Date.now();
for (;;) {
  for (const id of vaults) {
    try {
      await check(id);
    } catch (e) {
      console.error(`vault ${id}: ${e.message}`);
    }
  }
  if (!vaultList && Date.now() - lastScan > 120_000) {
    vaults = await guardedVaults().catch(() => vaults);
    lastScan = Date.now();
  }
  await sleep(every);
}
