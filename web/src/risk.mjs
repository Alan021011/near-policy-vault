// Warning signs for the guardian (M35). Plain JavaScript with no dependencies, shared by the web page
// (web/src/main.ts), the Telegram watcher (scripts/guardian-alerts.mjs) and the agent
// (scripts/agent.mjs), so all three flag the same things.
//
// These checks only ADVISE. They run off-chain, they never block a payment and they never widen
// what the vault may do: the NEAR contract alone decides what can be signed. A payment with no
// warning sign can still be wrong, and a flagged one can be fine (a monthly bill repeats); the
// guardian decides during the waiting time.
//
// riskSignals({ tx, policy, history, pending, text, now }) returns a list of
//   { level: 'high' | 'warn' | 'info', code, text }
// most serious first, where
//   tx       { to, value, data }            the payment being judged (value in wei, as a string)
//   policy   the vault's policy (get_policy().policy), optional
//   history  [{ to, value, data, ms }]      payments the vault already signed (cancellations excluded)
//   pending  [{ id, to, value, data }]      other payments waiting, or earlier requests in the same batch
//   text     the invoice or request text, when there is one (only the agent and the Try page have it)

export const DAY = 86_400_000;
const LEVELS = { high: 0, warn: 1, info: 2 };

const lower = (s) => String(s ?? '').toLowerCase();
const word = (data, i) => data.slice(10 + 64 * i, 10 + 64 * (i + 1));
const addrAt = (data, i) => '0x' + word(data, i).slice(24);
const numAt = (data, i) => BigInt('0x' + (word(data, i) || '0'));

/** What a transaction does: who receives what. Same reading as the page's describeTx. */
export function intentOf(tx) {
  const to = lower(tx.to);
  const data = lower(tx.data || '0x');
  if (data === '0x') return { kind: 'eth', asset: 'eth', recipient: to, amount: BigInt(tx.value ?? 0) };
  if (data.startsWith('0xa9059cbb')) return { kind: 'token', asset: to, recipient: addrAt(data, 0), amount: numAt(data, 1) };
  if (data.startsWith('0x095ea7b3')) return { kind: 'approve', asset: to, recipient: addrAt(data, 0), amount: numAt(data, 1) };
  if (data.startsWith('0x42842e0e')) return { kind: 'nft', asset: `${to}#${numAt(data, 2)}`, recipient: addrAt(data, 1), amount: 1n };
  if (data.startsWith('0xf242432a')) return { kind: 'nft', asset: `${to}#${numAt(data, 2)}`, recipient: addrAt(data, 1), amount: numAt(data, 3) };
  return { kind: 'call', asset: to, recipient: to, amount: BigInt(tx.value ?? 0) };
}

const same = (a, b) => a.kind === b.kind && a.asset === b.asset && a.recipient === b.recipient && a.amount === b.amount;

/** Two different addresses that look the same at a glance: same first 4 and last 4 hex characters. */
export function looksAlike(a, b) {
  a = lower(a);
  b = lower(b);
  return a !== b && a.length === 42 && b.length === 42 && a.slice(2, 6) === b.slice(2, 6) && a.slice(-4) === b.slice(-4);
}

const ago = (ms) => {
  const h = Math.max(0, Math.round(ms / 3_600_000));
  return h < 1 ? 'less than an hour ago' : h < 48 ? `${h} hour${h === 1 ? '' : 's'} ago` : `${Math.round(h / 24)} days ago`;
};
const shortA = (a) => `${a.slice(0, 6)}…${a.slice(-4)}`;
const median = (xs) => {
  const s = [...xs].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
  return s[Math.floor((s.length - 1) / 2)];
};

// Phrases that try to get around the process. Kept short and readable on purpose: a judge can see
// exactly what is matched, and a miss is a known limit, not a hidden one.
const TEXT_SIGNS = [
  { level: 'high', code: 'override', re: /\b(ignore|bypass|skip|override|disregard|forget)\b[^.]{0,40}\b(rules?|limits?|polic(y|ies)|approvals?|guardian|checks?|waiting time|instructions)\b/i, text: 'Asks to get around the rules' },
  { level: 'warn', code: 'urgency', re: /\b(urgent(ly)?|immediately|right now|asap|right away|within (the|an|one) (hour|minute))\b/i, text: 'Pushes for speed (urgent, right now)' },
  { level: 'warn', code: 'authority', re: /\b(ceo|cfo|founder|director|admin(istrator)?|security (team|update)|it department)\b/i, text: 'Claims to come from someone in charge' },
  { level: 'warn', code: 'changed-details', re: /\b(new|updated|changed|different)\s+(wallet|address|bank|account|payment details|contact)\b/i, text: 'Says the payment details or the contact changed' },
  { level: 'warn', code: 'repeat-text', re: /\b(sent again|resen[dt]|re-sent|duplicate|second copy|copy of)\b/i, text: 'Says it is a repeat of an earlier invoice' },
];

/**
 * @param {{ tx: any, policy?: any, history?: any[], pending?: any[], text?: string, now?: number }} args
 * @returns {{ level: 'high' | 'warn' | 'info', code: string, text: string }[]}
 */
export function riskSignals({ tx, policy, history = [], pending = [], text, now = Date.now() }) {
  const out = [];
  const add = (level, code, msg) => out.push({ level, code, text: msg });
  const me = intentOf(tx);
  const past = history.map((h) => ({ ...intentOf(h), ms: Number(h.ms ?? 0) }));

  // 1. Duplicates: the same payment already waiting, or already paid recently.
  const twin = pending.find((p) => same(intentOf(p), me));
  if (twin) add('high', 'duplicate-waiting', `Possible duplicate: the same payment is already waiting (${twin.id})`);
  const recent = past.filter((h) => same(h, me) && now - h.ms < 30 * DAY);
  if (recent.length) {
    const last = Math.max(...recent.map((h) => h.ms));
    add('warn', 'duplicate-paid', `Possible duplicate: the same amount went to this recipient ${ago(now - last)}${recent.length > 1 ? ` (${recent.length} times in 30 days)` : ''}`);
  }

  // 2. Recipient: not approved, a look-alike of a known address, or never paid before.
  const allowed = (policy?.allowed_destinations ?? []).map(lower);
  if (policy && me.kind === 'eth' && !allowed.includes(me.recipient)) add('high', 'not-approved', 'Not an approved recipient: the contract will refuse it');
  const known = [...new Set([...allowed, ...past.map((h) => h.recipient)])];
  const twinAddr = known.find((k) => looksAlike(k, me.recipient));
  if (twinAddr) add('high', 'look-alike', `Looks like ${shortA(twinAddr)}, which this vault knows, but it is a different address`);
  if (past.length && !past.some((h) => h.recipient === me.recipient)) add('warn', 'new-recipient', 'First payment from this vault to this address');
  if (!past.length) add('info', 'no-history', 'This vault has no earlier payments to compare with');

  // 3. Amount: far above what this vault usually sends, or a large share of the daily limit.
  const sameAsset = past.filter((h) => h.kind === me.kind && h.asset === me.asset);
  const toHim = sameAsset.filter((h) => h.recipient === me.recipient);
  const base = toHim.length >= 2 ? toHim : sameAsset.length >= 3 ? sameAsset : [];
  if (base.length && me.amount > 0n) {
    const m = median(base.map((h) => h.amount));
    if (m > 0n && me.amount > m * 10n) add('high', 'amount', `More than 10 times the usual amount (${toHim.length >= 2 ? 'to this recipient' : 'for this vault'})`);
    else if (m > 0n && me.amount > m * 3n) add('warn', 'amount', `More than 3 times the usual amount (${toHim.length >= 2 ? 'to this recipient' : 'for this vault'})`);
  }
  const cap = policy?.eth_daily_cap ? BigInt(policy.eth_daily_cap) : 0n;
  if (me.kind === 'eth' && cap > 0n) {
    if (me.amount > cap) add('high', 'over-cap', 'More than the whole daily limit: the contract will refuse it');
    else if (me.amount * 2n >= cap) add('warn', 'large-share', 'Uses half or more of the daily limit in one payment');
  }

  // 4. The words of the request (only when there is a text).
  if (text) for (const s of TEXT_SIGNS) if (s.re.test(text)) add(s.level, s.code, s.text);

  return out.sort((a, b) => LEVELS[a.level] - LEVELS[b.level]);
}

/** Decodes a signed EIP-1559 transaction (`0x02…`, as stored by the contract) into { to, value, data }. */
export function decodeSignedTx(raw) {
  const hex = lower(raw).replace(/^0x/, '');
  if (!hex.startsWith('02')) throw new Error('not an EIP-1559 transaction');
  const b = Uint8Array.from(hex.slice(2).match(/../g).map((x) => parseInt(x, 16)));
  const toHex = (u) => '0x' + Array.from(u, (x) => x.toString(16).padStart(2, '0')).join('');
  // A length of length above 6 bytes (more than 2^48 bytes) cannot be real here and would lose
  // precision as a Number: refuse it. Every item must also fit inside the input.
  const len = (at, n) => {
    if (n > 6) throw new Error('RLP length too large');
    let v = 0;
    for (let i = 0; i < n; i++) v = v * 256 + b[at + i];
    return v;
  };
  const fits = (end) => { if (end > b.length) throw new Error('RLP item runs past the end'); return end; };
  // returns [item, next position]; lists come back as arrays of byte strings or lists
  const item = (at) => {
    const p = b[at];
    if (p === undefined) throw new Error('RLP input ended early');
    if (p < 0x80) return [b.subarray(at, at + 1), at + 1];
    if (p < 0xb8) return [b.subarray(at + 1, fits(at + 1 + p - 0x80)), at + 1 + p - 0x80];
    if (p < 0xc0) { const n = p - 0xb7, l = len(at + 1, n); return [b.subarray(at + 1 + n, fits(at + 1 + n + l)), at + 1 + n + l]; }
    let start, end;
    if (p < 0xf8) { start = at + 1; end = fits(start + p - 0xc0); } else { const n = p - 0xf7; start = at + 1 + n; end = fits(start + len(at + 1, n)); }
    const list = [];
    for (let i = start; i < end;) { const [x, next] = item(i); list.push(x); i = next; }
    return [list, end];
  };
  const [f] = item(0);
  const big = (u) => (u.length ? BigInt(toHex(u)) : 0n);
  return { chain_id: Number(big(f[0])), nonce: Number(big(f[1])), to: toHex(f[5]), value: big(f[6]).toString(), data: f[7].length ? toHex(f[7]) : '0x' };
}

/**
 * Payments a vault already signed, from list_signed records: one per nonce (the last version), and
 * none for a nonce that was cancelled (its payment can never be mined).
 */
export function historyFromSigned(records) {
  const byNonce = new Map();
  for (const r of records ?? []) {
    const e = byNonce.get(r.nonce) ?? { cancelled: false, last: null };
    if (Number(r.proposal_id) > 1e18) e.cancelled = true; // CANCEL_PROPOSAL_ID
    else e.last = r;
    byNonce.set(r.nonce, e);
  }
  const out = [];
  for (const { cancelled, last } of byNonce.values()) {
    if (cancelled || !last) continue;
    try {
      out.push({ ...decodeSignedTx(last.signed_tx), ms: Number(last.signed_ms) });
    } catch {
      /* unreadable record: skipped */
    }
  }
  return out;
}
