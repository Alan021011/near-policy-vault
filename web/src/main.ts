import './style.css';
import { formatEther, parseEther } from 'viem';
import { audit, type AuditResult } from './audit';
import { AGENT_RUNS, human, type AgentStep } from './agent-run';
import {
  CONTRACT, DEFAULT_CHAIN, EXPLORER, NEAR_EXPLORER, OVERRIDDEN, accountId, call, connect, disconnect, eth, events,
  nearToYocto, onAccountChange, view, yoctoToNear,
} from './near';

const app = document.getElementById('app')!;
const ONE_YOCTO = '1';
const esc = (s: unknown) =>
  String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!);
const short = (s: string, a = 6, b = 4) => (s && s.length > a + b + 1 ? `${s.slice(0, a)}…${s.slice(-b)}` : s);
const ethFmt = (wei: string | bigint) => `${Number(formatEther(BigInt(wei))).toLocaleString('en', { maximumFractionDigits: 6 })} ETH`;
const inTime = (ms: number) => {
  const s = Math.max(0, Math.round((ms - Date.now()) / 1000));
  if (s === 0) return 'now';
  const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60), r = s % 60;
  return h ? `${h} h ${m} min` : m ? `${m} min ${r} s` : `${r} s`;
};
const txLink = (chain: number, h: string) => `<a class="mono" target="_blank" rel="noreferrer" href="${EXPLORER[chain]}/tx/${esc(h)}">${esc(short(h, 10, 6))}</a>`;
const addrLink = (chain: number, a: string) => `<a class="mono" target="_blank" rel="noreferrer" href="${EXPLORER[chain]}/address/${esc(a)}">${esc(a)}</a>`;

// ---------- toast ----------
const toastEl = document.getElementById('toast')!;
let toastTimer = 0;
/** Shows a message at the bottom. Refusals stay until clicked, with the contract's own words below. */
function toast(msg: string, kind: 'ok' | 'bad' | '' = '', raw = '') {
  toastEl.innerHTML = `${esc(msg)}${raw && raw !== msg ? `<div class="raw">${esc(raw)}</div>` : ''}${kind === 'bad' ? '<div class="raw">Click to close</div>' : ''}`;
  toastEl.className = `toast ${kind}`;
  toastEl.hidden = false;
  clearTimeout(toastTimer);
  if (kind !== 'bad') toastTimer = window.setTimeout(() => (toastEl.hidden = true), 6000);
}
toastEl.onclick = () => (toastEl.hidden = true);

/** Runs a contract call from the wallet, reports the outcome in plain words and re-renders. */
async function act(label: string, f: () => Promise<{ failure?: string; value?: any; logs: string[] } | void>, after?: (r: any) => void) {
  toast(`${label}: confirm in your wallet…`);
  try {
    const r = await f();
    if (r && r.failure) toast(`${label}: ${human(r.failure)}`, 'bad', r.failure);
    else {
      toast(`${label}: done`, 'ok');
      await after?.(r);
    }
  } catch (e: any) {
    const m = String(e?.message ?? e);
    toast(`${label} failed: ${human(m)}`, 'bad', m);
  }
  route();
}

// Live countdowns: every element with data-until shows the time left and the page reloads its
// data once when a wait ends, so "Approve & send" turns on by itself.
setInterval(() => {
  let ended = false;
  document.querySelectorAll<HTMLElement>('[data-until]').forEach((el) => {
    const until = Number(el.dataset.until);
    el.dataset.armed ??= Date.now() < until ? '1' : '0'; // only a wait seen running triggers a reload
    el.textContent = Date.now() >= until ? 'waiting time over, updating…' : `${el.dataset.prefix ?? ''}${inTime(until)}${el.dataset.suffix ?? ''}`;
    if (Date.now() >= until && el.dataset.armed === '1') {
      el.dataset.armed = '0';
      ended = true;
    }
  });
  if (ended) setTimeout(route, 1500);
}, 1000);

// ---------- wallet button ----------
const connectBtn = document.getElementById('connect') as HTMLButtonElement;
const accountEl = document.getElementById('account')!;
function renderAccount() {
  accountEl.textContent = accountId ?? '';
  connectBtn.textContent = accountId ? 'Disconnect' : 'Connect wallet';
  connectBtn.className = accountId ? 'btn' : 'btn primary';
}
connectBtn.onclick = () => (accountId ? disconnect() : connect()).catch((e) => toast(String(e?.message ?? e), 'bad'));
onAccountChange(() => {
  renderAccount();
  route();
});
renderAccount();
// Review M12 (R12-1): everything that can come from the URL is escaped.
document.getElementById('contract-link')!.innerHTML = `Contract <a class="mono" target="_blank" rel="noreferrer" href="${NEAR_EXPLORER}/address/${encodeURIComponent(CONTRACT)}">${esc(CONTRACT)}</a>`;
if (OVERRIDDEN) {
  const warn = document.createElement('div');
  warn.className = 'override';
  warn.textContent = `This page was opened with a custom contract or RPC (${CONTRACT}). Its audit never says SAFE. Open https://alan021011.github.io/near-policy-vault/ without parameters.`;
  document.body.prepend(warn);
}

// ---------- router ----------
window.addEventListener('hashchange', route);
let renderId = 0;
function route() {
  const id = ++renderId;
  const m = location.hash.match(/^#\/vault\/(\d+)/);
  (m ? vaultPage(m[1], id) : homePage(id)).catch((e) => {
    if (id === renderId) app.innerHTML = `<div class="card"><div class="body">Could not load: ${esc(e?.message ?? e)}</div></div>`;
  });
}

// ---------- home ----------
const DEMO_VAULTS = [
  { id: 78, title: 'An AI payments agent', badge: 'agent + guardian', tone: 'ok', text: 'An agent reads invoices and pays them. See what the rules blocked and what the guardian stopped.' },
  { id: 77, title: 'An Ethereum NFT', badge: '1 NFT a day', tone: 'warn', text: 'The vault holds NFTs and can send at most one a day, only to an approved address.' },
  { id: 75, title: 'A vault handed over', badge: 'new owner', tone: '', text: 'Checked in the browser, then bought by another account: the seller was paid in the same step.' },
];
async function vaultSummary(t: any) {
  const id = t.token_id;
  const [policy, sale, inflight, info] = await Promise.all([
    view('get_policy', { token_id: id }), view('get_sale', { token_id: id }), view('get_inflight', { token_id: id }), view('vault_info', { token_id: id }),
  ]);
  const pills = [
    inflight ? '<span class="badge warn">signing…</span>' : '',
    sale && Date.now() < sale.closes_at_ms ? '<span class="badge warn">handover open</span>' : '',
    policy.has_policy ? '<span class="badge ok">rules active</span>' : '<span class="badge">no rules yet</span>',
  ].join(' ');
  return `<a class="card vault-card" href="#/vault/${esc(id)}">
    <div class="row"><h2>Vault #${esc(id)}</h2><span class="spacer"></span></div>
    <div class="mono muted" style="margin:6px 0">${esc(short(info.evm_address ?? 'address not resolved', 10, 8))}</div>
    <div class="row">${pills}</div>
    <div class="faint" style="margin-top:6px;font-size:12px">${policy.policy.guardian ? `guardian: ${esc(policy.policy.guardian)}` : 'no guardian'}</div>
  </a>`;
}

async function homePage(id: number) {
  app.innerHTML = `
    <section class="hero">
      <h1>Give your AI agent an Ethereum account — without giving it the keys.</h1>
      <p class="lead">Every payment follows rules you set: a daily limit, approved recipients, a waiting time, and a person who can say no. The account lives in an NFT, so you can hand it over.</p>
      <div class="row" style="margin-top:20px">
        <a class="btn primary big" href="#/vault/78">See the live agent vault →</a>
        ${accountId ? '' : '<button class="btn big" data-home="connect">Connect wallet</button>'}
      </div>
    </section>
    <div class="features">
      <div class="feature"><div class="ico">☰</div><h3>Rules</h3><p>A NEAR contract refuses any payment over the daily limit or to an address you did not approve.</p></div>
      <div class="feature"><div class="ico">◷</div><h3>Waiting time</h3><p>Nothing is paid instantly. Every payment waits before it is signed, so there is time to react.</p></div>
      <div class="feature"><div class="ico">✋</div><h3>Human veto</h3><p>A guardian can stop any payment while it waits. The agent can never change the rules.</p></div>
    </div>
    <p class="faint small-note">No private key for the vault's Ethereum account exists: NEAR Chain Signatures signs only what the contract checked. Testnet and test funds only.</p>
    <div class="section-head"><h2>Live demo vaults</h2><span class="spacer"></span>
      <form id="open" class="row"><input id="open-id" class="mono" style="max-width:110px" placeholder="vault #" inputmode="numeric" aria-label="Vault number" /><button class="btn small">Open</button></form></div>
    <div class="grid demo-grid">
      ${DEMO_VAULTS.map((v) => `<a class="card vault-card" href="#/vault/${v.id}">
        <div class="row"><h2>Vault #${v.id}</h2><span class="spacer"></span><span class="badge ${v.tone}">${v.badge}</span></div>
        <div class="vc-title">${v.title}</div><p class="muted">${v.text}</p></a>`).join('')}
    </div>
    <div id="mine"></div>
    <div id="guarded"></div>`;
  app.querySelector('[data-home="connect"]')?.addEventListener('click', () => connect().catch((e) => toast(String(e?.message ?? e), 'bad')));
  (document.getElementById('open') as HTMLFormElement).onsubmit = (e) => {
    e.preventDefault();
    const v = (document.getElementById('open-id') as HTMLInputElement).value.trim();
    if (/^\d+$/.test(v)) location.hash = `#/vault/${v}`;
  };
  const mine = document.getElementById('mine')!;
  if (!accountId) {
    mine.innerHTML = `<div class="card"><header><h2>My vaults</h2></header><div class="body muted">Connect a NEAR testnet wallet to create a vault, set its rules and name an agent and a guardian.</div></div>`;
    return;
  }
  mine.innerHTML = `<div class="card"><header><h2>My vaults</h2><span class="spacer"></span>
    <button class="btn primary" id="mint" title="0.1 NEAR deposit; the unused part is refunded">Create a vault</button></header>
    <div class="body"><div class="grid" id="mine-grid"><span class="faint">Loading…</span></div></div></div>`;
  document.getElementById('mint')!.onclick = () =>
    act('Create vault', () => call('mint_vault', {}, nearToYocto('0.1'), 100n), (r) => {
      const t = r?.value?.token_id;
      if (t !== undefined) location.hash = `#/vault/${t}`;
    });
  const tokens = await view<any[]>('nft_tokens_for_owner', { account_id: accountId, from_index: '0', limit: 50 });
  if (id !== renderId) return;
  const cards = await Promise.all(tokens.map(vaultSummary));
  if (id !== renderId) return;
  document.getElementById('mine-grid')!.innerHTML = cards.join('') || '<span class="empty">You own no vault yet. Create one, then set its rules.</span>';

  const guarded = document.getElementById('guarded')!;
  guarded.innerHTML = `<div class="card"><header><h2>Vaults I guard</h2><span class="spacer"></span></header>
    <div class="body"><div class="grid" id="guard-grid"><span class="faint">Looking for vaults where you are the guardian…</span></div></div></div>`;
  const scan = async () => {
    const grid = document.getElementById('guard-grid')!;
    const total = Number(await view<string>('nft_total_supply'));
    const found: any[] = [];
    for (let from = 0; from < total; from += 50) {
      const page = await view<any[]>('nft_tokens', { from_index: String(from), limit: 50 });
      for (let i = 0; i < page.length; i += 6) {
        const batch = page.slice(i, i + 6);
        const policies = await Promise.all(batch.map((t) => view('get_policy', { token_id: t.token_id })));
        batch.forEach((t, k) => policies[k].policy.guardian === accountId && found.push(t));
      }
    }
    if (id !== renderId) return;
    grid.innerHTML = (await Promise.all(found.map(vaultSummary))).join('') || '<span class="empty">You guard no vault.</span>';
  };
  scan().catch(() => {});
}

// ---------- vault page ----------
interface VaultData {
  id: string; owner: string; info: any; chain: number; policy: any; proposals: any[]; checks: Record<number, any>;
  signed: any[]; sale: any; inflight: any; uncertain: any[]; next: number; mined: number; balance: bigint; transfer: any;
}

async function loadVault(id: string): Promise<VaultData> {
  const [token, info, chainRaw, policy, proposals, sale, inflight, uncertain, next, transfer] = await Promise.all([
    view('nft_token', { token_id: id }), view('vault_info', { token_id: id }), view('get_vault_chain', { token_id: id }),
    view('get_policy', { token_id: id }), view<any[]>('list_proposals', { token_id: id }), view('get_sale', { token_id: id }),
    view('get_inflight', { token_id: id }), view<any[]>('get_uncertain', { token_id: id }), view<number>('get_next_nonce', { token_id: id }),
    view('vault_transfer_info', { token_id: id }),
  ]);
  if (!token) throw new Error(`vault ${id} does not exist`);
  const chain = chainRaw ?? (policy.has_policy ? policy.policy.chain_id : DEFAULT_CHAIN);
  const checksArr = await Promise.all(proposals.map((p) => view('check_execution', { token_id: id, proposal_id: p.id })));
  const checks: Record<number, any> = {};
  proposals.forEach((p, i) => (checks[p.id] = checksArr[i]));
  const signed = next > 0 ? await view<any[]>('list_signed', { token_id: id, from_nonce: Math.max(0, next - 20), limit: 100 }) : [];
  let mined = 0;
  let balance = 0n;
  if (info.evm_address && EXPLORER[chain]) {
    [mined, balance] = await Promise.all([
      eth<string>(chain, 'eth_getTransactionCount', [info.evm_address, 'latest']).then((x) => Number(BigInt(x))),
      eth<string>(chain, 'eth_getBalance', [info.evm_address, 'latest']).then((x) => BigInt(x)),
    ]);
  }
  return { id, owner: token.owner_id, info, chain, policy, proposals, checks, signed, sale, inflight, uncertain, next, mined, balance, transfer };
}

async function feeFields(chain: number) {
  const block = await eth<any>(chain, 'eth_getBlockByNumber', ['latest', false]);
  const prio = 1_000_000_000n;
  return { max_priority_fee_per_gas: prio.toString(), max_fee_per_gas: (BigInt(block.baseFeePerGas) * 2n + prio).toString() };
}

const CHAIN_NAME: Record<number, string> = { 11155111: 'Sepolia (test Ethereum network)' };
const chainName = (c: number) => CHAIN_NAME[c] ?? `chain ${c}`;
const shortAddr = (a: string) => esc(short(a, 6, 4));

function vaultCard(d: VaultData, isOwner: boolean, isGuardian: boolean) {
  const p = d.policy.policy;
  const pend = d.policy.pending;
  const spent = BigInt(d.policy.spend?.eth?.spent ?? '0');
  const cap = d.policy.has_policy ? BigInt(p.eth_daily_cap) : 0n;
  const pct = cap > 0n ? Math.min(100, Number((spent * 1000n) / cap) / 10) : 0;
  const rule = (ok: boolean, text: string) => `<li class="${ok ? 'on' : 'off'}">${text}</li>`;
  const rules = d.policy.has_policy
    ? `<ul class="rules">
        ${rule(true, p.allowed_destinations.length ? `Can only pay ${p.allowed_destinations.map((a: string) => `<span class="mono">${shortAddr(a)}</span>`).join(', ')}` : 'Cannot pay any address yet (no approved recipient)')}
        ${rule(true, `Spends at most <b>${ethFmt(p.eth_daily_cap)}</b> a day, network fees included`)}
        ${rule(p.delay_ms > 0, p.delay_ms > 0 ? `Waits <b>${p.delay_ms / 1000} s</b> before paying` : 'Pays without a waiting time')}
        ${rule(!!p.guardian, p.guardian ? `<b>${esc(p.guardian)}</b> can stop any payment` : 'No guardian: nobody can stop a payment or a handover')}
        ${p.proposer ? rule(true, `Agent <b>${esc(p.proposer)}</b> can request and send payments, never change these rules`) : ''}
        ${p.tokens.length ? rule(true, `${p.tokens.length} token(s) allowed, each with its own daily limit`) : ''}
        ${(p.nfts ?? []).length ? rule(true, (p.nfts as any[]).map((n) => `At most ${esc(n.daily_count)} NFT(s) a day from <span class="mono">${shortAddr(n.contract)}</span>`).join('; ')) : ''}
      </ul>`
    : `<p class="muted">This vault has no rules yet, so it cannot pay anything. ${isOwner ? 'Set its rules below; the first rules apply at once.' : ''}</p>`;
  const pending = pend
    ? `<div class="notice" style="margin-top:12px"><b>Rule change waiting</b>, applies ${Date.now() >= pend.apply_after_ms ? 'now (anyone can apply it)' : `in <span data-until="${pend.apply_after_ms}">${inTime(pend.apply_after_ms)}</span>`}:
        approved recipients ${pend.policy.allowed_destinations.map(shortAddr).join(', ') || 'none'}; waiting time ${pend.policy.delay_ms / 1000} s; guardian ${esc(pend.policy.guardian ?? 'none')}; daily limit ${ethFmt(pend.policy.eth_daily_cap)}${pend.policy.proposer ? `; agent ${esc(pend.policy.proposer)}` : ''}.
        <div class="row" style="margin-top:8px">
          ${Date.now() >= pend.apply_after_ms ? '<button class="btn small" data-action="apply-policy">Apply</button>' : ''}
          ${isOwner ? '<button class="btn small" data-action="cancel-policy">Cancel change</button>' : ''}
          ${isGuardian ? '<button class="btn danger" data-action="veto-policy">Stop this rule change</button>' : ''}
        </div></div>`
    : '';
  const technical = `<details class="tech"><summary>Technical details</summary><div class="kv" style="margin-top:10px">
      <div><div class="label">Owner</div><div class="v">${esc(d.owner)}</div></div>
      <div><div class="label">Network</div><div class="v">${esc(chainName(d.chain))} · chain id ${esc(d.chain)}</div></div>
      <div><div class="label">Derivation path</div><div class="v">${esc(d.info.path)} <span class="faint">from ${esc(CONTRACT)}</span></div></div>
      <div><div class="label">Next nonce · account nonce</div><div class="v">${d.next} · ${d.mined}</div></div>
      <div><div class="label">Ownership changes</div><div class="v">${esc(d.transfer?.count ?? 0)}</div></div>
      ${d.policy.has_policy ? `
      <div><div class="label">Max network fee per payment</div><div class="v">${ethFmt(p.max_gas_cost)}</div></div>
      <div><div class="label">Approved recipients</div><div class="v">${p.allowed_destinations.map(esc).join('<br>') || 'none'}</div></div>
      <div><div class="label">Apps allowed to use tokens</div><div class="v">${p.allowed_spenders.map(esc).join('<br>') || 'none'}</div></div>
      <div><div class="label">Tokens</div><div class="v">${p.tokens.map((t: any) => `${esc(short(t.contract, 8, 6))}: ${esc(t.daily_cap)}/day, approve ≤ ${esc(t.max_approval)}`).join('<br>') || 'none'}</div></div>
      <div><div class="label">NFT collections</div><div class="v">${(p.nfts ?? []).map((t: any) => `${esc(short(t.contract, 8, 6))}: ${esc(t.daily_count)}/day`).join('<br>') || 'none'}</div></div>` : ''}
    </div></details>`;
  const draft = d.policy.has_policy ? p : { chain_id: DEFAULT_CHAIN, delay_ms: 60000, guardian: null, eth_daily_cap: parseEther('0.01').toString(), max_gas_cost: parseEther('0.002').toString(), allowed_destinations: [], allowed_spenders: [], tokens: [] };
  const form = isOwner
    ? `<details style="margin-top:12px"><summary class="btn small" style="display:inline-block">${d.policy.has_policy ? 'Change the rules' : 'Set the rules'}</summary>
        <p class="faint">Stricter rules apply at once. Looser rules (or a new agent) wait the current waiting time, and the guardian can stop them. Replacing the guardian waits max(2 × waiting time, 3 days).</p>
        <form id="policy-form" class="form">
          <label><div class="label">Waiting time (seconds)</div><input name="delay" value="${draft.delay_ms / 1000}" /></label>
          <label><div class="label">Guardian (NEAR account)</div><input name="guardian" value="${esc(draft.guardian ?? '')}" placeholder="none" /></label>
          <label><div class="label">Daily limit (ETH)</div><input name="cap" value="${formatEther(BigInt(draft.eth_daily_cap))}" /></label>
          <label><div class="label">Max network fee per payment (ETH)</div><input name="gas" value="${formatEther(BigInt(draft.max_gas_cost))}" /></label>
          <label class="full"><div class="label">Approved recipients (Ethereum addresses, comma separated)</div><input name="dest" value="${esc(draft.allowed_destinations.join(', '))}" /></label>
          <label class="full"><div class="label">Agent (NEAR account that may request and send payments, never change the rules)</div><input name="proposer" value="${esc(draft.proposer ?? '')}" placeholder="none" /></label>
          <details class="full"><summary class="faint">Tokens, NFTs and apps (advanced)</summary>
            <label><div class="label">Apps allowed to use tokens (comma separated)</div><input name="spenders" value="${esc(draft.allowed_spenders.join(', '))}" /></label>
            <label><div class="label">Tokens (JSON: [{"contract","daily_cap","max_approval"}])</div><textarea name="tokens" rows="2">${esc(JSON.stringify(draft.tokens))}</textarea></label>
            <label><div class="label">NFT collections (JSON: [{"contract","daily_count"}])</div><textarea name="nfts" rows="2">${esc(JSON.stringify(draft.nfts ?? []))}</textarea></label>
          </details>
          <div class="full"><button class="btn primary">Save rules</button> <span class="faint">0.05 NEAR deposit, the unused part is refunded</span></div>
        </form></details>`
    : '';
  return `<div class="card vault-main"><div class="body">
      <div class="vm-top">
        <div><div class="label">Balance</div><div class="balance">${ethFmt(d.balance)}</div><div class="faint">on ${esc(chainName(d.chain))}</div></div>
        <div class="addr">${d.info.evm_address ? `<span class="mono">${shortAddr(d.info.evm_address)}</span>
          <button class="btn small" data-action="copy" data-text="${esc(d.info.evm_address)}">Copy address</button>
          <a class="btn small" target="_blank" rel="noreferrer" href="${EXPLORER[d.chain]}/address/${esc(d.info.evm_address)}">Explorer ↗</a>` : 'address not resolved'}</div>
      </div>
      ${d.policy.has_policy ? `<div class="spent"><div class="row"><span>Spent today <b>${ethFmt(spent)}</b> of ${ethFmt(cap)} <span class="faint">(network fees included)</span></span><span class="spacer"></span><span class="mono faint">${pct}%</span></div>
        <div class="bar"><div style="width:${pct}%"></div></div></div>` : ''}
      <div class="label" style="margin-top:16px">Rules</div>
      ${rules}${pending}${technical}${form}
    </div></div>`;
}

function queueSection(d: VaultData, isOwner: boolean, isGuardian: boolean, frozen: boolean, isAgent = false) {
  const canSign = isOwner || isAgent;
  const rows = d.proposals.map((p) => {
    const c = d.checks[p.id];
    const tx = p.tx;
    const kind = !tx.data || tx.data === '0x' ? 'eth' : tx.data.startsWith('0x42842e0e') || tx.data.startsWith('0xf242432a') ? 'NFT transfer' : 'Token payment';
    const what = kind === 'eth' ? `<b>${ethFmt(tx.value)}</b> to <span class="mono">${shortAddr(tx.to)}</span>` : `${kind} on <span class="mono">${shortAddr(tx.to)}</span>`;
    const waiting = Date.now() < p.executable_after_ms;
    const status = c?.ready ? '<span class="badge ok">ready to send</span>'
      : waiting ? `<span class="badge warn">◷ <span data-until="${p.executable_after_ms}" data-prefix="pays in ">pays in ${inTime(p.executable_after_ms)}</span>${isGuardian ? ' unless you stop it' : ''}</span>`
      : `<span class="badge bad">blocked</span> <span class="muted">${esc(human(c?.reason ?? ''))}</span>`;
    return `<div class="pay-row">
      <div class="pay-what"><div>Payment request #${esc(p.id)}: ${what}</div><div style="margin-top:6px">${status}</div></div>
      <div class="pay-actions">
        ${isGuardian ? `<button class="btn danger big" data-action="veto-proposal" data-id="${p.id}">■ Stop this payment</button>` : ''}
        ${canSign ? `<button class="btn primary" data-action="execute" data-id="${p.id}" ${c?.ready ? '' : 'disabled'}>Approve &amp; send</button>` : ''}
        ${isOwner ? `<button class="btn small" data-action="cancel-proposal" data-id="${p.id}">Cancel</button>` : ''}
      </div></div>`;
  }).join('');
  const form = canSign && d.policy.has_policy
    ? `<details style="margin-top:12px"><summary class="btn small" style="display:inline-block">New payment request</summary>
        <form id="propose-form" class="form">
          <label><div class="label">Pay to (Ethereum address)</div><input name="to" placeholder="0x…" value="${esc(d.policy.policy.allowed_destinations[0] ?? '')}" /></label>
          <label><div class="label">Amount (ETH)</div><input name="value" value="0.0001" /></label>
          <details class="full"><summary class="faint">Send a token or an NFT instead (advanced)</summary>
            <label><div class="label">ERC-20 token contract</div><input name="token" placeholder="0x… (leave empty for ETH)" /></label>
            <label><div class="label">Token amount (base units)</div><input name="amount" placeholder="e.g. 60000000000000" /></label>
            <label><div class="label">NFT collection (ERC-721 or ERC-1155)</div><input name="nft" placeholder="0x…" /></label>
            <label><div class="label">NFT id · ERC-1155 amount (empty = ERC-721)</div><div class="row"><input name="nft_id" placeholder="id" style="max-width:45%" /><input name="nft_amount" placeholder="amount" style="max-width:45%" /></div></label>
          </details>
          <div class="full"><button class="btn primary">Request payment</button>
          <span class="faint">The rules are checked now and again before sending. 0.05 NEAR deposit, refunded when it ends.</span></div>
        </form></details>`
    : '';
  return `<div class="card"><header><h2>Waiting payments</h2>${frozen ? '<span class="badge warn">paused by the handover</span>' : ''}</header><div class="body">
    ${rows || '<div class="empty">Nothing is waiting.</div>'}
    ${form}</div></div>`;
}

/** The recorded runs of the payments agent, each line linked to its NEAR and Sepolia transactions. */
function agentSection(d: VaultData) {
  const runs = AGENT_RUNS[d.id];
  if (!runs) return '';
  const chip = (o: AgentStep['outcome']) => ({
    paid: '<span class="chip paid">Paid</span>',
    blocked: '<span class="chip blocked">Blocked by rules</span>',
    stopped: '<span class="chip stopped">Stopped by guardian</span>',
    declined: '<span class="chip declined">Model declined</span>',
  })[o];
  const nearTx = (h: string, label: string) => `<a target="_blank" rel="noreferrer" href="${NEAR_EXPLORER}/txns/${h}">${label} ↗</a>`;
  return `<div class="card"><header><h2>What the agent tried — and what stopped it</h2><span class="spacer"></span>
      <a href="https://github.com/Alan021011/near-policy-vault/actions/workflows/tests.yml" target="_blank" rel="noreferrer">49 attacks blocked in CI →</a></header>
    <div class="body">
      <p class="muted">A payments agent (<span class="mono">scripts/agent.mjs</span>) reads four invoices and tries to pay them. It holds no key: the contract checks every request, and a person can stop what is inside the rules but wrong. Recorded runs on testnet; every line links to its transaction.</p>
      ${runs.map((r) => `<h3 class="run-title">${esc(r.title)} <span class="faint">· ${esc(r.when)}</span></h3>
        <ol class="timeline">${r.steps.map((st) => `<li class="${st.outcome}">
          <div class="tl-req">“${esc(st.request)}”</div>
          <div class="tl-dec">Agent: ${esc(st.decision)} ${chip(st.outcome)}</div>
          <div class="tl-det muted">${esc(st.detail)}
            ${st.near ? nearTx(st.near, st.outcome === 'blocked' ? 'refused request' : 'request') : ''}
            ${st.guardianTx ? ' · ' + nearTx(st.guardianTx, 'guardian’s veto') : ''}
            ${st.receipt ? ` · <a target="_blank" rel="noreferrer" href="${EXPLORER[d.chain]}/tx/${st.receipt}">Ethereum receipt ↗</a>` : ''}</div>
        </li>`).join('')}</ol>`).join('')}
    </div></div>`;
}

async function signedSection(d: VaultData, isOwner: boolean) {
  // The public Sepolia RPC is load-balanced and some of its nodes answer `null` for a receipt that
  // exists, so a missing receipt is retried and never shown as a failure on its own: a record is
  // "replaced" only when another record with the same nonce is the one that was mined.
  const receipt = async (h: string) => {
    for (let i = 0; i < 5; i++) {
      const rc = await eth<any>(d.chain, 'eth_getTransactionReceipt', [h]).catch(() => null);
      if (rc) return rc;
      await new Promise((res) => setTimeout(res, 300));
    }
    return null;
  };
  const found = await Promise.all(d.signed.map((r) => (r.nonce >= d.mined ? null : receipt(r.tx_hash))));
  const minedNonces = new Set(d.signed.filter((_, i) => found[i]).map((r) => r.nonce));
  const statuses = d.signed.map((r, i) => {
    if (r.nonce >= d.mined) return 'not mined';
    const rc = found[i];
    if (rc) return rc.status === '0x1' ? 'mined' : 'reverted';
    return minedNonces.has(r.nonce) ? 'replaced' : 'checking';
  });
  const rows = d.signed.map((r, i) => {
    const st = statuses[i];
    const pill = st === 'mined' ? 'ok' : st === 'not mined' ? 'warn' : st === 'checking' ? '' : 'bad';
    const label = { mined: 'paid', 'not mined': 'not sent yet', checking: 'checking…', replaced: 'replaced', reverted: 'failed on chain' }[st] ?? st;
    const kind = r.proposal_id > 1e18 ? 'cancellation' : `request #${r.proposal_id}`;
    return `<tr><td class="mono">${esc(r.nonce)}</td><td>${kind}</td><td>${txLink(d.chain, r.tx_hash)}</td><td><span class="badge ${pill}">${label}</span></td><td class="row">
      ${st === 'not mined' ? `<button class="btn small" data-action="broadcast" data-raw="${esc(r.signed_tx)}">Send to Ethereum</button>` : ''}
      ${st === 'not mined' && isOwner ? `<button class="btn small" data-action="cancel-nonce" data-id="${r.nonce}" title="Signs a replacement that uses the same nonce, so this payment can never go through">Cancel this payment</button>` : ''}</td></tr>`;
  }).join('');
  const unc = d.uncertain.length ? `<div class="notice" style="margin-top:10px">Signing result unknown (the signer failed or answered something unreadable; the nonce stays used): ${d.uncertain.map((u) => `nonce ${u.nonce}`).join(', ')}. Sign the pinned proposal again or cancel the nonce.</div>` : '';
  return `<div class="card"><header><h2>Payments signed</h2><span class="faint">anyone can send them to Ethereum; no key needed</span></header><div class="body">
    ${rows ? `<table class="stack"><tr><th>Nonce</th><th>What</th><th>Receipt</th><th>Status</th><th></th></tr>${rows}</table>` : '<div class="empty">Nothing paid yet.</div>'}${unc}</div></div>`;
}

function saleSection(d: VaultData, isOwner: boolean, isGuardian: boolean) {
  const s = d.sale;
  const active = s && Date.now() < s.closes_at_ms;
  const info = active
    ? `<div class="kv">
        <div><div class="label">Handover</div><div class="v">#${esc(s.sale_id)}</div></div>
        <div><div class="label">Price</div><div class="v">${s.price ? `${yoctoToNear(s.price)} NEAR` : 'none (the owner transfers it)'}</div></div>
        <div><div class="label">Only for</div><div class="v">${esc(s.buyer ?? 'anyone')}</div></div>
        <div><div class="label">Window</div><div class="v">${Date.now() < s.opens_at_ms ? `opens in <span data-until="${s.opens_at_ms}">${inTime(s.opens_at_ms)}</span>` : `open, closes in ${inTime(s.closes_at_ms)}`}</div></div>
      </div>
      <div class="row" style="margin-top:10px">
        ${isOwner ? '<button class="btn small" data-action="cancel-sale">Stop handover</button>' : ''}
        ${isGuardian ? '<button class="btn danger" data-action="veto-sale">■ Stop this handover</button>' : ''}
        <a class="btn small primary" href="#/vault/${esc(d.id)}?audit" data-action="goto-audit">Check before you take over</a>
      </div>`
    : `<p class="muted">No handover open.</p>`;
  const form = isOwner && !active && !d.inflight
    ? `<form id="sale-form" class="form">
        <label><div class="label">Price in NEAR (optional)</div><input name="price" placeholder="e.g. 2" /></label>
        <label><div class="label">Only this account can take over (optional, needs a price)</div><input name="buyer" placeholder="buyer.testnet" /></label>
        <div class="full"><button class="btn primary">Start handover</button> <span class="faint">0.01 NEAR deposit</span></div>
      </form>`
    : '';
  return `<div class="card" id="sale"><header><h2>Handover</h2>${active ? '<span class="badge warn">handover open</span>' : ''}</header><div class="body">
    <p class="muted">Hand this vault to a new owner, team or treasurer. For at least 10 minutes (or the waiting time, if longer) the vault pays nothing and the guardian can stop the handover. The new owner checks the vault here, then pays and receives it in one step.</p>
    ${info}${form}</div></div>`;
}

function auditSection(d: VaultData) {
  return `<div class="card" id="audit"><header><h2>Check before you take over</h2><span class="spacer"></span><button class="btn" data-action="audit">Run the check</button></header>
    <div class="body"><p class="muted">Runs in your browser, no wallet needed: no old payment the previous owner signed can still go through, nobody can still pull tokens from the vault, and the contract runs the published code.</p>
    <div id="audit-out"></div></div></div>`;
}

function renderAudit(d: VaultData, r: AuditResult) {
  const out = document.getElementById('audit-out')!;
  const icon = { pass: '✓', fail: '✕', warn: '!', info: 'i' } as const;
  const canBuy = r.safe && r.sale?.price && accountId && accountId !== d.owner && (!r.sale.buyer || r.sale.buyer === accountId) && Date.now() >= r.sale.opens_at_ms;
  out.innerHTML = `
    <div class="verdict ${r.safe ? 'ok' : 'bad'}"><div class="big">${r.safe ? `Safe to take over (handover #${esc(r.sale.sale_id)})` : 'Not safe yet'}</div>
      <div class="muted">${r.safe ? 'No payment the previous owner signed can still go through, and no token permission is left.' : 'See the failed checks below.'}</div></div>
    ${r.checks.map((c) => `<div class="check ${c.state}"><div class="icon">${icon[c.state]}</div><div><div>${esc(c.title)}</div>${c.detail ? `<div class="detail">${esc(c.detail)}</div>` : ''}</div></div>`).join('')}
    ${r.safe && r.sale?.price ? `<div class="row" style="margin-top:14px">
      <button class="btn primary" data-action="buy" data-sale="${esc(r.sale.sale_id)}" data-price="${esc(r.sale.price)}" ${canBuy ? '' : 'disabled'}>Take over for ${yoctoToNear(r.sale.price)} NEAR (handover #${esc(r.sale.sale_id)})</button>
      <span class="faint">${!accountId ? 'Connect a wallet to take over.' : accountId === d.owner ? 'You own this vault.' : r.sale.buyer && r.sale.buyer !== accountId ? `Reserved for ${esc(r.sale.buyer)}.` : Date.now() < r.sale.opens_at_ms ? 'The handover has not opened yet.' : 'If the owner restarts the handover, this fails and your NEAR comes back.'}</span></div>`
      : r.safe ? `<p class="muted">No on-chain price: pay only through a transfer bound with memo <span class="mono">sale:${esc(r.sale.sale_id)}</span>.</p>` : ''}`;
}

async function vaultPage(id: string, rid: number) {
  app.innerHTML = '<p class="faint">Loading vault…</p>';
  const d = await loadVault(id);
  if (rid !== renderId) return;
  const isOwner = !!accountId && accountId === d.owner;
  const isGuardian = !!accountId && d.policy.policy.guardian === accountId;
  const isAgent = !!accountId && d.policy.policy.proposer === accountId;
  const frozen = !!d.sale && Date.now() < d.sale.closes_at_ms;
  const ROLE: Record<string, [string, string]> = {
    owner: ['owner', 'You own this vault: you set the rules, name the agent and the guardian, and can hand the vault over.'],
    agent: ['agent', 'You are this vault’s agent: you can request and send payments. The rules and the guardian decide what goes through.'],
    guardian: ['guardian', 'You are this vault’s guardian. Nothing is paid before the waiting time ends — you can stop any payment.'],
    visitor: ['visitor', 'Anyone can look at this vault and check it. Only its owner, agent and guardian can act.'],
    none: ['not connected', 'Anyone can look at this vault and check it, no wallet needed.'],
  };
  const role = isOwner ? 'owner' : isAgent ? 'agent' : isGuardian ? 'guardian' : accountId ? 'visitor' : 'none';
  const pills = [
    d.inflight ? '<span class="badge warn">signing…</span>' : '',
    frozen ? '<span class="badge warn">handover open</span>' : '',
    d.policy.has_policy ? '<span class="badge ok">rules active</span>' : '<span class="badge">no rules yet</span>',
    d.policy.policy.proposer ? '<span class="badge ok">AI agent</span>' : '',
    `<span class="badge">you: ${ROLE[role][0]}</span>`,
  ].join(' ');
  const signedHtml = await signedSection(d, isOwner);
  if (rid !== renderId) return;
  app.innerHTML = `
    <p><a href="#/">← Vaults</a></p>
    <div class="row"><h1>Vault #${esc(id)}</h1><span class="spacer"></span><button class="btn small" data-action="refresh">Refresh</button></div>
    <div class="row" style="margin:6px 0 12px">${pills}</div>
    <div class="role-banner ${role}">${ROLE[role][1]}</div>
    ${queueSection(d, isOwner, isGuardian, frozen, isAgent)}
    ${vaultCard(d, isOwner, isGuardian)}
    ${agentSection(d)}
    ${signedHtml}
    ${saleSection(d, isOwner, isGuardian)}
    ${auditSection(d)}`;
  wireVault(d);
  if (location.hash.includes('?audit')) document.getElementById('audit')?.scrollIntoView();
}

const csv = (s: string) => s.split(',').map((x) => x.trim().toLowerCase()).filter(Boolean);

function wireVault(d: VaultData) {
  const t = d.id;
  const policyForm = document.getElementById('policy-form') as HTMLFormElement | null;
  if (policyForm) policyForm.onsubmit = (e) => {
    e.preventDefault();
    const f = new FormData(policyForm);
    let tokens, nfts;
    try { tokens = JSON.parse(String(f.get('tokens') || '[]')); nfts = JSON.parse(String(f.get('nfts') || '[]')); } catch { return toast('Tokens and NFT collections must be JSON', 'bad'); }
    const policy = {
      chain_id: d.policy.has_policy ? d.policy.policy.chain_id : DEFAULT_CHAIN,
      delay_ms: Math.round(Number(f.get('delay')) * 1000),
      guardian: String(f.get('guardian') || '').trim() || null,
      eth_daily_cap: parseEther(String(f.get('cap'))).toString(),
      max_gas_cost: parseEther(String(f.get('gas'))).toString(),
      allowed_destinations: csv(String(f.get('dest'))),
      allowed_spenders: csv(String(f.get('spenders'))),
      tokens,
      nfts,
      proposer: String(f.get('proposer') || '').trim() || null,
    };
    act('Set policy', () => call('set_policy', { token_id: t, policy }, nearToYocto('0.05')), (r) =>
      toast(r?.value === true ? 'Policy applied at once' : 'Policy queued: it applies after the delay unless the guardian vetoes it', 'ok'));
  };
  const proposeForm = document.getElementById('propose-form') as HTMLFormElement | null;
  if (proposeForm) proposeForm.onsubmit = async (e) => {
    e.preventDefault();
    const f = new FormData(proposeForm);
    const to = String(f.get('to')).trim().toLowerCase();
    const token = String(f.get('token') || '').trim().toLowerCase();
    const nft = String(f.get('nft') || '').trim().toLowerCase();
    const word = (x: string | bigint) => (typeof x === 'bigint' ? x.toString(16) : x.replace(/^0x/, '')).padStart(64, '0');
    try {
      const fees = await feeFields(d.chain);
      let tx;
      if (nft) {
        const id = BigInt(String(f.get('nft_id') || '0'));
        const amount = String(f.get('nft_amount') || '').trim();
        const from = d.info.evm_address as string;
        const data = amount
          ? '0xf242432a' + word(from) + word(to) + word(id) + word(BigInt(amount)) + word(0xa0n) + word(0n)
          : '0x42842e0e' + word(from) + word(to) + word(id);
        const est = BigInt(await eth<string>(d.chain, 'eth_estimateGas', [{ from, to: nft, data }]));
        tx = { chain_id: d.chain, ...fees, gas_limit: Number((est * 13n) / 10n), to: nft, value: '0', data };
      } else if (token) {
        const data = '0xa9059cbb' + to.replace(/^0x/, '').padStart(64, '0') + BigInt(String(f.get('amount'))).toString(16).padStart(64, '0');
        const est = BigInt(await eth<string>(d.chain, 'eth_estimateGas', [{ from: d.info.evm_address, to: token, data }]));
        tx = { chain_id: d.chain, ...fees, gas_limit: Number((est * 13n) / 10n), to: token, value: '0', data };
      } else {
        tx = { chain_id: d.chain, ...fees, gas_limit: 21000, to, value: parseEther(String(f.get('value'))).toString(), data: '0x' };
      }
      act('Propose', () => call('propose', { token_id: t, tx }, nearToYocto('0.05')));
    } catch (err: any) {
      toast(`Could not build the transaction: ${err?.message ?? err}`, 'bad');
    }
  };
  const saleForm = document.getElementById('sale-form') as HTMLFormElement | null;
  if (saleForm) saleForm.onsubmit = (e) => {
    e.preventDefault();
    const f = new FormData(saleForm);
    const price = String(f.get('price') || '').trim();
    const buyer = String(f.get('buyer') || '').trim();
    act('Start sale', () => call('start_sale', { token_id: t, price: price ? nearToYocto(price) : null, buyer: buyer || null }, nearToYocto('0.01'), 50n));
  };

  current = d;
}

let current: VaultData | null = null;
app.addEventListener('click', async (e) => {
  const el = (e.target as HTMLElement).closest<HTMLElement>('[data-action]');
  if (!el || !current) return;
  const a = el.dataset.action!;
  if (a === 'goto-audit') return;
  e.preventDefault();
  const d = current;
  const t = d.id;
  const pid = Number(el.dataset.id);
  switch (a) {
    case 'refresh': return route();
    case 'copy':
      await navigator.clipboard.writeText(el.dataset.text ?? '').catch(() => {});
      return toast('Address copied', 'ok');
    case 'apply-policy': return act('Apply policy', () => call('apply_policy', { token_id: t }));
    case 'cancel-policy': return act('Cancel pending policy', () => call('cancel_pending_policy', { token_id: t }, ONE_YOCTO));
    case 'veto-policy': return act('Veto policy change', () => call('veto_pending_policy', { token_id: t }, ONE_YOCTO));
    case 'execute':
      // Approve & send: the contract checks the rules again and asks NEAR Chain Signatures to sign;
      // the signed transaction is then sent to Ethereum from this page (no key needed to send it).
      return act('Approve & send', () => call('execute_proposal', { token_id: t, proposal_id: pid }, nearToYocto('0.02'), 300n), async (r) => {
        const signed = events(r.logs, 'transaction_signed')[0];
        if (r?.value !== true || !signed) {
          const why = events(r.logs, 'signature_failed')[0] ?? events(r.logs, 'signature_uncertain')[0];
          return toast(`Not signed: ${human(JSON.stringify(why ?? {}))}`, 'bad');
        }
        try {
          const h = await eth<string>(d.chain, 'eth_sendRawTransaction', [signed.signed_tx]);
          toast(`Signed through NEAR Chain Signatures and sent to Ethereum (${short(h, 10, 6)}). It shows as paid once mined.`, 'ok');
        } catch (err: any) {
          toast('Signed, but sending to Ethereum failed. Use "Send to Ethereum" under Payments signed.', 'bad', String(err?.message ?? err));
        }
      });
    case 'cancel-proposal': return act('Cancel proposal', () => call('cancel_proposal', { token_id: t, proposal_id: pid }, ONE_YOCTO));
    case 'veto-proposal': return act('Veto proposal', () => call('veto_proposal', { token_id: t, proposal_id: pid }, ONE_YOCTO));
    case 'cancel-nonce': {
      const fees = await feeFields(d.chain);
      return act('Cancel nonce', () => call('cancel_nonce', { token_id: t, nonce: pid, ...fees }, nearToYocto('0.02'), 300n));
    }
    case 'broadcast':
      try {
        const h = await eth<string>(d.chain, 'eth_sendRawTransaction', [el.dataset.raw]);
        toast(`Sent ${h}; refresh in a few seconds`, 'ok');
      } catch (err: any) {
        toast(`Broadcast failed: ${err?.message ?? err}`, 'bad');
      }
      return;
    case 'cancel-sale': return act('Cancel sale', () => call('cancel_sale', { token_id: t }, ONE_YOCTO));
    case 'veto-sale': return act('Veto sale', () => call('veto_sale', { token_id: t }, ONE_YOCTO));
    case 'audit': {
      const out = document.getElementById('audit-out')!;
      out.innerHTML = '<p class="faint">Auditing on NEAR and Sepolia…</p>';
      try {
        renderAudit(d, await audit(t));
      } catch (err: any) {
        out.innerHTML = `<p class="faint">Audit failed: ${esc(err?.message ?? err)}</p>`;
      }
      return;
    }
    case 'buy':
      return act('Buy', () => call('buy', { token_id: t, sale_id: Number(el.dataset.sale) }, el.dataset.price!, 50n));
  }
});

route();
