import './style.css';
import { formatEther, parseEther } from 'viem';
import { audit, type AuditResult } from './audit';
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
function toast(msg: string, kind: 'ok' | 'bad' | '' = '') {
  toastEl.textContent = msg;
  toastEl.className = `toast ${kind}`;
  toastEl.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = window.setTimeout(() => (toastEl.hidden = true), kind === 'bad' ? 9000 : 5000);
}

/** Runs a contract call from the wallet, reports the outcome and re-renders. */
async function act(label: string, f: () => Promise<{ failure?: string; value?: any; logs: string[] } | void>, after?: (r: any) => void) {
  toast(`${label}: confirm in your wallet…`);
  try {
    const r = await f();
    if (r && r.failure) toast(`${label} refused: ${r.failure}`, 'bad');
    else {
      toast(`${label}: done`, 'ok');
      after?.(r);
    }
  } catch (e: any) {
    toast(`${label} failed: ${e?.message ?? e}`, 'bad');
  }
  route();
}

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
async function vaultSummary(t: any) {
  const id = t.token_id;
  const [policy, sale, inflight, info] = await Promise.all([
    view('get_policy', { token_id: id }), view('get_sale', { token_id: id }), view('get_inflight', { token_id: id }), view('vault_info', { token_id: id }),
  ]);
  const pills = [
    inflight ? '<span class="badge warn">signature in flight</span>' : '',
    sale && Date.now() < sale.closes_at_ms ? '<span class="badge warn">on sale</span>' : '',
    policy.has_policy ? '<span class="badge ok">policy active</span>' : '<span class="badge">locked · no policy</span>',
  ].join(' ');
  return `<a class="card vault-card" href="#/vault/${esc(id)}">
    <div class="row"><h2>Vault #${esc(id)}</h2><span class="spacer"></span></div>
    <div class="mono muted" style="margin:6px 0">${esc(short(info.evm_address ?? 'address not resolved', 10, 8))}</div>
    <div class="row">${pills}</div>
    <div class="faint" style="margin-top:6px;font-size:12px">${policy.policy.guardian ? `guardian ${esc(policy.policy.guardian)}` : 'no guardian'}</div>
  </a>`;
}

async function homePage(id: number) {
  app.innerHTML = `
    <section class="hero">
      <h1>An NFT that owns an Ethereum account.</h1>
      <p class="muted">It can only spend under a policy enforced by a NEAR contract, through NEAR Chain Signatures. Selling the NFT hands over the account without handing over any key.</p>
      <ul>
        <li>The contract computes and checks every transaction it asks the MPC network to sign: daily caps, allowed destinations, a delay, a guardian veto, no unlimited approvals.</li>
        <li>A sale runs in two phases: the vault freezes, the buyer audits it here, and <span class="mono">buy</span> pays the seller in the same transaction that moves the NFT.</li>
      </ul>
    </section>
    <div class="card"><header><h2>Open a vault by id</h2></header><div class="body">
      <form id="open" class="row"><input id="open-id" class="mono" style="max-width:160px" placeholder="74" inputmode="numeric" /><button class="btn">Open</button>
      <span class="faint">No wallet needed to look at a vault or run the buyer's audit.</span></form>
    </div></div>
    <div id="mine"></div>
    <div id="guarded"></div>`;
  (document.getElementById('open') as HTMLFormElement).onsubmit = (e) => {
    e.preventDefault();
    const v = (document.getElementById('open-id') as HTMLInputElement).value.trim();
    if (/^\d+$/.test(v)) location.hash = `#/vault/${v}`;
  };
  const mine = document.getElementById('mine')!;
  if (!accountId) {
    mine.innerHTML = `<div class="card"><header><h2>My vaults</h2></header><div class="body muted">Connect a NEAR testnet wallet to mint and manage vaults.</div></div>`;
    return;
  }
  mine.innerHTML = `<div class="card"><header><h2>My vaults</h2><span class="spacer"></span>
    <button class="btn primary" id="mint">Mint a vault (0.1 NEAR deposit, the rest is refunded)</button></header>
    <div class="body"><div class="grid" id="mine-grid"><span class="faint">Loading…</span></div></div></div>`;
  document.getElementById('mint')!.onclick = () =>
    act('Mint', () => call('mint_vault', {}, nearToYocto('0.1'), 100n), (r) => {
      const t = r?.value?.token_id;
      if (t !== undefined) location.hash = `#/vault/${t}`;
    });
  const tokens = await view<any[]>('nft_tokens_for_owner', { account_id: accountId, from_index: '0', limit: 50 });
  if (id !== renderId) return;
  const cards = await Promise.all(tokens.map(vaultSummary));
  if (id !== renderId) return;
  document.getElementById('mine-grid')!.innerHTML = cards.join('') || '<span class="empty">You own no vault yet.</span>';

  const guarded = document.getElementById('guarded')!;
  guarded.innerHTML = `<div class="card"><header><h2>Vaults I guard</h2><span class="spacer"></span><button class="btn small" id="scan">Find them</button></header>
    <div class="body"><div class="grid" id="guard-grid"><span class="faint">Scans every vault's policy (one request per vault).</span></div></div></div>`;
  document.getElementById('scan')!.onclick = async () => {
    const grid = document.getElementById('guard-grid')!;
    grid.innerHTML = '<span class="faint">Scanning…</span>';
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
    grid.innerHTML = (await Promise.all(found.map(vaultSummary))).join('') || '<span class="empty">You guard no vault.</span>';
  };
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

function policySection(d: VaultData, isOwner: boolean, isGuardian: boolean) {
  const p = d.policy.policy;
  const pend = d.policy.pending;
  const spent = d.policy.spend?.eth?.spent ?? '0';
  const rules = d.policy.has_policy
    ? `<div class="kv">
        <div><div class="label">Chain</div><div class="v">${esc(p.chain_id)}</div></div>
        <div><div class="label">Delay</div><div class="v">${esc(p.delay_ms / 1000)} s</div></div>
        <div><div class="label">Guardian</div><div class="v">${esc(p.guardian ?? 'none')}</div></div>
        <div><div class="label">ETH daily cap</div><div class="v">${ethFmt(p.eth_daily_cap)} <span class="faint">(${ethFmt(spent)} used)</span></div></div>
        <div><div class="label">Max gas cost per tx</div><div class="v">${ethFmt(p.max_gas_cost)}</div></div>
        <div><div class="label">Allowed destinations</div><div class="v">${p.allowed_destinations.map(esc).join('<br>') || 'none'}</div></div>
        <div><div class="label">Allowed spenders</div><div class="v">${p.allowed_spenders.map(esc).join('<br>') || 'none'}</div></div>
        <div><div class="label">Tokens</div><div class="v">${p.tokens.map((t: any) => `${esc(short(t.contract, 8, 6))}: ${esc(t.daily_cap)}/day, approve ≤ ${esc(t.max_approval)}`).join('<br>') || 'none'}</div></div>
      </div>`
    : `<p class="muted">Locked: no policy, so nothing can be signed. The first policy of a locked vault applies at once.</p>`;
  const pending = pend
    ? `<div class="notice" style="margin-top:12px">Pending change, applies ${Date.now() >= pend.apply_after_ms ? 'now (anyone can apply it)' : `in ${inTime(pend.apply_after_ms)}`}:
        destinations ${pend.policy.allowed_destinations.map(esc).join(', ') || 'none'}; delay ${pend.policy.delay_ms / 1000} s; guardian ${esc(pend.policy.guardian ?? 'none')}; ETH cap ${ethFmt(pend.policy.eth_daily_cap)}.
        <div class="row" style="margin-top:8px">
          ${Date.now() >= pend.apply_after_ms ? '<button class="btn small" data-action="apply-policy">Apply</button>' : ''}
          ${isOwner ? '<button class="btn small" data-action="cancel-policy">Cancel</button>' : ''}
          ${isGuardian ? '<button class="btn small danger" data-action="veto-policy">Veto</button>' : ''}
        </div></div>`
    : '';
  const draft = d.policy.has_policy ? p : { chain_id: DEFAULT_CHAIN, delay_ms: 60000, guardian: null, eth_daily_cap: parseEther('0.01').toString(), max_gas_cost: parseEther('0.002').toString(), allowed_destinations: [], allowed_spenders: [], tokens: [] };
  const form = isOwner
    ? `<details style="margin-top:12px"><summary class="btn small" style="display:inline-block">Change policy</summary>
        <p class="faint">Tightening applies at once. Loosening waits the current delay and the guardian can veto it. Replacing the guardian waits max(2 × delay, 3 days).</p>
        <form id="policy-form" class="form">
          <label><div class="label">Delay (seconds)</div><input name="delay" value="${draft.delay_ms / 1000}" /></label>
          <label><div class="label">Guardian (NEAR account)</div><input name="guardian" value="${esc(draft.guardian ?? '')}" placeholder="none" /></label>
          <label><div class="label">ETH daily cap (ETH)</div><input name="cap" value="${formatEther(BigInt(draft.eth_daily_cap))}" /></label>
          <label><div class="label">Max gas cost per tx (ETH)</div><input name="gas" value="${formatEther(BigInt(draft.max_gas_cost))}" /></label>
          <label class="full"><div class="label">Allowed destinations (comma separated)</div><input name="dest" value="${esc(draft.allowed_destinations.join(', '))}" /></label>
          <label class="full"><div class="label">Allowed spenders (comma separated)</div><input name="spenders" value="${esc(draft.allowed_spenders.join(', '))}" /></label>
          <label class="full"><div class="label">Tokens (JSON: [{"contract","daily_cap","max_approval"}])</div><textarea name="tokens" rows="2">${esc(JSON.stringify(draft.tokens))}</textarea></label>
          <div class="full"><button class="btn primary">Submit (0.05 NEAR storage deposit, the rest is refunded)</button></div>
        </form></details>`
    : '';
  return `<div class="card"><header><h2>Policy</h2>${d.policy.has_policy ? '<span class="badge ok">active</span>' : '<span class="badge">locked</span>'}</header>
    <div class="body">${rules}${pending}${form}</div></div>`;
}

function queueSection(d: VaultData, isOwner: boolean, isGuardian: boolean, frozen: boolean) {
  const rows = d.proposals.map((p) => {
    const c = d.checks[p.id];
    const tx = p.tx;
    const what = tx.data && tx.data !== '0x' ? `token call to ${short(tx.to, 8, 6)} <span class="faint">${esc(short(tx.data, 10, 8))}</span>` : `${ethFmt(tx.value)} to ${esc(short(tx.to, 8, 6))}`;
    const status = c?.ready ? '<span class="badge ok">ready to sign</span>'
      : Date.now() < p.executable_after_ms ? `<span class="badge warn">waiting ${inTime(p.executable_after_ms)}</span>`
      : `<span class="badge bad" title="${esc(c?.reason)}">refused</span> <span class="faint">${esc(c?.reason ?? '')}</span>`;
    return `<tr><td class="mono">#${esc(p.id)}</td><td class="mono">${what}</td><td>${status}</td><td class="row">
      ${isOwner ? `<button class="btn small primary" data-action="execute" data-id="${p.id}" ${c?.ready ? '' : 'disabled'}>Sign</button>
      <button class="btn small" data-action="cancel-proposal" data-id="${p.id}">Cancel</button>` : ''}
      ${isGuardian ? `<button class="btn small danger" data-action="veto-proposal" data-id="${p.id}">Veto</button>` : ''}</td></tr>`;
  }).join('');
  const form = isOwner && d.policy.has_policy
    ? `<details style="margin-top:12px"><summary class="btn small" style="display:inline-block">New proposal</summary>
        <form id="propose-form" class="form">
          <label><div class="label">To (EVM address)</div><input name="to" placeholder="0x…" value="${esc(d.policy.policy.allowed_destinations[0] ?? '')}" /></label>
          <label><div class="label">ETH amount</div><input name="value" value="0.0001" /></label>
          <label><div class="label">Or: ERC-20 contract (optional)</div><input name="token" placeholder="0x… (leave empty for ETH)" /></label>
          <label><div class="label">Token amount (base units)</div><input name="amount" placeholder="e.g. 60000000000000" /></label>
          <div class="full"><button class="btn primary">Propose (0.05 NEAR storage deposit)</button>
          <span class="faint">The fee is taken from Sepolia now; the policy is checked when proposing and again when signing.</span></div>
        </form></details>`
    : '';
  return `<div class="card"><header><h2>Proposal queue</h2>${frozen ? '<span class="badge warn">frozen by the sale</span>' : ''}</header><div class="body">
    ${rows ? `<table><tr><th>Id</th><th>Transaction</th><th>Status</th><th></th></tr>${rows}</table>` : '<div class="empty">No queued proposal.</div>'}
    ${form}</div></div>`;
}

async function signedSection(d: VaultData, isOwner: boolean) {
  const statuses = await Promise.all(d.signed.map(async (r) => {
    if (r.nonce >= d.mined) return 'not mined';
    const rc = await eth<any>(d.chain, 'eth_getTransactionReceipt', [r.tx_hash]).catch(() => null);
    return rc ? (rc.status === '0x1' ? 'mined' : 'reverted') : 'replaced';
  }));
  const rows = d.signed.map((r, i) => {
    const st = statuses[i];
    const pill = st === 'mined' ? 'ok' : st === 'not mined' ? 'warn' : 'bad';
    const kind = r.proposal_id > 1e18 ? 'cancellation' : `proposal #${r.proposal_id}`;
    return `<tr><td class="mono">${esc(r.nonce)}</td><td>${kind}</td><td>${txLink(d.chain, r.tx_hash)}</td><td><span class="badge ${pill}">${st}</span></td><td class="row">
      ${st === 'not mined' ? `<button class="btn small" data-action="broadcast" data-raw="${esc(r.signed_tx)}">Broadcast</button>` : ''}
      ${st === 'not mined' && isOwner ? `<button class="btn small" data-action="cancel-nonce" data-id="${r.nonce}">Cancel nonce</button>` : ''}</td></tr>`;
  }).join('');
  const unc = d.uncertain.length ? `<div class="notice" style="margin-top:10px">Uncertain signatures (the signer failed or answered something unreadable; the nonce stays used): ${d.uncertain.map((u) => `nonce ${u.nonce}`).join(', ')}. Sign the pinned proposal again or cancel the nonce.</div>` : '';
  return `<div class="card"><header><h2>Signed transactions</h2><span class="faint">anyone can broadcast them; no key needed</span></header><div class="body">
    ${rows ? `<table><tr><th>Nonce</th><th>Kind</th><th>Tx hash</th><th>On chain ${d.chain}</th><th></th></tr>${rows}</table>` : '<div class="empty">Nothing signed yet.</div>'}${unc}</div></div>`;
}

function saleSection(d: VaultData, isOwner: boolean, isGuardian: boolean) {
  const s = d.sale;
  const active = s && Date.now() < s.closes_at_ms;
  const info = active
    ? `<div class="kv">
        <div><div class="label">Sale</div><div class="v">#${esc(s.sale_id)}</div></div>
        <div><div class="label">Price</div><div class="v">${s.price ? `${yoctoToNear(s.price)} NEAR` : 'none (the seller transfers it)'}</div></div>
        <div><div class="label">Reserved for</div><div class="v">${esc(s.buyer ?? 'anyone')}</div></div>
        <div><div class="label">Window</div><div class="v">${Date.now() < s.opens_at_ms ? `opens in ${inTime(s.opens_at_ms)}` : `open, closes in ${inTime(s.closes_at_ms)}`}</div></div>
      </div>
      <div class="row" style="margin-top:10px">
        ${isOwner ? '<button class="btn small" data-action="cancel-sale">Cancel sale</button>' : ''}
        ${isGuardian ? '<button class="btn small danger" data-action="veto-sale">Veto sale</button>' : ''}
        <a class="btn small primary" href="#/vault/${esc(d.id)}?audit" data-action="goto-audit">Audit before buying</a>
      </div>`
    : `<p class="muted">Not on sale.</p>`;
  const form = isOwner && !active && !d.inflight
    ? `<form id="sale-form" class="form">
        <label><div class="label">Price in NEAR (optional)</div><input name="price" placeholder="e.g. 2" /></label>
        <label><div class="label">Reserved buyer (optional, needs a price)</div><input name="buyer" placeholder="buyer.testnet" /></label>
        <div class="full"><button class="btn primary">Start sale (0.01 NEAR storage deposit)</button></div>
      </form>`
    : '';
  return `<div class="card" id="sale"><header><h2>Sale</h2>${active ? '<span class="badge warn">on sale</span>' : ''}</header><div class="body">
    <p class="faint">During a sale the vault signs only cancellations. The window opens after max(policy delay, 10 minutes) and the guardian can veto it; a buyer who audited sale N can only buy sale N.</p>
    ${info}${form}</div></div>`;
}

function auditSection(d: VaultData) {
  return `<div class="card" id="audit"><header><h2>Buyer's audit</h2><span class="spacer"></span><button class="btn" data-action="audit">Run audit</button></header>
    <div class="body"><p class="faint">The contract cannot read Ethereum, so this audit runs in your browser against public RPCs: no signature the seller kept can still be mined, no ERC-20 approval survives, and what code the contract runs.</p>
    <div id="audit-out"></div></div></div>`;
}

function renderAudit(d: VaultData, r: AuditResult) {
  const out = document.getElementById('audit-out')!;
  const icon = { pass: '✓', fail: '✕', warn: '!', info: 'i' } as const;
  const canBuy = r.safe && r.sale?.price && accountId && accountId !== d.owner && (!r.sale.buyer || r.sale.buyer === accountId) && Date.now() >= r.sale.opens_at_ms;
  out.innerHTML = `
    <div class="verdict ${r.safe ? 'ok' : 'bad'}"><div class="big">${r.safe ? `SAFE for sale #${esc(r.sale.sale_id)}` : 'NOT SAFE'}</div>
      <div class="muted">${r.safe ? 'No signature the seller holds can still be mined and no ERC-20 approval is left.' : 'See the failed checks below.'}</div></div>
    ${r.checks.map((c) => `<div class="check ${c.state}"><div class="icon">${icon[c.state]}</div><div><div>${esc(c.title)}</div>${c.detail ? `<div class="detail">${esc(c.detail)}</div>` : ''}</div></div>`).join('')}
    ${r.safe && r.sale?.price ? `<div class="row" style="margin-top:14px">
      <button class="btn primary" data-action="buy" data-sale="${esc(r.sale.sale_id)}" data-price="${esc(r.sale.price)}" ${canBuy ? '' : 'disabled'}>Buy for ${yoctoToNear(r.sale.price)} NEAR (bound to sale #${esc(r.sale.sale_id)})</button>
      <span class="faint">${!accountId ? 'Connect a wallet to buy.' : accountId === d.owner ? 'You own this vault.' : r.sale.buyer && r.sale.buyer !== accountId ? `Reserved for ${esc(r.sale.buyer)}.` : Date.now() < r.sale.opens_at_ms ? 'The sale has not opened yet.' : 'If the seller restarts the sale, this purchase fails and your NEAR comes back.'}</span></div>`
      : r.safe ? `<p class="muted">No on-chain price: pay only through a transfer bound with memo <span class="mono">sale:${esc(r.sale.sale_id)}</span>.</p>` : ''}`;
}

async function vaultPage(id: string, rid: number) {
  app.innerHTML = '<p class="faint">Loading vault…</p>';
  const d = await loadVault(id);
  if (rid !== renderId) return;
  const isOwner = !!accountId && accountId === d.owner;
  const isGuardian = !!accountId && d.policy.policy.guardian === accountId;
  const frozen = !!d.sale && Date.now() < d.sale.closes_at_ms;
  const role = isOwner ? 'owner' : isGuardian ? 'guardian' : accountId ? 'visitor' : 'not connected';
  const pills = [
    d.inflight ? `<span class="badge warn">signature in flight · nonce ${d.inflight.nonce}</span>` : '',
    frozen ? '<span class="badge warn">on sale</span>' : '',
    d.policy.has_policy ? '<span class="badge ok">policy active</span>' : '<span class="badge">locked</span>',
    d.policy.has_policy && !d.policy.policy.guardian ? '<span class="badge warn" title="Without a guardian nobody can veto a sale: an owner (or a thief with the key) can sell the vault to another account of theirs after 10 minutes and start again with fresh daily caps.">no guardian</span>' : '',
    `<span class="badge">you: ${role}</span>`,
  ].join(' ');
  const signedHtml = await signedSection(d, isOwner);
  if (rid !== renderId) return;
  app.innerHTML = `
    <p><a href="#/">← Vaults</a></p>
    <div class="row"><h1>Vault #${esc(id)}</h1><span class="spacer"></span><button class="btn small" data-action="refresh">Refresh</button></div>
    <div class="row" style="margin-bottom:14px">${pills}</div>
    <div class="card"><div class="body kv">
      <div><div class="label">Owner</div><div class="v">${esc(d.owner)}</div></div>
      <div><div class="label">EVM address</div><div class="v">${d.info.evm_address ? addrLink(d.chain, d.info.evm_address) : 'not resolved'}</div></div>
      <div><div class="label">Balance on chain ${d.chain}</div><div class="v">${ethFmt(d.balance)}</div></div>
      <div><div class="label">Next nonce · account nonce</div><div class="v">${d.next} · ${d.mined}</div></div>
      <div><div class="label">Derivation path</div><div class="v">${esc(d.info.path)} <span class="faint">from ${esc(CONTRACT)}</span></div></div>
      <div><div class="label">Ownership changes</div><div class="v">${esc(d.transfer?.count ?? 0)}</div></div>
    </div></div>
    ${policySection(d, isOwner, isGuardian)}
    ${queueSection(d, isOwner, isGuardian, frozen)}
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
    let tokens;
    try { tokens = JSON.parse(String(f.get('tokens') || '[]')); } catch { return toast('Tokens must be JSON', 'bad'); }
    const policy = {
      chain_id: d.policy.has_policy ? d.policy.policy.chain_id : DEFAULT_CHAIN,
      delay_ms: Math.round(Number(f.get('delay')) * 1000),
      guardian: String(f.get('guardian') || '').trim() || null,
      eth_daily_cap: parseEther(String(f.get('cap'))).toString(),
      max_gas_cost: parseEther(String(f.get('gas'))).toString(),
      allowed_destinations: csv(String(f.get('dest'))),
      allowed_spenders: csv(String(f.get('spenders'))),
      tokens,
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
    try {
      const fees = await feeFields(d.chain);
      let tx;
      if (token) {
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
    case 'apply-policy': return act('Apply policy', () => call('apply_policy', { token_id: t }));
    case 'cancel-policy': return act('Cancel pending policy', () => call('cancel_pending_policy', { token_id: t }, ONE_YOCTO));
    case 'veto-policy': return act('Veto policy change', () => call('veto_pending_policy', { token_id: t }, ONE_YOCTO));
    case 'execute':
      return act('Sign', () => call('execute_proposal', { token_id: t, proposal_id: pid }, nearToYocto('0.02'), 300n), (r) =>
        toast(r?.value === true ? 'Signed by the MPC network and verified by the contract. Broadcast it below.' : `Not signed: ${JSON.stringify(events(r.logs, 'signature_failed')[0] ?? events(r.logs, 'signature_uncertain')[0] ?? {})}`, r?.value === true ? 'ok' : 'bad'));
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
