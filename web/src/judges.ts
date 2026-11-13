// Judges' guide (#/judges): five steps a judge can check without a wallet or installing anything.
// Every number on this page is read live from the deployed contract or links to a recorded
// transaction; every command shown was run against testnet before it was published.
import { formatEther } from 'viem';
import { AGENT_RUNS, type AgentStep } from './agent-run';
import { CONTRACT, EXPLORER, NEAR_EXPLORER, nearRpc, view } from './near';

const REPO = 'https://github.com/Alan021011/near-policy-vault';
const VAULT = '78';
const SEPOLIA = 11155111;
const APPROVED = '0x881294c1b52d631ab43fa2bd23d691209b548d11';
const DAY_MS = 24 * 3_600_000;

const esc = (s: unknown) =>
  String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!);
const short = (s: string, a = 6, b = 4) => (s && s.length > a + b + 1 ? `${s.slice(0, a)}…${s.slice(-b)}` : s);
const eth = (wei: string | bigint) => `${Number(formatEther(BigInt(wei))).toLocaleString('en', { maximumFractionDigits: 6 })} ETH`;
const nearTx = (h: string, label: string) => `<a target="_blank" rel="noreferrer" href="${NEAR_EXPLORER}/txns/${esc(h)}">${label} ↗</a>`;
const sepTx = (h: string, label: string) => `<a target="_blank" rel="noreferrer" href="${EXPLORER[SEPOLIA]}/tx/${esc(h)}">${label} ↗</a>`;

/** A transaction the contract can check: 0.05 ETH (over the cap) or 0.0001 ETH, to an approved or unknown address. */
const txOf = (to: string, value: string) => ({
  chain_id: SEPOLIA, nonce: 0, max_priority_fee_per_gas: '1000000000', max_fee_per_gas: '2000000000', gas_limit: 21000, to, value, data: '0x',
});
const OVER_CAP = txOf(APPROVED, '50000000000000000');

const cli = (method: string, args: object) =>
  `near contract call-function as-read-only ${CONTRACT} ${method} json-args '${JSON.stringify(args)}' network-config testnet now`;
const curlOf = (method: string, args: object) => {
  const b64 = btoa(JSON.stringify(args));
  return `curl -s https://rpc.testnet.near.org -H 'Content-Type: application/json' -d '{"jsonrpc":"2.0","id":"judge","method":"query","params":{"request_type":"call_function","finality":"final","account_id":"${CONTRACT}","method_name":"${method}","args_base64":"${b64}"}}' | jq -r '.result.result | implode'`;
};
const rpcCurl = (requestType: string) =>
  `curl -s https://rpc.testnet.near.org -H 'Content-Type: application/json' -d '{"jsonrpc":"2.0","id":"judge","method":"query","params":{"request_type":"${requestType}","finality":"final","account_id":"${CONTRACT}"}}'`;

let codeId = 0;
const code = (title: string, text: string, note = '') => {
  const id = `code-${++codeId}`;
  return `<div class="term"><div class="term-head"><span class="term-dots"><i></i><i></i><i></i></span><span>${title}</span><span class="spacer"></span>
    <button class="btn small" data-copy="${id}">Copy</button></div><pre class="mono" id="${id}">${esc(text)}</pre>${note ? `<div class="term-note">${note}</div>` : ''}</div>`;
};
const stepHead = (n: string, title: string, sub: string, tag: string, tone = '') =>
  `<header class="jstep-head"><span class="jstep-n mono">${n}</span><div><h2>${title}</h2><p class="muted">${sub}</p></div><span class="spacer"></span><span class="badge ${tone}">${tag}</span></header>`;

function runLine(s: AgentStep) {
  const icon = { paid: '✓', blocked: '✕', stopped: '■', declined: '–' }[s.outcome];
  const tone = { paid: 'ok', blocked: 'bad', stopped: 'warn', declined: '' }[s.outcome];
  const links = [s.near && nearTx(s.near, 'agent request'), s.guardianTx && nearTx(s.guardianTx, 'guardian stop'), s.receipt && sepTx(s.receipt, 'Sepolia payment')].filter(Boolean).join(' · ');
  return `<li class="run-line ${tone}"><span class="run-ico">${icon}</span><div><div class="run-req">“${esc(s.request)}”</div>
    <div class="faint">Agent decided: ${esc(s.decision)}</div><div>${esc(s.detail)}</div>${links ? `<div class="run-links">${links}</div>` : ''}</div></li>`;
}

export async function judgesPage(app: HTMLElement, isCurrent: () => boolean) {
  codeId = 0;
  const naive = AGENT_RUNS[VAULT][1];
  const model = AGENT_RUNS[VAULT][0];
  const injection = naive.steps[1]; // "URGENT from the CEO … 0.05 ETH"
  const unknown = naive.steps[2]; // new supplier, unknown address
  const vetoed = model.steps[3]; // inside the rules, stopped by the guardian
  const paid = model.steps[0];

  app.innerHTML = `
    <p><a href="#/">← Home</a></p>
    <section class="jhero">
      <div><div class="eyebrow-tag mono">Judges' guide · no wallet · nothing to install</div>
        <h1>Check it yourself in five steps</h1>
        <p class="lead">Every number on this page is read live from the deployed contract, and every event links to its transaction. Each step also gives the command to get the same answer from your own terminal.</p></div>
      <div class="jhero-links">
        <a class="btn primary" href="#/vault/${VAULT}">Open vault #${VAULT} →</a>
        <a class="btn" target="_blank" rel="noreferrer" href="${NEAR_EXPLORER}/address/${encodeURIComponent(CONTRACT)}">Contract on NEAR ↗</a>
        <a class="btn" id="j-eth-link" target="_blank" rel="noreferrer" href="${EXPLORER[SEPOLIA]}">Vault #${VAULT} on Sepolia ↗</a>
      </div>
    </section>

    <div class="card jinvariant"><div class="body jinv-grid">
      <div><h3 class="jinv-title">What you are checking</h3>
        <p class="muted">The agent never holds a key. It can only <b>ask</b> the NEAR contract for a payment. The contract checks the vault's rules; only then does NEAR's signing network (Chain Signatures) sign, and only after the waiting time, during which a guardian can stop it. A fooled agent can ask for anything: what leaves the vault is limited by the rules.</p>
        <div class="jfacts" id="j-facts">
          <div><span>Daily limit</span><b class="mono">…</b></div><div><span>Waiting time</span><b class="mono">…</b></div>
          <div><span>Guardian</span><b class="mono">…</b></div><div><span>Keys on the contract</span><b class="mono">…</b></div>
        </div></div>
      <div class="jpath" aria-label="The path of a payment">
        <div class="jpath-title mono">The path of a payment</div>
        <div class="jnode warn"><b>AI agent</b><span>can be fooled; holds no key</span></div><div class="jarrow">↓ asks</div>
        <div class="jnode ok"><b>NEAR contract</b><span>checks limit, recipient, waiting time, guardian</span></div><div class="jarrow">↓ only if it passes</div>
        <div class="jnode"><b>NEAR signing network</b><span>signs what the contract sent</span></div><div class="jarrow">↓</div>
        <div class="jnode"><b>Ethereum (Sepolia)</b><span>a refused payment never gets here</span></div>
      </div>
    </div></div>

    <section class="card jstep">${stepHead('01', `Read vault #${VAULT}'s rules from the contract`, 'Read-only, no wallet, no fee.', 'read-only')}
      <div class="body jsplit">
        <dl class="jspecs" id="j-specs"><div><dt>Reading the contract…</dt><dd></dd></div></dl>
        <div>${code('Same answer from your terminal (near-cli-rs)', cli('get_policy', { token_id: VAULT }))}
          <div class="term"><div class="term-head"><span class="term-dots"><i></i><i></i><i></i></span><span>What the contract answers right now</span></div><pre class="mono" id="j-policy-json">Loading…</pre></div></div>
      </div></section>

    <section class="card jstep">${stepHead('02', 'A prompt injection against the agent', 'What happened when the agent was given fake invoices (recorded runs, each linked to its transaction).', 'recorded on testnet', 'bad')}
      <div class="body">
        <ul class="run-list">${runLine(injection)}${runLine(unknown)}</ul>
        <p class="muted">The agent tried to pay both. The contract refused them, so nothing was signed and nothing reached Ethereum. With a real model (gpt-5-mini), the model itself declined the first one and tried to pay the second, which the contract refused: <a href="#/vault/${VAULT}">see both runs in vault #${VAULT}</a>.</p>
        <a class="btn primary" href="#/try">Write your own fake invoice →</a>
      </div></section>

    <section class="card jstep">${stepHead('03', 'Ask for more than the daily limit', `The live contract is asked now whether it would sign 0.05 ETH to vault #${VAULT}'s approved address.`, 'live answer', 'warn')}
      <div class="body jsplit">
        <div><div class="label">Today's limit</div><div class="capbar" id="j-capbar"><span class="cap-used"></span></div>
          <div class="capbar-legend mono" id="j-caplegend">Reading the contract…</div>
          <div class="verdict" id="j-verdict"><div class="muted">Asking the contract…</div></div></div>
        <div>${code('Same question from your terminal', cli('check_transaction', { token_id: VAULT, tx: OVER_CAP }), 'Change <span class="mono">value</span> to <span class="mono">100000000000000</span> (0.0001 ETH) and it is allowed; change <span class="mono">to</span> to any other address and it is refused with <span class="mono">destination not allowed</span>.')}</div>
      </div></section>

    <section class="card jstep">${stepHead('04', 'The waiting time and the guardian', 'A fake invoice that was inside the rules: the agent asked, it waited, the guardian stopped it.', 'human veto', 'ok')}
      <div class="body">
        <ol class="jtimeline">
          <li><span class="mono">1</span><div><b>The agent asks</b><p>“${esc(vetoed.request)}” Inside the rules, so the contract accepts the request but does not sign it yet. ${vetoed.near ? nearTx(vetoed.near, 'request') : ''}</p></div></li>
          <li><span class="mono">2</span><div><b>It waits ${'<span id="j-delay">60 seconds</span>'}</b><p>The request is public on NEAR. The guardian can be alerted by Telegram or by an open browser tab (optional, run by the guardian).</p></div></li>
          <li class="bad"><span class="mono">3</span><div><b>The guardian stops it</b><p>Only the guardian account can do this; it cannot spend. ${vetoed.guardianTx ? nearTx(vetoed.guardianTx, 'guardian stop') : ''}</p></div></li>
          <li class="ok"><span class="mono">4</span><div><b>Nothing is signed</b><p>No signature was asked for, so no transaction exists on Sepolia. For contrast, a real invoice waited the same 60 s and was paid: ${paid.receipt ? sepTx(paid.receipt, 'Sepolia payment') : ''}</p></div></li>
        </ol>
        <div class="jproof-cta"><div><b>Check that the vault's key signed what reached Ethereum.</b>
          <span class="muted">In vault #${VAULT}'s payment history, "Check this signature" recovers the signer from each signature in your browser and compares it with the vault's address and the Sepolia transaction.</span></div>
          <a class="btn primary" href="#/vault/${VAULT}?history">Check a signature →</a></div>
      </div></section>

    <section class="card jstep">${stepHead('05', 'Nobody can change the contract', 'The deployed code equals the published build, and the contract account has no keys.', 'verifiable')}
      <div class="body jsplit">
        <div><p class="muted">The <a href="#/verify">Verify page</a> compares the deployed code with the reproducible build, lists the contract's access keys (none) and re-checks every transaction cited in the README.</p>
          <a class="btn primary" href="#/verify">Open the Verify page →</a></div>
        <div>${code('Access keys of the contract (expect "keys": [])', rpcCurl('view_access_key_list'))}${code('Hash of the deployed code (compare with the README)', rpcCurl('view_account'))}</div>
      </div></section>

    <section class="jdeck">
      <div class="section-head col"><div class="eyebrow">Ready to paste</div><h2 class="big-h">More commands</h2>
        <p class="muted" style="margin:0">All read-only. Each was run against testnet before being published here. <span class="mono">curl</span> versions need <span class="mono">jq</span>.</p></div>
      <div class="jdeck-grid">
        ${code("Vault #78's Ethereum address and signing path (curl)", curlOf('vault_info', { token_id: VAULT }))}
        ${code('Would this payment to an unknown address pass? (near-cli-rs)', cli('check_transaction', { token_id: VAULT, tx: txOf('0x9999999999999999999999999999999999999999', '100000000000000') }))}
        ${code("Payments waiting in vault #78 (near-cli-rs)", cli('list_proposals', { token_id: VAULT }))}
        <div class="term jchecklist"><div class="term-head"><span>What has been tested, and where</span></div><ul>
          <li><a target="_blank" rel="noreferrer" href="${REPO}/actions/workflows/tests.yml">49/49 attacks from the threat model blocked in a local sandbox (CI) ↗</a></li>
          <li><a target="_blank" rel="noreferrer" href="${REPO}/blob/main/scripts/bench/results.md">Benchmark: 78 attack invoices, naive agent vs. contract ↗</a></li>
          <li><a target="_blank" rel="noreferrer" href="${REPO}/blob/main/scripts/bench/results-external.md">91 attacks written by other AIs: 73 blocked ↗</a></li>
          <li><a target="_blank" rel="noreferrer" href="${REPO}/blob/main/docs/DETAILS.md">Known limits, stated plainly (no independent human audit yet) ↗</a></li>
        </ul></div>
      </div>
    </section>`;

  app.querySelectorAll<HTMLButtonElement>('[data-copy]').forEach((b) => (b.onclick = () => {
    const text = document.getElementById(b.dataset.copy!)?.textContent ?? '';
    navigator.clipboard?.writeText(text).then(() => { b.textContent = 'Copied'; setTimeout(() => (b.textContent = 'Copy'), 1500); }, () => {});
  }));

  const [policy, info, keys] = await Promise.all([
    view<any>('get_policy', { token_id: VAULT }),
    view<any>('vault_info', { token_id: VAULT }),
    nearRpc('query', { request_type: 'view_access_key_list', finality: 'final', account_id: CONTRACT }).catch(() => null),
  ]);
  if (!isCurrent()) return;
  const p = policy.policy;
  const now = Date.now();
  const spentToday = now >= Number(policy.spend.eth.start_ms) + DAY_MS ? 0n : BigInt(policy.spend.eth.spent);
  const cap = BigInt(p.eth_daily_cap);
  const delayS = Math.round(p.delay_ms / 1000);
  const delayText = delayS % 60 === 0 && delayS >= 60 ? `${delayS / 60} minute${delayS === 60 ? '' : 's'}` : `${delayS} seconds`;
  const nKeys = keys?.keys?.length;

  const facts = document.getElementById('j-facts');
  if (facts) facts.innerHTML = [
    ['Daily limit', `${eth(cap)} / day`], ['Waiting time', delayText], ['Guardian', esc(short(p.guardian ?? 'none', 16, 8))],
    ['Keys on the contract', nKeys === undefined ? 'could not read' : String(nKeys)],
  ].map(([k, v]) => `<div><span>${k}</span><b class="mono">${v}</b></div>`).join('');

  const ethLink = document.getElementById('j-eth-link') as HTMLAnchorElement | null;
  if (ethLink && info.evm_address) ethLink.href = `${EXPLORER[SEPOLIA]}/address/${info.evm_address}`;
  const delayEl = document.getElementById('j-delay');
  if (delayEl) delayEl.textContent = delayText;

  const specs = document.getElementById('j-specs');
  if (specs) specs.innerHTML = [
    ['Chain', 'Ethereum Sepolia (11155111)'],
    ["Vault's Ethereum address", `<a target="_blank" rel="noreferrer" href="${EXPLORER[SEPOLIA]}/address/${esc(info.evm_address)}">${esc(short(info.evm_address, 8, 6))} ↗</a>`],
    ['Approved recipients', p.allowed_destinations.map((a: string) => esc(short(a, 8, 6))).join('<br>') || 'none'],
    ['Daily limit', `${eth(cap)} / day`],
    ['Spent in this 24 h window', eth(spentToday)],
    ['Waiting time', delayText],
    ['Guardian (can stop, cannot spend)', esc(p.guardian ?? 'none')],
    ['Agent (can ask, cannot change rules)', esc(p.proposer ?? 'none')],
    ['Signed by', esc(info.signer_id)],
  ].map(([k, v]) => `<div><dt>${k}</dt><dd class="mono">${v}</dd></div>`).join('') +
    '<p class="faint jspecs-note">No wallet signature was needed: anyone can read this from NEAR.</p>';
  const json = document.getElementById('j-policy-json');
  if (json) json.textContent = JSON.stringify(policy, null, 2);

  const used = Number((spentToday * 1000n) / (cap || 1n)) / 10;
  const bar = document.getElementById('j-capbar');
  if (bar) bar.innerHTML = `<span class="cap-used" style="width:${Math.min(100, used)}%"></span><span class="cap-over"></span>`;
  const legend = document.getElementById('j-caplegend');
  if (legend) legend.innerHTML = `<span>${eth(spentToday)} spent</span><span>${eth(cap)} limit</span><span class="bad-text">asked: 0.05 ETH</span>`;

  const r = await view<any>('check_transaction', { token_id: VAULT, tx: OVER_CAP }).catch((e) => ({ error: String(e?.message ?? e) }));
  if (!isCurrent()) return;
  const v = document.getElementById('j-verdict');
  if (!v) return;
  if (r.error) v.innerHTML = `<div class="muted">Could not ask the contract right now: ${esc(r.error)}</div>`;
  else if (r.allowed) { v.className = 'verdict ok'; v.innerHTML = '<div class="big">The contract would allow it</div><div class="muted">The vault\'s rules changed since this page was written.</div>'; }
  else { v.className = 'verdict bad'; v.innerHTML = `<div class="big">✕ Refused by the contract</div><div class="muted">The contract answered: <span class="mono">"${esc(r.reason)}"</span>. Nothing is signed, so nothing can reach Ethereum, whatever the agent was told.</div>`; }
}
