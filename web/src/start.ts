// Guided set-up (#/start): four steps to a first vault for someone new to crypto. It does not replace
// the vault page: it reuses the same two contract calls (mint_vault, then set_policy) and the same
// rules review (summarize, ruleWarnings), and keeps its draft in sessionStorage so a wallet pop-up or a
// reload does not lose it. Nothing here is simulated.
import { parseEther } from 'viem';
import { TEMPLATES, ruleWarnings, summarize, type TemplateKey } from './rules';
import { DEFAULT_CHAIN, EXPLORER, accountId, call, nearRpc, nearToYocto, view } from './near';

type Act = (label: string, f: () => Promise<any>, after?: (r: any) => void) => Promise<void>;
export interface StartDeps { act: Act; connect: () => Promise<void>; toast: (m: string, k?: 'ok' | 'bad' | '') => void }

interface Draft {
  template: TemplateKey; cap: string; delay: number; dest: string; agent: string; guardian: string;
  tokenId?: string; rulesSet?: boolean;
}
const KEY = 'pv-start-draft';
const fresh = (): Draft => ({ template: 'agent', cap: '0.01', delay: 3600, dest: '', agent: '', guardian: '' });
const load = (): Draft => { try { return { ...fresh(), ...JSON.parse(sessionStorage.getItem(KEY) ?? '{}') }; } catch { return fresh(); } };
const save = (d: Draft) => { try { sessionStorage.setItem(KEY, JSON.stringify(d)); } catch { /* private mode: keep in memory only */ } };
const esc = (s: unknown) =>
  String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!);
const isAddr = (a: string) => /^0x[0-9a-fA-F]{40}$/.test(a);
const isNear = (a: string) => /^(([a-z\d]+[-_])*[a-z\d]+\.)*([a-z\d]+[-_])*[a-z\d]+$/.test(a) && a.length >= 2 && a.length <= 64;
const addrs = (s: string) => s.split(/[\s,]+/).map((x) => x.trim().toLowerCase()).filter(Boolean);

const WAITS: [number, string][] = [[60, '1 minute (demos only)'], [600, '10 minutes'], [3600, '1 hour'], [6 * 3600, '6 hours'], [86400, '1 day']];
const STEPS = ['Connect a wallet', 'Set the rules', 'Choose a guardian', 'Create the vault'];
const GLOSSARY: [string, string][] = [
  ['Vault', 'An NFT in your NEAR wallet that controls its own Ethereum account. Whoever holds the NFT holds the account.'],
  ['Daily limit', 'The most ETH that can leave the vault in 24 hours, whoever asks.'],
  ['Waiting time', 'How long every payment waits before it is signed. The guardian can stop it during that time.'],
  ['Guardian', 'A person you trust (their NEAR account). They can stop a payment or a handover, never spend.'],
  ['Agent', 'An AI or a script that may ask for payments. It can never change the rules.'],
];

function policyOf(d: Draft) {
  return {
    chain_id: DEFAULT_CHAIN,
    delay_ms: d.delay * 1000,
    guardian: d.guardian.trim() || null,
    eth_daily_cap: parseEther(d.cap || '0').toString(),
    max_gas_cost: parseEther('0.002').toString(),
    allowed_destinations: addrs(d.dest),
    allowed_spenders: [] as string[],
    tokens: [] as any[],
    nfts: [] as any[],
    proposer: TEMPLATES[d.template].keepProposer ? d.agent.trim() || null : null,
  };
}

async function accountExists(id: string) {
  try { await nearRpc('query', { request_type: 'view_account', finality: 'final', account_id: id }); return true; } catch { return false; }
}

export async function startPage(app: HTMLElement, step: number, deps: StartDeps) {
  const d = load();
  const s = Math.min(4, Math.max(1, step || 1));
  const go = (n: number) => { location.hash = `#/start/${n}`; };
  const bar = `<ol class="stepper">${STEPS.map((t, i) => {
    const n = i + 1;
    const state = n < s ? 'done' : n === s ? 'now' : '';
    return `<li class="${state}"><a href="#/start/${n}"><span class="mono">${n < s ? '✓' : n}</span><div><small>Step ${n}</small><b>${t}</b></div></a></li>`;
  }).join('')}</ol>`;
  const glossary = `<div class="gloss"><b>In plain words</b>${GLOSSARY.map(([k, v]) => `<div><span>${k}</span>${v}</div>`).join('')}</div>`;
  const nav = (back: boolean, next: string, disabled = false) => `<div class="start-nav">${back ? `<a class="btn" href="#/start/${s - 1}">← Back</a>` : '<span></span>'}
    ${next ? `<button class="btn primary big" id="start-next" ${disabled ? 'disabled' : ''}>${next}</button>` : ''}</div>`;

  let body = '';
  if (s === 1) {
    body = `<div class="start-grid"><div>
      <h1>Your first vault, step by step</h1>
      <p class="lead">A vault gives an AI agent, or you, an Ethereum account with rules: a daily limit, approved recipients, a waiting time and a person who can say no. Nobody holds its key; a NEAR contract signs only what the rules allow.</p>
      <div class="card"><div class="body">
        <h3 style="margin-top:0">1 · Connect a NEAR wallet (testnet)</h3>
        ${accountId ? `<p class="ok-text">✓ Connected as <b class="mono">${esc(accountId)}</b>.</p>`
          : `<p class="muted">You need a free NEAR testnet wallet, for example <a href="https://wallet.meteorwallet.app" target="_blank" rel="noreferrer">Meteor Wallet ↗</a>, with a little test NEAR from a faucet such as <a href="https://near-faucet.io" target="_blank" rel="noreferrer">near-faucet.io ↗</a>. Creating a vault costs a 0.1 NEAR deposit for its storage, plus about 0.05 NEAR to save its rules (the unused part comes back). It is all test money.</p>
          <button class="btn primary big" id="start-connect">Connect wallet</button>`}
      </div></div>
      ${nav(false, 'Next: the rules →', !accountId)}</div>
      <div><div class="compare"><b>What changes with a vault</b>
        <div><span class="bad-text">Giving an agent a private key</span>Anyone who fools or hacks the agent can spend everything, at once.</div>
        <div><span class="warn-text">A multisig where a person signs each payment</span>Safe, but a person has to approve every bill: the agent saves no work.</div>
        <div><span class="ok-text">A Policy Vault</span>Normal bills are paid on their own. A fooled agent can lose at most one day's limit, only to approved addresses, and the guardian can stop what looks wrong while it waits.</div>
      </div>${glossary}</div></div>`;
  } else if (s === 2) {
    body = `<div class="start-grid"><div>
      <h1>2 · Set the rules</h1>
      <p class="lead">Start from a template; every field can be changed. The contract checks these rules before every signature.</p>
      <div class="tpl-cards">${(Object.keys(TEMPLATES) as TemplateKey[]).map((k) => `<button type="button" class="tpl ${d.template === k ? 'on' : ''}" data-tpl="${k}"><b>${esc(TEMPLATES[k].label)}</b><span>${esc(TEMPLATES[k].note)}</span></button>`).join('')}</div>
      <form id="start-rules" class="form">
        <label><div class="label">Daily limit (ETH)</div><input name="cap" value="${esc(d.cap)}" inputmode="decimal" /><div class="help">The most that can leave the vault in 24 hours. Start small: this is also the most a fooled agent can lose in a day.</div></label>
        <label><div class="label">Waiting time</div><select name="delay">${WAITS.map(([v, t]) => `<option value="${v}" ${d.delay === v ? 'selected' : ''}>${t}</option>`).join('')}</select><div class="help">Every payment waits this long; the guardian can stop it only during this time. With a person as guardian, use hours.</div></label>
        <label class="full"><div class="label">Approved recipients (Ethereum addresses, one per line)</div><textarea name="dest" rows="3" placeholder="0x…">${esc(d.dest)}</textarea><div class="help">The vault can pay only these addresses. You can add more later (that change waits the waiting time).</div></label>
        ${TEMPLATES[d.template].keepProposer ? `<label class="full"><div class="label">Agent's NEAR account (optional)</div><input name="agent" value="${esc(d.agent)}" placeholder="my-agent.testnet" /><div class="help">The account your AI or script uses. It may ask for payments; it can never change the rules, sell or move the vault.</div></label>` : ''}
      </form>
      ${nav(true, 'Next: the guardian →')}</div>
      <div><div class="card"><header><h2>These rules say</h2></header><div class="body"><div id="start-summary"></div><p class="faint" style="font-size:12px;margin:8px 0 0">The guardian is chosen in the next step.</p></div></div>${glossary}</div></div>`;
  } else if (s === 3) {
    body = `<div class="start-grid"><div>
      <h1>3 · Choose a guardian</h1>
      <p class="lead">A person you trust, with their own NEAR account. They can stop any payment while it waits, and stop a handover you did not start. They can never spend, change the rules or take the vault.</p>
      <form id="start-guard" class="form">
        <label class="full"><div class="label">Guardian's NEAR account</div><input name="guardian" value="${esc(d.guardian)}" placeholder="friend.testnet" /><div class="help">Not the agent's account, and better not your own: if your key is stolen, someone else should be able to stop the thief.</div></label>
      </form>
      <div id="guard-check" class="faint" style="font-size:13px"></div>
      ${nav(true, 'Next: review and create →')}</div>
      <div><div class="card"><header><h2>How the guardian hears about a payment</h2></header><div class="body">
        <ul class="plain">
          <li><b>In the browser:</b> on the home page, connected as the guardian, "Vaults I guard" lists their vaults and can watch them while the tab is open.</li>
          <li><b>On the phone (Telegram):</b> the guardian runs a small script, <span class="mono">scripts/guardian-alerts.mjs</span>, with their own Telegram bot. Each alert says why a payment looks unusual and links to the page where they stop it.</li>
          <li><b>Honest limit:</b> alerts only arrive while one of those runs. A payment nobody stops is paid when its waiting time ends.</li>
        </ul>
        <a target="_blank" rel="noreferrer" href="https://github.com/Alan021011/near-policy-vault/blob/main/scripts/guardian-alerts.mjs">How to set up the Telegram alerts ↗</a>
      </div></div>${glossary}</div></div>`;
  } else {
    const p = policyOf(d);
    const done = !!d.tokenId && !!d.rulesSet;
    body = `<div class="start-grid"><div>
      <h1>4 · Create the vault</h1>
      ${done ? `<div class="verdict ok"><div class="big">✓ Vault #${esc(d.tokenId)} is ready</div><div class="muted">Its rules are saved in the contract. Next: send it a little Sepolia test ETH, then let your agent ask for payments.</div></div>
        <div class="card"><div class="body" id="start-done"><p class="faint">Reading the vault…</p></div></div>
        <div class="start-nav"><button class="btn" id="start-reset">Start another vault</button><a class="btn primary big" href="#/vault/${esc(d.tokenId)}">Open vault #${esc(d.tokenId)} →</a></div>`
      : `<p class="lead">Two signatures in your wallet, one after the other. Each one says what it does before you sign.</p>
        <div class="card"><div class="body"><b>Your rules</b><ul class="plain">${summarize(p).map((x) => `<li>${esc(x)}</li>`).join('')}</ul>${warnsHtml(p)}</div></div>
        <ol class="sign-steps">
          <li class="${d.tokenId ? 'done' : 'now'}"><b>Create the vault NFT</b><span>0.1 NEAR deposit for its storage. ${d.tokenId ? `Done: vault #${esc(d.tokenId)}.` : 'It gets its own Ethereum address; with no rules yet it can pay nothing.'}</span>
            ${d.tokenId ? '' : '<button class="btn primary big" id="start-mint">Create the vault</button>'}</li>
          <li class="${d.tokenId ? 'now' : ''}"><b>Save the rules</b><span>About 0.05 NEAR deposit; the unused part comes back. The first rules of a vault apply at once.</span>
            ${d.tokenId ? '<button class="btn primary big" id="start-rules-sign">Save the rules</button>' : ''}</li>
        </ol>
        ${nav(true, '')}`}
      </div><div>${glossary}</div></div>`;
  }
  app.innerHTML = `<p><a href="#/">← Home</a> · <span class="faint">Guided set-up · testnet</span></p>${bar}${body}`;

  // ----- wiring -----
  if (s === 1) {
    document.getElementById('start-connect')?.addEventListener('click', () => deps.connect().catch((e) => deps.toast(String(e?.message ?? e), 'bad')));
    document.getElementById('start-next')?.addEventListener('click', () => go(2));
  }
  if (s === 2) {
    const form = document.getElementById('start-rules') as HTMLFormElement;
    const read = () => {
      const f = new FormData(form);
      d.cap = String(f.get('cap') ?? '').trim(); d.delay = Number(f.get('delay')); d.dest = String(f.get('dest') ?? '');
      if (f.has('agent')) d.agent = String(f.get('agent') ?? '').trim();
      save(d);
      let p;
      try { p = policyOf(d); } catch { document.getElementById('start-summary')!.innerHTML = '<p class="bad-text">The daily limit must be a number of ETH, e.g. 0.01.</p>'; return; }
      document.getElementById('start-summary')!.innerHTML = `<ul class="plain">${summarize(p).map((x) => `<li>${esc(x)}</li>`).join('')}</ul>${warnsHtml(p)}`;
    };
    form.addEventListener('input', read);
    document.querySelectorAll<HTMLButtonElement>('[data-tpl]').forEach((b) => (b.onclick = () => {
      d.template = b.dataset.tpl as TemplateKey; d.delay = TEMPLATES[d.template].delaySeconds; save(d); startPage(app, 2, deps);
    }));
    read();
    document.getElementById('start-next')!.onclick = () => {
      read();
      const bad = addrs(d.dest).find((a) => !isAddr(a));
      if (!/^\d*\.?\d+$/.test(d.cap)) return deps.toast('The daily limit must be a number of ETH, e.g. 0.01', 'bad');
      if (bad) return deps.toast(`"${bad}" is not an Ethereum address (0x and 40 characters)`, 'bad');
      if (d.agent && !isNear(d.agent)) return deps.toast(`"${d.agent}" is not a NEAR account name`, 'bad');
      go(3);
    };
  }
  if (s === 3) {
    const form = document.getElementById('start-guard') as HTMLFormElement;
    const out = document.getElementById('guard-check')!;
    form.addEventListener('input', () => { d.guardian = String(new FormData(form).get('guardian') ?? '').trim().toLowerCase(); save(d); out.textContent = ''; });
    document.getElementById('start-next')!.onclick = async () => {
      const g = d.guardian;
      if (g) {
        if (!isNear(g)) return deps.toast(`"${g}" is not a NEAR account name`, 'bad');
        if (g === d.agent) return deps.toast('The agent cannot also be the guardian: pick two different accounts', 'bad');
        out.textContent = 'Checking that the account exists on testnet…';
        if (!(await accountExists(g))) { out.innerHTML = `<span class="bad-text">${esc(g)} does not exist on NEAR testnet. Check the name.</span>`; return; }
      }
      if (d.agent && !(await accountExists(d.agent))) { out.innerHTML = `<span class="bad-text">The agent account ${esc(d.agent)} does not exist on NEAR testnet. Go back and check it.</span>`; return; }
      go(4);
    };
  }
  if (s === 4) {
    document.getElementById('start-mint')?.addEventListener('click', () => {
      if (!accountId) { deps.toast('Connect a wallet first (step 1)', 'bad'); return; }
      deps.act('Create vault', () => call('mint_vault', {}, nearToYocto('0.1'), 100n), (r) => {
        const t = r?.value?.token_id;
        if (t !== undefined) { d.tokenId = String(t); save(d); }
      });
    });
    document.getElementById('start-rules-sign')?.addEventListener('click', () => {
      const p = policyOf(d);
      deps.act('Set policy', () => call('set_policy', { token_id: d.tokenId, policy: p }, nearToYocto('0.05')), () => { d.rulesSet = true; save(d); });
    });
    document.getElementById('start-reset')?.addEventListener('click', () => { save(fresh()); go(1); });
    if (d.tokenId && d.rulesSet) {
      const info = await view<any>('vault_info', { token_id: d.tokenId }).catch(() => null);
      const el = document.getElementById('start-done');
      if (el && info?.evm_address) el.innerHTML = `<div class="label">The vault's Ethereum address (Sepolia)</div>
        <div class="mono" style="word-break:break-all;margin:4px 0 10px">${esc(info.evm_address)}</div>
        <div class="row"><button class="btn small" id="start-copy">Copy address</button>
          <a class="btn small" target="_blank" rel="noreferrer" href="${EXPLORER[DEFAULT_CHAIN]}/address/${esc(info.evm_address)}">See it on Etherscan ↗</a></div>
        <p class="faint" style="font-size:12.5px;margin-top:10px">Get free Sepolia test ETH from a public faucet, for example <a href="https://cloud.google.com/application/web3/faucet/ethereum/sepolia" target="_blank" rel="noreferrer">Google Cloud's ↗</a>, and send it to this address. Test ETH has no value.</p>`;
      document.getElementById('start-copy')?.addEventListener('click', () => navigator.clipboard?.writeText(info.evm_address).then(() => deps.toast('Address copied', 'ok'), () => {}));
    }
  }
}

function warnsHtml(p: ReturnType<typeof policyOf>) {
  const w = ruleWarnings(p);
  const label: Record<string, string> = { high: 'Warning', warn: 'Check', info: 'Note' };
  return w.length ? `<ul class="signs">${w.map((x) => `<li class="${x.level}"><b>${label[x.level]}:</b> ${esc(x.text)}</li>`).join('')}</ul>` : '<div class="signs-none">No weak spot found in these rules.</div>';
}
