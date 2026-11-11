// Policy Vault MCP server (M38): lets any MCP client (Claude Code, Claude Desktop, other agents) read
// a vault, ask the live contract whether a payment would pass, see what is waiting and, when an agent
// account is configured, propose a payment. Nothing else.
//
// Its only write: when POLICY_VAULT_AGENT is set, `propose_payment` signs and sends ONE kind of NEAR
// transaction, a call to the contract's `propose` as the vault's agent (through the NEAR CLI, with the
// agent's key from the system keychain; the server itself holds no key). The contract checks the
// proposal against the rules; the payment then waits the vault's waiting time and the guardian can
// stop it. What it can NEVER do: sign or broadcast the vault's Ethereum transaction (it has no
// `execute_proposal`), veto, cancel, change the rules, sell or move a vault. There is no such tool.
//
// Transport: MCP over stdio (JSON-RPC 2.0, one message per line), written by hand so the server has
// no dependency beyond what scripts/ already uses (viem).
//
//   Read-only:         node scripts/mcp-server.mjs
//   With proposing:    POLICY_VAULT_AGENT=<agent>.testnet node scripts/mcp-server.mjs
//   Other contract:    POLICY_VAULT_CONTRACT=<contract>.testnet (default m3.alan-vault-2026.testnet)
//
// Claude Code:  claude mcp add policy-vault -- node /path/to/near-policy-vault/scripts/mcp-server.mjs
// (or see .mcp.json at the repository root).
import { spawnSync } from 'node:child_process';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { createInterface } from 'node:readline';
import { formatEther, parseEther } from 'viem';
import { historyFromSigned, riskSignals } from '../web/src/risk.mjs';

const CONTRACT = process.env.POLICY_VAULT_CONTRACT || 'm3.alan-vault-2026.testnet';
const AGENT = process.env.POLICY_VAULT_AGENT || null;
const NEAR_RPC = process.env.NEAR_RPC || 'https://rpc.testnet.fastnear.com';
const ETH_RPC = process.env.ETH_RPC || 'https://sepolia.gateway.tenderly.co';
const NEAR = process.env.NEAR_CLI || join(homedir(), '.cargo', 'bin', process.platform === 'win32' ? 'near.exe' : 'near');
const SITE = 'https://alan021011.github.io/near-policy-vault/';
const EXPLORER = { 11155111: 'https://sepolia.etherscan.io' };
const log = (...a) => console.error('[policy-vault mcp]', ...a); // stdout is reserved for the protocol

// ---------- chain reads ----------
async function view(method, args) {
  for (let i = 1; ; i++) {
    try {
      const j = await fetch(NEAR_RPC, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'query',
        params: { request_type: 'call_function', finality: 'final', account_id: CONTRACT, method_name: method, args_base64: Buffer.from(JSON.stringify(args)).toString('base64') } }) }).then((r) => r.json());
      if (j.error) throw new Error(j.error.cause?.info?.error_message ?? j.error.data ?? JSON.stringify(j.error).slice(0, 200));
      return JSON.parse(Buffer.from(j.result.result).toString());
    } catch (e) {
      if (i >= 3 || /does not exist|panicked/i.test(String(e.message))) throw e;
      await new Promise((r) => setTimeout(r, 500 * i));
    }
  }
}
async function eth(method, params) {
  const j = await fetch(ETH_RPC, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }) }).then((r) => r.json());
  if (j.error) throw new Error(j.error.message);
  return j.result;
}
async function fees() {
  const block = await eth('eth_getBlockByNumber', ['latest', false]);
  const prio = 1_000_000_000n;
  return { max_priority_fee_per_gas: prio.toString(), max_fee_per_gas: (BigInt(block.baseFeePerGas) * 2n + prio).toString() };
}
const ethStr = (wei) => `${formatEther(BigInt(wei))} ETH`;
const idOf = (a) => {
  const id = String(a?.token_id ?? '').trim();
  if (!/^[0-9]+$/.test(id)) throw new Error('token_id must be a vault number, e.g. "78"');
  return id;
};
const addrOf = (a) => {
  const to = String(a?.to ?? '').trim().toLowerCase();
  if (!/^0x[0-9a-f]{40}$/.test(to)) throw new Error('to must be an Ethereum address (0x followed by 40 hex characters)');
  return to;
};
const weiOf = (a) => {
  const s = String(a?.amount_eth ?? '').trim();
  if (!/^[0-9]+(\.[0-9]{1,18})?$/.test(s)) throw new Error('amount_eth must be a decimal number of ETH, e.g. "0.0001"');
  return parseEther(s).toString();
};

/** Daily budget left now: the contract charges value plus worst-case gas against a 24-hour window. */
function budget(pol) {
  const cap = BigInt(pol.policy.eth_daily_cap);
  const spent = BigInt(pol.spend?.eth?.spent ?? '0');
  const start = Number(pol.spend?.eth?.start_ms ?? 0);
  const open = spent > 0n && Date.now() < start + 86_400_000;
  return { cap, spent: open ? spent : 0n, left: open ? (cap > spent ? cap - spent : 0n) : cap, resets_at: open ? new Date(start + 86_400_000).toISOString() : null };
}
async function context(id) {
  const [pol, next, proposals] = await Promise.all([view('get_policy', { token_id: id }), view('get_next_nonce', { token_id: id }), view('list_proposals', { token_id: id })]);
  const signed = next > 0 ? await view('list_signed', { token_id: id, from_nonce: Math.max(0, next - 20), limit: 100 }) : [];
  return { pol, next, proposals, signed, history: historyFromSigned(signed) };
}
const signsText = (signs) => (signs.length ? signs.map((s) => `  [${s.level}] ${s.text}`).join('\n') : '  none');

// ---------- tools ----------
const TOKEN = { token_id: { type: 'string', description: 'The vault number, e.g. "78"' } };
const PAYMENT = { ...TOKEN, to: { type: 'string', description: 'Recipient Ethereum address (0x…)' }, amount_eth: { type: 'string', description: 'Amount in ETH, as a decimal string, e.g. "0.0001"' } };
const TOOLS = [
  {
    name: 'get_vault',
    description: 'Read a Policy Vault: its Ethereum address and chain, owner, rules (daily limit, approved recipients, waiting time, guardian, agent), the budget left today and how many payments are waiting. Read-only.',
    inputSchema: { type: 'object', properties: TOKEN, required: ['token_id'] },
    async run(a) {
      const id = idOf(a);
      const [info, token, pol, proposals] = await Promise.all([view('vault_info', { token_id: id }), view('nft_token', { token_id: id }), view('get_policy', { token_id: id }), view('list_proposals', { token_id: id })]);
      if (!token) throw new Error(`vault ${id} does not exist`);
      const lines = [`Vault ${id} on ${CONTRACT} (${SITE}#/vault/${id})`, `Owner: ${token.owner_id}`, `Ethereum account: ${info.evm_address}`];
      if (!pol.has_policy) return [...lines, 'No rules yet: the vault cannot pay anything until its owner sets them.'].join('\n');
      const p = pol.policy;
      const b = budget(pol);
      lines.push(`Chain id: ${p.chain_id}`, `Daily limit: ${ethStr(b.cap)} (value plus worst-case gas); left today: ${ethStr(b.left)}${b.resets_at ? `, resets at ${b.resets_at}` : ''}`,
        `Approved recipients: ${p.allowed_destinations.join(', ') || 'none'}`, `Waiting time before signing: ${p.delay_ms / 1000} s`,
        `Guardian (can stop a waiting payment): ${p.guardian ?? 'none'}`, `Agent (can propose and sign, never change the rules): ${p.proposer ?? 'none'}`,
        `Payments waiting: ${proposals.length}`);
      if (pol.pending) lines.push(`A looser rule change is waiting until ${new Date(pol.pending.apply_after_ms).toISOString()}.`);
      return lines.join('\n');
    },
  },
  {
    name: 'get_remaining_budget',
    description: 'How much ETH the vault can still sign today under its daily limit, and when the window resets. Read-only.',
    inputSchema: { type: 'object', properties: TOKEN, required: ['token_id'] },
    async run(a) {
      const pol = await view('get_policy', { token_id: idOf(a) });
      if (!pol.has_policy) return 'No rules yet: nothing can be signed.';
      const b = budget(pol);
      return `Left today: ${ethStr(b.left)} of ${ethStr(b.cap)} (each payment is charged its value plus worst-case gas).${b.resets_at ? ` The window resets at ${b.resets_at}.` : ' Nothing spent in the current window.'}`;
    },
  },
  {
    name: 'check_payment',
    description: 'Ask the live contract whether an ETH payment from the vault would pass its rules right now (read-only check_transaction; nothing is signed or queued), and list the warning signs a guardian would see (possible duplicate, new or look-alike recipient, unusual amount, suspicious invoice wording). Pass the invoice text when there is one.',
    inputSchema: { type: 'object', properties: { ...PAYMENT, invoice_text: { type: 'string', description: 'Optional: the invoice or request text, checked for warning signs' } }, required: ['token_id', 'to', 'amount_eth'] },
    async run(a) {
      const id = idOf(a);
      const ctx = await context(id);
      if (!ctx.pol.has_policy) return 'No rules yet: the contract would refuse every payment.';
      const tx = { chain_id: ctx.pol.policy.chain_id, nonce: ctx.next, ...(await fees()), gas_limit: 21000, to: addrOf(a), value: weiOf(a), data: '0x' };
      const r = await view('check_transaction', { token_id: id, tx });
      const signs = riskSignals({ tx, policy: ctx.pol.policy, history: ctx.history, pending: ctx.proposals.map((q) => ({ id: `request #${q.id}`, ...q.tx })), text: a.invoice_text });
      return [r.allowed ? `The contract would ACCEPT it: inside the rules. If proposed, it waits ${ctx.pol.policy.delay_ms / 1000} s and the guardian (${ctx.pol.policy.guardian ?? 'none'}) can stop it.`
        : `The contract would REFUSE it: ${r.reason}.`, 'Warning signs (advice only; the contract does not read them):', signsText(signs)].join('\n');
    },
  },
  {
    name: 'list_pending',
    description: 'The payments waiting in the vault: what each pays, when it can be signed, whether it is ready, and its warning signs. Read-only.',
    inputSchema: { type: 'object', properties: TOKEN, required: ['token_id'] },
    async run(a) {
      const id = idOf(a);
      const ctx = await context(id);
      if (!ctx.proposals.length) return 'Nothing is waiting.';
      const out = [];
      for (const p of ctx.proposals) {
        const c = await view('check_execution', { token_id: id, proposal_id: p.id });
        const signs = riskSignals({ tx: p.tx, policy: ctx.pol.policy, history: ctx.history, pending: ctx.proposals.filter((q) => q.id < p.id).map((q) => ({ id: `request #${q.id}`, ...q.tx })) });
        const when = Date.now() < p.executable_after_ms ? `can be signed at ${new Date(p.executable_after_ms).toISOString()}` : c.ready ? 'ready to sign' : `blocked: ${c.reason}`;
        out.push(`Request #${p.id}: ${ethStr(p.tx.value)} to ${p.tx.to}${p.tx.data && p.tx.data !== '0x' ? ' (with calldata)' : ''}; ${when}\n${signsText(signs)}`);
      }
      return out.join('\n\n');
    },
  },
  {
    name: 'get_payment_history',
    description: 'The latest payments the vault signed (up to 20), with their Ethereum transaction hashes. Cancelled nonces are left out. Read-only.',
    inputSchema: { type: 'object', properties: TOKEN, required: ['token_id'] },
    async run(a) {
      const id = idOf(a);
      const ctx = await context(id);
      if (!ctx.signed.length) return 'Nothing signed yet.';
      const chain = ctx.pol.has_policy ? ctx.pol.policy.chain_id : 11155111;
      return ctx.signed.filter((r) => Number(r.proposal_id) < 1e18).map((r) => {
        const h = historyFromSigned([r])[0];
        return `nonce ${r.nonce} · ${new Date(Number(r.signed_ms)).toISOString()} · ${h ? `${ethStr(h.value)} to ${h.to}${h.data !== '0x' ? ' (with calldata)' : ''}` : 'unreadable'} · ${EXPLORER[chain] ? `${EXPLORER[chain]}/tx/${r.tx_hash}` : r.tx_hash}`;
      }).join('\n');
    },
  },
];

// Proposing is the only write, and only when an agent account is configured.
if (AGENT) TOOLS.push({
  name: 'propose_payment',
  description: `Propose an ETH payment from the vault, as its agent (${AGENT}). The contract checks it against the vault's rules; if accepted, it waits the vault's waiting time and the guardian can stop it. It signs and sends only that NEAR proposal transaction (with the agent's key); it cannot sign or broadcast the vault's Ethereum transaction, veto or change rules. Costs a 0.05 NEAR deposit, refunded when the proposal ends. Check the warning signs with check_payment first.`,
  inputSchema: { type: 'object', properties: { ...PAYMENT, invoice_text: { type: 'string', description: 'Optional: the invoice text, checked for warning signs' } }, required: ['token_id', 'to', 'amount_eth'] },
  async run(a) {
    const id = idOf(a);
    const ctx = await context(id);
    if (!ctx.pol.has_policy) throw new Error('the vault has no rules yet');
    if (ctx.pol.policy.proposer !== AGENT) throw new Error(`${AGENT} is not this vault's agent (the agent is ${ctx.pol.policy.proposer ?? 'nobody'})`);
    const tx = { chain_id: ctx.pol.policy.chain_id, ...(await fees()), gas_limit: 21000, to: addrOf(a), value: weiOf(a), data: '0x' };
    const signs = riskSignals({ tx, policy: ctx.pol.policy, history: ctx.history, pending: ctx.proposals.map((q) => ({ id: `request #${q.id}`, ...q.tx })), text: a.invoice_text });
    const p = spawnSync(NEAR, ['contract', 'call-function', 'as-transaction', CONTRACT, 'propose', 'json-args', JSON.stringify({ token_id: id, tx }),
      'prepaid-gas', '100 Tgas', 'attached-deposit', '0.05 NEAR', 'sign-as', AGENT, 'network-config', 'testnet', 'sign-with-keychain', 'send'], { encoding: 'utf8' });
    const out = (p.stdout || '') + (p.stderr || '');
    const created = [...out.matchAll(/EVENT_JSON:(\{.*\})/g)].map((m) => { try { return JSON.parse(m[1]); } catch { return null; } }).find((e) => e?.event === 'proposal_created');
    const txId = out.match(/Transaction ID: ([1-9A-HJ-NP-Za-km-z]{43,44})/)?.[1];
    if (!created) {
      const why = out.match(/Smart contract panicked: (.*?)(?:"\)|\n|$)/)?.[1] ?? 'see the NEAR CLI output in the server log';
      if (!/panicked/.test(out)) log(out.slice(-600));
      return `The contract REFUSED the proposal: ${why}.${txId ? ` NEAR transaction ${txId}.` : ''}\nWarning signs:\n${signsText(signs)}`;
    }
    const pid = created.data[0].proposal_id;
    return `Proposed as request #${pid}${txId ? ` (NEAR transaction ${txId})` : ''}. It can be signed after ${ctx.pol.policy.delay_ms / 1000} s unless the guardian (${ctx.pol.policy.guardian ?? 'none'}) stops it: ${SITE}#/vault/${id}\nWarning signs the guardian sees:\n${signsText(signs)}`;
  },
});

// ---------- MCP over stdio ----------
const SERVER = { name: 'policy-vault', version: '0.1.0' };
const send = (msg) => process.stdout.write(JSON.stringify({ jsonrpc: '2.0', ...msg }) + '\n');
async function handle(m) {
  const reply = m.id !== undefined && m.id !== null;
  try {
    let result;
    switch (m.method) {
      case 'initialize':
        result = {
          protocolVersion: m.params?.protocolVersion ?? '2025-06-18',
          capabilities: { tools: {} },
          serverInfo: SERVER,
          instructions: `Policy Vault on NEAR testnet (${CONTRACT}). Each vault is an NFT that controls an Ethereum account; the contract signs only what the vault's rules allow. These tools read vaults and check payments${AGENT ? `, and propose payments as the agent ${AGENT}` : ''}. No tool can sign or broadcast the vault's Ethereum transactions, veto or change rules; proposing sends a NEAR transaction as the agent.`,
        };
        break;
      case 'ping': result = {}; break;
      case 'tools/list': result = { tools: TOOLS.map(({ name, description, inputSchema }) => ({ name, description, inputSchema })) }; break;
      case 'tools/call': {
        const tool = TOOLS.find((t) => t.name === m.params?.name);
        if (!tool) { result = { content: [{ type: 'text', text: `Unknown tool: ${m.params?.name}` }], isError: true }; break; }
        try {
          result = { content: [{ type: 'text', text: await tool.run(m.params?.arguments ?? {}) }] };
        } catch (e) {
          result = { content: [{ type: 'text', text: `Error: ${e.message}` }], isError: true };
        }
        break;
      }
      default:
        if (String(m.method).startsWith('notifications/')) return; // e.g. notifications/initialized
        if (reply) send({ id: m.id, error: { code: -32601, message: `Method not found: ${m.method}` } });
        return;
    }
    if (reply) send({ id: m.id, result });
  } catch (e) {
    if (reply) send({ id: m.id, error: { code: -32603, message: e.message } });
  }
}

const rl = createInterface({ input: process.stdin });
rl.on('line', (line) => {
  if (!line.trim()) return;
  let m;
  try { m = JSON.parse(line); } catch { send({ id: null, error: { code: -32700, message: 'Parse error' } }); return; }
  handle(m);
});
log(`ready on ${CONTRACT}${AGENT ? `, proposing as ${AGENT}` : ', read-only'}`);
