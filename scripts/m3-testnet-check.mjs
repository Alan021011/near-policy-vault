// M3 review checks on testnet (R1, R2, R4). Uses the NEAR CLI (`near`) to send transactions
// signed with keys from the OS keychain, and the RPC to read results. Prints PASS/FAIL per check.
//
// Usage: node m3-testnet-check.mjs <owner-account> <vault-contract> <receiver-contract>
// Example: node m3-testnet-check.mjs alan-vault-2026.testnet m3.alan-vault-2026.testnet recv.alan-vault-2026.testnet
// The owner and the vault contract must have their keys in the keychain (the vault contract
// account acts as an "approved marketplace"). Each run mints 4 vaults (0.1 NEAR each, most refunded).
import { spawnSync } from 'node:child_process';
import { homedir } from 'node:os';
import { join } from 'node:path';

const [OWNER, VAULT, RECV] = process.argv.slice(2);
if (!RECV) throw new Error('usage: node m3-testnet-check.mjs <owner> <vault-contract> <receiver>');
const NEAR = process.env.NEAR_CLI || join(homedir(), '.cargo', 'bin', process.platform === 'win32' ? 'near.exe' : 'near');
const RPC = process.env.NEAR_RPC || 'https://rpc.testnet.near.org';
const BYTE_COST = 10n ** 19n; // yoctoNEAR per byte of storage on NEAR
let failures = 0;

function check(name, ok, detail = '') {
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${detail ? '  — ' + detail : ''}`);
  if (!ok) failures++;
}

// The public RPC rate-limits bursts, so retry with growing waits.
async function rpc(method, params, attempt = 1) {
  try {
    const res = await fetch(RPC, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
    });
    if (res.status === 429 || res.status >= 500) throw new Error(`HTTP ${res.status}`);
    const j = await res.json();
    if (j.error) throw new Error(`${method}: ${JSON.stringify(j.error)}`);
    return j.result;
  } catch (e) {
    if (attempt >= 5) throw e;
    await new Promise((r) => setTimeout(r, 2000 * attempt));
    return rpc(method, params, attempt + 1);
  }
}

async function view(method, args) {
  const r = await rpc('query', {
    request_type: 'call_function', finality: 'final', account_id: VAULT, method_name: method,
    args_base64: Buffer.from(JSON.stringify(args)).toString('base64'),
  });
  return JSON.parse(Buffer.from(r.result).toString());
}

/** Sends a function call with the CLI and returns the transaction outcome from the RPC. */
async function call(signer, method, args, deposit, gas = '100 Tgas') {
  // The CLI prints the transaction id on stderr, so both streams are read.
  const p = spawnSync(NEAR, ['contract', 'call-function', 'as-transaction', VAULT, method,
    'json-args', JSON.stringify(args), 'prepaid-gas', gas, 'attached-deposit', deposit,
    'sign-as', signer, 'network-config', 'testnet', 'sign-with-keychain', 'send'],
    { encoding: 'utf8' });
  const out = (p.stdout || '') + (p.stderr || '');
  const m = out.match(/Transaction ID: (\w+)/);
  if (!m) throw new Error(`no transaction id for ${method}:\n${out}`);
  const tx = await rpc('EXPERIMENTAL_tx_status', { tx_hash: m[1], sender_account_id: signer, wait_until: 'FINAL' });
  const logs = tx.receipts_outcome.flatMap((r) => r.outcome.logs);
  // NEAR transfers created by the vault contract (gas refunds come from "system" and are excluded).
  const refunds = tx.receipts
    .filter((r) => r.predecessor_id === VAULT && r.receipt.Action)
    .flatMap((r) => r.receipt.Action.actions
      .filter((a) => a.Transfer)
      .map((a) => ({ to: r.receiver_id, amount: BigInt(a.Transfer.deposit) })));
  return { hash: m[1], logs, refunds, out };
}

const events = (logs, name) => logs
  .filter((l) => l.startsWith('EVENT_JSON:'))
  .map((l) => JSON.parse(l.slice('EVENT_JSON:'.length)))
  .filter((e) => e.event === name);
const approvalBytes = (id) => BigInt(id.length + 4 + 8);
const owner = async (t) => (await view('nft_token', { token_id: t })).owner_id;

async function mint() {
  const r = await call(OWNER, 'mint_vault', {}, '0.1 NEAR');
  return events(r.logs, 'nft_mint')[0].data[0].token_ids[0];
}

// ---------- A. Approved account transfers (R1) and approvals are refunded (R4) ----------
{
  const t = await mint();
  await call(OWNER, 'nft_approve', { token_id: t, account_id: VAULT }, '0.01 NEAR');
  await call(OWNER, 'nft_approve', { token_id: t, account_id: RECV }, '0.01 NEAR');
  const r = await call(VAULT, 'nft_transfer', { receiver_id: RECV, token_id: t }, '1 yoctoNEAR');
  check(`A token ${t}: owner is now the receiver`, (await owner(t)) === RECV);
  const lib = events(r.logs, 'nft_transfer')[0]?.data[0] ?? {};
  check('A library nft_transfer event omits authorized_id (upstream bug, documented)', !('authorized_id' in lib), JSON.stringify(lib));
  const ours = events(r.logs, 'vault_transfer')[0]?.data[0] ?? {};
  check('A our vault_transfer event names the approved account', ours.authorized_id === VAULT, JSON.stringify(ours));
  const expected = (approvalBytes(VAULT) + approvalBytes(RECV)) * BYTE_COST;
  const got = r.refunds.filter((x) => x.to === OWNER).reduce((s, x) => s + x.amount, 0n);
  check('A approval storage refunded to the previous owner (R4)', got === expected, `expected ${expected}, got ${got}`);
  const info = await view('vault_transfer_info', { token_id: t });
  check('A on-chain record: count 1, authorized_id set', info.count === 1 && info.last.authorized_id === VAULT, JSON.stringify(info));
}

// ---------- B. transfer_call kept by the receiver (R2) refunds approvals in resolve (R4) ----------
{
  const t = await mint();
  await call(OWNER, 'nft_approve', { token_id: t, account_id: VAULT }, '0.01 NEAR');
  const r = await call(OWNER, 'nft_transfer_call', { receiver_id: RECV, token_id: t, msg: 'keep' }, '1 yoctoNEAR', '150 Tgas');
  check(`B token ${t}: receiver kept it`, (await owner(t)) === RECV);
  check('B receiver was called', r.logs.some((l) => l.includes(`nft_on_transfer token=${t}`)));
  const kinds = events(r.logs, 'vault_transfer').map((e) => e.data[0].kind);
  check('B events: one transfer_call, no return', JSON.stringify(kinds) === '["transfer_call"]', JSON.stringify(kinds));
  const got = r.refunds.filter((x) => x.to === OWNER).reduce((s, x) => s + x.amount, 0n);
  check('B approval storage refunded after resolve (R4)', got === approvalBytes(VAULT) * BYTE_COST, `got ${got}`);
}

// ---------- C. transfer_call returned by the receiver (R2): owner and approvals restored ----------
{
  const t = await mint();
  await call(OWNER, 'nft_approve', { token_id: t, account_id: VAULT }, '0.01 NEAR');
  const r = await call(OWNER, 'nft_transfer_call', { receiver_id: RECV, token_id: t, msg: 'return' }, '1 yoctoNEAR', '150 Tgas');
  check(`C token ${t}: back with the original owner`, (await owner(t)) === OWNER);
  check('C previous approval restored', await view('nft_is_approved', { token_id: t, approved_account_id: VAULT }));
  const kinds = events(r.logs, 'vault_transfer').map((e) => e.data[0].kind);
  check('C events: transfer_call then transfer_call_returned', JSON.stringify(kinds) === '["transfer_call","transfer_call_returned"]', JSON.stringify(kinds));
  check('C no approval refund when the token comes back', r.refunds.filter((x) => x.to === OWNER).length === 0);
  const info = await view('vault_transfer_info', { token_id: t });
  check('C on-chain record: count 2, last is the return', info.count === 2 && info.last.kind === 'transfer_call_returned', JSON.stringify(info));
}

// ---------- D. receiver fails (R2): the token must come back ----------
{
  const t = await mint();
  const r = await call(OWNER, 'nft_transfer_call', { receiver_id: RECV, token_id: t, msg: 'panic' }, '1 yoctoNEAR', '150 Tgas');
  check(`D token ${t}: back with the original owner after receiver panic`, (await owner(t)) === OWNER);
  const kinds = events(r.logs, 'vault_transfer').map((e) => e.data[0].kind);
  check('D events: transfer_call then transfer_call_returned', JSON.stringify(kinds) === '["transfer_call","transfer_call_returned"]', JSON.stringify(kinds));
}

console.log(failures === 0 ? '\nALL CHECKS PASSED' : `\n${failures} CHECK(S) FAILED`);
process.exit(failures === 0 ? 0 : 1);
