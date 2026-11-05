// M5 checks on testnet: the spending policy of a vault, end to end with real accounts.
// - a new vault is locked; the first policy applies at once;
// - check_transaction allows what the policy allows, with the same signing hash as viem,
//   and refuses (with the reason) cap overruns, strangers, unlimited and 2^255 approvals;
// - loosening waits the delay: the guardian vetoes it, a stranger cannot, applying early fails,
//   applying after the delay works; tightening applies at once;
// - transferring the NFT clears the policy and refunds its storage to the seller.
//
// Usage: node m5-testnet-check.mjs <owner> <vault-contract> <guardian>
// The three accounts need keys in the keychain. Takes about 2 minutes (it waits a 60 s delay).
// Mints one vault (0.1 NEAR, mostly refunded) and transfers it to the guardian at the end.
import { spawnSync } from 'node:child_process';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { keccak256, serializeTransaction } from 'viem';

const [OWNER, VAULT, GUARDIAN] = process.argv.slice(2);
if (!GUARDIAN) throw new Error('usage: node m5-testnet-check.mjs <owner> <vault-contract> <guardian>');
const NEAR = process.env.NEAR_CLI || join(homedir(), '.cargo', 'bin', process.platform === 'win32' ? 'near.exe' : 'near');
const RPC = process.env.NEAR_RPC || 'https://rpc.testnet.near.org';
const DELAY_MS = 60_000;
const DEST = '0x1111111111111111111111111111111111111111';
const STRANGER = '0x2222222222222222222222222222222222222222';
const TOKEN = '0x' + 'aa'.repeat(20);
const SPENDER = '0x' + 'bb'.repeat(20);
let failures = 0;
// Events printed by the CLI ("EVENT_JSON:{...}"), parsed instead of matched as text.
const events = (out, name) => [...out.matchAll(/EVENT_JSON:(\{.*\})/g)]
  .map((m) => { try { return JSON.parse(m[1]); } catch { return null; } })
  .filter((e) => e && (!name || e.event === name));
const applied = (out) => events(out, 'policy_set')[0]?.data[0].applied;

const check = (name, ok, detail = '') => {
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${detail ? '  — ' + detail : ''}`);
  if (!ok) failures++;
};
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// The public RPC rate-limits bursts, so retry with growing waits.
async function rpc(method, params, attempt = 1) {
  try {
    const res = await fetch(RPC, { method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }) });
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
  const r = await rpc('query', { request_type: 'call_function', finality: 'final', account_id: VAULT,
    method_name: method, args_base64: Buffer.from(JSON.stringify(args)).toString('base64') });
  return JSON.parse(Buffer.from(r.result).toString());
}
async function call(signer, method, args, deposit, gas = '100 Tgas') {
  const p = spawnSync(NEAR, ['contract', 'call-function', 'as-transaction', VAULT, method,
    'json-args', JSON.stringify(args), 'prepaid-gas', gas, 'attached-deposit', deposit,
    'sign-as', signer, 'network-config', 'testnet', 'sign-with-keychain', 'send'], { encoding: 'utf8' });
  const out = (p.stdout || '') + (p.stderr || '');
  const id = out.match(/Transaction ID: (\w+)/)?.[1];
  let refunds = [];
  if (id) {
    const tx = await rpc('EXPERIMENTAL_tx_status', { tx_hash: id, sender_account_id: signer, wait_until: 'FINAL' });
    refunds = tx.receipts.filter((r) => r.predecessor_id === VAULT && r.receipt.Action)
      .flatMap((r) => r.receipt.Action.actions.filter((a) => a.Transfer)
        .map((a) => ({ to: r.receiver_id, amount: BigInt(a.Transfer.deposit) })));
  }
  return { out, refunds, panic: (out.match(/Smart contract panicked: (.*?)(?:"\)|\n|$)/) || [])[1] };
}

const policy = (capEth, guardian = GUARDIAN) => ({
  chain_id: 11155111,
  delay_ms: DELAY_MS,
  guardian,
  eth_daily_cap: String(BigInt(Math.round(capEth * 1e6)) * 10n ** 12n),
  max_gas_cost: String(21000n * 50n * 10n ** 9n),
  allowed_destinations: [DEST],
  allowed_spenders: [SPENDER],
  tokens: [{ contract: TOKEN, daily_cap: '1000000', max_approval: '500000' }],
});
const word = (v) => BigInt(v).toString(16).padStart(64, '0');
const approve = (amountHex64) => '0x095ea7b3' + '0'.repeat(24) + SPENDER.slice(2) + amountHex64;
const txInput = (o = {}) => ({
  chain_id: 11155111, nonce: 0, max_priority_fee_per_gas: '1000000000', max_fee_per_gas: '20000000000',
  gas_limit: 21000, to: DEST, value: '10000000000000000', data: '0x', ...o,
});

// ---------- new vault: locked, first policy applies at once ----------
const mint = await call(OWNER, 'mint_vault', {}, '0.1 NEAR');
const t = events(mint.out, 'nft_mint')[0]?.data[0].token_ids[0];
check('vault minted', t !== undefined);
let v = await view('get_policy', { token_id: t });
check(`vault ${t} starts locked`, v.has_policy === false);
let c = await view('check_transaction', { token_id: t, tx: txInput() });
check('locked vault refuses everything', !c.allowed && c.reason === 'vault has no policy (locked)', c.reason);

let r = await call(OWNER, 'set_policy', { token_id: t, policy: policy(0.1) }, '0.05 NEAR');
v = await view('get_policy', { token_id: t });
check('first policy applies at once', applied(r.out) === true && v.has_policy && v.policy.guardian === GUARDIAN);

// ---------- check_transaction ----------
const input = txInput();
c = await view('check_transaction', { token_id: t, tx: input });
const viemHash = keccak256(serializeTransaction({ type: 'eip1559', chainId: input.chain_id, nonce: input.nonce,
  maxPriorityFeePerGas: BigInt(input.max_priority_fee_per_gas), maxFeePerGas: BigInt(input.max_fee_per_gas),
  gas: BigInt(input.gas_limit), to: input.to, value: BigInt(input.value), data: input.data, accessList: [] }));
check('allowed transfer within the policy', c.allowed === true, c.reason ?? '');
check('signing hash equals viem for the same fields', c.signing_hash === viemHash, `${c.signing_hash} vs ${viemHash}`);
const refusals = [
  ['above the ETH daily cap', txInput({ value: '100000000000000000' }), 'ETH daily cap exceeded'],
  ['ETH to a stranger', txInput({ to: STRANGER }), 'destination not allowed'],
  ['other chain (mainnet)', txInput({ chain_id: 1 }), "chain_id is not the vault's chain"],
  ['gas limit 0 (unminable, review P2)', txInput({ gas_limit: 0 }), 'gas_limit below 21000'],
  ['max fee 0 (unminable, review P2)', txInput({ max_fee_per_gas: '0', max_priority_fee_per_gas: '0' }), 'max_fee_per_gas must be above 0'],
  ['approve above max_approval', txInput({ to: TOKEN, value: '0', data: approve(word(500001)) }), "approval above the token's max_approval"],
  ['unlimited approve (2^256-1)', txInput({ to: TOKEN, value: '0', data: approve('f'.repeat(64)) }), 'amount does not fit in 128 bits'],
  ['almost unlimited approve (2^255)', txInput({ to: TOKEN, value: '0', data: approve('8' + '0'.repeat(63)) }), 'amount does not fit in 128 bits'],
  ['arbitrary calldata', txInput({ data: '0xdeadbeef' }), 'calldata is not a plain transfer, ERC-20 transfer or approve'],
];
for (const [name, tx, reason] of refusals) {
  const x = await view('check_transaction', { token_id: t, tx });
  check(`refused: ${name}`, x.allowed === false && x.reason === reason, x.reason);
}
c = await view('check_transaction', { token_id: t, tx: txInput({ to: TOKEN, value: '0', data: approve(word(500000)) }) });
check('approve exactly at max_approval is allowed', c.allowed === true, c.reason ?? '');

// ---------- loosening waits; guardian veto ----------
r = await call(OWNER, 'set_policy', { token_id: t, policy: policy(1) }, '0.05 NEAR');
v = await view('get_policy', { token_id: t });
check('raising the cap is queued, not applied', applied(r.out) === false && v.pending && v.policy.eth_daily_cap === policy(0.1).eth_daily_cap);
r = await call(OWNER, 'veto_pending_policy', { token_id: t }, '1 yoctoNEAR');
check('the owner cannot veto as guardian', r.panic === 'Only the guardian can veto', r.panic);
r = await call(GUARDIAN, 'veto_pending_policy', { token_id: t }, '1 yoctoNEAR');
v = await view('get_policy', { token_id: t });
check('the guardian vetoes the pending change', !r.panic && v.pending === null, r.panic);

// ---------- loosening applies after the delay ----------
await call(OWNER, 'set_policy', { token_id: t, policy: policy(1) }, '0.05 NEAR');
r = await call(OWNER, 'apply_policy', { token_id: t }, '0 NEAR');
check('applying before the delay fails', r.panic === 'Pending policy not ready yet', r.panic);
console.log(`      waiting ${DELAY_MS / 1000 + 5} s for the delay...`);
await sleep(DELAY_MS + 5000);
r = await call(OWNER, 'apply_policy', { token_id: t }, '0 NEAR');
v = await view('get_policy', { token_id: t });
check('after the delay anyone can apply it', !r.panic && v.policy.eth_daily_cap === policy(1).eth_daily_cap && v.pending === null, r.panic);

// ---------- tightening applies at once ----------
r = await call(OWNER, 'set_policy', { token_id: t, policy: policy(0.01) }, '0.05 NEAR');
v = await view('get_policy', { token_id: t });
check('lowering the cap applies at once', applied(r.out) === true && v.policy.eth_daily_cap === policy(0.01).eth_daily_cap);

// ---------- review P3: the guardian cannot freeze the vault ----------
const t0 = Date.now();
r = await call(OWNER, 'set_policy', { token_id: t, policy: { ...policy(0.01), guardian: null } }, '0.05 NEAR');
v = await view('get_policy', { token_id: t });
const lockH = v.pending ? (v.pending.apply_after_ms - t0) / 3_600_000 : 0;
check('removing the guardian waits the long lock (3 days)', applied(r.out) === false && lockH > 71.9, `${lockH.toFixed(2)} h`);
r = await call(GUARDIAN, 'veto_pending_policy', { token_id: t }, '1 yoctoNEAR');
check('the guardian cannot veto its own replacement', r.panic === 'The guardian cannot veto its own replacement', r.panic);
r = await call(OWNER, 'cancel_pending_policy', { token_id: t }, '1 yoctoNEAR');
v = await view('get_policy', { token_id: t });
check('the owner can cancel the replacement', !r.panic && v.pending === null && v.policy.guardian === GUARDIAN, r.panic);

// ---------- transfer clears the policy (M8: through a sale window, which waits the delay) ----------
await call(OWNER, 'start_sale', { token_id: t }, '0.01 NEAR');
console.log(`      waiting ${DELAY_MS / 1000 + 5} s for the sale window to open...`);
await sleep(DELAY_MS + 5000);
r = await call(OWNER, 'nft_transfer', { receiver_id: GUARDIAN, token_id: t }, '1 yoctoNEAR');
v = await view('get_policy', { token_id: t });
check('after a transfer the buyer gets a locked vault', v.has_policy === false);
const back = r.refunds.filter((x) => x.to === OWNER).reduce((s, x) => s + x.amount, 0n);
check('policy storage refunded to the seller', back > 0n, `${back} yoctoNEAR`);

console.log(failures === 0 ? '\nALL CHECKS PASSED' : `\n${failures} CHECK(S) FAILED`);
process.exit(failures === 0 ? 0 : 1);
