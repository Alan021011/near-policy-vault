// M6 checks on testnet: queued proposals with real accounts.
// - a proposal must pass the policy; the daily cap is charged only when it is signed (M7);
// - the guardian vetoes, the owner cancels, nobody else can;
// - a proposal is not ready before the delay; after it, check_execution gives nonce 0 and the
//   same signing hash as viem; tightening the policy also stops queued proposals;
// - selling the NFT empties the queue, and the vault's next nonce does not reset.
//
// Usage: node m6-testnet-check.mjs <owner> <vault-contract> <guardian>
// Keys for the three accounts in the keychain. About 12 minutes (the sale window waits at least 10).
import { spawnSync } from 'node:child_process';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { keccak256, serializeTransaction } from 'viem';

const [OWNER, VAULT, GUARDIAN] = process.argv.slice(2);
if (!GUARDIAN) throw new Error('usage: node m6-testnet-check.mjs <owner> <vault-contract> <guardian>');
const NEAR = process.env.NEAR_CLI || join(homedir(), '.cargo', 'bin', process.platform === 'win32' ? 'near.exe' : 'near');
const RPC = process.env.NEAR_RPC || 'https://rpc.testnet.near.org';
const DELAY_MS = 60_000;
const DEST = '0x1111111111111111111111111111111111111111';
const CENTI = 10n ** 16n; // 0.01 ETH
let failures = 0;
// Events printed by the CLI ("EVENT_JSON:{...}"), parsed instead of matched as text.
const events = (out, name) => [...out.matchAll(/EVENT_JSON:(\{.*\})/g)]
  .map((m) => { try { return JSON.parse(m[1]); } catch { return null; } })
  .filter((e) => e && (!name || e.event === name));

const check = (name, ok, detail = '') => {
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${detail ? '  — ' + detail : ''}`);
  if (!ok) failures++;
};
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
// The public RPC rate-limits bursts, so retry with growing waits.
async function view(method, args, attempt = 1) {
  try {
    const res = await fetch(RPC, { method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'query', params: { request_type: 'call_function',
        finality: 'final', account_id: VAULT, method_name: method,
        args_base64: Buffer.from(JSON.stringify(args)).toString('base64') } }) });
    if (res.status === 429 || res.status >= 500) throw new Error(`HTTP ${res.status}`);
    const j = await res.json();
    if (j.error) throw new Error(JSON.stringify(j.error));
    return JSON.parse(Buffer.from(j.result.result).toString());
  } catch (e) {
    if (attempt >= 5) throw e;
    await sleep(2000 * attempt);
    return view(method, args, attempt + 1);
  }
}
function call(signer, method, args, deposit) {
  const p = spawnSync(NEAR, ['contract', 'call-function', 'as-transaction', VAULT, method,
    'json-args', JSON.stringify(args), 'prepaid-gas', '100 Tgas', 'attached-deposit', deposit,
    'sign-as', signer, 'network-config', 'testnet', 'sign-with-keychain', 'send'], { encoding: 'utf8' });
  const out = (p.stdout || '') + (p.stderr || '');
  return { out, panic: (out.match(/Smart contract panicked: (.*?)(?:"\)|\n|$)/) || [])[1] };
}
const policy = (capCenti) => ({
  chain_id: 11155111, delay_ms: DELAY_MS, guardian: GUARDIAN,
  eth_daily_cap: String(BigInt(capCenti) * CENTI), max_gas_cost: String(21000n * 50n * 10n ** 9n),
  allowed_destinations: [DEST], allowed_spenders: [], tokens: [],
});
const ptx = (centi) => ({ chain_id: 11155111, max_priority_fee_per_gas: '1000000000',
  max_fee_per_gas: '20000000000', gas_limit: 21000, to: DEST, value: String(BigInt(centi) * CENTI), data: '0x' });
const proposalId = (out) => events(out, 'proposal_created')[0]?.data[0].proposal_id;

// setup: new vault with a 0.1 ETH/day policy, 60 s delay
const t = events(call(OWNER, 'mint_vault', {}, '0.1 NEAR').out, 'nft_mint')[0]?.data[0].token_ids[0];
check('vault minted', t !== undefined);
call(OWNER, 'set_policy', { token_id: t, policy: policy(10) }, '0.05 NEAR');
check('policy in force', (await view('get_policy', { token_id: t })).has_policy);

// proposals queue; the cap is charged when signing (review P1), not when proposing
let r = call(OWNER, 'propose', { token_id: t, tx: ptx(6) }, '0.05 NEAR');
const a = proposalId(r.out);
check('proposal A (0.06 ETH) queued', a !== undefined && (await view('list_proposals', { token_id: t })).length === 1, r.panic);
r = call(OWNER, 'propose', { token_id: t, tx: ptx(6) }, '0.05 NEAR');
const b = proposalId(r.out);
check('proposal B (0.06 ETH) also queues; nothing charged yet', b !== undefined && (await view('get_policy', { token_id: t })).spend.eth.spent === '0', r.panic);
r = call(OWNER, 'propose', { token_id: t, tx: ptx(11) }, '0.05 NEAR');
check('a single proposal above the cap is refused', r.panic === 'ETH daily cap exceeded', r.panic);
let e = await view('check_execution', { token_id: t, proposal_id: Number(a) });
check('A not ready before the delay', !e.ready && e.reason === 'Proposal delay has not passed yet', e.reason);

// veto and cancel
r = call(OWNER, 'veto_proposal', { token_id: t, proposal_id: Number(a) }, '1 yoctoNEAR');
check('the owner cannot veto as guardian', r.panic === 'Only the guardian can veto', r.panic);
r = call(GUARDIAN, 'veto_proposal', { token_id: t, proposal_id: Number(a) }, '1 yoctoNEAR');
check('the guardian vetoes A', !r.panic && (await view('list_proposals', { token_id: t })).length === 1, r.panic);
const c = proposalId(call(OWNER, 'propose', { token_id: t, tx: ptx(1) }, '0.05 NEAR').out);
r = call(GUARDIAN, 'cancel_proposal', { token_id: t, proposal_id: Number(c) }, '1 yoctoNEAR');
check('the guardian cannot cancel as owner', r.panic === 'Only the vault owner can do this', r.panic);
r = call(OWNER, 'cancel_proposal', { token_id: t, proposal_id: Number(c) }, '1 yoctoNEAR');
check('the owner cancels C', !r.panic && (await view('list_proposals', { token_id: t })).length === 1, r.panic);

// after the delay
console.log(`      waiting ${DELAY_MS / 1000 + 5} s for the delay...`);
await sleep(DELAY_MS + 5000);
e = await view('check_execution', { token_id: t, proposal_id: Number(b) });
const viemHash = keccak256(serializeTransaction({ type: 'eip1559', chainId: 11155111, nonce: 0,
  maxPriorityFeePerGas: 1000000000n, maxFeePerGas: 20000000000n, gas: 21000n, to: DEST, value: 6n * CENTI, data: '0x', accessList: [] }));
check('B ready after the delay with nonce 0', e.ready && e.nonce === 0, e.reason ?? '');
check('B signing hash equals viem (nonce 0)', e.signing_hash === viemHash, `${e.signing_hash} vs ${viemHash}`);

// tightening stops queued proposals
call(OWNER, 'set_policy', { token_id: t, policy: policy(1) }, '0.05 NEAR');
e = await view('check_execution', { token_id: t, proposal_id: Number(b) });
check('after lowering the cap, B is no longer executable', !e.ready && e.reason === 'Policy now refuses it: ETH daily cap exceeded', e.reason);

// sale empties the queue (M8: through a sale window, which waits at least 10 minutes). The sale
// starts only now: while it is active the vault is frozen and check_execution says so (review H4).
const saleOpensAt = events(call(OWNER, 'start_sale', { token_id: t }, '0.01 NEAR').out, 'sale_started')[0]?.data[0].opens_at_ms;
e = await view('check_execution', { token_id: t, proposal_id: Number(b) });
check('during the sale check_execution reports the freeze', !e.ready && /^The vault is frozen for a sale/.test(e.reason ?? ''), e.reason);
const saleWait = saleOpensAt - Date.now() + 5000;
if (saleWait > 0) {
  console.log(`      waiting ${Math.ceil(saleWait / 1000)} s for the sale window to open (minimum 10 minutes)...`);
  await sleep(saleWait);
}
call(OWNER, 'nft_transfer', { receiver_id: GUARDIAN, token_id: t }, '1 yoctoNEAR');
check('after the sale the queue is empty', (await view('list_proposals', { token_id: t })).length === 0);
check('the next nonce is still 0 (not reset, nothing signed)', (await view('get_next_nonce', { token_id: t })) === 0);

console.log(failures === 0 ? '\nALL CHECKS PASSED' : `\n${failures} CHECK(S) FAILED`);
process.exit(failures === 0 ? 0 : 1);
