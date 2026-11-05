// M7 review fixes on testnet + Sepolia, on a funded vault with a policy in force:
// 1. uncertain outcome, live: ask the signer with a 0 deposit; if it refuses, the nonce must stay
//    used, the charge kept, and the proposal pinned to that nonce (review S3);
// 2. retry: the identical transaction at the same nonce, not charged twice; it is signed but NOT
//    broadcast (a "pending signature", like the one a seller could keep, threat 1);
// 3. cancel_nonce: a 0-value self-transfer with that nonce, signed and mined on Sepolia;
// 4. the pending signature can no longer be mined (its nonce is used).
//
// Usage: node m7-cancel-testnet-check.mjs <owner> <vault-contract> <token_id>
// The vault must be funded (a few thousandths of ETH), have a policy whose allowed destinations
// include the owner's "ethereum-1" address, and nothing in flight. About 2-3 minutes.
import { spawnSync } from 'node:child_process';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { createPublicClient, http, keccak256 } from 'viem';
import { sepolia } from 'viem/chains';

const [OWNER, VAULT, T] = process.argv.slice(2);
if (!T) throw new Error('usage: node m7-cancel-testnet-check.mjs <owner> <vault-contract> <token_id>');
const NEAR = process.env.NEAR_CLI || join(homedir(), '.cargo', 'bin', process.platform === 'win32' ? 'near.exe' : 'near');
const RPC = process.env.NEAR_RPC || 'https://rpc.testnet.near.org';
const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const eth = createPublicClient({ chain: sepolia, transport: http('https://ethereum-sepolia-rpc.publicnode.com') });
let failures = 0;

const check = (name, ok, detail = '') => {
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${detail ? '  — ' + detail : ''}`);
  if (!ok) failures++;
};
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const events = (out, name) => [...out.matchAll(/EVENT_JSON:(\{.*\})/g)]
  .map((m) => { try { return JSON.parse(m[1]); } catch { return null; } })
  .filter((e) => e && (!name || e.event === name));
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
    await sleep(2000 * attempt);
    return rpc(method, params, attempt + 1);
  }
}
async function view(account, method, args) {
  const r = await rpc('query', { request_type: 'call_function', finality: 'final', account_id: account,
    method_name: method, args_base64: Buffer.from(JSON.stringify(args)).toString('base64') });
  return JSON.parse(Buffer.from(r.result).toString());
}
function call(method, args, deposit, gas = '300 Tgas') {
  const p = spawnSync(NEAR, ['contract', 'call-function', 'as-transaction', VAULT, method,
    'json-args', JSON.stringify(args), 'prepaid-gas', gas, 'attached-deposit', deposit,
    'sign-as', OWNER, 'network-config', 'testnet', 'sign-with-keychain', 'send'], { encoding: 'utf8' });
  const out = (p.stdout || '') + (p.stderr || '');
  return { out, stdout: (p.stdout || '').trim(), panic: (out.match(/Smart contract panicked: ([^"\n)]*)/) || [])[1] };
}
async function broadcast(raw) {
  const j = await fetch('https://ethereum-sepolia-rpc.publicnode.com', { method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'eth_sendRawTransaction', params: [raw] }) }).then((r) => r.json());
  return j.error ? { error: j.error.message } : { hash: j.result };
}

const vaultAddr = (await view(VAULT, 'vault_info', { token_id: T })).evm_address;
const key = await view('v1.signer-prod.testnet', 'derived_public_key', { path: 'ethereum-1', predecessor: OWNER, domain_id: 0 });
let n = 0n; for (const c of key.slice('secp256k1:'.length)) n = n * 58n + BigInt(B58.indexOf(c));
const funder = '0x' + keccak256('0x' + n.toString(16).padStart(128, '0')).slice(-40);
const pol = await view(VAULT, 'get_policy', { token_id: T });
check(`vault ${T} ready: funded, policy in force, nothing in flight`,
  (await eth.getBalance({ address: vaultAddr })) > 0n && pol.has_policy && (await view(VAULT, 'get_inflight', { token_id: T })) === null);
const delayMs = pol.policy.delay_ms;
const nonce = await view(VAULT, 'get_next_nonce', { token_id: T });
const chainNonceBefore = await eth.getTransactionCount({ address: vaultAddr });
check('contract next nonce equals the vault account nonce on Sepolia', nonce === chainNonceBefore, `${nonce} vs ${chainNonceBefore}`);

// ---------- propose ----------
const base = (await eth.getBlock()).baseFeePerGas;
const fee = base * 2n + 1_000_000_000n;
let r = call('propose', { token_id: T, tx: { chain_id: sepolia.id, max_priority_fee_per_gas: '1000000000',
  max_fee_per_gas: String(fee), gas_limit: 21000, to: funder, value: '100000000000000', data: '0x' } }, '0.05 NEAR', '100 Tgas');
const pid = events(r.out, 'proposal_created')[0]?.data[0].proposal_id;
check('proposal of 0.0001 ETH queued', pid !== undefined, r.panic);
console.log(`      waiting ${delayMs / 1000 + 5} s for the delay...`);
await sleep(delayMs + 5000);

// ---------- 1. uncertain outcome, live ----------
const spentBefore = BigInt((await view(VAULT, 'get_policy', { token_id: T })).spend.eth.spent);
r = call('execute_proposal', { token_id: T, proposal_id: pid, sign_deposit: '0' }, '0.02 NEAR');
const unc = events(r.out, 'signature_uncertain')[0]?.data[0];
const signedWith0 = events(r.out, 'transaction_signed').length === 1;
if (signedWith0) {
  console.log('NOTE  the signer accepted a 0 deposit, so the uncertain path could not be triggered live');
} else {
  check('signer refused a 0 deposit: outcome is uncertain, not undone', unc && unc.nonce === nonce && unc.requeued === true, unc ? unc.reason : r.panic ?? r.stdout);
  check('the nonce stays used', (await view(VAULT, 'get_next_nonce', { token_id: T })) === nonce + 1);
  check('the nonce is listed as uncertain', (await view(VAULT, 'get_uncertain', { token_id: T })).some((u) => u.nonce === nonce));
  const ex = await view(VAULT, 'check_execution', { token_id: T, proposal_id: pid });
  check('the proposal is back, pinned to the same nonce', ex.ready && ex.nonce === nonce, JSON.stringify(ex));
  const spentAfterUnc = BigInt((await view(VAULT, 'get_policy', { token_id: T })).spend.eth.spent);
  check('the charge was kept', spentAfterUnc > spentBefore, `${spentBefore} -> ${spentAfterUnc}`);

  // ---------- 2. retry: identical transaction, same nonce, not charged twice ----------
  r = call('execute_proposal', { token_id: T, proposal_id: pid }, '0.02 NEAR');
  check('retry signed', r.stdout === 'true', r.panic ?? r.stdout);
  const spentAfterRetry = BigInt((await view(VAULT, 'get_policy', { token_id: T })).spend.eth.spent);
  check('the retry was not charged twice', spentAfterRetry === spentAfterUnc, `${spentAfterUnc} -> ${spentAfterRetry}`);
  check('uncertain list is empty again', (await view(VAULT, 'get_uncertain', { token_id: T })).length === 0);
}
const pending = await view(VAULT, 'get_signed', { token_id: T, nonce });
check(`a signed transaction exists for nonce ${nonce} and is NOT broadcast (pending signature)`, pending && pending.nonce === nonce);

// ---------- 3. cancel that nonce ----------
r = call('cancel_nonce', { token_id: T, nonce, max_fee_per_gas: String(fee * 2n), max_priority_fee_per_gas: '2000000000' }, '0.02 NEAR');
check('cancel_nonce signed a cancellation (no delay needed)', r.stdout === 'true', r.panic ?? r.stdout);
const versions = await view(VAULT, 'get_signed_versions', { token_id: T, nonce });
check('the nonce now has two versions: the payment and the cancellation', versions.length === 2 && versions[1].proposal_id > 1e18, JSON.stringify(versions.map((v) => v.proposal_id)));
const sent = await broadcast(versions[1].signed_tx);
const rc = sent.hash ? await eth.waitForTransactionReceipt({ hash: sent.hash, timeout: 180_000 }) : null;
check('the cancellation is mined from the vault address', rc && rc.status === 'success' && rc.from.toLowerCase() === vaultAddr, sent.hash ? `https://sepolia.etherscan.io/tx/${sent.hash}` : sent.error);

// ---------- 4. the pending signature is now useless ----------
const late = await broadcast(pending.signed_tx);
check('the pending payment can no longer be mined', !!late.error && /nonce too low|already known|replacement/i.test(late.error), late.error ?? late.hash);
check('next nonce unchanged by the cancellation', (await view(VAULT, 'get_next_nonce', { token_id: T })) === nonce + 1);

console.log(failures === 0 ? '\nALL CHECKS PASSED' : `\n${failures} CHECK(S) FAILED`);
process.exit(failures === 0 ? 0 : 1);
