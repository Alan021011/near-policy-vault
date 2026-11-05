// M8 end to end on testnet + Sepolia: the two-phase sale of a funded vault.
// 1. no transfer without a sale; the guardian vetoes a sale (threat 16, stolen owner key);
// 2. the seller signs a payment and keeps it unbroadcast (threat 1), then starts a sale: the
//    vault signs no new payment while on sale;
// 3. the buyer's audit says NOT SAFE; the seller cancels that nonce (allowed during the sale),
//    the cancellation is mined, and the audit says SAFE;
// 4. once the window opens the NFT goes to the buyer, who gets a clean vault: no policy, no
//    queue, same chain and nonce, and the kept payment can no longer be mined.
//
// Usage: node m8-testnet-check.mjs <seller> <vault-contract> <buyer-and-guardian> <token_id>
// The vault must be funded, owned by <seller>, with a policy whose guardian is <buyer-and-guardian>
// and whose allowed destinations include the seller's "ethereum-1" address (as left by
// m7-testnet-check.mjs). Keys for both accounts in the keychain. About 13 minutes (every sale waits at least 10).
import { spawnSync } from 'node:child_process';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { createPublicClient, http, keccak256 } from 'viem';
import { sepolia } from 'viem/chains';
import { audit } from './sale-audit.mjs';

const [SELLER, VAULT, BUYER, T] = process.argv.slice(2);
if (!T) throw new Error('usage: node m8-testnet-check.mjs <seller> <vault-contract> <buyer-and-guardian> <token_id>');
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
async function view(account, method, args, attempt = 1) {
  try {
    const res = await fetch(RPC, { method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'query', params: { request_type: 'call_function',
        finality: 'final', account_id: account, method_name: method, args_base64: Buffer.from(JSON.stringify(args)).toString('base64') } }) });
    if (res.status === 429 || res.status >= 500) throw new Error(`HTTP ${res.status}`);
    const j = await res.json();
    if (j.error) throw new Error(JSON.stringify(j.error));
    return JSON.parse(Buffer.from(j.result.result).toString());
  } catch (e) {
    if (attempt >= 5) throw e;
    await sleep(2000 * attempt);
    return view(account, method, args, attempt + 1);
  }
}
function call(signer, method, args, deposit, gas = '300 Tgas') {
  const p = spawnSync(NEAR, ['contract', 'call-function', 'as-transaction', VAULT, method,
    'json-args', JSON.stringify(args), 'prepaid-gas', gas, 'attached-deposit', deposit,
    'sign-as', signer, 'network-config', 'testnet', 'sign-with-keychain', 'send'], { encoding: 'utf8' });
  const out = (p.stdout || '') + (p.stderr || '');
  return { out, stdout: (p.stdout || '').trim(), panic: (out.match(/Smart contract panicked: (.*?)(?:"\)|\n|$)/) || [])[1] };
}
async function broadcast(raw) {
  const j = await fetch('https://ethereum-sepolia-rpc.publicnode.com', { method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'eth_sendRawTransaction', params: [raw] }) }).then((r) => r.json());
  return j.error ? { error: j.error.message } : { hash: j.result };
}
const v = (m, a) => view(VAULT, m, a);

// ---------- setup ----------
const vaultAddr = (await v('vault_info', { token_id: T })).evm_address;
const key = await view('v1.signer-prod.testnet', 'derived_public_key', { path: 'ethereum-1', predecessor: SELLER, domain_id: 0 });
let n = 0n; for (const c of key.slice('secp256k1:'.length)) n = n * 58n + BigInt(B58.indexOf(c));
const funder = '0x' + keccak256('0x' + n.toString(16).padStart(128, '0')).slice(-40);
const pol = await v('get_policy', { token_id: T });
check(`vault ${T} ready: owned by the seller, policy with the guardian, funded, no sale`,
  (await v('nft_token', { token_id: T })).owner_id === SELLER && pol.has_policy && pol.policy.guardian === BUYER
  && (await eth.getBalance({ address: vaultAddr })) > 0n && (await v('get_sale', { token_id: T })) === null);
const delay = pol.policy.delay_ms;

// ---------- 1. no transfer without a sale; the guardian vetoes a sale ----------
let r = call(SELLER, 'nft_transfer', { receiver_id: BUYER, token_id: T }, '1 yoctoNEAR', '50 Tgas');
check('no transfer without a sale', r.panic === 'Start a sale (start_sale) and wait for it to open before transferring', r.panic);
r = call(SELLER, 'start_sale', { token_id: T }, '0.01 NEAR', '50 Tgas');
const firstSale = events(r.out, 'sale_started')[0]?.data[0];
check('sale started; it opens after max(policy delay, 10 minutes)', !!firstSale && firstSale.opens_at_ms - Date.now() > 9 * 60_000, r.panic);
r = call(SELLER, 'nft_transfer', { receiver_id: BUYER, token_id: T }, '1 yoctoNEAR', '50 Tgas');
check('no transfer before the sale opens', /^The sale opens at/.test(r.panic ?? ''), r.panic);
r = call(BUYER, 'veto_sale', { token_id: T }, '1 yoctoNEAR', '50 Tgas');
check('the guardian vetoes the sale (threat 16)', !r.panic && (await v('get_sale', { token_id: T })) === null, r.panic);

// ---------- 2. a payment signed and kept; then the sale freezes the vault ----------
const fee = (await eth.getBlock()).baseFeePerGas * 2n + 1_000_000_000n;
const ptx = { chain_id: sepolia.id, max_priority_fee_per_gas: '1000000000', max_fee_per_gas: String(fee),
  gas_limit: 21000, to: funder, value: '100000000000000', data: '0x' };
const p = events(call(SELLER, 'propose', { token_id: T, tx: ptx }, '0.05 NEAR', '100 Tgas').out, 'proposal_created')[0]?.data[0].proposal_id;
const q = events(call(SELLER, 'propose', { token_id: T, tx: ptx }, '0.05 NEAR', '100 Tgas').out, 'proposal_created')[0]?.data[0].proposal_id;
console.log(`      waiting ${delay / 1000 + 5} s for the proposals' delay...`);
await sleep(delay + 5000);
r = call(SELLER, 'execute_proposal', { token_id: T, proposal_id: p }, '0.02 NEAR');
const kept = events(r.out, 'transaction_signed')[0]?.data[0];
check('the seller signs a payment and keeps it unbroadcast', r.stdout === 'true' && kept, r.panic ?? r.stdout);
r = call(SELLER, 'start_sale', { token_id: T }, '0.01 NEAR', '50 Tgas');
const sale = events(r.out, 'sale_started')[0]?.data[0];
check('a new sale is started', !!sale, r.panic);
r = call(SELLER, 'execute_proposal', { token_id: T, proposal_id: q }, '0.02 NEAR');
check('while on sale the vault signs no new payment', r.panic === 'The vault is frozen for a sale; only cancel_nonce can sign until the sale ends', r.panic);

// ---------- 3. the buyer's audit, the cancellation, the audit again ----------
let a = await audit(VAULT, T);
check('the buyer\'s audit says NOT SAFE: one kept signature', !a.safe && a.outstanding.length === 1 && a.outstanding[0].nonce === kept.nonce, a.problems.join(' | '));
r = call(SELLER, 'cancel_nonce', { token_id: T, nonce: kept.nonce, max_fee_per_gas: String(fee * 2n), max_priority_fee_per_gas: '2000000000' }, '0.02 NEAR');
check('the seller cancels that nonce during the sale', r.stdout === 'true', r.panic ?? r.stdout);
const versions = await v('get_signed_versions', { token_id: T, nonce: kept.nonce });
const sent = await broadcast(versions[versions.length - 1].signed_tx);
const rc = sent.hash ? await eth.waitForTransactionReceipt({ hash: sent.hash, timeout: 180_000 }) : null;
check('the cancellation is mined from the vault', rc && rc.status === 'success', sent.hash ? `https://sepolia.etherscan.io/tx/${sent.hash}` : sent.error);
await sleep(3000);
a = await audit(VAULT, T);
const waitOpen = Math.max(0, sale.opens_at_ms - Date.now());
check('the audit now finds no kept signature', a.outstanding.length === 0 && a.mined === a.next, `mined ${a.mined}, next ${a.next}`);

// ---------- 4. the window opens and the buyer gets a clean vault ----------
if (waitOpen > 0) {
  console.log(`      waiting ${Math.ceil(waitOpen / 1000) + 5} s for the sale window to open...`);
  await sleep(waitOpen + 5000);
}
a = await audit(VAULT, T);
check('with the window open the audit says SAFE', a.safe, a.problems.join(' | '));
const nextBefore = await v('get_next_nonce', { token_id: T });
// M8 review V1: a buyer who audited the first (vetoed) sale binds the transfer to it, and it fails,
// because the seller signed something between the two sales.
r = call(SELLER, 'nft_transfer', { receiver_id: BUYER, token_id: T, memo: `sale:${firstSale.sale_id}` }, '1 yoctoNEAR', '50 Tgas');
check('a transfer bound to an older sale is refused', /^The sale changed since it was audited/.test(r.panic ?? ''), r.panic);
r = call(SELLER, 'nft_transfer', { receiver_id: BUYER, token_id: T, memo: `sale:${a.sale.sale_id}` }, '1 yoctoNEAR', '50 Tgas');
check('the NFT goes to the buyer, bound to the audited sale', !r.panic && (await v('nft_token', { token_id: T })).owner_id === BUYER, r.panic);
const after = await v('get_policy', { token_id: T });
check('the buyer gets a clean vault: no policy, no queue, no sale',
  !after.has_policy && (await v('list_proposals', { token_id: T })).length === 0 && (await v('get_sale', { token_id: T })) === null);
check('chain and nonce stay with the vault', (await v('get_vault_chain', { token_id: T })) === sepolia.id && (await v('get_next_nonce', { token_id: T })) === nextBefore);
const late = await broadcast(kept.signed_tx);
check('the payment the seller kept can no longer be mined', !!late.error && /nonce too low|underpriced|already known/i.test(late.error), late.error ?? late.hash);

console.log(failures === 0 ? '\nALL CHECKS PASSED' : `\n${failures} CHECK(S) FAILED`);
process.exit(failures === 0 ? 0 : 1);
