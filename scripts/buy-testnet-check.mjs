// General review after M8, end to end on testnet + Sepolia:
// A. H1: a transfer_call receiver that tries to act as owner before the transfer resolves (it
//    sets a policy with delay 0, the first step to sign a payment) is refused, and the vault goes
//    back to the sender, unlocked. The receiver is test-receiver/ with msg "act".
// B. H2: an ERC-20 approval the vault signed and that was mined survives a sale: the buyer's audit
//    now catches it (NOT SAFE), and says SAFE once the seller revokes it with approve(spender, 0).
// C. H3: buy at the sale price. A sale reserved for the buyer refuses a stranger, a purchase that
//    names an older sale fails, too small a deposit fails; then the buyer pays, gets a clean vault,
//    and the seller receives the price, all in one transaction.
//
// Usage: node buy-testnet-check.mjs <seller> <vault-contract> <buyer-and-guardian> <token_id> <stranger>
// <token_id>: a funded vault owned by <seller> with a policy whose guardian is <buyer-and-guardian>
// and a 60 s delay, as left by m7-testnet-check.mjs. <buyer-and-guardian> must run test-receiver/.
// <stranger>: any third account with a key in the keychain. About 15 minutes.
import { spawnSync } from 'node:child_process';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { createPublicClient, http, keccak256 } from 'viem';
import { sepolia } from 'viem/chains';
import { audit } from './sale-audit.mjs';

const [SELLER, VAULT, BUYER, T, STRANGER] = process.argv.slice(2);
if (!STRANGER) throw new Error('usage: node buy-testnet-check.mjs <seller> <vault-contract> <buyer-and-guardian> <token_id> <stranger>');
const NEAR = process.env.NEAR_CLI || join(homedir(), '.cargo', 'bin', process.platform === 'win32' ? 'near.exe' : 'near');
const RPC = process.env.NEAR_RPC || 'https://rpc.testnet.near.org';
const ETH_RPC = 'https://ethereum-sepolia-rpc.publicnode.com';
const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const WETH = '0xfff9976782d46cc05630d1f6ebab18b2324d6b14'; // WETH9 on Sepolia; approve needs no balance
const PRICE = 100_000_000_000_000_000_000_000n; // 0.1 NEAR
const eth = createPublicClient({ chain: sepolia, transport: http(ETH_RPC) });
let failures = 0;

const check = (name, ok, detail = '') => {
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${detail ? '  — ' + detail : ''}`);
  if (!ok) failures++;
};
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
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
const v = (m, a) => view(VAULT, m, a);

/** Calls the vault contract with the CLI; returns the panic (if any), all logs and the NEAR the contract sent. */
async function call(signer, method, args, deposit, gas = '100 Tgas') {
  const p = spawnSync(NEAR, ['contract', 'call-function', 'as-transaction', VAULT, method,
    'json-args', JSON.stringify(args), 'prepaid-gas', gas, 'attached-deposit', deposit,
    'sign-as', signer, 'network-config', 'testnet', 'sign-with-keychain', 'send'], { encoding: 'utf8' });
  const out = (p.stdout || '') + (p.stderr || '');
  const panic = (out.match(/Smart contract panicked: (.*?)(?:"\)|\n|$)/) || [])[1];
  const m = out.match(/Transaction ID: (\w+)/);
  if (!m) return { panic: panic ?? out.slice(-300), logs: [], sent: [], out };
  const tx = await rpc('EXPERIMENTAL_tx_status', { tx_hash: m[1], sender_account_id: signer, wait_until: 'FINAL' });
  const logs = tx.receipts_outcome.flatMap((r) => r.outcome.logs);
  const sent = tx.receipts
    .filter((r) => r.predecessor_id === VAULT && r.receipt.Action)
    .flatMap((r) => r.receipt.Action.actions.filter((a) => a.Transfer)
      .map((a) => ({ to: r.receiver_id, amount: BigInt(a.Transfer.deposit) })));
  const failuresText = JSON.stringify(tx.receipts_outcome.map((r) => r.outcome.status).filter((s) => s.Failure));
  return { panic, logs, sent, failuresText, hash: m[1], out };
}
const events = (logs, name) => logs.filter((l) => l.startsWith('EVENT_JSON:'))
  .map((l) => JSON.parse(l.slice('EVENT_JSON:'.length))).filter((e) => e.event === name);
const word = (x) => (typeof x === 'bigint' ? x.toString(16) : x.toLowerCase().replace(/^0x/, '')).padStart(64, '0');
// Read at a given block: the public RPC spreads calls over several nodes, and right after a receipt
// one of them may still be a block behind (a first run read the old allowance that way).
const allowance = async (owner, spender, blockNumber) =>
  BigInt(await eth.call({ to: WETH, data: '0xdd62ed3e' + word(owner) + word(spender), blockNumber }).then((r) => r.data ?? '0x0'));

async function waitMs(ms, why) {
  if (ms <= 0) return;
  console.log(`      waiting ${Math.ceil(ms / 1000)} s ${why}...`);
  await sleep(ms);
}

/** Proposes `approve(spender, amount)` on WETH, waits the delay, signs it and mines it. */
async function approveOnChain(spender, amount, delayMs) {
  const fee = (await eth.getBlock()).baseFeePerGas * 2n + 1_000_000_000n;
  const data = '0x095ea7b3' + word(spender) + word(amount);
  // On current Sepolia an approve that creates a new allowance costs about 129,000 gas (about
  // 20,000 to set one back to 0), so the gas limit is estimated from the vault's address.
  const gas = (await eth.estimateGas({ account: vaultAddr, to: WETH, data })) * 13n / 10n;
  const tx = { chain_id: sepolia.id, max_priority_fee_per_gas: '1000000000', max_fee_per_gas: String(fee),
    gas_limit: Number(gas), to: WETH, value: '0', data };
  let r = await call(SELLER, 'propose', { token_id: T, tx }, '0.05 NEAR');
  const id = events(r.logs, 'proposal_created')[0]?.data[0].proposal_id;
  if (id === undefined) return { error: r.panic };
  await waitMs(delayMs + 5000, 'for the proposal delay');
  r = await call(SELLER, 'execute_proposal', { token_id: T, proposal_id: id }, '0.02 NEAR', '300 Tgas');
  const signed = events(r.logs, 'transaction_signed')[0]?.data[0];
  if (!signed) return { error: r.panic ?? 'not signed' };
  const hash = await eth.sendRawTransaction({ serializedTransaction: signed.signed_tx });
  const rc = await eth.waitForTransactionReceipt({ hash, timeout: 180_000 });
  return { hash, ok: rc.status === 'success', block: rc.blockNumber };
}

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

// A (setup): a second, empty vault for the transfer_call attack; its sale opens in 10 minutes,
// while B runs.
let r = await call(SELLER, 'mint_vault', {}, '0.1 NEAR');
const X = events(r.logs, 'nft_mint')[0]?.data[0].token_ids[0];
r = await call(SELLER, 'start_sale', { token_id: X }, '0.01 NEAR');
const saleX = events(r.logs, 'sale_started')[0]?.data[0];
check(`vault ${X} minted for the transfer_call attack, its sale started`, X !== undefined && !!saleX, r.panic);

// ---------- B. an ERC-20 approval survives a sale; the audit catches it ----------
const loose = { ...pol.policy, eth_daily_cap: '10000000000000000', max_gas_cost: String(200000n * 10n * 10n ** 9n),
  allowed_spenders: [funder], tokens: [{ contract: WETH, daily_cap: '0', max_approval: '1000000' }] };
r = await call(SELLER, 'set_policy', { token_id: T, policy: loose }, '0.05 NEAR');
await waitMs(delay + 5000, 'for the looser policy (WETH approvals to the seller) to apply');
r = await call(SELLER, 'apply_policy', { token_id: T }, '0 NEAR');
check('the policy now allows WETH approvals to the seller\'s own address', !r.panic
  && (await v('get_policy', { token_id: T })).policy.allowed_spenders[0] === funder, r.panic);
let a = await approveOnChain(funder, 12345n, delay);
check('the vault approves the seller to take 12345 WETH units, and it is mined', a.ok && (await allowance(vaultAddr, funder, a.block)) === 12345n,
  a.hash ? `https://sepolia.etherscan.io/tx/${a.hash}` : a.error);
r = await call(SELLER, 'start_sale', { token_id: T, price: String(PRICE), buyer: BUYER }, '0.01 NEAR');
const sale1 = events(r.logs, 'sale_started')[0]?.data[0];
let au = await audit(VAULT, T);
check('every nonce is mined, yet the audit says NOT SAFE: the approval survives the sale (H2)',
  !au.safe && au.outstanding.length === 0 && au.allowances.some((x) => x.allowance === '12345'), au.problems.join(' | '));
r = await call(SELLER, 'cancel_sale', { token_id: T }, '1 yoctoNEAR');
a = await approveOnChain(funder, 0n, delay);
check('the seller revokes it (approve 0), mined', a.ok && (await allowance(vaultAddr, funder, a.block)) === 0n,
  a.hash ? `https://sepolia.etherscan.io/tx/${a.hash}` : a.error);

// ---------- C (first part). a new sale at a price, reserved for the buyer ----------
r = await call(SELLER, 'start_sale', { token_id: T, price: String(PRICE), buyer: BUYER }, '0.01 NEAR');
const sale2 = events(r.logs, 'sale_started')[0]?.data[0];
check('a new sale at 0.1 NEAR, reserved for the buyer', !!sale2 && sale2.sale_id !== sale1?.sale_id && sale2.price === String(PRICE), r.panic);
r = await call(BUYER, 'buy', { token_id: T, sale_id: sale2.sale_id }, '0.1 NEAR');
check('nobody buys before the sale opens', /^The sale opens at/.test(r.panic ?? ''), r.panic);

// ---------- A. the transfer_call receiver cannot act as owner ----------
await waitMs(saleX.opens_at_ms - Date.now() + 5000, `for vault ${X}'s sale window to open`);
r = await call(SELLER, 'nft_transfer_call', { receiver_id: BUYER, token_id: X, msg: 'act' }, '1 yoctoNEAR', '300 Tgas');
check('during the transfer_call the receiver tried to set a policy and was refused (H1)',
  r.logs.some((l) => l.includes('set_policy REFUSED')) && (r.failuresText ?? '').includes('A transfer_call is in progress'),
  r.logs.find((l) => l.startsWith('test receiver')) ?? r.panic);
const kinds = r.logs.filter((l) => l.includes('"vault_transfer"')).map((l) => JSON.parse(l.slice(11)).data[0].kind);
check('the vault went back to the sender, without a policy',
  (await v('nft_token', { token_id: X })).owner_id === SELLER && !(await v('get_policy', { token_id: X })).has_policy
  && JSON.stringify(kinds) === '["transfer_call","transfer_call_returned"]', JSON.stringify(kinds));
r = await call(SELLER, 'start_sale', { token_id: X }, '0.01 NEAR');
const unlocked = !r.panic;
await call(SELLER, 'cancel_sale', { token_id: X }, '1 yoctoNEAR');
check('the lock was released when the transfer resolved: the sender can act again', unlocked, r.panic);

// ---------- C. buy ----------
await waitMs(sale2.opens_at_ms - Date.now() + 5000, 'for the sale window to open');
au = await audit(VAULT, T);
check('the audit now says SAFE for this sale', au.safe && au.sale.sale_id === sale2.sale_id, au.problems.join(' | '));
r = await call(STRANGER, 'buy', { token_id: T, sale_id: sale2.sale_id }, '0.1 NEAR');
check('a stranger cannot buy a reserved sale', r.panic === 'This sale is reserved for another buyer', r.panic);
r = await call(BUYER, 'buy', { token_id: T, sale_id: sale1.sale_id }, '0.1 NEAR');
check('a purchase that names the older sale fails', /^The sale changed since it was audited/.test(r.panic ?? ''), r.panic);
r = await call(BUYER, 'buy', { token_id: T, sale_id: sale2.sale_id }, '0.05 NEAR');
check('too small a deposit fails', /^Attach the price/.test(r.panic ?? ''), r.panic);
const nextBefore = await v('get_next_nonce', { token_id: T });
r = await call(BUYER, 'buy', { token_id: T, sale_id: sale2.sale_id }, '0.1 NEAR');
check('the buyer pays 0.1 NEAR and gets the vault', !r.panic && (await v('nft_token', { token_id: T })).owner_id === BUYER
  && events(r.logs, 'sale_bought').length === 1, r.panic);
check('in the same transaction the seller receives the price', r.sent.some((s) => s.to === SELLER && s.amount === PRICE),
  JSON.stringify(r.sent.map((s) => [s.to, String(s.amount)])));
check('the buyer gets a clean vault: no policy, no queue, no sale, same chain and nonce',
  !(await v('get_policy', { token_id: T })).has_policy && (await v('list_proposals', { token_id: T })).length === 0
  && (await v('get_sale', { token_id: T })) === null && (await v('get_vault_chain', { token_id: T })) === sepolia.id
  && (await v('get_next_nonce', { token_id: T })) === nextBefore);

console.log(failures === 0 ? '\nALL CHECKS PASSED' : `\n${failures} CHECK(S) FAILED`);
process.exit(failures === 0 ? 0 : 1);
