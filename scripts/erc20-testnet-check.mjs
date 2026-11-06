// M10 (general review G5): an NFT vault moves an ERC-20 token on Sepolia under its policy.
// 1. mint a vault; the owner's own Chain Signatures account ("ethereum-1", like A1) sends it a
//    little ETH for gas, wraps some ETH into WETH and sends that WETH to the vault;
// 2. the vault's policy allows WETH transfers to one address, with a daily cap;
// 3. the policy refuses a transfer above the cap and one to another address;
// 4. two transfers that each fit the cap but not together are queued; after the delay the first is
//    signed by the MPC network through the contract and mined (the WETH balances move), and the
//    second is refused at signing, because the cap is charged when a transaction is signed.
//
// Usage: node erc20-testnet-check.mjs <owner> <vault-contract> <guardian>
// The owner's NEAR key must be in the keychain, and the owner's "ethereum-1" address needs a little
// Sepolia ETH (about 0.0025 ETH plus gas). About 4 minutes.
import { spawnSync } from 'node:child_process';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { createPublicClient, http, keccak256, parseTransaction, recoverTransactionAddress, serializeTransaction } from 'viem';
import { sepolia } from 'viem/chains';

const [OWNER, VAULT, GUARDIAN] = process.argv.slice(2);
if (!GUARDIAN) throw new Error('usage: node erc20-testnet-check.mjs <owner> <vault-contract> <guardian>');
const NEAR = process.env.NEAR_CLI || join(homedir(), '.cargo', 'bin', process.platform === 'win32' ? 'near.exe' : 'near');
const RPC = process.env.NEAR_RPC || 'https://rpc.testnet.near.org';
const SIGNER = 'v1.signer-prod.testnet';
const WETH = '0xfff9976782d46cc05630d1f6ebab18b2324d6b14'; // WETH9 on Sepolia
const OTHER = '0x9999999999999999999999999999999999999999';
const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const DELAY_MS = 60_000;
const GAS_ETH = 2_000_000_000_000_000n; // 0.002 ETH for the vault's gas
const WRAPPED = 200_000_000_000_000n; // 0.0002 WETH sent to the vault
const CAP = 100_000_000_000_000n; // 0.0001 WETH a day
const PAY = 60_000_000_000_000n; // 0.00006 WETH per transfer (two do not fit the cap)
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
const word = (x) => (typeof x === 'bigint' ? x.toString(16) : x.toLowerCase().replace(/^0x/, '')).padStart(64, '0');
const transferData = (to, amount) => '0xa9059cbb' + word(to) + word(amount);
const link = (h) => `https://sepolia.etherscan.io/tx/${h}`;

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
function call(contract, signer, method, args, deposit, gas = '100 Tgas') {
  const p = spawnSync(NEAR, ['contract', 'call-function', 'as-transaction', contract, method,
    'json-args', JSON.stringify(args), 'prepaid-gas', gas, 'attached-deposit', deposit,
    'sign-as', signer, 'network-config', 'testnet', 'sign-with-keychain', 'send'], { encoding: 'utf8' });
  const out = (p.stdout || '') + (p.stderr || '');
  return { out, stdout: (p.stdout || '').trim(), panic: (out.match(/Smart contract panicked: (.*?)(?:"\)|\n|$)/) || [])[1] };
}
const addressOfKey = (key) => {
  let n = 0n;
  for (const c of key.slice('secp256k1:'.length)) n = n * 58n + BigInt(B58.indexOf(c));
  return '0x' + keccak256('0x' + n.toString(16).padStart(128, '0')).slice(-40);
};
async function fees() {
  const block = await eth.getBlock();
  const prio = 1_000_000_000n;
  return { maxPriorityFeePerGas: prio, maxFeePerGas: block.baseFeePerGas * 2n + prio };
}
const wethBalance = async (owner, blockNumber) =>
  BigInt(await eth.call({ to: WETH, data: '0x70a08231' + word(owner), blockNumber }).then((r) => r.data ?? '0x0'));

/** The owner's own Chain Signatures account signs and sends a transaction (as in A1 and M7). */
async function funderSend(funder, nonce, to, value, data) {
  const f = await fees();
  const gas = (await eth.estimateGas({ account: funder, to, value, data })) * 13n / 10n;
  const tx = { type: 'eip1559', chainId: sepolia.id, nonce, ...f, gas, to, value, data, accessList: [] };
  const sig = JSON.parse(call(SIGNER, OWNER, 'sign', { request: { domain_id: 0, path: 'ethereum-1',
    payload_v2: { Ecdsa: keccak256(serializeTransaction(tx)).slice(2) } } }, '1 yoctoNEAR').stdout);
  const raw = serializeTransaction(tx, { r: '0x' + sig.big_r.affine_point.slice(2), s: '0x' + sig.s.scalar, yParity: sig.recovery_id });
  return eth.waitForTransactionReceipt({ hash: await eth.sendRawTransaction({ serializedTransaction: raw }), timeout: 180_000 });
}

// ---------- 1. a new vault, funded with ETH (gas) and WETH ----------
const mint = call(VAULT, OWNER, 'mint_vault', {}, '0.1 NEAR');
const t = events(mint.out, 'nft_mint')[0]?.data[0].token_ids[0];
const vaultAddr = t === undefined ? undefined : (await view(VAULT, 'vault_info', { token_id: t })).evm_address;
check('vault minted, its address published', /^0x[0-9a-f]{40}$/.test(vaultAddr ?? ''), `vault ${t}: ${vaultAddr}`);
const funder = addressOfKey(await view(SIGNER, 'derived_public_key', { path: 'ethereum-1', predecessor: OWNER, domain_id: 0 }));
let nonce = await eth.getTransactionCount({ address: funder });
const r1 = await funderSend(funder, nonce++, vaultAddr, GAS_ETH, '0x');
const r2 = await funderSend(funder, nonce++, WETH, WRAPPED, '0xd0e30db0'); // WETH9 deposit()
const r3 = await funderSend(funder, nonce++, WETH, 0n, transferData(vaultAddr, WRAPPED));
const start = await wethBalance(vaultAddr, r3.blockNumber);
check(`the owner's own account sent the vault 0.002 ETH and 0.0002 WETH (from ${funder.slice(0, 10)}…)`,
  [r1, r2, r3].every((r) => r.status === 'success') && start === WRAPPED, link(r3.transactionHash));

// ---------- 2. a policy that allows WETH to the owner's address, 0.0001 a day ----------
const pf = await fees();
const policy = {
  chain_id: sepolia.id, delay_ms: DELAY_MS, guardian: GUARDIAN,
  eth_daily_cap: '1000000000000000', max_gas_cost: String(100_000n * pf.maxFeePerGas * 2n),
  allowed_destinations: [funder], allowed_spenders: [],
  tokens: [{ contract: WETH, daily_cap: String(CAP), max_approval: '0' }],
};
let r = call(VAULT, OWNER, 'set_policy', { token_id: t, policy }, '0.05 NEAR');
check('policy set: WETH to the owner\'s address only, 0.0001 WETH a day, 60 s delay, a guardian', r.stdout === 'true', r.panic ?? r.stdout);

// ---------- 3. what the policy refuses ----------
// Estimated from the vault itself (retried: a load-balanced RPC node may not have the funding block yet).
let gasLimit;
for (let i = 0; i < 5 && gasLimit === undefined; i++) {
  try {
    gasLimit = Number((await eth.estimateGas({ account: vaultAddr, to: WETH, data: transferData(funder, PAY) })) * 13n / 10n);
  } catch (e) {
    if (i === 4) throw e;
    await sleep(3000);
  }
}
const tokenTx = (to, amount) => ({ chain_id: sepolia.id, max_priority_fee_per_gas: String(pf.maxPriorityFeePerGas),
  max_fee_per_gas: String(pf.maxFeePerGas), gas_limit: gasLimit, to: WETH, value: '0', data: transferData(to, amount) });
r = call(VAULT, OWNER, 'propose', { token_id: t, tx: tokenTx(funder, CAP + 1n) }, '0.05 NEAR');
check('a WETH transfer above the daily cap is refused', r.panic?.endsWith('token daily cap exceeded'), r.panic);
r = call(VAULT, OWNER, 'propose', { token_id: t, tx: tokenTx(OTHER, PAY) }, '0.05 NEAR');
check('a WETH transfer to an address the policy does not allow is refused', r.panic === 'destination not allowed', r.panic);

// ---------- 4. two transfers that only fit the cap one at a time ----------
r = call(VAULT, OWNER, 'propose', { token_id: t, tx: tokenTx(funder, PAY) }, '0.05 NEAR');
const p1 = events(r.out, 'proposal_created')[0]?.data[0].proposal_id;
r = call(VAULT, OWNER, 'propose', { token_id: t, tx: tokenTx(funder, PAY) }, '0.05 NEAR');
const p2 = events(r.out, 'proposal_created')[0]?.data[0].proposal_id;
check('two transfers of 0.00006 WETH queued (each fits the cap, both do not)', p1 !== undefined && p2 !== undefined, r.panic);
console.log(`      waiting ${DELAY_MS / 1000 + 5} s for the delay...`);
await sleep(DELAY_MS + 5000);

r = call(VAULT, OWNER, 'execute_proposal', { token_id: t, proposal_id: p1 }, '0.02 NEAR', '300 Tgas');
check('the first transfer is signed through the contract (MPC signature checked against the vault key)', r.stdout === 'true' && !r.panic, r.panic ?? r.stdout);
const rec = await view(VAULT, 'get_signed', { token_id: t, nonce: 0 });
const parsed = parseTransaction(rec.signed_tx);
const from = (await recoverTransactionAddress({ serializedTransaction: rec.signed_tx })).toLowerCase();
check('the signed transaction is exactly the proposal: WETH transfer(owner, 0.00006), value 0, from the vault',
  from === vaultAddr && parsed.to.toLowerCase() === WETH && parsed.data === transferData(funder, PAY) && !parsed.value);
const spent = (await view(VAULT, 'get_policy', { token_id: t })).spend.tokens.find((w) => w.contract === WETH)?.window.spent;
check('the token cap was charged at signing', spent === String(PAY), `${spent} of ${CAP}`);

const funderBefore = await wethBalance(funder);
const hash = await eth.sendRawTransaction({ serializedTransaction: rec.signed_tx });
const rc = await eth.waitForTransactionReceipt({ hash, timeout: 180_000 });
const vaultAfter = await wethBalance(vaultAddr, rc.blockNumber);
const funderAfter = await wethBalance(funder, rc.blockNumber);
check('mined on Sepolia: 0.00006 WETH left the vault and reached the owner\'s address',
  rc.status === 'success' && vaultAfter === WRAPPED - PAY && funderAfter - funderBefore === PAY, link(hash));

r = call(VAULT, OWNER, 'execute_proposal', { token_id: t, proposal_id: p2 }, '0.02 NEAR', '300 Tgas');
check('the second transfer is refused at signing: together they exceed the daily cap', r.panic?.endsWith('token daily cap exceeded'), r.panic);

console.log(`\nvault ${t}: ${vaultAddr}`);
console.log(failures === 0 ? 'ALL CHECKS PASSED' : `${failures} CHECK(S) FAILED`);
process.exit(failures === 0 ? 0 : 1);
