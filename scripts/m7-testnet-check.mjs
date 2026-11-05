// M7 end to end on testnet + Sepolia: an NFT vault spends ETH under its policy.
// 1. mint a vault; its EVM address is published by the contract (M4);
// 2. fund that address from the A1 address (the owner's own Chain Signatures account,
//    path "ethereum-1"), signed by the MPC network like in A1;
// 3. set a policy, propose 0.001 ETH from the vault to the A1 address, wait the delay;
// 4. execute: the contract charges the cap, asks the MPC network to sign, verifies the
//    signature against the vault key and stores the raw transaction;
// 5. anyone reads that raw transaction from the contract and broadcasts it; it is mined from
//    the vault's address.
//
// Usage: node m7-testnet-check.mjs <owner> <vault-contract> <guardian>
// The owner's NEAR key must be in the keychain, and the owner's "ethereum-1" address must
// hold some Sepolia ETH (it funds the vault with 0.003 ETH). About 2-3 minutes.
import { spawnSync } from 'node:child_process';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { createPublicClient, http, keccak256, parseTransaction, recoverTransactionAddress, serializeTransaction } from 'viem';
import { sepolia } from 'viem/chains';

const [OWNER, VAULT, GUARDIAN] = process.argv.slice(2);
if (!GUARDIAN) throw new Error('usage: node m7-testnet-check.mjs <owner> <vault-contract> <guardian>');
const NEAR = process.env.NEAR_CLI || join(homedir(), '.cargo', 'bin', process.platform === 'win32' ? 'near.exe' : 'near');
const RPC = process.env.NEAR_RPC || 'https://rpc.testnet.near.org';
const SIGNER = 'v1.signer-prod.testnet';
const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const DELAY_MS = 60_000;
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
function call(contract, signer, method, args, deposit, gas = '300 Tgas') {
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

// ---------- 1. a new vault and its address ----------
const t = events(call(VAULT, OWNER, 'mint_vault', {}, '0.1 NEAR', '100 Tgas').out, 'nft_mint')[0]?.data[0].token_ids[0];
check('vault minted', t !== undefined);
const vaultAddr = (await view(VAULT, 'vault_info', { token_id: t })).evm_address;
check('the contract published the vault address', /^0x[0-9a-f]{40}$/.test(vaultAddr ?? ''), vaultAddr);

// ---------- 2. fund it from the owner's own Chain Signatures account (like A1) ----------
const fundingKey = await view(SIGNER, 'derived_public_key', { path: 'ethereum-1', predecessor: OWNER, domain_id: 0 });
const funder = addressOfKey(fundingKey);
const f = await fees();
// Sepolia's current gas rules charge ~207k gas to send ETH to a never-used address (a new
// vault) and ~12k to an existing one, so the gas limit is estimated, not assumed to be 21000.
const fundGas = (await eth.estimateGas({ account: funder, to: vaultAddr, value: 3_000_000_000_000_000n })) * 12n / 10n;
const fundTx = { type: 'eip1559', chainId: sepolia.id, nonce: await eth.getTransactionCount({ address: funder }),
  ...f, gas: fundGas, to: vaultAddr, value: 3_000_000_000_000_000n, data: '0x', accessList: [] };
const fundHash = keccak256(serializeTransaction(fundTx));
const sig = JSON.parse(call(SIGNER, OWNER, 'sign', { request: { domain_id: 0, path: 'ethereum-1',
  payload_v2: { Ecdsa: fundHash.slice(2) } } }, '1 yoctoNEAR').stdout);
const fundRaw = serializeTransaction(fundTx, { r: '0x' + sig.big_r.affine_point.slice(2), s: '0x' + sig.s.scalar, yParity: sig.recovery_id });
const fundRcpt = await eth.waitForTransactionReceipt({ hash: await eth.sendRawTransaction({ serializedTransaction: fundRaw }), timeout: 180_000 });
check(`vault funded with 0.003 ETH from ${funder.slice(0, 10)}…`, fundRcpt.status === 'success', fundRcpt.transactionHash);

// ---------- 3. policy and proposal ----------
call(VAULT, OWNER, 'set_policy', { token_id: t, policy: {
  chain_id: sepolia.id, delay_ms: DELAY_MS, guardian: GUARDIAN,
  eth_daily_cap: '2000000000000000', max_gas_cost: String(21000n * 50n * 10n ** 9n),
  allowed_destinations: [funder], allowed_spenders: [], tokens: [] } }, '0.05 NEAR', '100 Tgas');
const pf = await fees();
const ptx = { chain_id: sepolia.id, max_priority_fee_per_gas: String(pf.maxPriorityFeePerGas),
  max_fee_per_gas: String(pf.maxFeePerGas), gas_limit: 21000, to: funder, value: '1000000000000000', data: '0x' };
let r = call(VAULT, OWNER, 'propose', { token_id: t, tx: ptx }, '0.05 NEAR', '100 Tgas');
const pid = events(r.out, 'proposal_created')[0]?.data[0].proposal_id;
check('proposal of 0.001 ETH queued', pid !== undefined, r.panic);
r = call(VAULT, OWNER, 'execute_proposal', { token_id: t, proposal_id: pid }, '0.02 NEAR');
check('executing before the delay is refused', r.panic === 'Proposal delay has not passed yet', r.panic);
console.log(`      waiting ${DELAY_MS / 1000 + 5} s for the delay...`);
await sleep(DELAY_MS + 5000);

// ---------- 4. the contract signs ----------
r = call(VAULT, OWNER, 'execute_proposal', { token_id: t, proposal_id: pid }, '0.02 NEAR');
check('execute_proposal: signature verified and stored (callback returned true)', r.stdout === 'true' && !r.panic, r.panic ?? r.stdout);
check('event transaction_signed emitted', events(r.out, 'transaction_signed').length === 1);
const rec = await view(VAULT, 'get_signed', { token_id: t, nonce: 0 });
check('signed record stored with nonce 0', rec && rec.nonce === 0 && rec.proposal_id === pid);
check('nothing left in flight; next nonce is 1', (await view(VAULT, 'get_inflight', { token_id: t })) === null && (await view(VAULT, 'get_next_nonce', { token_id: t })) === 1);
const parsed = parseTransaction(rec.signed_tx);
const from = (await recoverTransactionAddress({ serializedTransaction: rec.signed_tx })).toLowerCase();
check('viem recovers the vault address from the stored transaction', from === vaultAddr, from);
check('stored transaction has the proposed fields', parsed.to.toLowerCase() === funder && parsed.value === 1_000_000_000_000_000n && parsed.nonce === 0 && parsed.chainId === sepolia.id);
check('stored tx_hash is keccak of the raw transaction', rec.tx_hash === keccak256(rec.signed_tx));

// ---------- 5. anyone broadcasts it ----------
const h = await eth.sendRawTransaction({ serializedTransaction: rec.signed_tx });
const rcpt = await eth.waitForTransactionReceipt({ hash: h, timeout: 180_000 });
check('mined on Sepolia from the vault address', rcpt.status === 'success' && rcpt.from.toLowerCase() === vaultAddr && h === rec.tx_hash, `https://sepolia.etherscan.io/tx/${h}`);
const spent = (await view(VAULT, 'get_policy', { token_id: t })).spend.eth.spent;
check('the daily cap was charged at signing', BigInt(spent) > 0n, `${spent} wei`);

console.log(`\nvault ${t}: ${vaultAddr}`);
console.log(failures === 0 ? 'ALL CHECKS PASSED' : `${failures} CHECK(S) FAILED`);
process.exit(failures === 0 ? 0 : 1);
