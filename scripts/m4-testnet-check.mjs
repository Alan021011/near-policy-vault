// M4 checks on testnet: every vault's EVM address stored by the contract must equal an
// independent derivation (signer's derived_public_key queried here + keccak256 with viem).
// Also: the callback cannot be called from outside, and a resolved address cannot be redone.
//
// Usage: node m4-testnet-check.mjs <owner-account> <vault-contract>
// Needs the NEAR CLI with the owner's key in the keychain. Mints one vault (0.1 NEAR, most refunded)
// and pays 0.01 NEAR (mostly refunded) for each old vault that has no record yet.
import { spawnSync } from 'node:child_process';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { keccak256 } from 'viem';

const [OWNER, VAULT] = process.argv.slice(2);
if (!VAULT) throw new Error('usage: node m4-testnet-check.mjs <owner> <vault-contract>');
const NEAR = process.env.NEAR_CLI || join(homedir(), '.cargo', 'bin', process.platform === 'win32' ? 'near.exe' : 'near');
const RPC = process.env.NEAR_RPC || 'https://rpc.testnet.near.org';
const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
let failures = 0;

const check = (name, ok, detail = '') => {
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${detail ? '  — ' + detail : ''}`);
  if (!ok) failures++;
};

async function rpc(method, params) {
  const j = await fetch(RPC, { method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }) }).then((r) => r.json());
  if (j.error) throw new Error(`${method}: ${JSON.stringify(j.error)}`);
  return j.result;
}

async function view(account, method, args) {
  const r = await rpc('query', { request_type: 'call_function', finality: 'final', account_id: account,
    method_name: method, args_base64: Buffer.from(JSON.stringify(args)).toString('base64') });
  return JSON.parse(Buffer.from(r.result).toString());
}

function call(signer, method, args, deposit, gas = '100 Tgas') {
  const p = spawnSync(NEAR, ['contract', 'call-function', 'as-transaction', VAULT, method,
    'json-args', JSON.stringify(args), 'prepaid-gas', gas, 'attached-deposit', deposit,
    'sign-as', signer, 'network-config', 'testnet', 'sign-with-keychain', 'send'], { encoding: 'utf8' });
  return (p.stdout || '') + (p.stderr || '');
}

/** Independent derivation: ask the signer directly, then keccak256 with viem. */
async function independentAddress(signerId, path) {
  const key = await view(signerId, 'derived_public_key', { path, predecessor: VAULT, domain_id: 0 });
  let n = 0n;
  for (const c of key.slice('secp256k1:'.length)) n = n * 58n + BigInt(B58.indexOf(c));
  return '0x' + keccak256('0x' + n.toString(16).padStart(128, '0')).slice(-40);
}

// 1. Old vaults (minted before M4): resolve if needed, then compare.
const supply = Number(await view(VAULT, 'nft_total_supply', {}));
for (let i = 0; i < supply; i++) {
  const t = String(i);
  let info = await view(VAULT, 'vault_info', { token_id: t });
  if (!info.evm_address) {
    call(OWNER, 'resolve_vault_address', { token_id: t }, '0.01 NEAR');
    info = await view(VAULT, 'vault_info', { token_id: t });
  }
  const indep = await independentAddress(info.signer_id, info.path);
  check(`vault ${t}: contract address equals independent derivation`, info.evm_address === indep, `${info.evm_address} vs ${indep}`);
}

// 2. A new vault is resolved within the mint transaction.
const out = call(OWNER, 'mint_vault', {}, '0.1 NEAR');
const tid = out.match(/"token_ids":\["(\d+)"\]/)?.[1];
check('new vault minted', tid !== undefined);
if (tid !== undefined) {
  check('mint emitted vault_address in the same transaction', out.includes('"event":"vault_address"'));
  const info = await view(VAULT, 'vault_info', { token_id: tid });
  const indep = await independentAddress(info.signer_id, info.path);
  check(`vault ${tid}: contract address equals independent derivation`, info.evm_address === indep, `${info.evm_address} vs ${indep}`);

  // 3. Attacks.
  const a = call(OWNER, 'on_derived_key', { token_id: tid }, '0 NEAR', '30 Tgas');
  check('outsider cannot call the private callback', /is private/i.test(a), (a.match(/Smart contract panicked: [^"\n)]*/) || ['no panic'])[0]);
  const b = call(OWNER, 'resolve_vault_address', { token_id: tid }, '0 NEAR');
  check('resolved address cannot be requested again', /already resolved/.test(b));
  const after = await view(VAULT, 'vault_info', { token_id: tid });
  check('address unchanged after the attacks', after.evm_address === info.evm_address);
}

console.log(failures === 0 ? '\nALL CHECKS PASSED' : `\n${failures} CHECK(S) FAILED`);
process.exit(failures === 0 ? 0 : 1);
