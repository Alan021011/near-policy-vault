// Sends Sepolia ETH from the owner's own Chain Signatures account ("ethereum-1", as in A1) to a
// vault, so the vault can pay the gas of the transactions the contract signs for it.
// Usage: node fund-vault.mjs <owner> <vault-contract> <token_id> <eth amount>
import { spawnSync } from 'node:child_process';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { createPublicClient, http, keccak256, parseEther, serializeTransaction } from 'viem';
import { sepolia } from 'viem/chains';

const [OWNER, VAULT, T, AMOUNT] = process.argv.slice(2);
if (!AMOUNT) throw new Error('usage: node fund-vault.mjs <owner> <vault-contract> <token_id> <eth amount>');
const NEAR = process.env.NEAR_CLI || join(homedir(), '.cargo', 'bin', process.platform === 'win32' ? 'near.exe' : 'near');
const RPC = process.env.NEAR_RPC || 'https://rpc.testnet.fastnear.com';
const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const eth = createPublicClient({ chain: sepolia, transport: http('https://ethereum-sepolia-rpc.publicnode.com') });

async function view(account, method, args) {
  const j = await fetch(RPC, { method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'query', params: { request_type: 'call_function', finality: 'final',
      account_id: account, method_name: method, args_base64: Buffer.from(JSON.stringify(args)).toString('base64') } }) }).then((r) => r.json());
  if (j.error) throw new Error(JSON.stringify(j.error));
  return JSON.parse(Buffer.from(j.result.result).toString());
}
const key = await view('v1.signer-prod.testnet', 'derived_public_key', { path: 'ethereum-1', predecessor: OWNER, domain_id: 0 });
let n = 0n;
for (const c of key.slice('secp256k1:'.length)) n = n * 58n + BigInt(B58.indexOf(c));
const funder = '0x' + keccak256('0x' + n.toString(16).padStart(128, '0')).slice(-40);
const to = (await view(VAULT, 'vault_info', { token_id: T })).evm_address;
const value = parseEther(AMOUNT);
const block = await eth.getBlock();
const tx = { type: 'eip1559', chainId: sepolia.id, nonce: await eth.getTransactionCount({ address: funder }),
  maxPriorityFeePerGas: 1_000_000_000n, maxFeePerGas: block.baseFeePerGas * 2n + 1_000_000_000n,
  gas: (await eth.estimateGas({ account: funder, to, value })) * 12n / 10n, to, value, data: '0x', accessList: [] };
const p = spawnSync(NEAR, ['contract', 'call-function', 'as-transaction', 'v1.signer-prod.testnet', 'sign', 'json-args',
  JSON.stringify({ request: { domain_id: 0, path: 'ethereum-1', payload_v2: { Ecdsa: keccak256(serializeTransaction(tx)).slice(2) } } }),
  'prepaid-gas', '100 Tgas', 'attached-deposit', '1 yoctoNEAR', 'sign-as', OWNER, 'network-config', 'testnet', 'sign-with-keychain', 'send'], { encoding: 'utf8' });
const sig = JSON.parse(p.stdout.trim());
const raw = serializeTransaction(tx, { r: '0x' + sig.big_r.affine_point.slice(2), s: '0x' + sig.s.scalar, yParity: sig.recovery_id });
const rc = await eth.waitForTransactionReceipt({ hash: await eth.sendRawTransaction({ serializedTransaction: raw }), timeout: 180_000 });
console.log(`${rc.status}: ${AMOUNT} ETH from ${funder} to vault ${T} (${to}) https://sepolia.etherscan.io/tx/${rc.transactionHash}`);
