// An NFT vault sends an ERC-721 on Sepolia under its policy (after M12: NFTs in the policy).
// 1. mint a vault; the owner's own Chain Signatures account ("ethereum-1", as in A1) deploys the
//    test collection scripts/nft/TestNFT.sol (or reuses one given as 4th argument), sends the vault
//    ETH for gas and mints two NFTs straight to the vault's address;
// 2. the policy allows that collection, 1 NFT a day, only to the owner's address;
// 3. refused: an NFT transfer that does not send from the vault;
// 4. two transfers queued; after the delay the first is signed through the contract and mined
//    (the NFT changes owner on Sepolia) and the second is refused at signing (daily count).
//
// Usage: node nft-testnet-check.mjs <owner> <vault-contract> <guardian> [nft-contract]
// The owner's NEAR key must be in the keychain, and "ethereum-1" needs ~0.004 Sepolia ETH. ~4 min.
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { createPublicClient, decodeFunctionResult, encodeFunctionData, http, keccak256, parseTransaction, recoverTransactionAddress, serializeTransaction } from 'viem';
import { sepolia } from 'viem/chains';

const [OWNER, VAULT, GUARDIAN, NFT_ARG] = process.argv.slice(2);
if (!GUARDIAN) throw new Error('usage: node nft-testnet-check.mjs <owner> <vault-contract> <guardian> [nft-contract]');
const NEAR = process.env.NEAR_CLI || join(homedir(), '.cargo', 'bin', process.platform === 'win32' ? 'near.exe' : 'near');
const RPC = process.env.NEAR_RPC || 'https://rpc.testnet.fastnear.com';
const SIGNER = 'v1.signer-prod.testnet';
const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const DELAY_MS = 60_000;
const ART = JSON.parse(readFileSync(new URL('./nft/TestNFT.json', import.meta.url)));
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
const safeTransfer = (from, to, id) => '0x42842e0e' + word(from) + word(to) + word(id);
const link = (h) => `https://sepolia.etherscan.io/tx/${h}`;

async function view(account, method, args) {
  const j = await fetch(RPC, { method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'query', params: { request_type: 'call_function', finality: 'final',
      account_id: account, method_name: method, args_base64: Buffer.from(JSON.stringify(args)).toString('base64') } }) }).then((r) => r.json());
  if (j.error) throw new Error(JSON.stringify(j.error));
  return JSON.parse(Buffer.from(j.result.result).toString());
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
  return { maxPriorityFeePerGas: 1_000_000_000n, maxFeePerGas: block.baseFeePerGas * 2n + 1_000_000_000n };
}
async function estimate(params) {
  for (let i = 0; ; i++) {
    try {
      return (await eth.estimateGas(params)) * 13n / 10n;
    } catch (e) {
      if (i >= 5) throw e;
      await sleep(3000);
    }
  }
}
/** The owner's own Chain Signatures account signs and sends a transaction (`to` undefined = deploy). */
async function funderSend(funder, nonce, to, value, data) {
  const f = await fees();
  const gas = await estimate({ account: funder, to, value, data });
  const tx = { type: 'eip1559', chainId: sepolia.id, nonce, ...f, gas, ...(to ? { to } : {}), value, data, accessList: [] };
  const sig = JSON.parse(call(SIGNER, OWNER, 'sign', { request: { domain_id: 0, path: 'ethereum-1',
    payload_v2: { Ecdsa: keccak256(serializeTransaction(tx)).slice(2) } } }, '1 yoctoNEAR').stdout);
  const raw = serializeTransaction(tx, { r: '0x' + sig.big_r.affine_point.slice(2), s: '0x' + sig.s.scalar, yParity: sig.recovery_id });
  return eth.waitForTransactionReceipt({ hash: await eth.sendRawTransaction({ serializedTransaction: raw }), timeout: 180_000 });
}
const ownerOf = async (nft, id, blockNumber) => decodeFunctionResult({ abi: ART.abi, functionName: 'ownerOf',
  data: (await eth.call({ to: nft, data: encodeFunctionData({ abi: ART.abi, functionName: 'ownerOf', args: [id] }), blockNumber })).data }).toLowerCase();

// ---------- 1. vault, collection, ETH for gas, two NFTs owned by the vault ----------
const t = events(call(VAULT, OWNER, 'mint_vault', {}, '0.1 NEAR').out, 'nft_mint')[0]?.data[0].token_ids[0];
const vaultAddr = t === undefined ? undefined : (await view(VAULT, 'vault_info', { token_id: t })).evm_address;
check('vault minted, its address published', /^0x[0-9a-f]{40}$/.test(vaultAddr ?? ''), `vault ${t}: ${vaultAddr}`);
const funder = addressOfKey(await view(SIGNER, 'derived_public_key', { path: 'ethereum-1', predecessor: OWNER, domain_id: 0 }));
let nonce = await eth.getTransactionCount({ address: funder });
let nft = NFT_ARG?.toLowerCase();
if (!nft) {
  const d = await funderSend(funder, nonce++, undefined, 0n, ART.bytecode);
  nft = d.contractAddress?.toLowerCase();
  check(`the owner's account deployed the test collection (${ART.compiler})`, d.status === 'success' && !!nft, `${nft} ${link(d.transactionHash)}`);
} else {
  check('reusing the test collection', /^0x[0-9a-f]{40}$/.test(nft), nft);
}
const firstId = BigInt(decodeFunctionResult({ abi: ART.abi, functionName: 'nextId',
  data: (await eth.call({ to: nft, data: encodeFunctionData({ abi: ART.abi, functionName: 'nextId' }) })).data }));
const r1 = await funderSend(funder, nonce++, vaultAddr, 2_000_000_000_000_000n, '0x');
await funderSend(funder, nonce++, nft, 0n, encodeFunctionData({ abi: ART.abi, functionName: 'mint', args: [vaultAddr] }));
const r3 = await funderSend(funder, nonce++, nft, 0n, encodeFunctionData({ abi: ART.abi, functionName: 'mint', args: [vaultAddr] }));
const [idA, idB] = [firstId, firstId + 1n];
check(`the vault received 0.002 ETH and owns NFTs #${idA} and #${idB}`, r1.status === 'success'
  && (await ownerOf(nft, idA, r3.blockNumber)) === vaultAddr && (await ownerOf(nft, idB, r3.blockNumber)) === vaultAddr, link(r3.transactionHash));

// ---------- 2. a policy that allows that collection, 1 NFT a day, to the owner's address ----------
const pf = await fees();
const policy = {
  chain_id: sepolia.id, delay_ms: DELAY_MS, guardian: GUARDIAN,
  eth_daily_cap: '2000000000000000', max_gas_cost: String(150_000n * pf.maxFeePerGas * 2n),
  allowed_destinations: [funder], allowed_spenders: [], tokens: [],
  nfts: [{ contract: nft, daily_count: '1' }],
};
let r = call(VAULT, OWNER, 'set_policy', { token_id: t, policy }, '0.05 NEAR');
check('policy set: this collection only, 1 NFT a day, to the owner\'s address, 60 s delay, a guardian', r.stdout === 'true', r.panic ?? r.stdout);
const gasLimit = Number(await estimate({ account: vaultAddr, to: nft, data: safeTransfer(vaultAddr, funder, idA) }));
const nftTx = (from, id) => ({ chain_id: sepolia.id, max_priority_fee_per_gas: String(pf.maxPriorityFeePerGas),
  max_fee_per_gas: String(pf.maxFeePerGas), gas_limit: gasLimit, to: nft, value: '0', data: safeTransfer(from, funder, id) });

// ---------- 3. refused: an NFT the vault does not send itself ----------
r = call(VAULT, OWNER, 'propose', { token_id: t, tx: nftTx(funder, idA) }, '0.05 NEAR');
check('an NFT transfer that does not send from the vault is refused', r.panic === 'an NFT transfer must send from the vault\'s own address', r.panic);

// ---------- 4. two transfers; only one fits the daily count ----------
r = call(VAULT, OWNER, 'propose', { token_id: t, tx: nftTx(vaultAddr, idA) }, '0.05 NEAR');
const p1 = events(r.out, 'proposal_created')[0]?.data[0].proposal_id;
r = call(VAULT, OWNER, 'propose', { token_id: t, tx: nftTx(vaultAddr, idB) }, '0.05 NEAR');
const p2 = events(r.out, 'proposal_created')[0]?.data[0].proposal_id;
check(`two NFT transfers queued (#${idA}, #${idB})`, p1 !== undefined && p2 !== undefined, r.panic);
console.log(`      waiting ${DELAY_MS / 1000 + 5} s for the delay...`);
await sleep(DELAY_MS + 5000);

r = call(VAULT, OWNER, 'execute_proposal', { token_id: t, proposal_id: p1 }, '0.02 NEAR', '300 Tgas');
check('the first NFT transfer is signed through the contract (MPC signature checked against the vault key)', r.stdout === 'true' && !r.panic, r.panic ?? r.stdout);
const rec = await view(VAULT, 'get_signed', { token_id: t, nonce: 0 });
const parsed = parseTransaction(rec.signed_tx);
const from = (await recoverTransactionAddress({ serializedTransaction: rec.signed_tx })).toLowerCase();
check(`the signed transaction is exactly safeTransferFrom(vault, owner, ${idA}) from the vault`,
  from === vaultAddr && parsed.to.toLowerCase() === nft && parsed.data === safeTransfer(vaultAddr, funder, idA) && !parsed.value);
const hash = await eth.sendRawTransaction({ serializedTransaction: rec.signed_tx });
const rc = await eth.waitForTransactionReceipt({ hash, timeout: 180_000 });
check(`mined on Sepolia: NFT #${idA} left the vault and reached the owner's address`,
  rc.status === 'success' && (await ownerOf(nft, idA, rc.blockNumber)) === funder && (await ownerOf(nft, idB, rc.blockNumber)) === vaultAddr, link(hash));

r = call(VAULT, OWNER, 'execute_proposal', { token_id: t, proposal_id: p2 }, '0.02 NEAR', '300 Tgas');
check('the second NFT transfer is refused at signing: 1 NFT a day', r.panic?.endsWith('NFT daily count exceeded'), r.panic);

console.log(`\nvault ${t}: ${vaultAddr}  collection ${nft}`);
console.log(failures === 0 ? 'ALL CHECKS PASSED' : `${failures} CHECK(S) FAILED`);
process.exit(failures === 0 ? 0 : 1);
