// Buyer's audit before taking a vault (M8, threat 1; general review H2 and H5). The contract
// cannot read Ethereum, so this script does the checks it cannot:
// 1. Kept signatures. Every signature the contract ever produced uses a nonce below
//    `get_next_nonce`. If the vault's account has already used all of them (its mined nonce
//    equals the contract's next nonce), no signature the seller may have kept can be mined.
//    Otherwise each nonce in [mined nonce, next nonce) must be cancelled (`cancel_nonce`, allowed
//    during the sale) and the cancellation mined. Anyone can broadcast it: it is public.
// 2. ERC-20 allowances. An `approve` that was already mined leaves no pending signature, but the
//    spender can still take the vault's tokens after the sale. The script finds every `approve`
//    in the vault's signed history and asks the token for the allowance that is left.
// 3. The contract itself: its code hash and whether it still has a full-access key (if it does,
//    whoever holds that key can change the code; threat 9). `--expect-code <sha256 hex>` makes a
//    different code hash a failure.
// It also prints the vault's balance on its chain (funds at the same address on other EVM chains
// cannot be moved by this vault) and how to buy or bind the purchase to the audited sale.
//
// Review M12 also checks: a nonce whose signature outcome was uncertain but that is already mined
// (something the contract never recorded was mined with it), Approval events of the vault on every
// token its policy names or its history touched, that the sale did not change during the audit,
// and every version of every nonce (list_signed pages by record count).
//
// Usage: node sale-audit.mjs <vault-contract> <token_id> [--eth-rpc <url>] [--expect-code <hex>]
// Exit code 0 = SAFE, 2 = NOT SAFE or INCOMPLETE (a check could not be completed: never treated as safe).
import { fileURLToPath } from 'node:url';
import { parseTransaction } from 'viem';

const NEAR_RPC = process.env.NEAR_RPC || 'https://rpc.testnet.near.org';
const DEFAULT_ETH_RPC = { 11155111: 'https://ethereum-sepolia-rpc.publicnode.com', 560048: 'https://ethereum-hoodi-rpc.publicnode.com' };
const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const SEL_APPROVE = '0x095ea7b3';
const SEL_ALLOWANCE = '0xdd62ed3e';
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function nearRpc(method, params, attempt = 1) {
  try {
    const res = await fetch(NEAR_RPC, { method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }) });
    if (res.status === 429 || res.status >= 500) throw new Error(`HTTP ${res.status}`);
    const j = await res.json();
    if (j.error) throw new Error(JSON.stringify(j.error));
    return j.result;
  } catch (e) {
    if (attempt >= 5) throw e;
    await sleep(2000 * attempt);
    return nearRpc(method, params, attempt + 1);
  }
}

async function nearView(contract, method, args) {
  const r = await nearRpc('query', { request_type: 'call_function', finality: 'final', account_id: contract,
    method_name: method, args_base64: Buffer.from(JSON.stringify(args)).toString('base64') });
  return JSON.parse(Buffer.from(r.result).toString());
}

async function eth(rpc, method, params) {
  const j = await fetch(rpc, { method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }) }).then((r) => r.json());
  if (j.error) throw new Error(j.error.message);
  return j.result;
}

function base58ToHex(s) {
  let n = 0n;
  for (const c of s) n = n * 58n + BigInt(B58.indexOf(c));
  return n.toString(16).padStart(64, '0');
}

const word = (addr) => addr.toLowerCase().replace(/^0x/, '').padStart(64, '0');

const APPROVAL_TOPIC = '0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925';
const LOG_RANGE = 50_000; // the public RPC's largest eth_getLogs range
// Old Approval events: some public nodes answer "pruned history unavailable"; ask nodes that keep the
// history in turn (an --eth-rpc given by the user is tried first), a few times each.
const LOG_RPCS = ['https://sepolia.gateway.tenderly.co', 'https://ethereum-sepolia-rpc.publicnode.com'];
async function getLogs(first, filter) {
  const urls = [...new Set([first, ...LOG_RPCS].filter(Boolean))];
  let last;
  for (let i = 0; i < urls.length * 3; i++) {
    try {
      const r = await eth(urls[i % urls.length], 'eth_getLogs', [filter]);
      if (Array.isArray(r)) return r;
      throw new Error('no result');
    } catch (e) {
      last = e;
      await new Promise((ok) => setTimeout(ok, 300));
    }
  }
  throw last;
}

/** Every signed record of a vault, all versions. list_signed pages by record count, so a full
 *  page is continued from its last nonce and duplicates are dropped (review M12, R12-8). */
async function allSigned(contract, tokenId, next) {
  const seen = new Map();
  let from = 0;
  for (let guard = 0; from < next && guard < 1000; guard++) {
    const page = await nearView(contract, 'list_signed', { token_id: tokenId, from_nonce: from, limit: 100 });
    if (page.length === 0) break;
    for (const r of page) seen.set(`${r.nonce}|${r.tx_hash}`, r);
    const last = page[page.length - 1].nonce;
    from = page.length < 100 || page[0].nonce === last ? last + 1 : last;
  }
  return [...seen.values()];
}

/** Returns { safe, lines[], problems[], outstanding[], allowances[], ... } for a vault. */
export async function audit(contract, tokenId, ethRpc, expectCode) {
  const lines = [];
  const problems = [];
  const owner = (await nearView(contract, 'nft_token', { token_id: tokenId }))?.owner_id;
  const info = await nearView(contract, 'vault_info', { token_id: tokenId });
  const chain = await nearView(contract, 'get_vault_chain', { token_id: tokenId });
  const next = await nearView(contract, 'get_next_nonce', { token_id: tokenId });
  const uncertain = await nearView(contract, 'get_uncertain', { token_id: tokenId });
  const inflight = await nearView(contract, 'get_inflight', { token_id: tokenId });
  const sale = await nearView(contract, 'get_sale', { token_id: tokenId });
  const token = await nearView(contract, 'nft_token', { token_id: tokenId });
  const policy = await nearView(contract, 'get_policy', { token_id: tokenId });
  lines.push(`vault ${tokenId} of ${contract}, owner ${owner}`);
  lines.push(`EVM address ${info.evm_address ?? '(not resolved)'}, chain ${chain ?? '(never signed)'}`);

  // The contract: is it the code the buyer expects, and can someone still change it?
  const acct = await nearRpc('query', { request_type: 'view_account', finality: 'final', account_id: contract });
  const codeHex = base58ToHex(acct.code_hash);
  const keys = await nearRpc('query', { request_type: 'view_access_key_list', finality: 'final', account_id: contract });
  const fullKeys = keys.keys.filter((k) => k.access_key.permission === 'FullAccess').length;
  lines.push(`contract code sha256 ${codeHex}`);
  if (fullKeys > 0) lines.push(`note: the contract still has ${fullKeys} full-access key(s): whoever holds one can change its code (threat 9)`);
  else if (keys.keys.length === 0) lines.push('ok: the contract account has no access keys: nobody can change its code');
  if (expectCode && expectCode.toLowerCase() !== codeHex) problems.push(`the contract code is not the expected one (${expectCode})`);

  if (inflight) problems.push(`a signature is in flight (nonce ${inflight.nonce}); wait for it to finish`);
  const now = Date.now();
  if (!sale) problems.push('no sale is active: the owner must call start_sale');
  else if (now < sale.opens_at_ms) lines.push(`sale ${sale.sale_id} opens in ${Math.ceil((sale.opens_at_ms - now) / 1000)} s (the guardian can still veto it)`);
  else if (now >= sale.closes_at_ms) problems.push('the sale window has closed');
  else lines.push(`sale ${sale.sale_id} open until ${new Date(sale.closes_at_ms).toISOString()}`);
  if (sale?.price) {
    lines.push(`buy it with buy(token_id "${tokenId}", sale_id ${sale.sale_id}) attaching ${sale.price} yoctoNEAR${sale.buyer ? ` (reserved for ${sale.buyer})` : ''}: it fails if the seller restarts the sale`);
  } else if (sale) {
    lines.push(`no on-chain price: bind the purchase to this sale with memo "sale:${sale.sale_id}" (it fails if the seller restarts the sale)`);
  }

  let mined = 0;
  const outstanding = [];
  const allowances = [];
  const rpc = ethRpc || (chain ? DEFAULT_ETH_RPC[chain] : undefined);
  // Every Ethereum read uses one block, a little behind the head, from an up-to-date node; a node more
  // than 5 minutes behind makes the audit INCOMPLETE (external review, second round).
  let tag = 'latest';
  let pinned = null;
  if (rpc) {
    const head = await eth(rpc, 'eth_getBlockByNumber', ['latest', false]);
    pinned = Number(BigInt(head.number)) - 2;
    tag = '0x' + pinned.toString(16);
    const age = Math.round(Date.now() / 1000 - Number(BigInt(head.timestamp)));
    if (age > 300) problems.push(`INCOMPLETE: the Ethereum node's newest block is ${age} s old; run the audit again or use another --eth-rpc`);
    else lines.push(`Ethereum read at block ${pinned} (node up to date)`);
  }
  if (next > 0) {
    if (!rpc) throw new Error(`no RPC known for chain ${chain}; pass --eth-rpc`);
    mined = Number(BigInt(await eth(rpc, 'eth_getTransactionCount', [info.evm_address, tag])));
    const pending = Number(BigInt(await eth(rpc, 'eth_getTransactionCount', [info.evm_address, 'pending'])));
    lines.push(`nonces: contract next = ${next}, mined on chain = ${mined}, pending in mempool = ${pending}`);
    for (let n = mined; n < next; n++) {
      const versions = await nearView(contract, 'get_signed_versions', { token_id: tokenId, nonce: n });
      outstanding.push({ nonce: n, versions });
      const kinds = versions.map((v) => (v.proposal_id > 1e18 ? 'cancellation' : `payment (proposal ${v.proposal_id})`));
      problems.push(`nonce ${n} is signed but not mined: ${kinds.join(', ') || 'outcome unknown'} — the seller should cancel_nonce(${n}); anyone can then broadcast the cancellation (get_signed_versions) and it must be mined`);
    }

    // ERC-20 allowances (general review H2; review M12, R12-6): approvals in the signed history
    // and Approval events of the vault on every token its policy names or its history touched.
    const pairs = new Map();
    const tokens = new Set();
    for (const t of policy?.policy?.tokens ?? []) tokens.add(t.contract.toLowerCase());
    for (const t of policy?.pending?.policy?.tokens ?? []) tokens.add(t.contract.toLowerCase());
    for (const rec of await allSigned(contract, tokenId, next)) {
      const tx = parseTransaction(rec.signed_tx);
      if (tx.data && tx.data.length >= 10 && tx.to) tokens.add(tx.to.toLowerCase());
      if (tx.data && tx.data.startsWith(SEL_APPROVE) && tx.data.length === 2 + 8 + 128) {
        const spender = '0x' + tx.data.slice(2 + 8 + 24, 2 + 8 + 64);
        pairs.set(`${tx.to.toLowerCase()}|${spender}`, { token: tx.to.toLowerCase(), spender });
      }
    }
    try {
      const latest = pinned;
      const from = Math.max(0, latest - Math.ceil((Date.now() - Number(token?.metadata?.issued_at ?? 0)) / 12000) - 2000);
      for (const t of tokens) {
        for (let f = from; f <= latest; f += LOG_RANGE) {
          const logs = await getLogs(rpc, { address: t, fromBlock: '0x' + f.toString(16), toBlock: '0x' + Math.min(latest, f + LOG_RANGE - 1).toString(16), topics: [APPROVAL_TOPIC, '0x' + word(info.evm_address)] });
          for (const l of logs) pairs.set(`${t}|0x${l.topics[2].slice(26)}`, { token: t, spender: '0x' + l.topics[2].slice(26) });
        }
      }
    } catch (e) {
      // Fail closed: a check that could not run is not a pass (the approvals in the signed history are
      // still checked below, but the audit cannot say SAFE without the event scan).
      problems.push(`INCOMPLETE: Approval events could not be scanned (${e.message}); run the audit again, or with --eth-rpc pointing at another node`);
    }
    for (const { token, spender } of pairs.values()) {
      const left = BigInt(await eth(rpc, 'eth_call', [{ to: token, data: SEL_ALLOWANCE + word(info.evm_address) + word(spender) }, tag]));
      allowances.push({ token, spender, allowance: left.toString() });
      if (left > 0n) {
        problems.push(`token ${token}: ${spender} may still take ${left} units (an approval survives the sale) — before selling, the seller cancels the sale, signs approve(${spender}, 0), mines it and starts a new sale`);
      }
    }
    lines.push(`ERC-20 approvals ever signed: ${pairs.size}${pairs.size ? `, allowance left on each: ${allowances.map((a) => a.allowance).join(', ')}` : ''}`);
  } else {
    lines.push('the vault never signed anything');
  }
  if (rpc && info.evm_address) {
    const bal = BigInt(await eth(rpc, 'eth_getBalance', [info.evm_address, tag]));
    lines.push(`balance on chain ${chain ?? '(the policy chain)'}: ${bal} wei; funds at this address on other EVM chains cannot be moved by this vault`);
  }
  // Review M12 (R12-6): an uncertain nonce below the mined nonce means something the contract
  // never recorded was mined with it (it could have been an approval or a payment).
  for (const u of uncertain) {
    if (u.nonce < mined) problems.push(`nonce ${u.nonce} was mined, but the contract never recorded what was signed (uncertain outcome, signing hash ${u.signing_hash}): check that transaction before buying`);
    else if (!outstanding.some((o) => o.nonce === u.nonce)) problems.push(`nonce ${u.nonce} has an uncertain signature`);
  }
  // Review M12 (R12-7): the sale must not have changed while auditing.
  const saleAfter = await nearView(contract, 'get_sale', { token_id: tokenId });
  if (JSON.stringify(saleAfter) !== JSON.stringify(sale)) problems.push('the sale changed while auditing: run the audit again');
  return { safe: problems.length === 0, lines, problems, outstanding, allowances, mined, next, owner, sale, codeHex, fullKeys };
}

const isMain = process.argv[1] && fileURLToPath(import.meta.url).toLowerCase() === process.argv[1].toLowerCase();
if (isMain) {
  const [contract, tokenId] = process.argv.slice(2);
  if (!tokenId) throw new Error('usage: node sale-audit.mjs <vault-contract> <token_id> [--eth-rpc <url>] [--expect-code <hex>]');
  const opt = (name) => { const i = process.argv.indexOf(name); return i > 0 ? process.argv[i + 1] : undefined; };
  const r = await audit(contract, tokenId, opt('--eth-rpc'), opt('--expect-code'));
  for (const l of r.lines) console.log('  ' + l);
  for (const p of r.problems) console.log('  ! ' + p);
  console.log(r.safe
    ? `SAFE for sale ${r.sale.sale_id}: no signature the seller holds can still be mined and no ERC-20 approval is left. ${r.sale.price ? `Buy with sale_id ${r.sale.sale_id}.` : `Pay only through a transfer bound to "sale:${r.sale.sale_id}".`}`
    : r.problems.every((p) => p.startsWith('INCOMPLETE')) ? 'INCOMPLETE: a check could not be completed; do not buy until the audit says SAFE' : 'NOT SAFE: see the points above');
  if (r.safe && Date.now() < r.sale.opens_at_ms) console.log(`(the sale opens in ${Math.ceil((r.sale.opens_at_ms - Date.now()) / 1000)} s: the contract refuses a purchase before that; run the audit again then)`);
  process.exit(r.safe ? 0 : 2);
}
