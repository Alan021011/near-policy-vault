// The buyer's audit (M8, general review H2/H5, review M12), the same checks as
// scripts/sale-audit.mjs. The contract cannot read Ethereum, so these checks live off-chain.
// M39: this file has no browser or network dependency of its own: everything it reads goes through
// the `io` object, so the tests (web/test/audit.test.ts) run it against fake chains. The page wires
// it to the real RPCs in audit.ts.
import { parseTransaction } from 'viem';

export interface AuditIO {
  /** A view call on the vault contract (finality final). */
  view<T = any>(method: string, args: object): Promise<T>;
  /** An Ethereum JSON-RPC call on the given chain. */
  eth<T = any>(chain: number, method: string, params: unknown[]): Promise<T>;
  /** A NEAR JSON-RPC call. */
  nearRpc(method: string, params: object): Promise<any>;
  /** POST a JSON-RPC body to a URL and return the parsed answer (used for the Approval-event search). */
  fetchJson(url: string, body: object): Promise<any>;
  contract: string;
  defaultChain: number;
  expectedCode: string;
  /** The page was opened with another contract or RPC in its URL. */
  overridden: boolean;
  now(): number;
  sleep(ms: number): Promise<void>;
}

// 'incomplete': a required check could not be completed (e.g. an RPC did not answer); 'waiting':
// the handover has not opened yet. Either one keeps the verdict from being SAFE (fail closed).
export type CheckState = 'pass' | 'fail' | 'warn' | 'info' | 'incomplete' | 'waiting';
export type Verdict = 'safe' | 'unsafe' | 'incomplete' | 'waiting';
export interface Check {
  state: CheckState;
  title: string;
  detail?: string;
}
export interface AuditResult {
  /** True only when every required check passed: the only verdict that allows a purchase. */
  safe: boolean;
  verdict: Verdict;
  checks: Check[];
  sale: any;
  codeHex: string;
  fullKeys: number;
}

const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
function base58ToHex(s: string): string {
  let n = 0n;
  for (const c of s) n = n * 58n + BigInt(B58.indexOf(c));
  return n.toString(16).padStart(64, '0');
}
const word = (addr: string) => addr.toLowerCase().replace(/^0x/, '').padStart(64, '0');
const SEL_APPROVE = '0x095ea7b3';
const SEL_ALLOWANCE = '0xdd62ed3e';
const APPROVAL_TOPIC = '0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925';
const LOG_RANGE = 50_000; // the public RPC's largest eth_getLogs range
const SEPOLIA_BLOCK_MS = 12_000;
// Approval events of old blocks: some public nodes answer "pruned history unavailable", so each range
// is asked to nodes that keep the history, in turn, a few times. Only if all of them fail is the
// check reported incomplete (and the audit is then not SAFE).
const LOG_RPCS: Record<number, string[]> = { 11155111: ['https://sepolia.gateway.tenderly.co', 'https://ethereum-sepolia-rpc.publicnode.com'] };
async function getLogs(io: AuditIO, chain: number, filter: object): Promise<any[]> {
  const urls = LOG_RPCS[chain];
  if (!urls) return io.eth<any[]>(chain, 'eth_getLogs', [filter]);
  let last: unknown;
  for (let i = 0; i < urls.length * 3; i++) {
    try {
      const j = await io.fetchJson(urls[i % urls.length], { jsonrpc: '2.0', id: 1, method: 'eth_getLogs', params: [filter] });
      if (j.error) throw new Error(j.error.message);
      if (Array.isArray(j.result)) return j.result;
      throw new Error('no result');
    } catch (e) {
      last = e;
      await io.sleep(300);
    }
  }
  throw last;
}

/** Every signed record of a vault, every version. `list_signed` pages by record count, so a page
 *  that ends inside a nonce is continued from that nonce (review M12, R12-8). */
async function allSigned(io: AuditIO, tokenId: string, next: number): Promise<{ records: any[]; complete: boolean }> {
  const seen = new Map<string, any>();
  let from = 0;
  let guard = 0;
  for (; from < next && guard < 1000; guard++) {
    const page = await io.view<any[]>('list_signed', { token_id: tokenId, from_nonce: from, limit: 100 });
    if (page.length === 0) break;
    for (const r of page) seen.set(`${r.nonce}|${r.tx_hash}`, r);
    const last = page[page.length - 1].nonce;
    if (page.length < 100) { from = last + 1; continue; }
    if (page[0].nonce === last) {
      // External review (round 3, H2): a nonce can have more than 100 signed versions, so a page that
      // is all one nonce may have cut it. Read every version of that nonce, then go on.
      for (const r of await io.view<any[]>('get_signed_versions', { token_id: tokenId, nonce: last })) seen.set(`${r.nonce}|${r.tx_hash}`, r);
      from = last + 1;
    } else {
      // A full page may have cut the last nonce's versions: read that nonce again (duplicates are dropped).
      from = last;
    }
  }
  return { records: [...seen.values()], complete: from >= next };
}

/** The verdict from the checks: anything failed → unsafe; else anything not completed → incomplete;
 *  else the sale not open yet → waiting; only then safe. */
export function verdictOf(checks: Check[]): Verdict {
  return checks.some((c) => c.state === 'fail') ? 'unsafe'
    : checks.some((c) => c.state === 'incomplete') ? 'incomplete'
    : checks.some((c) => c.state === 'waiting') ? 'waiting' : 'safe';
}

export async function auditCore(tokenId: string, io: AuditIO): Promise<AuditResult> {
  const checks: Check[] = [];
  const { contract: CONTRACT, defaultChain: DEFAULT_CHAIN, expectedCode: EXPECTED_CODE, overridden: OVERRIDDEN } = io;
  const eth = io.eth.bind(io);
  const nearRpc = io.nearRpc.bind(io);
  const v = <T = any>(m: string, a: object) => io.view<T>(m, a);
  // Review M12 (R12-7): the sale is read before and after everything else; if it changed, the
  // audit says nothing about it.
  const saleBefore = await v('get_sale', { token_id: tokenId });
  const [info, chainRaw, next, uncertain, inflight, policy, token] = await Promise.all([
    v('vault_info', { token_id: tokenId }),
    v<number | null>('get_vault_chain', { token_id: tokenId }),
    v<number>('get_next_nonce', { token_id: tokenId }),
    v<any[]>('get_uncertain', { token_id: tokenId }),
    v('get_inflight', { token_id: tokenId }),
    v('get_policy', { token_id: tokenId }),
    v('nft_token', { token_id: tokenId }),
  ]);
  const chain = chainRaw ?? DEFAULT_CHAIN;
  const sale = saleBefore;

  // Review M12 (R12-2): a link can point the page at another contract or RPC.
  if (OVERRIDDEN)
    checks.push({ state: 'fail', title: 'This page was opened with a custom contract or RPC', detail: 'The audit only vouches for the default contract and public RPCs. Open the page without ?contract= / ?near_rpc= / ?eth_rpc=.' });

  // The sale itself.
  const now = io.now();
  if (!sale) checks.push({ state: 'fail', title: 'No sale is active', detail: 'The owner must call start_sale first.' });
  else if (now < sale.opens_at_ms)
    checks.push({ state: 'waiting', title: `Sale #${sale.sale_id} opens in ${Math.ceil((sale.opens_at_ms - now) / 1000)} s`, detail: 'Until then nobody can buy, and the guardian can still veto it.' });
  else if (now >= sale.closes_at_ms) checks.push({ state: 'fail', title: 'The sale window has closed' });
  else checks.push({ state: 'pass', title: `Sale #${sale.sale_id} is open`, detail: `Until ${new Date(sale.closes_at_ms).toUTCString()}.` });
  if (inflight) checks.push({ state: 'fail', title: `A signature is in flight (nonce ${inflight.nonce})`, detail: 'Wait for it to finish.' });

  // Every Ethereum read below uses one block, a little behind the head (some public nodes are
  // load-balanced across servers that are not all at the same height), and only if that node is up
  // to date: otherwise the audit is incomplete, never safe (external review, second round).
  const head = await eth<any>(chain, 'eth_getBlockByNumber', ['latest', false]);
  const pinned = Number(BigInt(head.number)) - 2;
  const tag = '0x' + pinned.toString(16);
  const headAgeS = Math.round(now / 1000 - Number(BigInt(head.timestamp)));
  checks.push(headAgeS > 300
    ? { state: 'incomplete', title: `The Ethereum node is ${headAgeS} s behind`, detail: 'Its newest block is too old to vouch for the current state. Run the check again later.' }
    : { state: 'pass', title: `Ethereum read at block ${pinned}`, detail: 'Every Ethereum check below reads this same block, from an up-to-date node.' });

  // Kept signatures: every nonce the contract signed must already be used on the vault's chain.
  let mined = 0;
  const history = next > 0 ? await allSigned(io, tokenId, next) : { records: [], complete: true };
  const signed = history.records;
  if (!history.complete)
    checks.push({ state: 'incomplete', title: 'The signed history could not be read to the end', detail: 'Some signed transactions were not read, so a kept signature or an approval could be missed. Run the check again.' });
  // External review (round 3, H6): the account's nonce must equal the contract's count exactly. More
  // nonces on Ethereum than the contract signed means activity the contract never recorded.
  mined = Number(BigInt(await eth<string>(chain, 'eth_getTransactionCount', [info.evm_address, tag])));
  if (mined > next) {
    checks.push({ state: 'incomplete', title: `Ethereum shows ${mined} nonces used, the contract signed only ${next}`, detail: 'Something the contract did not record was mined from this address. Do not take over until it is explained.' });
  } else if (next > 0) {
    if (mined === next) {
      checks.push({ state: 'pass', title: `Every nonce the contract signed is used on chain ${chain}`, detail: `Contract next nonce ${next}, account nonce ${mined}: no signature the seller kept can still be mined.` });
    } else {
      for (let n = mined; n < next; n++) {
        checks.push({ state: 'fail', title: `Nonce ${n} is signed but not mined`, detail: `The seller should call cancel_nonce(${n}); anyone can then broadcast the cancellation, and it must be mined.` });
      }
    }
  } else {
    checks.push({ state: 'pass', title: 'The vault never signed anything', detail: 'No signature can be pending, and the account has never sent a transaction.' });
  }

  // Review M12 (R12-6): an uncertain nonce below the mined nonce means something was mined with
  // it that the contract never recorded (it could have been an approval or a payment).
  for (const u of uncertain) {
    if (u.nonce < mined)
      checks.push({ state: 'fail', title: `Nonce ${u.nonce} was mined, but the contract never recorded what was signed`, detail: `Its signature outcome was uncertain (signing hash ${u.signing_hash}). Check that transaction on the explorer before buying.` });
  }

  // ERC-20 allowances (general review H2; review M12, R12-6): every token the vault's policy
  // names or its signed history touched, from approvals in the history and from Approval events.
  const pairs = new Map<string, { token: string; spender: string }>();
  const tokens = new Set<string>();
  for (const t of policy?.policy?.tokens ?? []) tokens.add(t.contract.toLowerCase());
  for (const t of policy?.pending?.policy?.tokens ?? []) tokens.add(t.contract.toLowerCase());
  for (const rec of signed) {
    const tx = parseTransaction(rec.signed_tx as `0x${string}`);
    if (tx.data && tx.data.length >= 10 && tx.to) tokens.add(tx.to.toLowerCase());
    if (tx.data && tx.data.startsWith(SEL_APPROVE) && tx.data.length === 2 + 8 + 128 && tx.to) {
      const spender = '0x' + tx.data.slice(2 + 8 + 24, 2 + 8 + 64);
      pairs.set(`${tx.to.toLowerCase()}|${spender}`, { token: tx.to.toLowerCase(), spender });
    }
  }
  let logsScanned = true;
  if (tokens.size && info.evm_address) {
    try {
      const latest = pinned;
      const issued = Number(token?.metadata?.issued_at ?? 0);
      const from = Math.max(0, latest - Math.ceil((now - issued) / SEPOLIA_BLOCK_MS) - 2000);
      for (const t of tokens) {
        for (let f = from; f <= latest; f += LOG_RANGE) {
          const logs = await getLogs(io, chain, { address: t, fromBlock: '0x' + f.toString(16), toBlock: '0x' + Math.min(latest, f + LOG_RANGE - 1).toString(16), topics: [APPROVAL_TOPIC, '0x' + word(info.evm_address)] });
          for (const l of logs) pairs.set(`${t}|0x${l.topics[2].slice(26)}`, { token: t, spender: '0x' + l.topics[2].slice(26) });
        }
      }
    } catch {
      logsScanned = false;
    }
  }
  let left = 0;
  for (const { token: t, spender } of pairs.values()) {
    const amount = BigInt(await eth<string>(chain, 'eth_call', [{ to: t, data: SEL_ALLOWANCE + word(info.evm_address) + word(spender) }, tag]));
    if (amount > 0n) {
      left++;
      checks.push({ state: 'fail', title: 'An ERC-20 approval survives the sale', detail: `Token ${t}: ${spender} may still take ${amount} units. The seller cancels the sale, signs approve(${spender}, 0), mines it and starts a new sale.` });
    }
  }
  if (left === 0)
    checks.push({ state: 'pass', title: 'No ERC-20 approval is left', detail: `${pairs.size} approval(s) found (signed history and Approval events of ${tokens.size} token(s)), none with an allowance left.` });
  if (!logsScanned)
    checks.push({ state: 'incomplete', title: 'Approval events could not be scanned', detail: 'A public RPC did not answer the Approval-event search, so this check is not complete (the approvals in the signed history were checked). Run the check again before taking over.' });

  // The contract itself (threat 9; review M12, R12-2: a different code hash is a failure).
  const acct = await nearRpc('query', { request_type: 'view_account', finality: 'final', account_id: CONTRACT });
  const codeHex = base58ToHex(acct.code_hash);
  const keys = await nearRpc('query', { request_type: 'view_access_key_list', finality: 'final', account_id: CONTRACT });
  const fullKeys = keys.keys.filter((k: any) => k.access_key.permission === 'FullAccess').length;
  checks.push(codeHex === EXPECTED_CODE
    ? { state: 'pass', title: 'The contract runs the expected code', detail: `sha256 ${codeHex}, the build published in the repository.` }
    : { state: 'fail', title: 'The contract does not run the expected code', detail: `sha256 ${codeHex}, expected ${EXPECTED_CODE}.` });
  // The contract account was locked (no access keys at all) on 2026-11-10: nobody can change its code.
  checks.push(keys.keys.length === 0
    ? { state: 'pass', title: 'Nobody can change the contract', detail: 'Its account has no access keys, so its code is final.' }
    : { state: 'fail', title: `The contract account has ${keys.keys.length} access key(s) (${fullKeys} full-access)`, detail: 'Whoever holds a full-access key can change the contract code (threat 9).' });

  // Funds: only the vault's own chain can be moved by this vault.
  const bal = BigInt(await eth<string>(chain, 'eth_getBalance', [info.evm_address, tag]));
  checks.push({ state: 'info', title: `Balance on chain ${chain}: ${Number(bal) / 1e18} ETH`, detail: 'Funds at this address on other EVM chains cannot be moved by this vault.' });

  const saleAfter = await v('get_sale', { token_id: tokenId });
  if (JSON.stringify(saleAfter) !== JSON.stringify(saleBefore))
    checks.push({ state: 'fail', title: 'The sale changed while auditing', detail: 'Run the audit again.' });

  const verdict = verdictOf(checks);
  return { safe: verdict === 'safe', verdict, checks, sale, codeHex, fullKeys };
}
