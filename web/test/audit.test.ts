// Tests for the buyer's audit (web/src/audit-core.ts) against fake chains (M39). No network.
//   cd web && npm test        (Node 22.6+: runs TypeScript with --experimental-strip-types)
// The audit must fail closed: only a complete, passing audit is "safe".
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { encodeFunctionData, parseAbi, serializeTransaction } from 'viem';
import { auditCore, verdictOf, type AuditIO, type Check } from '../src/audit-core.ts';

const CHAIN = 11155111;
const VAULT = '0x' + 'ab'.repeat(20);
const TOKEN = '0x' + 'cd'.repeat(20);
const SPENDER = '0x' + 'ef'.repeat(20);
const CODE_HEX = '0f'.repeat(32);
const NOW = 1_800_000_000_000;
const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const toB58 = (hex: string) => { let n = BigInt('0x' + hex); let s = ''; while (n > 0n) { s = B58[Number(n % 58n)] + s; n /= 58n; } return s; };
const hex = (n: number | bigint) => '0x' + n.toString(16);
const SIG = { r: ('0x' + '11'.repeat(32)) as `0x${string}`, s: ('0x' + '22'.repeat(32)) as `0x${string}`, yParity: 0 };
const signedTx = (nonce: number, to: string, data: `0x${string}` = '0x') =>
  serializeTransaction({ type: 'eip1559', chainId: CHAIN, nonce, maxPriorityFeePerGas: 1n, maxFeePerGas: 2n, gas: 60000n, to: to as `0x${string}`, value: 0n, data, accessList: [] }, SIG);
const approveData = encodeFunctionData({ abi: parseAbi(['function approve(address,uint256)']), args: [SPENDER as `0x${string}`, 5n] });

/** A fake world: a vault on sale with nothing left behind. Each test changes one thing. */
function world(over: Partial<Record<string, any>> = {}) {
  const w = {
    sale: { sale_id: 3, opens_at_ms: NOW - 1000, closes_at_ms: NOW + 3_600_000, price: '1', buyer: null } as any,
    saleAfter: undefined as any, // undefined = unchanged
    next: 0,
    mined: 0,
    signed: [] as any[],
    uncertain: [] as any[],
    inflight: null as any,
    tokens: [] as any[],
    allowance: 0n,
    headAgeS: 12,
    logsFail: false,
    codeHex: CODE_HEX,
    keys: [] as any[],
    overridden: false,
    ...over,
  };
  let saleReads = 0;
  const calls: string[] = [];
  const io: AuditIO = {
    async view(method, args: any) {
      calls.push(method);
      switch (method) {
        case 'get_sale': saleReads++; return (saleReads > 1 && w.saleAfter !== undefined ? w.saleAfter : w.sale) as any;
        case 'vault_info': return { evm_address: VAULT } as any;
        case 'get_vault_chain': return CHAIN as any;
        case 'get_next_nonce': return w.next as any;
        case 'get_uncertain': return w.uncertain as any;
        case 'get_inflight': return w.inflight as any;
        case 'get_policy': return { policy: { tokens: w.tokens } } as any;
        case 'nft_token': return { metadata: { issued_at: String(NOW - 86_400_000) } } as any;
        case 'list_signed': return w.signed.filter((r) => r.nonce >= args.from_nonce).slice(0, args.limit) as any;
        default: throw new Error(`unexpected view ${method}`);
      }
    },
    async eth(_chain, method, params: any[]) {
      calls.push(method);
      switch (method) {
        case 'eth_getBlockByNumber': return { number: hex(1_000_000), timestamp: hex(Math.floor(NOW / 1000) - w.headAgeS) } as any;
        case 'eth_getTransactionCount': assert.equal(params[1], hex(999_998), 'nonce read at the pinned block'); return hex(w.mined) as any;
        case 'eth_call': assert.equal(params[1], hex(999_998), 'allowance read at the pinned block'); return hex(w.allowance) as any;
        case 'eth_getBalance': return hex(0) as any;
        default: throw new Error(`unexpected eth ${method}`);
      }
    },
    async nearRpc(_m, p: any) {
      if (p.request_type === 'view_account') return { code_hash: toB58(w.codeHex) };
      if (p.request_type === 'view_access_key_list') return { keys: w.keys };
      throw new Error('unexpected nearRpc');
    },
    async fetchJson(_url, body: any) {
      calls.push(body.method);
      if (w.logsFail) return { error: { code: 4444, message: 'pruned history unavailable' } };
      return { result: [] };
    },
    contract: 'vault.testnet', defaultChain: CHAIN, expectedCode: CODE_HEX, overridden: w.overridden,
    now: () => NOW,
    sleep: async () => {},
  };
  return { io, calls };
}
const run = async (over?: Partial<Record<string, any>>) => auditCore('7', world(over).io);
const titles = (r: { checks: Check[] }, state: string) => r.checks.filter((c) => c.state === state).map((c) => c.title);

test('a clean vault on an open sale is safe', async () => {
  const r = await run();
  assert.equal(r.verdict, 'safe');
  assert.equal(r.safe, true);
});

test('no sale: unsafe', async () => {
  const r = await run({ sale: null });
  assert.equal(r.verdict, 'unsafe');
  assert.deepEqual(titles(r, 'fail'), ['No sale is active']);
});

test('a sale that has not opened yet: waiting, never safe', async () => {
  const r = await run({ sale: { sale_id: 3, opens_at_ms: NOW + 60_000, closes_at_ms: NOW + 3_600_000 } });
  assert.equal(r.verdict, 'waiting');
  assert.equal(r.safe, false);
});

test('a closed sale: unsafe', async () => {
  assert.equal((await run({ sale: { sale_id: 3, opens_at_ms: NOW - 2, closes_at_ms: NOW - 1 } })).verdict, 'unsafe');
});

test('a signature the seller kept (signed, not mined): unsafe', async () => {
  const r = await run({ next: 2, mined: 1, signed: [{ nonce: 0, tx_hash: 'a', signed_tx: signedTx(0, VAULT) }, { nonce: 1, tx_hash: 'b', signed_tx: signedTx(1, VAULT) }] });
  assert.equal(r.verdict, 'unsafe');
  assert.deepEqual(titles(r, 'fail'), ['Nonce 1 is signed but not mined']);
});

test('a signature in flight: unsafe', async () => {
  assert.equal((await run({ inflight: { nonce: 4 } })).verdict, 'unsafe');
});

test('an uncertain nonce that was mined: unsafe', async () => {
  const r = await run({ next: 1, mined: 1, signed: [{ nonce: 0, tx_hash: 'a', signed_tx: signedTx(0, VAULT) }], uncertain: [{ nonce: 0, signing_hash: '0x00' }] });
  assert.equal(r.verdict, 'unsafe');
});

test('an ERC-20 approval with an allowance left: unsafe', async () => {
  const r = await run({ next: 1, mined: 1, allowance: 5n, signed: [{ nonce: 0, tx_hash: 'a', signed_tx: signedTx(0, TOKEN, approveData) }] });
  assert.equal(r.verdict, 'unsafe');
  assert.deepEqual(titles(r, 'fail'), ['An ERC-20 approval survives the sale']);
});

test('the same approval revoked (allowance 0): safe', async () => {
  const r = await run({ next: 1, mined: 1, allowance: 0n, signed: [{ nonce: 0, tx_hash: 'a', signed_tx: signedTx(0, TOKEN, approveData) }] });
  assert.equal(r.verdict, 'safe');
});

test('the Approval-event search fails on every node: incomplete, never safe', async () => {
  const { io, calls } = world({ tokens: [{ contract: TOKEN }], logsFail: true });
  const r = await auditCore('7', io);
  assert.equal(r.verdict, 'incomplete');
  assert.equal(r.safe, false);
  assert.ok(calls.filter((c) => c === 'eth_getLogs').length >= 2, 'it retried on more than one try');
});

test('the Ethereum node is more than 5 minutes behind: incomplete', async () => {
  const r = await run({ headAgeS: 900 });
  assert.equal(r.verdict, 'incomplete');
  assert.match(titles(r, 'incomplete')[0], /900 s behind/);
});

test('the contract runs other code: unsafe', async () => {
  assert.equal((await run({ codeHex: 'ee'.repeat(32) })).verdict, 'unsafe');
});

test('the contract account has an access key: unsafe', async () => {
  assert.equal((await run({ keys: [{ access_key: { permission: 'FullAccess' } }] })).verdict, 'unsafe');
});

test('the page was opened with another contract or RPC: unsafe', async () => {
  assert.equal((await run({ overridden: true })).verdict, 'unsafe');
});

test('the sale changed while auditing: unsafe', async () => {
  const r = await run({ saleAfter: { sale_id: 4, opens_at_ms: NOW - 1000, closes_at_ms: NOW + 3_600_000 } });
  assert.equal(r.verdict, 'unsafe');
  assert.deepEqual(titles(r, 'fail'), ['The sale changed while auditing']);
});

test('verdict order: a failure beats an incomplete check, which beats waiting', () => {
  const c = (state: Check['state']) => ({ state, title: state });
  assert.equal(verdictOf([c('waiting'), c('incomplete'), c('fail')]), 'unsafe');
  assert.equal(verdictOf([c('waiting'), c('incomplete'), c('pass')]), 'incomplete');
  assert.equal(verdictOf([c('waiting'), c('pass'), c('warn'), c('info')]), 'waiting');
  assert.equal(verdictOf([c('pass'), c('warn'), c('info')]), 'safe');
});
