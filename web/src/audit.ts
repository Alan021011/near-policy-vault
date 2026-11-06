// The buyer's audit (M8, general review H2/H5), the same checks as scripts/sale-audit.mjs, run in
// the browser against public RPCs. The contract cannot read Ethereum, so these checks live here.
import { parseTransaction } from 'viem';
import { CONTRACT, DEFAULT_CHAIN, eth, nearRpc, view } from './near';

export type CheckState = 'pass' | 'fail' | 'warn' | 'info';
export interface Check {
  state: CheckState;
  title: string;
  detail?: string;
}
export interface AuditResult {
  safe: boolean;
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

export async function audit(tokenId: string, expectCode?: string): Promise<AuditResult> {
  const checks: Check[] = [];
  const [info, chainRaw, next, uncertain, inflight, sale] = await Promise.all([
    view('vault_info', { token_id: tokenId }),
    view<number | null>('get_vault_chain', { token_id: tokenId }),
    view<number>('get_next_nonce', { token_id: tokenId }),
    view<any[]>('get_uncertain', { token_id: tokenId }),
    view('get_inflight', { token_id: tokenId }),
    view('get_sale', { token_id: tokenId }),
  ]);
  const chain = chainRaw ?? DEFAULT_CHAIN;

  // The sale itself.
  const now = Date.now();
  if (!sale) checks.push({ state: 'fail', title: 'No sale is active', detail: 'The owner must call start_sale first.' });
  else if (now < sale.opens_at_ms)
    checks.push({ state: 'warn', title: `Sale #${sale.sale_id} opens in ${Math.ceil((sale.opens_at_ms - now) / 1000)} s`, detail: 'Until then nobody can buy, and the guardian can still veto it.' });
  else if (now >= sale.closes_at_ms) checks.push({ state: 'fail', title: 'The sale window has closed' });
  else checks.push({ state: 'pass', title: `Sale #${sale.sale_id} is open`, detail: `Until ${new Date(sale.closes_at_ms).toUTCString()}.` });
  if (inflight) checks.push({ state: 'fail', title: `A signature is in flight (nonce ${inflight.nonce})`, detail: 'Wait for it to finish.' });

  // Kept signatures: every nonce the contract signed must already be used on the vault's chain.
  let mined = 0;
  if (next > 0) {
    mined = Number(BigInt(await eth<string>(chain, 'eth_getTransactionCount', [info.evm_address, 'latest'])));
    if (mined >= next) {
      checks.push({ state: 'pass', title: `Every nonce the contract signed is used on chain ${chain}`, detail: `Contract next nonce ${next}, account nonce ${mined}: no signature the seller kept can still be mined.` });
    } else {
      for (let n = mined; n < next; n++) {
        checks.push({ state: 'fail', title: `Nonce ${n} is signed but not mined`, detail: `The seller should call cancel_nonce(${n}); anyone can then broadcast the cancellation, and it must be mined.` });
      }
    }
  } else {
    checks.push({ state: 'pass', title: 'The vault never signed anything', detail: 'No signature can be pending.' });
  }

  // ERC-20 allowances left by approvals the vault signed (general review H2).
  if (next > 0) {
    const pairs = new Map<string, { token: string; spender: string }>();
    for (let from = 0; from < next; ) {
      const page = await view<any[]>('list_signed', { token_id: tokenId, from_nonce: from, limit: 100 });
      if (page.length === 0) break;
      for (const rec of page) {
        const tx = parseTransaction(rec.signed_tx as `0x${string}`);
        if (tx.data && tx.data.startsWith(SEL_APPROVE) && tx.data.length === 2 + 8 + 128 && tx.to) {
          const spender = '0x' + tx.data.slice(2 + 8 + 24, 2 + 8 + 64);
          pairs.set(`${tx.to.toLowerCase()}|${spender}`, { token: tx.to.toLowerCase(), spender });
        }
      }
      from = page[page.length - 1].nonce + 1;
    }
    let left = 0;
    for (const { token, spender } of pairs.values()) {
      const amount = BigInt(await eth<string>(chain, 'eth_call', [{ to: token, data: SEL_ALLOWANCE + word(info.evm_address) + word(spender) }, 'latest']));
      if (amount > 0n) {
        left++;
        checks.push({ state: 'fail', title: `An ERC-20 approval survives the sale`, detail: `Token ${token}: ${spender} may still take ${amount} units. The seller cancels the sale, signs approve(${spender}, 0), mines it and starts a new sale.` });
      }
    }
    if (left === 0) checks.push({ state: 'pass', title: 'No ERC-20 approval is left', detail: `${pairs.size} approval(s) ever signed, none with an allowance left.` });
  }

  // Uncertain signatures that are not covered above.
  for (const u of uncertain.filter((u) => u.nonce >= mined && u.nonce >= next)) {
    checks.push({ state: 'fail', title: `Nonce ${u.nonce} has an uncertain signature` });
  }

  // The contract itself (threat 9).
  const acct = await nearRpc('query', { request_type: 'view_account', finality: 'final', account_id: CONTRACT });
  const codeHex = base58ToHex(acct.code_hash);
  const keys = await nearRpc('query', { request_type: 'view_access_key_list', finality: 'final', account_id: CONTRACT });
  const fullKeys = keys.keys.filter((k: any) => k.access_key.permission === 'FullAccess').length;
  if (expectCode) {
    checks.push(expectCode.toLowerCase() === codeHex
      ? { state: 'pass', title: 'The contract code is the expected build', detail: `sha256 ${codeHex}` }
      : { state: 'fail', title: 'The contract code is not the expected build', detail: `sha256 ${codeHex}, expected ${expectCode}` });
  } else {
    checks.push({ state: 'info', title: 'Contract code hash', detail: `sha256 ${codeHex}: compare it with a build of the repository.` });
  }
  if (fullKeys > 0)
    checks.push({ state: 'warn', title: `The contract has ${fullKeys} full-access key(s)`, detail: 'Whoever holds one can change the contract code (threat 9). It will be deleted before submission.' });

  // Funds: only the vault's own chain can be moved by this vault.
  const bal = BigInt(await eth<string>(chain, 'eth_getBalance', [info.evm_address, 'latest']));
  checks.push({ state: 'info', title: `Balance on chain ${chain}: ${Number(bal) / 1e18} ETH`, detail: 'Funds at this address on other EVM chains cannot be moved by this vault.' });

  const safe = !checks.some((c) => c.state === 'fail');
  return { safe, checks, sale, codeHex, fullKeys };
}
