// Reading the NEAR contract and Sepolia over public RPCs, and signing with the user's wallet.
import { NearConnector } from '@hot-labs/near-connect';

const params = new URLSearchParams(location.search);
const DEFAULT_CONTRACT = 'm3.alan-vault-2026.testnet';
/** SHA-256 of the contract build published in the repository (README "How to verify"). */
export const EXPECTED_CODE = '0ff14e796c977fb74a8ee976db940f799f6900d7303ee12fc31ee5b44edd958c';
// Review M12 (R12-1, R12-2): URL parameters are only accepted when well formed, and any override
// is shown and makes the audit refuse to say SAFE.
const ACCOUNT_RE = /^(?=.{2,64}$)[a-z0-9]+([-_][a-z0-9]+)*(\.[a-z0-9]+([-_][a-z0-9]+)*)*$/;
const HTTPS_RE = /^https:\/\/[a-z0-9.-]+(:\d+)?(\/[\w./-]*)?$/i;
const pick = (name: string, re: RegExp) => {
  const v = params.get(name);
  return v && re.test(v) ? v : null;
};
const contractParam = pick('contract', ACCOUNT_RE);
const nearRpcParam = pick('near_rpc', HTTPS_RE);
const ethRpcParam = pick('eth_rpc', HTTPS_RE);
export const OVERRIDDEN = !!(contractParam || nearRpcParam || ethRpcParam);
export const CONTRACT = contractParam ?? DEFAULT_CONTRACT;
// Public testnet RPCs, tried in order (the official one rate-limits browsers).
export const NEAR_RPCS = nearRpcParam
  ? [nearRpcParam]
  : ['https://rpc.testnet.fastnear.com', 'https://test.rpc.fastnear.com', 'https://rpc.testnet.near.org'];
export const ETH_RPC: Record<number, string> = {
  11155111: ethRpcParam ?? 'https://ethereum-sepolia-rpc.publicnode.com',
};
export const EXPLORER: Record<number, string> = { 11155111: 'https://sepolia.etherscan.io' };
/** Nodes for reading receipts: some public Sepolia nodes no longer serve old ones, so several are tried. */
const RECEIPT_RPCS: Record<number, string[]> = {
  11155111: ethRpcParam ? [ethRpcParam] : ['https://sepolia.gateway.tenderly.co', 'https://1rpc.io/sepolia', 'https://ethereum-sepolia-rpc.publicnode.com'],
};
export async function ethReceipt(chain: number, hash: string): Promise<any | null> {
  const urls = RECEIPT_RPCS[chain] ?? [];
  for (let i = 0; i < urls.length * 2; i++) {
    try {
      const j = await fetch(urls[i % urls.length], { method: 'POST', headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'eth_getTransactionReceipt', params: [hash] }) }).then((r) => r.json());
      if (j.result) return j.result;
    } catch {
      /* try the next node */
    }
  }
  return null;
}
export const NEAR_EXPLORER = 'https://testnet.nearblocks.io';
export const DEFAULT_CHAIN = 11155111;

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

export async function nearRpc(method: string, rpcParams: unknown, attempt = 1): Promise<any> {
  try {
    const res = await fetch(NEAR_RPCS[(attempt - 1) % NEAR_RPCS.length], {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params: rpcParams }),
    });
    if (res.status === 429 || res.status >= 500) throw new Error(`NEAR RPC HTTP ${res.status}`);
    const j = await res.json();
    if (j.error) {
      const err = new Error(JSON.stringify(j.error.data ?? j.error));
      (err as any).fatal = true; // the contract or the query failed: another RPC would answer the same
      throw err;
    }
    return j.result;
  } catch (e: any) {
    if (e?.fatal || attempt >= 5) throw e;
    await sleep(800 * attempt);
    return nearRpc(method, rpcParams, attempt + 1);
  }
}

const b64 = (s: string) => btoa(String.fromCharCode(...new TextEncoder().encode(s)));

export async function view<T = any>(method: string, args: object = {}, contract = CONTRACT, finality: 'optimistic' | 'final' = 'optimistic'): Promise<T> {
  const r = await nearRpc('query', {
    request_type: 'call_function',
    finality,
    account_id: contract,
    method_name: method,
    args_base64: b64(JSON.stringify(args)),
  });
  return JSON.parse(new TextDecoder().decode(new Uint8Array(r.result)));
}

export async function eth<T = any>(chain: number, method: string, ethParams: unknown[], attempt = 1): Promise<T> {
  const rpc = ETH_RPC[chain];
  if (!rpc) throw new Error(`no RPC for chain ${chain}`);
  let j;
  try {
    j = await fetch(rpc, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params: ethParams }),
    }).then((r) => r.json());
  } catch (e) {
    if (attempt >= 4) throw e;
    await sleep(800 * attempt);
    return eth(chain, method, ethParams, attempt + 1);
  }
  if (j.error) throw new Error(j.error.message);
  return j.result;
}

// ---------- units ----------
const YOCTO = 10n ** 24n;
export function nearToYocto(near: string): string {
  const [i, f = ''] = near.trim().split('.');
  return (BigInt(i || '0') * YOCTO + BigInt((f + '0'.repeat(24)).slice(0, 24))).toString();
}
export function yoctoToNear(yocto: string | bigint, digits = 4): string {
  const v = BigInt(yocto);
  const whole = v / YOCTO;
  const frac = (v % YOCTO).toString().padStart(24, '0').slice(0, digits).replace(/0+$/, '');
  return frac ? `${whole}.${frac}` : `${whole}`;
}
export const TGAS = 1_000_000_000_000n;

// ---------- wallet ----------
export const connector = new NearConnector({ network: 'testnet', footerBranding: null, providers: { testnet: NEAR_RPCS } });
export let accountId: string | null = null;
const listeners: Array<() => void> = [];
export const onAccountChange = (f: () => void) => listeners.push(f);
const setAccount = (a: string | null) => {
  accountId = a;
  listeners.forEach((f) => f());
};
connector.on('wallet:signIn', (t) => setAccount(t.accounts[0]?.accountId ?? null));
connector.on('wallet:signOut', () => setAccount(null));
connector
  .getConnectedWallet()
  .then(({ accounts }) => setAccount(accounts[0]?.accountId ?? null))
  .catch(() => {});

export async function connect() {
  await connector.connect();
}
export async function disconnect() {
  await connector.disconnect();
  setAccount(null);
}

export interface CallResult {
  value: any;
  logs: string[];
  failure?: string;
  hash: string;
}

/** Calls the vault contract from the connected wallet and returns its value, logs and any panic. */
export async function call(method: string, args: object, deposit = '0', tgas = 100n): Promise<CallResult> {
  if (!accountId) throw new Error('Connect a wallet first');
  const wallet = await connector.wallet();
  const outcome: any = await wallet.signAndSendTransaction({
    receiverId: CONTRACT,
    actions: [{ type: 'FunctionCall', params: { methodName: method, args, gas: (tgas * TGAS).toString(), deposit } }],
  });
  const logs: string[] = (outcome.receipts_outcome ?? []).flatMap((r: any) => r.outcome.logs);
  const failures = [outcome.status, ...(outcome.receipts_outcome ?? []).map((r: any) => r.outcome.status)]
    .filter((s: any) => s && s.Failure)
    .map((s: any) => panicText(JSON.stringify(s.Failure)));
  let value: any;
  const ok = outcome.status?.SuccessValue;
  if (typeof ok === 'string' && ok.length) {
    try {
      value = JSON.parse(atob(ok));
    } catch {
      value = atob(ok);
    }
  }
  return { value, logs, failure: failures[0], hash: outcome.transaction?.hash ?? outcome.transaction_outcome?.id ?? '' };
}

export function panicText(s: string): string {
  const m = s.match(/Smart contract panicked: (.*?)(?:\\?"|$)/);
  return m ? m[1] : s.slice(0, 300);
}

export const events = (logs: string[], name: string) =>
  logs
    .filter((l) => l.startsWith('EVENT_JSON:'))
    .map((l) => JSON.parse(l.slice('EVENT_JSON:'.length)))
    .filter((e) => e.event === name)
    .map((e) => e.data[0]);
