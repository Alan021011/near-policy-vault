// The buyer's audit in the page: the checks of audit-core.ts, wired to the public RPCs the page uses.
import { CONTRACT, DEFAULT_CHAIN, EXPECTED_CODE, OVERRIDDEN, eth, nearRpc, view } from './near';
import { auditCore, type AuditResult } from './audit-core';
export type { AuditResult, Check, CheckState, Verdict } from './audit-core';

export function audit(tokenId: string): Promise<AuditResult> {
  return auditCore(tokenId, {
    view: (m, a) => view(m, a, CONTRACT, 'final'),
    eth: (chain, m, p) => eth(chain, m, p),
    nearRpc: (m, p) => nearRpc(m, p),
    fetchJson: (url, body) => fetch(url, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) }).then((r) => r.json()),
    contract: CONTRACT,
    defaultChain: DEFAULT_CHAIN,
    expectedCode: EXPECTED_CODE,
    overridden: OVERRIDDEN,
    now: () => Date.now(),
    sleep: (ms) => new Promise((r) => setTimeout(r, ms)),
  });
}
