// M42: the vault's rules in plain words, warnings for weak set-ups, and ready-made templates. Pure
// functions (no page, no network) so web/test/rules.test.ts can check them.
import { formatEther } from 'viem';

export interface RulesDraft {
  delay_ms: number;
  guardian: string | null;
  eth_daily_cap: string; // wei
  max_gas_cost: string; // wei
  allowed_destinations: string[];
  proposer: string | null;
  tokens?: unknown[];
  nfts?: unknown[];
}
export interface RuleWarning { level: 'high' | 'warn' | 'info'; text: string }

const HOUR_MS = 3_600_000;
const eth = (wei: string) => `${Number(formatEther(BigInt(wei))).toLocaleString('en', { maximumFractionDigits: 6 })} ETH`;
const DAY_MS = 24 * HOUR_MS;
const wait = (ms: number) => (ms === 0 ? 'no waiting time' : ms % DAY_MS === 0 ? `${ms / DAY_MS} day${ms === DAY_MS ? '' : 's'}` : ms % HOUR_MS === 0 ? `${ms / HOUR_MS} hour${ms === HOUR_MS ? '' : 's'}` : ms >= 60_000 && ms % 60_000 === 0 ? `${ms / 60_000} minute${ms === 60_000 ? '' : 's'}` : `${ms / 1000} seconds`);

/** The rules as a person would say them, one sentence each. */
export function summarize(r: RulesDraft): string[] {
  const out = [`At most ${eth(r.eth_daily_cap)} can leave the vault per day (each payment counts its worst-case network fee too).`];
  out.push(r.allowed_destinations.length ? `It can only pay ${r.allowed_destinations.length} approved address${r.allowed_destinations.length === 1 ? '' : 'es'}.` : 'It cannot pay anyone yet: no approved address.');
  out.push(r.delay_ms > 0 ? `Every payment waits ${wait(r.delay_ms)} before it can be signed.` : 'Payments can be signed at once, with no waiting time.');
  out.push(r.guardian ? `${r.guardian} can stop any payment during that time.` : 'Nobody can stop a payment that fits these rules (no guardian).');
  out.push(r.proposer ? `The agent ${r.proposer} can request and send payments, and can never change these rules.` : 'No agent: only you can request payments.');
  if (r.tokens?.length) out.push(`${r.tokens.length} token${r.tokens.length === 1 ? '' : 's'} with their own daily limit.`);
  if (r.nfts?.length) out.push(`${r.nfts.length} NFT collection${r.nfts.length === 1 ? '' : 's'} with a daily count.`);
  return out;
}

/** What is weak about a set of rules, most serious first. Advice only: the contract accepts them. */
export function ruleWarnings(r: RulesDraft): RuleWarning[] {
  const w: RuleWarning[] = [];
  if (r.proposer && !r.guardian) w.push({ level: 'high', text: 'An agent with no guardian: a payment the agent was fooled into, inside the rules, goes through with nobody able to stop it.' });
  if (r.delay_ms === 0 && r.guardian) w.push({ level: 'high', text: 'A waiting time of 0: the guardian never gets a chance to stop a payment.' });
  if (r.proposer && r.delay_ms > 0 && r.delay_ms < HOUR_MS) w.push({ level: 'warn', text: `An agent with only ${wait(r.delay_ms)} of waiting time: a person needs more time to read an alert and react. Use at least 1 hour.` });
  if (!r.guardian && !r.proposer) w.push({ level: 'warn', text: 'No guardian: if your key is stolen, a handover to the thief cannot be stopped, and the daily limits start again for the new owner.' });
  if (r.proposer && BigInt(r.eth_daily_cap) > 10n ** 17n) w.push({ level: 'warn', text: `A daily limit of ${eth(r.eth_daily_cap)} with an agent: that is the most a fooled agent can lose in a day.` });
  if (!r.allowed_destinations.length) w.push({ level: 'info', text: 'No approved address yet: the vault cannot pay anyone until you add one.' });
  return w;
}

/** Ready-made starting points; the form fills these fields and the person reviews the rest. */
export const TEMPLATES = {
  agent: { label: 'An AI agent pays routine bills', delaySeconds: 3600, keepProposer: true, note: 'Set the agent and a guardian (a person you trust, not the agent), and list the suppliers it may pay. Each payment waits 1 hour so the guardian can stop it.' },
  me: { label: 'Only I pay, with a safety wait', delaySeconds: 600, keepProposer: false, note: 'No agent. Payments wait 10 minutes; add a guardian if someone else should be able to stop them.' },
  handover: { label: 'A vault I will hand over', delaySeconds: 600, keepProposer: false, note: 'No agent (a handover removes it anyway). Add a guardian: it can stop a handover you did not start.' },
} as const;
export type TemplateKey = keyof typeof TEMPLATES;

// ---------- M30: before / after, mirroring the contract's own rule (policy.rs, is_not_looser) ----------
export interface FullRules extends RulesDraft {
  chain_id: number;
  allowed_spenders: string[];
  tokens: { contract: string; daily_cap: string; max_approval: string }[];
  nfts: { contract: string; daily_count: string }[];
}
export interface RuleChange { what: string; before: string; after: string; looser: boolean }
export interface ChangeSummary { changes: RuleChange[]; appliesAtOnce: boolean; waitMs: number; replacesGuardian: boolean }

const THREE_DAYS_MS = 3 * 24 * HOUR_MS;
const list = (xs: string[]) => (xs.length ? xs.join(', ') : 'none');
const subset = (a: string[], b: string[]) => a.every((x) => b.includes(x));

/** What changes from the rules in force to the new ones, and when the change applies. A first set of
 *  rules applies at once. Otherwise, exactly as the contract decides: not looser in every dimension:
 *  at once; looser: after the current waiting time (the guardian can stop it); replacing or removing
 *  a guardian: after max(2 x waiting time, 3 days), and that guardian cannot stop it. */
export function changeOf(old: FullRules | null, neu: FullRules): ChangeSummary {
  if (!old) return { changes: [], appliesAtOnce: true, waitMs: 0, replacesGuardian: false };
  const c: RuleChange[] = [];
  const add = (what: string, before: string, after: string, looser: boolean) => { if (before !== after) c.push({ what, before, after, looser }); };
  add('Daily limit', eth(old.eth_daily_cap), eth(neu.eth_daily_cap), BigInt(neu.eth_daily_cap) > BigInt(old.eth_daily_cap));
  add('Max network fee per payment', eth(old.max_gas_cost), eth(neu.max_gas_cost), BigInt(neu.max_gas_cost) > BigInt(old.max_gas_cost));
  add('Waiting time', wait(old.delay_ms), wait(neu.delay_ms), neu.delay_ms < old.delay_ms);
  add('Guardian', old.guardian ?? 'none', neu.guardian ?? 'none', !!old.guardian && neu.guardian !== old.guardian);
  add('Agent', old.proposer ?? 'none', neu.proposer ?? 'none', !!neu.proposer && neu.proposer !== old.proposer);
  add('Approved recipients', list(old.allowed_destinations), list(neu.allowed_destinations), !subset(neu.allowed_destinations, old.allowed_destinations));
  add('Apps allowed to use tokens', list(old.allowed_spenders), list(neu.allowed_spenders), !subset(neu.allowed_spenders, old.allowed_spenders));
  const tokenLooser = !neu.tokens.every((t) => { const o = old.tokens.find((x) => x.contract === t.contract); return !!o && BigInt(t.daily_cap) <= BigInt(o.daily_cap) && BigInt(t.max_approval) <= BigInt(o.max_approval); });
  add('Tokens', `${old.tokens.length} token rule(s)`, `${neu.tokens.length} token rule(s)`, tokenLooser);
  if (JSON.stringify(old.tokens) !== JSON.stringify(neu.tokens) && old.tokens.length === neu.tokens.length) c.push({ what: 'Token limits', before: 'as before', after: 'changed', looser: tokenLooser });
  const nftLooser = !neu.nfts.every((n) => { const o = old.nfts.find((x) => x.contract === n.contract); return !!o && BigInt(n.daily_count) <= BigInt(o.daily_count); });
  add('NFT collections', `${old.nfts.length} collection(s)`, `${neu.nfts.length} collection(s)`, nftLooser);
  if (JSON.stringify(old.nfts) !== JSON.stringify(neu.nfts) && old.nfts.length === neu.nfts.length) c.push({ what: 'NFT daily counts', before: 'as before', after: 'changed', looser: nftLooser });
  if (neu.chain_id !== old.chain_id) c.push({ what: 'Chain', before: String(old.chain_id), after: String(neu.chain_id), looser: true });
  const replacesGuardian = !!old.guardian && neu.guardian !== old.guardian;
  const looser = c.some((x) => x.looser);
  return { changes: c, appliesAtOnce: !looser, waitMs: !looser ? 0 : replacesGuardian ? Math.max(2 * old.delay_ms, THREE_DAYS_MS) : old.delay_ms, replacesGuardian };
}
export const describeWait = wait;

// ---------- M30: the vault's safety check, a list of controls (no score) ----------
export interface VaultState { hasRules: boolean; unsent: number; uncertain: number; handoverOpen: boolean; looserChangeWaiting: boolean; signing: boolean }
export interface SafetyItem { state: 'ok' | 'warn' | 'bad'; text: string }

export function safetyChecks(p: RulesDraft | null, s: VaultState): SafetyItem[] {
  const out: SafetyItem[] = [];
  const add = (state: SafetyItem['state'], text: string) => out.push({ state, text });
  add('ok', 'Nobody can change the contract: its account has no keys (see Verify).');
  if (!s.hasRules || !p) {
    add('bad', 'No rules yet: the vault cannot pay anything until its owner sets them.');
    return out;
  }
  const n = p.allowed_destinations.length;
  add(n ? 'ok' : 'warn', n ? `Pays only ${n} approved address${n === 1 ? '' : 'es'}, at most ${eth(p.eth_daily_cap)} a day.` : 'No approved address: nothing can be paid.');
  add(p.guardian ? 'ok' : 'warn', p.guardian ? `A guardian (${p.guardian}) can stop any payment while it waits.` : 'No guardian: nobody can stop a payment that fits the rules.');
  if (p.guardian) add(p.delay_ms >= HOUR_MS ? 'ok' : p.delay_ms > 0 ? 'warn' : 'bad', p.delay_ms >= HOUR_MS ? `Payments wait ${wait(p.delay_ms)}: time for a person to react.` : p.delay_ms > 0 ? `Payments wait only ${wait(p.delay_ms)}: enough for a demo, short for a person.` : 'No waiting time: the guardian never gets a chance to stop a payment.');
  if (p.proposer) add(p.guardian ? 'ok' : 'bad', p.guardian ? `The agent (${p.proposer}) is watched by a guardian and can never change the rules.` : `The agent (${p.proposer}) has no guardian watching it.`);
  add(s.signing ? 'warn' : 'ok', s.signing ? 'A signature is in progress right now.' : 'No signature in progress.');
  add(s.unsent ? 'warn' : 'ok', s.unsent ? `${s.unsent} signed payment${s.unsent === 1 ? ' is' : 's are'} not on Ethereum yet (anyone can send it; the owner can cancel it).` : 'Every signed payment is already on Ethereum.');
  if (s.uncertain) add('warn', `${s.uncertain} signature${s.uncertain === 1 ? '' : 's'} with an unknown outcome: sign again or cancel the nonce.`);
  if (s.looserChangeWaiting) add('warn', 'A looser rule change is waiting: it applies when its time ends, unless the guardian stops it.');
  if (s.handoverOpen) add('warn', 'A handover is open: the vault may change owner, and pays nothing meanwhile.');
  return out;
}
