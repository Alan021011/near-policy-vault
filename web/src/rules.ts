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
const wait = (ms: number) => (ms === 0 ? 'no waiting time' : ms % HOUR_MS === 0 ? `${ms / HOUR_MS} hour${ms === HOUR_MS ? '' : 's'}` : ms >= 60_000 && ms % 60_000 === 0 ? `${ms / 60_000} minute${ms === 60_000 ? '' : 's'}` : `${ms / 1000} seconds`);

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
