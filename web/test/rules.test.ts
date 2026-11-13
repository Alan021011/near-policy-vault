// Tests for the rules summary and the weak set-up warnings (web/src/rules.ts, M42).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { changeOf, ruleWarnings, safetyChecks, summarize, type FullRules, type RulesDraft } from '../src/rules.ts';

const base: RulesDraft = {
  delay_ms: 3_600_000, guardian: 'friend.testnet', eth_daily_cap: '1000000000000000', max_gas_cost: '100000000000000',
  allowed_destinations: ['0x881294c1b52d631ab43fa2bd23d691209b548d11'], proposer: 'bot.testnet',
};
const levels = (r: RulesDraft) => ruleWarnings(r).map((w) => w.level);

test('a sound agent set-up has no warning', () => {
  assert.deepEqual(ruleWarnings(base), []);
});
test('an agent without a guardian is a red warning', () => {
  assert.deepEqual(levels({ ...base, guardian: null }), ['high']);
});
test('a waiting time of 0 with a guardian is a red warning', () => {
  assert.ok(levels({ ...base, delay_ms: 0 }).includes('high'));
});
test('an agent with less than an hour of waiting time is a warning', () => {
  assert.deepEqual(levels({ ...base, delay_ms: 60_000 }), ['warn']);
  assert.deepEqual(levels({ ...base, delay_ms: 3_600_000 }), []);
});
test('no guardian and no agent: a warning about handovers', () => {
  assert.deepEqual(levels({ ...base, guardian: null, proposer: null }), ['warn']);
});
test('a large daily limit with an agent is a warning', () => {
  assert.deepEqual(levels({ ...base, eth_daily_cap: (2n * 10n ** 17n).toString() }), ['warn']);
});
test('no approved address is a note', () => {
  assert.deepEqual(levels({ ...base, allowed_destinations: [] }), ['info']);
});
test('the summary says the rules in plain words', () => {
  const s = summarize(base).join(' ');
  assert.match(s, /At most 0\.001 ETH can leave the vault per day/);
  assert.match(s, /only pay 1 approved address\./);
  assert.match(s, /waits 1 hour/);
  assert.match(s, /friend\.testnet can stop any payment/);
  assert.match(s, /bot\.testnet can request and send payments/);
  assert.match(summarize({ ...base, guardian: null, delay_ms: 0, proposer: null }).join(' '), /signed at once.*Nobody can stop.*only you/);
});

// ---------- M30 ----------
const full: FullRules = { ...base, chain_id: 11155111, allowed_spenders: [], tokens: [], nfts: [] };

test('a first set of rules applies at once', () => {
  assert.equal(changeOf(null, full).appliesAtOnce, true);
});
test('only stricter changes apply at once', () => {
  const r = changeOf(full, { ...full, eth_daily_cap: '500000000000000', delay_ms: 7_200_000, proposer: null });
  assert.equal(r.appliesAtOnce, true);
  assert.deepEqual(r.changes.map((x) => [x.what, x.looser]), [['Daily limit', false], ['Waiting time', false], ['Agent', false]]);
});
test('a higher limit, a new address or a new agent is looser and waits the current waiting time', () => {
  for (const neu of [{ ...full, eth_daily_cap: '2000000000000000' }, { ...full, allowed_destinations: [...full.allowed_destinations, '0x' + '1'.repeat(40)] }, { ...full, proposer: 'other.testnet' }]) {
    const r = changeOf(full, neu);
    assert.equal(r.appliesAtOnce, false);
    assert.equal(r.waitMs, full.delay_ms);
  }
});
test('replacing or removing the guardian waits max(2 x waiting time, 3 days)', () => {
  assert.equal(changeOf(full, { ...full, guardian: null }).waitMs, 3 * 24 * 3_600_000);
  const long = { ...full, delay_ms: 3 * 24 * 3_600_000 };
  const r = changeOf(long, { ...long, guardian: 'new.testnet' });
  assert.equal(r.replacesGuardian, true);
  assert.equal(r.waitMs, 6 * 24 * 3_600_000);
});
test('adding a guardian where there was none is not looser', () => {
  assert.equal(changeOf({ ...full, guardian: null }, full).appliesAtOnce, true);
});
test('a new token, or a higher token cap, is looser; a lower one is not', () => {
  const t = { contract: '0x' + 'a'.repeat(40), daily_cap: '10', max_approval: '10' };
  assert.equal(changeOf(full, { ...full, tokens: [t] }).appliesAtOnce, false);
  assert.equal(changeOf({ ...full, tokens: [t] }, { ...full, tokens: [{ ...t, daily_cap: '20' }] }).appliesAtOnce, false);
  assert.equal(changeOf({ ...full, tokens: [t] }, { ...full, tokens: [{ ...t, daily_cap: '5' }] }).appliesAtOnce, true);
});
test('safety check: a sound vault is all ok, a weak one is flagged', () => {
  const quiet = { hasRules: true, unsent: 0, uncertain: 0, handoverOpen: false, looserChangeWaiting: false, signing: false };
  assert.ok(safetyChecks(base, quiet).every((x) => x.state === 'ok'));
  const weak = safetyChecks({ ...base, guardian: null }, { ...quiet, unsent: 1, handoverOpen: true });
  assert.ok(weak.some((x) => x.state === 'bad' && /no guardian watching/.test(x.text)));
  assert.ok(weak.some((x) => x.state === 'warn' && /not on Ethereum yet/.test(x.text)));
  assert.ok(weak.some((x) => x.state === 'warn' && /handover is open/.test(x.text)));
  assert.deepEqual(safetyChecks(null, { ...quiet, hasRules: false }).map((x) => x.state), ['ok', 'bad']);
  assert.ok(safetyChecks({ ...base, delay_ms: 60_000 }, quiet).some((x) => x.state === 'warn' && /only 1 minute/.test(x.text)));
});
