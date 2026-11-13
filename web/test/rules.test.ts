// Tests for the rules summary and the weak set-up warnings (web/src/rules.ts, M42).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ruleWarnings, summarize, type RulesDraft } from '../src/rules.ts';

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
