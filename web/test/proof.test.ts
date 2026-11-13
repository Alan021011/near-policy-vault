// Tests for "Check this signature" (web/src/proof.ts) with a real record of vault 78 (nonce 0).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { checkSignature, proofJson, type SignedRecord } from '../src/proof.ts';

const rec: SignedRecord = {
  token_id: '78', proposal_id: 60, nonce: 0, owner: 'recv.alan-vault-2026.testnet', signed_ms: 1794107347934,
  signed_tx: '0x02f87383aa36a780843b9aca00843b9aca1c82520894881294c1b52d631ab43fa2bd23d691209b548d11865af3107a400080c001a01bf57b97b4c51d9875a6420e00ce30b20d4b720212836f1c4f4c787cfa98e8ffa05472893d2540739f1041c84aedce6ce2f0a9e1199629af977caea8be416c48c2',
  signing_hash: '0x5c8d710bb308731c5b7d617cc5e28d8f8aeb7dd483edf90d64f6f7fac054dc6d',
  tx_hash: '0x984b7a1ae002155e9974d45897a8750de4be837bb508706122441acc8e40fdfc',
};
const vault = { address: '0x9b1cd76dcdc367c4364441e28f936508be189ff0', chain: 11155111 };
const mined = async () => ({ status: '0x1', from: vault.address, to: '0x881294c1b52d631ab43fa2bd23d691209b548d11', blockNumber: '0x10', transactionHash: rec.tx_hash });

test('a real signed payment of vault 78 passes every check', async () => {
  const p = await checkSignature(rec, vault, mined);
  assert.equal(p.ok, true, JSON.stringify(p.checks));
  assert.equal(p.recovered?.toLowerCase(), vault.address);
  assert.equal(p.tx.to?.toLowerCase(), '0x881294c1b52d631ab43fa2bd23d691209b548d11');
  assert.ok(JSON.parse(proofJson(rec, { ...vault, id: '78', contract: 'c.testnet' }, p)).all_passed);
});
test('another vault address is not the signer', async () => {
  const p = await checkSignature(rec, { ...vault, address: '0x' + '1'.repeat(40) }, mined);
  assert.equal(p.ok, false);
  assert.ok(p.checks.some((c) => c.ok === false && /vault's address/.test(c.label)));
});
test('a recorded hash that does not match the bytes fails', async () => {
  const p = await checkSignature({ ...rec, tx_hash: '0x' + '0'.repeat(64), signing_hash: '0x' + '0'.repeat(64) }, vault, async () => null);
  assert.equal(p.ok, false);
  assert.equal(p.checks.filter((c) => c.ok === false).length, 2);
});
test('no receipt is unknown, not a pass', async () => {
  const p = await checkSignature(rec, vault, async () => null);
  assert.equal(p.ok, false);
  assert.equal(p.checks.at(-1)?.ok, null);
});
test('a tampered raw transaction is rejected', async () => {
  const p = await checkSignature({ ...rec, signed_tx: rec.signed_tx.slice(0, -4) + 'ffff' }, vault, mined);
  assert.equal(p.ok, false);
});
test('garbage is reported, not thrown', async () => {
  const p = await checkSignature({ ...rec, signed_tx: '0x1234' }, vault, mined);
  assert.equal(p.ok, false);
  assert.equal(p.checks.length, 1);
});
