// "Check this signature": proves, in the browser, that a payment recorded by the contract was
// signed for the vault's own Ethereum address and is byte-for-byte the transaction on Ethereum.
// Pure except for `receipt`, which is injected (tests pass a fake).
import { keccak256, parseTransaction, recoverAddress, serializeTransaction, type Hex } from 'viem';

export interface SignedRecord {
  token_id: string; proposal_id: number; nonce: number; signing_hash: string; signed_tx: string; tx_hash: string; owner: string; signed_ms: number;
}
export interface ProofCheck { ok: boolean | null; label: string; detail: string }
export interface Proof {
  ok: boolean;
  checks: ProofCheck[];
  tx: { chainId?: number; nonce?: number; to?: string | null; value: string; data?: string; r?: string; s?: string; yParity?: number };
  recovered?: string;
  receipt?: { status: string; from: string; to: string | null; blockNumber: string; transactionHash: string } | null;
}

const lower = (s?: string | null) => (s ?? '').toLowerCase();

export async function checkSignature(
  rec: SignedRecord, vault: { address: string; chain: number },
  receipt: (hash: string) => Promise<any | null>,
): Promise<Proof> {
  const checks: ProofCheck[] = [];
  const add = (ok: boolean | null, label: string, detail: string) => checks.push({ ok, label, detail });
  let parsed: ReturnType<typeof parseTransaction>;
  try {
    parsed = parseTransaction(rec.signed_tx as Hex);
  } catch (e: any) {
    add(false, 'The signed transaction can be read', String(e?.shortMessage ?? e?.message ?? e));
    return { ok: false, checks, tx: { value: '0' } };
  }
  const { r, s, yParity, v, ...unsigned } = parsed as any;
  const tx = { chainId: parsed.chainId, nonce: parsed.nonce, to: parsed.to, value: String(parsed.value ?? 0n), data: parsed.data, r, s, yParity };

  // 1. What the contract recorded matches what it signed.
  add(parsed.nonce === rec.nonce && parsed.chainId === vault.chain, 'Same nonce and chain as the contract recorded',
    `nonce ${parsed.nonce} (record: ${rec.nonce}), chain ${parsed.chainId} (vault: ${vault.chain})`);

  // 2. The hash that was signed is the hash of this exact transaction.
  const signingHash = keccak256(serializeTransaction(unsigned));
  add(lower(signingHash) === lower(rec.signing_hash), 'The signed hash is the hash of this transaction',
    `recomputed ${signingHash}`);

  // 3. The signature recovers to the vault's own address: only the key derived for this vault could make it.
  let recovered: string | undefined;
  try {
    recovered = await recoverAddress({ hash: signingHash, signature: { r, s, yParity } });
    add(lower(recovered) === lower(vault.address), "The signature belongs to the vault's address",
      `recovered ${recovered}; vault ${vault.address}`);
  } catch (e: any) {
    add(false, "The signature belongs to the vault's address", String(e?.shortMessage ?? e?.message ?? e));
  }

  // 4. The Ethereum transaction hash is the hash of these exact bytes, and it was mined.
  const txHash = keccak256(rec.signed_tx as Hex);
  add(lower(txHash) === lower(rec.tx_hash), 'The Ethereum hash is the hash of these bytes', `keccak256(raw) = ${txHash}`);
  let rc: Proof['receipt'] = null;
  try {
    rc = await receipt(rec.tx_hash);
  } catch {
    rc = null;
  }
  if (!rc) add(null, 'Mined on Ethereum', 'No receipt found: not sent yet, replaced by another version of this nonce, or the node did not answer.');
  else add(rc.status === '0x1' && lower(rc.from) === lower(vault.address) && lower(rc.to) === lower(parsed.to),
    'Mined on Ethereum, from the vault, to the same recipient',
    `block ${Number(BigInt(rc.blockNumber))}, status ${rc.status === '0x1' ? 'success' : 'failed'}, from ${rc.from}`);

  return { ok: checks.every((c) => c.ok === true), checks, tx, recovered, receipt: rc };
}

/** The proof as a JSON file a judge can keep and re-check with any Ethereum library. */
export function proofJson(rec: SignedRecord, vault: { id: string; address: string; chain: number; contract: string }, p: Proof) {
  return JSON.stringify({
    what: 'A payment signed by NEAR Chain Signatures for a Policy Vault, checked in the browser',
    how_to_recheck: 'keccak256(signed_tx) must equal tx_hash; recover the signer of signing_hash with (r, s, yParity) and compare with vault.evm_address; look up tx_hash on the chain.',
    vault: { contract: vault.contract, token_id: vault.id, evm_address: vault.address, chain_id: vault.chain },
    record_from_contract: rec,
    decoded: { ...p.tx, value_wei: p.tx.value },
    recovered_signer: p.recovered ?? null,
    receipt: p.receipt ?? null,
    checks: p.checks,
    all_passed: p.ok,
    checked_at: new Date().toISOString(),
  }, (_k, v) => (typeof v === 'bigint' ? v.toString() : v), 2);
}
