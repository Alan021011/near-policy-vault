// Converts a NEAR "secp256k1:<base58>" public key (64 bytes, X||Y) into an EVM address.
import { keccak256 } from 'viem';
const A = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
function b58(s) {
  let n = 0n;
  for (const c of s) {
    const d = A.indexOf(c);
    if (d < 0) throw new Error(`invalid base58 character: ${c}`);
    n = n * 58n + BigInt(d);
  }
  // Leading zero bytes (base58 '1' characters) vanish in the BigInt; the key is always
  // 64 bytes, so pad back to 128 hex characters. Longer results are rejected below.
  return n.toString(16).padStart(128, '0');
}
const key = process.argv[2];
if (!key?.startsWith('secp256k1:')) throw new Error('usage: node derive-address.mjs secp256k1:<base58>');
const hex = b58(key.slice('secp256k1:'.length));
if (hex.length !== 128) throw new Error(`expected 64 bytes, got ${hex.length / 2}`);
console.log('0x' + keccak256('0x' + hex).slice(-40));
