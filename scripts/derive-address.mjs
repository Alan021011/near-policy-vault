// Converts a NEAR "secp256k1:<base58>" public key (64 bytes, X||Y) into an EVM address.
import { keccak256 } from 'viem';
const A = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
function b58(s) {
  let n = 0n;
  for (const c of s) n = n * 58n + BigInt(A.indexOf(c));
  let hex = n.toString(16);
  if (hex.length % 2) hex = '0' + hex;
  return hex;
}
const key = process.argv[2];
if (!key?.startsWith('secp256k1:')) throw new Error('usage: node derive-address.mjs secp256k1:<base58>');
const hex = b58(key.slice('secp256k1:'.length));
if (hex.length !== 128) throw new Error(`expected 64 bytes, got ${hex.length / 2}`);
console.log('0x' + keccak256('0x' + hex).slice(-40));
