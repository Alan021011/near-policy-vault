// Prueba A1, paso 1: construye la transaccion de prueba (Sepolia, 0.001 ETH a la propia direccion)
// y escribe su hash de firma y su serializacion sin firmar en a1-tx.json. No usa ninguna clave.
import { serializeTransaction, keccak256 } from 'viem';
import { writeFileSync } from 'node:fs';
const me = '0x881294c1b52d631ab43fa2bd23d691209b548d11';
const tx = { type: 'eip1559', chainId: 11155111, nonce: 0, maxPriorityFeePerGas: 1_000_000_000n,
  maxFeePerGas: 30_000_000_000n, gas: 21000n, to: me, value: 1_000_000_000_000_000n, data: '0x', accessList: [] };
const unsigned = serializeTransaction(tx);
const hash = keccak256(unsigned);
writeFileSync('a1-tx.json', JSON.stringify({ unsigned, hash }, null, 2));
console.log('hash a firmar:', hash);
