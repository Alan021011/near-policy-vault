// Prueba A1, paso 3: envia a Sepolia la transaccion firmada por Chain Signatures y espera su confirmacion.
import { createPublicClient, http, parseTransaction, serializeTransaction } from 'viem';
import { sepolia } from 'viem/chains';
import { readFileSync } from 'node:fs';
const { unsigned } = JSON.parse(readFileSync('a1-tx.json', 'utf8'));
const r = '0x4057bd4e77d6989afeabbb8eaef7cbe4554cc0eb036393d05a6195347cbf1d98';
const s = '0x3a85fc21be896c6b5c90c09b479f75806a2b0933b1994876b1a7bb6c25733809';
const signed = serializeTransaction(parseTransaction(unsigned), { r, s, yParity: 1 });
const client = createPublicClient({ chain: sepolia, transport: http('https://ethereum-sepolia-rpc.publicnode.com') });
const hash = await client.sendRawTransaction({ serializedTransaction: signed });
console.log('enviada, hash:', hash);
const rc = await client.waitForTransactionReceipt({ hash, timeout: 120_000 });
console.log('estado:', rc.status, '| bloque:', rc.blockNumber, '| gas usado:', rc.gasUsed, '| desde:', rc.from, '| hacia:', rc.to);
console.log('explorador: https://sepolia.etherscan.io/tx/' + hash);
