// Prueba A1, paso 2: comprueba que la firma devuelta por Chain Signatures corresponde a la direccion derivada.
import { recoverAddress, serializeTransaction, parseTransaction, keccak256 } from 'viem';
import { readFileSync } from 'node:fs';
const { unsigned, hash } = JSON.parse(readFileSync('a1-tx.json', 'utf8'));
const big_r = '024057bd4e77d6989afeabbb8eaef7cbe4554cc0eb036393d05a6195347cbf1d98';
const r = '0x' + big_r.slice(2);            // coordenada x del punto R
const s = '0x3a85fc21be896c6b5c90c09b479f75806a2b0933b1994876b1a7bb6c25733809';
const yParity = 1;                          // recovery_id devuelto
const rec = await recoverAddress({ hash, signature: { r, s, yParity } });
console.log('direccion recuperada:', rec);
console.log('direccion esperada  :', '0x881294c1b52d631ab43fa2bd23d691209b548d11');
console.log('coinciden:', rec.toLowerCase() === '0x881294c1b52d631ab43fa2bd23d691209b548d11');
const tx = parseTransaction(unsigned);
const signed = serializeTransaction(tx, { r, s, yParity });
console.log('tx firmada lista para enviar (', (signed.length-2)/2, 'bytes ):', signed);
