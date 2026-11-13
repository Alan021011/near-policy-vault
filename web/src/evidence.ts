// The live proofs the README cites, checked again from the visitor's browser on the Verify page and
// by scripts/evidence.mjs. The list lives in evidence.json so both read the same data.
import data from './evidence.json';
export interface EthProof { hash: string; what: string }
export interface NearProof { hash: string; sender: string; what: string; expect: 'success' | 'failure' }
export const ETH_PROOFS: EthProof[] = data.eth;
export const NEAR_PROOFS: NearProof[] = data.near as NearProof[];
/** The commit the deployed contract must name in contract_source_metadata. */
export const SOURCE_COMMIT: string = data.source_commit;
