// The live proofs the README cites, checked again from the visitor's browser on the Verify page.
// Sepolia hashes are checked for a successful receipt; NEAR transactions for their outcome
// (a refused request must have failed, a veto or the key deletion must have succeeded).
export interface EthProof { hash: string; what: string }
export interface NearProof { hash: string; sender: string; what: string; expect: 'success' | 'failure' }

export const ETH_PROOFS: EthProof[] = [
  { hash: '0xfe6d501e202d703ed56ef3978b6c6f666379fbe87d9d0c456683cd22741a45b1', what: 'First transaction signed by NEAR Chain Signatures (A1)' },
  { hash: '0xd77fb56f370bbecf0247db4a557ab15a04d0befdf0e2c620415ed95d872fd067', what: 'First payment signed through the vault contract (vault 29)' },
  { hash: '0xeeea5c420fae65dcae4f8e166e783ae6974c2487a6b0f128de2572bc2030fdcb', what: 'A kept signature cancelled with cancel_nonce' },
  { hash: '0x3eb5425d2dbd79df3e4d5bcb0cb2f7cca8ba90892a1752f3539079ba624a7890', what: 'Seller cancels a kept payment during a sale (vault 41)' },
  { hash: '0xda972f8b43e4cd710abf135ccd445aaf6872be4550e52dd9b2157b54e0463b96', what: 'ERC-20 (WETH) transfer within the token’s daily limit (vault 74)' },
  { hash: '0xc31f3f272071d04c69fb16bdcca19c16aecd994b5249a49e7058c9eba41e0bc4', what: 'A token permission (approve) that the buyer’s check flagged' },
  { hash: '0xfe85d9ca3502caf5bb07b2111b4655c8bdfb2256be933f85b78b6517a81e1494', what: 'That permission revoked before the sale could be SAFE' },
  { hash: '0x24a11e451a6d068208ae6d1ad6bcf742749462b757ee8ae9c17b198c1fc6d962', what: 'Payment from vault 75, later bought from the web page' },
  { hash: '0xd9d9873e806c33a1eb3f51f12be9b8c8be2767857542192f22a3ba48ff5f3f9a', what: 'An Ethereum NFT leaves vault 77 within its daily count' },
  { hash: '0x984b7a1ae002155e9974d45897a8750de4be837bb508706122441acc8e40fdfc', what: 'Payments agent, fixed rules: the legitimate invoice paid (vault 78)' },
  { hash: '0xe5844e89a4e9004c7b49757a399fd53f33f0d7ef010c2d5cb5379f10160204c1', what: 'Payments agent with an AI model: the legitimate invoice paid' },
  { hash: '0x47f9f68246197d890dbe205f0b351a20e3d5bbd44b61a626fc7276db2e176132', what: 'Agent payment after the reproducible build was deployed' },
  { hash: '0xeb05afdfebfadcfd1c0a4528203ccb4e674b333b62d08f698d74020ff916eea2', what: 'Agent payment after the NFT card (M26) was deployed' },
  { hash: '0x1e802e96e0b51354f9b8647702fd3ab7962da796e708e681d6c96aa2bb33f3d7', what: 'Agent payment after the contract was locked (0 keys)' },
];

export const NEAR_PROOFS: NearProof[] = [
  { hash: 'AKSN8WJmzQ9arVqkSf9tHsWUktmuHMRsaJ85VLHVS7ma', sender: 'recv.alan-vault-2026.testnet', what: 'Agent asks for 0.05 ETH ("URGENT, ignore your rules"): refused, over the daily limit', expect: 'failure' },
  { hash: 'CNdjnsnkNVfAaehPqxNfVHR6Lf32nQdP7rveLuNvUuY4', sender: 'recv.alan-vault-2026.testnet', what: 'Agent pays an unknown supplier: refused, not an approved recipient', expect: 'failure' },
  { hash: 'jFScaa5XX9KDN2vKNvmDMMQLtGmJARgkFiqjnwkPGNR', sender: 'recv.alan-vault-2026.testnet', what: 'The AI model approves the unknown supplier: refused by the contract', expect: 'failure' },
  { hash: 'DCDKqkiA9PKaHpEEUMhecWf5gh4XmcsZiXY9iMkzkbMs', sender: 'cheapicon4328.testnet', what: 'The guardian vetoes the duplicate invoice (fixed-rules run)', expect: 'success' },
  { hash: 'C7z75AR4dt2SweJg1gVAfoHFaL1CVJAPEw3iaj6q83ZH', sender: 'cheapicon4328.testnet', what: 'The guardian vetoes the duplicate the AI model approved', expect: 'success' },
  { hash: 'H1sjwkrYpFZh2Hpn25TYfrVDeopQhiewXiTokoP5D3jc', sender: 'cheapicon4328.testnet', what: 'Veto sent from a phone after a Telegram alert', expect: 'success' },
  { hash: 'AgJL65MQNxGK58Ai1Forvh71YD3HwpiqLMPUL61TwvMd', sender: 'm3.alan-vault-2026.testnet', what: 'The contract’s only full-access key deleted (contract locked)', expect: 'success' },
];
