//! Minimal EVM helpers: RLP encoding, the EIP-1559 (type 0x02) signing hash and a
//! strict classifier for the only calldata shapes the vault will ever build.
//!
//! The contract never signs a hash handed to it by a caller. It stores the
//! transaction fields, checks the policy on those fields and computes the hash here.
//!
//! Tested: the RLP unit tests use the examples from the Ethereum RLP specification, and
//! `tests/golden_vectors.rs` checks the serialization and the signing hash against 19
//! vectors generated with viem (`scripts/gen-vectors.mjs`).
//!
//! Limits the policy (M5) must cover, because this module only classifies:
//! - `is_max_uint256` detects only the exact maximum. An approval of 2^255 is practically
//!   unlimited too, so approvals must be capped by amount, not just checked for the maximum.
//! - `classify` does not look at the token contract (`to`) and accepts the zero address as
//!   recipient or spender.

use sha3::{Digest, Keccak256};

pub type Address = [u8; 20];

/// `transfer(address,uint256)`
pub const SEL_ERC20_TRANSFER: [u8; 4] = [0xa9, 0x05, 0x9c, 0xbb];
/// `approve(address,uint256)`
pub const SEL_ERC20_APPROVE: [u8; 4] = [0x09, 0x5e, 0xa7, 0xb3];

/// Fields of an EIP-1559 transaction with an empty access list and no contract creation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Eip1559Tx {
    pub chain_id: u64,
    pub nonce: u64,
    pub max_priority_fee_per_gas: u128,
    pub max_fee_per_gas: u128,
    pub gas_limit: u64,
    pub to: Address,
    pub value: u128,
    pub data: Vec<u8>,
}

pub fn keccak256(input: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(input);
    hasher.finalize().into()
}

/// Big-endian bytes without leading zeros; zero becomes the empty string.
fn be_minimal(v: u128) -> Vec<u8> {
    if v == 0 {
        return Vec::new();
    }
    let bytes = v.to_be_bytes();
    let first = bytes.iter().position(|b| *b != 0).unwrap_or(bytes.len() - 1);
    bytes[first..].to_vec()
}

/// RLP-encode a byte string and append it to `out`.
pub fn rlp_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    if bytes.len() == 1 && bytes[0] < 0x80 {
        out.push(bytes[0]);
    } else if bytes.len() <= 55 {
        out.push(0x80 + bytes.len() as u8);
        out.extend_from_slice(bytes);
    } else {
        let len = be_minimal(bytes.len() as u128);
        out.push(0xb7 + len.len() as u8);
        out.extend_from_slice(&len);
        out.extend_from_slice(bytes);
    }
}

/// RLP-encode an unsigned integer (zero is the empty string).
pub fn rlp_uint(out: &mut Vec<u8>, v: u128) {
    rlp_bytes(out, &be_minimal(v));
}

/// Wrap an already-concatenated payload of RLP items as an RLP list.
pub fn rlp_list(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + 9);
    if payload.len() <= 55 {
        out.push(0xc0 + payload.len() as u8);
    } else {
        let len = be_minimal(payload.len() as u128);
        out.push(0xf7 + len.len() as u8);
        out.extend_from_slice(&len);
    }
    out.extend_from_slice(payload);
    out
}

impl Eip1559Tx {
    /// RLP of `[chain_id, nonce, max_priority_fee, max_fee, gas_limit, to, value, data, access_list]`.
    pub fn rlp_unsigned(&self) -> Vec<u8> {
        let mut p = Vec::new();
        rlp_uint(&mut p, self.chain_id as u128);
        rlp_uint(&mut p, self.nonce as u128);
        rlp_uint(&mut p, self.max_priority_fee_per_gas);
        rlp_uint(&mut p, self.max_fee_per_gas);
        rlp_uint(&mut p, self.gas_limit as u128);
        rlp_bytes(&mut p, &self.to);
        rlp_uint(&mut p, self.value);
        rlp_bytes(&mut p, &self.data);
        p.push(0xc0); // empty access list
        rlp_list(&p)
    }

    /// `keccak256(0x02 || rlp(unsigned fields))`, the 32-byte payload to be signed.
    pub fn signing_hash(&self) -> [u8; 32] {
        let mut preimage = Vec::with_capacity(1 + 160 + self.data.len());
        preimage.push(0x02);
        preimage.extend_from_slice(&self.rlp_unsigned());
        keccak256(&preimage)
    }
}

/// What the calldata of a candidate transaction looks like. Anything not listed is `Unknown`
/// and the policy must refuse it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CallKind {
    /// Empty calldata: a plain ETH transfer.
    PlainTransfer,
    Erc20Transfer { recipient: Address, amount: [u8; 32] },
    Erc20Approve { spender: Address, amount: [u8; 32] },
    Unknown,
}

/// Strict decoder: exact length, and the 12 high bytes of the address word must be zero.
pub fn classify(data: &[u8]) -> CallKind {
    if data.is_empty() {
        return CallKind::PlainTransfer;
    }
    if data.len() != 68 {
        return CallKind::Unknown;
    }
    let selector = &data[0..4];
    let word_addr = &data[4..36];
    let word_amount = &data[36..68];
    if word_addr[..12].iter().any(|b| *b != 0) {
        return CallKind::Unknown;
    }
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&word_addr[12..]);
    let mut amount = [0u8; 32];
    amount.copy_from_slice(word_amount);
    if selector == SEL_ERC20_TRANSFER {
        CallKind::Erc20Transfer { recipient: addr, amount }
    } else if selector == SEL_ERC20_APPROVE {
        CallKind::Erc20Approve { spender: addr, amount }
    } else {
        CallKind::Unknown
    }
}

/// `true` when the amount is 2^256 - 1, the usual "unlimited approval".
pub fn is_max_uint256(amount: &[u8; 32]) -> bool {
    amount.iter().all(|b| *b == 0xff)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enc_bytes(b: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        rlp_bytes(&mut out, b);
        out
    }

    fn enc_uint(v: u128) -> Vec<u8> {
        let mut out = Vec::new();
        rlp_uint(&mut out, v);
        out
    }

    #[test]
    fn rlp_spec_strings() {
        assert_eq!(enc_bytes(b""), vec![0x80]);
        assert_eq!(enc_bytes(b"dog"), vec![0x83, b'd', b'o', b'g']);
        assert_eq!(enc_bytes(&[0x0f]), vec![0x0f]);
        assert_eq!(enc_bytes(&[0x80]), vec![0x81, 0x80]);
    }

    #[test]
    fn rlp_spec_integers() {
        assert_eq!(enc_uint(0), vec![0x80]);
        assert_eq!(enc_uint(15), vec![0x0f]);
        assert_eq!(enc_uint(1024), vec![0x82, 0x04, 0x00]);
    }

    #[test]
    fn rlp_spec_lists() {
        assert_eq!(rlp_list(&[]), vec![0xc0]);
        let mut payload = Vec::new();
        rlp_bytes(&mut payload, b"cat");
        rlp_bytes(&mut payload, b"dog");
        assert_eq!(
            rlp_list(&payload),
            vec![0xc8, 0x83, b'c', b'a', b't', 0x83, b'd', b'o', b'g']
        );
    }

    #[test]
    fn rlp_spec_long_string() {
        let s = b"Lorem ipsum dolor sit amet, consectetur adipisicing elit";
        assert_eq!(s.len(), 56);
        let enc = enc_bytes(s);
        assert_eq!(&enc[0..2], &[0xb8, 0x38]);
        assert_eq!(&enc[2..], &s[..]);
    }

    #[test]
    fn keccak_of_empty_input() {
        let h = keccak256(b"");
        let hex: String = h.iter().map(|b| format!("{:02x}", b)).collect();
        assert_eq!(
            hex,
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
        );
    }

    fn sample_tx() -> Eip1559Tx {
        Eip1559Tx {
            chain_id: 11155111,
            nonce: 0,
            max_priority_fee_per_gas: 1_000_000_000,
            max_fee_per_gas: 20_000_000_000,
            gas_limit: 21_000,
            to: [0x11; 20],
            value: 1_000_000_000_000_000,
            data: vec![],
        }
    }

    #[test]
    fn signing_hash_is_deterministic_and_field_sensitive() {
        let a = sample_tx();
        assert_eq!(a.signing_hash(), sample_tx().signing_hash());
        let mut b = sample_tx();
        b.value += 1;
        assert_ne!(a.signing_hash(), b.signing_hash());
        let mut c = sample_tx();
        c.chain_id = 1;
        assert_ne!(a.signing_hash(), c.signing_hash());
        let mut d = sample_tx();
        d.to = [0x22; 20];
        assert_ne!(a.signing_hash(), d.signing_hash());
    }

    fn calldata(selector: [u8; 4], addr_byte: u8, amount: [u8; 32]) -> Vec<u8> {
        let mut d = Vec::new();
        d.extend_from_slice(&selector);
        d.extend_from_slice(&[0u8; 12]);
        d.extend_from_slice(&[addr_byte; 20]);
        d.extend_from_slice(&amount);
        d
    }

    #[test]
    fn classify_known_shapes() {
        assert_eq!(classify(&[]), CallKind::PlainTransfer);

        let mut one = [0u8; 32];
        one[31] = 1;
        assert_eq!(
            classify(&calldata(SEL_ERC20_TRANSFER, 0xaa, one)),
            CallKind::Erc20Transfer { recipient: [0xaa; 20], amount: one }
        );
        assert_eq!(
            classify(&calldata(SEL_ERC20_APPROVE, 0xbb, one)),
            CallKind::Erc20Approve { spender: [0xbb; 20], amount: one }
        );
    }

    #[test]
    fn classify_rejects_malformed_or_unknown() {
        let one = [1u8; 32];
        // wrong length
        assert_eq!(classify(&[0xa9, 0x05, 0x9c, 0xbb]), CallKind::Unknown);
        // unknown selector
        assert_eq!(classify(&calldata([0xde, 0xad, 0xbe, 0xef], 0xaa, one)), CallKind::Unknown);
        // dirty high bytes in the address word
        let mut dirty = calldata(SEL_ERC20_APPROVE, 0xbb, one);
        dirty[4] = 0x01;
        assert_eq!(classify(&dirty), CallKind::Unknown);
    }

    #[test]
    fn unlimited_approval_is_detected() {
        let max = [0xffu8; 32];
        match classify(&calldata(SEL_ERC20_APPROVE, 0xbb, max)) {
            CallKind::Erc20Approve { amount, .. } => assert!(is_max_uint256(&amount)),
            other => panic!("unexpected kind: {:?}", other),
        }
        let mut almost = [0xffu8; 32];
        almost[31] = 0xfe;
        assert!(!is_max_uint256(&almost));
    }
}
