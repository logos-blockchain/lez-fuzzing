#![no_main]
//! Fuzz target: block hash integrity — three invariants unique to block-level validation.
//!
//! 1. **Hash integrity via `From<Block>` round-trip** — `HashableBlockData::from(block)`
//!    must be lossless: re-deriving the hash from the converted value must reproduce the
//!    hash that `into_pending_block` stored in `block.header.hash`.  Catches any field
//!    that is dropped or silently transformed by the `From` impl.
//!
//! 2. **Hash preimage completeness** — every header field of `HashableBlockData`
//!    (`block_id`, `prev_block_hash`, `timestamp`) must affect the computed hash.
//!    Verified by single-field mutations: changing one field must produce a different
//!    hash.  A hash that silently ignores a field allows an attacker to rewrite that
//!    field without invalidating the block hash.
//!
//! 3. **Transaction-order commitment** — the hash must be order-sensitive.  Reversing
//!    a block's transaction list (when the first and last transactions differ bytewise)
//!    must produce a different hash.  A commutative hash (e.g., XOR of per-tx hashes)
//!    would allow silent transaction reordering while the block hash remains valid.
//!

use arbitrary::{Arbitrary, Unstructured};
use common::block::HashableBlockData;
use fuzz_props::arbitrary_types::ArbHashableBlockData;
use libfuzzer_sys::fuzz_target;
use nssa::PrivateKey;

const DUMMY_KEY_BYTES: [u8; 32] = [1u8; 32];

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);
    let Ok(wrap) = ArbHashableBlockData::arbitrary(&mut u) else {
        return;
    };
    let base = wrap.0;

    let signing_key = PrivateKey::try_new(DUMMY_KEY_BYTES).expect("constant key is valid");
    let bedrock = [0u8; 32];

    // Compute the canonical hash for the base input.
    let block = base.clone().into_pending_block(&signing_key, bedrock);
    let hash_base = block.header.hash;

    // ── INVARIANT 1: HashableBlockData::from(Block) is lossless ──────────────────
    //
    // For blocks produced by `into_pending_block`, `header.hash` is the hash computed
    // from the block's semantic fields.  Converting back via `From<Block>` strips the
    // header (computed hash, signature) and retains only the payload.  Re-deriving the
    // hash from the round-tripped value must reproduce the original hash.
    //
    // This is the hash-integrity check the old target deliberately skipped for adversarial
    // inputs.  For *programmatically-constructed* blocks it is fully assertable.
    {
        let roundtrip_hashable = HashableBlockData::from(block);
        let hash_roundtrip = roundtrip_hashable
            .into_pending_block(&signing_key, bedrock)
            .header
            .hash;
        assert_eq!(
            hash_base,
            hash_roundtrip,
            "INVARIANT VIOLATION [HashRoundTrip]: HashableBlockData::from(Block) is lossy — \
             re-derived hash differs from the original (a field is dropped or transformed \
             by the From impl, breaking hash integrity)"
        );
    }

    // ── INVARIANT 2a: block_id is included in the hash preimage ──────────────────
    {
        let mut m = base.clone();
        m.block_id = m.block_id.wrapping_add(1);
        let hash_m = m.into_pending_block(&signing_key, bedrock).header.hash;
        assert_ne!(
            hash_base,
            hash_m,
            "INVARIANT VIOLATION [HashPreimage/block_id]: incrementing block_id did not \
             change the block hash (block_id is absent from the hash preimage — an attacker \
             can change the block number without invalidating the hash)"
        );
    }

    // ── INVARIANT 2b: prev_block_hash is included in the hash preimage ───────────
    {
        let mut m = base.clone();
        m.prev_block_hash.0[0] ^= 0xFF;
        let hash_m = m.into_pending_block(&signing_key, bedrock).header.hash;
        assert_ne!(
            hash_base,
            hash_m,
            "INVARIANT VIOLATION [HashPreimage/prev_block_hash]: flipping a byte in \
             prev_block_hash did not change the block hash (prev_block_hash is absent from \
             the hash preimage — chain continuity is not committed to)"
        );
    }

    // ── INVARIANT 2c: timestamp is included in the hash preimage ─────────────────
    {
        let mut m = base.clone();
        m.timestamp = m.timestamp.wrapping_add(1);
        let hash_m = m.into_pending_block(&signing_key, bedrock).header.hash;
        assert_ne!(
            hash_base,
            hash_m,
            "INVARIANT VIOLATION [HashPreimage/timestamp]: incrementing timestamp did not \
             change the block hash (timestamp is absent from the hash preimage — the block \
             time can be rewritten without invalidating the hash)"
        );
    }

    // ── INVARIANT 3: transaction-order commitment ─────────────────────────────────
    //
    // A hash commutative over its transaction list (e.g., XOR of per-tx hashes) would
    // produce the same block hash for [tx_A, tx_B] and [tx_B, tx_A], enabling a silent
    // transaction-reordering attack.  We assert only when the first and last transactions
    // are bytewise distinct — if they are identical, reversing the list is a semantic
    // no-op and the matching hashes are correct.
    if base.transactions.len() >= 2 {
        let first = borsh::to_vec(&base.transactions[0])
            .expect("serialising a fuzz-generated transaction must succeed");
        let last = borsh::to_vec(&base.transactions[base.transactions.len() - 1])
            .expect("serialising a fuzz-generated transaction must succeed");

        if first != last {
            let mut reordered = base.clone();
            reordered.transactions.reverse();
            let hash_reordered = reordered.into_pending_block(&signing_key, bedrock).header.hash;
            assert_ne!(
                hash_base,
                hash_reordered,
                "INVARIANT VIOLATION [TxOrderCommitment]: reversing the transaction list \
                 produced the same block hash — the hash is commutative over transactions \
                 (a transaction-reordering attack is possible without invalidating the block hash)"
            );
        }
    }
});
