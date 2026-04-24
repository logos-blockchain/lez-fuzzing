#![no_main]

use common::block::{Block, HashableBlockData};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(block) = borsh::from_slice::<Block>(data) else {
        return;
    };

    // Convert to hashable form and re-derive the block hash
    let hashable = HashableBlockData::from(block.clone());

    // INVARIANT: block_hash() must never panic regardless of fuzz input
    let recomputed = hashable.block_hash();

    // INVARIANT: block_hash() must be deterministic
    let recomputed2 = hashable.block_hash();
    assert_eq!(recomputed, recomputed2, "block_hash() is not deterministic");

    // We intentionally do NOT assert that the stored header hash equals the
    // recomputed one: adversarially-crafted fuzz inputs can store an arbitrary
    // hash field that does not match the body content, and that is a valid input
    // for the purpose of this target (which only tests hash stability, not
    // block validity).
    let _ = (block.header.hash, recomputed);
});
