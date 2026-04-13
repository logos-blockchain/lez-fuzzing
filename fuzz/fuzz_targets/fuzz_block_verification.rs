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

    // Log divergence between stored and recomputed hash for coverage guidance.
    // We do NOT assert equality because adversarially-crafted fuzz inputs can
    // store an arbitrary hash field without matching the body content.
    let stored_hash = block.header.hash;
    if stored_hash == recomputed {
        // Hashes match — this is the expected case for a valid sequencer-produced block
        let _ = stored_hash;
    }
});
