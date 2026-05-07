#![no_main]

use common::block::{Block, HashableBlockData};
use libfuzzer_sys::fuzz_target;
use nssa::PrivateKey;

// A fixed, valid signing key used only to exercise the hash-computation path.
// The specific key value is irrelevant to hash correctness.
const DUMMY_KEY_BYTES: [u8; 32] = [1u8; 32];

fuzz_target!(|data: &[u8]| {
    let Ok(block) = borsh::from_slice::<Block>(data) else {
        return;
    };

    let signing_key = PrivateKey::try_new(DUMMY_KEY_BYTES).expect("constant key is valid");
    let bedrock_parent_id = [0u8; 32];

    // Convert to hashable form twice so we can check determinism without
    // moving the value into the first call.
    let hashable1 = HashableBlockData::from(block.clone());
    let hashable2 = HashableBlockData::from(block.clone());

    // INVARIANT: into_pending_block() must never panic regardless of fuzz input
    let recomputed1 = hashable1.into_pending_block(&signing_key, bedrock_parent_id);
    let hash1 = recomputed1.header.hash;

    // INVARIANT: hash derivation must be deterministic
    let recomputed2 = hashable2.into_pending_block(&signing_key, bedrock_parent_id);
    let hash2 = recomputed2.header.hash;

    assert_eq!(hash1, hash2, "block hash is not deterministic");

    // We intentionally do NOT assert that the stored header hash equals the
    // recomputed one: adversarially-crafted fuzz inputs can store an arbitrary
    // hash field that does not match the body content, and that is a valid input
    // for the purpose of this target (which only tests hash stability, not
    // block validity).
    let _ = block.header.hash;
});
