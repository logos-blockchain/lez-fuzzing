#![no_main]

use common::{
    block::{Block, HashableBlockData},
    transaction::NSSATransaction,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Attempt 1: decode as NSSATransaction and verify roundtrip
    if let Ok(tx) = borsh::from_slice::<NSSATransaction>(data) {
        let re_encoded = borsh::to_vec(&tx).expect("re-encode of valid tx must succeed");
        let tx2 = borsh::from_slice::<NSSATransaction>(&re_encoded)
            .expect("second decode of re-encoded tx must succeed");
        assert_eq!(
            re_encoded,
            borsh::to_vec(&tx2).unwrap(),
            "NSSATransaction roundtrip encoding divergence"
        );
    }

    // Attempt 2: decode as Block — must never panic
    let _ = borsh::from_slice::<Block>(data);

    // Attempt 3: decode as HashableBlockData — must never panic
    let _ = borsh::from_slice::<HashableBlockData>(data);
});
