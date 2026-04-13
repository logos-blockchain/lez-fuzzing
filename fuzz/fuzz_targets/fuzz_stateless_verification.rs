#![no_main]

use arbitrary::Unstructured;
use common::transaction::NSSATransaction;
use fuzz_props::generators::arbitrary_transaction;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);

    // Path A: try to build a structured transaction from unstructured bytes
    if let Ok(tx) = arbitrary_transaction(&mut u) {
        let result = tx.clone().transaction_stateless_check();

        // Idempotency: if check passes, re-checking the returned tx must also pass
        if let Ok(checked_tx) = result {
            let result2 = checked_tx.transaction_stateless_check();
            assert!(
                result2.is_ok(),
                "stateless_check is not idempotent: second call failed"
            );
        }
    }

    // Path B: raw decode first, then check — must never panic
    if let Ok(tx) = borsh::from_slice::<NSSATransaction>(data) {
        let _ = tx.transaction_stateless_check();
    }
});
