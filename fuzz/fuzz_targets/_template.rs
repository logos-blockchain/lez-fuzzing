#![no_main]

use fuzz_props::arbitrary_types::ArbNSSATransaction;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|wrapped: ArbNSSATransaction| {
    let tx = wrapped.0;

    // ── Stateless gate ────────────────────────────────────────────────────────
    // Remove this block to fuzz malformed / unsigned transactions too.
    let Ok(tx) = tx.transaction_stateless_check() else {
        return;
    };

    // ── Call the function under test ──────────────────────────────────────────
    // Example:
    //   let mut state = V03State::new_with_genesis_accounts(&init_accs, vec![], 0);
    //   let result = tx.execute_check_on_state(&mut state, block_id, timestamp);

    // ── Assert invariants ─────────────────────────────────────────────────────
    // Use fuzz_props::invariants::assert_invariants(&ctx) or inline assertions.
    let _ = tx; // replace once the target body is implemented
});
