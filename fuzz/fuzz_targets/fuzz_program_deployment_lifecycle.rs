#![no_main]
//! Fuzz target: `V03State::transition_from_program_deployment_transaction`.
//!
//! The deployment path runs `ValidatedStateDiff::from_program_deployment_transaction`
//! followed by `apply_state_diff`, which means it touches WASM bytecode validation, program
//! ID derivation, and program insertion into `V03State::programs` — none of
//! which are exercised elsewhere.
//!
//! # Invariants
//!
//! 1. **NoPanic** — `transition_from_program_deployment_transaction` must never
//!    panic on any arbitrary `ProgramDeploymentTransaction`, whether the bytecode
//!    is valid WASM or random garbage.  It must return `Ok` or `Err`.
//!
//! 2. **BalanceIsolation** — program deployment does not transfer or mint tokens.
//!    Every genesis account balance must be identical before and after a
//!    deployment call, regardless of whether the transaction succeeds or fails.
//!
//! 3. **StateIsolationOnFailure** — if the call returns `Err`, no genesis account
//!    balance or nonce must change.  This mirrors the `StateIsolationOnFailure`
//!    invariant in `fuzz_state_transition` and ensures the deployment path shares
//!    the same atomicity guarantee as the public-transaction path.

use arbitrary::{Arbitrary, Unstructured};
use fuzz_props::arbitrary_types::ArbProgramDeploymentTransaction;
use fuzz_props::generators::arbitrary_fuzz_state;
use libfuzzer_sys::fuzz_target;
use nssa::V03State;

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);

    // Generate a fuzz-driven initial state.
    let fuzz_accs = match arbitrary_fuzz_state(&mut u) {
        Ok(accs) => accs,
        Err(_) => return,
    };
    let init_accs: Vec<(nssa::AccountId, u128)> = fuzz_accs
        .iter()
        .map(|a| (a.account_id, a.balance))
        .collect();

    // Generate an arbitrary program deployment transaction.
    let tx_wrap = match ArbProgramDeploymentTransaction::arbitrary(&mut u) {
        Ok(w) => w,
        Err(_) => return,
    };
    let tx = tx_wrap.0;

    let mut state = V03State::new_with_genesis_accounts(&init_accs, vec![], 0);

    // Capture per-account state snapshots before the deployment attempt.
    let balances_before: Vec<u128> = init_accs
        .iter()
        .map(|&(id, _)| state.get_account_by_id(id).balance)
        .collect();
    let nonces_before: Vec<nssa_core::account::Nonce> = init_accs
        .iter()
        .map(|&(id, _)| state.get_account_by_id(id).nonce)
        .collect();

    // ── Invariant 1: NoPanic ──────────────────────────────────────────────────
    // The call may return Ok or Err — it must not panic.
    let result = state.transition_from_program_deployment_transaction(&tx);

    match result {
        Err(_) => {
            // ── Invariant 3: StateIsolationOnFailure ──────────────────────────
            // On failure, all genesis account balances and nonces must be unchanged.
            for (i, &(acc_id, _)) in init_accs.iter().enumerate() {
                let bal_after = state.get_account_by_id(acc_id).balance;
                assert_eq!(
                    balances_before[i],
                    bal_after,
                    "INVARIANT VIOLATION [StateIsolationOnFailure]: \
                     program deployment failure changed balance of account {:?} \
                     (before={}, after={})",
                    acc_id,
                    balances_before[i],
                    bal_after,
                );
                let nonce_after = state.get_account_by_id(acc_id).nonce;
                assert_eq!(
                    nonces_before[i],
                    nonce_after,
                    "INVARIANT VIOLATION [StateIsolationOnFailure]: \
                     program deployment failure changed nonce of account {:?}",
                    acc_id,
                );
            }
        }
        Ok(()) => {
            // ── Invariant 2: BalanceIsolation ─────────────────────────────────
            // On success, no genesis account balance may change — deployment
            // only inserts a new program entry, it does not move tokens.
            for (i, &(acc_id, _)) in init_accs.iter().enumerate() {
                let bal_after = state.get_account_by_id(acc_id).balance;
                assert_eq!(
                    balances_before[i],
                    bal_after,
                    "INVARIANT VIOLATION [BalanceIsolation]: \
                     successful program deployment changed balance of account {:?} \
                     (before={}, after={}) — deployment must not transfer tokens",
                    acc_id,
                    balances_before[i],
                    bal_after,
                );
            }
        }
    }
});
