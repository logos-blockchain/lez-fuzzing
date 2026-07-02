#![cfg_attr(feature = "fuzzer-libfuzzer", no_main)]
//! Fuzz target: transaction **ordering-independence** for the shielded (privacy-preserving)
//! path — the property no other target asserts.
//!
//! Every other target applies transactions in a single fixed order and checks the *result*.
//! None asks whether the *order* of two transactions can change which ones are accepted. This
//! target does: it applies a nullifier-conflicting pair in both orders on independent copies
//! of the same base state and asserts the outcome is order-independent.
//!
//! # Why the shielded path (and not native transfers)
//!
//! The original `fuzz_transaction_non_interference` proposal aimed this idea at native
//! transfers, but `V03State`'s only cross-transaction state is the append-only
//! `(CommitmentSet, NullifierSet)`; two disjoint public transfers touch only per-account maps
//! and commute trivially, so that target would be permanently green. The nullifier set is the
//! real shared state — it is what prevents double-spends — so that is where ordering can
//! actually matter.
//!
//! # The oracle
//!
//! `arb_conflicting_nullifier_pair` builds two *distinct* transactions `B` and `C` that
//! declare the **same** nullifier. A correct state machine enforces first-come-first-served:
//! whichever is applied first spends the nullifier, and the second is rejected at
//! `check_nullifiers_are_valid`. Both orderings are applied at an **identical** `(block_id,
//! timestamp)` so the *only* difference between them is transaction order — fixing a flaw in
//! the original sketch, which varied the clock per position and so could not distinguish
//! ordering effects from validity-window effects.
//!
//! Note on scope: this nullifier check is enforced by the *state machine*, not by the ZK
//! circuit, so the dev-mode synthesised proof (which bypasses the circuit) does **not** mask
//! it — unlike balance conservation, which this path deliberately never asserts.
//!
//! Requires `RISC0_DEV_MODE=1` (set by every `just fuzz` recipe) for the synthesised proofs.
//!
//! # Invariants asserted
//!
//! * **NoDoubleSpend** — in neither ordering are both conflicting transactions accepted; a
//!   shared nullifier is spendable at most once. A violation is a literal double-spend.
//! * **OrderIndependentAcceptance** — the number of transactions accepted from the pair is the
//!   same in both orderings. A violation means acceptance leaks across transactions depending
//!   on order (order-dependent interference through global state).

use arbitrary::{Arbitrary, Unstructured};
use common::transaction::LeeTransaction;
use fuzz_props::generators::arbitrary_fuzz_state;
use fuzz_props::privacy::{arb_conflicting_nullifier_pair, arb_privacy_preserving_tx};
use nssa::{AccountId, PrivacyPreservingTransaction};

/// Apply the production stateless gate and wrap for execution; `None` drops the input.
fn gate(tx: PrivacyPreservingTransaction) -> Option<LeeTransaction> {
    LeeTransaction::PrivacyPreserving(tx)
        .transaction_stateless_check()
        .ok()
}

fuzz_props::fuzz_entry!(|data: &[u8]| {
    let mut u = Unstructured::new(data);

    // Need at least two keyed accounts so the conflicting pair can use distinct signers.
    let fuzz_accs = match arbitrary_fuzz_state(&mut u) {
        Ok(accs) if accs.len() >= 2 => accs,
        _ => return,
    };
    let init_accs: Vec<(AccountId, u128)> = fuzz_accs
        .iter()
        .map(|a| (a.account_id, a.balance))
        .collect();
    let mut base = fuzz_props::genesis::genesis_state(&init_accs, vec![]);

    // ── Seed the commitment set ──────────────────────────────────────────────────────────
    // A nullifier only passes check 6 when its digest is in `root_history`, which starts empty
    // and is seeded only once a commitment-bearing transaction applies. Reuse the
    // proven-reachable generator to grow it; individual outcomes don't matter here.
    let n_seed: u8 = u8::arbitrary(&mut u).unwrap_or(0) % 4;
    for i in 0..n_seed {
        let Ok(tx) = arb_privacy_preserving_tx(&mut u, &base, &fuzz_accs) else {
            break;
        };
        let Some(lee) = gate(tx) else { continue };
        let _ = lee.execute_check_on_state(&mut base, 1 + u64::from(i), u64::from(i));
    }

    // ── Build the nullifier-conflicting pair against the seeded base ─────────────────────
    let Ok((tx_b, tx_c)) = arb_conflicting_nullifier_pair(&mut u, &base, &fuzz_accs) else {
        return;
    };

    // Two independent instances of each so both orderings get a fresh, un-consumed copy.
    let (Some(b1), Some(c1)) = (gate(tx_b.clone()), gate(tx_c.clone())) else {
        return;
    };
    let (Some(b2), Some(c2)) = (gate(tx_b), gate(tx_c)) else {
        return;
    };

    // Identical clock for both orderings: the sole difference is transaction order. The pair's
    // validity windows are unbounded, so the specific values are immaterial.
    const BLOCK: u64 = 1;
    const TS: u64 = 0;

    // ── Order 1: B → C ───────────────────────────────────────────────────────────────────
    let mut s_bc = base.clone();
    let rb1 = b1.execute_check_on_state(&mut s_bc, BLOCK, TS).is_ok();
    let rc1 = c1.execute_check_on_state(&mut s_bc, BLOCK, TS).is_ok();

    // ── Order 2: C → B ───────────────────────────────────────────────────────────────────
    let mut s_cb = base.clone();
    let rc2 = c2.execute_check_on_state(&mut s_cb, BLOCK, TS).is_ok();
    let rb2 = b2.execute_check_on_state(&mut s_cb, BLOCK, TS).is_ok();

    // ── INVARIANT [NoDoubleSpend] ────────────────────────────────────────────────────────
    // The shared nullifier must be spendable at most once, in either order.
    assert!(
        !(rb1 && rc1),
        "INVARIANT VIOLATION [NoDoubleSpend]: both conflicting transactions accepted in order \
         B→C — the shared nullifier was double-spent"
    );
    assert!(
        !(rc2 && rb2),
        "INVARIANT VIOLATION [NoDoubleSpend]: both conflicting transactions accepted in order \
         C→B — the shared nullifier was double-spent"
    );

    // ── INVARIANT [OrderIndependentAcceptance] ───────────────────────────────────────────
    // The count of accepted transactions from the pair must not depend on ordering.
    let accepted_bc = u8::from(rb1) + u8::from(rc1);
    let accepted_cb = u8::from(rb2) + u8::from(rc2);
    assert_eq!(
        accepted_bc, accepted_cb,
        "INVARIANT VIOLATION [OrderIndependentAcceptance]: {accepted_bc} of the pair accepted \
         as B→C but {accepted_cb} as C→B — transaction acceptance is order-dependent",
    );
});
