#![cfg_attr(feature = "fuzzer-libfuzzer", no_main)]
//! Fuzz target: sequencer vs replayer differential state-root equivalence.
//!
//! Feeds the same block of transactions through two independent state-transition
//! pipelines and asserts that the resulting state is bit-for-bit identical:
//!
//! - **Sequencer path** — mirrors `SequencerCore::build_block_from_mempool`:
//!   for each user transaction call `validate_on_state` and, on success, call
//!   `apply_state_diff`; skip rejected transactions.  Append the mandatory clock
//!   invocation last via `transition_from_public_transaction`.
//!
//! - **Replayer path** — mirrors `IndexerStore::put_block`:
//!   for each transaction that the sequencer accepted, call
//!   `transaction_stateless_check` followed by `execute_check_on_state`.
//!   Apply the clock invocation last via `transition_from_public_transaction`.
//!
//! Both pipelines start from the **same** fuzz-generated initial state and
//! process the **same** set of accepted transactions with the same block context
//! (block_id, timestamp).  Any difference in the resulting account states is a
//! consensus-breaking bug: a replaying node would derive a different state root
//! from the sequencer, which would invalidate all subsequent blocks.
//!
//! # Invariants
//!
//! 1. **SequencerReplayerEquivalence** — for every known account (genesis ∪
//!    accounts declared in any accepted transaction's diff), the sequencer state
//!    and the replayer state must agree on balance, nonce, data, and
//!    program_owner after applying the full block.
//!
//! 2. **ReplayerAcceptsAllSequencerTxs** — every transaction accepted by the
//!    sequencer (`validate_on_state` returned `Ok`) must also be accepted by the
//!    replayer (`execute_check_on_state` returned `Ok`).  A replayer rejection of
//!    a sequencer-accepted transaction is a validity-rule divergence bug.
//!
//! 3. **ClockConsistency** — the mandatory clock invocation appended at the end
//!    of every block must succeed on both paths and leave both states identical.

use std::collections::HashSet;

use arbitrary::{Arbitrary, Unstructured};
use common::transaction::{LeeTransaction, clock_invocation};
use fuzz_props::generators::{arb_fuzz_native_transfer, arbitrary_fuzz_state, arbitrary_transaction};

fuzz_props::fuzz_entry!(|data: &[u8]| {
    let mut u = Unstructured::new(data);

    // ── Initial state ─────────────────────────────────────────────────────────
    // Generate a fuzz-driven initial state so that state-dependent bugs
    // (e.g. zero balance, u128::MAX nonce) are reachable by the fuzzer.
    let fuzz_accs = match arbitrary_fuzz_state(&mut u) {
        Ok(accs) => accs,
        Err(_) => return,
    };
    let init_accs: Vec<(nssa::AccountId, u128)> = fuzz_accs
        .iter()
        .map(|a| (a.account_id, a.balance))
        .collect();

    // Both pipelines use the same block_id and timestamp, drawn from the fuzz corpus
    // so the fuzzer can explore clock-dependent and block-ID-dependent code paths.
    // The invariant is path-equivalence at every (block_id, timestamp); it does not
    // require either value to be constant.  If the protocol rejects block_id=0 or
    // timestamp=0 as structurally invalid, the existing clock-failure guard below
    // (lines ~130-133) will return early without panicking — no extra guard needed.
    let block_id: u64 = u64::arbitrary(&mut u).unwrap_or(2);
    let timestamp: u64 = u64::arbitrary(&mut u).unwrap_or(1_000);

    // Shared base state — cloned once for each pipeline.
    let base_state = fuzz_props::genesis::genesis_state(&init_accs, vec![]);

    // Track all account IDs touched by accepted transactions so we can compare
    // them across both pipelines after the full block is applied.
    let mut touched_ids: HashSet<nssa::AccountId> =
        init_accs.iter().map(|&(id, _)| id).collect();

    // ── Phase 1: Sequencer path ───────────────────────────────────────────────
    // Mirrors `SequencerCore::build_block_from_mempool`:
    //   for each mempool transaction: try validate_on_state; on success apply_state_diff.
    let mut seq_state = base_state.clone();

    // Accepted transaction list — populated here, consumed by the replayer phase
    // so that both pipelines process exactly the same set of transactions.
    let mut accepted_txs: Vec<LeeTransaction> = Vec::new();

    let n_txs: u8 = u8::arbitrary(&mut u).unwrap_or(0) % 8;

    for _ in 0..n_txs {
        // Mix correctly-signed fuzz transfers (likely to succeed) with
        // random structured transactions (likely to fail — stress the skip path).
        let tx_raw = if bool::arbitrary(&mut u).unwrap_or(false) {
            match arb_fuzz_native_transfer(&mut u, &fuzz_accs) {
                Ok(tx) => tx,
                Err(_) => break,
            }
        } else {
            match arbitrary_transaction(&mut u) {
                Ok(tx) => tx,
                Err(_) => break,
            }
        };

        // Stateless gate — both sequencer and replayer reject malformed transactions
        // before they ever touch state.
        let Ok(tx) = tx_raw.transaction_stateless_check() else {
            continue;
        };

        // Sequencer: validate_on_state borrows `tx` (does not consume it).
        let Ok(diff) = tx.validate_on_state(&seq_state, block_id, timestamp) else {
            // Sequencer skips failed transactions; they do not appear in the block.
            continue;
        };

        // Record the account IDs declared by this diff so they are included in
        // the invariant check after both pipelines finish.
        for acc_id in diff.public_diff().keys().copied() {
            touched_ids.insert(acc_id);
        }

        // Sequencer: apply_state_diff consumes the diff and mutates seq_state.
        seq_state.apply_state_diff(diff);

        // Save the accepted transaction for the replayer phase.
        accepted_txs.push(tx);
    }

    // Sequencer: append the mandatory clock invocation as the last transaction
    // in the block.  If the clock fails here (e.g. corrupted initial state),
    // the block cannot be produced — abort without a panic.
    let clock_tx = clock_invocation(timestamp);
    if seq_state
        .transition_from_public_transaction(&clock_tx, block_id, timestamp)
        .is_err()
    {
        return;
    }

    // ── Phase 2: Replayer path ────────────────────────────────────────────────
    // Mirrors `IndexerStore::put_block`:
    //   for each transaction in the block: stateless_check → execute_check_on_state.
    let mut rep_state = base_state.clone();

    for tx in &accepted_txs {
        // Replayer: stateless check.  This must succeed because the sequencer
        // already passed the same check above (deterministic, no state involved).
        let Ok(checked_tx) = tx.clone().transaction_stateless_check() else {
            // INVARIANT 2: sequencer accepted this tx but stateless check fails
            // on the replayer.  Stateless validity is deterministic — this is a bug.
            panic!(
                "INVARIANT VIOLATION [ReplayerAcceptsAllSequencerTxs]: \
                 transaction_stateless_check failed on the replayer for a \
                 sequencer-accepted transaction (stateless check is deterministic)"
            );
        };

        // Replayer: execute_check_on_state must succeed for every transaction
        // the sequencer accepted (INVARIANT 2).
        checked_tx
            .execute_check_on_state(&mut rep_state, block_id, timestamp)
            .unwrap_or_else(|e| {
                panic!(
                    "INVARIANT VIOLATION [ReplayerAcceptsAllSequencerTxs]: \
                     execute_check_on_state rejected a sequencer-accepted \
                     transaction on the replayer: {e:?}"
                )
            });
    }

    // Replayer: apply the same clock invocation (INVARIANT 3).
    rep_state
        .transition_from_public_transaction(&clock_tx, block_id, timestamp)
        .unwrap_or_else(|e| {
            panic!(
                "INVARIANT VIOLATION [ClockConsistency]: \
                 clock invocation succeeded on the sequencer state but failed \
                 on the replayer state: {e:?}"
            )
        });

    // ── Invariant 1: SequencerReplayerEquivalence ─────────────────────────────
    // Compare every known account (genesis ∪ diff-declared) across both states.
    // Any mismatch means the two pipelines derived a different state root —
    // a consensus-breaking bug.
    for acc_id in &touched_ids {
        let seq_acc = seq_state.get_account_by_id(*acc_id);
        let rep_acc = rep_state.get_account_by_id(*acc_id);

        assert_eq!(
            seq_acc.balance,
            rep_acc.balance,
            "INVARIANT VIOLATION [SequencerReplayerEquivalence]: balance diverges \
             for account {:?} — sequencer={} replayer={}",
            acc_id,
            seq_acc.balance,
            rep_acc.balance,
        );

        assert_eq!(
            seq_acc.nonce,
            rep_acc.nonce,
            "INVARIANT VIOLATION [SequencerReplayerEquivalence]: nonce diverges \
             for account {:?} — sequencer={:?} replayer={:?}",
            acc_id,
            seq_acc.nonce,
            rep_acc.nonce,
        );

        assert_eq!(
            seq_acc.data,
            rep_acc.data,
            "INVARIANT VIOLATION [SequencerReplayerEquivalence]: data field \
             diverges for account {:?}",
            acc_id,
        );

        assert_eq!(
            seq_acc.program_owner,
            rep_acc.program_owner,
            "INVARIANT VIOLATION [SequencerReplayerEquivalence]: program_owner \
             diverges for account {:?}",
            acc_id,
        );
    }
});
