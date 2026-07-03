#![cfg_attr(feature = "fuzzer-libfuzzer", no_main)]
//! Fuzz target: **model-based stateful lockstep** — the Rung-3 lever.
//!
//! Every other target in this repo fuzzes a *single* call, or applies a linear list of
//! transactions and checks aggregate invariants. None of them steps an **independent
//! reference model** in lockstep with the real state machine, asserting agreement after
//! *every* operation. That is the technique this target adds:
//!
//! 1. Decode the fuzz input into a `Vec<Command>` — an *operation grammar* (transfer /
//!    advance-block / replay), not raw bytes. Mutating this grammar is "higher-level
//!    mutation": the fuzzer explores *schedules* of domain operations.
//! 2. Maintain a tiny, self-contained [`Model`] of `(balance, nonce)` per account that
//!    reimplements native-transfer semantics **without** calling into `nssa`.
//! 3. After each command, apply it to both the real [`V03State`] and the model, then assert
//!    they agree on (a) whether the transaction was *accepted* and (b) the resulting
//!    per-account balances and nonces.
//!
//! A divergence is a real bug in exactly the class single-shot fuzzing cannot reach:
//! acceptance or state that depends on the *history* of operations (a replay that should
//! have been rejected, a nonce that drifts across a sequence, balance that leaks between
//! transactions).
//!
//! # Why the model is a *sound* oracle (no false positives)
//!
//! The model only claims to predict the outcome of native transfers **between two distinct,
//! fuzz-generated public accounts** — the exact shape [`arbitrary_fuzz_state`] produces.
//! For that shape the complete set of dynamic acceptance rules is small and fully modelled:
//!
//! * **Nonce** — the declared nonce must equal the signer's current nonce
//!   (`validated_state_diff.rs`: `current_nonce == *nonce`).
//! * **Sufficient balance** — the guest program does `balance.checked_sub(amount)`
//!   (`authenticated_transfer/src/main.rs`), so `amount > sender.balance` is rejected.
//! * **No recipient overflow** — `balance.checked_add(amount)`. Under the generator's
//!   `u128::MAX / 8` per-account cap this can never fire (total supply ≤ `u128::MAX`, so
//!   `recipient + amount ≤ total ≤ u128::MAX`), but the model encodes it for completeness.
//!
//! Everything else that could reject a transaction is held *constant* by construction and so
//! cannot cause the model to diverge from reality:
//!
//! * The signature is always valid — the account id is derived from the signing key
//!   (`FuzzAccount`), so the signer is authorized.
//! * Neither party is a reserved system account (faucet / bridge / clock) —
//!   [`arbitrary_fuzz_state`] excludes those ids, so the system-account guard never trips.
//! * The recipient is genesis-owned by the authenticated-transfer program, so it is never
//!   re-claimed; `program_owner` is invariant.
//! * **Self-transfers are excluded** — the recipient index is remapped to always differ from
//!   the sender (see `resolve_recipient`). A `from == to` transfer aliases one account in the
//!   diff and its post-balance depends on diff-merge internals we deliberately do not model;
//!   excluding it keeps the oracle sound. Self-transfers remain covered by
//!   `fuzz_multi_block_state_sequence` / `arb_fuzz_native_transfer`.
//!
//! Because those rules are fully modelled and everything else is constant, the model's
//! accept/reject prediction is *exact* for the transactions this target generates: a
//! disagreement is always a protocol bug, never a modelling gap.
//!
//! # Invariants asserted (after every command)
//!
//! * **ModelAcceptanceAgreement** — the real state machine accepts a transaction iff the
//!   reference model does. A real-accept / model-reject split is a double-spend, replay, or
//!   token-inflation bug; a real-reject / model-accept split is a spurious rejection
//!   (liveness bug).
//! * **ModelStateAgreement** — after applying the command, every fuzz account's balance and
//!   nonce in the real state equals the model. Catches drift that acceptance parity alone
//!   would miss (e.g. a transfer accepted by both but crediting the wrong amount).

use arbitrary::{Arbitrary, Unstructured};
use common::transaction::LeeTransaction;
use fuzz_props::generators::arbitrary_fuzz_state;
use nssa::AccountId;
use std::collections::HashMap;

/// How the declared nonce for a transfer is chosen. Biased toward `Correct` so the accept
/// path is reached often, with adversarial variants to drive the reject path.
#[derive(Arbitrary, Debug)]
enum NonceKind {
    /// The signer's current nonce in the model — should be accepted.
    Correct,
    /// `current + delta` (delta ≥ 1) — a stale/future nonce, should be rejected.
    Off(u8),
    /// A fully arbitrary nonce — usually rejected.
    Raw(u128),
}

/// How the transfer amount is chosen, relative to the sender's modelled balance.
#[derive(Arbitrary, Debug)]
enum AmountKind {
    /// Zero — accepted, a no-op on balances.
    Zero,
    /// `raw % (balance + 1)` — always within balance, should be accepted.
    WithinBalance(u128),
    /// Exactly the whole balance — accepted, drains the sender.
    All,
    /// Strictly greater than the balance — should be rejected (insufficient funds).
    Excessive(u128),
    /// A fully arbitrary amount — accepted only if it happens to fit.
    Raw(u128),
}

/// One step in the generated schedule.
#[derive(Arbitrary, Debug)]
enum Command {
    /// Transfer native balance between two distinct fuzz accounts.
    Transfer {
        from: u8,
        to: u8,
        nonce: NonceKind,
        amount: AmountKind,
    },
    /// Advance the block id / timestamp without applying a transaction. Exercises schedules
    /// where block progression is decoupled from transaction count; must not perturb state.
    AdvanceBlock(u8),
    /// Re-submit the most recently accepted transaction. The model predicts rejection (its
    /// nonce is already consumed); a real acceptance is a replay/double-spend.
    ReplayLast,
}

/// Independent reference model: `account_id -> (balance, nonce)` for the fuzz accounts only.
/// Reimplements native-transfer semantics with zero dependence on `nssa`.
struct Model {
    accounts: HashMap<AccountId, (u128, u128)>,
}

/// The model's prediction for a transfer.
enum Predict {
    /// Rejected — no state change.
    Reject,
    /// Accepted — `from` debited by `amount`, `to` credited, `from` nonce incremented.
    Accept { amount: u128 },
}

impl Model {
    fn new(accounts: &[(AccountId, u128)]) -> Self {
        Self {
            accounts: accounts.iter().map(|&(id, bal)| (id, (bal, 0))).collect(),
        }
    }

    fn balance(&self, id: AccountId) -> u128 {
        self.accounts.get(&id).map_or(0, |&(b, _)| b)
    }

    fn nonce(&self, id: AccountId) -> u128 {
        self.accounts.get(&id).map_or(0, |&(_, n)| n)
    }

    /// Predict whether a transfer `from -> to` of `amount` declaring `declared_nonce` is
    /// accepted. `from != to` is a precondition (self-transfers are excluded upstream).
    fn predict(&self, from: AccountId, to: AccountId, declared_nonce: u128, amount: u128) -> Predict {
        if declared_nonce != self.nonce(from) {
            return Predict::Reject; // nonce mismatch
        }
        if amount > self.balance(from) {
            return Predict::Reject; // insufficient balance (checked_sub fails)
        }
        if self.balance(to).checked_add(amount).is_none() {
            return Predict::Reject; // recipient overflow (checked_add fails)
        }
        Predict::Accept { amount }
    }

    /// Commit an accepted transfer to the model.
    fn apply_transfer(&mut self, from: AccountId, to: AccountId, amount: u128) {
        let (from_bal, from_nonce) = self.accounts[&from];
        let (to_bal, to_nonce) = self.accounts[&to];
        self.accounts.insert(from, (from_bal - amount, from_nonce + 1));
        self.accounts.insert(to, (to_bal + amount, to_nonce));
    }
}

/// Map a raw `to` index to an account distinct from `from`. With `len >= 2` accounts, picks
/// among the `len - 1` accounts other than `from`, so a self-transfer is impossible.
fn resolve_recipient(raw: u8, from_idx: usize, len: usize) -> usize {
    let offset = 1 + (raw as usize) % (len - 1); // 1..=len-1
    (from_idx + offset) % len
}

/// Resolve `NonceKind` against the model's current view of the signer.
fn resolve_nonce(kind: &NonceKind, current: u128) -> u128 {
    match *kind {
        NonceKind::Correct => current,
        NonceKind::Off(d) => current.wrapping_add(u128::from(d).max(1)),
        NonceKind::Raw(n) => n,
    }
}

/// Resolve `AmountKind` against the sender's modelled balance.
fn resolve_amount(kind: &AmountKind, balance: u128) -> u128 {
    match *kind {
        AmountKind::Zero => 0,
        AmountKind::WithinBalance(raw) => raw % balance.saturating_add(1),
        AmountKind::All => balance,
        AmountKind::Excessive(raw) => balance.saturating_add(1).saturating_add(raw % 1024),
        AmountKind::Raw(n) => n,
    }
}

/// Assert the real state agrees with the model on every fuzz account.
fn assert_state_agreement(state: &nssa::V03State, model: &Model, step: usize, what: &str) {
    for (&id, &(model_bal, model_nonce)) in &model.accounts {
        let acc = state.get_account_by_id(id);
        assert_eq!(
            acc.balance, model_bal,
            "INVARIANT VIOLATION [ModelStateAgreement]: balance diverged from reference model \
             at step {step} after {what} for account {id:?} — real={}, model={model_bal}",
            acc.balance,
        );
        assert_eq!(
            acc.nonce.0, model_nonce,
            "INVARIANT VIOLATION [ModelStateAgreement]: nonce diverged from reference model \
             at step {step} after {what} for account {id:?} — real={}, model={model_nonce}",
            acc.nonce.0,
        );
    }
}

fuzz_props::fuzz_entry!(|data: &[u8]| {
    let mut u = Unstructured::new(data);

    // Need at least two distinct accounts so every transfer is cross-account.
    let fuzz_accs = match arbitrary_fuzz_state(&mut u) {
        Ok(accs) if accs.len() >= 2 => accs,
        _ => return,
    };
    let init_accs: Vec<(AccountId, u128)> = fuzz_accs.iter().map(|a| (a.account_id, a.balance)).collect();

    let mut state = fuzz_props::genesis::genesis_state(&init_accs, vec![]);
    let mut model = Model::new(&init_accs);

    // Monotonic clock — both the protocol and replay-rejection want strictly increasing ids.
    let mut block_id: u64 = 1;
    let mut timestamp: u64 = 0;

    // The most recently accepted transaction, kept for ReplayLast.
    let mut last_applied: Option<LeeTransaction> = None;

    // Bounded schedule length keeps individual corpus entries small and fast.
    let n_cmds: u8 = u8::arbitrary(&mut u).unwrap_or(0) % 32;

    for step in 0..usize::from(n_cmds) {
        let Ok(cmd) = Command::arbitrary(&mut u) else { break };

        match cmd {
            Command::AdvanceBlock(jump) => {
                block_id += 1 + u64::from(jump);
                timestamp += 1000 * (1 + u64::from(jump));
                // No transaction applied — state must be untouched, model unchanged.
                assert_state_agreement(&state, &model, step, "AdvanceBlock");
            }

            Command::ReplayLast => {
                let Some(tx) = last_applied.clone() else {
                    // Nothing to replay yet.
                    continue;
                };
                let accepted = tx.execute_check_on_state(&mut state, block_id, timestamp).is_ok();
                assert!(
                    !accepted,
                    "INVARIANT VIOLATION [ModelAcceptanceAgreement]: the state machine accepted a \
                     replay of an already-applied transaction at step {step} (block_id={block_id}) \
                     — its nonce was consumed, so the reference model rejects it. This is a \
                     replay / double-spend.",
                );
                block_id += 1;
                timestamp += 1000;
                assert_state_agreement(&state, &model, step, "ReplayLast");
            }

            Command::Transfer { from, to, nonce, amount } => {
                let len = fuzz_accs.len();
                let from_idx = (from as usize) % len;
                let to_idx = resolve_recipient(to, from_idx, len);
                let from_acc = &fuzz_accs[from_idx];
                let to_id = fuzz_accs[to_idx].account_id;
                let from_id = from_acc.account_id;

                let declared_nonce = resolve_nonce(&nonce, model.nonce(from_id));
                let amount = resolve_amount(&amount, model.balance(from_id));

                let tx = common::test_utils::create_transaction_native_token_transfer(
                    from_id,
                    declared_nonce,
                    to_id,
                    amount,
                    &from_acc.private_key,
                );

                let prediction = model.predict(from_id, to_id, declared_nonce, amount);
                let result = tx.execute_check_on_state(&mut state, block_id, timestamp);
                let real_accepted = result.is_ok();

                match prediction {
                    Predict::Accept { amount } => {
                        assert!(
                            real_accepted,
                            "INVARIANT VIOLATION [ModelAcceptanceAgreement]: the reference model \
                             accepts this transfer but the state machine REJECTED it at step {step} \
                             (from={from_id:?} to={to_id:?} nonce={declared_nonce} amount={amount}) \
                             — spurious rejection / liveness bug.",
                        );
                        model.apply_transfer(from_id, to_id, amount);
                    }
                    Predict::Reject => {
                        assert!(
                            !real_accepted,
                            "INVARIANT VIOLATION [ModelAcceptanceAgreement]: the state machine \
                             ACCEPTED a transfer the reference model rejects at step {step} \
                             (from={from_id:?} to={to_id:?} nonce={declared_nonce} amount={amount}) \
                             — double-spend, bad-nonce acceptance, or token-inflation bug.",
                        );
                    }
                }

                if let Ok(applied) = result {
                    last_applied = Some(applied);
                }

                block_id += 1;
                timestamp += 1000;
                assert_state_agreement(&state, &model, step, "Transfer");
            }
        }
    }
});
