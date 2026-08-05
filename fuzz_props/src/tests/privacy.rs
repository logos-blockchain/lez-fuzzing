use arbitrary::Unstructured;

use crate::generators::{FuzzAccount, account_id_for_key};
use crate::privacy::{
    arb_account, arb_conflicting_nullifier_pair, arb_privacy_preserving_tx, arb_validity_window,
    synthesize_passing_proof,
};
use nssa::privacy_preserving_transaction::{Message as PPMessage, WitnessSet as PPWitnessSet};
use nssa::{AccountId, PrivacyPreservingTransaction, PrivateKey, V03State};
use nssa_core::account::Account;
use nssa_core::encryption::Ciphertext;
use nssa_core::program::{BlockValidityWindow, TimestampValidityWindow};
use nssa_core::{Commitment, EncryptedAccountData, EphemeralPublicKey, Nullifier, PrivateAction};

/// A structurally-valid [`PrivateAction`] whose nullifier digest is the live commitment-set
/// root of `state` (a member of `root_history` from genesis onwards, since the protocol seeds
/// the history with its dummy commitment) — so checks 5 and 6 both pass on a fresh state.
fn valid_private_action(state: &V03State, seed: u8) -> PrivateAction {
    let aid = AccountId::new([seed; 32]);
    PrivateAction {
        nullifier: Nullifier::for_account_initialization(&aid),
        root: state.commitment_set_digest(),
        commitment: Commitment::new(&aid, &Account::default()),
        encrypted_post_state: EncryptedAccountData {
            ciphertext: Ciphertext::from_inner(vec![]),
            epk: EphemeralPublicKey(vec![]),
            view_tag: 0,
        },
    }
}

/// `synthesize_passing_proof` must drive the executor *past* proof verification (check 4)
/// into checks 5–6 and `apply_state_diff`. If the reconstructed journal were even one
/// byte off, `is_valid_for` would return `false` and the executor would stop at check 4 —
/// silently degrading Path B back to Path A.5. This test fails loudly in that case.
///
/// Fake-receipt verification is a pass-through only under `RISC0_DEV_MODE`; the test is a
/// no-op when the variable is unset (e.g. a bare `cargo test`). `just fuzz-props` exports
/// it, as does running with `RISC0_DEV_MODE=1 cargo test`.
#[test]
fn synthesized_proof_reaches_checks_5_6_and_applies() {
    let dev_mode = std::env::var("RISC0_DEV_MODE").is_ok_and(|v| v == "1" || v == "true");
    if !dev_mode {
        return;
    }

    let mut state = crate::genesis::genesis_state(&[], vec![]);

    // No signers and a single valid private action (fresh commitment, nullifier bound to the
    // live root): checks 1–3 are vacuous/trivially met and checks 5–6 pass, so the only way
    // to reach the successful apply is for the synthesised proof to pass check 4.
    let action = valid_private_action(&state, 7);
    let commitment = action.commitment;
    let message = PPMessage {
        public_actions: vec![],
        nonces: vec![],
        private_actions: vec![action],
        block_validity_window: BlockValidityWindow::new_unbounded(),
        timestamp_validity_window: TimestampValidityWindow::new_unbounded(),
    };

    let proof = synthesize_passing_proof(&message, &state, &[]);
    let witness_set = PPWitnessSet::for_message(&message, proof, &[]);
    let tx = PrivacyPreservingTransaction::new(message, witness_set);

    state
        .transition_from_privacy_preserving_transaction(&tx, 1, 0)
        .expect(
            "a synthesised passing proof must drive the executor to success (checks 5-6 + apply)",
        );

    // Check 5 reached and applied: the commitment is now a member of the set.
    assert!(
        state.get_proof_for_commitment(&commitment).is_some(),
        "accepted commitment must be inserted into the commitment set",
    );

    // Replaying the same transaction must now be rejected (commitment already seen).
    assert!(
        state
            .transition_from_privacy_preserving_transaction(&tx, 2, 1)
            .is_err(),
        "replayed transaction must be rejected after its commitment was inserted",
    );
}

/// Negative counterpart to the test above: the synthesised `FakeReceipt` is a forgery that
/// must pass **only** under `RISC0_DEV_MODE`. With dev mode off, `Receipt::verify` runs the
/// real integrity check, the fake fails it, and the executor must reject the transaction at
/// check 4 — never reaching checks 5–6 or `apply_state_diff`.
///
/// This locks the dev-mode boundary in CI: it asserts the forgery is genuinely inert in a
/// production-mode verifier, so `synthesize_passing_proof` can never be mistaken for a
/// real-proof generator. It is the mirror of `synthesized_proof_reaches_checks_5_6_and_applies`
/// — exactly one of the two runs in any given environment (a bare `cargo test` runs this one;
/// `RISC0_DEV_MODE=1 cargo test` runs the other), so both directions are covered across CI.
#[test]
fn synthesized_proof_is_rejected_without_dev_mode() {
    let dev_mode = std::env::var("RISC0_DEV_MODE").is_ok_and(|v| v == "1" || v == "true");
    if dev_mode {
        return;
    }

    let mut state = crate::genesis::genesis_state(&[], vec![]);

    // Same well-formed message as the positive test: checks 1–3 are vacuous/trivially met and
    // checks 5–6 would pass, so a rejection can only come from check 4 (proof verification)
    // failing on the fake receipt.
    let action = valid_private_action(&state, 7);
    let commitment = action.commitment;
    let message = PPMessage {
        public_actions: vec![],
        nonces: vec![],
        private_actions: vec![action],
        block_validity_window: BlockValidityWindow::new_unbounded(),
        timestamp_validity_window: TimestampValidityWindow::new_unbounded(),
    };

    let proof = synthesize_passing_proof(&message, &state, &[]);
    let witness_set = PPWitnessSet::for_message(&message, proof, &[]);
    let tx = PrivacyPreservingTransaction::new(message, witness_set);

    assert!(
        state
            .transition_from_privacy_preserving_transaction(&tx, 1, 0)
            .is_err(),
        "a synthesised fake receipt must be rejected at check 4 when RISC0_DEV_MODE is off - \
         the forgery must never verify in a production-mode verifier",
    );

    // The rejection must also leave private state untouched (no commitment inserted).
    assert!(
        state.get_proof_for_commitment(&commitment).is_none(),
        "a rejected transaction must not insert its commitment into the set",
    );
}

// ─────────────────────────────────────────────────────────────────────────────
//  Generator contract tests
//
//  The `arb_*` helpers in `privacy.rs` shape the fuzz input. Their bounding
//  arithmetic, dedup guards, and branch conditions decide the *shape* of every
//  generated transaction — how many signers/commitments/nullifiers it carries,
//  which accounts it touches, whether its proof is a passing one or garbage — but
//  none of that is visible in the encoded bytes, so the encoding/executor tests
//  cannot observe it. The tests below assert those shape guarantees directly.
// ─────────────────────────────────────────────────────────────────────────────

/// Tiny deterministic xorshift64 PRNG so the distributional generator test below
/// is reproducible (no `rand`, no clock seeding) yet samples a wide spread of inputs.
struct Rng(u64);

impl Rng {
    const fn new() -> Self {
        Self(0x9E37_79B9_7F4A_7C15)
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13_u32;
        x ^= x >> 7_u32;
        x ^= x << 17_u32;
        self.0 = x;
        x
    }

    fn fill(&mut self, buf: &mut [u8]) {
        for chunk in buf.chunks_mut(8) {
            let bytes = self.next_u64().to_le_bytes();
            for (dst, src) in chunk.iter_mut().zip(bytes.iter()) {
                *dst = *src;
            }
        }
    }
}

/// `arb_account` caps the nonce at `u128 % 1024` to keep a forced-pass post-state
/// from driving a signer's nonce to `u128::MAX` (and tripping the protocol's
/// overflow panic on the subsequent increment). The cap must hold for every
/// generated account regardless of the fuzz bytes.
#[test]
fn arb_account_nonce_capped_below_1024() {
    let buf = vec![0xAB_u8; 1024];
    let mut u = Unstructured::new(&buf);
    for _ in 0_u32..8 {
        let acc = arb_account(&mut u).expect("arb_account never errors on fill_buffer primitives");
        assert!(
            acc.nonce.0 < 1024,
            "nonce {} must stay within the [0, 1024) cap for any input",
            acc.nonce.0
        );
    }
}

/// Each of `arb_account`'s three explicit fields must be sourced from the fuzz
/// bytes, not left at `Account::default()` — deleting any field assignment leaves
/// the corresponding field at its (zero) default.
#[test]
fn arb_account_fields_are_populated_from_fuzz_bytes() {
    let buf = vec![0xAB_u8; 256];
    let mut u = Unstructured::new(&buf);
    let acc = arb_account(&mut u).expect("arb_account never errors on fill_buffer primitives");
    let default = Account::default();

    assert_ne!(
        acc.program_owner, default.program_owner,
        "program_owner must be drawn from the fuzz bytes, not left at its default"
    );
    assert_ne!(
        acc.balance, default.balance,
        "balance must be drawn from the fuzz bytes, not left at its default"
    );
    assert_ne!(
        acc.nonce, default.nonce,
        "nonce must be drawn from the fuzz bytes, not left at its default"
    );
}

/// `arb_validity_window` leaves the window unbounded for ~3 of every 4 selector
/// bytes (`u8 % 4 != 0`) so the success path stays frequently reachable. A selector
/// of `1` satisfies `1 % 4 != 0`, so the window must come back fully unbounded —
/// the function returns before it ever reads the follow-on bound bytes.
#[test]
fn arb_validity_window_selector_nonzero_is_unbounded() {
    // [selector=1, from_bool=1, from_val=2, to_bool=1, to_val=5]
    let buf = vec![1_u8, 1, 2, 1, 5];
    let mut u = Unstructured::new(&buf);
    let w = arb_validity_window(&mut u).expect("arb_validity_window never errors");
    assert_eq!(
        w.start(),
        None,
        "selector 1 (1 % 4 != 0) must yield an unbounded window"
    );
    assert_eq!(w.end(), None, "selector 1 must yield an unbounded window");
}

/// The remaining ~1 in 4 selectors (`u8 % 4 == 0`) take the bounded path, where the
/// follow-on bytes set actual `[from, to)` bounds. A selector of `0` must therefore
/// produce a window with at least one finite bound.
#[test]
fn arb_validity_window_selector_zero_is_bounded() {
    // [selector=0, from_bool=1, from_val=2, to_bool=1, to_val=5]
    let buf = vec![0_u8, 1, 2, 1, 5];
    let mut u = Unstructured::new(&buf);
    let w = arb_validity_window(&mut u).expect("arb_validity_window never errors");
    assert!(
        w.start().is_some() || w.end().is_some(),
        "selector 0 (0 % 4 == 0) must yield a bounded window"
    );
}

/// On the bounded path both bounds are kept in `0..8` via `u8 % 8` so they straddle
/// the harness's block/timestamp range. With `from_val = 8` (→ `8 % 8 = 0`) and
/// `to_val = 5` (→ `5`) the resulting window must be exactly `[0, 5)`.
#[test]
fn arb_validity_window_bounds_use_modulo_8() {
    // [selector=0, from_bool=1, from_val=8, to_bool=1, to_val=5] → window [0, 5)
    let buf = vec![0_u8, 1, 8, 1, 5];
    let mut u = Unstructured::new(&buf);
    let w = arb_validity_window(&mut u).expect("arb_validity_window never errors");
    assert_eq!(w.start(), Some(0_u64), "from must be 8 % 8 = 0");
    assert_eq!(w.end(), Some(5_u64), "to must be 5 % 8 = 5");
}

/// Drive `arb_privacy_preserving_tx` over many pseudo-random inputs and assert the
/// structural guarantees of the transactions it builds: the bounded counts, the
/// in-range account indexing, the deduplicated/non-empty field sets, and the
/// passing-vs-garbage proof mix. Six distinct keyed accounts give the signer count
/// headroom above its cap of 3 (so any over-counting shows up) and provide several
/// valid indices (so off-by-one indexing would read past the slice and panic).
///
/// Two flavours of check run here: per-iteration upper bounds that must hold for
/// *every* generated transaction, and end-of-run reachability checks that confirm
/// the interesting shapes actually occur across the sampled inputs.
/// Which branches of the extra-id `if !accounts.is_empty() && bool::arbitrary(u)?` were
/// observable across a transaction's non-signer "extra" public-account ids.
#[derive(Default)]
struct ExtraKinds {
    /// At least one extra (non-signer id) was appended at all.
    any: bool,
    /// An extra equal to a *known* fuzz-account id (the `&&`-true branch).
    known: bool,
    /// An extra that is a *random* id (the `else` branch).
    random: bool,
}

/// Classify a message's extras. A signer's public-account id is key-derived and independent
/// of `FuzzAccount.account_id`, so any non-signer id present in the public-action list was
/// appended by the extra-id `if`; a *known* id can only come from its `&&`-true branch.
fn classify_extras(
    public_account_ids: &[AccountId],
    signer_ids: &[AccountId],
    known_ids: &std::collections::HashSet<AccountId>,
) -> ExtraKinds {
    let mut kinds = ExtraKinds::default();
    for id in public_account_ids {
        if signer_ids.contains(id) {
            continue;
        }
        kinds.any = true;
        if known_ids.contains(id) {
            kinds.known = true;
        } else {
            kinds.random = true;
        }
    }
    kinds
}

#[test]
fn arb_privacy_preserving_tx_generator_invariants() {
    let accounts: Vec<FuzzAccount> = (1..=6_u8)
        .map(|i| FuzzAccount {
            account_id: AccountId::new([i; 32]),
            balance: 1_000_000,
            private_key: PrivateKey::try_new([i; 32]).expect("nonzero scalar is a valid key"),
        })
        .collect();
    let genesis: Vec<(AccountId, u128)> =
        accounts.iter().map(|a| (a.account_id, a.balance)).collect();
    let state = crate::genesis::genesis_state(&genesis, vec![]);

    let known_ids: std::collections::HashSet<AccountId> =
        accounts.iter().map(|a| a.account_id).collect();

    let mut rng = Rng::new();
    let mut buf = vec![0_u8; 8192];

    let mut oks = 0_usize;
    let mut max_signers = 0_usize;
    let mut saw_signer = false;
    let mut saw_extra = false;
    let mut saw_known_extra = false;
    let mut saw_random_extra = false;
    let mut max_private_actions = 0_usize;
    let mut garbage = 0_usize;
    let mut saw_garbage = false;

    for _ in 0..2000_usize {
        rng.fill(&mut buf);
        let mut u = Unstructured::new(&buf);
        // Never returns Err: every leaf is a `fill_buffer`-backed primitive that
        // zero-pads rather than failing. (Indexing an account slice out of range
        // would instead panic — also a failure this test would surface.)
        let tx = arb_privacy_preserving_tx(&mut u, &state, &accounts)
            .expect("generator never returns Err for fill_buffer-backed primitives");
        oks += 1;
        let msg = tx.message();

        let signer_ids: Vec<AccountId> = tx
            .witness_set()
            .signatures_and_public_keys()
            .iter()
            .map(|(_, pk)| AccountId::from(pk))
            .collect();
        let n_signers = signer_ids.len();
        max_signers = max_signers.max(n_signers);
        saw_signer |= n_signers >= 1;

        // ── per-transaction upper bounds ──
        // The signer count is drawn modulo `max_signers + 1`, so it can never exceed
        // the cap of 3 distinct signers.
        assert!(n_signers <= 3, "n_signers {n_signers} exceeds the cap of 3");
        // At most 3 signers plus at most 3 extra ids (both deduplicated).
        assert!(
            msg.public_actions.len() <= 6,
            "public_actions {} exceeds signers (<=3) + extras (<=3)",
            msg.public_actions.len()
        );
        // The account ids across public actions must be unique (validator check 2).
        let public_account_ids = msg.public_account_ids();
        let unique_ids: std::collections::HashSet<&AccountId> = public_account_ids.iter().collect();
        assert_eq!(
            unique_ids.len(),
            public_account_ids.len(),
            "public action account ids must be deduplicated"
        );
        // `private_actions` count is drawn modulo 4 (0..=3), with a non-empty fallback.
        assert!(
            (1..=3).contains(&msg.private_actions.len()),
            "private_actions {} outside the expected 1..=3 range",
            msg.private_actions.len()
        );
        // Nullifiers and commitments across private actions must be unique (validator
        // check 2).
        let nullifiers = msg.nullifiers();
        let unique_nullifiers: std::collections::HashSet<_> =
            nullifiers.iter().map(|(n, _)| *n).collect();
        assert_eq!(
            unique_nullifiers.len(),
            nullifiers.len(),
            "private-action nullifiers must be deduplicated"
        );
        let commitments = msg.commitments();
        let unique_commitments: std::collections::HashSet<_> = commitments.iter().collect();
        assert_eq!(
            unique_commitments.len(),
            commitments.len(),
            "private-action commitments must be deduplicated"
        );

        // Classify the non-signer "extras" by which branch of the extra-id `if` produced
        // them — a *known* fuzz-account id, a *random* id, or both.
        let extras = classify_extras(&public_account_ids, &signer_ids, &known_ids);
        saw_extra |= extras.any;
        saw_known_extra |= extras.known;
        saw_random_extra |= extras.random;

        max_private_actions = max_private_actions.max(msg.private_actions.len());

        // Which proof branch ran? A synthesized passing proof is a deterministic
        // function of (message, state, signers); re-synthesizing reproduces it
        // byte-for-byte, so anything else is the garbage-bytes branch.
        let synth = synthesize_passing_proof(msg, &state, &signer_ids);
        if tx.witness_set().proof() == &synth {
            // synthesized passing proof
        } else {
            garbage += 1;
            saw_garbage = true;
        }
    }

    assert!(
        oks > 1000,
        "expected many successful generations, got {oks}"
    );

    // ── reachability across the sampled inputs ──
    // With accounts present, transactions must sometimes carry signers.
    assert!(saw_signer, "no transaction ever carried a signer");
    // The full signer range up to the cap of 3 distinct signers must be reachable.
    assert_eq!(
        max_signers, 3,
        "the generator never reached 3 distinct signers"
    );
    // Extra public account ids must actually get appended.
    assert!(
        saw_extra,
        "the generator never appended an extra public account id"
    );
    // Both branches `if !accounts.is_empty() && bool::arbitrary(u)?` must be
    // reachable. The known-account branch must fire (else `delete !` — which short-circuits to
    // the random branch when accounts are present — would be indistinguishable)
    assert!(
        saw_known_extra,
        "the generator never appended a *known* fuzz-account id as an extra"
    );
    // …and the random branch must fire (else `&&`→`||` — which short-circuits to the known
    // branch when accounts are present — would be indistinguishable).
    assert!(
        saw_random_extra,
        "the generator never appended a *random* id as an extra"
    );
    // Multiple distinct private actions must be reachable (the dedup must keep, not drop).
    assert!(
        max_private_actions >= 2,
        "the generator never produced >= 2 private actions"
    );
    // The garbage-proof branch (~1 in 8) must be reachable at all.
    assert!(saw_garbage, "the generator never produced a garbage proof");
    // The garbage-proof rate must sit near the intended 1/8. Integer bands avoid float
    // arithmetic: it must fall within [1/16, 1/4].
    assert!(
        garbage * 4 <= oks,
        "garbage-proof rate {garbage}/{oks} is above 1/4 (expected ~1/8)"
    );
    assert!(
        garbage * 16 >= oks,
        "garbage-proof rate {garbage}/{oks} is below 1/16 (expected ~1/8)"
    );
}

// ── arb_conflicting_nullifier_pair ──────────────────────────────────────────────────────
// The pair builder underpins `fuzz_transaction_ordering_independence`: it must always yield
// two transactions that use *distinct* signers (so a rejection of the second application is
// attributable to the shared nullifier, not a nonce clash) and index only within the account
// set. These tests pin the account-count guard, the collision-repair branch, and the modular
// index arithmetic.

/// `n` distinct keyed fuzz accounts (`[1; 32]`, `[2; 32]`, …). Distinct nonzero scalars give
/// distinct keys and therefore distinct key-derived signer ids.
fn keyed_accounts(n: u8) -> Vec<FuzzAccount> {
    (1..=n)
        .map(|i| FuzzAccount {
            account_id: AccountId::new([i; 32]),
            balance: 1_000_000,
            private_key: PrivateKey::try_new([i; 32]).expect("nonzero scalar is a valid key"),
        })
        .collect()
}

/// The key-derived signer ids the validator would recover from a transaction's witness set.
fn signer_ids(tx: &PrivacyPreservingTransaction) -> Vec<AccountId> {
    tx.witness_set()
        .signatures_and_public_keys()
        .iter()
        .map(|(_, pk)| AccountId::from(pk))
        .collect()
}

/// The builder needs two distinct accounts: fewer than two is always rejected (before any
/// index arithmetic runs), exactly two always succeeds. This pins the `accounts.len() < 2`
/// guard against `==` / `>` / `<=` mutations.
#[test]
fn arb_conflicting_nullifier_pair_requires_two_accounts() {
    let accounts = keyed_accounts(2);
    let genesis: Vec<(AccountId, u128)> =
        accounts.iter().map(|a| (a.account_id, a.balance)).collect();
    let state = crate::genesis::genesis_state(&genesis, vec![]);

    let mut rng = Rng::new();
    let mut buf = vec![0_u8; 512];
    rng.fill(&mut buf);

    // Zero accounts: rejected by the guard. A guard mutated to `== 2` / `> 2` would fall
    // through and divide by `accounts.len() == 0`, panicking — also a failure this catches.
    let mut u0 = Unstructured::new(&buf);
    assert!(
        arb_conflicting_nullifier_pair(&mut u0, &state, &[]).is_err(),
        "an empty account set must be rejected"
    );
    // One account: still rejected — there is no room for two distinct signers.
    let mut u1 = Unstructured::new(&buf);
    assert!(
        arb_conflicting_nullifier_pair(&mut u1, &state, &accounts[..1]).is_err(),
        "a single-account set must be rejected"
    );
    // Two accounts: must succeed. A guard mutated to `== 2` / `<= 2` would reject this.
    let mut u2 = Unstructured::new(&buf);
    assert!(
        arb_conflicting_nullifier_pair(&mut u2, &state, &accounts).is_ok(),
        "two distinct accounts must yield a pair"
    );
}

/// When both index bytes select the same account (`i == j`), the repair branch
/// `j = (i + 1) % len` must pick the *other* account so the pair keeps distinct signers.
/// Forcing `i == j == 0` over two accounts exercises that branch: the only correct outcome is
/// signers `{account 0, account 1}`. This pins the `j == i` test, the `(i + 1) % len` repair,
/// and the two distinctness guards (`== 2` mutations of them all reject this otherwise-valid
/// input, and the arithmetic mutations either repair to `j == i` again or index out of range).
#[test]
fn arb_conflicting_nullifier_pair_repairs_colliding_indices() {
    let accounts = keyed_accounts(2);
    let genesis: Vec<(AccountId, u128)> =
        accounts.iter().map(|a| (a.account_id, a.balance)).collect();
    let state = crate::genesis::genesis_state(&genesis, vec![]);

    let mut rng = Rng::new();
    let mut buf = vec![0_u8; 512];
    rng.fill(&mut buf);
    // The first two bytes are the `i` and `j` index draws; zero both so `i == j == 0`.
    buf[0] = 0;
    buf[1] = 0;

    let mut u = Unstructured::new(&buf);
    let (tx_b, tx_c) = arb_conflicting_nullifier_pair(&mut u, &state, &accounts)
        .expect("colliding indices must be repaired into two distinct signers, not rejected");

    let sb = signer_ids(&tx_b);
    let sc = signer_ids(&tx_c);
    assert_eq!(sb.len(), 1, "tx_b must carry exactly one signer");
    assert_eq!(sc.len(), 1, "tx_c must carry exactly one signer");
    assert_ne!(
        sb[0], sc[0],
        "a conflicting pair must use two distinct signers"
    );

    let known: std::collections::HashSet<AccountId> = accounts
        .iter()
        .map(|a| account_id_for_key(&a.private_key))
        .collect();
    assert!(
        known.contains(&sb[0]) && known.contains(&sc[0]),
        "both signers must be drawn from the account set"
    );
}

/// Over many random inputs the index arithmetic must stay within the account slice. A `% len`
/// mutated to `/ len` or `+ len` computes an out-of-range index and panics on `accounts[i]`;
/// the modulo keeps every draw in range and the two signers distinct.
#[test]
fn arb_conflicting_nullifier_pair_indexes_in_range() {
    let accounts = keyed_accounts(2);
    let genesis: Vec<(AccountId, u128)> =
        accounts.iter().map(|a| (a.account_id, a.balance)).collect();
    let state = crate::genesis::genesis_state(&genesis, vec![]);
    let known: std::collections::HashSet<AccountId> = accounts
        .iter()
        .map(|a| account_id_for_key(&a.private_key))
        .collect();

    let mut rng = Rng::new();
    let mut buf = vec![0_u8; 512];
    for _ in 0..500_usize {
        rng.fill(&mut buf);
        let mut u = Unstructured::new(&buf);
        let (tx_b, tx_c) = arb_conflicting_nullifier_pair(&mut u, &state, &accounts)
            .expect("two distinct accounts always yield a pair");
        let sb = signer_ids(&tx_b);
        let sc = signer_ids(&tx_c);
        assert_ne!(sb[0], sc[0], "conflicting-pair signers must be distinct");
        assert!(
            known.contains(&sb[0]) && known.contains(&sc[0]),
            "signers must be drawn from the account set"
        );
    }
}
