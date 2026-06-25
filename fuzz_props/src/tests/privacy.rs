use arbitrary::Unstructured;

use crate::generators::FuzzAccount;
use crate::privacy::{
    arb_account, arb_privacy_preserving_tx, arb_validity_window, synthesize_passing_proof,
};
use nssa::privacy_preserving_transaction::{Message as PPMessage, WitnessSet as PPWitnessSet};
use nssa::{AccountId, PrivacyPreservingTransaction, PrivateKey};
use nssa_core::Commitment;
use nssa_core::account::Account;
use nssa_core::program::{BlockValidityWindow, TimestampValidityWindow};

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

    // No signers and a single fresh commitment: checks 1–3 are vacuous/trivially met, so
    // the only way to reach checks 5–6 is for the synthesised proof to pass check 4.
    let aid = AccountId::new([7_u8; 32]);
    let commitment = Commitment::new(&aid, &Account::default());
    let message = PPMessage {
        public_account_ids: vec![],
        nonces: vec![],
        public_post_states: vec![],
        encrypted_private_post_states: vec![],
        new_commitments: vec![commitment.clone()],
        new_nullifiers: vec![],
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

    // Same well-formed message as the positive test: checks 1–3 are vacuous/trivially met, so a
    // rejection can only come from check 4 (proof verification) failing on the fake receipt.
    let aid = AccountId::new([7_u8; 32]);
    let commitment = Commitment::new(&aid, &Account::default());
    let message = PPMessage {
        public_account_ids: vec![],
        nonces: vec![],
        public_post_states: vec![],
        encrypted_private_post_states: vec![],
        new_commitments: vec![commitment.clone()],
        new_nullifiers: vec![],
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

    let mut rng = Rng::new();
    let mut buf = vec![0_u8; 8192];

    let mut oks = 0_usize;
    let mut max_signers = 0_usize;
    let mut saw_signer = false;
    let mut saw_extra = false;
    let mut max_commitments = 0_usize;
    let mut max_nullifiers = 0_usize;
    let mut saw_empty_comm_nonempty_null = false;
    let mut saw_oversize_post_states = false;
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
        // Post-states are drawn modulo `public_account_ids.len() + 4` (0..=len+3).
        assert!(
            msg.public_post_states.len() <= msg.public_account_ids.len() + 3,
            "public_post_states {} exceeds public_account_ids + 3 ({})",
            msg.public_post_states.len(),
            msg.public_account_ids.len() + 3
        );
        if msg.public_post_states.len() > msg.public_account_ids.len() {
            saw_oversize_post_states = true;
        }
        // At most 3 signers plus at most 3 extra ids (both deduplicated).
        assert!(
            msg.public_account_ids.len() <= 6,
            "public_account_ids {} exceeds signers (<=3) + extras (<=3)",
            msg.public_account_ids.len()
        );
        // `new_commitments` count is drawn modulo 4 (0..=3).
        assert!(
            msg.new_commitments.len() <= 3,
            "new_commitments {} exceeds 3",
            msg.new_commitments.len()
        );
        // `new_nullifiers` count is drawn modulo 3 (0..=2).
        assert!(
            msg.new_nullifiers.len() <= 2,
            "new_nullifiers {} exceeds 2",
            msg.new_nullifiers.len()
        );
        // `encrypted_private_post_states` count is drawn modulo 3 (0..=2).
        assert!(
            msg.encrypted_private_post_states.len() <= 2,
            "encrypted_private_post_states {} exceeds 2",
            msg.encrypted_private_post_states.len()
        );

        // An id that is not a signer can only be present because an extra was appended.
        if msg
            .public_account_ids
            .iter()
            .any(|id| !signer_ids.contains(id))
        {
            saw_extra = true;
        }

        max_commitments = max_commitments.max(msg.new_commitments.len());
        max_nullifiers = max_nullifiers.max(msg.new_nullifiers.len());

        // The fallback that guarantees "commitments or nullifiers non-empty" must fire
        // only when *both* are empty. So a message with empty commitments but non-empty
        // nullifiers is a valid, reachable shape — the fallback must leave it alone.
        if msg.new_commitments.is_empty() && !msg.new_nullifiers.is_empty() {
            saw_empty_comm_nonempty_null = true;
        }

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
    // Multiple distinct commitments must be reachable (the dedup must keep, not drop).
    assert!(
        max_commitments >= 2,
        "the generator never produced >= 2 commitments"
    );
    // Multiple distinct nullifiers must be reachable (the dedup must keep, not drop).
    assert!(
        max_nullifiers >= 2,
        "the generator never produced >= 2 nullifiers"
    );
    // The empty-commitments + non-empty-nullifiers shape must be reachable, proving the
    // fallback does not over-fire.
    assert!(
        saw_empty_comm_nonempty_null,
        "the generator never produced empty commitments with non-empty nullifiers"
    );
    // The oversized shape (more post-states than public account ids) must be reachable.
    assert!(
        saw_oversize_post_states,
        "the generator never produced more post-states than public account ids"
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
