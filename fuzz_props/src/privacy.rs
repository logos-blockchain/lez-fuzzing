//! Privacy-preserving state-transition fuzzing support — **Path B**.
//!
//! Path A (`fuzz_encoding_privacy_preserving`, `fuzz_privacy_preserving_witness`) covers
//! the *encoding* of privacy-preserving transactions. It does not reach the
//! privacy-preserving *executor*:
//! [`ValidatedStateDiff::from_privacy_preserving_transaction`] performs ten distinct
//! checks, of which checks 5 and 6 (`check_commitments_are_new`,
//! `check_nullifiers_are_valid`) and the subsequent `apply_state_diff` were **0% covered**
//! because they are only reachable behind a proof that *passes* `Proof::is_valid_for`.
//!
//! # How a passing proof is obtained without a prover
//!
//! `Proof::is_valid_for` borsh-decodes the proof bytes into a `risc0_zkvm::InnerReceipt`,
//! wraps it in a `Receipt` whose journal is `circuit_output.to_bytes()`, and calls
//! `Receipt::verify(PRIVACY_PRESERVING_CIRCUIT_ID)`. Under `RISC0_DEV_MODE=1` (exported by
//! every `just fuzz` recipe) a [`FakeReceipt`] passes the integrity step without any ZK
//! computation — **but** `Receipt::verify` still checks that the receipt's *claim digest*
//! equals `ReceiptClaim::ok(image_id, journal_digest).digest()`. A fake receipt is therefore
//! bound to one exact journal and circuit id; it cannot be precomputed once and reused
//! across fuzz-varied messages (the "binding caveat" in
//! `../privacy_preserving_coverage_gap.md`).
//!
//! [`synthesize_passing_proof`] takes the per-message route: it reconstructs the exact
//! [`PrivacyPreservingCircuitOutput`] the validator will build — including
//! `public_pre_states`, which the validator reads from live chain state — then builds a
//! [`FakeReceipt`] whose `ReceiptClaim::ok` matches that journal. Check 4 then passes for
//! that specific (message, state) pair, and execution proceeds into checks 5–6 and state
//! application.
//!
//! # Soundness note for callers
//!
//! Because the proof is *forced* to pass, this harness deliberately does **not** assert
//! balance conservation: under a real proof the circuit is what guarantees the
//! `public_post_states` conserve value, and that guarantee is exactly what a synthesised
//! pass bypasses. Asserting conservation here would only re-test the fake. The sound
//! invariants for this path — no panic, state isolation on rejection, commitment insertion,
//! signer-nonce increment, post-state application, and replay rejection — are checked by the
//! `fuzz_privacy_preserving_state_transition` target.

use arbitrary::{Arbitrary, Result as ArbResult, Unstructured};
use borsh::to_vec as borsh_to_vec;
use nssa::{
    AccountId, PRIVACY_PRESERVING_CIRCUIT_ID, PrivacyPreservingTransaction, PrivateKey, PublicKey,
    V03State,
    privacy_preserving_transaction::{
        Message as PPMessage, WitnessSet as PPWitnessSet, circuit::Proof,
    },
};
use nssa_core::{
    Commitment, CommitmentSetDigest, EncryptedAccountData, EncryptionScheme, EphemeralPublicKey,
    Nullifier, PrivacyPreservingCircuitOutput, PrivateAccountKind, SharedSecretKey,
    account::{Account, AccountWithMetadata, Nonce},
    program::ValidityWindow,
};
use risc0_zkvm::{FakeReceipt, InnerReceipt, ReceiptClaim};

use crate::generators::FuzzAccount;

/// Synthesise a [`Proof`] that **passes** `Proof::is_valid_for` for `message` against
/// `state`, under `RISC0_DEV_MODE`.
///
/// `signer_account_ids` must be the ids the validator will derive from the witness set —
/// i.e. `AccountId::from(public_key)` for every key the message is signed with. They drive
/// the `is_authorized` flag of each reconstructed `public_pre_state`, so they must match the
/// witness set exactly or the journal digest diverges and the proof is rejected at check 4.
///
/// The returned proof is valid **only** for this exact `(message, state, signers)` triple;
/// it must be regenerated whenever any of them changes (notably after a prior transaction
/// has mutated `state`).
#[must_use]
pub fn synthesize_passing_proof(
    message: &PPMessage,
    state: &V03State,
    signer_account_ids: &[AccountId],
) -> Proof {
    // Reconstruct `public_pre_states` byte-for-byte as
    // `ValidatedStateDiff::from_privacy_preserving_transaction` does: read each public
    // account from live chain state, marking it authorised iff it signed.
    let public_pre_states: Vec<AccountWithMetadata> = message
        .public_account_ids
        .iter()
        .map(|account_id| {
            AccountWithMetadata::new(
                state.get_account_by_id(*account_id),
                signer_account_ids.contains(account_id),
                *account_id,
            )
        })
        .collect();

    let output = PrivacyPreservingCircuitOutput {
        public_pre_states,
        public_post_states: message.public_post_states.clone(),
        encrypted_private_post_states: message.encrypted_private_post_states.clone(),
        new_commitments: message.new_commitments.clone(),
        new_nullifiers: message.new_nullifiers.clone(),
        block_validity_window: message.block_validity_window,
        timestamp_validity_window: message.timestamp_validity_window,
    };

    // `ReceiptClaim::ok` fixes exit code Halted(0) and binds (image_id, journal_digest);
    // `Receipt::verify` reconstructs exactly this claim, so the digests match. In dev mode
    // the fake integrity check is a pass-through, so the whole receipt verifies.
    let journal = output.to_bytes();
    let claim = ReceiptClaim::ok(PRIVACY_PRESERVING_CIRCUIT_ID, journal);
    let inner = InnerReceipt::Fake(FakeReceipt::new(claim));
    let proof_bytes = borsh_to_vec(&inner).expect("InnerReceipt is borsh-serialisable");
    Proof::from_inner(proof_bytes)
}

/// Build a fuzz-driven [`Account`] for use as a private commitment pre-image or a
/// `public_post_state`.
///
/// The nonce is intentionally capped well below `u128::MAX`: a `public_post_state` is
/// applied verbatim and a signer's nonce is then incremented, and the protocol's
/// `public_account_nonce_increment` panics on overflow. An uncapped nonce would let the
/// fuzzer drive a signer to `u128::MAX` via a forced-pass post-state and then trip that
/// panic — a self-inflicted artefact, not a protocol bug.
fn arb_account(u: &mut Unstructured<'_>) -> ArbResult<Account> {
    Ok(Account {
        program_owner: <[u32; 8]>::arbitrary(u)?,
        balance: u128::arbitrary(u)?,
        nonce: Nonce(u128::arbitrary(u)? % 1024),
        ..Account::default()
    })
}

/// Build a fuzz-driven block/timestamp [`ValidityWindow`].
///
/// `from_privacy_preserving_transaction` checks `block_validity_window.is_valid_for(block_id)` and
/// `timestamp_validity_window.is_valid_for(timestamp)` (returning `LeeError::OutOfValidityWindow`)
/// *before* proof verification. The window is reconstructed byte-for-byte into the synthesised
/// proof's journal, so a bounded window still passes check 4 and is then rejected at the window
/// check — exercising that rejection path and its state-isolation guarantee.
///
/// Windows are left **unbounded most of the time** so the success path (checks 5-6 + apply) stays
/// frequently reachable. When bounded, the half-open `[from, to)` bounds are kept in `0..8` so they
/// straddle the harness's `block_id` / `timestamp` range (both `< 6`), landing on both sides of the
/// check. `try_from` rejects `from >= to`; that falls back to unbounded rather than biasing toward
/// always-valid windows.
fn arb_validity_window(u: &mut Unstructured<'_>) -> ArbResult<ValidityWindow<u64>> {
    if (u8::arbitrary(u)? % 4) != 0 {
        return Ok(ValidityWindow::new_unbounded());
    }
    let from = bool::arbitrary(u)?.then(|| u64::from(u8::arbitrary(u).unwrap_or(0) % 8));
    let to = bool::arbitrary(u)?.then(|| u64::from(u8::arbitrary(u).unwrap_or(0) % 8));
    Ok(ValidityWindow::try_from((from, to)).unwrap_or_else(|_| ValidityWindow::new_unbounded()))
}

/// Build one fuzz-driven [`EncryptedAccountData`] for `message.encrypted_private_post_states`.
///
/// The executor does not validate the encrypted notes directly — they are only bound into the proof
/// journal — so this needs no real recipient keys: the three fields are public, and the only one
/// that cannot be built outside `lee_core` is the [`Ciphertext`](nssa_core), whose inner `Vec` is
/// `pub(crate)`. We therefore obtain it through `EncryptionScheme::encrypt` (a cheap
/// `ChaCha20` + SHA256 transform, no ML-KEM keygen) and fuzz the `epk` / `view_tag` directly. The
/// synthesised proof binds whatever we produce, so checks 5-6 + apply stay reachable.
fn arb_encrypted_account_data(u: &mut Unstructured<'_>) -> ArbResult<EncryptedAccountData> {
    let account = arb_account(u)?;
    let kind = PrivateAccountKind::Regular(u128::arbitrary(u)?);
    let shared_secret = SharedSecretKey(<[u8; 32]>::arbitrary(u)?);
    let commitment = Commitment::new(&AccountId::new(<[u8; 32]>::arbitrary(u)?), &account);
    let ciphertext = EncryptionScheme::encrypt(
        &account,
        &kind,
        &shared_secret,
        &commitment,
        u32::arbitrary(u)?,
    );
    Ok(EncryptedAccountData {
        ciphertext,
        epk: EphemeralPublicKey(<Vec<u8>>::arbitrary(u)?),
        view_tag: u8::arbitrary(u)?,
    })
}

/// Generate a privacy-preserving transaction aimed at the **state-transition executor**.
///
/// The transaction is built to *frequently* pass every validation check up to and including
/// proof verification (check 4) so that the previously-uncovered checks 5–6 and
/// `apply_state_diff` are exercised, while fuzz-driven choices (mismatched nullifier digest,
/// occasional garbage proof, duplicated/oversized field shapes, bounded validity windows that
/// exclude the block/timestamp) still drive the rejection and isolation paths.
///
/// `state` must be the *current* state the transaction will be validated against — the
/// synthesised proof binds to it. `accounts` supplies signing keys (each [`FuzzAccount`]
/// carries a usable [`PrivateKey`]); their key-derived public-account ids become the
/// transaction's signers.
pub fn arb_privacy_preserving_tx(
    u: &mut Unstructured<'_>,
    state: &V03State,
    accounts: &[FuzzAccount],
) -> ArbResult<PrivacyPreservingTransaction> {
    // ── Signers ──────────────────────────────────────────────────────────────────────
    // 0..=3 distinct signers drawn from the keyed fuzz accounts. A signer's public-account
    // id is `AccountId::from(&its_public_key)` — exactly what the validator derives from the
    // witness set — and is independent of `FuzzAccount.account_id`.
    let max_signers = accounts.len().min(3);
    let n_signers = if max_signers == 0 {
        0
    } else {
        (u8::arbitrary(u)? as usize) % (max_signers + 1)
    };
    let mut keys: Vec<&PrivateKey> = Vec::with_capacity(n_signers);
    let mut signer_ids: Vec<AccountId> = Vec::with_capacity(n_signers);
    for _ in 0..n_signers {
        let key = &accounts[(u8::arbitrary(u)? as usize) % accounts.len()].private_key;
        let id = AccountId::from(&PublicKey::new_from_private_key(key));
        if signer_ids.contains(&id) {
            continue; // keep signer ids distinct so `nonces` stays 1:1 with `keys`
        }
        keys.push(key);
        signer_ids.push(id);
    }

    // Nonces read live from state → check 3c (nonce match) passes by construction. After a
    // successful apply the signer nonce advances, which makes a replay fail check 3c.
    let nonces: Vec<Nonce> = signer_ids
        .iter()
        .map(|id| state.get_account_by_id(*id).nonce)
        .collect();

    // ── public_account_ids (must be unique — validator check 2) ──────────────────────
    let mut public_account_ids: Vec<AccountId> = Vec::new();
    // Sometimes treat the signers themselves as updated public accounts (the common shape);
    // otherwise leave them out so the signer-nonce-increment invariant is exercised on an
    // account that is *not* also overwritten by a post-state.
    if bool::arbitrary(u)? {
        public_account_ids.extend_from_slice(&signer_ids);
    }
    let n_extra = (u8::arbitrary(u)? as usize) % 4;
    for _ in 0..n_extra {
        let id = if bool::arbitrary(u)? {
            // a known fuzz account — its post-state change is observable in the snapshot
            accounts[(u8::arbitrary(u)? as usize) % accounts.len()].account_id
        } else {
            AccountId::new(<[u8; 32]>::arbitrary(u)?)
        };
        if !public_account_ids.contains(&id) {
            public_account_ids.push(id);
        }
    }

    // ── public_post_states (length varied to exercise the apply/zip-truncation path) ──
    let n_post = (u8::arbitrary(u)? as usize) % (public_account_ids.len() + 1);
    let public_post_states = std::iter::repeat_with(|| arb_account(u))
        .take(n_post)
        .collect::<ArbResult<Vec<_>>>()?;

    // ── new_commitments (unique — validator check 2c; fresh against a genesis state) ──
    let n_comm = (u8::arbitrary(u)? as usize) % 4;
    let mut new_commitments: Vec<Commitment> = Vec::new();
    for _ in 0..n_comm {
        let aid = AccountId::new(<[u8; 32]>::arbitrary(u)?);
        let acc = arb_account(u)?;
        let commitment = Commitment::new(&aid, &acc);
        if !new_commitments.contains(&commitment) {
            new_commitments.push(commitment);
        }
    }

    // ── new_nullifiers (unique — validator check 2b) ─────────────────────────────────
    // Check 6 additionally requires each digest to be a recognised commitment-set root.
    // Using the live root makes the success path reachable; a random digest drives the
    // check-6 rejection path.
    let n_null = (u8::arbitrary(u)? as usize) % 3;
    let live_root = state.commitment_set_digest();
    let mut new_nullifiers: Vec<(Nullifier, CommitmentSetDigest)> = Vec::new();
    for _ in 0..n_null {
        let aid = AccountId::new(<[u8; 32]>::arbitrary(u)?);
        let nullifier = Nullifier::for_account_initialization(&aid);
        let digest: CommitmentSetDigest = if bool::arbitrary(u)? {
            live_root
        } else {
            <[u8; 32]>::arbitrary(u)?
        };
        if !new_nullifiers.iter().any(|(n, _)| n == &nullifier) {
            new_nullifiers.push((nullifier, digest));
        }
    }

    // Validator check 1: commitments OR nullifiers must be non-empty.
    if new_commitments.is_empty() && new_nullifiers.is_empty() {
        let aid = AccountId::new(<[u8; 32]>::arbitrary(u)?);
        let acc = arb_account(u)?;
        new_commitments.push(Commitment::new(&aid, &acc));
    }

    // ── encrypted_private_post_states (carried into the proof journal, not validated) ──
    let n_enc = (u8::arbitrary(u)? as usize) % 3;
    let encrypted_private_post_states = std::iter::repeat_with(|| arb_encrypted_account_data(u))
        .take(n_enc)
        .collect::<ArbResult<Vec<_>>>()?;

    let message = PPMessage {
        public_account_ids,
        nonces,
        public_post_states,
        encrypted_private_post_states,
        new_commitments,
        new_nullifiers,
        block_validity_window: arb_validity_window(u)?,
        timestamp_validity_window: arb_validity_window(u)?,
    };

    // Mostly a passing proof (so checks 5–6 + apply are reached); occasionally garbage so
    // the check-4 rejection path is hit from the executor side too.
    let proof = if (u8::arbitrary(u)? % 8) == 0 {
        Proof::from_inner(<Vec<u8>>::arbitrary(u)?)
    } else {
        synthesize_passing_proof(&message, state, &signer_ids)
    };

    let witness_set = PPWitnessSet::for_message(&message, proof, &keys);
    Ok(PrivacyPreservingTransaction::new(message, witness_set))
}

#[cfg(test)]
mod tests {
    use super::*;
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

        let mut state = V03State::new_with_genesis_accounts(&[], vec![], 0);

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
            .expect("a synthesised passing proof must drive the executor to success (checks 5-6 + apply)");

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
}
