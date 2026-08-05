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
//! [`PrivacyPreservingCircuitOutput`] the validator will build — including the `pre` half
//! of each [`PublicAction`], which the validator reads from live chain state — then builds
//! a [`FakeReceipt`] whose `ReceiptClaim::ok` matches that journal. Check 4 then passes for
//! that specific (message, state) pair, and execution proceeds into checks 5–6 and state
//! application.
//!
//! # Soundness note for callers
//!
//! Because the proof is *forced* to pass, this harness deliberately does **not** assert
//! balance conservation: under a real proof the circuit is what guarantees the public
//! post-states conserve value, and that guarantee is exactly what a synthesised pass
//! bypasses. Asserting conservation here would only re-test the fake. The sound
//! invariants for this path — no panic, state isolation on rejection, commitment insertion,
//! signer-nonce increment, post-state application, and replay rejection — are checked by the
//! `fuzz_privacy_preserving_state_transition` target.

use arbitrary::{Arbitrary, Result as ArbResult, Unstructured};
use borsh::to_vec as borsh_to_vec;
use nssa::{
    AccountId, PRIVACY_PRESERVING_CIRCUIT_ID, PrivacyPreservingTransaction, PrivateKey, V03State,
    privacy_preserving_transaction::{
        Message as PPMessage, WitnessSet as PPWitnessSet, circuit::Proof,
        message::PublicActionWithID,
    },
};
use nssa_core::{
    Commitment, CommitmentSetDigest, EncryptedAccountData, EncryptionScheme, EphemeralPublicKey,
    Nullifier, PrivacyPreservingCircuitOutput, PrivateAccountKind, PrivateAction, PublicAction,
    SharedSecretKey,
    account::{Account, AccountWithMetadata, Nonce},
    program::ValidityWindow,
};
use risc0_zkvm::{FakeReceipt, InnerReceipt, ReceiptClaim};

use crate::generators::{FuzzAccount, account_id_for_key};

/// Synthesise a [`Proof`] that **passes** `Proof::is_valid_for` for `message` against
/// `state`, under `RISC0_DEV_MODE`.
///
/// `signer_account_ids` must be the ids the validator will derive from the witness set —
/// i.e. `AccountId::from(public_key)` for every key the message is signed with. They drive
/// the `is_authorized` flag of each reconstructed `PublicAction::pre`, so they must match
/// the witness set exactly or the journal digest diverges and the proof is rejected at
/// check 4.
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
    // Reconstruct each `PublicAction` byte-for-byte as
    // `ValidatedStateDiff::from_privacy_preserving_transaction` does: read each public
    // account's pre-state from live chain state (marking it authorised iff it signed) and
    // pair it with the message's declared post-state.
    let public_actions: Vec<PublicAction> = message
        .public_actions
        .iter()
        .map(|action| PublicAction {
            pre: AccountWithMetadata::new(
                state.get_account_by_id(action.account_id),
                signer_account_ids.contains(&action.account_id),
                action.account_id,
            ),
            post: action.post_state.clone(),
        })
        .collect();

    let output = PrivacyPreservingCircuitOutput {
        public_actions,
        private_actions: message.private_actions.clone(),
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
/// public action's post-state.
///
/// The nonce is intentionally capped well below `u128::MAX`: a public post-state is
/// applied verbatim and a signer's nonce is then incremented, and the protocol's
/// `public_account_nonce_increment` panics on overflow. An uncapped nonce would let the
/// fuzzer drive a signer to `u128::MAX` via a forced-pass post-state and then trip that
/// panic — a self-inflicted artefact, not a protocol bug.
pub(crate) fn arb_account(u: &mut Unstructured<'_>) -> ArbResult<Account> {
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
pub(crate) fn arb_validity_window(u: &mut Unstructured<'_>) -> ArbResult<ValidityWindow<u64>> {
    if (u8::arbitrary(u)? % 4) != 0 {
        return Ok(ValidityWindow::new_unbounded());
    }
    let from = bool::arbitrary(u)?.then(|| u64::from(u8::arbitrary(u).unwrap_or(0) % 8));
    let to = bool::arbitrary(u)?.then(|| u64::from(u8::arbitrary(u).unwrap_or(0) % 8));
    Ok(ValidityWindow::try_from((from, to)).unwrap_or_else(|_| ValidityWindow::new_unbounded()))
}

/// Build one fuzz-driven [`EncryptedAccountData`] for a [`PrivateAction`]'s
/// `encrypted_post_state`.
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
    let nullifier =
        Nullifier::for_account_initialization(&AccountId::new(<[u8; 32]>::arbitrary(u)?));
    let ciphertext = EncryptionScheme::encrypt(&account, &kind, &shared_secret, &nullifier);
    Ok(EncryptedAccountData {
        ciphertext,
        epk: EphemeralPublicKey(<Vec<u8>>::arbitrary(u)?),
        view_tag: u8::arbitrary(u)?,
    })
}

/// Build one fuzz-driven [`PrivateAction`].
///
/// The nullifier is derived from a random account id, so distinct draws collide only with
/// negligible probability (the caller still deduplicates — validator check 2). The digest is
/// the **live commitment-set root half the time** so check 6's `root_history` membership
/// passes (the root history is seeded at genesis by the protocol's dummy commitment, so the
/// live root is always a member) and the success path stays frequently reachable; a random
/// digest drives the check-6 rejection path.
fn arb_private_action(
    u: &mut Unstructured<'_>,
    live_root: CommitmentSetDigest,
) -> ArbResult<PrivateAction> {
    let null_aid = AccountId::new(<[u8; 32]>::arbitrary(u)?);
    let nullifier = Nullifier::for_account_initialization(&null_aid);
    let root: CommitmentSetDigest = if bool::arbitrary(u)? {
        live_root
    } else {
        <[u8; 32]>::arbitrary(u)?
    };
    let commitment = Commitment::new(&AccountId::new(<[u8; 32]>::arbitrary(u)?), &arb_account(u)?);
    Ok(PrivateAction {
        nullifier,
        root,
        commitment,
        encrypted_post_state: arb_encrypted_account_data(u)?,
    })
}

/// Generate a privacy-preserving transaction aimed at the **state-transition executor**.
///
/// The transaction is built to *frequently* pass every validation check up to and including
/// proof verification (check 4) so that the previously-uncovered checks 5–6 and
/// `apply_state_diff` are exercised, while fuzz-driven choices (mismatched nullifier digest,
/// occasional garbage proof, duplicated field shapes, bounded validity windows that
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
    // id is `account_id_for_key(key)` — exactly what the validator derives from the witness
    // set. Since `arbitrary_fuzz_state` now derives `FuzzAccount.account_id` the same way,
    // this id also equals that account's `account_id`, so the funded account is the signer.
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
        let id = account_id_for_key(key);
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

    // ── public_actions (account ids must be unique — validator check 2) ──────────────
    // Each action pairs an account id with its declared post-state; the id set mirrors the
    // pre-bundling shape: sometimes the signers themselves (the common shape), otherwise
    // signers are left out so the signer-nonce-increment invariant is exercised on an
    // account that is *not* also overwritten by a post-state, plus up to 3 extra ids.
    let mut public_account_ids: Vec<AccountId> = Vec::new();
    if bool::arbitrary(u)? {
        public_account_ids.extend_from_slice(&signer_ids);
    }
    let n_extra = (u8::arbitrary(u)? as usize) % 4;
    for _ in 0..n_extra {
        let id = if !accounts.is_empty() && bool::arbitrary(u)? {
            // a known fuzz account — its post-state change is observable in the snapshot
            accounts[(u8::arbitrary(u)? as usize) % accounts.len()].account_id
        } else {
            AccountId::new(<[u8; 32]>::arbitrary(u)?)
        };
        if !public_account_ids.contains(&id) {
            public_account_ids.push(id);
        }
    }
    let public_actions = public_account_ids
        .into_iter()
        .map(|account_id| {
            Ok(PublicActionWithID {
                account_id,
                post_state: arb_account(u)?,
            })
        })
        .collect::<ArbResult<Vec<_>>>()?;

    // ── private_actions (unique nullifiers and commitments — validator check 2) ──────
    // Check 6 additionally requires each action's digest to be in the commitment set's
    // `root_history`. The protocol seeds the history at genesis (the `Default` state inserts
    // a dummy commitment, recording the post-insert root), so an action bound to the live
    // root passes check 6 even on the first transaction in a sequence; a random digest
    // always drives the check-6 rejection path.
    let n_priv = (u8::arbitrary(u)? as usize) % 4;
    let live_root = state.commitment_set_digest();
    let mut private_actions: Vec<PrivateAction> = Vec::new();
    for _ in 0..n_priv {
        let action = arb_private_action(u, live_root)?;
        if !private_actions
            .iter()
            .any(|a| a.nullifier == action.nullifier || a.commitment == action.commitment)
        {
            private_actions.push(action);
        }
    }

    // Validator check 1: the private-action list must be non-empty.
    if private_actions.is_empty() {
        private_actions.push(arb_private_action(u, live_root)?);
    }

    let message = PPMessage {
        public_actions,
        nonces,
        private_actions,
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

/// Build a minimal *pure-private* transaction: one signer, no public actions, the given
/// private actions, and unbounded validity windows.
///
/// Two properties matter for the ordering-independence oracle in
/// `fuzz_transaction_ordering_independence`:
///
/// * **`public_actions` is empty**, so `synthesize_passing_proof` reconstructs an empty
///   public-action list and the journal does not depend on live chain state. The proof
///   therefore stays valid at check 4 even after another transaction has mutated the state —
///   i.e. it is valid whether this tx is applied *first* or *second*. That is what lets us
///   apply the same transaction in both orderings and compare outcomes soundly.
/// * The single signer's nonce is read live from `state`, so check 3c passes by construction
///   at first application; because the paired transaction uses a *different* signer, this
///   signer's nonce is untouched when this tx is applied second — so any rejection of the
///   second application is attributable to the shared nullifier, not to a nonce mismatch.
fn build_pure_private_tx(
    state: &V03State,
    key: &PrivateKey,
    private_actions: Vec<PrivateAction>,
) -> PrivacyPreservingTransaction {
    let signer_id = account_id_for_key(key);
    let message = PPMessage {
        public_actions: Vec::new(),
        nonces: vec![state.get_account_by_id(signer_id).nonce],
        private_actions,
        block_validity_window: ValidityWindow::new_unbounded(),
        timestamp_validity_window: ValidityWindow::new_unbounded(),
    };
    let proof = synthesize_passing_proof(&message, state, &[signer_id]);
    let witness_set = PPWitnessSet::for_message(&message, proof, &[key]);
    PrivacyPreservingTransaction::new(message, witness_set)
}

/// Build a **nullifier-conflicting pair**: two *distinct* privacy-preserving transactions
/// (different signers, different fresh commitments) that both declare the **same** nullifier.
///
/// The shared nullifier's digest is bound to the current commitment-set root
/// (`state.commitment_set_digest()`), which is a member of `root_history` from genesis
/// onwards (the protocol seeds the history with its dummy commitment), so check 6 passes for
/// whichever transaction is applied first. The two transactions are otherwise independently
/// valid, so a correct state machine must accept *at most one* of them regardless of
/// application order — the property the ordering-independence target asserts.
///
/// Returns `Err` when there are fewer than two distinct keyed accounts to draw signers from.
pub fn arb_conflicting_nullifier_pair(
    u: &mut Unstructured<'_>,
    state: &V03State,
    accounts: &[FuzzAccount],
) -> ArbResult<(PrivacyPreservingTransaction, PrivacyPreservingTransaction)> {
    if accounts.len() < 2 {
        return Err(arbitrary::Error::IncorrectFormat);
    }
    // Two distinct signer accounts so the pair's nonce checks are independent.
    let i = (u8::arbitrary(u)? as usize) % accounts.len();
    let mut j = (u8::arbitrary(u)? as usize) % accounts.len();
    if j == i {
        j = (i + 1) % accounts.len();
    }
    let key_b = &accounts[i].private_key;
    let key_c = &accounts[j].private_key;
    if account_id_for_key(key_b) == account_id_for_key(key_c) {
        return Err(arbitrary::Error::IncorrectFormat);
    }

    // One nullifier, shared by both transactions, bound to a historical commitment-set root.
    let root = state.commitment_set_digest();
    let null_aid = AccountId::new(<[u8; 32]>::arbitrary(u)?);
    let shared_nullifier = Nullifier::for_account_initialization(&null_aid);

    // Distinct fresh commitments make the two transactions genuinely different (and keep them
    // from colliding with each other on check 5).
    let comm_b = Commitment::new(&AccountId::new(<[u8; 32]>::arbitrary(u)?), &arb_account(u)?);
    let comm_c = Commitment::new(&AccountId::new(<[u8; 32]>::arbitrary(u)?), &arb_account(u)?);
    if comm_b == comm_c {
        return Err(arbitrary::Error::IncorrectFormat);
    }

    let action_b = PrivateAction {
        nullifier: shared_nullifier,
        root,
        commitment: comm_b,
        encrypted_post_state: arb_encrypted_account_data(u)?,
    };
    let action_c = PrivateAction {
        nullifier: shared_nullifier,
        root,
        commitment: comm_c,
        encrypted_post_state: arb_encrypted_account_data(u)?,
    };

    let tx_b = build_pure_private_tx(state, key_b, vec![action_b]);
    let tx_c = build_pure_private_tx(state, key_c, vec![action_c]);
    Ok((tx_b, tx_c))
}
