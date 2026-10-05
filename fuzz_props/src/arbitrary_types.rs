//! Newtype wrappers that implement [`arbitrary::Arbitrary`] for LEZ types.
//!
//! **No changes to `../logos-execution-zone` are required.**
//!
//! The Rust orphan rule forbids `impl Arbitrary for LeeTransaction` when both
//! the trait and the type come from external crates.  Using newtypes (`ArbXxx`)
//! sidesteps the restriction entirely.
//!
//! # Usage in a fuzz target
//!
//! ```rust,ignore
//! #![no_main]
//! use fuzz_props::arbitrary_types::ArbLeeTransaction;
//! use libfuzzer_sys::fuzz_target;
//!
//! fuzz_target!(|wrapped: ArbLeeTransaction| {
//!     let tx = wrapped.0;
//!     let Ok(valid_tx) = tx.transaction_stateless_check() else { return; };
//!     // …
//! });
//! ```

use arbitrary::{Arbitrary, Result as ArbResult, Unstructured};
use common::{HashType, block::HashableBlockData, transaction::LeeTransaction};
use nssa::{
    AccountId, FeeDeclaration, PrivateKey, ProgramShardSelector, PublicKey, Signature,
    public_transaction::{Message, PublicTransaction, WitnessSet},
};
use nssa_core::account::Nonce;

// ── AccountId ─────────────────────────────────────────────────────────────────
// `AccountId::new([u8; 32])` accepts any byte array — no validity constraint.

/// Newtype wrapper providing [`Arbitrary`] for [`AccountId`].
#[derive(Debug)]
pub struct ArbAccountId(pub AccountId);

impl<'a> Arbitrary<'a> for ArbAccountId {
    fn arbitrary(u: &mut Unstructured<'a>) -> ArbResult<Self> {
        Ok(Self(AccountId::new(<[u8; 32]>::arbitrary(u)?)))
    }
}

// ── Nonce ─────────────────────────────────────────────────────────────────────
// `Nonce` wraps `u128` and exposes `From<u128>`.

/// Newtype wrapper providing [`Arbitrary`] for [`Nonce`].
#[derive(Debug)]
pub struct ArbNonce(pub Nonce);

impl<'a> Arbitrary<'a> for ArbNonce {
    fn arbitrary(u: &mut Unstructured<'a>) -> ArbResult<Self> {
        Ok(Self(Nonce::from(u128::arbitrary(u)?)))
    }
}

// ── Signature ─────────────────────────────────────────────────────────────────
// `Signature.value` is `pub [u8; 64]`, so we can construct a value directly.
// Cryptographic validity is only checked at verification time, meaning invalid
// byte patterns are legal at the struct level and will exercise the rejection
// path in `WitnessSet::is_valid_for`.

/// Newtype wrapper providing [`Arbitrary`] for [`Signature`].
#[derive(Debug)]
pub struct ArbSignature(pub Signature);

impl<'a> Arbitrary<'a> for ArbSignature {
    fn arbitrary(u: &mut Unstructured<'a>) -> ArbResult<Self> {
        Ok(Self(Signature {
            value: <[u8; 64]>::arbitrary(u)?,
        }))
    }
}

// ── PrivateKey ────────────────────────────────────────────────────────────────
// `PrivateKey::try_new` succeeds for almost all non-zero 32-byte values: only
// the zero scalar and values ≥ the secp256k1 group order (< 2⁻¹²⁸ of the
// input space) are rejected.  A known-good fallback handles the rare failure.

/// Newtype wrapper providing [`Arbitrary`] for [`PrivateKey`].
#[derive(Debug)]
pub struct ArbPrivateKey(pub PrivateKey);

impl<'a> Arbitrary<'a> for ArbPrivateKey {
    fn arbitrary(u: &mut Unstructured<'a>) -> ArbResult<Self> {
        let bytes = <[u8; 32]>::arbitrary(u)?;
        let key = PrivateKey::try_new(bytes)
            .unwrap_or_else(|_| PrivateKey::try_new([1_u8; 32]).expect("known-good seed"));
        Ok(Self(key))
    }
}

// ── PublicKey ─────────────────────────────────────────────────────────────────
// `PublicKey::try_new` validates that the bytes form a valid secp256k1
// x-coordinate (roughly 50% of random inputs succeed).  Two modes:
// 1. Derive from a valid `PrivateKey` → exercises the happy-path verification.
// 2. Use raw bytes → exercises the rejection path in `is_valid_for`; on
//    construction failure falls back to a derived key so upstream callers
//    (ArbWitnessSet, ArbPublicTransaction) are not silently discarded.

/// Newtype wrapper providing [`Arbitrary`] for [`PublicKey`].
#[derive(Debug)]
pub struct ArbPublicKey(pub PublicKey);

impl<'a> Arbitrary<'a> for ArbPublicKey {
    fn arbitrary(u: &mut Unstructured<'a>) -> ArbResult<Self> {
        if bool::arbitrary(u)? {
            // Valid key pair — exercises happy-path signature verification.
            let pk = PublicKey::new_from_private_key(&ArbPrivateKey::arbitrary(u)?.0);
            Ok(Self(pk))
        } else {
            // Raw bytes — may be an invalid x-coordinate, exercises the rejection
            // path in `is_valid_for`.  On failure we fall back to a key derived
            // from a valid private key so that upstream callers (ArbWitnessSet,
            // ArbPublicTransaction) are not silently discarded ~25% of the time.
            // The ArbSignature type (random bytes) already exercises the full
            // rejection path in `is_valid_for` independently.
            let bytes = <[u8; 32]>::arbitrary(u)?;
            let pk = PublicKey::try_new(bytes).unwrap_or_else(|_| {
                PublicKey::new_from_private_key(&ArbPrivateKey::arbitrary(u).map_or_else(
                    |_| PrivateKey::try_new([1_u8; 32]).expect("known-good seed"),
                    |w| w.0,
                ))
            });
            Ok(Self(pk))
        }
    }
}

// ── Message (public transaction) ──────────────────────────────────────────────
// `Message::new_preserialized` takes all fields directly without any validity
// constraint — any combination of program account id, shard selectors, nonces,
// instruction_data, and fee declaration is accepted.

/// Newtype wrapper providing [`Arbitrary`] for the public-transaction [`Message`].
#[derive(Debug)]
pub struct ArbPubTxMessage(pub Message);

impl<'a> Arbitrary<'a> for ArbPubTxMessage {
    fn arbitrary(u: &mut Unstructured<'a>) -> ArbResult<Self> {
        let program_account_id = ArbAccountId::arbitrary(u)?.0;
        // Generate 0–7 shard selectors; nonces vector is given the same length.
        let len = (u8::arbitrary(u)? as usize) % 8;
        let shard_selectors = std::iter::repeat_with(|| {
            Ok(ProgramShardSelector::new(
                ArbAccountId::arbitrary(u)?.0,
                ArbAccountId::arbitrary(u)?.0,
            ))
        })
        .take(len)
        .collect::<ArbResult<Vec<_>>>()?;
        let nonces = std::iter::repeat_with(|| ArbNonce::arbitrary(u).map(|n| n.0))
            .take(len)
            .collect::<ArbResult<Vec<_>>>()?;
        let instruction_data: Vec<u8> = Vec::<u8>::arbitrary(u)?;
        // `None` is a fee-exempt (system) message; `Some` carries arbitrary fee fields.
        let fee = if bool::arbitrary(u)? {
            Some(FeeDeclaration::new(
                ArbAccountId::arbitrary(u)?.0,
                u64::arbitrary(u)?,
                u64::arbitrary(u)?,
                u128::arbitrary(u)?,
            ))
        } else {
            None
        };
        Ok(Self(Message::new_preserialized(
            program_account_id,
            shard_selectors,
            nonces,
            instruction_data,
            fee,
        )))
    }
}

// ── WitnessSet ────────────────────────────────────────────────────────────────
// `WitnessSet::from_raw_parts` accepts any `Vec<(Signature, PublicKey)>`.
// We deliberately mix valid and invalid pairs so the fuzzer exercises both
// the accept and reject branches of `WitnessSet::is_valid_for`.

/// Newtype wrapper providing [`Arbitrary`] for [`WitnessSet`].
#[derive(Debug)]
pub struct ArbWitnessSet(pub WitnessSet);

impl<'a> Arbitrary<'a> for ArbWitnessSet {
    fn arbitrary(u: &mut Unstructured<'a>) -> ArbResult<Self> {
        // 0–3 (signature, public_key) pairs
        let n = (u8::arbitrary(u)? as usize) % 4;
        let pairs = std::iter::repeat_with(|| {
            Ok((ArbSignature::arbitrary(u)?.0, ArbPublicKey::arbitrary(u)?.0))
        })
        .take(n)
        .collect::<ArbResult<Vec<_>>>()?;
        Ok(Self(WitnessSet::from_raw_parts(pairs)))
    }
}

// ── PublicTransaction ─────────────────────────────────────────────────────────

/// Newtype wrapper providing [`Arbitrary`] for [`PublicTransaction`].
#[derive(Debug)]
pub struct ArbPublicTransaction(pub PublicTransaction);

impl<'a> Arbitrary<'a> for ArbPublicTransaction {
    fn arbitrary(u: &mut Unstructured<'a>) -> ArbResult<Self> {
        Ok(Self(PublicTransaction::new(
            ArbPubTxMessage::arbitrary(u)?.0,
            ArbWitnessSet::arbitrary(u)?.0,
        )))
    }
}

// ── LeeTransaction ───────────────────────────────────────────────────────────
// `PrivacyPreservingTransaction` is intentionally excluded *here*: a passing proof
// binds to the live chain state, so it cannot be produced by a state-independent
// `Arbitrary` impl.  Privacy-preserving state-transition coverage (Path B) lives in
// [`crate::privacy`], which synthesises a per-message dev-mode fake receipt against the
// current state and is driven by the `fuzz_privacy_preserving_state_transition` target.

/// Newtype wrapper providing [`Arbitrary`] for [`LeeTransaction`].
///
/// Generates the `Public` variant only (LEZ removed the dedicated program-deployment
/// transaction; deployment now goes through the `program_loader` program).
#[derive(Debug)]
pub struct ArbLeeTransaction(pub LeeTransaction);

impl<'a> Arbitrary<'a> for ArbLeeTransaction {
    fn arbitrary(u: &mut Unstructured<'a>) -> ArbResult<Self> {
        Ok(Self(LeeTransaction::Public(
            ArbPublicTransaction::arbitrary(u)?.0,
        )))
    }
}

// ── HashableBlockData ─────────────────────────────────────────────────────────
// All fields of `HashableBlockData` are `pub`, so we can construct it with a
// struct literal after generating each field independently.

/// Newtype wrapper providing [`Arbitrary`] for [`HashableBlockData`].
#[derive(Debug)]
pub struct ArbHashableBlockData(pub HashableBlockData);

impl<'a> Arbitrary<'a> for ArbHashableBlockData {
    fn arbitrary(u: &mut Unstructured<'a>) -> ArbResult<Self> {
        // 0–7 transactions per block
        let n = (u8::arbitrary(u)? as usize) % 8;
        let transactions = std::iter::repeat_with(|| ArbLeeTransaction::arbitrary(u).map(|t| t.0))
            .take(n)
            .collect::<ArbResult<Vec<_>>>()?;
        Ok(Self(HashableBlockData {
            block_id: u64::arbitrary(u)?,
            prev_block_hash: HashType(<[u8; 32]>::arbitrary(u)?),
            timestamp: u64::arbitrary(u)?,
            transactions,
        }))
    }
}
