//! Newtype wrappers that implement [`arbitrary::Arbitrary`] for LEZ types.
//!
//! **No changes to `../logos-execution-zone` are required.**
//!
//! The Rust orphan rule forbids `impl Arbitrary for NSSATransaction` when both
//! the trait and the type come from external crates.  Using newtypes (`ArbXxx`)
//! sidesteps the restriction entirely.
//!
//! # Usage in a fuzz target
//!
//! ```rust,ignore
//! #![no_main]
//! use fuzz_props::arbitrary_types::ArbNSSATransaction;
//! use libfuzzer_sys::fuzz_target;
//!
//! fuzz_target!(|wrapped: ArbNSSATransaction| {
//!     let tx = wrapped.0;
//!     let Ok(valid_tx) = tx.transaction_stateless_check() else { return; };
//!     // …
//! });
//! ```

use arbitrary::{Arbitrary, Result as ArbResult, Unstructured};
use common::{HashType, block::HashableBlockData, transaction::NSSATransaction};
use nssa::{
    AccountId, PrivateKey, PublicKey, Signature,
    program_deployment_transaction::ProgramDeploymentTransaction,
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
                PublicKey::new_from_private_key(
                    &ArbPrivateKey::arbitrary(u)
                        .map(|w| w.0)
                        .unwrap_or_else(|_| {
                            PrivateKey::try_new([1_u8; 32]).expect("known-good seed")
                        }),
                )
            });
            Ok(Self(pk))
        }
    }
}

// ── Message (public transaction) ──────────────────────────────────────────────
// `Message::new_preserialized` takes all fields directly without any validity
// constraint — any combination of program_id, account_ids, nonces, and
// instruction_data is accepted.

/// Newtype wrapper providing [`Arbitrary`] for the public-transaction [`Message`].
#[derive(Debug)]
pub struct ArbPubTxMessage(pub Message);

impl<'a> Arbitrary<'a> for ArbPubTxMessage {
    fn arbitrary(u: &mut Unstructured<'a>) -> ArbResult<Self> {
        let program_id: [u32; 8] = <[u32; 8]>::arbitrary(u)?;
        // Generate 0–7 accounts; nonces vector is given the same length.
        let len = (u8::arbitrary(u)? as usize) % 8;
        let account_ids = (0..len)
            .map(|_| ArbAccountId::arbitrary(u).map(|a| a.0))
            .collect::<ArbResult<Vec<_>>>()?;
        let nonces = (0..len)
            .map(|_| ArbNonce::arbitrary(u).map(|n| n.0))
            .collect::<ArbResult<Vec<_>>>()?;
        let instruction_data: Vec<u32> = Vec::<u32>::arbitrary(u)?;
        Ok(Self(Message::new_preserialized(
            program_id,
            account_ids,
            nonces,
            instruction_data,
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
        let pairs = (0..n)
            .map(|_| Ok((ArbSignature::arbitrary(u)?.0, ArbPublicKey::arbitrary(u)?.0)))
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

// ── ProgramDeploymentTransaction ──────────────────────────────────────────────
// `ProgramDeploymentTransaction` wraps a single `Message { bytecode: Vec<u8> }`.

/// Newtype wrapper providing [`Arbitrary`] for [`ProgramDeploymentTransaction`].
#[derive(Debug)]
pub struct ArbProgramDeploymentTransaction(pub ProgramDeploymentTransaction);

impl<'a> Arbitrary<'a> for ArbProgramDeploymentTransaction {
    fn arbitrary(u: &mut Unstructured<'a>) -> ArbResult<Self> {
        let bytecode = Vec::<u8>::arbitrary(u)?;
        let msg = nssa::program_deployment_transaction::Message::new(bytecode);
        Ok(Self(ProgramDeploymentTransaction::new(msg)))
    }
}

// ── NSSATransaction ───────────────────────────────────────────────────────────
// `PrivacyPreservingTransaction` is intentionally excluded: it embeds a risc0
// ZK receipt that cannot be generated inside a hot fuzzing loop.  This matches
// the known limitation documented in `docs/fuzzing.md`.

/// Newtype wrapper providing [`Arbitrary`] for [`NSSATransaction`].
///
/// Generates `Public` and `ProgramDeployment` variants only.
#[derive(Debug)]
pub struct ArbNSSATransaction(pub NSSATransaction);

impl<'a> Arbitrary<'a> for ArbNSSATransaction {
    fn arbitrary(u: &mut Unstructured<'a>) -> ArbResult<Self> {
        match u8::arbitrary(u)? % 2 {
            0 => Ok(Self(NSSATransaction::Public(
                ArbPublicTransaction::arbitrary(u)?.0,
            ))),
            _ => Ok(Self(NSSATransaction::ProgramDeployment(
                ArbProgramDeploymentTransaction::arbitrary(u)?.0,
            ))),
        }
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
        let transactions = (0..n)
            .map(|_| ArbNSSATransaction::arbitrary(u).map(|t| t.0))
            .collect::<ArbResult<Vec<_>>>()?;
        Ok(Self(HashableBlockData {
            block_id: u64::arbitrary(u)?,
            prev_block_hash: HashType(<[u8; 32]>::arbitrary(u)?),
            timestamp: u64::arbitrary(u)?,
            transactions,
        }))
    }
}
