use arbitrary::{Arbitrary, Unstructured};
use common::{block::HashableBlockData, transaction::NSSATransaction};
use nssa::{AccountId, PrivateKey};

use crate::arbitrary_types::ArbNSSATransaction;
use proptest::prelude::*;
use testnet_initial_state::initial_pub_accounts_private_keys;

// ── Arbitrary (for libFuzzer targets) ────────────────────────────────────────

/// A best-effort attempt to create a structurally plausible `NSSATransaction`
/// from unstructured bytes. Falls back to raw borsh decoding.
pub fn arbitrary_transaction(u: &mut Unstructured<'_>) -> arbitrary::Result<NSSATransaction> {
    // Prefer structured generation (via Arbitrary impls); raw borsh decode as fallback.
    if bool::arbitrary(u)? {
        let raw = Vec::<u8>::arbitrary(u)?;
        borsh::from_slice::<NSSATransaction>(&raw).map_err(|_| arbitrary::Error::IncorrectFormat)
    } else {
        // Use the full ArbNSSATransaction generator, which produces both Public and
        // ProgramDeployment variants with realistic account IDs, nonces, and witness sets —
        // far richer than the previous degenerate single-byte key / empty-message path.
        ArbNSSATransaction::arbitrary(u).map(|w| w.0)
    }
}

// ── proptest strategies ───────────────────────────────────────────────────────

prop_compose! {
    /// Strategy: a valid native-transfer public transaction between two known accounts.
    pub fn arb_native_transfer_tx(
        accounts: Vec<(AccountId, PrivateKey)>,
    )(
        from_idx in 0..accounts.len(),
        to_idx   in 0..accounts.len(),
        nonce    in 0u128..1_000u128,
        amount   in 0u128..10_000u128,
    ) -> NSSATransaction {
        let (from_id, from_key) = &accounts[from_idx];
        let (to_id, _)          = &accounts[to_idx];
        common::test_utils::create_transaction_native_token_transfer(
            *from_id, nonce, *to_id, amount, from_key,
        )
    }
}

/// Return the test accounts from `testnet_initial_state` as `(AccountId, PrivateKey)` pairs.
pub fn test_accounts() -> Vec<(AccountId, PrivateKey)> {
    initial_pub_accounts_private_keys()
        .into_iter()
        .map(|k| (k.account_id, k.pub_sign_key))
        .collect()
}

/// Strategy: raw bytes that are valid borsh encodings of `NSSATransaction`.
pub fn arb_borsh_transaction_bytes() -> impl Strategy<Value = Vec<u8>> {
    any::<Vec<u8>>().prop_map(|bytes| {
        // Either pass through raw bytes OR encode a known dummy transaction
        if borsh::from_slice::<NSSATransaction>(&bytes).is_ok() {
            bytes
        } else {
            borsh::to_vec(&common::test_utils::produce_dummy_empty_transaction()).unwrap()
        }
    })
}

/// Strategy: a `HashableBlockData` with 0–8 transactions.
pub fn arb_hashable_block_data() -> impl Strategy<Value = HashableBlockData> {
    let accounts = test_accounts();
    proptest::collection::vec(arb_native_transfer_tx(accounts), 0..8).prop_map(|txs| {
        HashableBlockData {
            block_id: 1,
            prev_block_hash: common::HashType([0; 32]),
            timestamp: 0,
            transactions: txs,
        }
    })
}

// ── IS-3: Invalid account / state combinations ────────────────────────────────

prop_compose! {
    /// Strategy: a transfer from an account that does not exist in the genesis state,
    /// or a transfer whose amount exceeds the sender's balance (invalid state combo).
    /// These inputs are expected to be rejected; the invariant being tested is that
    /// the state is left unchanged on rejection (StateIsolationOnFailure).
    pub fn arb_invalid_account_state_tx()(
        // Use a random 32-byte seed as a "phantom" account id not in genesis
        phantom_id_bytes in proptest::array::uniform32(0u8..),
        amount in (u128::MAX / 2)..u128::MAX,   // overflow-inducing amount
        nonce  in 0u128..10u128,
    ) -> NSSATransaction {
        let phantom_id = nssa::AccountId::new(phantom_id_bytes);
        // Attempt to sign with a key that has no matching on-chain account
        let signing_key = nssa::PrivateKey::try_new(phantom_id_bytes)
            .expect("phantom signing key");
        let (valid_to_id, _) = test_accounts()
            .into_iter()
            .next()
            .expect("at least one account");
        common::test_utils::create_transaction_native_token_transfer(
            phantom_id, nonce, valid_to_id, amount, &signing_key,
        )
    }
}

// ── IS-4: Re-ordered / duplicated inputs ─────────────────────────────────────

/// Strategy: a sequence of transactions where some are exact duplicates (replay
/// attack candidates) and some are re-ordered permutations of a valid sequence.
/// Used in proptest-level tests and as a seed generator for the state-transition
/// fuzz target.
pub fn arb_duplicate_tx_sequence() -> impl Strategy<Value = Vec<NSSATransaction>> {
    let accounts = test_accounts();
    proptest::collection::vec(arb_native_transfer_tx(accounts), 1..5_usize).prop_flat_map(|txs| {
        // Build a sequence that: original | duplicates | reversed
        let duped: Vec<NSSATransaction> = txs
            .iter()
            .cloned()
            .chain(txs.iter().cloned()) // append exact duplicates
            .chain(txs.iter().rev().cloned()) // append reversed order
            .collect();
        Just(duped)
    })
}

// ── IS-5: Pathological sequences intended to violate protocol rules ───────────

/// Strategy: sequences designed to probe boundary conditions and protocol rules:
/// - zero-value transfers (no-op drain),
/// - self-transfers (sender == recipient),
/// - max-nonce wrapping,
/// - alternating valid / invalid transactions to test partial-batch isolation.
pub fn arb_pathological_sequence() -> impl Strategy<Value = Vec<NSSATransaction>> {
    let accounts = test_accounts();
    let n = accounts.len();
    proptest::collection::vec((0..n, 0..n, 0u128..5u128, any::<bool>()), 1..8_usize).prop_map(
        move |params| {
            params
                .into_iter()
                .map(|(from_idx, to_idx, nonce, zero_amount)| {
                    let (from_id, from_key) = &accounts[from_idx];
                    let (to_id, _) = &accounts[to_idx];
                    let amount = if zero_amount { 0u128 } else { u128::MAX }; // 0 or overflow
                    common::test_utils::create_transaction_native_token_transfer(
                        *from_id, nonce, *to_id, amount, from_key,
                    )
                })
                .collect()
        },
    )
}
