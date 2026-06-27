use arbitrary::{Arbitrary, Unstructured};
use common::{block::HashableBlockData, transaction::LeeTransaction};
use nssa::{AccountId, PrivateKey};

use crate::arbitrary_types::{ArbAccountId, ArbLeeTransaction, ArbPrivateKey};
use proptest::prelude::*;
use testnet_initial_state::initial_pub_accounts_private_keys;

// ── Signer account ID extraction ─────────────────────────────────────────────

/// Extract the [`AccountId`]s of all signers from a transaction's
/// witness set.  Used by fuzz targets that need to verify nonce
/// increments after `execute_check_on_state`.
#[must_use]
pub fn signer_account_ids(tx: &common::transaction::LeeTransaction) -> Vec<nssa::AccountId> {
    use common::transaction::LeeTransaction;
    match tx {
        LeeTransaction::Public(pt) => pt
            .witness_set()
            .signatures_and_public_keys()
            .iter()
            .map(|(_, pk)| nssa::AccountId::from(pk))
            .collect(),
        LeeTransaction::PrivacyPreserving(pt) => pt
            .witness_set()
            .signatures_and_public_keys()
            .iter()
            .map(|(_, pk)| nssa::AccountId::from(pk))
            .collect(),
        LeeTransaction::ProgramDeployment(_) => vec![],
    }
}

// ── Fuzz-driven state generation ─────────────────────────────────────────────

/// An account with an arbitrary identifier, balance, and private key,
/// generated entirely from unstructured fuzzer bytes.
///
/// Using random account IDs (rather than the fixed `testnet_initial_state` set)
/// exposes state-dependent bugs that only manifest with specific account shapes —
/// for example: zero balance, [`u128::MAX`] balance, or a nonce at the
/// wrap-around boundary.  The [`PrivateKey`] field lets downstream generators
/// produce correctly-signed transfers referencing accounts present in this state.
pub struct FuzzAccount {
    pub account_id: AccountId,
    pub balance: u128,
    pub private_key: PrivateKey,
}

/// Generate 1–8 fuzz-driven accounts with arbitrary IDs, balances, and keys.
///
/// Call this before generating transactions so the constructed [`nssa::V03State`]
/// has a shape controlled by the fuzzer rather than fixed at compile time.
///
/// # Balance cap
///
/// Each account's balance is capped at `u128::MAX / 8`.  With at most 8 accounts, this
/// guarantees the sum of all balances fits in a `u128` without overflow.  Balance-
/// conservation checks can therefore use `checked_add` instead of `saturating_add` to
/// turn silent overflow into a detected violation, ruling out false-positive panics on
/// legitimate fuzz inputs.
///
/// # Reserved-ID and duplicate exclusion
///
/// The cap above is only sound if every generated balance survives genesis construction
/// unchanged.  Two failure modes break that:
///
/// * **Reserved system accounts.** [`nssa::V03State::new_with_genesis_accounts`] inserts
///   the faucet account (`balance = u128::MAX`) and bridge account *after* the supplied
///   genesis accounts, overwriting any generated account whose ID collides.  A fuzzer that
///   lands on the faucet ID would make a caller read back `u128::MAX` instead of the capped
///   balance it generated, overflowing the conservation sum — a harness false positive, not
///   a protocol bug.
/// * **Duplicate IDs.** Genesis stores accounts in a `HashMap` keyed by ID, so duplicate
///   IDs collapse to a single (last-write-wins) account, while a caller's per-ID balance sum
///   double-counts that account's balance.
///
/// Both are excluded here: generated IDs equal to a reserved system account, or already
/// seen in this state, are skipped.  The result therefore contains only distinct,
/// non-reserved IDs whose generated balances match what genesis stores — so `0..=8`
/// accounts are returned (an empty state is a valid degenerate case).
pub fn arbitrary_fuzz_state(u: &mut Unstructured<'_>) -> arbitrary::Result<Vec<FuzzAccount>> {
    let reserved = [
        nssa::system_faucet_account_id(),
        nssa::system_bridge_account_id(),
    ];
    let n = ((u8::arbitrary(u)? as usize) % 8) + 1; // 1..=8

    let mut seen = std::collections::HashSet::with_capacity(n);
    let mut accounts = Vec::with_capacity(n);
    for _ in 0..n {
        let account_id = ArbAccountId::arbitrary(u)?.0;
        // Divide by 8 so the sum of 8 accounts is at most u128::MAX, preventing
        // false-positive checked_add panics that would mask real inflation bugs.
        let balance = u128::arbitrary(u)? / 8;
        let private_key = ArbPrivateKey::arbitrary(u)?.0;

        // Skip IDs that genesis would overwrite (reserved system accounts) or that would
        // collapse on insertion (duplicates); see the doc comment above.
        if reserved.contains(&account_id) || !seen.insert(account_id) {
            continue;
        }
        accounts.push(FuzzAccount {
            account_id,
            balance,
            private_key,
        });
    }
    Ok(accounts)
}

/// Reduce raw fuzzer draws into a *biased-valid* `(nonce, amount)` pair.
///
/// The nonce is mapped into `0..=3` (near the genesis value) and the amount into
/// `0..=balance`, so the success path is actually reached. Extracted as a pure
/// function so the reduction arithmetic is unit-testable.
pub(crate) fn biased_valid_nonce_amount(
    nonce_byte: u8,
    amount_raw: u128,
    balance: u128,
) -> (u128, u128) {
    let nonce = u128::from(nonce_byte) % 4; // 0..=3
    let amount = amount_raw % balance.saturating_add(1); // 0..=balance
    (nonce, amount)
}

/// Generate a native-transfer [`LeeTransaction`] between two accounts chosen
/// from `accounts`.
///
/// Because every account in the slice has a known private key, the resulting
/// transaction is correctly signed and references account IDs that actually
/// exist in the fuzz-generated state — giving the fuzzer a direct path to
/// exercise **successful** state transitions rather than only rejection paths.
///
/// Self-transfers (`from_idx == to_idx`) are allowed since they are a useful
/// edge case (balance should remain unchanged).
///
/// The `nonce`/`amount` draw is biased toward valid inputs so the success path
/// is actually reached, with a minority branch for the rejection paths.
pub fn arb_fuzz_native_transfer(
    u: &mut Unstructured<'_>,
    accounts: &[FuzzAccount],
) -> arbitrary::Result<LeeTransaction> {
    if accounts.is_empty() {
        return Err(arbitrary::Error::IncorrectFormat);
    }
    let from_idx = (u8::arbitrary(u)? as usize) % accounts.len();
    let to_idx = (u8::arbitrary(u)? as usize) % accounts.len();

    let from = &accounts[from_idx];
    let to = &accounts[to_idx];

    let (nonce, amount) = if bool::arbitrary(u)? {
        // Biased valid: nonce near the genesis value, amount within balance.
        biased_valid_nonce_amount(u8::arbitrary(u)?, u128::arbitrary(u)?, from.balance)
    } else {
        // Adversarial: full range drives the rejection paths.
        (u128::arbitrary(u)?, u128::arbitrary(u)?)
    };

    Ok(
        common::test_utils::create_transaction_native_token_transfer(
            from.account_id,
            nonce,
            to.account_id,
            amount,
            &from.private_key,
        ),
    )
}

// ── Arbitrary (for libFuzzer targets) ────────────────────────────────────────

/// Generate a structurally plausible `LeeTransaction` from unstructured bytes.
pub fn arbitrary_transaction(u: &mut Unstructured<'_>) -> arbitrary::Result<LeeTransaction> {
    ArbLeeTransaction::arbitrary(u).map(|w| w.0)
}

// ── proptest strategies ───────────────────────────────────────────────────────

prop_compose! {
    /// Strategy: a valid native-transfer public transaction between two known accounts.
    pub fn arb_native_transfer_tx(
        accounts: Vec<(AccountId, PrivateKey)>,
    )(
        from_idx in 0..accounts.len(),
        to_idx   in 0..accounts.len(),
        nonce    in 0_u128..1_000_u128,
        amount   in 0_u128..10_000_u128,
    ) -> LeeTransaction {
        let (from_id, from_key) = &accounts[from_idx];
        let (to_id, _)          = &accounts[to_idx];
        common::test_utils::create_transaction_native_token_transfer(
            *from_id, nonce, *to_id, amount, from_key,
        )
    }
}

/// Return the test accounts from `testnet_initial_state` as `(AccountId, PrivateKey)` pairs.
#[must_use]
pub fn test_accounts() -> Vec<(AccountId, PrivateKey)> {
    initial_pub_accounts_private_keys()
        .into_iter()
        .map(|k| (k.account_id, k.pub_sign_key))
        .collect()
}

/// Strategy: raw bytes that are valid borsh encodings of `LeeTransaction`.
pub fn arb_borsh_transaction_bytes() -> impl Strategy<Value = Vec<u8>> {
    any::<Vec<u8>>().prop_map(|bytes| {
        // Either pass through raw bytes OR encode a known dummy transaction
        if borsh::from_slice::<LeeTransaction>(&bytes).is_ok() {
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
        phantom_id_bytes in proptest::array::uniform32(0_u8..),
        amount in (u128::MAX / 2)..u128::MAX,   // overflow-inducing amount
        nonce  in 0_u128..10_u128,
    ) -> LeeTransaction {
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
pub fn arb_duplicate_tx_sequence() -> impl Strategy<Value = Vec<LeeTransaction>> {
    let accounts = test_accounts();
    proptest::collection::vec(arb_native_transfer_tx(accounts), 1..5_usize).prop_flat_map(|txs| {
        // Build a sequence that: original | duplicates | reversed
        let duped: Vec<LeeTransaction> = txs
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
pub fn arb_pathological_sequence() -> impl Strategy<Value = Vec<LeeTransaction>> {
    let accounts = test_accounts();
    let n = accounts.len();
    proptest::collection::vec((0..n, 0..n, 0_u128..5_u128, any::<bool>()), 1..8_usize).prop_map(
        move |params| {
            params
                .into_iter()
                .map(|(from_idx, to_idx, nonce, zero_amount)| {
                    let (from_id, from_key) = &accounts[from_idx];
                    let (to_id, _) = &accounts[to_idx];
                    let amount = if zero_amount { 0_u128 } else { u128::MAX }; // 0 or overflow
                    common::test_utils::create_transaction_native_token_transfer(
                        *from_id, nonce, *to_id, amount, from_key,
                    )
                })
                .collect()
        },
    )
}
