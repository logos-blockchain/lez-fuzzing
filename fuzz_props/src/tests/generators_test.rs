//! Tests that detect mutations in `generators.rs`.

use arbitrary::Unstructured;
use nssa::{AccountId, PrivateKey};

use crate::generators::{
    FuzzAccount, arb_fuzz_native_transfer, arbitrary_fuzz_state, signer_account_ids, test_accounts,
};

/// Verifies that `signer_account_ids` returns a **non-empty** list for a properly signed
/// public transaction.
#[test]
fn signer_ids_nonempty_for_signed_public_tx() {
    let accounts = test_accounts();
    let (from_id, from_key) = &accounts[0];
    let (to_id, _) = &accounts[1];

    let tx = common::test_utils::create_transaction_native_token_transfer(
        *from_id, 0, // nonce 0 — genesis nonce for the account
        *to_id, 100, from_key,
    );

    let ids = signer_account_ids(&tx);
    assert!(
        !ids.is_empty(),
        "signer_account_ids must return at least one ID for a signed public transaction \
         (mutation: function body replaced with vec![])"
    );
}

/// Verifies that the returned signer ID matches the account that actually signed the
/// transaction — not a default/zeroed account ID.
#[test]
fn signer_ids_contains_the_signing_account() {
    let accounts = test_accounts();
    let (from_id, from_key) = &accounts[0];
    let (to_id, _) = &accounts[1];

    let tx = common::test_utils::create_transaction_native_token_transfer(
        *from_id, 0, *to_id, 100, from_key,
    );

    let ids = signer_account_ids(&tx);
    assert!(
        ids.contains(from_id),
        "signer_account_ids must contain the account ID of the private key that signed \
         the transaction; got {ids:?} but expected it to contain {from_id:?}"
    );
}

#[test]
fn fuzz_state_never_empty() {
    let buf = vec![0_u8; 1000];
    let mut u = Unstructured::new(&buf);
    let accounts = arbitrary_fuzz_state(&mut u).expect("should succeed");
    assert!(
        !accounts.is_empty(),
        "arbitrary_fuzz_state must return at least 1 account (n = 1..=8); \
         returned 0 \u{2014} mutation: `+ 1` replaced by `* 1` or `Ok(vec![])`"
    );
}

#[test]
fn fuzz_state_count_uses_modulo_not_div_or_add() {
    // fill_buffer reads from the front; the first byte is the n-selector.
    let mut buf = vec![0_u8; 1000];
    buf[0] = 8; // selector byte: 8 % 8 = 0, +1 -> n=1  |  8 / 8 = 1, +1 -> n=2  |  8 + 8 = 16, +1 -> n=17
    let mut u = Unstructured::new(&buf);
    let accounts = arbitrary_fuzz_state(&mut u).expect("should succeed");
    assert_eq!(
        accounts.len(),
        1,
        "with selector byte=8: (8 % 8) + 1 = 1 account; \
         mutation `% \u{2192} /` gives (8/8)+1=2; mutation `% \u{2192} +` gives (8+8)+1=17"
    );
}

/// Verifies that each account's balance is <= `u128::MAX / 8`.
#[test]
fn fuzz_state_balances_bounded_by_max_div_8() {
    let buf = vec![255_u8; 10_000];
    let mut u = Unstructured::new(&buf);
    // With correct division, this must NOT overflow (no panic).
    let accounts = arbitrary_fuzz_state(&mut u)
        .expect("should succeed \u{2014} no overflow with correct / 8 implementation");

    let max_balance = u128::MAX / 8;
    for acc in &accounts {
        assert!(
            acc.balance <= max_balance,
            "account balance {} exceeds u128::MAX/8={} \u{2014} \
             mutation: `/ 8` replaced by `* 8` (overflow) or `% 8`",
            acc.balance,
            max_balance
        );
    }

    // Ensures the `% 8` mutation is caught: with u128::MAX bytes, correct `/` gives a
    // large balance (u128::MAX/8 ~= 3.4e37), while `%` gives only 0-7.
    let has_large_balance = accounts.iter().any(|a| a.balance > 7);
    assert!(
        has_large_balance,
        "expected at least one account with balance > 7 \u{2014} \
         mutation: `/ 8` replaced by `% 8` (balance capped at 7)"
    );
}

#[test]
fn native_transfer_index_uses_modulo_not_div_add() {
    let accounts = vec![
        FuzzAccount {
            account_id: AccountId::new([1_u8; 32]),
            balance: 1_000_000,
            private_key: PrivateKey::try_new([1_u8; 32]).expect("scalar 1 is a valid private key"),
        },
        FuzzAccount {
            account_id: AccountId::new([2_u8; 32]),
            balance: 1_000_000,
            private_key: PrivateKey::try_new([2_u8; 32]).expect("scalar 2 is a valid private key"),
        },
    ];

    // All-0xFF bytes: the from_idx byte = 255, to_idx byte = 255.
    // 255 % 2 = 1 (in-bounds), 255 / 2 = 127 (out-of-bounds), 255 + 2 = 257 (out-of-bounds).
    let buf = vec![0xFF_u8; 500];
    let mut u = Unstructured::new(&buf);

    // With the mutated `/ 2` or `+ 2`, `accounts[127]` or `accounts[257]` panics.
    let result = arb_fuzz_native_transfer(&mut u, &accounts);
    assert!(
        result.is_ok(),
        "arb_fuzz_native_transfer should succeed with valid modulo-bounded indices; \
         mutation: `% accounts.len()` replaced by `/ accounts.len()` or `+ accounts.len()`"
    );
}
