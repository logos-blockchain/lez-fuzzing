//! Tests that detect mutations in `generators.rs`.

use arbitrary::Unstructured;
use nssa::{AccountId, PrivateKey};

use crate::generators::{
    FuzzAccount, arb_fuzz_native_transfer, arbitrary_fuzz_state, biased_valid_nonce_amount,
    signer_account_ids, test_accounts,
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

/// A buffer whose bytes are all distinct within any 80-byte window (the per-account
/// stride: 32 id + 16 balance + 32 key), so each generated account gets a distinct ID
/// and the dedup pass in `arbitrary_fuzz_state` does not collapse the count.  Using
/// `buf[i] = i` works because two account-ID windows starting at offsets `a` and `b`
/// (both `< 256`) are equal only when `a ≡ b (mod 256)`, which never holds for the
/// `1 + j*80` offsets of the first eight accounts.
fn distinct_byte_buffer(len: usize) -> Vec<u8> {
    (0_u8..=255).cycle().take(len).collect()
}

#[test]
fn fuzz_state_never_empty_for_distinct_ids() {
    // Selector byte 0 -> (0 % 8) + 1 = 1 account; distinct bytes keep it from being
    // deduped away.  (An all-duplicate or all-reserved draw may legitimately return
    // 0 accounts now — see `fuzz_state_dedups_account_ids` — so non-emptiness is only
    // asserted for an input that yields distinct, non-reserved IDs.)
    let buf = distinct_byte_buffer(1000);
    let mut u = Unstructured::new(&buf);
    let accounts = arbitrary_fuzz_state(&mut u).expect("should succeed");
    assert!(
        !accounts.is_empty(),
        "arbitrary_fuzz_state must return at least 1 account for distinct-ID input; \
         returned 0 \u{2014} mutation: `+ 1` replaced by `* 1` or `Ok(vec![])`"
    );
}

#[test]
fn fuzz_state_count_uses_modulo_not_div_or_add() {
    // fill_buffer reads from the front; the first byte is the n-selector.  Distinct
    // bytes give every account a unique ID so the count is not masked by dedup.
    let mut buf = distinct_byte_buffer(1000);
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

#[test]
fn fuzz_state_excludes_reserved_system_ids() {
    // Genesis overwrites the faucet (balance = u128::MAX) and bridge accounts after
    // inserting the supplied genesis accounts; a generated account colliding with one
    // would read back a balance the cap never produced, overflowing conservation sums.
    // The generator must therefore never emit a reserved system ID.
    let reserved = [
        system_accounts::faucet_account_id(),
        system_accounts::bridge_account_id(),
    ];
    let buf = distinct_byte_buffer(10_000);
    let mut u = Unstructured::new(&buf);
    let accounts = arbitrary_fuzz_state(&mut u).expect("should succeed");
    for acc in &accounts {
        assert!(
            !reserved.contains(&acc.account_id),
            "arbitrary_fuzz_state emitted reserved system account ID {:?} \u{2014} \
             genesis would overwrite it and break the balance-conservation invariant",
            acc.account_id
        );
    }
}

#[test]
fn fuzz_state_dedups_account_ids() {
    // All-identical bytes make every drawn account ID identical; genesis stores
    // accounts in a HashMap (last-write-wins), so duplicate IDs would let a per-ID
    // balance sum double-count one account.  The generator must collapse them to one.
    let buf = vec![0xAB_u8; 10_000];
    let mut u = Unstructured::new(&buf);
    let accounts = arbitrary_fuzz_state(&mut u).expect("should succeed");
    assert!(
        accounts.len() <= 1,
        "arbitrary_fuzz_state must dedup identical account IDs; got {} accounts",
        accounts.len()
    );

    // Independent confirmation on a distinct-ID draw: no ID appears twice.
    let distinct_buf = distinct_byte_buffer(10_000);
    let mut distinct_u = Unstructured::new(&distinct_buf);
    let distinct_accounts = arbitrary_fuzz_state(&mut distinct_u).expect("should succeed");
    let unique: std::collections::HashSet<_> =
        distinct_accounts.iter().map(|a| a.account_id).collect();
    assert_eq!(
        unique.len(),
        distinct_accounts.len(),
        "arbitrary_fuzz_state returned duplicate account IDs"
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

#[test]
fn biased_nonce_is_always_in_genesis_range() {
    // Every possible nonce byte must reduce into 0..=3. This rules out the
    // `/` and `+` variants of the `% 4` reduction, which escape that range.
    for byte in 0..=u8::MAX {
        let (nonce, _) = biased_valid_nonce_amount(byte, 0, 0);
        assert!(
            nonce <= 3,
            "byte {byte} produced out-of-range nonce {nonce}"
        );
    }
}

#[test]
fn biased_nonce_wraps_modulo_four() {
    // Pin specific residues so `/ 4` (→1, →63) and `+ 4` (→8, →259) both fail.
    assert_eq!(biased_valid_nonce_amount(4, 0, 0).0, 0);
    assert_eq!(biased_valid_nonce_amount(255, 0, 0).0, 3);
    assert_eq!(biased_valid_nonce_amount(7, 0, 0).0, 3);
}

#[test]
fn biased_amount_never_exceeds_balance() {
    for balance in [0_u128, 1, 100, u128::MAX] {
        for amount_raw in [0_u128, 1, balance, balance.wrapping_add(1), u128::MAX] {
            let (_, amount) = biased_valid_nonce_amount(0, amount_raw, balance);
            assert!(
                amount <= balance,
                "amount {amount} exceeded balance {balance} (raw {amount_raw})"
            );
        }
    }
}

#[test]
fn biased_amount_wraps_modulo_balance_plus_one() {
    // `10 % 101 == 10` but `10 / 101 == 0`, so this kills the `/` variant.
    assert_eq!(biased_valid_nonce_amount(0, 10, 100).1, 10);
    // balance 0 → modulus 1 → amount always 0.
    assert_eq!(biased_valid_nonce_amount(0, u128::MAX, 0).1, 0);
}
