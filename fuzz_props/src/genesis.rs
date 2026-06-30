//! Genesis state construction for fuzz targets and tests.
//!
//! LEZ moved builtin-program and system-account assembly out of the state machine
//! (the former `V03State::new_with_genesis_accounts`) into the `programs` /
//! `system_accounts` crates. [`genesis_state`] reproduces that genesis setup so fuzz
//! targets and tests can build a realistic starting state from arbitrary account data.

use nssa::{Account, AccountId, V03State};
use nssa_core::{Commitment, Nullifier};

/// Build a genesis [`V03State`] from the given public account balances and private accounts.
///
/// Mirrors the former `V03State::new_with_genesis_accounts(balances, private_accounts, 0)`:
/// every public account is owned by the authenticated-transfer program, the faucet/bridge/clock
/// system accounts are present, and the eight builtin programs are registered. The genesis
/// timestamp is fixed at 0, matching `system_accounts::clock_account()`'s default (every former
/// caller passed `0`).
#[must_use]
pub fn genesis_state(
    balances: &[(AccountId, u128)],
    private_accounts: Vec<(Commitment, Nullifier)>,
) -> V03State {
    let public_accounts = balances
        .iter()
        .map(|&(account_id, balance)| {
            (
                account_id,
                Account {
                    program_owner: programs::authenticated_transfer().id(),
                    balance,
                    ..Account::default()
                },
            )
        })
        .chain([
            (
                system_accounts::faucet_account_id(),
                system_accounts::faucet_account(),
            ),
            (
                system_accounts::bridge_account_id(),
                system_accounts::bridge_account(),
            ),
        ])
        .chain(
            system_accounts::clock_account_ids()
                .into_iter()
                .map(|clock_id| (clock_id, system_accounts::clock_account())),
        );

    V03State::new()
        .with_public_accounts(public_accounts)
        .with_private_accounts(private_accounts)
        .with_programs([
            programs::authenticated_transfer(),
            programs::token(),
            programs::amm(),
            programs::clock(),
            programs::ata(),
            programs::vault(),
            programs::faucet(),
            programs::bridge(),
        ])
}
