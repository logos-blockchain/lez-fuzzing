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
/// Mirrors `testnet_initial_state::initial_state(false)` with fuzz-supplied user accounts:
/// every public account holds its balance in the native-token shard, the bridge/clock/
/// sequencer-stake/fee system accounts are present, and the seven non-cross-zone builtin
/// programs are registered at their name-derived addresses. The genesis timestamp is fixed
/// at 0, matching `system_accounts::clock_account()`'s default.
#[must_use]
pub fn genesis_state(
    balances: &[(AccountId, u128)],
    private_accounts: Vec<(Commitment, Nullifier)>,
) -> V03State {
    let public_accounts = balances
        .iter()
        .map(|&(account_id, balance)| (account_id, Account::funded(balance)))
        .chain([(
            system_accounts::bridge_account_id(),
            system_accounts::bridge_account(),
        )])
        .chain(
            system_accounts::clock_account_ids()
                .into_iter()
                .map(|clock_id| (clock_id, system_accounts::clock_account())),
        )
        .chain([
            (
                system_accounts::sequencer_stake_config_account_id(),
                system_accounts::sequencer_stake_config_account(None, None),
            ),
            (
                system_accounts::fee_state_account_id(),
                system_accounts::fee_state_account(),
            ),
            (system_accounts::fee_escrow_account_id(), Account::default()),
            (system_accounts::fee_inbox_account_id(), Account::default()),
        ]);

    V03State::new()
        .with_public_accounts(public_accounts)
        .with_private_accounts(private_accounts)
        .with_named_programs([
            (programs::token_account_id(), programs::token()),
            (programs::amm_account_id(), programs::amm()),
            (programs::clock_account_id(), programs::clock()),
            (programs::fee_account_id(), programs::fee()),
            (programs::ata_account_id(), programs::ata()),
            (programs::bridge_account_id(), programs::bridge()),
            (
                programs::sequencer_stake_account_id(),
                programs::sequencer_stake(),
            ),
        ])
}

/// Public account ids that [`genesis_state`] populates itself. A fuzz-generated account
/// landing on one of these would be overwritten at genesis, so generators exclude them.
#[must_use]
pub fn reserved_account_ids() -> Vec<AccountId> {
    [
        system_accounts::bridge_account_id(),
        system_accounts::sequencer_stake_config_account_id(),
    ]
    .into_iter()
    .chain(system_accounts::clock_account_ids())
    .chain(system_accounts::fee_account_ids())
    .collect()
}
