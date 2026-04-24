The project contains 9 distinct fuzz targets covering all four required categories:

**Transaction decoding / instruction parsing**
- [`fuzz_transaction_decoding.rs`](fuzz/fuzz_targets/fuzz_transaction_decoding.rs:9) — raw `&[u8]` fed to the Borsh parser for `NSSATransaction`, `Block`, and `HashableBlockData`; checks no-panic and encode/decode round-trip identity.
- [`fuzz_encoding_roundtrip.rs`](fuzz/fuzz_targets/fuzz_encoding_roundtrip.rs:15) — structured `Arbitrary` inputs through the custom `to_bytes`/`from_bytes` codec for `PublicTransaction` and `ProgramDeploymentTransaction`; different codec, different types, different invariant.

**Stateless verification checks**
- [`fuzz_stateless_verification.rs`](fuzz/fuzz_targets/fuzz_stateless_verification.rs:13) — calls the application-level `transaction_stateless_check()` and verifies idempotency (a passing check must pass a second time).
- [`fuzz_signature_verification.rs`](fuzz/fuzz_targets/fuzz_signature_verification.rs:27) — directly exercises the cryptographic primitive layer (`Signature::new` / `is_valid_for`): correctness for the signing key, no-panic on garbage bytes, no-panic on cross-key mismatch.

**State transition / execution engine**
- [`fuzz_state_transition.rs`](fuzz/fuzz_targets/fuzz_state_transition.rs:43) — multi-transaction sequences with monotonically increasing block context; asserts that a rejected transaction leaves all genesis account balances unchanged.
- [`fuzz_replay_prevention.rs`](fuzz/fuzz_targets/fuzz_replay_prevention.rs:36) — applies the same transaction twice and asserts rejection on the second application (nonce consumed after first acceptance).
- [`fuzz_state_diff_computation.rs`](fuzz/fuzz_targets/fuzz_state_diff_computation.rs:28) — exercises `ValidatedStateDiff::from_public_transaction` and verifies diff containment: only accounts declared in `affected_public_account_ids()` may appear in the diff.
- [`fuzz_validate_execute_consistency.rs`](fuzz/fuzz_targets/fuzz_validate_execute_consistency.rs:42) — runs `validate_on_state` (read-only) and `execute_check_on_state` (mutating) on cloned state and checks bidirectional agreement: same success/failure verdict, and the diff matches the actual mutations in both directions.

**Block verification / replayer logic**
- [`fuzz_block_verification.rs`](fuzz/fuzz_targets/fuzz_block_verification.rs:15) — the only block-level target; decodes raw bytes as `Block` / `HashableBlockData` and verifies that `block_hash()` never panics and is deterministic.

Each target differs in entry-point API, input shape, types under test, and the specific invariant asserted, making all nine genuinely distinct.