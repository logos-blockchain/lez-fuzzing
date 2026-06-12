# Lez-fuzzing

Coverage-guided fuzzing and adversarial testing infrastructure for the
**Logos Execution Zone (LEZ)** protocol.

---

## Repository Layout

```
lez-fuzzing/
├── Cargo.toml              # Workspace root (members: fuzz_props)
├── Justfile                # Turn-key entry-points
├── rust-toolchain.toml     # Pins Rust nightly (required by cargo-fuzz)
├── .gitignore
├── fuzz_props/             # Shared invariant framework + input generators
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs
│       ├── arbitrary_types.rs  # Arbitrary impl wrappers for LEZ types (libFuzzer)
│       ├── invariants.rs       # ProtocolInvariant trait + concrete invariants
│       └── generators.rs       # Arbitrary / proptest strategies
├── fuzz/                   # cargo-fuzz crate (own [workspace] sentinel)
│   ├── Cargo.toml
│   ├── fuzz_targets/
│   │   ├── _template.rs                        # Template for just new-target
│   │   ├── fuzz_transaction_decoding.rs
│   │   ├── fuzz_stateless_verification.rs
│   │   ├── fuzz_state_transition.rs
│   │   ├── fuzz_block_verification.rs
│   │   ├── fuzz_encoding_roundtrip.rs
│   │   ├── fuzz_signature_verification.rs
│   │   ├── fuzz_replay_prevention.rs
│   │   ├── fuzz_state_diff_computation.rs
│   │   ├── fuzz_validate_execute_consistency.rs
│   │   ├── fuzz_state_serialization.rs
│   │   ├── fuzz_witness_set_verification.rs
│   │   ├── fuzz_program_deployment_lifecycle.rs
│   │   ├── fuzz_apply_state_diff_split_path.rs
│   │   ├── fuzz_multi_block_state_sequence.rs
│   │   ├── fuzz_sequencer_vs_replayer.rs
│   │   ├── fuzz_merkle_tree.rs
│   │   ├── fuzz_transaction_properties.rs
│   │   ├── fuzz_privacy_preserving_witness.rs
│   │   ├── fuzz_encoding_privacy_preserving.rs
│   │   └── fuzz_nullifier_set_roundtrip.rs   # 20 targets total — see table below
│   └── corpus/             # Curated seed inputs (one dir per target)
├── .github/
│   └── workflows/
│       ├── fuzz.yml        # CI: smoke-fuzz · regression · proptest · perf (libFuzzer)
│       ├── fuzz-afl.yml    # CI: AFL++ lane
│       ├── mutants.yml     # CI: mutation testing (cargo-mutants)
│       └── lint.yml        # CI: fmt + clippy
├── scripts/
│   └── add_fuzz_target.py  # Automates new-target scaffolding (called by just new-target)
└── docs/
    └── fuzzing.md          # Full developer guide
```

The LEZ codebase is consumed as a **sibling directory** — clone
`logos-execution-zone` next to this repository:

```
parent/
├── lez-fuzzing/            ← this repo
└── logos-execution-zone/   ← LEZ codebase (path deps resolve via ../)
```

---

## Quick Start

### Prerequisites

```bash
rustup install nightly
rustup component add llvm-tools-preview --toolchain nightly
cargo install cargo-fuzz
# Optional but recommended:
cargo install just
```

> **Why nightly?** `cargo-fuzz` passes `-Zsanitizer=address` and
> `-Zinstrument-coverage` (unstable flags) to `rustc`, and depends on the
> `llvm-tools-preview` nightly component for coverage reporting. The
> `rust-toolchain.toml` pins the whole repository to nightly so you never
> need an explicit `+nightly` flag.

### Setup

```bash
# Clone both repositories side by side
git clone <LEZ_REPO_URL> logos-execution-zone
git clone <LEZ_FUZZING_REPO_URL> lez-fuzzing
cd lez-fuzzing
```

### Run the fuzz targets

```bash
# All targets for 30 s each (RISC0_DEV_MODE=1 is set automatically)
just fuzz

# Specific duration
just fuzz 120

# Single target
RISC0_DEV_MODE=1 cargo fuzz run fuzz_state_transition -- -max_total_time=120

# Corpus regression (replay saved corpus, no mutations)
just fuzz-regression

# Property-based tests only (no libFuzzer)
just fuzz-props
```

> **ZK-proof cost:** `RISC0_DEV_MODE=1` is exported at the top of the
> `Justfile` and must be set in every fuzz run to stub out ZK proof
> generation. Without it each execution takes seconds instead of
> microseconds.

---

## Fuzz Targets

| Target | Protocol layer | Entry point |
|--------|---------------|-------------|
| `fuzz_transaction_decoding` | Borsh decoding of all tx/block types (`LeeTransaction`, `Block`, `HashableBlockData`) with roundtrip re-encoding | `fuzz/fuzz_targets/fuzz_transaction_decoding.rs` |
| `fuzz_stateless_verification` | `transaction_stateless_check()` no-panic + idempotency | `fuzz/fuzz_targets/fuzz_stateless_verification.rs` |
| `fuzz_state_transition` | `V03State` transition: StateIsolationOnFailure + BalanceConservation + ReplayRejection invariants across up to 8 txs with fuzz-driven state | `fuzz/fuzz_targets/fuzz_state_transition.rs` |
| `fuzz_block_verification` | Block hash integrity: HashRoundTrip · HashPreimage completeness (block_id/prev_hash/timestamp) · TxOrderCommitment | `fuzz/fuzz_targets/fuzz_block_verification.rs` |
| `fuzz_encoding_roundtrip` | Borsh encode→decode→encode round-trip identity + canonical encoding for `PublicTransaction` and `ProgramDeploymentTransaction` | `fuzz/fuzz_targets/fuzz_encoding_roundtrip.rs` |
| `fuzz_signature_verification` | Signature correctness (sign→verify), no-panic on random bytes, cross-key soundness | `fuzz/fuzz_targets/fuzz_signature_verification.rs` |
| `fuzz_replay_prevention` | Transaction nonce replay rejection with fuzz-driven initial state | `fuzz/fuzz_targets/fuzz_replay_prevention.rs` |
| `fuzz_state_diff_computation` | `ValidatedStateDiff` forward containment + reverse completeness (bidirectional isolation check) | `fuzz/fuzz_targets/fuzz_state_diff_computation.rs` |
| `fuzz_validate_execute_consistency` | `validate_on_state` / `execute_check_on_state` agreement + diff accuracy + BalanceConservation | `fuzz/fuzz_targets/fuzz_validate_execute_consistency.rs` |
| `fuzz_state_serialization` | `V03State` Borsh decode no-panic + StateSerializationRoundtrip idempotency + NullifierDeduplication (`NullifierSet` hand-written impl) | `fuzz/fuzz_targets/fuzz_state_serialization.rs` |
| `fuzz_witness_set_verification` | `WitnessSet::is_valid_for` no-panic + CorrectVerification (sign→verify) + MessageIsolation (witness set for msg A rejected on msg B) | `fuzz/fuzz_targets/fuzz_witness_set_verification.rs` |
| `fuzz_program_deployment_lifecycle` | `V03State::transition_from_program_deployment_transaction` no-panic + BalanceIsolation (deployment must not move tokens) + StateIsolationOnFailure | `fuzz/fuzz_targets/fuzz_program_deployment_lifecycle.rs` |
| `fuzz_apply_state_diff_split_path` | SplitPathEquivalence: `validate_on_state + apply_state_diff` == `execute_check_on_state` for all known accounts (balance, nonce, data, program_owner); NonceIncrementCorrectness | `fuzz/fuzz_targets/fuzz_apply_state_diff_split_path.rs` |
| `fuzz_multi_block_state_sequence` | LongRangeBalanceConservation across up to 16 blocks + FailedTxNonceStability (nonce must not change on rejection) + PerBlockReplayRejection | `fuzz/fuzz_targets/fuzz_multi_block_state_sequence.rs` |
| `fuzz_sequencer_vs_replayer` | Differential: sequencer path (`validate_on_state` → `apply_state_diff`) vs replayer path (`execute_check_on_state`) — SequencerReplayerEquivalence + ReplayerAcceptsAllSequencerTxs + ClockConsistency | `fuzz/fuzz_targets/fuzz_sequencer_vs_replayer.rs` |
| `fuzz_merkle_tree` | Commitment Merkle tree via the commitment set: ProofSome · ProofValid (leaf + auth path recomputes the root) · NonMembershipNone · IndicesSequential | `fuzz/fuzz_targets/fuzz_merkle_tree.rs` |
| `fuzz_transaction_properties` | Transaction property invariants: HashDeterministic/HashNonDefault, SignerIds derived from witness keys & non-empty, AffectedAccountsContainSigners, PublicDiffNonEmptyOnSuccess | `fuzz/fuzz_targets/fuzz_transaction_properties.rs` |
| `fuzz_privacy_preserving_witness` | `privacy_preserving_transaction::WitnessSet`: CorrectVerification (witness for msg A passes `signatures_are_valid_for(A)`) + MessageIsolation + SignerIdsMatchWitnessKeys | `fuzz/fuzz_targets/fuzz_privacy_preserving_witness.rs` |
| `fuzz_encoding_privacy_preserving` | Privacy-preserving encoding: MessageEncodingRoundtrip + TxEncodingDeterministic/NonEmpty | `fuzz/fuzz_targets/fuzz_encoding_privacy_preserving.rs` |
| `fuzz_nullifier_set_roundtrip` | `NullifierSet` Borsh serialisation: NullifierSetRoundtrip (decode→encode identity for the hand-written impl) | `fuzz/fuzz_targets/fuzz_nullifier_set_roundtrip.rs` |

> **Input-independent checks are not fuzz targets here.** Deterministic invariants
> that ignore their input (e.g. genesis-account contents, getter/round-trip
> identities, the system-account-modification guard) belong in `logos-execution-zone`
> unit tests, not the fuzz corpus. See
> [`docs/mutants-not-fuzzable.md`](docs/mutants-not-fuzzable.md) for the policy and
> the mutant→test mapping.

---

## Corpus Management

```bash
# Minimise all corpora (removes dominated inputs, keeps coverage-equivalent set)
just corpus-cmin

# Minimise a single target's corpus
just corpus-cmin-target fuzz_state_transition
```

---

## Crash / Failure Workflow

```bash
# Minimise a crash artifact
just fuzz-tmin fuzz_state_transition fuzz/artifacts/fuzz_state_transition/crash-abc123

# Print the bytes as a Rust literal (for a regression #[test])
cargo fuzz fmt fuzz_state_transition fuzz/artifacts/fuzz_state_transition/crash-abc123

# Promote the minimised input to the corpus so CI catches regressions
cp fuzz/artifacts/fuzz_state_transition/crash-abc123-minimised \
   fuzz/corpus/fuzz_state_transition/regression_001
```

---

## Adding a New Target

```bash
# Scaffold everything automatically (corpus dir, .rs file, Cargo.toml entry, CI matrix entry)
just new-target my_feature   # creates fuzz_my_feature
```

`just new-target` calls [`scripts/add_fuzz_target.py`](scripts/add_fuzz_target.py) which
appends the `[[bin]]` entry to [`fuzz/Cargo.toml`](fuzz/Cargo.toml) and inserts the target
into every strategy matrix in [`.github/workflows/fuzz.yml`](.github/workflows/fuzz.yml).

---

## Housekeeping

```bash
just clean            # Remove Cargo build artefacts (target/ and fuzz/target/)
just clean-artifacts  # Remove fuzz/artifacts/  (crash/timeout inputs)
just clean-coverage   # Remove fuzz/coverage/   (LLVM coverage reports)
just clean-all        # All of the above
```

---

## CI

GitHub Actions runs these workflows on every push/PR and nightly:

| Workflow | What it does |
|----------|-------------|
| `fuzz.yml` — `smoke-fuzz` (matrix) | Builds + runs each libFuzzer target for 60 s |
| `fuzz.yml` — `regression` (matrix) | Replays the saved corpus (`-runs=0`) |
| `fuzz.yml` — `proptest` | `cargo test -p fuzz_props --release` |
| `fuzz.yml` — `perf-baseline` (nightly only) | Measures exec/sec per target, uploads `perf_baseline.txt` |
| `fuzz-afl.yml` | AFL++ lane over the same targets/corpus |
| `mutants.yml` | Mutation testing (`cargo-mutants`) |
| `lint.yml` | Formatting + Clippy |

> **Note:** The `fuzz.yml` matrix currently lists 15 of the 20 libFuzzer targets.
> Still missing: `fuzz_merkle_tree`, `fuzz_transaction_properties`,
> `fuzz_privacy_preserving_witness`, `fuzz_encoding_privacy_preserving`, and
> `fuzz_nullifier_set_roundtrip` — add them to `.github/workflows/fuzz.yml`. See
> [`docs/fuzzing.md`](docs/fuzzing.md) for the manual fallback instructions.

---

## Documentation

Full developer guide — how to add new targets, interpret crashes, update
the LEZ sibling clone, and tune performance — is in
[`docs/fuzzing.md`](docs/fuzzing.md).

---

## License

Licensed under the [MIT License](LICENSE-MIT).
