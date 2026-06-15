<div align="center">

# <img src="logos.avif" alt="" height="32" valign="middle"> Lez-fuzzing

**Coverage-guided fuzzing & adversarial testing infrastructure for the
[Logos Execution Zone (LEZ)](https://github.com/) protocol.**

[![Rust](https://img.shields.io/badge/rust-nightly-orange?logo=rust)](rust-toolchain.toml)
[![Fuzzing](https://img.shields.io/badge/libFuzzer%20%C2%B7%20AFL%2B%2B-20%20targets-blue)](#-fuzz-targets)
[![Mutation testing](https://img.shields.io/badge/cargo--mutants-enabled-green)](.github/workflows/mutants.yml)
[![License](https://img.shields.io/badge/license-MIT-lightgrey)](LICENSE-MIT)

</div>

---

## 📂 Repository Layout

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
│   ├── fuzz_targets/       # 20 targets total — see table below
│   │   ├── _template.rs    # Template for `just new-target`
│   │   └── fuzz_*.rs
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
    ├── fuzzing.md              # Full developer guide
    └── mutants-not-fuzzable.md # Policy + mutant→test mapping
```

The LEZ codebase is consumed as a **sibling directory** — clone
`logos-execution-zone` next to this repository so the `../` path deps resolve:

```
parent/
├── lez-fuzzing/            ← this repo
└── logos-execution-zone/   ← LEZ codebase (path deps resolve via ../)
```

---

## 🚀 Quick Start

### 1. Prerequisites

```bash
rustup install nightly
rustup component add llvm-tools-preview --toolchain nightly
cargo install cargo-fuzz
cargo install just            # optional but recommended
```

### 2. Setup

```bash
# Clone both repositories side by side
git clone <LEZ_REPO_URL> logos-execution-zone
git clone <LEZ_FUZZING_REPO_URL> lez-fuzzing
cd lez-fuzzing
```

### 3. Run the fuzz targets

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

> [!IMPORTANT]
> **ZK-proof cost:** `RISC0_DEV_MODE=1` is exported at the top of the
> `Justfile` and must be set in every fuzz run to stub out ZK proof
> generation. Without it, each execution takes **seconds** instead of
> **microseconds**.

---

## 🎯 Fuzz Targets

| # | Target | Protocol layer |
|---|--------|----------------|
| 1 | `fuzz_transaction_decoding` | Borsh decoding of all tx/block types (`LeeTransaction`, `Block`, `HashableBlockData`) with roundtrip re-encoding |
| 2 | `fuzz_stateless_verification` | `transaction_stateless_check()` no-panic + idempotency |
| 3 | `fuzz_state_transition` | `V03State` transition: StateIsolationOnFailure + BalanceConservation + ReplayRejection invariants across up to 8 txs with fuzz-driven state |
| 4 | `fuzz_block_verification` | Block hash integrity: HashRoundTrip · HashPreimage completeness (block_id/prev_hash/timestamp) · TxOrderCommitment |
| 5 | `fuzz_encoding_roundtrip` | Borsh encode→decode→encode round-trip identity + canonical encoding for `PublicTransaction` and `ProgramDeploymentTransaction` |
| 6 | `fuzz_signature_verification` | Signature correctness (sign→verify), no-panic on random bytes, cross-key soundness |
| 7 | `fuzz_replay_prevention` | Transaction nonce replay rejection with fuzz-driven initial state |
| 8 | `fuzz_state_diff_computation` | `ValidatedStateDiff` forward containment + reverse completeness (bidirectional isolation check) |
| 9 | `fuzz_validate_execute_consistency` | `validate_on_state` / `execute_check_on_state` agreement + diff accuracy + BalanceConservation |
| 10 | `fuzz_state_serialization` | `V03State` Borsh decode no-panic + StateSerializationRoundtrip idempotency + NullifierDeduplication (`NullifierSet` hand-written impl) |
| 11 | `fuzz_witness_set_verification` | `WitnessSet::is_valid_for` no-panic + CorrectVerification (sign→verify) + MessageIsolation (witness set for msg A rejected on msg B) |
| 12 | `fuzz_program_deployment_lifecycle` | `V03State::transition_from_program_deployment_transaction` no-panic + BalanceIsolation (deployment must not move tokens) + StateIsolationOnFailure |
| 13 | `fuzz_apply_state_diff_split_path` | SplitPathEquivalence: `validate_on_state + apply_state_diff` == `execute_check_on_state` for all known accounts (balance, nonce, data, program_owner); NonceIncrementCorrectness |
| 14 | `fuzz_multi_block_state_sequence` | LongRangeBalanceConservation across up to 16 blocks + FailedTxNonceStability (nonce must not change on rejection) + PerBlockReplayRejection |
| 15 | `fuzz_sequencer_vs_replayer` | Differential: sequencer path (`validate_on_state` → `apply_state_diff`) vs replayer path (`execute_check_on_state`) — SequencerReplayerEquivalence + ReplayerAcceptsAllSequencerTxs + ClockConsistency |
| 16 | `fuzz_merkle_tree` | Commitment Merkle tree via the commitment set: ProofSome · ProofValid (leaf + auth path recomputes the root) · NonMembershipNone · IndicesSequential |
| 17 | `fuzz_transaction_properties` | Transaction property invariants: HashDeterministic/HashNonDefault, SignerIds derived from witness keys & non-empty, AffectedAccountsContainSigners, PublicDiffNonEmptyOnSuccess |
| 18 | `fuzz_privacy_preserving_witness` | `privacy_preserving_transaction::WitnessSet`: CorrectVerification (witness for msg A passes `signatures_are_valid_for(A)`) + MessageIsolation + SignerIdsMatchWitnessKeys |
| 19 | `fuzz_encoding_privacy_preserving` | Privacy-preserving encoding: MessageEncodingRoundtrip + TxEncodingDeterministic/NonEmpty |
| 20 | `fuzz_nullifier_set_roundtrip` | `NullifierSet` Borsh serialisation: NullifierSetRoundtrip (decode→encode identity for the hand-written impl) |

Each target lives at `fuzz/fuzz_targets/<name>.rs`.

---

## 🧬 Corpus Management

```bash
# Minimise all corpora (removes dominated inputs, keeps coverage-equivalent set)
just corpus-cmin

# Minimise a single target's corpus
just corpus-cmin-target fuzz_state_transition
```

---

## 💥 Crash / Failure Workflow

```bash
# 1. Minimise a crash artifact
just fuzz-tmin fuzz_state_transition fuzz/artifacts/fuzz_state_transition/crash-abc123

# 2. Print the bytes as a Rust literal (for a regression #[test])
cargo fuzz fmt fuzz_state_transition fuzz/artifacts/fuzz_state_transition/crash-abc123

# 3. Promote the minimised input to the corpus so CI catches regressions
cp fuzz/artifacts/fuzz_state_transition/crash-abc123-minimised \
   fuzz/corpus/fuzz_state_transition/regression_001
```

---

## ➕ Adding a New Target

```bash
# Scaffold everything automatically (corpus dir, .rs file, Cargo.toml entry, CI matrix entry)
just new-target my_feature   # creates fuzz_my_feature
```

`just new-target` calls [`scripts/add_fuzz_target.py`](scripts/add_fuzz_target.py), which
appends the `[[bin]]` entry to [`fuzz/Cargo.toml`](fuzz/Cargo.toml) and inserts the target
into every strategy matrix in [`.github/workflows/fuzz.yml`](.github/workflows/fuzz.yml).

---

## 🧹 Housekeeping

| Command | Removes |
|---------|---------|
| `just clean` | Cargo build artefacts (`target/` and `fuzz/target/`) |
| `just clean-artifacts` | `fuzz/artifacts/` (crash/timeout inputs) |
| `just clean-coverage` | `fuzz/coverage/` (LLVM coverage reports) |
| `just clean-all` | All of the above |

---

## ⚙️ CI

GitHub Actions runs these workflows on every push/PR and nightly:

| Workflow | What it does |
|----------|--------------|
| `fuzz.yml` — `smoke-fuzz` (matrix) | Builds + runs each libFuzzer target for 60 s |
| `fuzz.yml` — `regression` (matrix) | Replays the saved corpus (`-runs=0`) |
| `fuzz.yml` — `proptest` | `cargo test -p fuzz_props --release` |
| `fuzz.yml` — `perf-baseline` (nightly only) | Measures exec/sec per target, uploads `perf_baseline.txt` |
| `fuzz-afl.yml` | AFL++ lane over the same targets/corpus |
| `mutants.yml` | Mutation testing (`cargo-mutants`) |
| `lint.yml` | Formatting + Clippy |

---

## 📖 Documentation

The full developer guide — how to add new targets, interpret crashes, update
the LEZ sibling clone, and tune performance — lives in
[`docs/fuzzing.md`](docs/fuzzing.md).

---

## 📜 License

Licensed under the [MIT License](LICENSE-MIT).
