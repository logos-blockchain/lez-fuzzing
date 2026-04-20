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
├── scripts/
│   └── add_fuzz_target.py  # Automates new-target scaffolding (called by just new-target)
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
│   │   └── fuzz_validate_execute_consistency.rs
│   └── corpus/             # Curated seed inputs (one dir per target)
├── .github/
│   └── workflows/
│       └── fuzz.yml        # CI: smoke-fuzz · regression · proptest · perf
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
| `fuzz_transaction_decoding` | Borsh decoding of all tx/block types | `fuzz/fuzz_targets/fuzz_transaction_decoding.rs` |
| `fuzz_stateless_verification` | `transaction_stateless_check()` idempotency | `fuzz/fuzz_targets/fuzz_stateless_verification.rs` |
| `fuzz_state_transition` | `V03State` transition + state-isolation invariant | `fuzz/fuzz_targets/fuzz_state_transition.rs` |
| `fuzz_block_verification` | Block hash integrity | `fuzz/fuzz_targets/fuzz_block_verification.rs` |
| `fuzz_encoding_roundtrip` | Borsh encode→decode→encode round-trip identity | `fuzz/fuzz_targets/fuzz_encoding_roundtrip.rs` |
| `fuzz_signature_verification` | Signature creation + verification correctness and no-panic | `fuzz/fuzz_targets/fuzz_signature_verification.rs` |
| `fuzz_replay_prevention` | Transaction nonce replay rejection | `fuzz/fuzz_targets/fuzz_replay_prevention.rs` |
| `fuzz_state_diff_computation` | `ValidatedStateDiff` scope isolation (only declared accounts mutated) | `fuzz/fuzz_targets/fuzz_state_diff_computation.rs` |
| `fuzz_validate_execute_consistency` | `validate_on_state` / `execute_check_on_state` agreement + diff accuracy | `fuzz/fuzz_targets/fuzz_validate_execute_consistency.rs` |

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

GitHub Actions runs four jobs on every push/PR and nightly:

| Job | What it does |
|-----|-------------|
| `smoke-fuzz` (matrix, 9 targets) | Builds + runs each target for 60 s |
| `regression` (matrix, 9 targets) | Replays the saved corpus (`-runs=0`) |
| `proptest` | `cargo test -p fuzz_props --release` |
| `perf-baseline` (nightly only) | Measures exec/sec per target, uploads `perf_baseline.txt` |

---

## Documentation

Full developer guide — how to add new targets, interpret crashes, update
the LEZ sibling clone, and tune performance — is in
[`docs/fuzzing.md`](docs/fuzzing.md).

---

## License

Licensed under the [MIT License](LICENSE-MIT).
