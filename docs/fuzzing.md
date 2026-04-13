# Fuzzing Guide

This document covers how to run fuzz targets, add new targets, minimise failures,
and convert findings into regression tests.

The fuzzing infrastructure lives in a **separate repository** (`lez-fuzzing/`) which
reads the Logos Execution Zone (LEZ) codebase from `../logos-execution-zone/` (a sibling
directory that must be cloned separately).

---

## Prerequisites

```bash
# Rust nightly is required by cargo-fuzz / libFuzzer
rustup install nightly
rustup component add llvm-tools-preview --toolchain nightly

cargo install cargo-fuzz
```

---

## Repository Setup

`lez-fuzzing` is a **standalone repository** — it does **not** use git submodules.
It expects the LEZ codebase to be cloned at `../logos-execution-zone` relative to itself.

```bash
# Clone both repositories side-by-side into the same parent directory:
git clone <LEZ_REPO_URL>           logos-execution-zone
git clone <LEZ_FUZZING_REPO_URL>   lez-fuzzing

# The directory layout must be:
#   <parent>/
#   ├── logos-execution-zone/
#   └── lez-fuzzing/
```

---

## How to Run

All fuzz targets must be run with `RISC0_DEV_MODE=1` to disable expensive ZK
proof generation. The `just` recipes handle this automatically.

```bash
# From lez-fuzzing/

# Run all targets for 30 s each
just fuzz

# Run a specific target for 120 s
RISC0_DEV_MODE=1 cargo fuzz run fuzz_state_transition -- -max_total_time=120

# Run the saved corpus (regression mode, no mutations)
just fuzz-regression
```

---

## Available Fuzz Targets

| Target | What it fuzzes | Entry point |
|--------|---------------|-------------|
| `fuzz_transaction_decoding` | borsh decoding of all transaction and block types | `fuzz/fuzz_targets/fuzz_transaction_decoding.rs` |
| `fuzz_stateless_verification` | `transaction_stateless_check()` signature validation | `fuzz/fuzz_targets/fuzz_stateless_verification.rs` |
| `fuzz_state_transition` | `V03State::transition_from_*()` with invariant checks | `fuzz/fuzz_targets/fuzz_state_transition.rs` |
| `fuzz_block_verification` | Block hash integrity + replayer pipeline | `fuzz/fuzz_targets/fuzz_block_verification.rs` |

---

## How to Add a New Fuzz Target

1. Create `fuzz/fuzz_targets/fuzz_<name>.rs` using the template below.
2. Add a `[[bin]]` entry to `fuzz/Cargo.toml`.
3. Create an empty seed corpus directory: `mkdir -p fuzz/corpus/fuzz_<name>`.
4. Add the target to the CI matrix in `.github/workflows/fuzz.yml`.
5. Run `RISC0_DEV_MODE=1 cargo fuzz build fuzz_<name>` to verify it compiles.

**Template:**

```rust
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // 1. Parse / decode `data` into your target type
    // 2. Call the function under test
    // 3. Assert invariants using `fuzz_props::invariants::assert_invariants()`
    // 4. Never panic on invalid input; only panic on invariant violations
});
```

---

## Updating the LEZ Dependency

`lez-fuzzing` reads LEZ source directly from `../logos-execution-zone`. To pick up LEZ
changes, simply update that repo:

```bash
cd ../logos-execution-zone
git pull --ff-only
cd ../lez-fuzzing

# Rebuild to confirm compatibility:
cargo build -p fuzz_props
RISC0_DEV_MODE=1 cargo fuzz build
```

The `just update-lez` recipe automates the pull:

```bash
just update-lez
```

---

## Minimising & Reproducing Failures

When `cargo fuzz` finds a crash it writes an artifact to
`fuzz/artifacts/fuzz_<target>/crash-<hash>`.

### Minimise

```bash
# Produces a smaller input that still triggers the same crash
just fuzz-tmin fuzz_state_transition fuzz/artifacts/fuzz_state_transition/crash-abc123
```

### Convert to a regression test

```bash
# Print the bytes as a Rust byte-literal (paste into a #[test])
cargo fuzz fmt fuzz_state_transition fuzz/artifacts/fuzz_state_transition/crash-abc123
```

Add the minimised file to the corpus so CI always reproduces it:

```bash
cp fuzz/artifacts/fuzz_state_transition/crash-abc123-minimised \
   fuzz/corpus/fuzz_state_transition/regression_001
```

Open a PR. The `regression` CI job will permanently block re-introduction of this bug.

---

## Invariant Framework

Shared invariants live in `fuzz_props/src/invariants.rs`. Each invariant implements
`ProtocolInvariant` and is automatically run by `assert_invariants()`.

To add a new invariant:

1. Add a zero-size struct implementing `ProtocolInvariant`.
2. Register it in the `invariants` slice inside `assert_invariants()`.
3. Write a `#[test]` in `fuzz_props` that triggers and detects a synthetic violation.

---

## Performance Baseline

Measured on a 4-core x86_64 Linux runner with `RISC0_DEV_MODE=1`:

| Target | Throughput |
|--------|-----------|
| `fuzz_transaction_decoding` | ~200 000 exec/sec |
| `fuzz_stateless_verification` | ~30 000 exec/sec |
| `fuzz_state_transition` | ~5 000 exec/sec |
| `fuzz_block_verification` | ~50 000 exec/sec |

Recommended local settings for longer runs:

```bash
# Use all available cores
RISC0_DEV_MODE=1 cargo fuzz run fuzz_state_transition \
  -- -max_total_time=3600 -jobs=$(nproc) -workers=$(nproc)
```

---

## ZK-Proof Cost Warning

`PrivacyPreservingTransaction` uses `risc0-zkvm` (seconds per proof).
All fuzz targets **must** set `RISC0_DEV_MODE=1` in the environment and the `just`
recipes handle this automatically via:

```just
export RISC0_DEV_MODE := "1"
```

Do **not** invoke full proof generation inside any fuzz target. The `RISC0_DEV_MODE=1`
flag stubs out ZK proof generation and replaces it with a fast mock implementation.

---

## Input Generators

The `fuzz_props` crate (`fuzz_props/src/generators.rs`) provides reusable input
generators for both `libfuzzer` (via `arbitrary`) and `proptest`:

| Generator | Covers |
|-----------|--------|
| `arbitrary_transaction()` | IS-2: malformed + boundary transactions |
| `arb_borsh_transaction_bytes()` | IS-2: raw borsh bytes including invalid encodings |
| `arb_invalid_account_state_tx()` | IS-3: phantom accounts + overflow amounts |
| `arb_duplicate_tx_sequence()` | IS-4: duplicated + re-ordered transaction sequences |
| `arb_pathological_sequence()` | IS-5: zero-value, self-transfer, max-nonce inputs |

---

## Known Limitations & Future Work

| Item | Notes |
|------|-------|
| `PrivacyPreservingTransaction` coverage | Currently only exercised in decoding target; a dedicated slow target with `RISC0_DEV_MODE=1` and `proptest` should be added after the four MVP targets are stable |
| `V03State` snapshot equality | If `V03State` does not implement `PartialEq`/`Clone`, implement or derive them in `lez/nssa/src/state.rs` behind a `cfg(any(test, feature = "fuzzing"))` guard |
| AFL++ integration | A `just fuzz-afl` recipe can be added later; the same corpus is compatible |
| Differential testing (sequencer vs replayer) | Add a fifth target that feeds the same block to `SequencerCore` and `indexer_core` and asserts identical state roots |
| LEZ version tracking | There is no submodule pin — `lez-fuzzing` reads `../logos-execution-zone` as checked out. Update that repo to a release tag or a tested commit, then run `just update-lez` (which does `git pull --ff-only`) and open a PR to bump it. |
