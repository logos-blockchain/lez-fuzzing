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
| `fuzz_transaction_decoding` | Borsh decoding of `NSSATransaction`, `Block`, and `HashableBlockData`; roundtrip re-encoding of successfully decoded transactions | `fuzz/fuzz_targets/fuzz_transaction_decoding.rs` |
| `fuzz_stateless_verification` | `transaction_stateless_check()` no-panic on arbitrary bytes; idempotency — a transaction that passes the check must pass it again | `fuzz/fuzz_targets/fuzz_stateless_verification.rs` |
| `fuzz_state_transition` | `execute_check_on_state()` across up to 8 transactions with monotonically-advancing block context; asserts balance isolation on rejection | `fuzz/fuzz_targets/fuzz_state_transition.rs` |
| `fuzz_block_verification` | `block_hash()` no-panic and determinism — recomputing the hash of any fuzz-generated `Block` must never panic and must return the same value on repeated calls | `fuzz/fuzz_targets/fuzz_block_verification.rs` |
| `fuzz_encoding_roundtrip` | `decode(encode(tx)) == Ok(tx)` and `encode(decode(encode(tx))) == encode(tx)` for `PublicTransaction` and `ProgramDeploymentTransaction` | `fuzz/fuzz_targets/fuzz_encoding_roundtrip.rs` |
| `fuzz_signature_verification` | Signature correctness (sign→verify), no-panic on random bytes, cross-key soundness | `fuzz/fuzz_targets/fuzz_signature_verification.rs` |
| `fuzz_replay_prevention` | A tx accepted in block N must be rejected when replayed in block N+1 (nonce consumed) | `fuzz/fuzz_targets/fuzz_replay_prevention.rs` |
| `fuzz_state_diff_computation` | `ValidatedStateDiff` only modifies accounts declared in `affected_public_account_ids()` | `fuzz/fuzz_targets/fuzz_state_diff_computation.rs` |
| `fuzz_validate_execute_consistency` | `validate_on_state` and `execute_check_on_state` must agree on success/failure and produce identical state changes | `fuzz/fuzz_targets/fuzz_validate_execute_consistency.rs` |

---

## How to Add a New Fuzz Target

### Step 1 — Scaffold with `just new-target`

```bash
just new-target my_feature
```

This single command does four things automatically:

| What | Where |
|---|---|
| Creates the corpus directory | `fuzz/corpus/fuzz_my_feature/` |
| Writes a typed fuzz target template | `fuzz/fuzz_targets/fuzz_my_feature.rs` |
| Appends `[[bin]]` entry | `fuzz/Cargo.toml` |
| Inserts target into every CI matrix + perf loop | `.github/workflows/fuzz.yml` |

The generated template uses `ArbNSSATransaction` from `fuzz_props::arbitrary_types`
so libfuzzer drives every field of `NSSATransaction` independently — no manual
`Unstructured` wiring required.

### Step 2 — Implement the target

Edit `fuzz/fuzz_targets/fuzz_my_feature.rs`.  Replace the placeholder with the
function under test and any invariant assertions.  Use the typed wrappers from
[`fuzz_props::arbitrary_types`](../fuzz_props/src/arbitrary_types.rs) for
structured input, or the proptest generators from
[`fuzz_props::generators`](../fuzz_props/src/generators.rs) for richer strategies.

### Step 3 — Register the binary (automated)

`just new-target` calls [`scripts/add_fuzz_target.py`](../scripts/add_fuzz_target.py)
which appends the `[[bin]]` entry to [`fuzz/Cargo.toml`](../fuzz/Cargo.toml)
automatically. Once present, `cargo fuzz list` (and therefore `just fuzz`,
`just fuzz-regression`, `just corpus-cmin`) pick up the target automatically — no
further Justfile edits required.

> **Manual fallback:** if you create a target without `just new-target`, add the
> entry yourself:
>
> ```toml
> [[bin]]
> name = "fuzz_my_feature"
> path = "fuzz_targets/fuzz_my_feature.rs"
> test = false
> bench = false
> ```

### Step 4 — Add to CI matrix (automated)

`just new-target` also inserts `fuzz_my_feature` into every strategy matrix and the
perf-baseline shell loop in [`.github/workflows/fuzz.yml`](../.github/workflows/fuzz.yml)
automatically via `scripts/add_fuzz_target.py`.

> **Manual fallback:** if you created the target without `just new-target`, add
> `- fuzz_my_feature` to the `target:` list in the three places shown in
> `.github/workflows/fuzz.yml` (smoke-fuzz, regression, perf-baseline).

### Step 5 — Verify

```bash
RISC0_DEV_MODE=1 cargo fuzz build fuzz_my_feature
just fuzz-regression   # runs the new target against its (empty) corpus
```

### Quick reference: what to touch

| File | Action | Automated? |
|---|---|---|
| `fuzz/fuzz_targets/fuzz_<name>.rs` | Create | ✅ `just new-target` |
| `fuzz/corpus/fuzz_<name>/` | Create | ✅ `just new-target` |
| `fuzz/Cargo.toml` | Add `[[bin]]` | ✅ `just new-target` |
| `Justfile` | Nothing — auto-discovers | ✅ automatic |
| `.github/workflows/fuzz.yml` | Add to 3 matrix lists | ✅ `just new-target` |

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

Concrete invariants currently registered:

| Invariant | Description |
|-----------|-------------|
| `StateIsolationOnFailure` | Account balances must not change when a transaction is rejected |
| `ReplayRejection` | An accepted transaction must be rejected when replayed (see `fuzz_replay_prevention`) |

To add a new invariant:

1. Add a zero-size struct implementing `ProtocolInvariant`.
2. Register it in the `invariants` slice inside `assert_invariants()`.
3. Write a `#[test]` in `fuzz_props` that triggers and detects a synthetic violation.

---

## Input Generators

The `fuzz_props` crate provides two layers of input generation:

### `fuzz_props::arbitrary_types` (libFuzzer / `Arbitrary`)

Typed wrappers that implement `Arbitrary` for LEZ structs.  Use them directly as
fuzz target parameters for zero-boilerplate structured fuzzing.

| Wrapper | Wraps |
|---------|-------|
| `ArbAccountId` | `AccountId` (any 32-byte array) |
| `ArbNonce` | `Nonce` (any `u128`) |
| `ArbPrivateKey` | `PrivateKey` (valid scalar; known-good fallback for the negligible invalid range) |
| `ArbPublicKey` | `PublicKey` (50 % derived from a valid private key; 50 % raw bytes with fallback) |
| `ArbSignature` | `Signature` (random 64-byte value; may be cryptographically invalid) |
| `ArbPubTxMessage` | `Message` for `PublicTransaction` (0–7 accounts, arbitrary instruction data) |
| `ArbWitnessSet` | `WitnessSet` (0–3 `(Signature, PublicKey)` pairs; mixes valid and invalid) |
| `ArbPublicTransaction` | `PublicTransaction` (composed from `ArbPubTxMessage` + `ArbWitnessSet`) |
| `ArbProgramDeploymentTransaction` | `ProgramDeploymentTransaction` (arbitrary bytecode) |
| `ArbHashableBlockData` | `HashableBlockData` (0–7 `ArbNSSATransaction` entries, random header fields) |
| `ArbNSSATransaction` | `NSSATransaction` (`Public` or `ProgramDeployment` variant; `PrivacyPreserving` excluded) |

### `fuzz_props::generators` (proptest strategies + libFuzzer helpers)

| Generator | Covers |
|-----------|--------|
| `arbitrary_transaction()` | Best-effort structured `NSSATransaction` from unstructured bytes, falls back to raw Borsh decode |
| `arb_borsh_transaction_bytes()` | Raw Borsh bytes including invalid encodings (IS-2) |
| `arb_native_transfer_tx()` | Valid native-transfer `NSSATransaction` between known genesis accounts |
| `test_accounts()` | Returns `(AccountId, PrivateKey)` pairs from `testnet_initial_state` |
| `arb_hashable_block_data()` | `HashableBlockData` with 0–8 valid native transfers |
| `arb_invalid_account_state_tx()` | Phantom accounts + overflow amounts — expected to be rejected (IS-3) |
| `arb_duplicate_tx_sequence()` | Duplicated + re-ordered transaction sequences (IS-4) |
| `arb_pathological_sequence()` | Zero-value, self-transfer, max-nonce inputs (IS-5) |

---

## Performance Baseline

Measured on a 4-core x86_64 Linux runner with `RISC0_DEV_MODE=1`:

| Target | Throughput |
|--------|-----------|
| `fuzz_transaction_decoding` | ~200 000 exec/sec |
| `fuzz_stateless_verification` | ~30 000 exec/sec |
| `fuzz_state_transition` | ~5 000 exec/sec |
| `fuzz_block_verification` | ~50 000 exec/sec |
| `fuzz_encoding_roundtrip` | ~150 000 exec/sec |
| `fuzz_signature_verification` | ~20 000 exec/sec |
| `fuzz_replay_prevention` | ~5 000 exec/sec |
| `fuzz_state_diff_computation` | ~10 000 exec/sec |
| `fuzz_validate_execute_consistency` | ~3 000 exec/sec |

> Numbers for the five newer targets are rough estimates; run `just perf-baseline`
> locally or check the `perf-baseline` CI artifact for up-to-date measurements.

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

## Known Limitations & Future Work

| Item | Notes |
|------|-------|
| `PrivacyPreservingTransaction` coverage | Excluded from `fuzz_encoding_roundtrip` because its ZK receipt cannot be reconstructed in a fuzzing loop. A dedicated slow target with `RISC0_DEV_MODE=1` and `proptest` should be added after the current targets are stable |
| `fuzz_validate_execute_consistency` new-account detection | If `execute_check_on_state` creates a brand-new account absent from both the genesis set and the diff, that state-widening will not be detected — full detection requires iterating all accounts in `V03State`, which the API does not currently expose |
| AFL++ integration | A `just fuzz-afl` recipe can be added later; the same corpus is compatible |
| Differential testing (sequencer vs replayer) | Add a target that feeds the same block to `SequencerCore` and `indexer_core` and asserts identical state roots |
| LEZ version tracking | There is no submodule pin — `lez-fuzzing` reads `../logos-execution-zone` as checked out. Update that repo to a release tag or a tested commit, then run `just update-lez` (which does `git pull --ff-only`) and open a PR to bump it |
