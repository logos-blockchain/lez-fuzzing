<div align="center">

# 🔬 Fuzzing Guide

**The full developer guide to running, extending, and triaging the LEZ fuzzing infrastructure.**

</div>

This document covers how to run fuzz targets, add new targets, minimise failures,
and convert findings into regression tests.

The fuzzing infrastructure lives in a **separate repository** (`lez-fuzzing/`) which
reads the Logos Execution Zone (LEZ) codebase from `../logos-execution-zone/` (a sibling
directory that must be cloned separately).

---

## 🏗️ Architecture

The fuzz workspace (`fuzz/`) is a single Cargo workspace that covers **both** fuzzing
engines via Cargo features.  No separate Cargo manifest is needed.

| | libFuzzer lane | AFL++ lane |
|---|---|---|
| **Build command** | `cargo fuzz build <TARGET>` | `cd fuzz && cargo afl build --no-default-features --features fuzzer-afl --release --bin <TARGET>` |
| **Run command** | `cargo fuzz run <TARGET>` | `afl-fuzz -i fuzz/corpus/<TARGET> -o afl-output/<TARGET> -- fuzz/target/release/<TARGET>` |
| **Cargo feature** | `fuzzer-libfuzzer` (default) | `fuzzer-afl` |
| **Harness entry** | `::libfuzzer_sys::fuzz_target!(…)` | `fn main() { ::afl::fuzz!(…) }` |
| **`main()` presence** | Suppressed via `#![no_main]` | Required; provided by `afl::fuzz!` |
| **`fuzz/Cargo.toml`** | ✅ Source of truth | ✅ Same file — covers both lanes |

The engine is selected at the call site via the `fuzz_props::fuzz_entry!` macro:

```rust
#![cfg_attr(feature = "fuzzer-libfuzzer", no_main)]

fuzz_props::fuzz_entry!(|data: &[u8]| {
    // … harness body …
});
```

The `cfg` attributes in the macro expansion resolve against the **calling crate's** features
(`fuzz/`), not `fuzz_props`'s features.

---

## 🧰 Prerequisites

```bash
# libFuzzer lane
rustup install nightly
rustup component add llvm-tools-preview --toolchain nightly
cargo install cargo-fuzz

# AFL++ lane (additional)
# macOS:
brew install afl-fuzz

# Linux — build from source (apt packages are several major versions behind):
git clone https://github.com/AFLplusplus/AFLplusplus
cd AFLplusplus && make distrib && sudo make install
cd ..

# Rust wrapper (all platforms):
cargo install cargo-afl
```

---

## 📁 Repository Setup

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

## ▶️ How to Run

All fuzz targets must be run with `RISC0_DEV_MODE=1` to disable expensive ZK
proof generation. The `just` recipes handle this automatically.

```bash
# From lez-fuzzing/

# Run all targets for 30 s each (libFuzzer)
just fuzz

# Run a specific target for 120 s (libFuzzer)
RISC0_DEV_MODE=1 cargo fuzz run fuzz_state_transition -- -max_total_time=120

# Run the saved corpus (regression mode, no mutations)
just fuzz-regression
```

---

## 🎯 Available Fuzz Targets

| Target | What it fuzzes | Entry point |
|--------|---------------|-------------|
| `fuzz_transaction_decoding` | Borsh decoding of `LeeTransaction`, `Block`, and `HashableBlockData`; roundtrip re-encoding of successfully decoded transactions | `fuzz/fuzz_targets/fuzz_transaction_decoding.rs` |
| `fuzz_stateless_verification` | `transaction_stateless_check()` no-panic on arbitrary bytes; idempotency — a transaction that passes the check must pass it again | `fuzz/fuzz_targets/fuzz_stateless_verification.rs` |
| `fuzz_state_transition` | `execute_check_on_state()` across up to 8 transactions with fuzz-driven initial state and monotonically-advancing block context; asserts **StateIsolationOnFailure** (balances unchanged on rejection), **BalanceConservation** (total balance unchanged on success), and **ReplayRejection** (nonce consumed on first acceptance) | `fuzz/fuzz_targets/fuzz_state_transition.rs` |
| `fuzz_block_verification` | Three block-hash invariants: **HashRoundTrip** (`HashableBlockData::from(Block)` is lossless), **HashPreimage** (block_id, prev_block_hash, timestamp each individually affect the hash), **TxOrderCommitment** (reversing the transaction list changes the hash) | `fuzz/fuzz_targets/fuzz_block_verification.rs` |
| `fuzz_encoding_roundtrip` | `decode(encode(tx)) == Ok(tx)` and `encode(decode(encode(tx))) == encode(tx)` for `PublicTransaction` and `ProgramDeploymentTransaction`; raw bytes that decode successfully must re-encode identically (canonical encoding) | `fuzz/fuzz_targets/fuzz_encoding_roundtrip.rs` |
| `fuzz_signature_verification` | Signature correctness (sign→verify), no-panic on random bytes, cross-key soundness | `fuzz/fuzz_targets/fuzz_signature_verification.rs` |
| `fuzz_replay_prevention` | A tx accepted in block N must be rejected when replayed in block N+1 (nonce consumed); fuzz-driven initial state exposes nonce edge cases (nonce 0, `u128::MAX`, zero-balance sender) | `fuzz/fuzz_targets/fuzz_replay_prevention.rs` |
| `fuzz_state_diff_computation` | **Forward containment**: `ValidatedStateDiff` only modifies accounts declared in `affected_public_account_ids()`; **Reverse completeness**: every declared account actually modified by `execute_check_on_state` appears in the diff | `fuzz/fuzz_targets/fuzz_state_diff_computation.rs` |
| `fuzz_validate_execute_consistency` | `validate_on_state` and `execute_check_on_state` must agree on success/failure; diff accuracy (forward + reverse); **BalanceConservation** on success | `fuzz/fuzz_targets/fuzz_validate_execute_consistency.rs` |
| `fuzz_state_serialization` | `V03State` Borsh no-panic (**NoPanic**) + **StateSerializationRoundtrip** (`encode(decode(encode(decode(data)))) == encode(decode(data))`) + **NullifierDeduplication** (hand-written `NullifierSet` deserializer returns `Err`, not panic, on duplicate nullifiers) | `fuzz/fuzz_targets/fuzz_state_serialization.rs` |
| `fuzz_witness_set_verification` | `WitnessSet::is_valid_for` no-panic on adversarial input (**NoPanic**); **CorrectVerification** (`WitnessSet::for_message` always passes `is_valid_for` on the same message); **MessageIsolation** (witness set built for message A fails `is_valid_for` on any Borsh-distinct message B) | `fuzz/fuzz_targets/fuzz_witness_set_verification.rs` |
| `fuzz_program_deployment_lifecycle` | `V03State::transition_from_program_deployment_transaction` no-panic on arbitrary WASM bytecode (**NoPanic**); **BalanceIsolation** (successful deployment must not move tokens); **StateIsolationOnFailure** (failed deployment must not change any genesis account balance or nonce) | `fuzz/fuzz_targets/fuzz_program_deployment_lifecycle.rs` |
| `fuzz_apply_state_diff_split_path` | **SplitPathEquivalence**: for every known account, `validate_on_state` + `apply_state_diff` must produce exactly the same balance, nonce, data, and program_owner as `execute_check_on_state`; **NonceIncrementCorrectness**: nonce after the split path equals nonce after the direct path for all signer accounts (catches bugs in the two-step `apply_state_diff` nonce-increment logic) | `fuzz/fuzz_targets/fuzz_apply_state_diff_split_path.rs` |
| `fuzz_multi_block_state_sequence` | **LongRangeBalanceConservation**: total genesis-account balance identical before and after all N (≤ 16) blocks; **FailedTxNonceStability**: every genesis-account nonce unchanged after a rejected transaction; **PerBlockReplayRejection**: every transaction accepted in block B is rejected in block B+1 (cumulative nonce-interaction coverage) | `fuzz/fuzz_targets/fuzz_multi_block_state_sequence.rs` |
| `fuzz_sequencer_vs_replayer` | **SequencerReplayerEquivalence**: for every known account (genesis ∪ diff-declared), the sequencer path (`validate_on_state` → `apply_state_diff`) and the replayer path (`execute_check_on_state`) must produce identical balance, nonce, data, and program_owner after applying a full block of up to 8 transactions plus the mandatory clock invocation; **ReplayerAcceptsAllSequencerTxs**: every transaction accepted by `validate_on_state` must also be accepted by `execute_check_on_state`; **ClockConsistency**: the mandatory clock invocation must succeed on both paths and leave both states identical | `fuzz/fuzz_targets/fuzz_sequencer_vs_replayer.rs` |
| `fuzz_merkle_tree` | Commitment Merkle tree via the commitment set: **ProofSome**, **ProofValid** (leaf + auth path recomputes the root), **NonMembershipNone**, **IndicesSequential** | `fuzz/fuzz_targets/fuzz_merkle_tree.rs` |
| `fuzz_transaction_properties` | Transaction property invariants: **HashDeterministic** / **HashNonDefault**, **SignerIds** derived from witness keys & non-empty, **AffectedAccountsContainSigners**, **PublicDiffNonEmptyOnSuccess** | `fuzz/fuzz_targets/fuzz_transaction_properties.rs` |
| `fuzz_privacy_preserving_witness` | `privacy_preserving_transaction::WitnessSet`: **CorrectVerification** (witness for message A passes `signatures_are_valid_for(A)`), **MessageIsolation**, **SignerIdsMatchWitnessKeys** | `fuzz/fuzz_targets/fuzz_privacy_preserving_witness.rs` |
| `fuzz_encoding_privacy_preserving` | Privacy-preserving encoding: **MessageEncodingRoundtrip**, **TxEncodingDeterministic** / **NonEmpty** | `fuzz/fuzz_targets/fuzz_encoding_privacy_preserving.rs` |
| `fuzz_nullifier_set_roundtrip` | `NullifierSet` Borsh serialisation: **NullifierSetRoundtrip** (decode→encode identity for the hand-written impl) | `fuzz/fuzz_targets/fuzz_nullifier_set_roundtrip.rs` |

---

## ➕ How to Add a New Fuzz Target

### Step 1 — Scaffold with `just new-target`

```bash
just new-target my_feature
```

This single command does four things automatically:

| What | Where |
|---|---|
| Creates the corpus directory | `fuzz/corpus/fuzz_my_feature/` |
| Writes a typed fuzz target template | `fuzz/fuzz_targets/fuzz_my_feature.rs` |
| Appends `[[bin]]` entry to `fuzz/Cargo.toml` | Covers **both** the libFuzzer and AFL++ lanes |
| Inserts target into every CI matrix + perf loop | `.github/workflows/fuzz.yml` |

The generated template uses `fuzz_props::fuzz_entry!` and works with both engines
without modification.

### Step 2 — Implement the target

Edit `fuzz/fuzz_targets/fuzz_my_feature.rs`.  Replace the placeholder with the
function under test and any invariant assertions.  Use the typed wrappers from
[`fuzz_props::arbitrary_types`](../fuzz_props/src/arbitrary_types.rs) for
structured input, or the proptest generators from
[`fuzz_props::generators`](../fuzz_props/src/generators.rs) for richer strategies.

### Step 3 — Automated registration (cargo-fuzz + CI)

`just new-target` calls [`scripts/add_fuzz_target.py`](../scripts/add_fuzz_target.py)
which:
- Appends the `[[bin]]` entry to [`fuzz/Cargo.toml`](../fuzz/Cargo.toml).
  This **single entry** covers both the libFuzzer lane (`cargo fuzz build`) and
  the AFL++ lane (`cargo afl build --no-default-features --features fuzzer-afl`).
- Inserts the target name into every strategy matrix and the perf-baseline shell
  loop in [`.github/workflows/fuzz.yml`](../.github/workflows/fuzz.yml).

> [!TIP]
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

### Step 4 — Verify

```bash
# Verify the libFuzzer build
RISC0_DEV_MODE=1 cargo fuzz build fuzz_my_feature
just fuzz-regression   # runs the new target against its (empty) corpus

# Verify the AFL++ build (same fuzz/Cargo.toml — no separate manifest needed)
cd fuzz && cargo afl build \
  --no-default-features \
  --features fuzzer-afl \
  --release \
  --bin fuzz_my_feature
```

### Quick reference: what to touch

| File | Action | Automated? |
|---|---|---|
| `fuzz/fuzz_targets/fuzz_<name>.rs` | Create | ✅ `just new-target` |
| `fuzz/corpus/fuzz_<name>/` | Create | ✅ `just new-target` |
| `fuzz/Cargo.toml` | Add `[[bin]]` (covers both lanes) | ✅ `just new-target` |
| `Justfile` | Nothing — auto-discovers | ✅ automatic |
| `.github/workflows/fuzz.yml` | Add to 3 matrix lists | ✅ `just new-target` |

---

## 🔀 AFL++ Parallel Fuzzing Lane

### Prerequisites

Install AFL++ natively on your machine.

> [!NOTE]
> **Note on Linux package versions**: The `afl++` package in Debian stable (Bookworm)
> and Ubuntu LTS is several major versions behind the current AFL++ 4.x series and may
> be incompatible with `cargo-afl`. **Build from source** for a current version.

```bash
# macOS — Homebrew keeps the formula up to date
brew install afl-fuzz

# Linux — build from source (~5 min)
git clone https://github.com/AFLplusplus/AFLplusplus
cd AFLplusplus
make distrib        # builds all components: afl-fuzz, afl-cc, afl-clang-fast, …
sudo make install
cd ..

# Rust build wrapper (all platforms)
cargo install cargo-afl
```

> [!IMPORTANT]
> **macOS: run `afl-system-config` once before fuzzing** — AFL++ uses System V shared
> memory (`shmget`) to pass coverage bitmaps between the fuzzer and the target.  macOS
> ships with very small defaults (`kern.sysv.shmmax = 4 MB`, `kern.sysv.shmmni = 32`)
> that are exhausted as soon as multiple AFL++ instances start in parallel, causing every
> run to abort immediately with:
>
> ```
> [-]  SYSTEM ERROR : shmget() failed, try running afl-system-config
>        OS message : Invalid argument
> ```
>
> Fix by running the AFL++ system-configuration helper once per boot (or after every
> macOS update):
>
> ```bash
> sudo afl-system-config
> ```
>
> This raises `shmmax`, `shmmni`, `shmall`, and related limits to values suitable for
> parallel fuzzing.  The change is not persistent across reboots, so re-run it after
> each restart.  The `just fuzz-afl` and `just fuzz-afl-parallel` recipes **do not**
> call this automatically because it requires `sudo`.

> [!IMPORTANT]
> **macOS: crash reporter must be disabled** — AFL++ detects the macOS `ReportCrash`
> daemon and aborts if it is active (it delays crash notifications and causes AFL++ to
> mis-classify crashes as timeouts).  The `just fuzz-afl` and `just fuzz-afl-parallel`
> recipes disable it automatically for the duration of the run and re-enable it on exit
> (via a shell `trap`).  You can also manage it manually:
>
> ```bash
> # Disable (run once before a long session)
> just afl-macos-setup
>
> # Re-enable afterward
> just afl-macos-teardown
> ```
>
> Or use the raw `launchctl` commands shown in the AFL++ error message:
>
> ```bash
> SL=/System/Library; PL=com.apple.ReportCrash
> launchctl unload -w ${SL}/LaunchAgents/${PL}.plist
> sudo launchctl unload -w ${SL}/LaunchDaemons/${PL}.Root.plist
> ```

### Build

```bash
# All targets
just afl-build

# Single target
just afl-build-target fuzz_state_transition
```

Both commands compile `fuzz/` with `--no-default-features --features fuzzer-afl`.
Output binaries land in `fuzz/target/release/`.

### Run (single instance)

```bash
# 120-second smoke run
just fuzz-afl fuzz_state_transition

# Custom duration
just fuzz-afl fuzz_state_transition 600
```

### Run (parallel)

```bash
# 1 main + 3 secondary instances for 5 minutes
just fuzz-afl-parallel fuzz_state_transition 4 300

# AFL++ rule: always start the main instance first;
# secondary instances are started with -S flags automatically.
```

### Monitor

```bash
just afl-status fuzz_state_transition
# … calls afl-whatsup afl-output/fuzz_state_transition
```

### Triage

```bash
# Minimise a crash artifact to the smallest reproducing input
just afl-tmin fuzz_state_transition afl-output/fuzz_state_transition/default/crashes/id:000000,...

# Pretty-print as Rust byte literal (for pasting into a unit test)
just afl-fmt afl-output/fuzz_state_transition/default/crashes/id:000000,...
```

### Sync queue to shared corpus

```bash
# Copies afl-output/*/queue/id:* into fuzz/corpus/<target>/
# Run this after any AFL++ session to share findings with cargo-fuzz
just afl-corpus-sync
```

### How the shared harness works

| Mechanism | libFuzzer | AFL++ |
|---|---|---|
| **Entry macro** | `::libfuzzer_sys::fuzz_target!(…)` | `::afl::fuzz!(…)` inside `fn main()` |
| **`no_main` suppression** | `#![cfg_attr(feature = "fuzzer-libfuzzer", no_main)]` | Not applied (AFL++ needs a real `main`) |
| **Feature gate** | `cfg(feature = "fuzzer-libfuzzer")` | `cfg(feature = "fuzzer-afl")` |
| **Feature resolution** | Resolved at `fuzz/` (calling crate), not at `fuzz_props/` | Same |
| **`libfuzzer-sys` dep** | Optional, active under `fuzzer-libfuzzer` | Not compiled — avoids `main()` conflict |
| **`afl` dep** | Not compiled | Optional, active under `fuzzer-afl` |
| **Default build** | `default = ["fuzzer-libfuzzer"]` → `cargo fuzz` just works | Requires `--no-default-features --features fuzzer-afl` |

The `fuzz_props::fuzz_entry!` macro defined in [`fuzz_props/src/lib.rs`](../fuzz_props/src/lib.rs)
expands to the right entry point based on the active feature:

```rust
#[macro_export]
macro_rules! fuzz_entry {
    (|$data:ident: &[u8]| $body:block) => {
        #[cfg(feature = "fuzzer-libfuzzer")]
        ::libfuzzer_sys::fuzz_target!(|$data: &[u8]| $body);

        #[cfg(feature = "fuzzer-afl")]
        fn main() {
            ::afl::fuzz!(|$data: &[u8]| $body);
        }
    };
}
```

### CI (`.github/workflows/fuzz-afl.yml`)

The nightly AFL++ CI workflow has two jobs:

| Job | Triggers | Matrix |
|-----|----------|--------|
| `afl-smoke` | nightly + `workflow_dispatch` | all 20 targets, 60 s each |
| `afl-coverage-aggregate` | nightly, `needs: afl-smoke` | all 20 targets merged into one LLVM HTML report |

The smoke job (one matrix leg per target, on `ubuntu-latest`):
1. Builds AFL++ from source, then builds the target with `cargo afl build --no-default-features --features fuzzer-afl`
2. Runs `afl-fuzz` for 60 s (`timeout 60`)
3. Reports edge-bitmap coverage to the job step summary
4. Uploads the queue/crashes/hangs as a workflow artifact

The coverage-aggregate job:
1. Downloads every smoke leg's findings
2. Rebuilds all 20 targets with `RUSTFLAGS="-C instrument-coverage"`
3. Runs all checked-in corpus + AFL queue inputs through each binary
4. Merges every `.profraw` → one `.profdata` → a single combined HTML report via `llvm-cov show`

---

## 🔄 Updating the LEZ Dependency

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

## 🐛 Minimising & Reproducing Failures

When `cargo fuzz` finds a crash it writes an artifact to
`fuzz/artifacts/fuzz_<target>/crash-<hash>`.

### Minimise (libFuzzer)

```bash
# Produces a smaller input that still triggers the same crash
just fuzz-tmin fuzz_state_transition fuzz/artifacts/fuzz_state_transition/crash-abc123
```

### Minimise (AFL++)

```bash
just afl-tmin fuzz_state_transition afl-output/fuzz_state_transition/default/crashes/id:000000,...
```

### Convert to a regression test

```bash
# libFuzzer: print bytes as a Rust byte-literal
cargo fuzz fmt fuzz_state_transition fuzz/artifacts/fuzz_state_transition/crash-abc123

# AFL++: print bytes as a Rust byte-literal
just afl-fmt afl-output/fuzz_state_transition/default/crashes/id:000000,...
```

Add the minimised file to the corpus so CI always reproduces it:

```bash
cp fuzz/artifacts/fuzz_state_transition/crash-abc123-minimised \
   fuzz/corpus/fuzz_state_transition/regression_001
```

Open a PR. The `regression` CI job will permanently block re-introduction of this bug.

---

## 📊 Coverage Reports

### Step 1 — libFuzzer coverage (via `cargo fuzz coverage`)

```bash
# Generates coverage for a single target
cargo fuzz coverage fuzz_state_transition

# Generates coverage for all targets
just coverage-all
```

Reports land in `fuzz/coverage/<target>/`.

### Step 2 — AFL++ LLVM coverage

Run after a successful AFL++ session (queue data in `afl-output/<target>/`):

```bash
# Combines libFuzzer + AFL++ corpus into a single LLVM HTML report
just coverage fuzz_state_transition
```

This:
1. Runs `cargo fuzz coverage` (step 1)
2. Detects `afl-output/fuzz_state_transition/` and builds the target with
   `RUSTFLAGS="-C instrument-coverage" cargo build --manifest-path fuzz/Cargo.toml --no-default-features --features fuzzer-afl --release`
3. Runs all AFL++ queue entries through the binary, collects `.profraw` files
4. Merges profiles with `llvm-profdata merge` and generates an HTML report with `llvm-cov show`
5. Writes the report to `coverage/afl/fuzz_state_transition/html/index.html`

The AFL++ CI coverage job (`afl-coverage` in [`.github/workflows/fuzz-afl.yml`](../.github/workflows/fuzz-afl.yml))
automates steps 2–5 and uploads the report as a workflow artifact.

---

## 🛡️ Invariant Framework

Shared invariants live in `fuzz_props/src/invariants.rs`. There are two layers:

### Primary API — `assert_tx_execution_invariants()`

For every fuzz target that calls `execute_check_on_state`, use the single unified entry
point.  It enforces the five state-transition invariants in one call, routing by outcome:

| Invariant | Active when |
|-----------|-------------|
| `StateIsolationOnFailure` | `execution_result` is `Err` |
| `FailedTxNonceStability` | `execution_result` is `Err` |
| `BalanceConservation` | `execution_result` is `Ok` |
| `NonceIncrementCorrectness` | `execution_result` is `Ok` |
| `ReplayRejection` | `execution_result` is `Ok` |

```rust
let state_snapshot = state.clone();
let result = tx.execute_check_on_state(&mut state, block_id, timestamp);

assert_tx_execution_invariants(
    &state_snapshot,
    &mut state,
    balances_before,
    nonces_before,
    result,
    (block_id + 1, timestamp + 1),
);
```

One call.  No standalone helpers to remember.

### Registry API — `assert_invariants()` + `ProtocolInvariant`

Each invariant is a zero-size struct implementing `ProtocolInvariant`; `assert_invariants()`
runs the registry and panics on the first violation.  This lower-level API is used
internally by `assert_tx_execution_invariants` and is also available for targets where no
transaction is available for replay (e.g. pure state-serialization targets).

```rust
// Only use assert_invariants() directly for non-execution contexts.
// For execute_check_on_state call sites, prefer assert_tx_execution_invariants().
assert_invariants(&InvariantCtx { state_before, state_after, execution_succeeded,
                                  balances_before, nonces_before });
```

Additional invariants enforced **inline** in specific targets (not via `ProtocolInvariant`):

| Invariant | Targets |
|-----------|---------|
| `HashRoundTrip` / `HashPreimage` / `TxOrderCommitment` | `fuzz_block_verification` |
| Diff forward containment / reverse completeness | `fuzz_state_diff_computation` |

To add a new invariant:

1. Add a zero-size struct implementing `ProtocolInvariant`.
2. Register it in the `invariants` slice inside `assert_invariants()`.
3. Write a `#[test]` in `fuzz_props` that triggers and detects a synthetic violation.

---

## 🎲 Input Generators

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
| `ArbHashableBlockData` | `HashableBlockData` (0–7 `ArbLeeTransaction` entries, random header fields) |
| `ArbLeeTransaction` | `LeeTransaction` (`Public` or `ProgramDeployment` variant; `PrivacyPreserving` excluded) |

### `fuzz_props::generators` (libFuzzer helpers + proptest strategies)

| Generator | Covers |
|-----------|--------|
| `arbitrary_fuzz_state()` | 1–8 fuzz-driven accounts with arbitrary IDs, balances, and private keys; used by `fuzz_state_transition`, `fuzz_replay_prevention`, `fuzz_validate_execute_consistency`, `fuzz_state_diff_computation` |
| `arb_fuzz_native_transfer()` | Correctly-signed native-transfer `LeeTransaction` referencing accounts from an `arbitrary_fuzz_state()` result; gives the fuzzer a path to successful state transitions |
| `arbitrary_transaction()` | Structured `LeeTransaction` (`Public` or `ProgramDeployment`) from unstructured bytes via `ArbLeeTransaction` |
| `arb_borsh_transaction_bytes()` | Raw Borsh bytes including invalid encodings |
| `signer_account_ids()` | Extracts `AccountId`s of all signers from an `LeeTransaction`'s witness set; used to derive signer IDs before `apply_state_diff` consumes the diff |
| `arb_native_transfer_tx()` | Valid native-transfer `LeeTransaction` between known testnet genesis accounts (proptest strategy) |
| `test_accounts()` | Returns `(AccountId, PrivateKey)` pairs from `testnet_initial_state` |
| `arb_hashable_block_data()` | `HashableBlockData` with 0–8 valid native transfers (proptest strategy) |
| `arb_invalid_account_state_tx()` | Phantom accounts + overflow amounts — expected to be rejected (IS-3) |
| `arb_duplicate_tx_sequence()` | Duplicated + re-ordered transaction sequences (IS-4) |
| `arb_pathological_sequence()` | Zero-value, self-transfer, max-nonce inputs (IS-5) |

---

## ⚡ Performance Baseline

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
| `fuzz_state_serialization` | ~100 000 exec/sec *(estimate)* |
| `fuzz_witness_set_verification` | ~15 000 exec/sec *(estimate)* |
| `fuzz_program_deployment_lifecycle` | ~4 000 exec/sec *(estimate)* |
| `fuzz_apply_state_diff_split_path` | ~5 000 exec/sec *(estimate)* |
| `fuzz_multi_block_state_sequence` | ~1 000 exec/sec *(estimate)* |
| `fuzz_sequencer_vs_replayer` | ~2 000 exec/sec *(estimate)* |
| `fuzz_merkle_tree` | ~20 000 exec/sec *(estimate)* |
| `fuzz_transaction_properties` | ~15 000 exec/sec *(estimate)* |
| `fuzz_privacy_preserving_witness` | ~15 000 exec/sec *(estimate)* |
| `fuzz_encoding_privacy_preserving` | ~50 000 exec/sec *(estimate)* |
| `fuzz_nullifier_set_roundtrip` | ~100 000 exec/sec *(estimate)* |

> [!NOTE]
> Throughput figures for the five new targets are rough estimates; run `just perf-baseline`
> locally or check the `perf-baseline` CI artifact for up-to-date measurements.

Recommended local settings for longer runs:

```bash
# libFuzzer — use all available cores
RISC0_DEV_MODE=1 cargo fuzz run fuzz_state_transition \
  -- -max_total_time=3600 -jobs=$(nproc) -workers=$(nproc)

# AFL++ — parallel (1 main + N-1 secondary)
just fuzz-afl-parallel fuzz_state_transition $(nproc) 3600
```

---

## ⚠️ ZK-Proof Cost Warning

`PrivacyPreservingTransaction` uses `risc0-zkvm` (seconds per proof).
All fuzz targets **must** set `RISC0_DEV_MODE=1` in the environment and the `just`
recipes handle this automatically via:

```just
export RISC0_DEV_MODE := "1"
```

Do **not** invoke full proof generation inside any fuzz target. The `RISC0_DEV_MODE=1`
flag stubs out ZK proof generation and replaces it with a fast mock implementation.

---

## 🧬 Mutation testing — the two planes

Mutation testing here runs in two distinct planes, answering two different questions:

- **Plane A — "does a test catch this mutant?"** Run with a standard `cargo test`
  oracle against the `lee` crate's own unit tests.
- **Plane B — "does the committed fuzz corpus catch this mutant?"** Run with
  `just mutants-protocol`, which swaps `cargo test` for a fuzz-corpus replay
  (`cargo fuzz run … -runs=0`) as the oracle.

A mutant surviving Plane B is **not automatically a corpus gap to fill.** Some
mutations are only reachable by a fully-valid executing transaction or by a
deliberately-misbehaving program — neither of which a fuzzer can synthesise from
random bytes, and both of which are better pinned by deterministic unit tests in
the `lee` crate. Encoding such scenarios as input-independent fuzz targets only
duplicates those tests and slows every corpus replay.

The mutants that are **expected** to survive Plane B (and where each is actually
covered) are catalogued in [`mutants-not-fuzzable.md`](mutants-not-fuzzable.md).
Reconcile new `mutants-protocol` runs against that list: only a surviving mutant
**not** on it warrants a new corpus input.

**No input-independent targets.** A fuzz target whose closure ignores its input
(`|_data|`) is a deterministic unit test, not a fuzzer — it belongs in the LEZ
crate that owns the code. Three such targets once existed
(`fuzz_common_invariants`, `fuzz_genesis_invariants`,
`fuzz_system_account_protection`); their invariants were ported to LEZ unit tests
and the targets removed. The mutant→test mapping is recorded under "Group 2" in
[`mutants-not-fuzzable.md`](mutants-not-fuzzable.md). When adding a target, drive it
from `data`; if a check doesn't depend on the input, write it as a unit test in
`logos-execution-zone` instead.

---

## 🚧 Known Limitations & Future Work

| Item | Notes |
|------|-------|
| `PrivacyPreservingTransaction` coverage | Excluded from `fuzz_encoding_roundtrip` because its ZK receipt cannot be reconstructed in a fuzzing loop. A dedicated slow target with `RISC0_DEV_MODE=1` and `proptest` should be added after the current targets are stable |
| `fuzz_validate_execute_consistency` new-account detection | If `execute_check_on_state` creates a brand-new account absent from both the genesis set and the diff, that state-widening will not be detected — full detection requires iterating all accounts in `V03State`, which the API does not currently expose |
| Differential testing (sequencer vs replayer) | ✅ Implemented — `fuzz_sequencer_vs_replayer` feeds the same block through the sequencer path (`validate_on_state` → `apply_state_diff`) and the replayer path (`execute_check_on_state`) and asserts identical state for all known accounts |
| AFL++ integration | ✅ Implemented — `just afl-build`, `just fuzz-afl`, `just fuzz-afl-parallel`; nightly CI in `.github/workflows/fuzz-afl.yml`; single `fuzz/Cargo.toml` covers both engines via feature flags |
| LEZ version tracking | There is no submodule pin — `lez-fuzzing` reads `../logos-execution-zone` as checked out. Update that repo to a release tag or a tested commit, then run `just update-lez` (which does `git pull --ff-only`) and open a PR to bump it |
