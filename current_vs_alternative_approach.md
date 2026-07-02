# Alternative Approaches vs. Current Implementation

## 🧩 What the Current Project Does

The `lez-fuzzing` repository is a **coverage-guided, structured mutation fuzzing system** built on **cargo-fuzz / libFuzzer**, operating as a standalone companion to the Logos Execution Zone (LEZ) codebase. Its key design pillars:

| Pillar | How it is realised |
|---|---|
| Coverage guidance | LLVM libFuzzer instruments every branch; mutations steered toward uncovered code |
| Structured inputs | [`fuzz_props::arbitrary_types`](fuzz_props/src/arbitrary_types.rs) wraps all LEZ transaction types with the `Arbitrary` trait |
| Rich generators | [`fuzz_props::generators`](fuzz_props/src/generators.rs) adds `proptest` strategies for pathological sequences, phantom-account attacks, overflow amounts, replay sequences |
| Protocol invariants | [`fuzz_props::invariants`](fuzz_props/src/invariants.rs) expresses zero-mutation-on-rejection and replay-rejection as reusable `ProtocolInvariant` objects |
| ZK-awareness | `RISC0_DEV_MODE=1` stubs out `risc0-zkvm` proofs, enabling ~5 000–200 000 exec/sec depending on target |
| 22 dedicated targets | Covers encoding, signature verification, stateless checks, state transitions, state diffs, replay prevention, validate/execute consistency, block verification, state serialization, witness-set verification, program deployment lifecycle, split-path equivalence, multi-block sequences, sequencer-vs-replayer differential, Merkle-tree invariants, transaction properties, privacy-preserving witness/encoding, nullifier-set round-trips, the privacy-preserving state-transition executor, and transaction ordering-independence (shielded-path nullifier double-spend across orderings). Input-independent invariant checks (genesis contents, getters, system-account guard) are kept as **LEZ unit tests**, not targets — see [`docs/mutants-not-fuzzable.md`](docs/mutants-not-fuzzable.md) |
| CI integration | GitHub Actions libFuzzer (`fuzz.yml`), AFL++ (`fuzz-afl.yml`), and mutation-testing (`mutants.yml`) workflows run on every PR / nightly |
| Pre-seeded corpus | Hundreds of minimised seed files in [`fuzz/corpus/`](fuzz/corpus/) ensure regressions are caught instantly |

---

## 🔬 Alternative Approaches

### 1. AFL++ (American Fuzzy Lop++)

**What it is**: A fork of the original AFL with structured binary mutation, QEMU/Unicorn modes, and custom mutators. Corpus-compatible with libFuzzer.

| Dimension | AFL++ | Current (libFuzzer) |
|---|---|---|
| Mutation engine | Multiple (havoc, splice, custom) | Single (libFuzzer) |
| Structured mutators | `afl-fuzz -c` custom mutators possible | `arbitrary` trait |
| Parallel scaling | `--parallel` native, multi-machine via `afl-whatsup` | `-jobs=N -workers=N` flags |
| Corpus sharing | Same binary files — **zero migration cost** | (source) |
| CI ergonomics | Requires AFL++ binary in CI image | `cargo install cargo-fuzz` only |
| Rust integration | `cargo-afl` | `cargo-fuzz` |

**Decision-maker view**: ✅ **Implemented.** AFL++ and libFuzzer find *different* bugs because they use different mutation heuristics, and running both on the same corpus is the industry-standard "belt and suspenders" approach. AFL++ is now a live lane: `just fuzz-afl` / `just fuzz-afl-parallel` and the `.github/workflows/fuzz-afl.yml` nightly job, sharing the same [`fuzz_props`](fuzz_props/src/lib.rs) crate and seed corpus at **zero migration cost**.

---

### 2. Honggfuzz

**What it is**: Google's fuzzer, available via `cargo-hfuzz`. Uses hardware performance counters for coverage in addition to software instrumentation.

| Dimension | Honggfuzz | Current (libFuzzer) |
|---|---|---|
| Coverage model | HW perf counters + SW instrumentation | SW instrumentation only |
| Crash deduplication | Built-in | Manual `cargo fuzz tmin` |
| macOS support | Partial (no HW counters on Apple Silicon) | Full |
| Parallel | Native thread-based | `-jobs` flag |

**Decision-maker view**: On x86-64 Linux CI runners, Honggfuzz's hardware coverage signal finds shallow loops and conditional jumps that software instrumentation misses. On macOS (this project's primary dev platform), it degrades to software-only mode — identical to libFuzzer. **Medium implementation cost**, moderate incremental benefit on Linux CI.

---

### 3. Property-Based Testing Only (proptest / quickcheck — no libFuzzer)

**What it is**: Pure property testing without coverage guidance. The project already uses `proptest` strategies inside [`fuzz_props::generators`](fuzz_props/src/generators.rs); the question is whether this alone is sufficient.

| Dimension | proptest-only | Current (libFuzzer + proptest) |
|---|---|---|
| Coverage guidance | ❌ None | ✅ LLVM-driven |
| Input shrinking | ✅ Automatic, human-readable | ❌ Manual `cargo fuzz tmin` |
| Determinism | ✅ Seed-reproducible | ❌ Inherently non-deterministic |
| CI integration | ✅ Standard `cargo test` | Needs separate `cargo fuzz` step |
| Depth of exploration | Shallow (combinatorial) | Deep (mutation chains) |

**Decision-maker view**: proptest is already present and valuable for human-readable regression tests. It **cannot replace** libFuzzer for deep protocol bugs — coverage guidance is what lets libFuzzer reach the 20th nested conditional in Borsh decoding. The two are **complementary, not substitutes**. Dropping libFuzzer and keeping only proptest would roughly halve the expected bug-finding rate on encoding and state-transition targets.

---

### 4. Differential Fuzzing (Sequencer vs. Replayer)

**What it is**: Feed identical inputs to two independent implementations of the same interface and assert identical outputs. Already **partially implemented** in [`fuzz_validate_execute_consistency.rs`](fuzz/fuzz_targets/fuzz_validate_execute_consistency.rs) — it compares [`validate_on_state`](fuzz/fuzz_targets/fuzz_validate_execute_consistency.rs:61) vs. [`execute_check_on_state`](fuzz/fuzz_targets/fuzz_validate_execute_consistency.rs:65), and also asserts balance conservation.

The extension noted in [`docs/fuzzing.md`](docs/fuzzing.md:356) is:

> Feed the same block to `SequencerCore` and `indexer_core` and assert identical state roots.

| Dimension | Differential target | Single-oracle target |
|---|---|---|
| Bug class | Implementation divergence | Crash / invariant violation |
| Requires two implementations | ✅ | ❌ |
| Implementation cost | High (replayer in scope) | Low |
| Value for protocol correctness | Very high | High |

**Decision-maker view**: ✅ **Implemented** as [`fuzz_sequencer_vs_replayer`](fuzz/fuzz_targets/fuzz_sequencer_vs_replayer.rs). The target feeds up to 8 transactions through the sequencer path (`validate_on_state` → `apply_state_diff`) and the replayer path (`execute_check_on_state`) with the same initial state and block context, then asserts **SequencerReplayerEquivalence** (identical balance, nonce, data, and program_owner for all known accounts), **ReplayerAcceptsAllSequencerTxs** (replayer must accept every transaction the sequencer accepted), and **ClockConsistency** (mandatory clock invocation must succeed and leave both states identical). This catches the consensus-breaking divergence class — a state root difference between sequencer and replayer — that no single-oracle target can detect.

---

### 5. Formal Verification (TLA+, Coq, Isabelle/HOL)

**What it is**: Mathematical proof that the protocol model satisfies all invariants for *all* possible inputs, not just sampled ones.

| Dimension | Formal verification | Current fuzzing |
|---|---|---|
| Coverage | 100 % (exhaustive proof) | Probabilistic |
| Implementation cost | Very high (months–years) | ✅ Already built |
| Maintenance cost | Very high (proofs break on refactors) | Low (re-run fuzzer) |
| ZK circuit coverage | Can cover RISC0 guest formally | Not applicable (mocked out) |

**Decision-maker view**: Formal verification and fuzzing are **not substitutes** for a blockchain protocol — they address different threat models. Fuzzing finds concrete exploitable bugs quickly; formal methods prove absence of entire bug classes. The current codebase complexity (ZK proofs, Borsh encoding, state machine) makes formal verification very expensive. **Recommended only for core invariants** (balance conservation, replay prevention) as a long-term supplement, not a replacement.

---

### 6. Mutation Testing (cargo-mutants)

**What it is**: Systematically modifies the production source code and checks whether existing tests kill the mutant. A surviving mutant indicates a coverage gap in the assertions.

| Dimension | Mutation testing | Current fuzzing |
|---|---|---|
| What it measures | Quality of *existing tests* | Finds *new bugs* |
| Execution time | Slow (recompile per mutation) | Continuous |
| Output | Surviving mutants = assertion gaps | Crash artifacts |

**Decision-maker view**: ✅ **Implemented.** `cargo-mutants` runs in two modes —
`just mutants-harness` (mutates `fuzz_props`, oracle = `cargo test`, auditing the
invariant assertions themselves) and `just mutants-protocol` (mutates the LEZ
`lee`/`common` crates, oracle = a fuzz-corpus replay), with a `mutants.yml` CI job.
The two oracles correspond to a deliberate **Plane A / Plane B** split — see
[`docs/mutants-not-fuzzable.md`](docs/mutants-not-fuzzable.md), which catalogues
the mutants each plane is and isn't expected to catch and why. (For reference, the
`fuzz_props` registry still implements [`StateIsolationOnFailure`](fuzz_props/src/invariants.rs),
[`BalanceConservation`](fuzz_props/src/invariants.rs), and
[`FailedTxNonceStability`](fuzz_props/src/invariants.rs) in `assert_invariants()`,
with `ReplayRejection` and `NonceIncrementCorrectness` enforced via standalone
helpers outside the registry.) This is a **complementary quality gate**, not a
fuzzing replacement.

---

## 📊 Summary Comparison Matrix

| Approach | Bug-finding depth | CI cost | Impl. cost | Complements current? | Recommended action |
|---|---|---|---|---|---|
| **Current (cargo-fuzz/libFuzzer)** | High | Medium | ✅ Done | — | Maintain & expand |
| AFL++ | High (different bugs) | Medium | ✅ Done | ✅ Yes | ✅ Implemented (`just fuzz-afl`, `fuzz-afl.yml`) |
| Honggfuzz | High on Linux | Medium | Medium | ✅ Yes | Add for Linux CI only |
| proptest-only | Low–medium | Low | ✅ Done | Already present | Keep as unit-test layer |
| Differential (sequencer/replayer) | Very high (new bug class) | Medium | ✅ Done | ✅ Yes | ✅ Implemented (`fuzz_sequencer_vs_replayer`) |
| Formal verification | Exhaustive (selected invariants) | Very high | Very high | ✅ Yes | Long-term supplement |
| Mutation testing (`cargo-mutants`) | Measures assertion quality | High | ✅ Done | ✅ Yes | ✅ Implemented (`just mutants-harness` / `mutants-protocol`) |

---

## 🧭 Decision-maker Recommendations

**Remaining higher-ROI next steps, in priority order:**

1. **Honggfuzz on Linux CI only** — hardware-counter coverage finds different paths;
   gated to Linux since Apple Silicon has no HW counters.

2. **Formal verification of core invariants** (balance conservation, replay
   prevention) — a long-term supplement, not a replacement.