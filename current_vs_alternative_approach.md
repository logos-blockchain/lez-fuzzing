# Alternative Approaches vs. Current Implementation

## What the Current Project Does

The `lez-fuzzing` repository is a **coverage-guided, structured mutation fuzzing system** built on **cargo-fuzz / libFuzzer**, operating as a standalone companion to the Logos Execution Zone (LEZ) codebase. Its key design pillars:

| Pillar | How it is realised |
|---|---|
| Coverage guidance | LLVM libFuzzer instruments every branch; mutations steered toward uncovered code |
| Structured inputs | [`fuzz_props::arbitrary_types`](fuzz_props/src/arbitrary_types.rs) wraps all LEZ transaction types with the `Arbitrary` trait |
| Rich generators | [`fuzz_props::generators`](fuzz_props/src/generators.rs) adds `proptest` strategies for pathological sequences, phantom-account attacks, overflow amounts, replay sequences |
| Protocol invariants | [`fuzz_props::invariants`](fuzz_props/src/invariants.rs) expresses zero-mutation-on-rejection and replay-rejection as reusable `ProtocolInvariant` objects |
| ZK-awareness | `RISC0_DEV_MODE=1` stubs out `risc0-zkvm` proofs, enabling ~5 000–200 000 exec/sec depending on target |
| 9 dedicated targets | Covers encoding, signature verification, stateless checks, state transitions, state diffs, replay prevention, validate/execute consistency, block verification |
| CI integration | GitHub Actions smoke, regression, and performance-baseline jobs run on every PR |
| Pre-seeded corpus | Hundreds of minimised seed files in [`fuzz/corpus/`](fuzz/corpus/) ensure regressions are caught instantly |

---

## Alternative Approaches

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

**Decision-maker view**: AFL++ and libFuzzer find *different* bugs because they use different mutation heuristics. Running both on the same corpus is the industry-standard "belt and suspenders" approach. [`docs/fuzzing.md`](docs/fuzzing.md:273) already lists `just fuzz-afl` as planned future work. **Incremental cost is low** — the same [`fuzz_props`](fuzz_props/src/lib.rs) crate and seed corpus work unchanged.

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

**What it is**: Feed identical inputs to two independent implementations of the same interface and assert identical outputs. Already **partially implemented** in [`fuzz_validate_execute_consistency.rs`](fuzz/fuzz_targets/fuzz_validate_execute_consistency.rs) — it compares [`validate_on_state`](fuzz/fuzz_targets/fuzz_validate_execute_consistency.rs:35) vs. [`execute_check_on_state`](fuzz/fuzz_targets/fuzz_validate_execute_consistency.rs:39).

The extension noted in [`docs/fuzzing.md`](docs/fuzzing.md:274) is:

> Feed the same block to `SequencerCore` and `indexer_core` and assert identical state roots.

| Dimension | Differential target | Single-oracle target |
|---|---|---|
| Bug class | Implementation divergence | Crash / invariant violation |
| Requires two implementations | ✅ | ❌ |
| Implementation cost | High (replayer in scope) | Low |
| Value for protocol correctness | Very high | High |

**Decision-maker view**: This is the **highest-value extension** to the current project. The `fuzz_validate_execute_consistency` target proves the pattern works. A sequencer-vs-replayer target would catch consensus-breaking state root divergence — a class of bug no single-oracle target can detect. Estimated cost: 1–2 engineer-weeks.

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

**Decision-maker view**: `cargo-mutants` would **audit the invariant assertions themselves** — revealing if [`assert_invariants()`](fuzz_props/src/invariants.rs:72) has gaps (and it currently does, as [`StateIsolationOnFailure`](fuzz_props/src/invariants.rs:38) and [`ReplayRejection`](fuzz_props/src/invariants.rs:59) are stubs). This is a **complementary quality gate**, not a fuzzing replacement. Low cost (~1 day), highly useful before an external security audit.

---

## Summary Comparison Matrix

| Approach | Bug-finding depth | CI cost | Impl. cost | Complements current? | Recommended action |
|---|---|---|---|---|---|
| **Current (cargo-fuzz/libFuzzer)** | High | Medium | ✅ Done | — | Maintain & expand |
| AFL++ | High (different bugs) | Medium | Low | ✅ Yes | Add `just fuzz-afl` (already planned) |
| Honggfuzz | High on Linux | Medium | Medium | ✅ Yes | Add for Linux CI only |
| proptest-only | Low–medium | Low | ✅ Done | Already present | Keep as unit-test layer |
| Differential (sequencer/replayer) | Very high (new bug class) | Medium | Medium–high | ✅ Yes | **Priority extension** |
| Formal verification | Exhaustive (selected invariants) | Very high | Very high | ✅ Yes | Long-term supplement |
| Mutation testing (`cargo-mutants`) | Measures assertion quality | High | Low | ✅ Yes | Pre-audit quality gate |

---

## Decision-maker Recommendations

The current implementation is **well-architected and production-ready** for a protocol at this stage. Its [`fuzz_props`](fuzz_props/src/lib.rs) crate, typed `Arbitrary` wrappers, and `ProtocolInvariant` framework provide the right abstractions to add new targets and invariants incrementally.

**Highest-ROI next steps, in priority order:**

1. **Complete the stub invariants** in [`fuzz_props/src/invariants.rs`](fuzz_props/src/invariants.rs:41) — [`StateIsolationOnFailure`](fuzz_props/src/invariants.rs:38) and [`ReplayRejection`](fuzz_props/src/invariants.rs:59) are currently no-ops. This costs less than one day and immediately hardens all existing targets.

2. **Add the sequencer-vs-replayer differential target** — highest new bug-finding value, unique to this protocol's architecture, already identified in [`docs/fuzzing.md`](docs/fuzzing.md:274).

3. **Add AFL++ as a parallel fuzzing lane** (`just fuzz-afl`) — zero corpus migration cost, discovers different mutation paths through the same targets as libFuzzer.

4. **Add `cargo-mutants`** before any external security audit — proves the invariant assertions in [`fuzz_props/src/invariants.rs`](fuzz_props/src/invariants.rs) are actually capable of catching the bugs they claim to detect.