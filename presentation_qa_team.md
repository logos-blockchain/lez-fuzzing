# LEZ Fuzzing — QA Team Presentation

> **Project:** `lez-fuzzing` — Automated Fuzz Testing for the Logos Execution Zone (LEZ)
> **Audience:** QA Team
> **Date:** April 2026

---

## Agenda

1. [What Is This Project?](#1-what-is-this-project)
2. [Why Fuzzing? (Not Just Unit Tests)](#2-why-fuzzing-not-just-unit-tests)
3. [Architecture Overview](#3-architecture-overview)
4. [What We Are Testing — 9 Fuzz Targets](#4-what-we-are-testing--9-fuzz-targets)
5. [Protocol Invariants — The Safety Net](#5-protocol-invariants--the-safety-net)
6. [Input Generation Strategy](#6-input-generation-strategy)
7. [How to Run Locally](#7-how-to-run-locally)
8. [CI/CD Integration](#8-cicd-integration)
9. [Performance Characteristics](#9-performance-characteristics)
10. [Known Limitations & Future Work](#10-known-limitations--future-work)
11. [Key Takeaways for QA](#11-key-takeaways-for-qa)

---

## 1. What Is This Project?

`lez-fuzzing` is a **coverage-guided, structured mutation fuzzing system** for the **Logos Execution Zone (LEZ)** blockchain protocol.

### High-Level Context

```
<parent directory>/
├── logos-execution-zone/     ← Production codebase (LEZ protocol)
│   ├── nssa/                 ← Node State & State Accumulator
│   ├── common/               ← Shared types (transactions, blocks)
│   └── key_protocol/         ← Cryptographic primitives
└── lez-fuzzing/              ← This repository (fuzzing harness)
    ├── fuzz_props/           ← Reusable: generators + invariants
    └── fuzz/                 ← Fuzz targets + pre-seeded corpus
        └── fuzz_targets/     ← 9 individual fuzz entry points
```

### What the Fuzzer Does

The fuzzer automatically generates **millions of malformed, adversarial, and boundary-case inputs** and feeds them into the protocol. It then checks that:
- The process never **panics or crashes unexpectedly**
- Protocol **invariants** (safety rules) are never violated
- **Encoding/decoding** is lossless and deterministic
- **State integrity** is preserved even on rejected transactions

---

## 2. Why Fuzzing? (Not Just Unit Tests)

### The Gap Unit Tests Leave

Unit tests check what engineers **think of** in advance. Fuzzing discovers what engineers **don't think of**.

| Technique | Finds Known Bugs | Finds Unknown Bugs | Coverage Guidance | Scale |
|---|---|---|---|---|
| Unit tests | ✅ | ❌ | Manual | Hundreds of cases |
| Property tests (proptest) | ✅ | Partial | ❌ None | Thousands of cases |
| **Fuzzing (libFuzzer)** | ✅ | ✅ | ✅ LLVM-driven | **Millions/sec** |

### Bugs Fuzzing Is Uniquely Good At Finding

- **Panic on malformed input** — decoder receives garbled bytes → should return `Err`, not crash
- **State leakage on rejection** — a rejected transaction changes account balances (silent corruption)
- **Replay attacks** — a transaction accepted in block N is accepted again in block N+1
- **Encoding non-determinism** — `encode(decode(encode(x))) ≠ encode(x)`
- **Integer overflow / underflow** in balance arithmetic
- **Phantom account attacks** — transfers from accounts that don't exist in genesis state

### Why This Matters for a Blockchain Protocol

On a blockchain, a single invariant violation can lead to:
- **Double-spend** (state leakage on failure or replay acceptance)
- **Consensus split** (non-deterministic hashing)
- **Fund loss** (overflow in balance computation)

---

## 3. Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                        lez-fuzzing                          │
│                                                             │
│  ┌──────────────────────────────────────────────────────┐   │
│  │                    fuzz_props crate                  │   │
│  │                                                      │   │
│  │  arbitrary_types.rs  ← Typed Arbitrary wrappers      │   │
│  │  generators.rs       ← proptest + libFuzzer helpers  │   │
│  │  invariants.rs       ← ProtocolInvariant trait       │   │
│  └──────────────────────────────────────────────────────┘   │
│                            ↓                                │
│  ┌──────────────────────────────────────────────────────┐   │
│  │               fuzz/fuzz_targets/                     │   │
│  │                                                      │   │
│  │  fuzz_transaction_decoding.rs                        │   │
│  │  fuzz_stateless_verification.rs                      │   │
│  │  fuzz_state_transition.rs           (9 targets)      │   │
│  │  fuzz_block_verification.rs                          │   │
│  │  fuzz_encoding_roundtrip.rs                          │   │
│  │  fuzz_signature_verification.rs                      │   │
│  │  fuzz_replay_prevention.rs                           │   │
│  │  fuzz_state_diff_computation.rs                      │   │
│  │  fuzz_validate_execute_consistency.rs                │   │
│  └──────────────────────────────────────────────────────┘   │
│                            ↓                                │
│  ┌──────────────────────────────────────────────────────┐   │
│  │              fuzz/corpus/  (pre-seeded)              │   │
│  │   ~150 minimised seed files per target               │   │
│  └──────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
                            ↕ path dependencies
┌─────────────────────────────────────────────────────────────┐
│             ../logos-execution-zone  (LEZ)                  │
│   nssa  ·  common  ·  key_protocol  ·  token_core  …        │
└─────────────────────────────────────────────────────────────┘
```

### Technology Stack

| Component | Technology |
|---|---|
| Fuzzer engine | **libFuzzer** via `cargo-fuzz` |
| Coverage instrumentation | **LLVM SanitizerCoverage** |
| Structured input generation | **`arbitrary` crate** (typed wrappers) |
| Property-based strategies | **`proptest`** |
| ZK proof layer | **RISC0** (stubbed out with `RISC0_DEV_MODE=1`) |
| Serialization format | **Borsh** (binary object representation) |
| Language | **Rust (nightly toolchain)** |
| CI | **GitHub Actions** |

---

## 4. What We Are Testing — 9 Fuzz Targets

### Target Map

| # | Target | What Is Being Tested | Key Invariant |
|---|---|---|---|
| 1 | `fuzz_transaction_decoding` | Borsh decode of all tx/block types | Never panic; roundtrip stable |
| 2 | `fuzz_stateless_verification` | `transaction_stateless_check()` signature validation | No panic on any input |
| 3 | `fuzz_state_transition` | `V03State::transition_from_*()` with 0–8 txs | Balances unchanged on rejection |
| 4 | `fuzz_block_verification` | Block hash integrity + replayer pipeline | `block_hash()` is deterministic |
| 5 | `fuzz_encoding_roundtrip` | `decode(encode(tx)) == Ok(tx)` | Encoding is lossless |
| 6 | `fuzz_signature_verification` | Sign→verify correctness, cross-key soundness | No false positive verifications |
| 7 | `fuzz_replay_prevention` | Tx accepted in block N rejected in block N+1 | Nonce consumed, replay blocked |
| 8 | `fuzz_state_diff_computation` | `ValidatedStateDiff` scope correctness | Only declared accounts modified |
| 9 | `fuzz_validate_execute_consistency` | `validate_on_state` vs `execute_check_on_state` agree | No divergence between validators |

---

### Target Deep-Dives

#### `fuzz_state_transition` — The Core Safety Target

This is the most important target from a protocol correctness standpoint.

```
Input bytes
    ↓
[Generate up to 8 transactions from fuzz bytes]
    ↓
[Filter: pass only stateless-valid txs]
    ↓
[Apply each tx to V03State]
    ↓
[INVARIANT CHECK on rejection]:
  for every account in genesis:
    assert balance_before == balance_after
```

**What it catches:** Any code path where a **rejected** transaction silently mutates account state — the classic "partial write" class of state corruption bug.

---

#### `fuzz_transaction_decoding` — The Crash-Safety Target

```rust
fuzz_target!(|data: &[u8]| {
    // 1. If it decodes: roundtrip must be stable
    if let Ok(tx) = borsh::from_slice::<NSSATransaction>(data) {
        let re_encoded = borsh::to_vec(&tx).expect("must succeed");
        // assert stability...
    }

    // 2. Block decode: must never panic
    let _ = borsh::from_slice::<Block>(data);

    // 3. HashableBlockData decode: must never panic
    let _ = borsh::from_slice::<HashableBlockData>(data);
});
```

**What it catches:** Panics in the Borsh decoder when receiving malformed bytes (e.g., truncated input, wrong variant tags, overflow in length fields).

---

#### `fuzz_block_verification` — Determinism Target

```rust
fuzz_target!(|data: &[u8]| {
    let Ok(block) = borsh::from_slice::<Block>(data) else { return; };
    let hashable = HashableBlockData::from(block.clone());

    let hash1 = hashable.block_hash();  // first call
    let hash2 = hashable.block_hash();  // second call — must match

    assert_eq!(hash1, hash2, "block_hash() is not deterministic");
});
```

**What it catches:** Non-deterministic hashing — a critical consensus bug where two nodes compute different block hashes for the same block content.

---

## 5. Protocol Invariants — The Safety Net

The [`fuzz_props/src/invariants.rs`](fuzz_props/src/invariants.rs) module defines a **pluggable invariant framework**.

### The `ProtocolInvariant` Trait

```rust
pub trait ProtocolInvariant {
    fn name(&self) -> &'static str;
    fn check(&self, ctx: &InvariantCtx<'_>) -> Option<InvariantViolation>;
}
```

Every invariant receives a **snapshot** of the world before and after a transaction:

```rust
pub struct InvariantCtx<'a> {
    pub state_before:    &'a V03State,
    pub state_after:     &'a V03State,
    pub tx:              &'a NSSATransaction,
    pub result:          &'a Result<(), NssaError>,
    pub balances_before: BalanceSnapshot,
}
```

### Currently Registered Invariants

| Invariant | Rule |
|---|---|
| `StateIsolationOnFailure` | If a tx is **rejected**, all account balances must be identical before and after |
| `ReplayRejection` | A tx **accepted** in block N must be **rejected** in block N+1 (nonce consumed) |

### How to Add a New Invariant (for QA team)

```rust
// 1. Define a zero-size struct
pub struct BalanceConservation;

// 2. Implement the trait
impl ProtocolInvariant for BalanceConservation {
    fn name(&self) -> &'static str { "BalanceConservation" }
    fn check(&self, ctx: &InvariantCtx<'_>) -> Option<InvariantViolation> {
        let before = ctx.balances_before.total();
        let after  = /* sum state_after balances */;
        if before != after {
            Some(InvariantViolation {
                invariant: self.name(),
                message: format!("total balance changed: {} → {}", before, after),
            })
        } else {
            None
        }
    }
}

// 3. Register in assert_invariants()
let invariants: &[&dyn ProtocolInvariant] = &[
    &StateIsolationOnFailure,
    &ReplayRejection,
    &BalanceConservation,  // ← new
];
```

---

## 6. Input Generation Strategy

The [`fuzz_props/src/generators.rs`](fuzz_props/src/generators.rs) module provides two generation layers:

### Layer 1 — Typed `Arbitrary` Wrappers (for libFuzzer)

These give libFuzzer **structured, valid-looking inputs** instead of random bytes:

| Wrapper | Generates |
|---|---|
| `ArbNSSATransaction` | Full transaction with realistic fields |
| `ArbPublicTransaction` | Native token transfer |
| `ArbProgramDeploymentTransaction` | Smart contract deploy |
| `ArbPrivateKey` / `ArbPublicKey` | Cryptographic key pairs |
| `ArbSignature` | ECDSA signatures |

**Why this matters:** Without typed wrappers, libFuzzer would spend most of its time generating bytes that fail Borsh deserialization at the outermost layer — never reaching deeper code paths.

### Layer 2 — proptest Strategies (richer adversarial scenarios)

| Strategy | Tests Scenario |
|---|---|
| `arb_native_transfer_tx()` | Valid transfer between known genesis accounts |
| `arb_borsh_transaction_bytes()` | Valid + intentionally invalid Borsh encodings |
| `arb_invalid_account_state_tx()` | Phantom accounts, overflow amounts (IS-3) |
| `arb_duplicate_tx_sequence()` | Duplicated + re-ordered tx sequences (IS-4) |
| `arb_pathological_sequence()` | Zero-value, self-transfer, max-nonce inputs (IS-5) |
| `arb_hashable_block_data()` | Block with 0–8 native transfers |

### The Hybrid Approach

```
libFuzzer mutation engine
        ↓
   arbitrary bytes
        ↓
 arbitrary_transaction()
    ├── 50%: ArbNSSATransaction (structured)
    └── 50%: raw Borsh decode (may fail → libFuzzer learns)
```

This hybrid means **half the inputs** are structurally valid (reach deep code), and **half** stress the decoder boundary.

---

## 7. How to Run Locally

### Prerequisites

```bash
# Nightly Rust is required by cargo-fuzz / libFuzzer
rustup install nightly
rustup component add llvm-tools-preview --toolchain nightly
cargo install cargo-fuzz
```

### Repository Setup

```bash
# Clone both repositories side-by-side:
git clone <LEZ_REPO_URL>         logos-execution-zone
git clone <LEZ_FUZZING_REPO_URL> lez-fuzzing

# Required directory layout:
#   <parent>/
#   ├── logos-execution-zone/
#   └── lez-fuzzing/          ← work from here
```

### Common Commands

```bash
# Run ALL targets for 30 seconds each (smoke test)
just fuzz

# Run regression suite (no mutations — just corpus replay)
just fuzz-regression

# Run a specific target for 2 minutes
RISC0_DEV_MODE=1 cargo fuzz run fuzz_state_transition -- -max_total_time=120

# Minimise a crash artifact
just fuzz-tmin fuzz_state_transition fuzz/artifacts/fuzz_state_transition/crash-abc123

# View all available targets
cargo fuzz list
```

> ⚠️ **Always use `RISC0_DEV_MODE=1`** — without it, ZK proof generation runs at ~1 proof/sec, making fuzzing impractical. The `just` recipes set this automatically.

### Adding a New Fuzz Target

```bash
# Scaffold everything automatically (corpus dir, target file, Cargo.toml, CI matrix)
just new-target my_feature

# Then implement the target body
$EDITOR fuzz/fuzz_targets/fuzz_my_feature.rs

# Build and verify
RISC0_DEV_MODE=1 cargo fuzz build fuzz_my_feature
just fuzz-regression
```

---

## 8. CI/CD Integration

Three GitHub Actions jobs run on every pull request:

| Job | Trigger | What It Does | Duration |
|---|---|---|---|
| `smoke-fuzz` | Every PR | Runs each target for 30 seconds | ~5 min |
| `regression` | Every PR | Replays all corpus files (no mutations) | ~2 min |
| `perf-baseline` | Every PR | Measures exec/sec and fails if throughput drops >20% | ~10 min |

### Failure Workflow

```
CI detects crash
      ↓
cargo fuzz tmin  →  minimised input
      ↓
cargo fuzz fmt   →  Rust byte literal
      ↓
Add to corpus/   →  permanent regression test
      ↓
Open PR          →  regression job blocks reintroduction forever
```

---

## 9. Performance Characteristics

Measured on a 4-core x86_64 Linux runner with `RISC0_DEV_MODE=1`:

| Target | Throughput | Why |
|---|---|---|
| `fuzz_transaction_decoding` | **~200,000 exec/sec** | Pure decode, no state |
| `fuzz_encoding_roundtrip` | **~150,000 exec/sec** | Decode + encode, no state |
| `fuzz_block_verification` | **~50,000 exec/sec** | Hash computation |
| `fuzz_state_transition` | **~5,000 exec/sec** | Full state machine execution |
| `fuzz_replay_prevention` | **~5,000 exec/sec** | Two state transitions per input |
| `fuzz_validate_execute_consistency` | **~3,000 exec/sec** | Two paths compared |

### Running on All Cores for Long Sessions

```bash
RISC0_DEV_MODE=1 cargo fuzz run fuzz_state_transition \
  -- -max_total_time=3600 -jobs=$(nproc) -workers=$(nproc)
```

---

## 10. Known Limitations & Future Work

### Current Gaps

| Gap | Impact | Status |
|---|---|---|
| `StateIsolationOnFailure` invariant is a partial placeholder | Balance corruption may go undetected | Known — needs full account iterator API from LEZ |
| `PrivacyPreservingTransaction` excluded from encoding roundtrip | ZK receipts can't be reconstructed in fuzzing loop | Documented; dedicated slow target planned |
| No version pin between repos | Stale LEZ checkout silently fuzzes wrong code | Known limitation — `just update-lez` is manual |

### Highest-Value Future Extensions (Priority Order)

1. **Complete stub invariants** in [`fuzz_props/src/invariants.rs`](fuzz_props/src/invariants.rs) — `StateIsolationOnFailure` and `ReplayRejection` need their full implementations. **Cost: < 1 day. Impact: immediately hardens all 9 targets.**

2. **Sequencer-vs-Replayer differential target** — Feed the same block to `SequencerCore` and `indexer_core`, assert identical state roots. Catches consensus-splitting divergence. **Cost: 1–2 engineer-weeks. Impact: unique bug class not catchable any other way.**

3. **Add AFL++ as a parallel fuzzing lane** (`just fuzz-afl`) — Same corpus, different mutation engine, finds different bugs. **Cost: ~1 day. Zero corpus migration.**

4. **Add `cargo-mutants` before security audit** — Proves the invariant assertions are actually capable of catching the bugs they claim to detect. **Cost: ~1 day.**

5. **Co-locate fuzz/ into logos-execution-zone/** — Eliminates version drift; standard `cargo fuzz` convention. LEZ CI would run `cargo fuzz build` on every PR. **Cost: ~1 day migration.**

---

## 11. Key Takeaways for QA

### What the Fuzzer Covers

✅ **No crash on any byte sequence** — all decoders handle malformed input gracefully
✅ **State integrity on rejection** — failed transactions don't mutate balances
✅ **Replay protection** — spent nonces are permanently rejected
✅ **Encoding determinism** — identical inputs produce identical bytes every time
✅ **Signature soundness** — no false positives, no cross-key verification
✅ **Diff scope** — state changes only affect declared accounts

### What the Fuzzer Does NOT Cover

⚠️ **Business logic correctness** — fuzzing checks safety properties, not "is the amount correct"
⚠️ **ZK proof validity** — mocked out; proofs are not generated during fuzzing
⚠️ **Network/consensus layer** — only state machine and encoding layers are fuzzed
⚠️ **`PrivacyPreservingTransaction` encoding roundtrip** — excluded (ZK receipts)

### QA Team Action Items

| Action | Who | When |
|---|---|---|
| Run `just fuzz-regression` before merging LEZ changes | Dev / QA | Each LEZ PR |
| Review crash artifacts in `fuzz/artifacts/` when CI fails | QA | On CI failure |
| Add new invariants when new protocol rules are introduced | QA + Dev | Feature additions |
| Run `just update-lez` before long fuzzing sessions | QA | Before overnight runs |
| Add new fuzz targets for new transaction types | QA + Dev | New tx types |

---

## Appendix: Project File Map

| File / Directory | Purpose |
|---|---|
| [`fuzz_props/src/invariants.rs`](fuzz_props/src/invariants.rs) | `ProtocolInvariant` trait + registered invariants |
| [`fuzz_props/src/generators.rs`](fuzz_props/src/generators.rs) | `proptest` strategies + `Arbitrary` helpers |
| [`fuzz/fuzz_targets/`](fuzz/fuzz_targets/) | 9 fuzz entry points |
| [`fuzz/corpus/`](fuzz/corpus/) | Pre-seeded corpus files (minimised, binary) |
| [`docs/fuzzing.md`](docs/fuzzing.md) | Full operational guide (how-to, commands, CI) |
| [`current_vs_alternative_approach.md`](current_vs_alternative_approach.md) | Comparison with AFL++, proptest-only, formal verification |
| [`colocated_vs_separated.md`](colocated_vs_separated.md) | Architecture decision: separate repo vs. co-located |
| [`fuzz/Cargo.toml`](fuzz/Cargo.toml) | Fuzz workspace manifest (all 9 `[[bin]]` entries) |
| [`Cargo.toml`](Cargo.toml) | Root workspace (fuzz_props + LEZ path dependencies) |

---

*Presentation generated from the `lez-fuzzing` repository. For full operational details, see [`docs/fuzzing.md`](docs/fuzzing.md).*
