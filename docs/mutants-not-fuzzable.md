# Mutants Not Coverable by Fuzzing

This document catalogues the source mutations (from `just mutants-protocol`, the
"Plane B" corpus-replay mutation run over the `lee` / `common` crates) that the
**fuzzing corpus is not the right tool to catch**, together with where each one is
actually covered.

It exists to keep a clean separation between two questions that the tooling can
otherwise blur together:

- **"Does a test catch this mutant?"** — answered by the `lee` crate's own unit
  tests via `cargo test` (call this **Plane A**).
- **"Does the committed fuzz corpus catch this mutant?"** — answered by
  `just mutants-protocol`, which replaces `cargo test` with a fuzz-corpus replay
  (`cargo fuzz run … -runs=0`) as the oracle (call this **Plane B**).

The mutants listed here are **expected Plane-B misses**. A future
`mutants-protocol` run that reports them as surviving is *not* a regression — it
is the documented, intended state.

This file is the complete registry, in **two groups**:

1. **Structurally unreachable by fuzzing** (Group 1) — mutants behind code that a
   fuzzer cannot reach from raw bytes (they need a valid executing transaction or a
   deliberately-misbehaving program). These were always unit-test territory.
2. **Migrated input-independent targets** (Group 2) — mutants that *were* caught by
   input-independent fuzz targets (`fuzz_common_invariants`,
   `fuzz_genesis_invariants`, `fuzz_system_account_protection`). Because an
   input-independent target is a unit test in disguise, those targets were removed
   and their invariants ported to LEZ unit tests; the mutants therefore now survive
   Plane B by design.

Reconcile new `mutants-protocol` runs against this registry; only a surviving
mutant on **neither** list warrants a new corpus input.

---

## 🧭 Why fuzzing is the wrong tool for these

Fuzzing earns its keep by exploring a large, *unknown* input space to find inputs
a human wouldn't think of — malformed transactions, adversarial byte sequences,
surprising state-transition orderings. The corpus-replay oracle then re-runs those
discovered inputs cheaply as a regression net.

The mutations below live behind code that is only reachable by a **specific,
valid, semantically rich object** that random bytes essentially never synthesise:

1. **A fully-valid, executing transaction.** Reaching the post-execution
   validation logic (authorization checks, claim checks, cycle limit) requires a
   transaction whose signature matches its signer, whose nonce matches the
   on-chain nonce, and whose program is deployed. A fuzzer mutating raw bytes
   almost always breaks one of these and is rejected at the stateless/nonce gate
   *before* any program runs — so the code never executes. Constructing such a
   transaction is a deterministic "this exact scenario must hold" property, which
   is the domain of **unit tests**, not input exploration.

2. **A deliberately-misbehaving program.** Some validator checks only fire when a
   program returns malformed output (claims an account it shouldn't, mutates a
   default account without claiming it, etc.). The only such programs are the
   test fixtures behind `V03State::with_test_programs()` (`program_owner_changer`,
   `extra_output_program`, …). They are **never deployed** in genesis or
   production, so they are unreachable through the public transaction API that the
   fuzzer drives — by construction, no fuzz input can exercise them.

In both cases the behaviour is pinned by deterministic unit tests in the `lee` /
`common` crates. Encoding such scenarios as **input-independent** fuzz targets
(targets that ignore their input and run a fixed battery) is an anti-pattern — it
duplicates the unit-test role, adds heavyweight zkVM work to every corpus replay,
and risks silent corpus rot, all to satisfy a metric (Plane B) better served by
documenting the boundary. `lez-fuzzing` therefore keeps **no** input-independent
targets: the public/privacy execution targets (which duplicated existing `lee`
tests) and the three genesis/common/system targets (whose invariants were ported
to new unit tests — see the companion doc) were all removed.

---

## 📋 Catalogue (Group 1 — structurally unreachable by fuzzing)

The mutations reported as MISSED by the `mutants-protocol` run for which
fuzzing is structurally the wrong tool, with their true coverage. Verified by
applying each mutation to the `logos-execution-zone` working tree and running the
cited tests (`RISC0_DEV_MODE=1 cargo test -p lee --lib`). (Group 2 — the migrated
input-independent-target mutants — is summarised further down.)

> [!NOTE]
> **Line numbers drift as the LEZ source evolves.** Reconcile by *function name +
> mutation operator*, not by line number. The `Location` column below was last
> refreshed against `logos-execution-zone` at `e37876a64` (2026-07-08). If a
> `mutants-protocol` run reports a documented mutation at a *different* line, it is
> the same catalogued miss — update the line here rather than treating it as new.

| # | Location | Mutation | Category | Covered by |
|---|----------|----------|----------|------------|
| 1 | `lee/state_machine/src/program.rs:15:51` | `*` → `/` (cycle limit `32`) | Valid-tx unit test | transfer-execution tests |
| 2 | `lee/state_machine/src/program.rs:15:51` | `*` → `+` (cycle limit `33 792`) | Valid-tx unit test | transfer-execution tests |
| 3 | `lee/state_machine/src/program.rs:15:58` | `*` → `/` (cycle limit `32 768`) | Valid-tx unit test | transfer-execution tests |
| 4 | `lee/state_machine/src/program.rs:15:58` | `*` → `+` (cycle limit `1 048 608`) | **Near-equivalent — genuine gap** | nothing (see below) |
| 5 | `lee/state_machine/src/validated_state_diff.rs:160:21` | `\|\|` → `&&` | Valid-tx unit test | transfer-execution tests |
| 6 | `lee/state_machine/src/validated_state_diff.rs:316:34` | `!=` → `==` | Misbehaving-program unit test | `public_changer_claimer_*` |
| 7 | `lee/state_machine/src/validated_state_diff.rs:319:20` | `==` → `!=` | Misbehaving-program unit test | `public_changer_claimer_*` + validity-window tests |
| 8 | `lee/state_machine/src/privacy_preserving_transaction/circuit.rs:90:32` | `>=` → `<` | Valid-PP-tx unit test | PP transition tests |
| 9 | `lee/state_machine/src/state.rs:302:16` | delete `!` | Valid-PP-tx unit test | PP transition tests |
| 10 | `lez/common/src/transaction.rs:173:17` | delete `balance` field | Bridge-guard gap (see Category D) | **nothing yet** |
| 11 | `lez/common/src/transaction.rs:176:27` | `==` → `!=` | Misbehaving-program unit test (see Category D) | **nothing yet** |
| 12 | `lez/common/src/transaction.rs:176:35` | `&&` → `\|\|` | Misbehaving-program unit test (see Category D) | **nothing yet** |
| 13 | `lez/common/src/transaction.rs:176:51` | `<=` → `>` | Bridge-guard gap (see Category D) | **nothing yet** |
| 14 | `lee/state_machine/src/signature/private_key.rs:71:12` | delete `!` in `tweak` | Crypto key-derivation unit test | `signature::private_key::tests::tweak_deterministic` |

### Category A — Covered by `lee` unit tests, requires a valid *executing* transaction (1–3, 5, 8, 9)

These fire only after a fully-valid transaction reaches real program execution.
A fuzzer's random bytes are rejected at the nonce/signature gate first, so the
corpus never reaches them; the `lee` crate pins each with a deterministic test.

- **1–3 (public cycle limit, the catchable variants).**
  `MAX_NUM_CYCLES_PUBLIC_EXECUTION = 1024 * 1024 * 32` (= 33 554 432). A real
  `authenticated_transfer` execution consumes **between 33 792 and 1 048 608**
  RISC-V cycles, so any mutation lowering the limit below that range aborts
  execution with *"Session limit exceeded"*.
  Covered by `state::tests::transition_from_authenticated_transfer_program_invocation_*`
  (and the ~66 other public-execution tests that run a transfer). Verified: limit
  `33 792` → 66 tests fail.

- **5 (`||` → `&&` in `is_authorized`,
  `validated_state_diff.rs:155`).** With `&&`, the transaction signer is no longer
  treated as authorized, so a valid transfer fails with
  `InvalidAccountAuthorization`. Covered by the same transfer-execution tests.
  Verified: 3 of 7 `transition_from*` tests fail.

- **8 (`>=` → `<` in `execute_and_prove`,
  `circuit.rs:88`).** With `<`, the chained-call guard fires on the first
  iteration (`0 < MAX`) and proving aborts immediately with
  `MaxChainedCallsDepthExceeded`. Covered by
  `state::tests::transition_from_privacy_preserving_transaction_{shielded,private,deshielded}`.
  Verified: 3 PP tests fail.

- **9 (delete `!` in `check_nullifiers_are_valid`,
  `state.rs:335`).** Removing the `!` inverts the digest check so a *recognised*
  commitment-set digest is rejected, breaking every valid privacy-preserving
  transfer that spends a private input. Covered by the same PP transition tests.
  Verified: 3 PP tests fail.

### Category B — Covered by `lee` unit tests, requires a *misbehaving* program (6, 7)

These guard against a program returning malformed output (modifying or claiming a
default account incorrectly). Only the test-only fixtures behind
`V03State::with_test_programs()` misbehave this way; they are never deployed, so no
fuzz input can reach this code. The `lee` crate exercises them directly.

- **6 (`!=` → `==`, `validated_state_diff.rs:311`)** — the
  "only inspect uninitialised accounts" filter. Verified: 1 test fails under the
  full `lee` suite.
- **7 (`==` → `!=`, `validated_state_diff.rs:314`)** — the
  "skip unmodified accounts" guard. Verified: 16 tests fail, including
  `state::tests::public_changer_claimer_data_change_no_claim_fails` and
  `public_changer_claimer_no_data_change_no_claim_succeeds`.

> [!NOTE]
> an earlier analysis guessed 6 and 7 were *equivalent mutants*. They are
> not — they are caught by Plane A, just not reachable by Plane B. They appear
> "equivalent" only if you restrict yourself to the deployed `authenticated_transfer`
> program, which is exactly the restriction fuzzing operates under.

### Category C — The single genuine gap: near-equivalent weak mutant (4)

- **4 (`*` → `+` at `program.rs:21:58`, cycle limit `1 048 608`).**
  Catching this would require a *single* public program execution that consumes
  **more than 1 048 608 RISC-V cycles**. The `authenticated_transfer` instruction
  uses fewer than that (it is caught only by limits ≤ 33 792 — see category A), and
  no deployed program's single instruction reaches ~1M cycles. The difference
  between the mutated limit (1.05M) and the real limit (33.5M) is therefore
  **unobservable for any realistic workload**, making this a practically
  equivalent / weak mutant. Verified: survives the full `lee` suite (211/211 pass).

  It is not worth chasing in either plane. If a future deployed program legitimately
  performs a >1M-cycle public execution, a normal execution test for that program
  would catch this mutation incidentally.

### Category D — System-bridge guard (10–13) and key tweak (14)

Added after the original catalogue; both live behind a valid *executing* transaction
and so are structurally unreachable by the byte-mutating fuzzer for the same reason
as Categories A/B.

**10–13 — `LeeTransaction::validate_bridge_account_modification`
(`lez/common/src/transaction.rs:154`).** This guard runs inside `validate_on_state`
and only does anything when the transaction's `public_diff` already *modifies the
system bridge account*:

```rust
let Some(post) = diff.public_diff().get(&bridge_account_id).cloned() else {
    return Ok(());                       // bridge untouched → nothing to check
};
// …
let only_balance_increased = {
    let expected_pre = lee::Account { balance: pre.balance, ..post.clone() };
    (expected_pre == pre) && (pre.balance <= post.balance)   // lines 172–176
};
```

Getting the bridge into `public_diff` at all is exactly what a random-bytes fuzzer
cannot do:

- A plain signed `authenticated_transfer` that *credits* the bridge is rejected by
  program execution with `ClaimedUnauthorizedAccount` (the bridge is not a signer),
  so it never lands in the diff. **Verified** by constructing such a transfer and
  running it through `validate_on_state`.
- The only transactions that legitimately touch the bridge are sequencer-built
  deposits (`programs::bridge()` + `bridge_core::Instruction::Deposit`, empty witness
  set). Those change the bridge account's *data*, not just its balance, and are run
  through the guard-bypassing `execute_without_system_accounts_check_on_state`
  path — never through `validate_on_state`.

So no fuzz input can reach this guard, and `common`'s existing
`validate_on_state`-based tests pass *trivially* (the transfer errors before the
guard). **These four mutants are currently caught by neither plane** — an genuine
Plane-A gap on protocol-critical system-account-protection logic, not just a Plane-B
miss:

| # | Mutation | Killed by a test that asserts… |
|---|----------|--------------------------------|
| 10 | delete `balance: pre.balance` override | a pure bridge *balance increase* is **accepted** |
| 11 | `==` → `!=` in `expected_pre == pre` | a pure bridge *balance increase* is **accepted** |
| 12 | `&&` → `\|\|` | a bridge modification that also changes *data* is **rejected** |
| 13 | `<=` → `>` | a pure bridge *balance increase* is **accepted** |

Recommended follow-up (in `logos-execution-zone`, not the fuzzing corpus): a
`common` unit test that reaches the guard with a genuine bridge-modifying diff. It
needs the `bridge`/`vault` programs and a bridge-owned account (i.e. the sequencer
deposit construction), which `common`'s test deps do not currently pull in — hence
this is filed as a gap rather than resolved here. Mutant 12 also has a
misbehaving-program flavour (a program that alters the bridge's data while raising
its balance), mirroring Category B.

**14 — delete `!` in `PrivateKey::tweak`
(`lee/state_machine/src/signature/private_key.rs:71`).** `tweak` derives the
"tweaked secret key" used for BIP-340 Schnorr signatures; it is called from
`key_protocol` key derivation, never from the transaction-validation path a fuzzer
drives, so raw bytes cannot reach it. Removing the `!` inverts the up-front validity
check (`if !is_valid_key { return Err }`), causing a *valid* key to be rejected.
**Covered by Plane A:** `signature::private_key::tests::tweak_deterministic` tweaks
`[1; 32]` and `.unwrap()`s the result — under the mutation that call returns
`Err(InvalidPrivateKey)` and the test fails. **Verified:** applying the mutation
fails `tweak_deterministic` (4 passed / 1 failed) under `cargo test -p lee --lib`.

---

## 🔁 Group 2 — migrated input-independent targets

These mutants used to be caught by Plane B via input-independent fuzz targets.
Those targets were removed and their invariants ported to LEZ unit tests, so the
mutants now survive Plane B by design. They are **not** structurally unreachable
like Group 1 — a fuzzer could "catch" them, but only by running a fixed scenario
that ignores its input, which is a unit test, not fuzzing.

Each port below was verified to kill its mutant (apply the mutation → run the named
test → observe a failure). Where a mutant had **no** prior unit-test coverage, the
port *added* coverage rather than merely relocating it; those are marked **(new)**.

**From `fuzz_common_invariants`:**

| Mutant | New unit test |
|---|---|
| `HashType::as_ref` → `Vec::leak(Vec::new())` / `vec![0]` / `vec![1]` | `common::tests::as_ref_returns_exact_inner_bytes` (`common/src/lib.rs`) **(new)** |
| `BasicAuth` `FromStr` delete `!` in `.filter(\|p\| !p.is_empty())` | `common::config::tests::parse_empty_password_is_none` (+ `parse_preserves_non_empty_password`) **(new)** |
| `Program::elf` → empty / `vec![0]` / `vec![1]` | `program::tests::elf_returns_the_program_bytecode_constant` (was already caught incidentally) |
| `Proof::into_inner` / `from_inner` → `vec![]` / `vec![0]` / `vec![1]` | `…::circuit::tests::proof_inner_roundtrip` **(new)** |
| `Message::into_bytecode` → `vec![]` / `vec![0]` / `vec![1]` | `program_deployment_transaction::message::tests::bytecode_roundtrip` **(new)** |

**From `fuzz_genesis_invariants`** (all in `lee/state_machine/src/state.rs`):

| Mutant | New unit test |
|---|---|
| `system_faucet_account` → `Default` / delete `balance` / delete `program_owner` | `state::tests::genesis_system_accounts_have_expected_contents` **(new)** |
| `system_bridge_account` → `Default` / delete `program_owner` | `genesis_system_accounts_have_expected_contents` **(new)** |
| `commitment_set_digest` → `Default` | `state::tests::genesis_commitment_set_digest_differs_from_empty_state` **(new)** |
| `add_pinata_token_program` delete `program_owner` / `data` | `state::tests::add_pinata_token_program_sets_non_default_owner_and_data` **(new)** |
| `system_faucet_account_id` / `system_bridge_account_id` → `Default` | `genesis_system_accounts_have_expected_contents` + `system_account_ids_are_distinct_and_non_default` (was already caught) |

**From `fuzz_system_account_protection`:**

| Mutant | New unit test |
|---|---|
| `validate_doesnt_modify_account` `!=` → `==` (`common/src/transaction.rs`) | `common::transaction::tests::validate_on_state_rejects_modifying_a_system_account` **(new)** |
| `public_diff` → `HashMap::new()` (`lee/.../validated_state_diff.rs`) | `validated_state_diff::tests::public_diff_reflects_a_successful_transfer` (+ the `validate_on_state_rejects…` test) **(new)** |
| `system_*_account_id` non-default / distinct | `common::transaction::tests::system_account_ids_are_distinct_and_non_default` (was already caught) |

---

## ✅ Re-verifying

From `logos-execution-zone/` with the fuzzing repo checked out as a sibling:

```bash
export RISC0_DEV_MODE=1

# Pick a mutation from a table above, apply it to the cited line, then run the
# owning crate's tests (Plane A). A real failure ⇒ unit tests cover it.
cargo test -p lee --lib              # lee-owned mutants
cargo test -p common                 # common-owned mutants (Group 2)
git checkout -- <mutated-file>       # always revert
```

A mutation that makes `cargo test` fail is covered by Plane A and belongs in this
registry; a mutation that the corpus replay (`just mutants-protocol`) catches
belongs in the corpus instead. Caught by **neither** plane today: mutation #4 (the
near-equivalent cycle-limit weak mutant) and mutations #10–#13 (the system-bridge
guard, Category D) — the latter a genuine Plane-A gap awaiting a `common` unit test
that reaches the guard with a real bridge-modifying diff.

> [!TIP]
> when reverting, prefer reverse-editing only the mutated line rather than
> `git checkout -- <file>` if you have uncommitted unit tests in the same file —
> a whole-file checkout would discard them too.
