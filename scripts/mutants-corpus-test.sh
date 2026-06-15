#!/usr/bin/env bash
# Plane-B mutation-testing oracle.
#
# Called by `cargo mutants --test-command` from *inside* the logos-execution-zone
# workspace directory after each source mutation.  Replays the committed
# libFuzzer corpus against every fuzz target (cargo fuzz run -runs=0).
#
# Exit behaviour (used by cargo-mutants to classify each mutant):
#   exit 0   → all corpus replays passed  → mutant SURVIVED (corpus gap)
#   exit ≠0  → at least one replay panicked → mutant CAUGHT  (corpus covers it)
#
# Environment variables:
#   FUZZ_REPO   absolute path to the lez-fuzzing repository root.
#               Defaults to the directory one level above this script.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FUZZ_REPO="${FUZZ_REPO:-"$(cd "${SCRIPT_DIR}/.." && pwd)"}"

CORPUS_ROOT="${FUZZ_REPO}/corpus/libfuzz"
FUZZ_DIR="${FUZZ_REPO}/fuzz"

targets=(
  fuzz_transaction_decoding
  fuzz_stateless_verification
  fuzz_state_transition
  fuzz_block_verification
  fuzz_encoding_roundtrip
  fuzz_signature_verification
  fuzz_replay_prevention
  fuzz_state_diff_computation
  fuzz_validate_execute_consistency
  fuzz_state_serialization
  fuzz_witness_set_verification
  fuzz_program_deployment_lifecycle
  fuzz_apply_state_diff_split_path
  fuzz_multi_block_state_sequence
  fuzz_sequencer_vs_replayer
  fuzz_merkle_tree
  fuzz_transaction_properties
  fuzz_privacy_preserving_witness
  fuzz_encoding_privacy_preserving
  fuzz_nullifier_set_roundtrip
)

# cargo-fuzz requires the nightly toolchain (-Zsanitizer=address etc.).
# When this script is called by `cargo-mutants` the working directory is the
# LEZ workspace (logos-execution-zone/), whose rust-toolchain.toml pins the
# stable 1.x compiler.  Change to the fuzzing repo so that rustup resolves
# the nightly toolchain from lez-fuzzing/rust-toolchain.toml instead.
cd "${FUZZ_REPO}"

for target in "${targets[@]}"; do
  corpus="${CORPUS_ROOT}/${target}"
  mkdir -p "${corpus}"

  # -runs=0  → replay every file in the corpus directory exactly once, then exit.
  # A panic (invariant violation) causes cargo fuzz to exit non-zero, which
  # propagates through this script and causes cargo-mutants to mark the mutant
  # as CAUGHT.
  cargo fuzz run "${target}" \
    --fuzz-dir "${FUZZ_DIR}" \
    "${corpus}" \
    -- -runs=0
done
