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

# Derive the target list from fuzz/Cargo.toml (the single source of truth) — the same
# `[[bin]] name = "fuzz_*"` parse that .github/actions/resolve-targets uses. This keeps
# the script in sync with every workflow automatically, with no hand-maintained list.
# (A while-read loop rather than `mapfile`, so this also works under macOS' bash 3.2.)
CARGO_TOML="${FUZZ_DIR}/Cargo.toml"
targets=()
while IFS= read -r _target; do
  [ -n "${_target}" ] && targets+=("${_target}")
done < <(
  grep -oE 'name = "fuzz_[a-z0-9_]+"' "${CARGO_TOML}" \
    | sed -E 's/.*"(fuzz_[a-z0-9_]+)"/\1/' \
    | awk '!seen[$0]++'
)
if [ "${#targets[@]}" -eq 0 ]; then
  echo "ERROR: no fuzz_* [[bin]] targets found in ${CARGO_TOML}" >&2
  exit 1
fi

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
