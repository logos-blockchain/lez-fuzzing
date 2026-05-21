# ── Fuzzing ───────────────────────────────────────────────────────────────────
export RISC0_DEV_MODE := "1"

# List all registered fuzz targets (reads fuzz/Cargo.toml via cargo-fuzz)
list-targets:
    cargo fuzz list

# Run all fuzz targets for TIME seconds each (default: 30).
# Targets are discovered automatically from fuzz/Cargo.toml — no edit needed here
# when a new [[bin]] entry is added.
fuzz TIME="30":
    #!/bin/bash
    set -euo pipefail
    for target in $(cargo fuzz list 2>/dev/null); do
        echo "=== fuzzing $target for {{TIME}}s ==="
        cargo fuzz run "$target" -- -max_total_time={{TIME}}
    done

# Re-run the saved corpus for every target (regression mode, no new mutations)
fuzz-regression:
    #!/bin/bash
    set -euo pipefail
    for target in $(cargo fuzz list 2>/dev/null); do
        echo "=== regression $target ==="
        mkdir -p "fuzz/corpus/$target"
        cargo fuzz run "$target" "fuzz/corpus/$target" -- -runs=0
    done

# Minimise a crash artifact
# Usage: just fuzz-tmin fuzz_state_transition fuzz/artifacts/fuzz_state_transition/crash-XXX
fuzz-tmin TARGET ARTIFACT:
    cargo fuzz tmin {{TARGET}} {{ARTIFACT}}

# Run the proptest-based property tests
fuzz-props:
    cargo test -p fuzz_props --release

# Pull the latest LEZ changes from the sibling logos-execution-zone directory
update-lez:
    git -C ../logos-execution-zone pull --ff-only

# ── Corpus management ─────────────────────────────────────────────────────────

# Minimise the corpus for all targets (removes dominated inputs)
corpus-cmin:
    #!/bin/bash
    set -euo pipefail
    for target in $(cargo fuzz list 2>/dev/null); do
        echo "=== cmin $target ==="
        cargo fuzz cmin "$target"
    done

# Minimise the corpus for a single target
# Usage: just corpus-cmin-target fuzz_state_transition
corpus-cmin-target TARGET:
    cargo fuzz cmin {{TARGET}}

# ── Adding a new target ───────────────────────────────────────────────────────

# Scaffold a new fuzz target — fully automated, no manual edits required.
#
# Steps performed automatically:
#   1. Creates fuzz/corpus/<TARGET>/
#   2. Copies fuzz/fuzz_targets/_template.rs → fuzz/fuzz_targets/<TARGET>.rs
#   3. Appends the [[bin]] entry to fuzz/Cargo.toml
#   4. Inserts <TARGET> into every strategy matrix in .github/workflows/fuzz.yml
#
# Usage: just new-target my_feature
# (the "fuzz_" prefix is added automatically)
new-target NAME:
    #!/bin/bash
    set -euo pipefail
    TARGET="fuzz_{{NAME}}"
    TEMPLATE="fuzz/fuzz_targets/_template.rs"
    RS_FILE="fuzz/fuzz_targets/${TARGET}.rs"
    CORPUS_DIR="fuzz/corpus/${TARGET}"

    # ── 1. Create corpus directory ────────────────────────────────────────────
    mkdir -p "$CORPUS_DIR"
    echo "[1/4] Created corpus directory: $CORPUS_DIR"

    # ── 2. Copy the typed fuzz target template ────────────────────────────────
    if [ -f "$RS_FILE" ]; then
        echo "SKIP [2/4]: $RS_FILE already exists — not overwriting."
    else
        cp "$TEMPLATE" "$RS_FILE"
        echo "[2/4] Created target from template: $RS_FILE"
    fi

    # ── 3 & 4. Update Cargo.toml and fuzz.yml automatically ──────────────────
    python3 scripts/add_fuzz_target.py "$TARGET"
    echo ""
    echo "Done!  Verify the libFuzzer build with:"
    echo "  RISC0_DEV_MODE=1 cargo fuzz build ${TARGET}"
    echo ""
    echo "Verify the AFL++ build with:"
    echo "  cd fuzz && cargo afl build --no-default-features --features fuzzer-afl --release --bin ${TARGET}"

# ── AFL++ fuzzing ──────────────────────────────────────────────────────────────
# Prerequisites (install once):
#   macOS:  brew install afl-fuzz && cargo install cargo-afl
#   Linux:  Build AFL++ from source (recommended — Debian/Ubuntu apt packages are
#           several major versions behind; see https://github.com/AFLplusplus/AFLplusplus):
#             git clone https://github.com/AFLplusplus/AFLplusplus
#             cd AFLplusplus && make distrib && sudo make install
#           Then: cargo install cargo-afl

# Build ALL fuzz targets for AFL++ (output: fuzz/target/release/<target>)
afl-build:
    cd fuzz && cargo afl build --no-default-features --features fuzzer-afl --release

# Build a SINGLE fuzz target for AFL++
# Usage: just afl-build-target fuzz_state_transition
afl-build-target TARGET:
    cd fuzz && cargo afl build --no-default-features --features fuzzer-afl --release --bin {{TARGET}}

# Disable the macOS crash reporter daemon so AFL++ can detect crashes reliably.
# This is a macOS-only requirement; on Linux this is a no-op.
# The `fuzz-afl` recipe calls this automatically; run it manually if you want
# to keep the reporter disabled across multiple just invocations.
#
# Re-enable with: just afl-macos-teardown
afl-macos-setup:
    #!/bin/bash
    if [ "$(uname)" != "Darwin" ]; then echo "Not macOS — nothing to do."; exit 0; fi
    SL=/System/Library; PL=com.apple.ReportCrash
    echo "Disabling macOS crash reporter (required by AFL++)…"
    launchctl unload -w "${SL}/LaunchAgents/${PL}.plist"       2>/dev/null || true
    sudo launchctl unload -w "${SL}/LaunchDaemons/${PL}.Root.plist" 2>/dev/null || true
    echo "Done. Re-enable with: just afl-macos-teardown"

# Re-enable the macOS crash reporter after an AFL++ session.
afl-macos-teardown:
    #!/bin/bash
    if [ "$(uname)" != "Darwin" ]; then echo "Not macOS — nothing to do."; exit 0; fi
    SL=/System/Library; PL=com.apple.ReportCrash
    echo "Re-enabling macOS crash reporter…"
    launchctl load -w "${SL}/LaunchAgents/${PL}.plist"       2>/dev/null || true
    sudo launchctl load -w "${SL}/LaunchDaemons/${PL}.Root.plist" 2>/dev/null || true
    echo "Done."

# Run AFL++ on one target or ALL targets when no target is supplied.
# Builds binaries as needed; syncs the queue to the shared corpus when done.
#
# On macOS the crash reporter is disabled automatically for the duration of the
# run and re-enabled when the script exits (via a shell trap).
#
# Requires afl-fuzz and cargo-afl to be installed locally:
#   macOS:  brew install afl-fuzz && cargo install cargo-afl
#   Linux:  Build AFL++ from source (apt packages are several major versions
#           behind): see https://github.com/AFLplusplus/AFLplusplus
#
# Usage: just fuzz-afl                            # all targets, 120 s each
#        just fuzz-afl "" 60                      # all targets, 60 s each
#        just fuzz-afl fuzz_state_transition      # single target, 120 s
#        just fuzz-afl fuzz_state_transition 300  # single target, 300 s
fuzz-afl TARGET="" TIME="120":
    #!/bin/bash
    set -euo pipefail
    TARGET="{{TARGET}}"
    TIME="{{TIME}}"

    # ── Collect targets to run ────────────────────────────────────────────────
    if [ -z "$TARGET" ]; then
        TARGETS=($(cargo fuzz list 2>/dev/null))
    else
        TARGETS=("$TARGET")
    fi

    # ── Require local AFL++ installation ─────────────────────────────────────
    if ! command -v afl-fuzz &>/dev/null; then
        echo "ERROR: afl-fuzz not found in PATH."
        echo ""
        echo "Install AFL++ before running this recipe:"
        echo ""
        echo "  macOS : brew install afl-fuzz"
        echo ""
        echo "  Linux : Build from source (apt packages are several major versions behind):"
        echo "            git clone https://github.com/AFLplusplus/AFLplusplus"
        echo "            cd AFLplusplus && make distrib && sudo make install"
        echo ""
        echo "Also install the cargo-afl build wrapper:"
        echo "  cargo install cargo-afl"
        echo ""
        exit 1
    fi
    if ! command -v cargo-afl &>/dev/null && ! cargo afl --version &>/dev/null 2>&1; then
        echo "ERROR: cargo-afl not found."
        echo "  cargo install cargo-afl"
        exit 1
    fi

    # ── macOS: disable crash reporter for the duration of this run ───────────
    if [ "$(uname)" = "Darwin" ]; then
        SL=/System/Library; PL=com.apple.ReportCrash
        echo "macOS: disabling crash reporter (AFL++ requirement)…"
        launchctl unload -w "${SL}/LaunchAgents/${PL}.plist"            2>/dev/null || true
        sudo launchctl unload -w "${SL}/LaunchDaemons/${PL}.Root.plist" 2>/dev/null || true
        # Re-enable on any exit — normal, error, or Ctrl-C
        trap '
            echo "Re-enabling macOS crash reporter…"
            SL=/System/Library; PL=com.apple.ReportCrash
            launchctl load -w "${SL}/LaunchAgents/${PL}.plist"            2>/dev/null || true
            sudo launchctl load -w "${SL}/LaunchDaemons/${PL}.Root.plist" 2>/dev/null || true
        ' EXIT
    fi

    # ── Run targets ───────────────────────────────────────────────────────────
    _run_one() {
        local t="$1"
        local BINARY="fuzz/target/release/$t"
        local CORPUS="fuzz/corpus/$t"
        local OUTPUT="afl-output/$t"
        mkdir -p "$CORPUS" "$OUTPUT"
        if [ ! -f "$BINARY" ]; then
            echo "Binary not found — building $t first…"
            just afl-build-target "$t"
        fi
        timeout "$TIME" afl-fuzz -i "$CORPUS" -o "$OUTPUT" -- "$BINARY" || true
    }
    for t in "${TARGETS[@]}"; do
        echo "=== afl++ $t for ${TIME}s ==="
        _run_one "$t"
    done
    just afl-corpus-sync

# Run AFL++ with N parallel instances (1 main + N-1 secondary) for TIME seconds.
# Requires that afl-fuzz is on PATH; all instances share afl-output/{{TARGET}}/.
# On macOS the crash reporter is disabled automatically for the duration of the
# run and re-enabled when the script exits.
#
# Usage: just fuzz-afl-parallel fuzz_state_transition
#        just fuzz-afl-parallel fuzz_state_transition 8 600
fuzz-afl-parallel TARGET WORKERS="4" TIME="300":
    #!/bin/bash
    set -euo pipefail
    BINARY="fuzz/target/release/{{TARGET}}"
    CORPUS="fuzz/corpus/{{TARGET}}"
    OUTPUT="afl-output/{{TARGET}}"
    mkdir -p "$CORPUS" "$OUTPUT"
    if [ ! -f "$BINARY" ]; then
        echo "Binary not found — building first…"
        just afl-build-target {{TARGET}}
    fi
    # ── macOS: disable crash reporter for the duration of this run ───────────
    if [ "$(uname)" = "Darwin" ]; then
        SL=/System/Library; PL=com.apple.ReportCrash
        echo "macOS: disabling crash reporter (AFL++ requirement)…"
        launchctl unload -w "${SL}/LaunchAgents/${PL}.plist"            2>/dev/null || true
        sudo launchctl unload -w "${SL}/LaunchDaemons/${PL}.Root.plist" 2>/dev/null || true
        trap '
            echo "Re-enabling macOS crash reporter…"
            SL=/System/Library; PL=com.apple.ReportCrash
            launchctl load -w "${SL}/LaunchAgents/${PL}.plist"            2>/dev/null || true
            sudo launchctl load -w "${SL}/LaunchDaemons/${PL}.Root.plist" 2>/dev/null || true
        ' EXIT
    fi
    # Main instance
    afl-fuzz -M main -i "$CORPUS" -o "$OUTPUT" -- "$BINARY" &
    # Secondary instances
    for i in $(seq 1 $(( {{WORKERS}} - 1 ))); do
        afl-fuzz -S "secondary${i}" -i "$CORPUS" -o "$OUTPUT" -- "$BINARY" &
    done
    sleep {{TIME}}
    kill $(jobs -p) 2>/dev/null || true
    wait 2>/dev/null || true
    just afl-corpus-sync

# Copy all queue entries from every AFL++ output directory into the matching
# shared corpus directory (fuzz/corpus/<target>/).  Run after any AFL++ session
# to make new interesting inputs available to cargo-fuzz and CI.
afl-corpus-sync:
    #!/bin/bash
    set -euo pipefail
    if [ ! -d afl-output ]; then
        echo "afl-output/ does not exist — nothing to sync."
        exit 0
    fi
    for target_dir in afl-output/*/; do
        TARGET=$(basename "$target_dir")
        DEST="fuzz/corpus/${TARGET}"
        mkdir -p "$DEST"
        count=0
        for instance_dir in "$target_dir"*/; do
            QUEUE="${instance_dir}queue"
            [ -d "$QUEUE" ] || continue
            for f in "$QUEUE"/id:*; do
                [ -f "$f" ] || continue
                HASH=$(sha1sum "$f" | cut -d' ' -f1)
                DEST_FILE="${DEST}/${HASH}"
                if [ ! -f "$DEST_FILE" ]; then
                    cp "$f" "$DEST_FILE"
                    count=$((count + 1))
                fi
            done
        done
        echo "Synced $count new input(s) → $DEST"
    done

# Show AFL++ campaign statistics for a target
# Usage: just afl-status fuzz_state_transition
afl-status TARGET:
    afl-whatsup afl-output/{{TARGET}}

# Minimise a crash or hang artifact to the smallest reproducing input.
# Usage: just afl-tmin fuzz_state_transition afl-output/fuzz_state_transition/crashes/id:000000,...
afl-tmin TARGET ARTIFACT:
    afl-tmin -i {{ARTIFACT}} -o {{ARTIFACT}}.min -- fuzz/target/release/{{TARGET}}

# Pretty-print an AFL++ artifact as a Rust byte-string literal (for copy-paste
# into a unit test or issue report).
# Usage: just afl-fmt afl-output/fuzz_state_transition/crashes/id:000000,...
afl-fmt ARTIFACT:
    python3 -c "import sys; data=open(sys.argv[1],'rb').read(); print('b\"' + ''.join(f'\\\\x{b:02x}' for b in data) + '\"')" {{ARTIFACT}}

# ── Coverage ──────────────────────────────────────────────────────────────────

# Generate a coverage report for a single target.
#
# Step 1 (libFuzzer): cargo fuzz coverage {{TARGET}}
# Step 2 (AFL++, only if afl-output/{{TARGET}}/ exists):
#   Build with instrument-coverage, run the AFL++ queue through the binary,
#   merge raw profiles, and generate an HTML report in coverage/afl/{{TARGET}}/.
#
# Usage: just coverage fuzz_state_transition
coverage TARGET:
    #!/bin/bash
    set -euo pipefail
    # ── Step 1: libFuzzer coverage ────────────────────────────────────────────
    echo "=== cargo fuzz coverage {{TARGET}} ==="
    cargo fuzz coverage {{TARGET}} || true

    # ── Step 2: AFL++ LLVM coverage (only if queue data exists) ──────────────
    AFL_OUTPUT="afl-output/{{TARGET}}"
    if [ ! -d "$AFL_OUTPUT" ]; then
        echo "No AFL++ output for {{TARGET}} — skipping AFL++ coverage step."
        exit 0
    fi
    echo "=== AFL++ LLVM coverage for {{TARGET}} ==="
    BINARY_DIR="fuzz/target/release"
    COV_DIR="coverage/afl/{{TARGET}}"
    PROFRAW_DIR="${COV_DIR}/profraw"
    mkdir -p "$PROFRAW_DIR"

    # Build the target with LLVM instrumentation enabled.
    RUSTFLAGS="-C instrument-coverage" \
        cargo build \
            --manifest-path fuzz/Cargo.toml \
            --no-default-features \
            --features fuzzer-afl \
            --release \
            --bin {{TARGET}}

    BINARY="${BINARY_DIR}/{{TARGET}}"

    # Run every queue entry through the instrumented binary.
    idx=0
    for instance_dir in "$AFL_OUTPUT"/*/; do
        QUEUE="${instance_dir}queue"
        [ -d "$QUEUE" ] || continue
        for f in "$QUEUE"/id:*; do
            [ -f "$f" ] || continue
            LLVM_PROFILE_FILE="${PROFRAW_DIR}/${idx}.profraw" "$BINARY" < "$f" 2>/dev/null || true
            idx=$((idx + 1))
        done
    done

    # Merge raw profiles.
    PROFDATA="${COV_DIR}/merged.profdata"
    llvm-profdata merge -sparse "${PROFRAW_DIR}"/*.profraw -o "$PROFDATA"

    # Generate HTML report.
    HTML_DIR="${COV_DIR}/html"
    mkdir -p "$HTML_DIR"
    llvm-cov show \
        "$BINARY" \
        --instr-profile="$PROFDATA" \
        --format=html \
        --output-dir="$HTML_DIR" \
        --ignore-filename-regex='\.cargo|rustc'
    echo "AFL++ HTML coverage report: ${HTML_DIR}/index.html"

# Generate coverage for ALL registered fuzz targets (libFuzzer + AFL++).
coverage-all:
    #!/bin/bash
    set -euo pipefail
    for target in $(cargo fuzz list 2>/dev/null); do
        echo "=== coverage $target ==="
        just coverage "$target"
    done

# ── Housekeeping ──────────────────────────────────────────────────────────────

# Remove all Cargo build artefacts (workspace + fuzz sub-crate)
clean:
    cargo clean
    cargo clean --manifest-path fuzz/Cargo.toml

# Remove libFuzzer crash/timeout artifacts for all targets (corpus is kept)
clean-artifacts:
    rm -rf fuzz/artifacts/

# Remove coverage reports generated by `cargo fuzz coverage` and `just coverage`
clean-coverage:
    rm -rf fuzz/coverage/ coverage/

# Remove AFL++ output directories (crash/hang/queue findings)
clean-afl:
    rm -rf afl-output/

# Remove everything: builds, artifacts, coverage, and AFL++ output
clean-all: clean clean-artifacts clean-coverage clean-afl
