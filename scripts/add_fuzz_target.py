#!/usr/bin/env python3
"""Register a new cargo-fuzz / AFL++ fuzz target.

Usage:
    python3 scripts/add_fuzz_target.py <TARGET_NAME>

Where TARGET_NAME is the full binary name, e.g. fuzz_my_feature.

A single `[[bin]]` entry in fuzz/Cargo.toml is the source of truth for BOTH
engines and for every workflow/script: the CI matrices and build loops derive
their target lists from fuzz/Cargo.toml at runtime (via the
`.github/actions/resolve-targets` composite action, or an inline parse in
`scripts/mutants-corpus-test.sh`). Appending the `[[bin]]` is therefore all this
script needs to do — no workflow editing.

  - libFuzzer build:  cargo fuzz build <TARGET>
  - AFL++ build:      cd fuzz && cargo afl build \\
                        --no-default-features --features fuzzer-afl \\
                        --release --bin <TARGET>

The only remaining manual step is the human-authored target tables in README.md
and docs/fuzzing.md, which carry a prose description per target that cannot be
auto-generated. `scripts/check_target_inventory.py` (run in CI) guards those.

Run from the repository root.
"""

import re
import sys
from pathlib import Path

# Target names must follow the cargo-fuzz binary naming convention.
_TARGET_RE = re.compile(r"^fuzz_[a-z][a-z0-9_]*$")


def append_cargo_bin(target: str, cargo_toml: Path) -> None:
    """Append a [[bin]] entry to fuzz/Cargo.toml if not already present."""
    content = cargo_toml.read_text()
    if f'name = "{target}"' in content:
        print(f"  SKIP fuzz/Cargo.toml — [[bin]] {target!r} already present")
        return

    entry = (
        f"\n[[bin]]\n"
        f'name = "{target}"\n'
        f'path = "fuzz_targets/{target}.rs"\n'
        f"test = false\n"
        f"bench = false\n"
    )
    cargo_toml.write_text(content.rstrip("\n") + "\n" + entry)
    print(f"  [+] fuzz/Cargo.toml  — added [[bin]] {target!r}")


def main() -> None:
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <TARGET_NAME>", file=sys.stderr)
        sys.exit(1)

    target = sys.argv[1]

    if not _TARGET_RE.match(target):
        print(
            f"ERROR: target name must match fuzz_[a-z][a-z0-9_]*, got: {target!r}",
            file=sys.stderr,
        )
        sys.exit(1)

    root = Path(__file__).parent.parent  # repository root

    cargo_toml = root / "fuzz" / "Cargo.toml"
    if not cargo_toml.exists():
        print(f"ERROR: {cargo_toml} not found", file=sys.stderr)
        sys.exit(1)

    append_cargo_bin(target, cargo_toml)

    # ── Print build instructions ──────────────────────────────────────────────
    print()
    print("Registration complete!  Next steps:")
    print()
    print("  1. Implement the harness body in:")
    print(f"       fuzz/fuzz_targets/{target}.rs")
    print()
    print("  2. Verify the libFuzzer (cargo-fuzz) build:")
    print(f"       RISC0_DEV_MODE=1 cargo fuzz build {target}")
    print()
    print("  3. Verify the AFL++ build (single shared fuzz/Cargo.toml):")
    print(f"       cd fuzz && cargo afl build \\")
    print(f"         --no-default-features --features fuzzer-afl \\")
    print(f"         --release --bin {target}")
    print()
    print("  4. Run with libFuzzer:  just fuzz-one", target)
    print("     Run with AFL++:      just fuzz-afl", target)
    print()
    print("  5. Every workflow and script derives its target list from")
    print("     fuzz/Cargo.toml, so no CI edits are needed. Only add a prose row")
    print("     to the two doc tables, then verify with:")
    print("       python3 scripts/check_target_inventory.py")
    print("     (the same check runs in CI and will fail the build on drift):")
    print("       README.md, docs/fuzzing.md")


if __name__ == "__main__":
    main()
