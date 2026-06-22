#!/usr/bin/env python3
"""Fail if any fuzz target registered in fuzz/Cargo.toml is missing from a
workflow / script / doc that enumerates the target list.

`fuzz/Cargo.toml` is the single source of truth: every `[[bin]] name = "fuzz_*"`
must be mentioned by name in each of the consumer files below. This guards
against the drift that `scripts/add_fuzz_target.py` cannot prevent on its own
(it only edits `.github/workflows/fuzz.yml`).

Usage:
    python3 scripts/check_target_inventory.py

Exit code 0 = all consumers list every target; 1 = drift detected (prints the
missing target/file pairs). Run from anywhere; paths are resolved relative to
the repository root.
"""

import re
import sys
from pathlib import Path

# Files that enumerate the full target list and must stay in sync with Cargo.toml.
# Paths are relative to the repository root.
CONSUMERS = [
    ".github/workflows/fuzz.yml",
    ".github/workflows/fuzz-afl.yml",
    ".github/workflows/mutants.yml",
    "scripts/mutants-corpus-test.sh",
    "README.md",
    "docs/fuzzing.md",
]

_BIN_NAME_RE = re.compile(r'name\s*=\s*"(fuzz_[a-z0-9_]+)"')


def registered_targets(cargo_toml: Path) -> list[str]:
    """Every `[[bin]] name = "fuzz_*"` in fuzz/Cargo.toml, in file order."""
    names = _BIN_NAME_RE.findall(cargo_toml.read_text())
    # Preserve order, drop duplicates defensively.
    seen: set[str] = set()
    ordered: list[str] = []
    for n in names:
        if n not in seen:
            seen.add(n)
            ordered.append(n)
    return ordered


def main() -> None:
    root = Path(__file__).parent.parent  # repository root
    cargo_toml = root / "fuzz" / "Cargo.toml"
    if not cargo_toml.exists():
        print(f"ERROR: {cargo_toml} not found", file=sys.stderr)
        sys.exit(1)

    targets = registered_targets(cargo_toml)
    if not targets:
        print(f"ERROR: no [[bin]] targets found in {cargo_toml}", file=sys.stderr)
        sys.exit(1)

    missing: list[tuple[str, str]] = []
    for rel in CONSUMERS:
        path = root / rel
        if not path.exists():
            print(f"ERROR: consumer file not found: {rel}", file=sys.stderr)
            sys.exit(1)
        text = path.read_text()
        for target in targets:
            if target not in text:
                missing.append((rel, target))

    if missing:
        print(
            f"Target-inventory drift: {len(targets)} targets registered in "
            f"fuzz/Cargo.toml, but some consumers are missing entries:\n",
            file=sys.stderr,
        )
        for rel, target in missing:
            print(f"  MISSING  {rel}  ->  {target}", file=sys.stderr)
        print(
            "\nAdd the target(s) above to each listed file "
            "(see scripts/add_fuzz_target.py for the canonical insertion points).",
            file=sys.stderr,
        )
        sys.exit(1)

    print(f"OK: all {len(CONSUMERS)} consumers list every one of the "
          f"{len(targets)} registered targets.")


if __name__ == "__main__":
    main()
