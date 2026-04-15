#!/usr/bin/env python3
"""Fully automates registering a new cargo-fuzz target.

Usage:
    python3 scripts/add_fuzz_target.py <TARGET_NAME>

Where TARGET_NAME is the full binary name, e.g. fuzz_my_feature.

Actions performed:
  1. Appends a [[bin]] entry to fuzz/Cargo.toml
  2. Inserts TARGET_NAME into every YAML matrix block in
     .github/workflows/fuzz.yml  (smoke-fuzz, regression)
  3. Inserts TARGET_NAME into the perf-baseline shell for-loop in
     .github/workflows/fuzz.yml

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


def insert_into_yaml_matrices(target: str, content: str) -> tuple[str, int]:
    """Insert target into YAML strategy matrix blocks.

    Matches blocks of the form::

        target:
          - fuzz_a
          - fuzz_b

    and appends ``          - <target>`` after the last existing entry.
    """
    pattern = re.compile(
        r"(        target:\n(?:          - fuzz_\w+\n)+)",
        re.MULTILINE,
    )

    def add_target(m: re.Match) -> str:
        return m.group(0) + f"          - {target}\n"

    new_content, count = pattern.subn(add_target, content)
    return new_content, count


def insert_into_shell_loop(target: str, content: str) -> tuple[str, int]:
    """Insert target into a 'for target in ... ; do' shell loop.

    The last entry in the loop ends with ``; do``.  We change it to end with
    a backslash continuation and append the new entry with ``; do``.

    Example — before::

              fuzz_block_verification; do

    After::

              fuzz_block_verification \\
              fuzz_new_target; do
    """
    # Match the last fuzz target in the for-loop: "            fuzz_xxx; do"
    # Indentation: 12 spaces (inside a run: | block).
    pattern = re.compile(r"(            fuzz_\w+)(; do)", re.MULTILINE)

    # We only want to replace the *last* occurrence (the closing entry).
    matches = list(pattern.finditer(content))
    if not matches:
        return content, 0

    if len(matches) > 1:
        print(
            f"  ERROR: found {len(matches)} shell loops matching the pattern; "
            "cannot determine which one to update. "
            "Please edit .github/workflows/fuzz.yml manually.",
            file=sys.stderr,
        )
        sys.exit(1)

    m = matches[-1]
    replacement = f"{m.group(1)} \\\n            {target}{m.group(2)}"
    new_content = content[: m.start()] + replacement + content[m.end() :]
    return new_content, 1


def insert_into_workflow(target: str, workflow: Path) -> None:
    """Update all target lists in the fuzz workflow file."""
    content = workflow.read_text()

    if target in content:
        print(f"  SKIP .github/workflows/fuzz.yml — {target!r} already present")
        return

    # 1. YAML matrix blocks (smoke-fuzz, regression)
    content, yaml_count = insert_into_yaml_matrices(target, content)
    if yaml_count:
        print(
            f"  [+] .github/workflows/fuzz.yml — inserted {target!r} into "
            f"{yaml_count} YAML matrix block(s)"
        )
    else:
        print(
            f"  ERROR: no YAML matrix blocks matched in {workflow} — please edit manually",
            file=sys.stderr,
        )
        sys.exit(1)

    # 2. Shell for-loop (perf-baseline)
    content, loop_count = insert_into_shell_loop(target, content)
    if loop_count:
        print(
            f"  [+] .github/workflows/fuzz.yml — inserted {target!r} into "
            f"perf-baseline shell loop"
        )
    else:
        print(
            f"  ERROR: perf-baseline shell loop not found in {workflow} — please edit manually",
            file=sys.stderr,
        )
        sys.exit(1)

    workflow.write_text(content)


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
    workflow = root / ".github" / "workflows" / "fuzz.yml"

    if not cargo_toml.exists():
        print(f"ERROR: {cargo_toml} not found", file=sys.stderr)
        sys.exit(1)
    if not workflow.exists():
        print(f"ERROR: {workflow} not found", file=sys.stderr)
        sys.exit(1)

    append_cargo_bin(target, cargo_toml)
    insert_into_workflow(target, workflow)


if __name__ == "__main__":
    main()
