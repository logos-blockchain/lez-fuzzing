#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

cargo test -p fuzz_props generate_seeds -- --nocapture 2>/dev/null || true
