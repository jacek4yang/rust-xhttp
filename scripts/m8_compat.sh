#!/usr/bin/env bash
# Compatibility smoke test for the current rust-xhttp stack.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
"$ROOT/scripts/m7_e2e.sh"
