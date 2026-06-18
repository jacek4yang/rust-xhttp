#!/usr/bin/env bash
# Netem wrapper entry. For now it runs the local XHTTP E2E; add traffic shaping
# outside this script before invoking it.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
echo "running local XHTTP E2E"
"$ROOT/scripts/m7_e2e.sh"
