#!/usr/bin/env bash
# Create the local/ skeleton. Idempotent. Run from anywhere.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
for d in config secrets references geodata bin artifacts cache logs tmp; do
  mkdir -p "$HERE/$d"
done
echo "local/ skeleton ready at $HERE"
echo "Populate: references/Xray-core/xray, geodata/geoip.dat, geodata/geosite.dat, config/config.toml (see ../config.example.toml)."
