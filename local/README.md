# `local/` — machine-local assets (git-ignored)

Everything under `local/` is **ignored by Git** except this `README.md` and
`init.sh`. It holds long-term local-only data so the repo root stays clean and no
secrets are ever tracked. Nothing here is required for a normal `cargo build` /
`cargo test`; only *live* tests, benchmarks, and deployment use it (and they fail
with a clear message when a needed asset is missing).

## Layout
| Dir | Holds | Examples |
|---|---|---|
| `config/` | local runtime configs (may contain secrets) | `config.toml` |
| `secrets/` | credentials, SSH/test-server info, built deploy bundles | `test-server-ssh-info`, `deploy/` |
| `references/` | reference source checkouts / peer implementations | `Xray-core/`, `v2rayng/` |
| `geodata/` | downloaded geo databases | `geoip.dat`, `geosite.dat` |
| `bin/` | local helper/test binaries | |
| `artifacts/` | benchmark / profiling / harness output | |
| `cache/` | reusable caches | |
| `logs/` | local run logs | |
| `tmp/` | scratch | |

## Setup
Run `local/init.sh` once to create the directory skeleton, then populate:
- `local/references/Xray-core/xray` — official Xray-core client binary (build:
  `cd Xray-core && CGO_ENABLED=0 go build -o xray -trimpath -buildvcs=false -ldflags="-s -w -buildid=" ./main`).
- `local/geodata/geoip.dat`, `local/geodata/geosite.dat` — from the v2ray-rules-dat releases.
- `local/config/config.toml` — your runtime config (see `config.example.toml`).

Scripts that need these read them from `local/...` and abort with a clear error if absent.
