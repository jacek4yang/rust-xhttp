# Production Hardening

The recommended local setup is the Rust
[interactive installer and manager](installation-management.md). For deploying
a locally built release to one or more already configured root SSH targets:

```bash
ops/deploy.sh root@server
```

Each target must already contain `/etc/rust-xhttp/config.json`. The script sends
both locally built binaries and asks `rust-xhttpctl` to validate the existing
config, install the canonical unit, and restart. It does not replace website,
certificate, or ACME data.

## Remote layout

```text
/usr/local/bin/
  rust-xhttp
  rust-xhttpctl
/etc/rust-xhttp/
  config.json
  backups/
  tls/
/var/lib/rust-xhttp/
  acme/
  site/
/var/lib/rust-xhttp-manager/
  rollback/             # previous daemon + manager pair
```

## Runtime notes

- Official Linux builds target `x86-64-v3`. Older hosts should build from
  source with a compatible `RUSTFLAGS` target CPU.
- The supplied service receives only `CAP_NET_BIND_SERVICE`, disables core
  dumps, protects system paths, creates private state storage, and has a stop
  deadline five seconds longer than the default application drain deadline.
- `MemoryHigh=1536M` and `MemoryMax=2G` match the default 1 GiB protocol buffer
  budget plus the 128 MiB site limit and runtime headroom. Recalculate them if
  either JSON limit changes.
- `LimitNOFILE=65536` must cover public sockets, target sockets, ACME, and
  system overhead. Do not increase concurrency limits independently.
- `workers: 0`, `reusePort: true`, `backlog: 4096`, and 300-second keepalive
  are intended Linux defaults. Measure before changing worker count.
- The service runs as a dedicated non-login user. Put custom `dist` content in
  `/var/lib/rust-xhttp/site`; the installer copies and preloads it there.
- Use `rust-xhttp check /etc/rust-xhttp/config.json` in deployment automation
  before restart. `ExecStartPre` enforces the same check in systemd.
- Monitor SIGTERM drain, accept-pressure warnings, buffer/session rejections,
  target timeouts, certificate expiry, and ACME renewal failures.

See [Performance and Availability](performance-and-availability.md) for sizing
and overload analysis.
