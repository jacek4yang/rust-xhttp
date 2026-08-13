# Production Hardening

First complete the [configuration guide](configuration.md), then use the
systemd unit at `ops/systemd/rust-xhttp.service`:

```bash
ops/deploy.sh root@server
```

The script atomically replaces the binary and restarts the service. It does not
modify the remote JSON, website, certificate, or private keys.

## Remote layout

```text
/root/xhttp/
  config.json
  rust-xhttp
  rust-xhttp.old
/var/lib/rust-xhttp/
  acme/                 # only when automatic certificates are enabled
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
- Put a user `dist` directory under a service-readable path and keep it
  immutable at runtime. ACME cache is the only normal runtime write path.
- Use `rust-xhttp check config.json` in deployment automation before restart.
- Monitor SIGTERM drain, accept-pressure warnings, buffer/session rejections,
  target timeouts, certificate expiry, and ACME renewal failures.

See [Performance and Availability](performance-and-availability.md) for sizing
and overload analysis.
