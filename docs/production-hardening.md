# Production Hardening

Use the systemd unit at `ops/systemd/rust-xhttp.service` and deploy with:

```bash
ops/deploy.sh root@server
```

The deploy script builds `target/release/rust-xhttp`, copies it to
`/root/xhttp/rust-xhttp`, atomically swaps the binary, reloads systemd, and
restarts the service. It does not modify remote config or secrets.

## Remote layout

```text
/root/xhttp/
  config.toml
  rust-xhttp
  rust-xhttp.old
```

## Runtime notes

- Release builds use the repository's `x86-64-v3` target profile and require a
  Haswell/Zen-class CPU or newer. For older x86-64 hosts, build with
  `RUSTFLAGS="-C target-cpu=x86-64-v2 -C target-feature=+aes,+pclmulqdq"`.
- Put certificates and keys outside the repository or under ignored `local/`
  paths.
- Keep `LimitNOFILE` high for concurrent HTTP streams and target sockets.
- Tune `[listen]` for the host: `workers = 0` uses the available CPU count,
  `reuse_port = true` and `backlog = 4096` are the intended Linux defaults, and
  `tcp_keepalive_secs = 300` prevents dead peers from pinning long-lived streams.
- Size `[limits].global_buffer_bytes` below the service memory limit. It gates
  buffered XHTTP upload bytes across sessions and fails closed before the process
  can be pushed into OOM.
- The provided unit logs to journald and disables core dumps.
- Bind privileged ports with `CAP_NET_BIND_SERVICE`, not a fully privileged
  process.
