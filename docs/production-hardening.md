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

- Put certificates and keys outside the repository or under ignored `local/`
  paths.
- Keep `LimitNOFILE` high for concurrent HTTP streams and target sockets.
- The provided unit logs to journald and disables core dumps.
- Bind privileged ports with `CAP_NET_BIND_SERVICE`, not a fully privileged
  process.
