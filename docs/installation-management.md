# Installation and Long-Term Management

English | [简体中文](installation-management.zh-CN.md)

`rust-xhttpctl` is the Rust administrative companion to the network daemon. It
is a separate binary, so installation dependencies and interactive code never
enter the server data path.

## Preconditions

- x86_64 Linux with systemd for the official managed package;
- a Haswell/Zen or newer CPU for the official `x86-64-v3` binary, or a local
  source build for an older CPU;
- root access through `sudo`, plus `curl`, `tar`, and `sha256sum`;
- TCP 443 reachable from clients;
- for automatic certificates, public DNS already resolving to the server and
  TCP 80 reachable by the ACME CA.

The ACME HTTP-01 listener cannot share port 80 with an existing web server. Use
manual certificates or terminate TLS in the existing proxy in that situation.

## Bootstrap and trust boundary

```bash
curl --proto '=https' --tlsv1.2 -fsSL \
  https://github.com/jacek4yang/rust-xhttp/releases/latest/download/install.sh | sudo sh
```

The release copy of `install.sh` is stamped with its release tag. It downloads
only that tag's archive and checksum over HTTPS, verifies SHA-256, extracts only
`rust-xhttp` and `rust-xhttpctl`, rejects symlinks, then launches the Rust
installer using `/dev/tty`. SHA-256 detects corruption and mismatched assets; it
does not replace trust in the GitHub repository and release workflow. Review the
script and release provenance when that trust model is insufficient.

The Rust wizard performs all persistent changes. It creates a system account,
copies files atomically, writes restrictive modes, validates configuration and
resources, installs the hardened unit, reloads systemd, and checks that the
enabled service becomes active.

## Wizard choices

### Automatic certificate

Enter the public domain and contact email. The daemon owns account/certificate
state below `/var/lib/rust-xhttp/acme` and renews in the background with atomic
certificate activation.

### Existing certificate

Enter the source paths of the full chain and private key. The installer copies
them to `/etc/rust-xhttp/tls`; the service cannot read `/root` or home directories
because `ProtectHome=true`.

### TLS proxy or CDN

Choose plaintext mode when Cloudflare, nginx, or another trusted local component
terminates TLS. The default bind is `127.0.0.1:8080`. Authenticate and firewall
the origin if it must bind a non-loopback address.

### Fallback site

The default is a generated blog with configurable language and identity.
Selecting a `dist` directory copies regular files into
`/var/lib/rust-xhttp/site`; symlinks and special files are rejected. The daemon
preloads it for unauthenticated/non-XHTTP requests. The directory must contain
the configured `index.html`.

## Service security model

The unit runs as the non-login `rust-xhttp` user. It validates config with
`ExecStartPre`, grants only `CAP_NET_BIND_SERVICE`, makes system/config paths
read-only, allows writes only in `/var/lib/rust-xhttp`, hides homes/devices,
restricts address families, disables core dumps, and sets FD/memory limits.
Modify limits with a drop-in so `repair` can restore the canonical unit safely:

```bash
sudo systemctl edit rust-xhttp
sudo systemctl daemon-reload
sudo systemctl restart rust-xhttp
```

## Configuration lifecycle

`sudo rust-xhttpctl edit` edits a private copy using `$VISUAL`, `$EDITOR`, or
`vi`, validates syntax and resources, creates a timestamped backup below
`/etc/rust-xhttp/backups`, then atomically replaces the live file. If restart
fails, it restores the backup and attempts to bring the old service back.

```bash
rust-xhttp check /etc/rust-xhttp/config.json
```

Relative resource paths resolve from `/var/lib/rust-xhttp`; absolute paths are
clearer in production.

## Updates and rollback

```bash
sudo rust-xhttpctl update          # latest release
sudo rust-xhttpctl update v0.2.0   # selected release
sudo rust-xhttpctl rollback        # previous binary pair
```

The manager allows HTTPS-only redirects, validates the tag/archive paths and
published SHA-256, checks both binary identities, and asks the downloaded server
to validate the installed config. It then saves the current daemon and manager
together, atomically replaces them, regenerates the unit, and restarts. Failed
activation restores both old binaries. One rollback generation is retained; a
successful rollback swaps the two sets so the operation can be reversed.

Updates do not overwrite config, certificates, ACME state, or fallback content.

## Operations and recovery

```bash
rust-xhttpctl status
rust-xhttpctl logs
rust-xhttpctl doctor
sudo rust-xhttpctl service restart
sudo rust-xhttpctl repair
```

`doctor` is read-only and reports missing files, config/resource errors, and
systemd enablement/activity. `repair` recreates the account, directories,
ownership, and unit after validating installed binaries and config. It never
regenerates user config.

For ACME failure, verify external DNS, public port 80 reachability, system time,
and whether another process owns the challenge port. For restart failure, run
`rust-xhttp check` and inspect `journalctl -u rust-xhttp` before changing files.

## Uninstall and retained data

`sudo rust-xhttpctl uninstall` disables the unit and removes both executables,
but preserves configuration, certificates, website, and state for reinstall.
`--purge` also removes those directories, root-only rollback data, ACME private
material, and the system account. Purge is irreversible; back up first.

## Noninteractive/staged installation

```bash
sudo rust-xhttpctl install \
  --server-binary ./rust-xhttp --ctl-binary ./rust-xhttpctl \
  --config ./config.json --yes

rust-xhttpctl install --root /tmp/rust-xhttp-image --no-start \
  --server-binary ./rust-xhttp --ctl-binary ./rust-xhttpctl \
  --config ./config.acme.example.json --yes
```

The alternate root affects installed filesystem locations only; JSON and unit
contents retain their production absolute paths.
