# Configuration and Deployment Guide

[English](configuration.md) · [简体中文](configuration.zh-CN.md)

`rust-xhttp` uses strict JSON shaped like an Xray Core server config. The
supported subset is intentionally narrow: exactly one VLESS inbound over XHTTP.
Unknown fields, unsupported protocols, conflicting certificate modes, and zero
resource limits stop startup with an error instead of being silently ignored.

## 1. Install and create an identity

```bash
git clone https://github.com/jacek4yang/rust-xhttp.git
cd rust-xhttp
cargo build --release --locked
uuidgen
```

The binary requires Rust 1.88 or newer when building from source. Put the UUID
in both the server `settings.clients` array and the official Xray client.

Before starting a server, validate the JSON and local resources:

```bash
./target/release/rust-xhttp check /etc/rust-xhttp/config.json
```

For automatic ACME mode this validates the configuration without contacting the
CA. For manual TLS it also parses the configured certificate and private key;
for a directory site it preloads and validates the complete directory.

## 2. Choose certificate management

### Automatic HTTPS with ACME HTTP-01

Start from [`config.acme.example.json`](../config.acme.example.json). Replace the
domain, email, UUID, XHTTP path, and Host. The relevant block is:

```json
{
  "streamSettings": {
    "network": "xhttp",
    "security": "tls",
    "tlsSettings": {
      "alpn": ["h2", "http/1.1"],
      "acme": {
        "domains": ["xhttp.example.com"],
        "email": "admin@example.com",
        "directoryUrl": "https://acme-v02.api.letsencrypt.org/directory",
        "challengeListen": "0.0.0.0:80",
        "cacheDir": "/var/lib/rust-xhttp/acme",
        "renewBeforeDays": 30,
        "renewCheckHours": 12,
        "acceptTerms": true
      }
    },
    "xhttpSettings": {
      "path": "/change-this-path/",
      "host": "xhttp.example.com"
    }
  }
}
```

Requirements:

- Every name in `domains` must already resolve to this server.
- Public TCP port 80 must reach `challengeListen`; HTTP-01 cannot issue wildcard
  certificates.
- The process needs permission to bind ports 80/443 and write `cacheDir`. The
  supplied systemd unit grants `CAP_NET_BIND_SERVICE` and creates
  `/var/lib/rust-xhttp` with mode `0700`.
- `acceptTerms` is deliberately required. Setting it to `false` rejects the
  config.

The port-80 listener returns ACME tokens only under
`/.well-known/acme-challenge/`; other HTTP requests receive a permanent HTTPS
redirect. Account credentials and the private key are written with restricted
permissions. If no usable certificate exists, issuance completes before port
443 starts. Renewals happen in the background; a failure keeps the current
certificate active and retries with bounded exponential backoff. A successful
renewal is atomically loaded for new TLS handshakes without dropping established
connections.

Test DNS and firewall routing against Let's Encrypt staging first:

```json
"directoryUrl": "https://acme-staging-v02.api.letsencrypt.org/directory",
"cacheDir": "/var/lib/rust-xhttp/acme-staging"
```

Use a separate cache directory for staging. Staging certificates are not
publicly trusted.

Private/test ACME servers may additionally set `caCertificateFile` to a PEM
root certificate used only for the ACME HTTPS client. Omit it for Let's Encrypt.

### User-managed certificate files

Start from [`config.example.json`](../config.example.json). Configure exactly
one certificate entry and omit `acme`:

```json
"tlsSettings": {
  "alpn": ["h2", "http/1.1"],
  "certificates": [
    {
      "certificateFile": "/etc/rust-xhttp/tls/fullchain.pem",
      "keyFile": "/etc/rust-xhttp/tls/privkey.pem"
    }
  ]
}
```

The first file must contain the leaf certificate followed by intermediate
certificates in PEM format. RSA, ECDSA P-256/P-384, and Ed25519 signing keys are
accepted when the client offers a compatible TLS 1.3 signature scheme. Restart
the service after replacing manually managed files.

### TLS terminated by nginx, a tunnel, or a trusted edge

Bind only loopback, set `security` to `none`, and remove `tlsSettings`:

```json
{
  "listen": "127.0.0.1",
  "port": 8080,
  "streamSettings": {
    "network": "xhttp",
    "security": "none",
    "xhttpSettings": {
      "path": "/change-this-path/",
      "host": "xhttp.example.com"
    }
  }
}
```

Never expose this plaintext listener to an untrusted network. Disable reverse
proxy buffering for long-lived XHTTP downloads and preserve the original Host.

## 3. Complete server example

The following automatic-certificate config is ready after replacing the marked
values:

```json
{
  "log": { "loglevel": "info" },
  "inbounds": [
    {
      "tag": "vless-xhttp-in",
      "listen": "0.0.0.0",
      "port": 443,
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "REPLACE-WITH-UUID",
            "email": "primary-device",
            "flow": ""
          }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "xhttp",
        "security": "tls",
        "tlsSettings": {
          "alpn": ["h2", "http/1.1"],
          "acme": {
            "domains": ["xhttp.example.com"],
            "email": "admin@example.com",
            "challengeListen": "0.0.0.0:80",
            "cacheDir": "/var/lib/rust-xhttp/acme",
            "renewBeforeDays": 30,
            "renewCheckHours": 12,
            "acceptTerms": true
          }
        },
        "xhttpSettings": {
          "path": "/REPLACE-WITH-RANDOM-PATH/",
          "host": "xhttp.example.com",
          "scMaxEachPostBytes": 1000000,
          "scMaxBufferedPosts": 30,
          "sessionGraceSeconds": 30,
          "noSSEHeader": false,
          "serverMaxHeaderBytes": 8192,
          "xPaddingBytes": "100-1000",
          "uplinkDataPlacement": "body",
          "uplinkDataKey": ""
        }
      }
    }
  ],
  "server": {
    "workers": 0,
    "tcpNodelay": true,
    "reusePort": true,
    "backlog": 4096,
    "tcpKeepaliveSeconds": 300,
    "gracefulShutdownSeconds": 30,
    "limits": {
      "maxSessions": 65536,
      "maxPendingPacketsPerSession": 30,
      "maxPendingBytesPerSession": 16777216,
      "globalBufferBytes": 1073741824,
      "maxConcurrentTargetConns": 100000,
      "handshakeTimeoutSeconds": 10,
      "targetConnectSeconds": 10,
      "udpAssociationIdleSeconds": 60
    }
  },
  "fallback": {
    "mode": "builtin",
    "site": {
      "seed": "xhttp.example.com",
      "title": "",
      "author": "",
      "description": "",
      "language": "en"
    }
  }
}
```

Start it with:

```bash
sudo install -d -m 700 /var/lib/rust-xhttp/acme
sudo ./target/release/rust-xhttp /etc/rust-xhttp/config.json
```

## 4. Official Xray Core client

This project intentionally uses Xray's familiar VLESS/XHTTP field names. A
matching official client can use:

```json
{
  "log": { "loglevel": "warning" },
  "inbounds": [
    {
      "listen": "127.0.0.1",
      "port": 10808,
      "protocol": "socks",
      "settings": { "auth": "noauth", "udp": true }
    }
  ],
  "outbounds": [
    {
      "tag": "rust-xhttp",
      "protocol": "vless",
      "settings": {
        "vnext": [
          {
            "address": "xhttp.example.com",
            "port": 443,
            "users": [
              {
                "id": "REPLACE-WITH-THE-SAME-UUID",
                "encryption": "none",
                "flow": ""
              }
            ]
          }
        ]
      },
      "streamSettings": {
        "network": "xhttp",
        "security": "tls",
        "tlsSettings": {
          "serverName": "xhttp.example.com",
          "alpn": ["h2"]
        },
        "xhttpSettings": {
          "path": "/REPLACE-WITH-RANDOM-PATH/",
          "host": "xhttp.example.com",
          "mode": "packet-up",
          "xPaddingBytes": "100-1000",
          "scMaxEachPostBytes": 1000000,
          "scMaxBufferedPosts": 30,
          "uplinkDataPlacement": "body"
        }
      }
    }
  ]
}
```

The server supports `body`, `header`, `cookie`, and `auto` uplink data
placements. For non-body modes, set the same non-empty `uplinkDataKey` on both
sides. Header chunks use `KEY-0`, `KEY-1`, and cookie chunks use `KEY_0`,
`KEY_1`.

For VLESS Encryption, run `xray vlessenc`, put its `decryption` value in the
server `settings.decryption`, and put the paired `encryption` value in the
client user. For Vision, set `flow` to `xtls-rprx-vision` on both sides.

## 5. Normal website and `dist` directory

Traffic that does not qualify for the configured XHTTP path, Host, and padding
is handled by the fallback site. Operational `/healthz` and `/readyz` endpoints
remain reserved.

### Generated built-in blog

The default `builtin` mode renders a polished, responsive blog entirely in
memory. `seed` deterministically selects one of several names, authors, themes,
and article sets, so restarts do not unexpectedly change the site. Set any
metadata field to override the generated value:

```json
"fallback": {
  "mode": "builtin",
  "site": {
    "seed": "my-stable-seed",
    "title": "Field Notes",
    "author": "Lin",
    "description": "Essays about places, objects, and ordinary days.",
    "language": "en"
  }
}
```

Use `"language": "zh-CN"` for the built-in Chinese edition. Empty metadata
uses generated content.

### User-supplied directory

```json
"fallback": {
  "mode": "directory",
  "dist": "/srv/www/example.com/dist",
  "index": "index.html",
  "notFound": "404.html",
  "maxFileBytes": 8388608,
  "maxTotalBytes": 134217728
}
```

At startup, every regular file is read into immutable memory, MIME type and
ETag are precomputed, and directory index aliases are built. Request handling
does no filesystem I/O and `If-None-Match` receives `304 Not Modified`.
Symlinks are rejected rather than followed. A missing index, unreadable file,
oversized file, or total-size overflow stops startup. Restart after changing
files in `dist`.

`maxTotalBytes` is reserved in addition to protocol buffers, so size it below
the process memory limit. The supplied systemd unit permits a 1 GiB protocol
buffer budget plus a 128 MiB site and runtime overhead.

### Authentication boundary

Ordinary browser requests and malformed HTTP/XHTTP probes use the site. VLESS
authentication itself is inside the first XHTTP session payload, after the HTTP
upload has been accepted. A wrong UUID or encryption key therefore closes the
session with the same uniform authentication failure; it cannot safely be
rewritten into a browser response without breaking XHTTP framing or leaking an
authentication oracle. The distinction is intentional.

## 6. Field reference

| JSON path | Default | Purpose |
|---|---:|---|
| `log.loglevel` | `info` | `tracing` filter (`warn`, `info`, or a full EnvFilter expression). |
| `inbounds` | required | Exactly one inbound is currently supported. |
| `inbounds[].listen` | `0.0.0.0` | Numeric listen IP. |
| `inbounds[].port` | required | TCP port, non-zero. |
| `inbounds[].protocol` | required | Must be `vless`. |
| `settings.clients` | required | Non-empty UUID account list. |
| `settings.decryption` | empty | `none` or the server half of VLESS Encryption. |
| `streamSettings.network` | required | Must be `xhttp`. |
| `streamSettings.security` | `none` | `tls` or `none`. |
| `xhttpSettings.path` | required | Normalized to leading and trailing `/`. |
| `xhttpSettings.host` | empty | Optional Host pin; port is ignored while matching. |
| `scMaxEachPostBytes` | `1000000` | Maximum decoded bytes in one packet-up request. |
| `scMaxBufferedPosts` | `30` | Maximum XHTTP out-of-order packet window. |
| `sessionGraceSeconds` | `30` | Lifetime of a session that never receives its download GET. |
| `noSSEHeader` | `false` | Suppress `text/event-stream` on download responses. |
| `serverMaxHeaderBytes` | `8192` | Request-target and header byte limit. |
| `xPaddingBytes` | `100-1000` | Accepted response/request padding range; an integer fixes the size. |
| `uplinkDataPlacement` | `body` | `body`, `header`, `cookie`, or `auto`. |
| `uplinkDataKey` | empty | Required for every non-body placement. |
| `server.workers` | `0` | Tokio workers; zero selects available CPU parallelism. |
| `server.tcpNodelay` | `true` | Disable Nagle on client and target TCP streams. |
| `server.reusePort` | `true` | Enable Linux `SO_REUSEPORT`. |
| `server.backlog` | `4096` | Listen backlog. |
| `server.tcpKeepaliveSeconds` | `300` | TCP keepalive idle time; zero disables it. |
| `server.gracefulShutdownSeconds` | `30` | SIGTERM drain deadline, 1–300 seconds. |
| `limits.maxSessions` | `65536` | Global live XHTTP session cap. |
| `limits.maxPendingPacketsPerSession` | `30` | Per-session out-of-order packet cap. |
| `limits.maxPendingBytesPerSession` | `16777216` | Per-session pending-byte cap. |
| `limits.globalBufferBytes` | `1073741824` | Global buffered-upload budget. |
| `limits.maxConcurrentTargetConns` | `100000` | Outbound TCP/UDP concurrency semaphore. |
| `limits.handshakeTimeoutSeconds` | `10` | TLS and VLESS/VLESS-Encryption handshake deadline. |
| `limits.targetConnectSeconds` | `10` | DNS and outbound TCP connect deadline. |
| `limits.udpAssociationIdleSeconds` | `60` | UDP/XUDP idle deadline. |

See [Performance and availability](performance-and-availability.md) before
raising concurrency or memory limits.

## 7. Validation and troubleshooting

```bash
cargo test --locked --all-targets
bash scripts/m7_e2e.sh
bash scripts/m9_tls_h2_smoke.sh
bash scripts/m10_uplink_placements.sh
# Optional local CA integration (requires a Pebble source checkout):
bash scripts/m13_acme_pebble.sh /path/to/pebble
```

- **Config says unknown field** — names are case-sensitive; for example Xray's
  spelling is `noSSEHeader`.
- **ACME listener cannot bind** — another process owns port 80, or the service
  lacks `CAP_NET_BIND_SERVICE`.
- **ACME authorization fails** — verify public A/AAAA records and inbound port
  80 before retrying; use staging to avoid production rate limits.
- **Static 404 instead of XHTTP** — path, Host, or padding does not match.
- **HTTP 413** — `scMaxEachPostBytes` was exceeded after decoding all selected
  body/header/cookie layers.
- **HTTP 431** — `serverMaxHeaderBytes` is too small, especially for header
  placement.
- **Session closes after upload** — UUID, flow, or VLESS Encryption pairing is
  wrong; authentication failures are intentionally uniform.
- **Target timeout** — inspect DNS, firewall, `targetConnectSeconds`, and the
  outbound concurrency limit.
