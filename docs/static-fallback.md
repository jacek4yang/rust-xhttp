# Static Website Fallback

`rust-xhttp` is a normal website for HTTP traffic that does not qualify for the
configured XHTTP transport. This is a deployment and isolation feature, not a
claim of indistinguishability.

## Request split

- `/healthz` and `/readyz` are reserved operational endpoints.
- A request enters XHTTP only when path, Host, and request padding all match the
  strict transport configuration.
- Other browser-style GET/HEAD requests use either the generated blog or the
  user-supplied `fallback.dist` site.
- Other methods on the website surface return 405 with `Allow: GET, HEAD`.
- Valid XHTTP responses carry configured `X-Padding`; website responses do not.

VLESS authentication happens later, inside the first XHTTP session payload. A
wrong UUID/encryption key uniformly closes the session; it cannot become an HTML
response without corrupting XHTTP framing and exposing an authentication oracle.

## Performance and containment

The complete site is preloaded before the listener starts. Request handling
clones immutable `Bytes` and never opens files. MIME type, ETag, Last-Modified,
and directory index aliases are precomputed; `If-None-Match` is supported.
`maxFileBytes` and `maxTotalBytes` bound memory. Symlinks are rejected, so the
loader cannot follow a link outside `dist`. Updating files requires a restart.

See the bilingual [configuration guide](configuration.md) for both modes and
the [performance/availability note](performance-and-availability.md) for the
resource model.

## Local evidence

- `scripts/m7_e2e.sh` validates packet-up/stream-down and response padding.
- `scripts/m9_tls_h2_smoke.sh` validates TLS 1.3, ALPN H2, a customized blog,
  and separation between website and XHTTP headers.
- `scripts/m13_acme_pebble.sh` validates real HTTP-01 issuance against a local
  Pebble CA, atomic cache publication, and activation on the TLS endpoint.
- Unit tests validate directory aliases, MIME, byte limits, ETag responses, and
  rejection of symlinks.
