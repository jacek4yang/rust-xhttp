# TLS Fidelity Analysis

`rust-xhttp` is not a REALITY TLS mimicry server. TLS fidelity here means:

- direct deployments terminate TLS with rustls and advertise the configured ALPN;
- proxied deployments rely on the front proxy or Cloudflare to terminate TLS;
- plaintext h2c deployments are intended only behind a trusted TLS terminator.

The inherited nginx build scripts are retained as local reference/proxy builders,
but there is not yet an automated nginx differential test for this project.

The built-in static fallback aligns HTTP response shape with a small static
site, including nginx-like static headers, but it does not make the direct
rustls TLS handshake identical to nginx/OpenSSL. For public Cloudflare
deployments the visible TLS endpoint is Cloudflare; for nginx deployments it is
nginx/OpenSSL. Direct rustls deployments should be treated as their own TLS
profile.

## Current evidence

- Unit and integration tests validate protocol internals.
- Origin tests validate static fallback responses for non-XHTTP GETs,
  malformed XHTTP-looking GET probes, and write methods on the static surface.
- `scripts/m9_tls_h2_smoke.sh` validates local HTTPS origin startup, ALPN
  negotiation to HTTP/2, static fallback behavior, and XHTTP response padding.
- `scripts/gate.sh` covers fmt, clippy, and tests.
- Manual TLS/proxy fidelity work should be added as an XHTTP-specific harness
  before making production claims beyond the supported deployment modes.
