# TLS Fidelity Analysis

`rust-xhttp` is not a REALITY TLS mimicry server. TLS fidelity here means:

- direct deployments terminate TLS with the in-tree TLS 1.3 backend and
  advertise the configured ALPN;
- proxied deployments rely on the front proxy or Cloudflare to terminate TLS;
- plaintext h2c deployments are intended only behind a trusted TLS terminator.

The inherited nginx build scripts are retained as local reference/proxy builders,
and an ignored nginx differential harness exists for local comparison.

The built-in static fallback aligns HTTP response shape with a small static
site, including nginx-like static headers, but it does not make the direct
TLS handshake proven identical to nginx/OpenSSL. For public Cloudflare
deployments the visible TLS endpoint is Cloudflare; for nginx deployments it is
nginx/OpenSSL. Direct deployments should be treated as the in-tree TLS profile
until the differential harness is green.

## Gap against nginx/OpenSSL-equivalent TLS

The updated target state is stronger than the current implementation: direct
deployments should terminate HTTPS with a self-contained TLS implementation whose
observable behavior matches nginx/OpenSSL. The current origin uses the in-tree
TLS 1.3 state machine for direct TLS, but it does not yet prove
OpenSSL-equivalent record-state errors, close_notify timing, or byte-for-byte
nginx differential behavior.

The implementation path should follow the reusable parts of `rust-reality`:

1. Split TLS termination behind an internal backend boundary so the HTTP origin
   can run on the self-contained nginx-profile backend without touching XHTTP
   request handling.
2. Port the TLS 1.3 record, key schedule, ClientHello parsing, and differential
   test helpers from `rust-reality`; do not port REALITY authentication into
   this project.
3. Add certificate/key loading and CertificateVerify signing for the key types
   used in production, with the first milestone scoped to TLS 1.3 plus `h2` and
   `http/1.1` ALPN.
4. Add an ignored nginx/OpenSSL differential harness for XHTTP direct TLS: send
   the same ClientHello/probe bytes to nginx and this backend, then compare ALPN,
   alert/close behavior, record-length sequence, and static fallback HTTP
   responses.
5. Only after that harness is green should direct TLS be documented as
   nginx/OpenSSL-equivalent. Until then, the exact nginx/OpenSSL deployment mode
   remains nginx in front with `rust-xhttp` behind h2c/HTTP.

## Backend boundary status

TLS termination is now isolated under `src/tls/`. The HTTP origin accepts an
`AcceptedStream` from `crate::tls::Server` and no longer owns certificate parsing
or the concrete TLS acceptor. `crate::tls::Server` now instantiates the
self-contained nginx-profile backend, which consumes `TcpStream` and returns an
`AcceptedStream` implementing `AsyncRead + AsyncWrite`, without touching XHTTP
routing, static fallback, session management, or VLESS dispatch. The previous
external TLS acceptor and dependency have been removed from the production path.

The reusable TLS 1.3 foundation from `rust-reality` has been started under
`src/tls/`:

- `client_hello.rs` parses SNI, ALPN, signature_algorithms, TLS 1.3 support,
  cipher suites, session id, and key_share entries from a bounds-checked
  ClientHello, and includes a TLSPlaintext handshake-record buffer for
  fragmented ClientHello messages.
- `cert.rs` loads the configured PEM certificate chain/private key with the
  in-tree PEM parser, uses ring for RSA-PSS/ECDSA/Ed25519 signing, encodes TLS
  1.3 Certificate messages, and signs CertificateVerify over the RFC 8446
  server context string.
- `flight.rs` validates and rewrites a captured nginx/OpenSSL-style ServerHello
  template, echoes the ClientHello session id, replaces the server key_share,
  verifies cipher/group offers, and assembles the encrypted server handshake
  flight containing EncryptedExtensions, Certificate, CertificateVerify, and
  Finished.
- `handshake.rs` composes ClientHello parsing, X25519 key agreement, ALPN
  selection, CertificateVerify signing, key schedule setup, ServerHello
  synthesis, encrypted server flight generation, client-handshake read keys, and
  constant-time client Finished verify_data checking in memory.
- `keyschedule.rs` implements HKDF-Expand-Label, traffic-secret derivation, and
  Finished verify-data generation for SHA-256/SHA-384 suites.
- `keyshare.rs` implements server-side X25519 key_share generation and shared
  secret derivation, including wrong-length, unsupported-group, and
  non-contributory peer-key rejection.
- `messages.rs` builds basic TLS 1.3 handshake messages
  (EncryptedExtensions, Certificate, CertificateVerify, Finished, and a
  NewSessionTicket helper for future experiments) and parses ServerHello
  cipher/key_share fields used by nginx-profile mirroring. The production
  direct TLS path intentionally does not issue NewSessionTicket records today,
  and does not claim TLS session resumption.
- `record.rs` implements AES-128-GCM, AES-256-GCM, and ChaCha20-Poly1305
  TLSCiphertext seal/open, including allocation-reusing `seal_into` and
  in-place `open_in_place`.
- `nginx_backend.rs` wires the pieces into the direct TLS accept path: it reads
  ClientHello records from the socket, sends ServerHello plus encrypted server
  flight, verifies client Finished, derives application traffic keys, and
  exposes an encrypted `AsyncRead + AsyncWrite` stream to hyper.

These pieces are covered by unit tests and are now used by the direct TLS server.
The session-ticket policy is conservative: no TLS tickets are issued and no TLS
resumption is claimed, matching an nginx/OpenSSL reference configured with
`ssl_session_tickets off`. The remaining nginx-profile work is differential
fidelity: OpenSSL-style alert/close behavior, broader ClientHello
compatibility, and running the ignored nginx harness against live endpoints.

## Current evidence

- Unit and integration tests validate protocol internals.
- TLS unit coverage includes ClientHello parsing, TLS 1.3 HKDF key schedule,
  X25519 key_share derivation, in-memory handshake preparation, record
  seal/open, certificate/CV encoding, ServerHello template synthesis, and
  decryptable encrypted server handshake flight generation.
- Direct TLS unit coverage validates the socket-facing TLS stream decrypts
  application records from a client and encrypts server application writes.
- Origin tests validate static fallback responses for non-XHTTP GETs,
  malformed XHTTP-looking GET probes, and write methods on the static surface.
- `scripts/m9_tls_h2_smoke.sh` validates local HTTPS origin startup, ALPN
  negotiation to HTTP/2, static fallback behavior, and XHTTP response padding.
- `tests/tls_nginx_diff.rs` is an ignored nginx/OpenSSL differential harness.
  Run it with `RXHTTP_DIFF_NGINX_ADDR`, `RXHTTP_DIFF_CANDIDATE_ADDR`, and
  `RXHTTP_DIFF_SNI` to send the same TLS 1.3 ClientHello probe to both
  endpoints and compare the visible TLS record shape.
- `scripts/gate.sh` covers fmt, clippy, and tests.
- The remaining production claim blocker is running the nginx differential
  harness and closing any observed alert, close, compatibility, or record-shape
  gaps. The nginx reference for that comparison should disable TLS session
  tickets unless this project later adds a real resumption implementation.
