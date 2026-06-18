# Static Fallback Surface

`rust-xhttp` now serves a small built-in static site for non-XHTTP traffic.
This is a deployability feature, not a claim of indistinguishability.

## Request split

- `/healthz` and `/readyz` remain operational health endpoints.
- Requests that match the configured XHTTP path and Host and carry valid
  XHTTP padding continue into the packet-up/stream-down protocol handler.
- Browser-style `GET` and `HEAD` requests that do not qualify as XHTTP return
  static blog content, assets, `robots.txt`, or a static 404 page.
- Non-read methods on the static surface return `405 Method Not Allowed` with
  `Allow: GET, HEAD`.
- Valid XHTTP responses include default-mode `X-Padding` response padding.
  Static fallback responses intentionally do not include this header.

This keeps malformed probes away from protocol internals while preserving the
strict Xray-compatible path for real clients.

## Reference notes

- Xray-core validates Host and path before writing XHTTP response padding and
  checking request padding in
  `local/references/Xray-core/transport/internet/splithttp/hub.go`.
- Xray-core extracts default `x_padding` from `Referer` query or the request
  query in
  `local/references/Xray-core/transport/internet/splithttp/xpadding.go`.
- Xray-core applies non-obfs response padding as an `X-Padding` header before
  XHTTP method handling in the same `hub.go`/`xpadding.go` path.
- nginx's HTTP header filter emits static-site headers such as `Server`,
  `Last-Modified`, `Accept-Ranges`, and `ETag` from
  `local/references/nginx/src/http/ngx_http_header_filter_module.c`.

## Local evidence

- `scripts/m7_e2e.sh` validates packet-up/stream-down over a local HTTP
  origin and checks XHTTP response padding on upload and download responses.
- `scripts/m9_tls_h2_smoke.sh` validates a local TLS origin with ALPN `h2`,
  static fallback shape, and XHTTP OPTIONS response padding.
- `scripts/m10_uplink_placements.sh` validates Xray-compatible packet-up
  payload placement for `header`, `cookie`, and `auto`.

## TLS boundary

For public Cloudflare deployments, the externally visible TLS fingerprint is
Cloudflare's edge, not this Rust origin. For direct TLS deployments, rustls
does not produce the same handshake profile as nginx linked against OpenSSL.
If exact nginx/OpenSSL public TLS behavior is required, terminate public TLS at
nginx or Cloudflare and run `rust-xhttp` as the origin behind that layer.
