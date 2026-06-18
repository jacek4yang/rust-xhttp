# Protocol Notes

The implementation is derived from local Xray-core sources under
`local/references/Xray-core`, especially:

- `transport/internet/splithttp`
- `proxy/vless`
- `common/xudp`
- Vision and VLESS-Encryption code paths used by the official client

## XHTTP mode

The supported mode is packet-up: independent upload POSTs carrying sequence
numbers, plus a long-lived stream-down GET for responses. Stream-up and
stream-one are classified but rejected by policy.

## VLESS

The server accepts VLESS TCP, UDP, Mux/XUDP, Vision, and optional
VLESS-Encryption according to the current config. Unsupported or malformed
requests fail closed.

## Deployment boundary

The wire protocol is identical across direct TLS/H2, Cloudflare-origin, and
plaintext h2c behind a trusted proxy. Only listen address and TLS config differ.
