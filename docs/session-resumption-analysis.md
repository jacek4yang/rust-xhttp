# Session Resumption Analysis

This project currently does not implement custom TLS session resumption logic.
Direct TLS is handled by rustls; HTTP session continuity is owned by the XHTTP
session table and the official packet-up/stream-down request model.

## XHTTP session model

- Uploads are independent POST requests with sequence numbers.
- Downloads are long-lived GET responses keyed by session id.
- The server reorders bounded uploads before VLESS parsing.
- Idle sessions are reaped by configured timers.

Future work should separately analyze HTTP/2 connection reuse, TLS resumption
behavior in rustls, and Xray client expectations before adding any custom
session-resumption claims.
