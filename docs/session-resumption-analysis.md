# Session Resumption Analysis

This project currently does not implement or claim TLS session resumption.
Direct TLS is handled by the in-tree TLS 1.3 backend, which does not issue
NewSessionTicket records in the production accept path. HTTP session continuity
is owned by the XHTTP session table and the official packet-up/stream-down
request model.

## XHTTP session model

- Uploads are independent POST requests with sequence numbers.
- Downloads are long-lived GET responses keyed by session id.
- The server reorders bounded uploads before VLESS parsing.
- Idle sessions are reaped by configured timers.

For nginx/OpenSSL differential tests, compare against a reference configured
with TLS session tickets disabled. Future work should separately analyze HTTP/2
connection reuse, stateful/stateless TLS tickets, and Xray client expectations
before adding any session-resumption claims.
