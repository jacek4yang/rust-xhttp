#!/usr/bin/env bash
# build_vendored_nginx.sh — build nginx from the project's OWN vendored sources
# (local/references/nginx + local/references/openssl) into a local reference
# binary.
#
# This establishes a fixed baseline *from the vendored trees* (not a released
# image). NOTE the vendored versions are nginx 1.31.2 + OpenSSL 4.1.0-dev (a git
# master snapshot), NOT the stated 1.30.2 / 3.5.7 LTS — see
# docs/tls-fidelity-analysis.md. For the stated-version baseline, the nginx
# differential's default path uses the pinned nginx 1.30.2 / OpenSSL 3.5.6 image.
#
# Requires Docker (host networking, for apt). Output binary: $OUT (default below).
# rust-xhttp does not yet have an automated nginx differential test; use the
# produced binary as a manual local proxy/reference when building that harness.
#
# Built --without-http_rewrite_module/--without-http_gzip_module to avoid the
# pcre2/zlib build deps; the differential serves a static file instead of `return`.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
NGINX_SRC="$ROOT/local/references/nginx"
OPENSSL_SRC="$ROOT/local/references/openssl"
OUT="${OUT:-$ROOT/local/.build/nginx}"

[ -x "$NGINX_SRC/auto/configure" ] || { echo "missing vendored nginx at $NGINX_SRC"; exit 1; }
[ -x "$OPENSSL_SRC/Configure" ]    || { echo "missing vendored openssl at $OPENSSL_SRC"; exit 1; }
mkdir -p "$(dirname "$OUT")"

cat > /tmp/_rr_build_nginx.sh <<'BUILD'
set -e
apt-get update -qq
apt-get install -y -qq build-essential perl >/dev/null
cp -r /src/nginx /b-nginx && cp -r /src/openssl /b-openssl
cd /b-nginx
auto/configure --with-http_ssl_module --with-http_v2_module \
  --without-http_rewrite_module --without-http_gzip_module \
  --with-openssl=/b-openssl --with-openssl-opt="no-tests no-docs no-apps" >/tmp/cfg.log 2>&1 \
  || { echo "CONFIGURE FAILED"; tail -25 /tmp/cfg.log; exit 2; }
make -j"$(nproc)" >/tmp/make.log 2>&1 || { echo "MAKE FAILED"; tail -45 /tmp/make.log; exit 3; }
objs/nginx -V 2>&1
cp objs/nginx /out/nginx
echo "BUILD OK"
BUILD

echo "Building vendored nginx (this compiles the vendored OpenSSL too; a few minutes)..."
docker run --rm --network host \
  -v "$NGINX_SRC:/src/nginx:ro" \
  -v "$OPENSSL_SRC:/src/openssl:ro" \
  -v /tmp/_rr_build_nginx.sh:/build.sh:ro \
  -v "$(dirname "$OUT"):/out" \
  debian:trixie-slim bash /build.sh

echo
echo "Built: $OUT"
echo "Use it as a local nginx reference/proxy while developing the xhttp harness."
