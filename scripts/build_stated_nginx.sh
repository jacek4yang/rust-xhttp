#!/usr/bin/env bash
# build_stated_nginx.sh — build the GOAL'S EXACT stated pair, nginx 1.30.2 +
# OpenSSL 3.5.7, ENTIRELY FROM THE VENDORED SOURCES, for use as the fixed
# local reference baseline.
#
# Vendored sources (both under local/references/):
#   - nginx 1.30.2: local/references/nginx-1.30.2  (release tarball, NGINX_VERSION 1.30.2)
#   - OpenSSL 3.5.7: local/references/openssl       (git tag openssl-3.5.7, VERSION.dat 3.5.7)
# Linked statically via nginx's --with-openssl, so the binary is self-contained.
#
# Built --without-http_rewrite/gzip to avoid pcre2/zlib deps (the differential
# serves a static file, not `return`). Requires Docker (host networking for apt).
#
# Output: $OUT (default below). rust-xhttp does not yet have an automated nginx
# differential test; use this binary as a manual local reference while building
# that harness.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
NGINX_SRC="${NGINX_SRC:-$ROOT/local/references/nginx-1.30.2}"
OSSL_SRC="${OSSL_SRC:-$ROOT/local/references/openssl}"
OUT="${OUT:-$ROOT/local/.build/nginx-1.30.2-openssl-3.5.7}"

[ -x "$NGINX_SRC/configure" ] || { echo "missing vendored nginx 1.30.2 at $NGINX_SRC"; exit 1; }
[ -x "$OSSL_SRC/Configure" ]  || { echo "missing vendored OpenSSL at $OSSL_SRC"; exit 1; }
nver="$(awk -F'\"' '/NGINX_VERSION/{print $2}' "$NGINX_SRC/src/core/nginx.h" 2>/dev/null)"
over="$(awk -F= '/^MAJOR/{a=$2}/^MINOR/{b=$2}/^PATCH/{c=$2}END{print a"."b"."c}' "$OSSL_SRC/VERSION.dat" 2>/dev/null)"
echo "vendored nginx: ${nver:-?}   vendored OpenSSL: ${over:-?}"
mkdir -p "$(dirname "$OUT")"

cat > /tmp/_rr_build_stated.sh <<'BUILD'
set -e
apt-get update -qq
apt-get install -y -qq build-essential perl >/dev/null
mkdir -p /work && cd /work
cp -r /nginx /work/nginx-src && cp -r /ossl /work/openssl-src
cd /work/nginx-src
./configure --with-http_ssl_module --with-http_v2_module \
  --without-http_rewrite_module --without-http_gzip_module \
  --with-openssl=/work/openssl-src --with-openssl-opt="no-tests no-docs no-apps" >/tmp/cfg.log 2>&1 \
  || { echo CONFIGURE FAILED; tail -20 /tmp/cfg.log; exit 2; }
make -j"$(nproc)" >/tmp/make.log 2>&1 || { echo MAKE FAILED; tail -40 /tmp/make.log; exit 3; }
objs/nginx -V 2>&1
cp objs/nginx /out/nginx
echo "BUILD OK"
BUILD

echo "Building nginx ${nver} + OpenSSL ${over} from the vendored trees (a few minutes)..."
docker run --rm --network host \
  -v "$NGINX_SRC:/nginx:ro" \
  -v "$OSSL_SRC:/ossl:ro" \
  -v /tmp/_rr_build_stated.sh:/build.sh:ro \
  -v "$(dirname "$OUT"):/out" \
  debian:trixie-slim bash /build.sh

mv "$(dirname "$OUT")/nginx" "$OUT"
echo
echo "Built (from vendored sources): $OUT"
echo "Use it as a local nginx reference/proxy while developing the xhttp harness."
