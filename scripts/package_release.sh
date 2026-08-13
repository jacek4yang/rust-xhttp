#!/usr/bin/env bash
# Build the release archive layout and standalone version-pinned bootstrap.
set -euo pipefail
cd "$(dirname "$0")/.."

if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then
  echo "usage: $0 <vVERSION> [output-directory]" >&2
  exit 2
fi
tag=$1
output=${2:-release-dist}
case "$tag" in
  v*) ;;
  *) echo "release tag must start with v" >&2; exit 2 ;;
esac
case "${tag#v}" in
  ''|*[!0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz.+-]*)
    echo "invalid release tag: $tag" >&2
    exit 2
    ;;
esac
test -x target/release/rust-xhttp
test -x target/release/rust-xhttpctl
mkdir -p "$output"
output_absolute=$(realpath "$output")
repository_absolute=$(pwd -P)
if [ "$output_absolute" = "$repository_absolute" ]; then
  echo "refusing to write release assets over the repository root" >&2
  exit 2
fi

archive="rust-xhttp-${tag}-x86_64-unknown-linux-gnu"
mkdir "$output/$archive"
chmod 755 "$output/$archive"
install -m 755 target/release/rust-xhttp target/release/rust-xhttpctl \
  "$output/$archive/"
install -m 644 README.md README.zh-CN.md LICENSE config.example.json \
  config.acme.example.json "$output/$archive/"
sed "s/@RUST_XHTTP_TAG@/$tag/g" install.sh > "$output/install.sh"
chmod 755 "$output/install.sh"
cp "$output/install.sh" "$output/$archive/install.sh"
while IFS= read -r -d '' document; do
  install -D -m 644 "$document" "$output/$archive/$document"
done < <(git ls-files -z --cached --others --exclude-standard docs)
archive_epoch=${SOURCE_DATE_EPOCH:-$(git log -1 --format=%ct)}
tar -C "$output" --sort=name --owner=0 --group=0 --numeric-owner \
  --mtime="@$archive_epoch" -czf "$output/$archive.tar.gz" "$archive"
(
  cd "$output"
  sha256sum "$archive.tar.gz" > "$archive.tar.gz.sha256"
)

echo "$output/$archive.tar.gz"
