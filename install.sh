#!/bin/sh
# Minimal bootstrap for the Rust rust-xhttpctl installer. The release archive and
# checksum are fetched from the same immutable GitHub release, verified locally,
# and then the Rust wizard performs every privileged installation step.
set -eu

REPOSITORY="jacek4yang/rust-xhttp"
TARGET="x86_64-unknown-linux-gnu"
RELEASE_TAG="@RUST_XHTTP_TAG@"

fail() {
    printf 'rust-xhttp installer: %s\n' "$*" >&2
    exit 1
}

command -v curl >/dev/null 2>&1 || fail "curl is required"
command -v sha256sum >/dev/null 2>&1 || fail "sha256sum is required"
command -v tar >/dev/null 2>&1 || fail "tar is required"
command -v awk >/dev/null 2>&1 || fail "awk is required"
[ "$(uname -s)" = "Linux" ] || fail "managed installation currently supports Linux only"
[ "$(uname -m)" = "x86_64" ] || fail "official managed releases currently support x86_64 only"

case "$RELEASE_TAG" in
    @RUST_*)
        effective_url=$(curl --proto '=https' --proto-redir '=https' --tlsv1.2 \
            --fail --silent --show-error --location --output /dev/null \
            --write-out '%{url_effective}' \
            "https://github.com/$REPOSITORY/releases/latest")
        RELEASE_TAG=${effective_url##*/}
        ;;
esac
case "$RELEASE_TAG" in
    v*) ;;
    *) fail "GitHub returned an invalid release tag: $RELEASE_TAG" ;;
esac
case "${RELEASE_TAG#v}" in
    ''|*[!0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz.+-]*)
        fail "GitHub returned an invalid release tag: $RELEASE_TAG"
        ;;
esac

temporary=$(mktemp -d "/tmp/rust-xhttp-install.XXXXXX")
case "$temporary" in
    /tmp/rust-xhttp-install.*) ;;
    *) fail "mktemp returned an unexpected path" ;;
esac
cleanup() {
    rm -r -- "$temporary"
}
trap cleanup EXIT HUP INT TERM

archive="rust-xhttp-$RELEASE_TAG-$TARGET.tar.gz"
base="https://github.com/$REPOSITORY/releases/download/$RELEASE_TAG"
curl --proto '=https' --proto-redir '=https' --tlsv1.2 \
    --fail --silent --show-error --location \
    --output "$temporary/$archive" "$base/$archive"
curl --proto '=https' --proto-redir '=https' --tlsv1.2 \
    --fail --silent --show-error --location \
    --output "$temporary/$archive.sha256" "$base/$archive.sha256"

(
    cd "$temporary"
    sha256sum --check "$archive.sha256"
)
prefix="rust-xhttp-$RELEASE_TAG-$TARGET"
members=$(tar --list --verbose --gzip --file "$temporary/$archive" \
    "$prefix/rust-xhttp" "$prefix/rust-xhttpctl")
printf '%s\n' "$members" | awk '
    substr($1, 1, 1) != "-" { exit 1 }
    { count += 1 }
    END { if (count != 2) exit 1 }
' || fail "release binaries must be unique regular files"
tar --extract --gzip --file "$temporary/$archive" --directory "$temporary" \
    --no-same-owner --no-same-permissions \
    "$prefix/rust-xhttp" "$prefix/rust-xhttpctl"

server="$temporary/$prefix/rust-xhttp"
manager="$temporary/$prefix/rust-xhttpctl"
[ -f "$server" ] && [ ! -L "$server" ] || fail "release is missing rust-xhttp"
[ -f "$manager" ] && [ ! -L "$manager" ] || fail "release is missing rust-xhttpctl"
chmod 755 "$server" "$manager"

printf '\nVerified rust-xhttp %s. Starting the Rust installation wizard...\n\n' "$RELEASE_TAG"
if [ "$(id -u)" -eq 0 ]; then
    "$manager" install --server-binary "$server" --ctl-binary "$manager" </dev/tty >/dev/tty
else
    command -v sudo >/dev/null 2>&1 || fail "run this installer as root or install sudo"
    sudo "$manager" install --server-binary "$server" --ctl-binary "$manager" </dev/tty >/dev/tty
fi
