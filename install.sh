#!/bin/sh
set -eu

ENTANGLE_VERSION=${ENTANGLE_VERSION:-latest}
ENTANGLE_SKIP_CROC=${ENTANGLE_SKIP_CROC:-0}
CROC_VERSION=${CROC_VERSION:-v11.5.4}

if [ -z "${ENTANGLE_INSTALL_DIR:-}" ]; then
    : "${HOME:?Set HOME or ENTANGLE_INSTALL_DIR before installing}"
    ENTANGLE_INSTALL_DIR=$HOME/.local/bin
fi

system=$(uname -s)
machine=$(uname -m)
case "$system/$machine" in
    Darwin/arm64|Darwin/aarch64)
        target=aarch64-apple-darwin
        croc_asset=macOS-ARM64.tar.gz
        ;;
    Darwin/x86_64)
        target=x86_64-apple-darwin
        croc_asset=macOS-64bit.tar.gz
        ;;
    Linux/x86_64|Linux/amd64)
        target=x86_64-unknown-linux-gnu
        croc_asset=Linux-64bit.tar.gz
        ;;
    *)
        printf 'Unsupported platform %s/%s. Install from source with: cargo install --git https://github.com/DailenG/entangle entangle\n' "$system" "$machine" >&2
        exit 1
        ;;
esac

if [ "$ENTANGLE_VERSION" = latest ]; then
    default_download_base=https://github.com/DailenG/entangle/releases/latest/download
else
    default_download_base="https://github.com/DailenG/entangle/releases/download/$ENTANGLE_VERSION"
fi
download_base=${ENTANGLE_DOWNLOAD_BASE:-$default_download_base}
download_base=${download_base%/}

mkdir -p "$ENTANGLE_INSTALL_DIR"
install_dir=$(cd "$ENTANGLE_INSTALL_DIR" && pwd -P)
tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/entangle-install.XXXXXX")
cleanup() {
    rm -rf "$tmp_dir"
}
trap cleanup 0
trap 'exit 1' HUP INT TERM

verify_checksum() {
    file_path=$1
    sums_path=$2
    file_name=$3
    expected=$(awk -v name="$file_name" '$2 == name { print $1; exit }' "$sums_path")
    if [ -z "$expected" ]; then
        printf 'No checksum found for %s in %s\n' "$file_name" "$sums_path" >&2
        return 1
    fi

    if command -v sha256sum >/dev/null 2>&1; then
        actual=$(sha256sum "$file_path" | awk '{ print $1 }')
    elif command -v shasum >/dev/null 2>&1; then
        actual=$(shasum -a 256 "$file_path" | awk '{ print $1 }')
    else
        printf 'Cannot verify downloads: install sha256sum or shasum\n' >&2
        return 1
    fi
    if [ "$expected" != "$actual" ]; then
        printf 'SHA-256 mismatch for %s\n' "$file_name" >&2
        return 1
    fi
}

entangle_archive="entangle-$target.tar.gz"
entangle_path="$tmp_dir/$entangle_archive"
entangle_extract="$tmp_dir/entangle"
mkdir -p "$entangle_extract"
curl -fsSL "$download_base/$entangle_archive" -o "$entangle_path"
curl -fsSL "$download_base/SHA256SUMS" -o "$tmp_dir/SHA256SUMS"
verify_checksum "$entangle_path" "$tmp_dir/SHA256SUMS" "$entangle_archive"
tar -xzf "$entangle_path" -C "$entangle_extract"
if [ ! -f "$entangle_extract/entangle" ]; then
    printf 'The Entangle archive does not contain a root-level entangle binary\n' >&2
    exit 1
fi
cp "$entangle_extract/entangle" "$install_dir/entangle"
chmod 755 "$install_dir/entangle"

if command -v croc >/dev/null 2>&1; then
    printf 'Using existing croc: %s\n' "$(command -v croc)"
elif [ "$ENTANGLE_SKIP_CROC" = 1 ]; then
    printf 'Skipping croc installation because ENTANGLE_SKIP_CROC=1\n'
else
    case "$CROC_VERSION" in
        v*) croc_tag=$CROC_VERSION ;;
        *) croc_tag="v$CROC_VERSION" ;;
    esac
    croc_archive="croc_${croc_tag}_${croc_asset}"
    croc_sums="croc_${croc_tag}_checksums.txt"
    croc_default_base="https://github.com/schollz/croc/releases/download/$croc_tag"
    croc_download_base=${CROC_DOWNLOAD_BASE:-$croc_default_base}
    croc_download_base=${croc_download_base%/}
    croc_path="$tmp_dir/$croc_archive"
    croc_extract="$tmp_dir/croc"
    mkdir -p "$croc_extract"
    curl -fsSL "$croc_download_base/$croc_archive" -o "$croc_path"
    curl -fsSL "$croc_download_base/$croc_sums" -o "$tmp_dir/$croc_sums"
    verify_checksum "$croc_path" "$tmp_dir/$croc_sums" "$croc_archive"
    tar -xzf "$croc_path" -C "$croc_extract"
    croc_binary=$(find "$croc_extract" -type f -name croc -print | sed -n '1p')
    if [ -z "$croc_binary" ]; then
        printf 'The croc archive does not contain a croc binary\n' >&2
        exit 1
    fi
    cp "$croc_binary" "$install_dir/croc"
    chmod 755 "$install_dir/croc"
fi

printf '\nEntangle version:\n'
"$install_dir/entangle" --version
printf 'Entangle MCP executable: %s\n' "$install_dir/entangle"
if [ -x "$install_dir/croc" ]; then
    printf 'croc version:\n'
    "$install_dir/croc" --version
elif [ "$ENTANGLE_SKIP_CROC" = 1 ] && ! command -v croc >/dev/null 2>&1; then
    printf 'croc was not installed; install croc >= 10 before using state syncs\n'
fi

case ":${PATH:-}:" in
    *":$install_dir:"*) ;;
    *) printf "Add Entangle to PATH with: export PATH=\"%s:\$PATH\"\n" "$install_dir" ;;
esac
