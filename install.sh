#!/bin/sh
set -eu

ENTANGLE_VERSION=${ENTANGLE_VERSION:-latest}
ENTANGLE_SKIP_CROC=${ENTANGLE_SKIP_CROC:-0}
CROC_VERSION=${CROC_VERSION:-v11.5.4}
case "$CROC_VERSION" in
    v*) croc_tag=$CROC_VERSION ;;
    *) croc_tag="v$CROC_VERSION" ;;
esac

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
staged_entangle="$install_dir/.entangle.new.$$"
staged_croc="$install_dir/.croc.new.$$"
tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/entangle-install.XXXXXX")
cleanup() {
    rm -rf "$tmp_dir"
    rm -f "$staged_entangle" "$staged_croc"
}
trap cleanup 0
trap 'exit 1' HUP INT TERM

parse_croc_major() {
    printf '%s\n' "$1" | awk '
        { version = $NF }
        END {
            sub(/^v/, "", version)
            split(version, components, ".")
            major = components[1]
            if (major ~ /^[0-9]+$/ && major + 0 <= 4294967295) {
                printf "%.0f\n", major + 0
            }
        }'
}

install_binary() {
    source_path=$1
    destination_path=$2
    staged_path=$3
    cp "$source_path" "$staged_path"
    chmod 755 "$staged_path"
    mv -f "$staged_path" "$destination_path"
}

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
install_binary "$entangle_extract/entangle" "$install_dir/entangle" "$staged_entangle"

if [ "$ENTANGLE_SKIP_CROC" = 1 ]; then
    printf 'Skipping croc installation because ENTANGLE_SKIP_CROC=1\n'
else
    install_croc=0
    existing_croc=$(command -v croc 2>/dev/null || true)
    if [ -n "$existing_croc" ]; then
        if existing_croc_version=$(croc --version 2>&1); then
            existing_croc_major=$(parse_croc_major "$existing_croc_version")
        else
            existing_croc_major=
        fi
        if [ -n "$existing_croc_major" ] && [ "$existing_croc_major" -ge 10 ]; then
            printf 'Using existing croc %s: %s\n' "$existing_croc_version" "$existing_croc"
        else
            printf 'Warning: ignoring croc at %s with version "%s"; installing pinned croc %s in %s\n' \
                "$existing_croc" "${existing_croc_version:-no version output}" "$croc_tag" "$install_dir" >&2
            install_croc=1
        fi
    else
        install_croc=1
    fi

    if [ "$install_croc" = 1 ]; then
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
        install_binary "$croc_binary" "$install_dir/croc" "$staged_croc"
    fi
fi

printf '\nEntangle version:\n'
"$install_dir/entangle" --version
printf 'Entangle MCP executable: %s\n' "$install_dir/entangle"
if [ "$ENTANGLE_SKIP_CROC" != 1 ] && [ -x "$install_dir/croc" ]; then
    printf 'croc version:\n'
    "$install_dir/croc" --version
fi

case ":${PATH:-}:" in
    *":$install_dir:"*) ;;
    *) printf "Add Entangle to PATH with: export PATH=\"%s:\$PATH\"\n" "$install_dir" ;;
esac
