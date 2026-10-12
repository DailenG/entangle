#!/bin/sh
set -eu

ENTANGLE_VERSION=${ENTANGLE_VERSION:-latest}

if [ -z "${ENTANGLE_INSTALL_DIR:-}" ]; then
    : "${HOME:?Set HOME or ENTANGLE_INSTALL_DIR before installing}"
    ENTANGLE_INSTALL_DIR=$HOME/.local/bin
fi

system=$(uname -s)
machine=$(uname -m)
case "$system/$machine" in
    Darwin/arm64|Darwin/aarch64)
        target=aarch64-apple-darwin
        ;;
    Darwin/x86_64)
        target=x86_64-apple-darwin
        ;;
    Linux/x86_64|Linux/amd64)
        target=x86_64-unknown-linux-gnu
        ;;
    Linux/aarch64|Linux/arm64)
        target=aarch64-unknown-linux-gnu
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
tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/entangle-install.XXXXXX")
cleanup() {
    rm -rf "$tmp_dir"
    rm -f "$staged_entangle"
}
trap cleanup 0
trap 'exit 1' HUP INT TERM

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

printf '\nEntangle version:\n'
"$install_dir/entangle" --version
printf 'Entangle MCP executable: %s\n' "$install_dir/entangle"

case ":${PATH:-}:" in
    *":$install_dir:"*) ;;
    *) printf "Add Entangle to PATH with: export PATH=\"%s:\$PATH\"\n" "$install_dir" ;;
esac
printf 'Reload or restart your MCP client so it runs this version.\n'
printf 'After reloading the MCP client, check `entangle group list`.\n'
printf 'Group create/invite/join commands are typed by a human; see https://raw.githubusercontent.com/DailenG/entangle/main/docs/AGENT_SETUP.md or playbook 01.\n'
