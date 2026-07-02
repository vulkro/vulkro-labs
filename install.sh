#!/usr/bin/env bash
#
# Vulkro Labs installer - downloads the latest `vulkro-live` release binary
# (verify + warden + the MCP server) for your platform from the Vulkro CDN,
# verifies its SHA-256 checksum, and installs it to a sensible location on
# PATH.
#
# This is the repo copy of the installer served at
# https://dist.vulkro.com/install-live.sh (keep the two in sync).
#
# Usage:
#   curl -fsSL https://dist.vulkro.com/install-live.sh | bash
#   curl -fsSL https://dist.vulkro.com/install-live.sh | bash -s -- --version v0.1.0
#   curl -fsSL https://dist.vulkro.com/install-live.sh | bash -s -- --bin-dir ~/.local/bin
#
# Or download and inspect first (recommended):
#   curl -fsSLO https://dist.vulkro.com/install-live.sh
#   less install-live.sh
#   bash install-live.sh
#
# This installer is a sibling of the general `install.sh` and `install-sf.sh`:
#   - Same CDN, same release-feed layout, same SHA-256 verification, and the
#     same install-target selection. The binary name is `vulkro-live`.
#   - `vulkro-live` is Vulkro's FREE, keyless developer CLI. It runs entirely
#     on your machine, needs no account and no API key, and sends only public
#     metadata (package names, versions, tool manifests) to public services.
#     Your source code never leaves your machine.
#   - Its tools are `verify` (the AI package bouncer), `warden` (the MCP
#     tool bouncer), and `mcp` (a built-in MCP server that exposes both to an
#     AI agent).
#
# These free tools are open source: https://github.com/vulkro/vulkro-labs
#
# Environment overrides:
#   VULKRO_LIVE_VERSION : pin a specific tag (default: latest)
#   VULKRO_LIVE_BIN_DIR : install destination (default: /usr/local/bin if writable, else ~/.local/bin)
#   VULKRO_CDN          : override the binary CDN base (default: https://dist.vulkro.com)
#
# This installer makes a single network call to the Vulkro CDN for the binary
# (plus one for the sibling .sha256 file). No telemetry. No post-install fetch.

set -euo pipefail

# -- Defaults --------------------------------------------------------------

CDN="${VULKRO_CDN:-https://dist.vulkro.com}"
VERSION="${VULKRO_LIVE_VERSION:-${VULKRO_VERSION:-latest}}"
BIN_DIR="${VULKRO_LIVE_BIN_DIR:-${VULKRO_BIN_DIR:-}}"
BIN_NAME="vulkro-live"

# -- Args ------------------------------------------------------------------

while [[ $# -gt 0 ]]; do
    case "$1" in
        --version)  VERSION="$2"; shift 2 ;;
        --bin-dir)  BIN_DIR="$2";  shift 2 ;;
        --cdn)      CDN="$2";      shift 2 ;;
        -h|--help)
            grep -E '^#( |$)' "$0" | sed -E 's/^# ?//'
            exit 0
            ;;
        *)
            echo "error: unknown argument: $1" >&2
            exit 2
            ;;
    esac
done

# -- Pretty output ---------------------------------------------------------

if [[ -t 1 ]]; then
    BOLD=$'\033[1m'; DIM=$'\033[2m'; GREEN=$'\033[0;32m'; YELLOW=$'\033[0;33m'; RED=$'\033[0;31m'; RESET=$'\033[0m'
else
    BOLD=""; DIM=""; GREEN=""; YELLOW=""; RED=""; RESET=""
fi
say() { printf '%s\n' "$*"; }
ok()  { say "${GREEN}check${RESET} $*"; }
warn(){ say "${YELLOW}!${RESET} $*"; }
die() { say "${RED}x${RESET} $*" >&2; exit 1; }

# -- Detect OS + arch ------------------------------------------------------

detect_target() {
    local os arch
    os="$(uname -s)"
    arch="$(uname -m)"
    case "$os" in
        Darwin)
            case "$arch" in
                arm64|aarch64) TARGET="mac-arm64";  EXT="tar.gz" ;;
                x86_64|amd64)  TARGET="mac-x64";    EXT="tar.gz" ;;
                *) die "unsupported macOS architecture: $arch" ;;
            esac
            ;;
        Linux)
            case "$arch" in
                x86_64|amd64)  TARGET="linux-x64";   EXT="tar.gz" ;;
                aarch64|arm64) TARGET="linux-arm64"; EXT="tar.gz" ;;
                *) die "unsupported Linux architecture: $arch" ;;
            esac
            ;;
        MINGW*|MSYS*|CYGWIN*)
            die "for Windows, download vulkro-live-${VERSION#v}-windows-x64.zip from ${CDN}/releases/${VERSION}/ and unzip it manually."
            ;;
        *)
            die "unsupported OS: $os"
            ;;
    esac
}

# -- Pick install dir ------------------------------------------------------

pick_bin_dir() {
    if [[ -n "$BIN_DIR" ]]; then
        return
    fi
    if [[ -d /usr/local/bin && -w /usr/local/bin ]]; then
        BIN_DIR=/usr/local/bin
    elif [[ -w /usr/local && ! -d /usr/local/bin ]]; then
        BIN_DIR=/usr/local/bin
    else
        BIN_DIR="${HOME}/.local/bin"
    fi
}

# -- Resolve release version + asset URL -----------------------------------

resolve_version() {
    if [[ "$VERSION" == "latest" ]]; then
        # vulkro-live versions independently of the `vulkro` and `vulkro-sf`
        # binaries, so it has its own release feed (releases/latest-live.json).
        # Reading the wrong feed would fetch a non-existent asset, so this
        # installer MUST read latest-live.json. Extract tag_name with POSIX
        # awk so it works before any binary is on the box.
        local manifest
        manifest="$(curl -fsSL "${CDN}/releases/latest-live.json")" \
            || die "could not fetch ${CDN}/releases/latest-live.json. Set VULKRO_LIVE_VERSION explicitly or check ${CDN}/."
        VERSION="$(printf '%s' "$manifest" | awk -F'"' '/"tag_name"[[:space:]]*:/{print $4; exit}')"
        if [[ -z "$VERSION" ]]; then
            die "latest-live.json did not contain a tag_name field. Set VULKRO_LIVE_VERSION explicitly."
        fi
    fi
}

build_urls() {
    local stripped="${VERSION#v}"
    ASSET="${BIN_NAME}-${stripped}-${TARGET}.${EXT}"
    SHA256_ASSET="${ASSET}.sha256"
    BASE="${CDN}/releases/${VERSION}"
}

# -- Download + verify -----------------------------------------------------

require_cmd() {
    command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

verify_sha256() {
    local archive="$1" expected="$2"
    local actual
    if command -v sha256sum >/dev/null 2>&1; then
        actual="$(sha256sum "$archive" | awk '{print $1}')"
    elif command -v shasum >/dev/null 2>&1; then
        actual="$(shasum -a 256 "$archive" | awk '{print $1}')"
    else
        warn "no sha256sum / shasum found - skipping checksum verification"
        return
    fi
    if [[ "$actual" != "$expected" ]]; then
        die "SHA-256 mismatch - expected ${expected}, got ${actual}. Refusing to install."
    fi
    ok "checksum verified (${actual:0:16}...)"
}

download() {
    local url="$1" dest="$2"
    if command -v curl >/dev/null 2>&1; then
        if [ -t 1 ]; then
            curl -fL --proto '=https' --tlsv1.2 --progress-bar -o "$dest" "$url"
        else
            curl -fsSL --proto '=https' --tlsv1.2 -o "$dest" "$url"
        fi
    elif command -v wget >/dev/null 2>&1; then
        if [ -t 1 ]; then
            wget --show-progress -O "$dest" "$url" 2>&1 | tail -n +1
        else
            wget -q -O "$dest" "$url"
        fi
    else
        die "neither curl nor wget is installed"
    fi
}

# -- Main ------------------------------------------------------------------

main() {
    say ""
    say "${BOLD}Vulkro Labs installer (vulkro-live)${RESET}"
    say "${DIM}cdn: ${CDN}${RESET}"

    require_cmd uname
    detect_target
    pick_bin_dir
    resolve_version
    build_urls

    say ""
    say "  version:  ${BOLD}${VERSION}${RESET}"
    say "  target:   ${TARGET}"
    say "  install:  ${BIN_DIR}/${BIN_NAME}"
    say ""

    local tmpdir archive
    tmpdir="$(mktemp -d)"
    trap 'rm -rf "${tmpdir:-}"' EXIT
    archive="${tmpdir}/${ASSET}"

    say "Downloading ${ASSET}..."
    download "${BASE}/${ASSET}" "$archive" \
        || die "download failed: ${BASE}/${ASSET}
Check ${CDN}/releases/ for available versions and platforms."

    # Optional checksum verification - releases ship .sha256 files alongside.
    local sha_file="${tmpdir}/${SHA256_ASSET}"
    if download "${BASE}/${SHA256_ASSET}" "$sha_file" 2>/dev/null; then
        local expected
        expected="$(awk '{print $1}' "$sha_file")"
        verify_sha256 "$archive" "$expected"
    else
        warn "no .sha256 file published for this release - skipping checksum verification"
    fi

    say "Extracting..."
    case "$EXT" in
        tar.gz) tar -xzf "$archive" -C "$tmpdir" ;;
        zip)    unzip -q "$archive" -d "$tmpdir" ;;
        *)      die "unknown archive format: $EXT" ;;
    esac

    # Locate the binary inside the extracted tree.
    local found
    found="$(find "$tmpdir" -type f -name "$BIN_NAME" -perm -u+x | head -n 1)"
    if [[ -z "$found" ]]; then
        found="$(find "$tmpdir" -type f -name "$BIN_NAME" | head -n 1)"
    fi
    [[ -n "$found" ]] || die "vulkro-live binary not found inside ${ASSET}"

    say "Installing to ${BIN_DIR}..."
    mkdir -p "$BIN_DIR"
    install -m 0755 "$found" "${BIN_DIR}/${BIN_NAME}"

    ok "Installed ${BIN_NAME} ${VERSION} to ${BIN_DIR}/${BIN_NAME}"
    say ""

    # Detect whether $BIN_DIR is on PATH and nudge if not.
    case ":$PATH:" in
        *":${BIN_DIR}:"*) ;;
        *)
            warn "${BIN_DIR} is not on your PATH."
            say "  Add it with one of:"
            say "    ${DIM}echo 'export PATH=\"${BIN_DIR}:\$PATH\"' >> ~/.zshrc${RESET}"
            say "    ${DIM}echo 'export PATH=\"${BIN_DIR}:\$PATH\"' >> ~/.bashrc${RESET}"
            ;;
    esac

    say "Try ${BOLD}vulkro-live verify express${RESET}, or ${BOLD}vulkro-live --help${RESET}."
    say ""
    say "${DIM}Use it with an AI agent: 'vulkro-live mcp' is a Model Context"
    say "Protocol server that exposes verify and warden as tools.${RESET}"
    say ""

    rm -rf "$tmpdir"
    trap - EXIT
}

main "$@"
