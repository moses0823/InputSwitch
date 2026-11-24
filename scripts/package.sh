#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
DRY_RUN=0
BUNDLES="${TAURI_BUNDLES:-}"

usage() {
  printf 'Usage: %s [--dry-run] [bundle[,bundle...]]\n' "$0"
  printf 'Linux default: deb,appimage | macOS default: app (.app)\n'
  printf 'Override bundle selection with TAURI_BUNDLES or the positional argument.\n'
}

for arg in "$@"; do
  case "$arg" in
    --dry-run) DRY_RUN=1 ;;
    -h|--help) usage; exit 0 ;;
    *)
      if [[ -n "$BUNDLES" ]]; then
        printf 'Only one bundle list may be provided.\n' >&2
        usage >&2
        exit 2
      fi
      BUNDLES="$arg"
      ;;
  esac
done

case "$(uname -s)" in
  Linux)
    PLATFORM="Linux"
    BUNDLES="${BUNDLES:-deb,appimage}"
    BUNDLE_DIR="$ROOT_DIR/src-tauri/target/release/bundle"
    ;;
  Darwin)
    PLATFORM="macOS"
    BUNDLES="${BUNDLES:-app}"
    BUNDLE_DIR="$ROOT_DIR/src-tauri/target/release/bundle/macos"
    ;;
  *)
    printf 'Unsupported build host: %s. Run this script on Linux or macOS.\n' "$(uname -s)" >&2
    exit 1
    ;;
esac

if ! command -v cargo >/dev/null 2>&1; then
  printf 'Rust/Cargo is required. Install it from https://rustup.rs/\n' >&2
  exit 1
fi

if ! cargo tauri --version >/dev/null 2>&1; then
  printf 'Tauri CLI is missing. Install it with: cargo install tauri-cli --version "^2" --locked\n' >&2
  exit 1
fi

printf 'Building %s bundle(s): %s\n' "$PLATFORM" "$BUNDLES"
printf 'Frontend: %s/ui\n' "$ROOT_DIR"

if [[ "$DRY_RUN" == "1" ]]; then
  printf 'Command: (cd %q && cargo tauri build --bundles %q)\n' "$ROOT_DIR/src-tauri" "$BUNDLES"
  exit 0
fi

cd "$ROOT_DIR/src-tauri"
cargo tauri build --bundles "$BUNDLES"

printf '\nBuild artifacts:\n'
if [[ "$PLATFORM" == "macOS" ]]; then
  find "$BUNDLE_DIR" -maxdepth 1 -type d -name '*.app' -print
else
  find "$BUNDLE_DIR" -maxdepth 2 -type f \( -name '*.deb' -o -name '*.AppImage' \) -print
fi