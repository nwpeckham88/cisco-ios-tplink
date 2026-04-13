#!/usr/bin/env bash

set -euo pipefail

require_option_value() {
  local opt="$1"
  local next="${2:-}"
  if [ -z "$next" ] || [ "${next#--}" != "$next" ]; then
    echo "Missing value for ${opt}" >&2
    usage >&2
    exit 1
  fi
}

sanitize_label() {
  local raw="$1"
  local cleaned
  cleaned="$(printf '%s' "$raw" | sed -E 's/[^A-Za-z0-9._-]+/-/g; s/^-+//; s/-+$//; s/-+/-/g')"
  if [ -z "$cleaned" ]; then
    cleaned="unknown"
  fi
  printf '%s' "$cleaned"
}

usage() {
  cat <<'EOF'
Build a release artifact directory and tarball for tplink-cli.

Usage:
  scripts/build-release.sh [options]

Options:
  --goos <value>         Target GOOS (default: env GOOS or linux)
  --goarch <value>       Target GOARCH (default: env GOARCH or amd64)
  --version <value>      Version label in artifact name (default: git describe or dev)
  --output-dir <path>    Output root directory (default: dist/releases)
  --binary-name <name>   Binary base name (default: tplink-cli)
  -h, --help             Show this help text

Examples:
  scripts/build-release.sh
  scripts/build-release.sh --goos linux --goarch arm64 --version v1.2.3
EOF
}

GOOS_VALUE="${GOOS:-linux}"
GOARCH_VALUE="${GOARCH:-amd64}"
OUTPUT_DIR="dist/releases"
BINARY_NAME="tplink-cli"
VERSION_VALUE=""

while [ "$#" -gt 0 ]; do
  case "$1" in
    --goos)
      require_option_value "$1" "${2:-}"
      GOOS_VALUE="$2"
      shift 2
      ;;
    --goarch)
      require_option_value "$1" "${2:-}"
      GOARCH_VALUE="$2"
      shift 2
      ;;
    --version)
      require_option_value "$1" "${2:-}"
      VERSION_VALUE="$2"
      shift 2
      ;;
    --output-dir)
      require_option_value "$1" "${2:-}"
      OUTPUT_DIR="$2"
      shift 2
      ;;
    --binary-name)
      require_option_value "$1" "${2:-}"
      BINARY_NAME="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

if [ -z "$VERSION_VALUE" ]; then
  if command -v git >/dev/null 2>&1; then
    VERSION_VALUE="$(git describe --tags --always --dirty 2>/dev/null || true)"
  fi
fi
if [ -z "$VERSION_VALUE" ]; then
  VERSION_VALUE="dev"
fi

BINARY_NAME="$(sanitize_label "$BINARY_NAME")"
VERSION_VALUE="$(sanitize_label "$VERSION_VALUE")"
GOOS_VALUE="$(sanitize_label "$GOOS_VALUE")"
GOARCH_VALUE="$(sanitize_label "$GOARCH_VALUE")"

BIN_FILE="$BINARY_NAME"
if [ "$GOOS_VALUE" = "windows" ]; then
  BIN_FILE="${BINARY_NAME}.exe"
fi

PACKAGE_BASE="${BINARY_NAME}-${VERSION_VALUE}-${GOOS_VALUE}-${GOARCH_VALUE}"
STAGE_DIR="${OUTPUT_DIR}/${PACKAGE_BASE}"
TAR_PATH="${OUTPUT_DIR}/${PACKAGE_BASE}.tar.gz"

mkdir -p "$STAGE_DIR"

echo "Building ${BINARY_NAME} for ${GOOS_VALUE}/${GOARCH_VALUE}..."
CGO_ENABLED=0 GOOS="$GOOS_VALUE" GOARCH="$GOARCH_VALUE" \
  go build -trimpath -o "${STAGE_DIR}/${BIN_FILE}" ./cmd/tplink-cli

echo "Packing ${TAR_PATH}..."
tar -C "$OUTPUT_DIR" -czf "$TAR_PATH" "$PACKAGE_BASE"

if command -v sha256sum >/dev/null 2>&1; then
  sha256sum "$TAR_PATH" > "${TAR_PATH}.sha256"
elif command -v shasum >/dev/null 2>&1; then
  shasum -a 256 "$TAR_PATH" > "${TAR_PATH}.sha256"
fi

if [ -n "${GITHUB_OUTPUT:-}" ]; then
  echo "artifact_dir=${STAGE_DIR}" >> "$GITHUB_OUTPUT"
  echo "tarball=${TAR_PATH}" >> "$GITHUB_OUTPUT"
fi

echo "Done."
echo "Directory: ${STAGE_DIR}"
echo "Tarball:   ${TAR_PATH}"