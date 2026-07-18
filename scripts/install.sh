#!/usr/bin/env bash
set -euo pipefail

VERSION="${ASIRI_VERSION:-0.1.43}"
INSTALL_DIR="${ASIRI_INSTALL_DIR:-$HOME/.local/bin}"
SOURCE_DIR="${ASIRI_INSTALL_SOURCE_DIR:-}"
BASE_URL="${ASIRI_RELEASE_BASE_URL:-https://github.com/o-clan/asiri-cli/releases/download/v${VERSION}}"
RELEASE_PUBLIC_KEY_PEM_B64="LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUZrd0V3WUhLb1pJemowQ0FRWUlLb1pJemowREFRY0RRZ0FFQ1IxT2RRcU9lb25ad0NvUndGQlJwWFJGUXcrZgp0aDZIazRMU1VLTkRNS1Q2Si80K0RSVHB6VGtNUUtQc2FNNkh1ZlJJMlU2cU1QNTQ3S1ZtYzQxS2FRPT0KLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg=="
TMP_DIR=""

usage() {
  cat <<USAGE
Install Asiri CLI ${VERSION}

Environment:
  ASIRI_VERSION             Version to install (default: ${VERSION})
  ASIRI_INSTALL_DIR         Destination directory (default: ~/.local/bin)
  ASIRI_INSTALL_SOURCE_DIR  Local artifact directory for offline/testing installs
  ASIRI_RELEASE_BASE_URL    Release artifact base URL when not using local source
USAGE
}

case "${1:-}" in
  -h|--help) usage; exit 0 ;;
esac

need() {
  command -v "$1" >/dev/null 2>&1 || { echo "asiri installer: $1 is required" >&2; exit 1; }
}
need uname
need mkdir
need chmod

base64_decode() {
  if printf '' | base64 --decode >/dev/null 2>&1; then
    base64 --decode
  else
    base64 -D
  fi
}

verify_manifest_signature() {
  local dir="$1"
  local sums="$dir/SHA256SUMS"
  local sig="$dir/SHA256SUMS.sig"
  local pub
  pub="$(mktemp "${TMPDIR:-/tmp}/asiri-release-pub.XXXXXX")"
  [[ -f "$sums" ]] || { echo "asiri installer: missing SHA256SUMS" >&2; exit 1; }
  [[ -f "$sig" ]] || { echo "asiri installer: missing SHA256SUMS.sig" >&2; exit 1; }
  [[ -n "$RELEASE_PUBLIC_KEY_PEM_B64" ]] || {
    echo "asiri installer: missing pinned release verification key" >&2
    exit 1
  }
  need openssl
  if ! printf '%s' "$RELEASE_PUBLIC_KEY_PEM_B64" | base64_decode > "$pub"; then
    rm -f "$pub"
    echo "asiri installer: invalid release verification key" >&2
    exit 1
  fi
  if ! openssl dgst -sha256 -verify "$pub" -signature "$sig" "$sums" >/dev/null 2>&1; then
    rm -f "$pub"
    echo "asiri installer: release manifest signature verification failed" >&2
    exit 1
  fi
  rm -f "$pub"
}

verify_checksum() {
  local dir="$1"
  local artifact_name="$2"
  local sums="$dir/SHA256SUMS"
  local one
  one="$(mktemp "${TMPDIR:-/tmp}/asiri-checksum.XXXXXX")"
  [[ -f "$sums" ]] || { echo "asiri installer: missing SHA256SUMS" >&2; exit 1; }
  awk -v name="$artifact_name" '$NF == name { print }' "$sums" > "$one"
  [[ -s "$one" ]] || { echo "asiri installer: checksum missing for $artifact_name" >&2; exit 1; }
  if command -v sha256sum >/dev/null 2>&1; then
    (cd "$dir" && sha256sum -c "$one" >/dev/null)
  elif command -v shasum >/dev/null 2>&1; then
    (cd "$dir" && shasum -a 256 -c "$one" >/dev/null)
  else
    echo "asiri installer: sha256sum or shasum is required to verify checksums" >&2
    exit 1
  fi
  rm -f "$one"
}

install_binary() {
  local src="$1"
  local dest="$INSTALL_DIR/asiri"
  local tmp="$INSTALL_DIR/.asiri-install.$$"
  cp "$src" "$tmp"
  chmod 0755 "$tmp"
  xattr -c "$tmp" 2>/dev/null || true
  mv "$tmp" "$dest"
}

spinner() {
  local message="$1"
  local frames='|/-\'
  local i=0
  while :; do
    printf '\r%s %s' "$message" "${frames:$((i % 4)):1}" >&2
    i=$((i + 1))
    sleep 0.1
  done
}

fetch_with_progress() {
  local url="$1"
  local dest="$2"
  local label="$3"
  local message="Downloading $label"
  local spinner_pid=""
  local status=0

  if [[ -t 2 ]]; then
    spinner "$message" &
    spinner_pid="$!"
  else
    printf '%s...\n' "$message" >&2
  fi

  set +e
  "${fetch[@]}" "$url" > "$dest"
  status="$?"
  set -e

  if [[ -n "$spinner_pid" ]]; then
    kill "$spinner_pid" >/dev/null 2>&1 || true
    wait "$spinner_pid" 2>/dev/null || true
    if [[ "$status" -eq 0 ]]; then
      printf '\r%s done\n' "$message" >&2
    else
      printf '\r%s failed\n' "$message" >&2
    fi
  elif [[ "$status" -eq 0 ]]; then
    printf '%s done\n' "$message" >&2
  else
    printf '%s failed\n' "$message" >&2
  fi

  return "$status"
}

version_hint() {
  local dest="$INSTALL_DIR/asiri"
  local resolved
  resolved="$(command -v asiri 2>/dev/null || true)"
  if [[ "$resolved" == "$dest" ]]; then
    printf 'asiri --version'
  else
    printf '%s --version' "$dest"
  fi
}

os="$(uname -s | tr '[:upper:]' '[:lower:]')"
arch="$(uname -m)"
case "$os" in
  linux) os="linux" ;;
  darwin) os="darwin" ;;
  *) echo "asiri installer: unsupported OS $os; download a binary manually" >&2; exit 1 ;;
esac
case "$arch" in
  x86_64|amd64) arch="amd64" ;;
  arm64|aarch64) arch="arm64" ;;
  *) echo "asiri installer: unsupported architecture $arch" >&2; exit 1 ;;
esac

artifact="asiri_${VERSION}_${os}_${arch}"
mkdir -p "$INSTALL_DIR"

if [[ -n "$SOURCE_DIR" ]]; then
  src="$SOURCE_DIR/$artifact"
  [[ -f "$src" ]] || { echo "asiri installer: missing $src" >&2; exit 1; }
  verify_manifest_signature "$SOURCE_DIR"
  verify_checksum "$SOURCE_DIR" "$artifact"
  install_binary "$src"
else
  if command -v curl >/dev/null 2>&1; then
    fetch=(curl -fsSL)
  elif command -v wget >/dev/null 2>&1; then
    fetch=(wget -qO-)
  else
    echo "asiri installer: curl or wget is required for remote installs" >&2
    exit 1
  fi
  TMP_DIR="$(mktemp -d)"
  trap '[[ -n "$TMP_DIR" ]] && rm -rf "$TMP_DIR"' EXIT
  fetch_with_progress "$BASE_URL/$artifact" "$TMP_DIR/$artifact" "Asiri CLI ${VERSION}"
  fetch_with_progress "$BASE_URL/SHA256SUMS" "$TMP_DIR/SHA256SUMS" "release manifest"
  fetch_with_progress "$BASE_URL/SHA256SUMS.sig" "$TMP_DIR/SHA256SUMS.sig" "release signature"
  verify_manifest_signature "$TMP_DIR"
  verify_checksum "$TMP_DIR" "$artifact"
  install_binary "$TMP_DIR/$artifact"
fi

installed_version="$("$INSTALL_DIR/asiri" --version)"

cat <<DONE
Asiri CLI ${VERSION} installed to $INSTALL_DIR/asiri
Version: $installed_version
Run: $(version_hint)
DONE
