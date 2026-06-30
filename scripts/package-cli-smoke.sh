#!/usr/bin/env bash
set -euo pipefail

OUT_DIR="${ASIRI_CLI_DIST:-dist/cli}"
VERSION="${ASIRI_VERSION:-$(tr -d '[:space:]' < VERSION)}"
SIGNING_DIR="$(mktemp -d)"
trap 'rm -rf "$SIGNING_DIR"' EXIT
SIGNING_KEY="${ASIRI_RELEASE_SIGNING_KEY:-}"
SIGNING_PUB="$SIGNING_DIR/release-public-key.pem"
EXPECTED=(
  "asiri_${VERSION}_linux_amd64"
  "asiri_${VERSION}_linux_arm64"
  "asiri_${VERSION}_darwin_amd64"
  "asiri_${VERSION}_darwin_arm64"
  "asiri_${VERSION}_windows_amd64.exe"
  "asiri_${VERSION}_windows_arm64.exe"
  "asiri-skill.tar.gz"
)

run() {
  printf '\n$'
  for arg in "$@"; do printf ' %q' "$arg"; done
  printf '\n'
  "$@"
}

if [[ -z "$SIGNING_KEY" ]]; then
  SIGNING_KEY="$SIGNING_DIR/release-signing-key.pem"
  openssl ecparam -name prime256v1 -genkey -noout -out "$SIGNING_KEY"
fi
export ASIRI_RELEASE_SIGNING_KEY="$SIGNING_KEY"
export ASIRI_ALLOW_UNTRUSTED_RELEASE_KEY=1
openssl ec -in "$SIGNING_KEY" -pubout -out "$SIGNING_PUB" >/dev/null 2>&1

run ./scripts/package-cli.sh

checksum_check() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum -c SHA256SUMS
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 -c SHA256SUMS
  else
    echo "sha256sum or shasum is required" >&2
    return 1
  fi
}

for artifact in "${EXPECTED[@]}"; do
  path="$OUT_DIR/$artifact"
  test -f "$path"
  test -s "$path"
  run file "$path"
  case "$artifact" in
    *.exe|*.tar.gz)
      ;;
    *)
      test -x "$path"
      ;;
  esac
done

skill_extract_dir="$(mktemp -d)"
run tar -xzf "$OUT_DIR/asiri-skill.tar.gz" -C "$skill_extract_dir"
test -f "$skill_extract_dir/asiri/SKILL.md"
test -f "$skill_extract_dir/asiri/agents/openai.yaml"
grep -q '^name: asiri$' "$skill_extract_dir/asiri/SKILL.md"
grep -q '^description: ' "$skill_extract_dir/asiri/SKILL.md"
grep -q '^interface:$' "$skill_extract_dir/asiri/agents/openai.yaml"

test -f "$OUT_DIR/SHA256SUMS"
test -s "$OUT_DIR/SHA256SUMS"
test -f "$OUT_DIR/SHA256SUMS.sig"
test -s "$OUT_DIR/SHA256SUMS.sig"
test -x "$OUT_DIR/install.sh"
(
  cd "$OUT_DIR"
  run checksum_check
  run openssl dgst -sha256 -verify "$SIGNING_PUB" -signature SHA256SUMS.sig SHA256SUMS
)

host_os="$(go env GOOS)"
host_arch="$(go env GOARCH)"
host_bin="$OUT_DIR/asiri_${VERSION}_${host_os}_${host_arch}"
if [[ "$host_os" == "windows" ]]; then
  host_bin="${host_bin}.exe"
fi
if [[ ! -x "$host_bin" ]]; then
  echo "host-compatible artifact $host_bin is not executable on this host" >&2
  exit 1
fi

install_dir="$(mktemp -d)"
install_output="$(ASIRI_INSTALL_SOURCE_DIR="$OUT_DIR" ASIRI_INSTALL_DIR="$install_dir" PATH="$install_dir:$PATH" "$OUT_DIR/install.sh" 2>&1)"
printf '%s\n' "$install_output"
if [[ "$install_output" != *"Run: asiri --version"* ]]; then
  echo "installer did not prefer the asiri command when the install directory is on PATH" >&2
  exit 1
fi
if [[ "$install_output" != *"Version: asiri $VERSION"* ]]; then
  echo "installer did not print the installed binary version" >&2
  exit 1
fi
installed_version="$("$install_dir/asiri" --version)"
if [[ "$installed_version" != "asiri $VERSION" ]]; then
  echo "installed version mismatch: $installed_version" >&2
  exit 1
fi
printf '%s\n' "$installed_version"

remote_install_dir="$(mktemp -d)"
release_base="file://$(cd "$OUT_DIR" && pwd)"
ASIRI_RELEASE_BASE_URL="$release_base" ASIRI_INSTALL_DIR="$remote_install_dir" run "$OUT_DIR/install.sh"
remote_version="$("$remote_install_dir/asiri" --version)"
if [[ "$remote_version" != "asiri $VERSION" ]]; then
  echo "remote installer version mismatch: $remote_version" >&2
  exit 1
fi
printf '%s\n' "$remote_version"

run "$host_bin" --help
login_help="$("$host_bin" login --help)"
if [[ "$login_help" != *"Default origin: https://asiri.dev"* ]]; then
  echo "host artifact login help does not show production origin" >&2
  echo "$login_help" >&2
  exit 1
fi
host_version="$("$host_bin" --version)"
if [[ "$host_version" != "asiri $VERSION" ]]; then
  echo "host artifact version mismatch: $host_version" >&2
  exit 1
fi
printf '%s\n' "$host_version"
if [[ "${CI:-}" != "true" ]]; then
  export ASIRI_HOME="$(mktemp -d)"
  run "$host_bin" init
  export ASIRI_HOME="$(mktemp -d)"
  run "$host_bin" cache wipe
else
  printf '%s\n' "Skipping local keychain smoke on CI; full smoke covers key storage in a container secret service."
fi

printf '\nPackage smoke complete for %s/%s using %s\n' "$host_os" "$host_arch" "$host_bin"
