#!/usr/bin/env bash
set -euo pipefail

VERSION="${ASIRI_VERSION:-$(node -p "require('./package.json').version")}"
OUT_DIR="${ASIRI_CLI_DIST:-dist/cli}"
TARGETS="${ASIRI_CLI_TARGETS:-linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64}"
PACKAGE="./cli/cmd/asiri"
MODULE_PATH="$(go list -m)"
PRODUCTION_CONTROL_PLANE_ORIGIN="https://asiri.dev"
LDFLAGS="-s -w -X ${MODULE_PATH}/cli/internal/cli.Version=${VERSION} -X ${MODULE_PATH}/cli/internal/cli.defaultControlPlaneOrigin=${PRODUCTION_CONTROL_PLANE_ORIGIN}"
RELEASE_SIGNING_KEY="${ASIRI_RELEASE_SIGNING_KEY:-}"
GENERATED_SIGNING_DIR=""

ASIRI_VERSION="$VERSION" node scripts/release-check.mjs
command -v openssl >/dev/null 2>&1 || { echo "openssl is required to sign release artifacts" >&2; exit 1; }
command -v tar >/dev/null 2>&1 || { echo "tar is required to package the Asiri skill" >&2; exit 1; }
if [[ -z "$RELEASE_SIGNING_KEY" ]]; then
  if [[ "${ASIRI_ALLOW_UNTRUSTED_RELEASE_KEY:-}" != "1" ]]; then
    echo "ASIRI_RELEASE_SIGNING_KEY must point to the release signing private key" >&2
    exit 1
  fi
  GENERATED_SIGNING_DIR="$(mktemp -d)"
  trap '[[ -n "$GENERATED_SIGNING_DIR" ]] && rm -rf "$GENERATED_SIGNING_DIR"' EXIT
  RELEASE_SIGNING_KEY="$GENERATED_SIGNING_DIR/release-signing-key.pem"
  openssl ecparam -name prime256v1 -genkey -noout -out "$RELEASE_SIGNING_KEY"
  echo "ASIRI_ALLOW_UNTRUSTED_RELEASE_KEY is set; using a temporary test signing key" >&2
elif [[ ! -f "$RELEASE_SIGNING_KEY" ]]; then
  echo "ASIRI_RELEASE_SIGNING_KEY must point to the release signing private key" >&2
  exit 1
fi

pinned_public_key_b64="$(awk -F'"' '/^RELEASE_PUBLIC_KEY_PEM_B64=/ { print $2; exit }' scripts/install.sh)"
[[ -n "$pinned_public_key_b64" ]] || { echo "asiri release package: missing pinned installer public key" >&2; exit 1; }
public_key="$(mktemp "${TMPDIR:-/tmp}/asiri-release-public.XXXXXX")"
openssl ec -in "$RELEASE_SIGNING_KEY" -pubout -out "$public_key" >/dev/null 2>&1
public_key_b64="$(base64 < "$public_key" | tr -d '\n')"
rm -f "$public_key"
installer_public_key_b64="$pinned_public_key_b64"
if [[ "${ASIRI_ALLOW_UNTRUSTED_RELEASE_KEY:-}" == "1" ]]; then
  installer_public_key_b64="$public_key_b64"
elif [[ "$public_key_b64" != "$pinned_public_key_b64" ]]; then
  echo "asiri release package: signing key does not match pinned installer public key" >&2
  exit 1
fi

rm -rf "$OUT_DIR"
mkdir -p "$OUT_DIR"

checksum_tool() {
  if command -v sha256sum >/dev/null 2>&1; then
    echo sha256sum
  elif command -v shasum >/dev/null 2>&1; then
    echo "shasum -a 256"
  else
    echo "sha256sum or shasum is required" >&2
    return 1
  fi
}

sha_cmd="$(checksum_tool)"
artifacts=()

for target in $TARGETS; do
  os="${target%/*}"
  arch="${target#*/}"
  ext=""
  if [[ "$os" == "windows" ]]; then
    ext=".exe"
  fi
  artifact="asiri_${VERSION}_${os}_${arch}${ext}"
  output="$OUT_DIR/$artifact"
  echo "building $artifact"
  CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go build -trimpath -ldflags "$LDFLAGS" -o "$output" "$PACKAGE"
  if [[ "$os" != "windows" ]]; then
    chmod 0755 "$output"
  fi
  artifacts+=("$artifact")
done

skill_artifact="asiri-skill.tar.gz"
tar -czf "$OUT_DIR/$skill_artifact" -C skills asiri
artifacts+=("$skill_artifact")

(
  cd "$OUT_DIR"
  : > SHA256SUMS
  for artifact in "${artifacts[@]}"; do
    $sha_cmd "$artifact" >> SHA256SUMS
  done
  openssl dgst -sha256 -sign "$(cd -P "$(dirname "$RELEASE_SIGNING_KEY")" && pwd)/$(basename "$RELEASE_SIGNING_KEY")" -out SHA256SUMS.sig SHA256SUMS
)

sed \
  -e "s/^VERSION=.*/VERSION=\"\${ASIRI_VERSION:-${VERSION}}\"/" \
  -e "s|$pinned_public_key_b64|$installer_public_key_b64|" \
  scripts/install.sh > "$OUT_DIR/install.sh"
chmod 0755 "$OUT_DIR/install.sh"

cat > "$OUT_DIR/README.txt" <<EOF_README
Asiri CLI ${VERSION} release binaries

Fast local install from this artifact directory:
  ASIRI_INSTALL_SOURCE_DIR="\$(pwd)" ./install.sh

Pick the binary matching your OS and CPU architecture:
- Linux x64:   asiri_${VERSION}_linux_amd64
- Linux ARM64: asiri_${VERSION}_linux_arm64
- macOS Intel: asiri_${VERSION}_darwin_amd64
- macOS Apple: asiri_${VERSION}_darwin_arm64
- Windows x64: asiri_${VERSION}_windows_amd64.exe
- Windows ARM: asiri_${VERSION}_windows_arm64.exe

Install the agent skill from this release:
  https://github.com/o-clan/asiri-cli/releases/latest/download/asiri-skill.tar.gz

Verify the signed checksum manifest with the trusted Asiri release public key,
then verify checksums from this directory:
  sha256sum -c SHA256SUMS

Install on Linux/macOS:
  chmod +x ./asiri_${VERSION}_linux_amd64
  mv ./asiri_${VERSION}_linux_amd64 /usr/local/bin/asiri
  asiri --version

Install on Windows PowerShell:
  .\\asiri_${VERSION}_windows_amd64.exe --version
EOF_README

cat > "$OUT_DIR/RELEASE_NOTES.md" <<EOF_NOTES
Asiri CLI v${VERSION}

Install:
\`\`\`bash
curl -fsSL https://github.com/o-clan/asiri-cli/releases/latest/download/install.sh | ASIRI_VERSION=${VERSION} bash
\`\`\`

Compatibility:
- Linux amd64/arm64
- macOS amd64/arm64
- Windows amd64/arm64

Verification:
- All artifacts are listed in SHA256SUMS.
- SHA256SUMS is signed with the Asiri release key.
- The installer verifies the signed checksum manifest and the exact downloaded artifact before installing.
- The Asiri agent skill is attached as asiri-skill.tar.gz for compatible agent harnesses.
EOF_NOTES

echo "wrote $OUT_DIR"
ls -l "$OUT_DIR"
