# Asiri CLI

Asiri CLI is the local runtime for Asiri secrets.

It handles local vault state, trusted-device operations, encrypted secret sync, policy checks, command injection, temporary secret files, and broker access.

## Install

```bash
curl -fsSL https://github.com/o-clan/asiri-cli/releases/latest/download/install.sh | bash
```

## Verify

```bash
asiri --version
```

## Release Trust

Release binaries are published through GitHub Releases. The installer verifies the signed `SHA256SUMS` manifest with the pinned Asiri release public key, then verifies the exact downloaded artifact checksum before installing.

GitHub is the distribution channel. The Asiri release key is the trust root.
