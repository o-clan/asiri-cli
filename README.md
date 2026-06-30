# Asiri CLI

Stop copying secrets everywhere.

Asiri CLI is the local runtime for Asiri secrets. It gives you an encrypted local vault, policy checks, command injection, temporary secret files, broker access, and encrypted sync when you choose to use the hosted control plane.

You can use it entirely locally. An Asiri account is only needed when you want hosted sync, device approval, recovery, or workspace sharing.

When hosted sync is enabled, Asiri keeps secret labels, encrypted secret material, trusted devices, policies, and audit state in one place. The hosted service cannot decrypt your secrets. It does not have the key material. Trusted devices handle decryption locally.

This CLI is open source so teams can inspect how secrets are decrypted, injected, mounted, and enforced before they trust it.

## Install

```bash
curl -fsSL https://github.com/o-clan/asiri-cli/releases/latest/download/install.sh | bash
```

## Verify

```bash
asiri --version
```

## Local Use

Start with a local encrypted vault:

```bash
asiri init --device local-laptop
```

Add a secret without putting the value in shell history:

```bash
printf '%s\n' "$API_KEY" | asiri add --workspace personal dev/API_KEY --stdin
```

Grant a local tool or agent label permission to receive that secret, then run a command with the secret injected:

```bash
asiri grant --workspace personal local-script dev/API_KEY --inject-only
asiri env --workspace personal --agent local-script dev/API_KEY -- ./deploy.sh
```

For tools that read files instead of environment variables, use `asiri mount` to create temporary secret files for the child process.

`asiri login`, `asiri push`, and `asiri pull` are optional. Use them when you want this local vault to sync encrypted secrets through the Asiri control plane.

## Release Signing

Asiri CLI binaries are published on GitHub Releases. Before installing, the installer checks the signed `SHA256SUMS` file against Asiri's pinned release public key, then checks the downloaded binary against that manifest.

GitHub hosts the files. Asiri's release key is what the installer trusts.
