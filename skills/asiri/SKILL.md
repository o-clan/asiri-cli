---
name: asiri
description: "Use when an agent needs to operate Asiri CLI or Asiri-managed secrets: inspect secret metadata, run commands with scoped secrets, add or rotate operational secrets, grant local runtime access, push or pull encrypted records, configure service-account runtime access for CI or servers, or diagnose Asiri workspace/device state without exposing secret values. Focus on safe operational use first; use trust, recovery, rekey, revocation, service-account setup, and remote policy changes only when explicitly requested."
---

# Asiri

Asiri is a secrets access layer. Treat it as the source of operational secrets and the local runtime that uses them without copying values into agent context.

## Core Rules

- Never print, paste, log, summarize, or store secret values.
- Prefer metadata-only checks: list workspaces, list secret names, check status, inspect audit.
- Use `--workspace <slug>` on every command that reads, writes, grants, pushes, pulls, or runs with secrets.
- Use exact workspace slugs and secret paths from the user or from `asiri workspace list` / `asiri list`.
- Prefer `asiri env` or `asiri mount` over raw reads.
- Use raw reads only when the user explicitly asks and policy allows it; redirect verification reads to `/dev/null`.
- Stop before changing trust, device, recovery, rekey, or local key material unless the user explicitly asked for that repair.
- If Asiri reports missing platform key material, keyring errors, duplicated devices, unknown trust, or recovery problems, report the state and ask before mutating anything.

## First Checks

Run these before using or changing secrets:

```sh
asiri --version
asiri setup doctor
asiri workspace list
```

If the user named a workspace, verify it is visible and whether this device is trusted:

```sh
asiri workspace list
asiri list --workspace <workspace>
```

`asiri list` is safe for normal inspection. It shows names, hashes, sync state, and write status. It does not print plaintext.

## Use A Secret

Prefer environment injection for tools that read environment variables:

```sh
asiri env --workspace <workspace> <scope/SECRET_NAME> -- <command> <args>
```

For a group of direct child secrets under one scope:

```sh
asiri env --workspace <workspace> <scope> -- <command> <args>
```

Prefer temporary files for tools that read Docker-style secret files:

```sh
asiri mount --workspace <workspace> <scope/SECRET_NAME> -- <command> <args>
```

Use an explicit agent label when the audit/policy subject should differ from the child command name:

```sh
asiri env --workspace <workspace> --agent <label> <scope/SECRET_NAME> -- <command> <args>
```

Use argv substitution only as an escape hatch for tools that cannot read env vars or files:

```sh
asiri run --workspace <workspace> --unsafe-argv --agent <label> <command> --token asiri://<scope/SECRET_NAME>
```

## Add Or Track A Secret

Use stdin or a value file. Do not put values in command arguments.

From an environment variable:

```sh
printf '%s\n' "$VALUE_FROM_EXISTING_ENV" | asiri add --workspace <workspace> <scope/SECRET_NAME> --stdin
```

From a file:

```sh
asiri add --workspace <workspace> <scope/SECRET_NAME> --value-file <path>
```

After adding or rotating a secret that must be preserved remotely, push the narrowest target:

```sh
asiri push --workspace <workspace> --scope <scope> --secret <SECRET_NAME>
```

Before a risky or broad push, use dry-run:

```sh
asiri push --workspace <workspace> --scope <scope> --secret <SECRET_NAME> --dry-run
```

If a same-version remote record already exists and matches, push should skip it. If Asiri reports a conflict, do not overwrite blindly; inspect the local and remote metadata and ask.

## Grant Access

Grant the smallest action that lets the target command work:

```sh
asiri grant --workspace <workspace> <label> <scope/SECRET_NAME> --inject-only
asiri grant --workspace <workspace> <label> <scope/SECRET_NAME> --mount
```

Avoid `--read` for agents unless the user explicitly wants plaintext returned to that agent.

Check recent activity without values:

```sh
asiri audit tail --limit 20
```

## Pull, Push, And Rewrap

Use pull when a trusted device needs encrypted remote records locally:

```sh
asiri pull --workspace <workspace>
```

Use push when local encrypted records should be tracked in the hosted workspace:

```sh
asiri push --workspace <workspace>
```

Use rewrap only when the user explicitly wants trusted devices or recovery recipients to receive wrapped access to existing encrypted records:

```sh
asiri rewrap --workspace <workspace>
```

## Service Accounts, CI, And Servers

Use service accounts for CI and servers instead of long-lived shared tokens. Service accounts are permission identities; trusted devices remain the decryption boundary.

Only create, disable, or grant service accounts from a real authenticated user-device session:

```sh
asiri service-account create --workspace <workspace> --slug <service-account> --name <name>
asiri service-account grant --workspace <workspace> --service-account <service-account> --scope <scope> --secret <pattern> --inject-only
```

These are remote control-plane mutations. Run them only when the user explicitly asked to create, disable, or update service-account access. Service-account sessions are read-only for control-plane and local vault mutations.

For service-account login, start a browser approval flow from the runtime device. A workspace owner or delegated service-account admin must approve it:

```sh
export ASIRI_HOME="<isolated-state-dir>"
asiri init --device gha-runner
asiri service-account login --origin <origin> --workspace <workspace> --service-account <service-account>
asiri whoami
```

After approval, `whoami` should show identity type `service account`, the service-account slug/name, workspace, device, and approving human. Runtime commands audit as the service account.

Pull and injection still require the allowed secrets to be wrapped to the current trusted device:

```sh
asiri pull --workspace <workspace>
asiri env --workspace <workspace> <scope/SECRET_NAME> -- <command> <args>
```

If pull reports that an allowed secret is not wrapped to this trusted device, ask the user to rewrap from a trusted device that can already decrypt it:

```sh
asiri rewrap --workspace <workspace>
```

Do not try to recover by storing decryption material in CI secrets unless the user explicitly chooses that operational tradeoff.

## Stop And Ask

Stop before running any of these unless the user directly requested that exact operation:

- `asiri init` on an existing install.
- `asiri login --force`.
- `asiri device trust`, `asiri device revoke`, or dashboard trust changes.
- `asiri service-account create`, `asiri service-account disable`, or `asiri service-account grant`.
- `asiri service-account login` when it would bind a new runtime device to a service account.
- `asiri recovery setup`, `asiri recovery restore`, or recovery key handling.
- `asiri rekey`.
- Deleting or editing local Asiri state, keychain entries, or keyring material.
- Recreating a workspace binding, migrating prefixes, or removing local secrets.

When blocked by local key material or trust state, preserve the current state and explain the smallest safe next human action.

## Advanced Context

Trusted device state is the runtime security boundary. Agent, app, process, and command names are policy and audit labels, not strong identities.

For CI or servers, prefer service accounts over long-lived shared tokens. A service account should receive a browser-approved scoped session, then use the same local-runtime patterns: inject, mount, broker, pull, and audit. Service-account sessions cannot mutate secrets, policies, devices, members, billing, recovery, or service accounts.

For suspected host compromise, revocation blocks future access but does not erase what the host may already have seen. Rotate the upstream secret after revocation.
