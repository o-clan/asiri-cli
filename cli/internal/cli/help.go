package cli

import (
	"fmt"
	"strings"
)

func (a App) help() {
	fmt.Fprintf(a.Out, `Asiri local secrets runtime

Usage:
  asiri <command> [options]

Commands:
  init        Create a local encrypted vault and trusted local device.
  setup       Diagnose local, device, workspace, and recovery setup.
  login       Link this device to the hosted control plane.
  logout      Remove the hosted control-plane session from this device.
  workspace   Create and inspect local workspaces, aliases, and hosted access trees.
  member      List workspace members and manage their secret access.
  service-account
              Manage and log in as service accounts.
  push        Upload encrypted local-only secrets to a specified workspace.
  pull        Pull encrypted remote secrets into the local vault.
  rewrap      Add missing trusted-device recipients to remote secret versions.
  rekey       Re-encrypt local secrets with fresh scoped data keys, then push.
  recovery    Configure or use workspace recovery keys.
  device      Trust, inspect, list, or revoke devices.
  secret      Manage remote control-plane secrets.
  local       Manage local machine state.
  whoami      Show the signed-in control-plane user.
  add         Add a local secret from stdin or a value file.
  get         Read a local secret if policy allows raw read.
  list        Show local and visible remote secret metadata.
  rotate      Add a new local version for an existing secret.
  rm          Mark a local secret as deleted, or explicitly soft-delete a remote secret.
  grant       Allow a subject to use a secret through policy.
  deny        Deny a subject at a scope.
  policy      List local policy rules.
  run         Run a command with injected secrets.
  env         Run a command with one scope or secret injected.
  mount       Run a command with temporary secret files.
  broker      Start the local broker. Example: asiri broker start --workspace qa --agent app.
  audit       Read local audit events.
  cache       Wipe local Asiri cache and control-plane keys.

Run "asiri <command> --help" for command-specific help.

Secrets are encrypted locally. Device trust is the security boundary; agent and process names are policy labels.
`)
}

func commandHelpRequested(args []string) bool {
	if len(args) < 2 {
		return false
	}
	if args[1] == "--help" || args[1] == "-h" {
		return true
	}
	if args[0] == "run" {
		return false
	}
	for _, arg := range args[2:] {
		if arg == "--" {
			return false
		}
		if arg == "--help" || arg == "-h" {
			return true
		}
	}
	return false
}

func commandHelpPath(args []string) []string {
	path := []string{args[0]}
	limit := 2
	if args[0] == "member" && len(args) > 1 && args[1] == "access" {
		limit = 3
	}
	for _, arg := range args[1:] {
		if arg == "--" || strings.HasPrefix(arg, "-") {
			break
		}
		path = append(path, arg)
		if len(path) == limit {
			break
		}
	}
	return path
}

func (a App) helpFor(path []string) int {
	if len(path) == 0 {
		a.help()
		return 0
	}
	topic := strings.Join(path, " ")
	switch topic {
	case "init":
		fmt.Fprint(a.Out, "Usage: asiri init [--device <device>] [--kind <laptop|server|ci|agent-host>] [--workspace <slug>]\n\nCreates local encrypted state and a trusted device. Sign in next to use the hosted personal workspace, or provide --workspace to create an offline workspace during initialization.\n")
	case "setup":
		fmt.Fprint(a.Out, "Usage: asiri setup <command>\n\nCommands:\n  doctor  Diagnose setup readiness and print next safe steps.\n")
	case "setup doctor":
		fmt.Fprint(a.Out, "Usage: asiri setup doctor --workspace <slug>\n\nChecks local initialization, account authentication, device trust, key coverage, and recovery status for one explicit workspace. It does not create devices, change trust, rewrap keys, or write secrets.\n")
	case "version":
		fmt.Fprint(a.Out, "Usage: asiri version\n       asiri --version\n\nPrints the CLI version.\n")
	case "login":
		fmt.Fprintf(a.Out, "Usage: asiri login [--origin <url>] [--force]\n\nLinks this local device to the control plane. Rerun without --force to recover an expired session. --force replaces a linked session but does not create new device keys. For revoked keys, run asiri logout, then asiri device enroll --name <new-name>, then asiri login. Default origin: %s.\n", defaultControlPlaneOrigin)
	case "logout":
		fmt.Fprint(a.Out, "Usage: asiri logout\n\nRevokes the local control-plane session and removes local session tokens. The local vault, secrets, and device keys are preserved.\n")
	case "whoami":
		fmt.Fprint(a.Out, "Usage: asiri whoami\n\nShows the signed-in control-plane identity and authentication device. User sessions do not select a workspace.\n")
	case "workspace":
		fmt.Fprint(a.Out, "Usage: asiri workspace <command>\n\nCommands:\n  create   Create a local workspace.\n  alias    Set a local or account-scoped workspace alias.\n  list     Show local or visible hosted workspaces.\n  tree     Show users, trusted devices, effective access, and secret counts.\n")
	case "workspace create":
		fmt.Fprint(a.Out, "Usage: asiri workspace create <slug>\n\nCreates an offline-capable local workspace. Its first hosted sync assigns an immutable canonical slug and retains the selected local alias, or this slug when no alias was selected.\n")
	case "workspace alias":
		fmt.Fprint(a.Out, "Usage: asiri workspace alias set --workspace <canonical-slug-or-alias> <alias>\n\nAliases are unique for one user and may be reused by different users.\n")
	case "workspace list":
		fmt.Fprint(a.Out, "Usage: asiri workspace list\n\nShows canonical workspace slugs and user-scoped aliases. Offline it lists local workspaces; after login it lists visible hosted workspaces.\n")
	case "workspace tree":
		fmt.Fprint(a.Out, "Usage: asiri workspace tree --workspace <slug> [--json] [--include-revoked]\n\nShows one compact workspace access tree for the workspace owner, including active service-account sessions on trusted devices. Access belongs to users; devices are listed separately because trust only determines where permitted secrets can be decrypted. Secret values are never returned.\n")
	case "member":
		fmt.Fprint(a.Out, "Usage: asiri member <command>\n\nCommands:\n  list    List workspace members by name and email.\n  access  List, grant, or revoke member access to envelopes and secrets.\n\nRequires a trusted device linked through asiri login.\n")
	case "member list":
		fmt.Fprint(a.Out, "Usage: asiri member list --workspace <slug> [--all]\n\nLists workspace member metadata. Removed members are hidden unless --all is set. Secret values are never shown.\n")
	case "member access":
		fmt.Fprint(a.Out, "Usage: asiri member access <command>\n\nCommands:\n  list    List member secret-access grants.\n  grant   Grant an active member access to one envelope or secret.\n  revoke  Revoke one grant by id.\n")
	case "member access list":
		fmt.Fprint(a.Out, "Usage: asiri member access list --workspace <slug> [--member <email-or-user-id>] [--all]\n\nLists active member access grants. Revoked grants are included with --all.\n")
	case "member access grant":
		fmt.Fprint(a.Out, "Usage: asiri member access grant --workspace <slug> --member <email-or-user-id> --envelope <scope|/> [--include-descendants]\n       asiri member access grant --workspace <slug> --member <email-or-user-id> --secret <scope/name>\n\nUse / for the workspace-root envelope. A direct envelope grant covers secrets directly inside it; --include-descendants also covers child envelopes. Run rewrap afterward so permitted trusted devices receive wrapped keys.\n")
	case "member access revoke":
		fmt.Fprint(a.Out, "Usage: asiri member access revoke --workspace <slug> --grant <id>\n\nRevokes future access through that grant. Existing decrypted or cached copies are not erased, and another active grant may still authorize the same secrets.\n")
	case "service-account":
		fmt.Fprint(a.Out, "Usage: asiri service-account <command>\n\nCommands:\n  create   Create a service account from a trusted device session.\n  list     List service accounts in a workspace.\n  disable  Disable a service account.\n  grant    Add a remote service policy for a service account.\n  login    Start a browser-approved service account login.\n")
	case "service-account create":
		fmt.Fprint(a.Out, "Usage: asiri service-account create --workspace <slug> --slug <slug> --name <name>\n")
	case "service-account list":
		fmt.Fprint(a.Out, "Usage: asiri service-account list --workspace <slug> [--all]\n")
	case "service-account disable":
		fmt.Fprint(a.Out, "Usage: asiri service-account disable --workspace <slug> --service-account <slug-or-id>\n")
	case "service-account grant":
		fmt.Fprint(a.Out, "Usage: asiri service-account grant --workspace <slug> --service-account <slug-or-id> --scope <scope> --secret <pattern> --inject-only|--read|--mount|--broker|--sign|--proxy-local [--approval-mode none|require-owner] [--expires-at <iso>]\n")
	case "service-account login":
		fmt.Fprintf(a.Out, "Usage: asiri service-account login --workspace <slug> --service-account <slug> [--origin <url>]\n\nCreates a browser approval link. A workspace owner or service-account admin must approve it. Default origin: %s.\n", defaultControlPlaneOrigin)
	case "push":
		fmt.Fprint(a.Out, "Usage: asiri push --workspace <slug> [--scope <scope>...] [--secret <scope/name>...] [--version <n>] [--dry-run] [--yes]\n\nUploads new local encrypted versions for the specified workspace. Existing matching versions are skipped, older local versions are skipped with a warning, and same-version mismatches fail as conflicts. Use --scope for one envelope, --secret for one exact secret, and --version only with one --secret. Use short paths without the workspace prefix.\n")
	case "pull":
		fmt.Fprint(a.Out, "Usage: asiri pull --workspace <slug> [--force]\n\nPulls encrypted remote secret versions from one explicit workspace into the local vault. Pull is import-only; it never uploads local-only secrets.\n")
	case "rewrap":
		fmt.Fprint(a.Out, "Usage: asiri rewrap --workspace <slug>\n\nAdds missing wrapped-key recipients for trusted devices in the specified workspace.\n")
	case "rekey":
		fmt.Fprint(a.Out, "Usage: asiri rekey --workspace <slug> [--yes]\n\nRe-encrypts local secrets in the specified workspace with fresh scoped data keys, then pushes the new versions.\n")
	case "recovery":
		fmt.Fprint(a.Out, "Usage: asiri recovery <command>\n\nCommands:\n  setup    Create or replace a workspace recovery key.\n  restore  Restore recoverable workspace secrets to this trusted device.\n  status   Show recovery status for one workspace.\n")
	case "recovery setup":
		fmt.Fprint(a.Out, "Usage: asiri recovery setup --workspace <slug> [--force] [--output-file <path>]\n\nCreates a recovery key for the specified workspace and stores recovery recipient metadata remotely.\n")
	case "recovery restore":
		fmt.Fprint(a.Out, "Usage: asiri recovery restore --workspace <slug> --stdin|--key-file <path> [--force]\n\nUses a recovery key to add this trusted device as a recipient for recoverable remote secrets in the specified workspace.\n")
	case "recovery status":
		fmt.Fprint(a.Out, "Usage: asiri recovery status --workspace <slug>\n\nShows whether recovery is configured for one explicit workspace.\n")
	case "device":
		fmt.Fprint(a.Out, "Usage: asiri device <command>\n\nCommands:\n  name    Print the current local device name.\n  enroll  Add a local device record.\n  status  Show current-device trust and key coverage.\n  trust   Trust this device in one workspace.\n  list    Show local or remote devices.\n  revoke  Revoke a local or remote device.\n")
	case "device name":
		fmt.Fprint(a.Out, "Usage: asiri device name\n\nPrints the current local device name.\n")
	case "device enroll":
		fmt.Fprint(a.Out, "Usage: asiri device enroll --name <device> [--kind <laptop|server|ci|agent-host>]\n\nCreates a new local device keypair and local trusted-device record without changing the vault or local secrets. Kind is inferred for common CI and headless Linux environments unless set explicitly. Log out first when replacing keys for a linked device.\n")
	case "device list":
		fmt.Fprint(a.Out, "Usage: asiri device list --remote --workspace <slug> [--include-revoked]\n       asiri device list --local [--include-revoked]\n\nLists remote devices in one explicit workspace, or this machine's local device records. Revoked devices are hidden unless --include-revoked is set.\n")
	case "device status":
		fmt.Fprint(a.Out, "Usage: asiri device status --workspace <slug>\n\nShows whether this device is trusted in one explicit workspace and whether that workspace's remote secrets are wrapped to it.\n")
	case "device trust":
		fmt.Fprint(a.Out, "Usage: asiri device trust --workspace <slug> [--origin <url>]\n\nStarts browser approval to trust this device in one explicit workspace without replacing the account session.\n")
	case "device revoke":
		fmt.Fprint(a.Out, "Usage: asiri device revoke <device>\n       asiri device revoke --remote --workspace <slug> <device>\n\nRevokes a local device record, or revokes a remote trusted device in the specified workspace.\n")
	case "secret":
		fmt.Fprint(a.Out, "Usage: asiri secret <command>\n\nCommands:\n  delete   Mark the active remote secret version as deleted.\n  restore  Restore a soft-deleted remote secret version.\n")
	case "secret delete":
		fmt.Fprint(a.Out, "Usage: asiri secret delete --workspace <slug> <scope/name> [--dry-run|--confirm-token <token>]\n       asiri secret delete --workspace <slug> --where remote-only [--dry-run|--confirm-token <token>]\n\nSoft-deletes active remote secret versions in the control plane. Use short paths without the workspace prefix. Run --dry-run first for an agent-friendly confirmation token, or type the requested confirmation text interactively.\n")
	case "secret restore":
		fmt.Fprint(a.Out, "Usage: asiri secret restore --workspace <slug> <scope/name> [--yes]\n\nRestores a soft-deleted remote secret version before its purge window expires. Use short paths without the workspace prefix.\n")
	case "local":
		fmt.Fprint(a.Out, "Usage: asiri local <command>\n\nCommands:\n  wipe  Delete local state and Asiri key material.\n")
	case "local wipe":
		fmt.Fprint(a.Out, "Usage: asiri local wipe [--yes]\n\nDeletes local state and Asiri key material for this machine. This never calls remote APIs. Without --yes, type `wipe local` to confirm.\n")
	case "add":
		fmt.Fprint(a.Out, "Usage: asiri add --workspace <slug> <scope/name> --stdin|--value-file <path>\n\nAdds a local encrypted secret. Use short paths without the workspace prefix. File and stdin input are stored byte-for-byte, including final newlines and empty input.\n")
	case "get":
		fmt.Fprint(a.Out, "Usage: asiri get --workspace <slug> <scope/name> [--agent <agent>]\n\nReads a local secret when policy allows raw read for the human user or named agent label. Use short paths without the workspace prefix.\n")
	case "list":
		fmt.Fprint(a.Out, "Usage: asiri list --workspace <canonical-slug-or-alias> [filter] [--local|--remote] [--status <status>] [--include-inactive]\n\nShows metadata for one explicit local or hosted workspace. A fresh offline vault will suggest creating a workspace first. Values are never printed.\n")
	case "rotate":
		fmt.Fprint(a.Out, "Usage: asiri rotate --workspace <slug> <scope/name> --stdin|--value-file <path>\n\nAdds a new local encrypted version for an existing secret. Use short paths without the workspace prefix. File and stdin input are stored byte-for-byte.\n")
	case "rm":
		fmt.Fprint(a.Out, "Usage: asiri rm --workspace <slug> <scope/name>\n       asiri rm --remote --workspace <slug> <scope/name> [--dry-run|--confirm-token <token>]\n       asiri rm --remote --workspace <slug> --where remote-only [--dry-run|--confirm-token <token>]\n\nMarks a local secret as deleted by default. With --remote, soft-deletes active remote secret versions in the control plane. Use short paths without the workspace prefix.\n")
	case "grant":
		fmt.Fprint(a.Out, "Usage: asiri grant --workspace <slug> <subject-label> <scope/name> --inject-only|--read|--mount|--broker\n\nAdds a local policy rule allowing a non-human subject label to use a secret. Use short paths without the workspace prefix.\n")
	case "deny":
		fmt.Fprint(a.Out, "Usage: asiri deny --workspace <slug> <subject-label> <scope/*>\n\nAdds a local policy rule denying a subject label at a scope. Use short paths without the workspace prefix.\n")
	case "policy":
		fmt.Fprint(a.Out, "Usage: asiri policy list --workspace <slug>\n\nLists local policy rules for one explicit workspace.\n")
	case "policy list":
		fmt.Fprint(a.Out, "Usage: asiri policy list --workspace <slug>\n\nLists local allow and deny policy rules for one explicit workspace.\n")
	case "run":
		fmt.Fprint(a.Out, "Usage: asiri run --workspace <slug> [--agent <subject-label>] --env NAME=<scope/name> -- <command...>\n       asiri run --workspace <slug> [--agent <subject-label>] --unsafe-argv <command... asiri://scope/name>\n\nRuns a command with secrets injected through environment variables or explicit unsafe argument substitution. Use short paths without the workspace prefix.\n")
	case "env":
		fmt.Fprint(a.Out, "Usage: asiri env --workspace <slug> [--agent <subject-label>] <scope-or-secret> -- <command...>\n\nRuns a command with secrets from one scope or one secret injected into the environment. Use short paths without the workspace prefix.\n")
	case "mount":
		fmt.Fprint(a.Out, "Usage: asiri mount --workspace <slug> [--agent <subject-label>] [--dir <dir>] <scope-or-secret[:dest]> -- <command...>\n\nRuns a command with temporary secret files mounted under a private directory. Use short paths without the workspace prefix.\n")
	case "broker":
		fmt.Fprint(a.Out, "Usage: asiri broker start --workspace <slug> --agent <subject-label> [--socket <path>|--listen <addr>] [--client-file <path>] [--token-ttl <duration>] [--idle-timeout <duration>] [--max-runtime <duration>] [--once]\n\nStarts a local broker for approved per-request secret access. Defaults to a Unix socket when supported and loopback HTTP otherwise.\n")
	case "broker start":
		fmt.Fprint(a.Out, "Usage: asiri broker start --workspace <slug> --agent <subject-label> [--socket <path>|--listen <addr>] [--client-file <path>] [--token-ttl <duration>] [--idle-timeout <duration>] [--max-runtime <duration>] [--once]\n\nStarts the local broker. With --once, handles one request and exits.\n")
	case "audit":
		fmt.Fprint(a.Out, "Usage: asiri audit tail --workspace <slug> [--limit N]\n\nShows recent local audit events for one explicit workspace.\n")
	case "audit tail":
		fmt.Fprint(a.Out, "Usage: asiri audit tail --workspace <slug> [--limit N]\n\nShows the most recent local audit events for one explicit workspace, newest first.\n")
	case "cache":
		fmt.Fprint(a.Out, "Usage: asiri cache wipe\n\nAlias for local wipe. Deletes local state and Asiri key material for this machine.\n")
	case "cache wipe":
		fmt.Fprint(a.Out, "Usage: asiri cache wipe\n\nAlias for local wipe. Deletes local state and Asiri key material for this machine.\n")
	default:
		return a.fail(fmt.Errorf("unknown help topic %q", topic))
	}
	return 0
}
