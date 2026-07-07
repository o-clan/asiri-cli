package cli

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/o-clan/asiri/cli/internal/asiri"
	"github.com/o-clan/asiri/cli/internal/broker"
	"github.com/o-clan/asiri/cli/internal/keystore"
	"github.com/o-clan/asiri/cli/internal/store"
	"golang.org/x/term"
)

type App struct {
	Out io.Writer
	Err io.Writer
	In  io.Reader
}

var Version = "0.1.30"

var defaultControlPlaneOrigin = "http://127.0.0.1:4173"

var envNamePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
var asiriRefPattern = regexp.MustCompile(`asiri://[A-Za-z0-9][A-Za-z0-9/_-]{1,96}/[A-Za-z0-9][A-Za-z0-9_.-]{1,96}`)

func New(out, err io.Writer) App {
	return App{Out: out, Err: err, In: os.Stdin}
}

func (a App) Run(args []string) int {
	if len(args) == 0 || args[0] == "--help" || args[0] == "help" {
		if len(args) > 1 && args[0] == "help" {
			return a.helpFor(args[1:])
		}
		a.help()
		return 0
	}
	if commandHelpRequested(args) {
		return a.helpFor(commandHelpPath(args))
	}
	if args[0] == "--version" || args[0] == "version" {
		fmt.Fprintf(a.Out, "asiri %s\n", Version)
		return 0
	}
	st, err := store.LoadDefault()
	if err != nil {
		return a.fail(err)
	}
	cmd := args[0]
	args = args[1:]
	switch cmd {
	case "init":
		return a.initLocal(st, args)
	case "setup":
		return a.setup(st, args)
	case "login":
		return a.login(st, args)
	case "logout":
		return a.logout(st, args)
	case "whoami":
		return a.whoami(st, args)
	case "workspace":
		return a.workspace(st, args)
	case "service-account":
		return a.serviceAccount(st, args)
	case "push":
		return a.push(st, args)
	case "pull":
		return a.pull(st, args)
	case "rewrap":
		return a.rewrap(st, args)
	case "rekey":
		return a.rekey(st, args)
	case "recovery":
		return a.recovery(st, args)
	case "device":
		return a.device(st, args)
	case "secret":
		return a.secret(st, args)
	case "local":
		return a.local(st, args)
	case "add":
		return a.add(st, args)
	case "get":
		return a.get(st, args)
	case "list":
		return a.list(st, args)
	case "rotate":
		return a.rotate(st, args)
	case "rm":
		return a.remove(st, args)
	case "grant":
		return a.grant(st, args)
	case "deny":
		return a.deny(st, args)
	case "policy":
		return a.policy(st, args)
	case "run":
		return a.run(st, args)
	case "env":
		return a.env(st, args)
	case "mount":
		return a.mount(st, args)
	case "broker":
		return a.broker(st, args)
	case "audit":
		return a.audit(st, args)
	case "cache":
		return a.cache(st, args)
	default:
		return a.fail(fmt.Errorf("unknown command %q", cmd))
	}
}

func (a App) help() {
	fmt.Fprintf(a.Out, `Asiri local secrets runtime

Usage:
  asiri <command> [options]

Commands:
  init        Create a local encrypted vault and trusted local device.
  setup       Diagnose local, device, workspace, and recovery setup.
  login       Link this device to the hosted control plane.
  logout      Remove the hosted control-plane session from this device.
  workspace   List visible control-plane workspaces.
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
	for _, arg := range args[1:] {
		if arg == "--" || strings.HasPrefix(arg, "-") {
			break
		}
		path = append(path, arg)
		if len(path) == 2 {
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
	topic := path[0]
	if len(path) > 1 {
		topic += " " + path[1]
	}
	switch topic {
	case "init":
		fmt.Fprint(a.Out, "Usage: asiri init [--device <device>]\n\nCreates a local encrypted vault and a trusted local device. Local vaults do not have workspace slugs.\n")
	case "setup":
		fmt.Fprint(a.Out, "Usage: asiri setup <command>\n\nCommands:\n  doctor  Diagnose setup readiness and print next safe steps.\n")
	case "setup doctor":
		fmt.Fprint(a.Out, "Usage: asiri setup doctor [--workspace <slug>...]\n\nChecks local initialization, control-plane auth, current-device trust, key coverage, and recovery status. It does not create devices, change trust, rewrap keys, or write secrets.\n")
	case "version":
		fmt.Fprint(a.Out, "Usage: asiri version\n       asiri --version\n\nPrints the CLI version.\n")
	case "login":
		fmt.Fprintf(a.Out, "Usage: asiri login [--origin <url>] [--force]\n\nLinks this local device to the control plane. Default origin: %s.\n", defaultControlPlaneOrigin)
	case "logout":
		fmt.Fprint(a.Out, "Usage: asiri logout\n\nRevokes the local control-plane session and removes local session tokens.\n")
	case "whoami":
		fmt.Fprint(a.Out, "Usage: asiri whoami\n\nShows the signed-in control-plane user, active workspace session, and current local device.\n")
	case "workspace":
		fmt.Fprint(a.Out, "Usage: asiri workspace <command>\n\nCommands:\n  list   Show visible workspaces, role, device trust, account write access, and id.\n")
	case "workspace list":
		fmt.Fprint(a.Out, "Usage: asiri workspace list\n\nShows visible workspaces as a table. This device controls pull and workspace-scoped push. Account write means the user owns the workspace or has effective secret-write capability.\n")
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
		fmt.Fprint(a.Out, "Usage: asiri pull [--force] [--workspace <slug>...]\n\nPulls encrypted remote secret versions into the local vault. Pull is import-only; it never uploads local-only secrets. Without --workspace, all eligible visible workspaces are pulled and ineligible workspaces are reported as skipped.\n")
	case "rewrap":
		fmt.Fprint(a.Out, "Usage: asiri rewrap --workspace <slug>\n\nAdds missing wrapped-key recipients for trusted devices in the specified workspace.\n")
	case "rekey":
		fmt.Fprint(a.Out, "Usage: asiri rekey --workspace <slug> [--yes]\n\nRe-encrypts local secrets in the specified workspace with fresh scoped data keys, then pushes the new versions.\n")
	case "recovery":
		fmt.Fprint(a.Out, "Usage: asiri recovery <command>\n\nCommands:\n  setup    Create or replace a workspace recovery key.\n  restore  Restore recoverable workspace secrets to this trusted device.\n  status   Show recovery status for visible workspaces.\n")
	case "recovery setup":
		fmt.Fprint(a.Out, "Usage: asiri recovery setup --workspace <slug> [--force] [--output-file <path>]\n\nCreates a recovery key for the specified workspace and stores recovery recipient metadata remotely.\n")
	case "recovery restore":
		fmt.Fprint(a.Out, "Usage: asiri recovery restore --workspace <slug> --stdin|--key-file <path> [--force]\n\nUses a recovery key to add this trusted device as a recipient for recoverable remote secrets in the specified workspace.\n")
	case "recovery status":
		fmt.Fprint(a.Out, "Usage: asiri recovery status [--workspace <slug>...]\n\nShows whether recovery is configured for visible workspaces.\n")
	case "device":
		fmt.Fprint(a.Out, "Usage: asiri device <command>\n\nCommands:\n  name    Print the current local device name.\n  enroll  Add a local device record.\n  status  Show current-device trust and key coverage.\n  trust   Trust this device in one or more workspaces.\n  list    Show local or remote devices.\n  revoke  Revoke a local or remote device.\n")
	case "device name":
		fmt.Fprint(a.Out, "Usage: asiri device name\n\nPrints the current local device name.\n")
	case "device enroll":
		fmt.Fprint(a.Out, "Usage: asiri device enroll --name <device>\n\nCreates a new local device keypair and local trusted-device record.\n")
	case "device list":
		fmt.Fprint(a.Out, "Usage: asiri device list [--local|--remote] [--workspace <slug>...] [--include-revoked]\n\nLists remote devices in visible workspaces when linked to the control plane. Use --local to show only this machine's local device records. Revoked devices are hidden unless --include-revoked is set.\n")
	case "device status":
		fmt.Fprint(a.Out, "Usage: asiri device status [--workspace <slug>...]\n\nShows whether this device is trusted in visible workspaces and whether visible remote secrets are wrapped to it.\n")
	case "device trust":
		fmt.Fprint(a.Out, "Usage: asiri device trust --workspace <slug> [--origin <url>]\n       asiri device trust --all\n\nStarts browser approval to trust this device in a workspace. --all walks every visible workspace where this account can approve devices.\n")
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
		fmt.Fprint(a.Out, "Usage: asiri add --workspace <slug> <scope/name> --stdin|--value-file <path>\n\nAdds a local encrypted secret. Use short paths without the workspace prefix. Values are accepted only through stdin or a file to avoid shell history exposure.\n")
	case "get":
		fmt.Fprint(a.Out, "Usage: asiri get --workspace <slug> <scope/name> [--agent <agent>]\n\nReads a local secret when policy allows raw read for the human user or named agent label. Use short paths without the workspace prefix.\n")
	case "list":
		fmt.Fprint(a.Out, "Usage: asiri list [filter] [--workspace <slug>...] [--local|--remote] [--status <status>] [--include-inactive]\n\nShows secret metadata only. Values are never printed by list. Without --workspace, visible workspaces are included. Inactive remote versions are hidden unless --include-inactive is set.\n")
	case "rotate":
		fmt.Fprint(a.Out, "Usage: asiri rotate --workspace <slug> <scope/name> --stdin|--value-file <path>\n\nAdds a new local encrypted version for an existing secret. Use short paths without the workspace prefix.\n")
	case "rm":
		fmt.Fprint(a.Out, "Usage: asiri rm --workspace <slug> <scope/name>\n       asiri rm --remote --workspace <slug> <scope/name> [--dry-run|--confirm-token <token>]\n       asiri rm --remote --workspace <slug> --where remote-only [--dry-run|--confirm-token <token>]\n\nMarks a local secret as deleted by default. With --remote, soft-deletes active remote secret versions in the control plane. Use short paths without the workspace prefix.\n")
	case "grant":
		fmt.Fprint(a.Out, "Usage: asiri grant --workspace <slug> <subject-label> <scope/name> --inject-only|--read|--mount|--broker\n\nAdds a local policy rule allowing a non-human subject label to use a secret. Use short paths without the workspace prefix.\n")
	case "deny":
		fmt.Fprint(a.Out, "Usage: asiri deny --workspace <slug> <subject-label> <scope/*>\n\nAdds a local policy rule denying a subject label at a scope. Use short paths without the workspace prefix.\n")
	case "policy":
		fmt.Fprint(a.Out, "Usage: asiri policy list [--workspace <slug>...]\n\nLists local policy rules.\n")
	case "policy list":
		fmt.Fprint(a.Out, "Usage: asiri policy list [--workspace <slug>...]\n\nLists local allow and deny policy rules.\n")
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
		fmt.Fprint(a.Out, "Usage: asiri audit tail [--limit N] [--workspace <slug>...]\n\nShows recent local audit events.\n")
	case "audit tail":
		fmt.Fprint(a.Out, "Usage: asiri audit tail [--limit N] [--workspace <slug>...]\n\nShows the most recent local audit events, newest first.\n")
	case "cache":
		fmt.Fprint(a.Out, "Usage: asiri cache wipe\n\nAlias for local wipe. Deletes local state and Asiri key material for this machine.\n")
	case "cache wipe":
		fmt.Fprint(a.Out, "Usage: asiri cache wipe\n\nAlias for local wipe. Deletes local state and Asiri key material for this machine.\n")
	default:
		return a.fail(fmt.Errorf("unknown help topic %q", topic))
	}
	return 0
}

func (a App) initLocal(st *store.FileStore, args []string) int {
	deviceName, err := parseInitArgs(args)
	if err != nil {
		return a.fail(err)
	}
	if deviceName == "" {
		hostname, hostErr := os.Hostname()
		if hostErr != nil || hostname == "" {
			deviceName = "local-device"
		} else {
			deviceName = hostname
		}
	}
	if err := st.InitializeLocal(); err != nil {
		return a.fail(err)
	}
	device, refs, err := createDevice(deviceName)
	usedFileKeyStore := false
	if errors.Is(err, keystore.ErrPlatformUnavailable) && keystore.FileKeyStoreDir() == "" {
		st.UseDefaultFileKeyStore()
		device, refs, err = createDevice(deviceName)
		usedFileKeyStore = err == nil
	}
	if err != nil {
		_ = st.DeletePlatformKeys()
		_ = os.Remove(st.Path)
		return a.fail(err)
	}
	st.State.Devices = append(st.State.Devices, device)
	st.State.LocalDeviceID = device.ID
	for _, ref := range refs {
		st.AddKeyRef(ref.Purpose, ref.Account)
	}
	st.Audit(st.State.UserID, "device_enrolled", "allowed", "", "", "local device trusted", map[string]string{"device": deviceName})
	if err := st.Save(); err != nil {
		_ = st.DeletePlatformKeys()
		_ = os.Remove(st.Path)
		return a.fail(err)
	}
	fmt.Fprintf(a.Out, "✓ Initialized local Asiri vault with trusted device %s\n", deviceName)
	if usedFileKeyStore {
		fmt.Fprintf(a.Out, "  Platform keyring unavailable; using local file key store at %s\n", keystore.FileKeyStoreDir())
	}
	return 0
}

func parseInitArgs(args []string) (string, error) {
	deviceName := ""
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--device":
			if i+1 >= len(args) || strings.HasPrefix(args[i+1], "--") {
				return "", errors.New("--device requires a value")
			}
			deviceName = args[i+1]
			i++
		case "--workspace":
			return "", errors.New("asiri init no longer accepts --workspace; local vaults do not have workspace slugs")
		default:
			return "", fmt.Errorf("unknown init argument %q", args[i])
		}
	}
	return deviceName, nil
}

func (a App) login(st *store.FileStore, args []string) int {
	if err := st.RequireInitialized(); err != nil {
		return a.fail(err)
	}
	force := hasFlag(args, "--force")
	origin := loginOrigin(args, st)
	if err := validateControlPlaneOrigin(origin); err != nil {
		return a.fail(err)
	}
	if st.State.ControlPlane != nil && !force {
		if st.State.ControlPlane.Source == "service-account" {
			return a.fail(errors.New("service account session active; run asiri logout first, or asiri login --force to replace it"))
		}
		result, status, err := refreshDeviceSession(origin, st)
		if err == nil && status == http.StatusOK {
			if err := st.RefreshControlPlane(result.AccessToken, result.ExpiresIn, result.RefreshExpiresAt); err != nil {
				return a.fail(err)
			}
			fmt.Fprintf(a.Out, "✓ Control-plane session refreshed for workspace %s\n", st.State.ControlPlane.WorkspaceSlug)
			return 0
		}
		if err == nil && remoteDeviceNotTrusted(status, result.Error) {
			if err := st.QuarantineLocalKeys("remote device is no longer trusted"); err != nil {
				return a.fail(fmt.Errorf("remote device is no longer trusted, but local key cleanup failed: %w", err))
			}
			return a.fail(errors.New("remote device is no longer trusted; local key material was cleared"))
		}
		if err != nil || (status != http.StatusUnauthorized && status != http.StatusForbidden) {
			if err != nil {
				return a.fail(err)
			}
			return a.fail(fmt.Errorf("control plane returned HTTP %d", status))
		}
	}
	device, err := st.ActiveDevice()
	if err != nil {
		return a.fail(err)
	}
	start, err := startDeviceCodeLogin(origin, "", *device)
	if err != nil {
		return a.fail(err)
	}
	fmt.Fprintf(a.Out, "Open %s\n", start.VerificationURIComplete)
	fmt.Fprintf(a.Out, "Code: %s\n", start.UserCode)
	result, err := pollDeviceCodeLogin(st, origin, start)
	if err != nil {
		return a.fail(err)
	}
	if err := st.LinkControlPlaneForDevice(origin, result.OrgID, result.WorkspaceSlug, result.UserID, result.DeviceID, device.ID, result.AccessToken, result.RefreshToken, result.ExpiresIn, result.RefreshExpiresAt); err != nil {
		return a.fail(err)
	}
	fmt.Fprintf(a.Out, "✓ Linked local device to workspace %s\n", result.WorkspaceSlug)
	return 0
}

func loginOrigin(args []string, st *store.FileStore) string {
	if origin := strings.TrimRight(flagValue(args, "--origin", ""), "/"); origin != "" {
		return origin
	}
	if origin := strings.TrimRight(os.Getenv("ASIRI_CONTROL_PLANE_ORIGIN"), "/"); origin != "" {
		return origin
	}
	if st.State.ControlPlane != nil && !hasFlag(args, "--force") {
		return st.State.ControlPlane.Origin
	}
	return defaultControlPlaneOrigin
}

func (a App) serviceAccount(st *store.FileStore, args []string) int {
	if len(args) == 0 {
		return a.fail(errors.New("service-account subcommand required"))
	}
	switch args[0] {
	case "create":
		return a.serviceAccountCreate(st, args[1:])
	case "list":
		return a.serviceAccountList(st, args[1:])
	case "disable":
		return a.serviceAccountDisable(st, args[1:])
	case "grant":
		return a.serviceAccountGrant(st, args[1:])
	case "login":
		return a.serviceAccountLogin(st, args[1:])
	default:
		return a.fail(fmt.Errorf("unknown service-account command %q", args[0]))
	}
}

type serviceAccountCreateOptions struct {
	Workspace string
	Slug      string
	Name      string
}

func parseServiceAccountCreateArgs(args []string) (serviceAccountCreateOptions, error) {
	var options serviceAccountCreateOptions
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--workspace":
			if i+1 >= len(args) || strings.HasPrefix(args[i+1], "--") {
				return options, errors.New("--workspace requires a slug")
			}
			options.Workspace = args[i+1]
			i++
		case "--slug":
			if i+1 >= len(args) || strings.HasPrefix(args[i+1], "--") {
				return options, errors.New("--slug requires a slug")
			}
			options.Slug = args[i+1]
			i++
		case "--name":
			if i+1 >= len(args) || strings.HasPrefix(args[i+1], "--") {
				return options, errors.New("--name requires a value")
			}
			options.Name = args[i+1]
			i++
		case "--origin":
			if i+1 >= len(args) || strings.HasPrefix(args[i+1], "--") {
				return options, errors.New("--origin requires a URL")
			}
			i++
		default:
			return options, fmt.Errorf("unknown service-account create argument %q", args[i])
		}
	}
	if options.Workspace == "" {
		return options, errors.New("service-account create requires --workspace")
	}
	if options.Slug == "" {
		return options, errors.New("service-account create requires --slug")
	}
	if options.Name == "" {
		return options, errors.New("service-account create requires --name")
	}
	return options, nil
}

type serviceAccountSelectOptions struct {
	Workspace      string
	ServiceAccount string
	All            bool
}

func parseServiceAccountSelectArgs(args []string, command string) (serviceAccountSelectOptions, error) {
	var options serviceAccountSelectOptions
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--workspace":
			if i+1 >= len(args) || strings.HasPrefix(args[i+1], "--") {
				return options, errors.New("--workspace requires a slug")
			}
			options.Workspace = args[i+1]
			i++
		case "--service-account":
			if i+1 >= len(args) || strings.HasPrefix(args[i+1], "--") {
				return options, errors.New("--service-account requires a slug or id")
			}
			options.ServiceAccount = args[i+1]
			i++
		case "--all":
			options.All = true
		case "--origin":
			if i+1 >= len(args) || strings.HasPrefix(args[i+1], "--") {
				return options, errors.New("--origin requires a URL")
			}
			i++
		default:
			return options, fmt.Errorf("unknown service-account %s argument %q", command, args[i])
		}
	}
	if options.Workspace == "" {
		return options, fmt.Errorf("service-account %s requires --workspace", command)
	}
	if command != "list" && options.ServiceAccount == "" {
		return options, fmt.Errorf("service-account %s requires --service-account", command)
	}
	return options, nil
}

type serviceAccountGrantOptions struct {
	Workspace      string
	ServiceAccount string
	ScopePattern   string
	SecretPattern  string
	Actions        []string
	ApprovalMode   string
	ExpiresAt      string
}

func parseServiceAccountGrantArgs(args []string) (serviceAccountGrantOptions, error) {
	options := serviceAccountGrantOptions{ApprovalMode: "none"}
	for i := 0; i < len(args); i++ {
		if action, ok := servicePolicyAction(args[i]); ok {
			if !stringSliceContains(options.Actions, action) {
				options.Actions = append(options.Actions, action)
			}
			continue
		}
		switch args[i] {
		case "--workspace":
			if i+1 >= len(args) || strings.HasPrefix(args[i+1], "--") {
				return options, errors.New("--workspace requires a slug")
			}
			options.Workspace = args[i+1]
			i++
		case "--service-account":
			if i+1 >= len(args) || strings.HasPrefix(args[i+1], "--") {
				return options, errors.New("--service-account requires a slug or id")
			}
			options.ServiceAccount = args[i+1]
			i++
		case "--scope":
			if i+1 >= len(args) || strings.HasPrefix(args[i+1], "--") {
				return options, errors.New("--scope requires a value")
			}
			options.ScopePattern = args[i+1]
			i++
		case "--secret":
			if i+1 >= len(args) || strings.HasPrefix(args[i+1], "--") {
				return options, errors.New("--secret requires a value")
			}
			options.SecretPattern = args[i+1]
			i++
		case "--approval-mode":
			if i+1 >= len(args) || strings.HasPrefix(args[i+1], "--") {
				return options, errors.New("--approval-mode requires a value")
			}
			options.ApprovalMode = args[i+1]
			i++
		case "--expires-at":
			if i+1 >= len(args) || strings.HasPrefix(args[i+1], "--") {
				return options, errors.New("--expires-at requires a value")
			}
			expiresAt, err := normalizeFutureTimestamp(args[i+1], "--expires-at")
			if err != nil {
				return options, err
			}
			options.ExpiresAt = expiresAt
			i++
		case "--origin":
			if i+1 >= len(args) || strings.HasPrefix(args[i+1], "--") {
				return options, errors.New("--origin requires a URL")
			}
			i++
		default:
			return options, fmt.Errorf("unknown service-account grant argument %q", args[i])
		}
	}
	if options.Workspace == "" {
		return options, errors.New("service-account grant requires --workspace")
	}
	if options.ServiceAccount == "" {
		return options, errors.New("service-account grant requires --service-account")
	}
	if options.ScopePattern == "" {
		return options, errors.New("service-account grant requires --scope")
	}
	if options.SecretPattern == "" {
		return options, errors.New("service-account grant requires --secret")
	}
	if len(options.Actions) == 0 {
		return options, errors.New("service-account grant requires --inject-only, --read, --mount, --broker, --sign, or --proxy-local")
	}
	if options.ApprovalMode != "none" && options.ApprovalMode != "require-owner" {
		return options, errors.New("--approval-mode must be none or require-owner")
	}
	return options, nil
}

func servicePolicyAction(flag string) (string, bool) {
	switch flag {
	case "--read":
		return "read", true
	case "--inject-only":
		return "inject", true
	case "--mount":
		return "mount", true
	case "--broker":
		return "broker", true
	case "--sign":
		return "sign", true
	case "--proxy-local":
		return "proxy-local", true
	default:
		return "", false
	}
}

func (a App) serviceAccountCreate(st *store.FileStore, args []string) int {
	if err := st.RequireInitialized(); err != nil {
		return a.fail(err)
	}
	if err := rejectServiceAccountControlPlaneMutation(st); err != nil {
		return a.fail(err)
	}
	options, err := parseServiceAccountCreateArgs(args)
	if err != nil {
		return a.fail(err)
	}
	origin := loginOrigin(args, st)
	accessToken, err := ensureControlPlaneAccess(origin, st)
	if err != nil {
		return a.fail(err)
	}
	target, accessToken, err := a.remoteWorkspaceTarget(st, accessToken, options.Workspace)
	if err != nil {
		return a.fail(err)
	}
	account, err := createRemoteServiceAccount(st, st.State.ControlPlane.Origin, accessToken, target.ID, options.Slug, options.Name)
	if err != nil {
		return a.fail(err)
	}
	fmt.Fprintf(a.Out, "✓ Created service account %s in workspace %s (%s)\n", account.Slug, target.Slug, account.ID)
	return 0
}

func (a App) serviceAccountList(st *store.FileStore, args []string) int {
	if err := st.RequireInitialized(); err != nil {
		return a.fail(err)
	}
	options, err := parseServiceAccountSelectArgs(args, "list")
	if err != nil {
		return a.fail(err)
	}
	origin := loginOrigin(args, st)
	accessToken, err := ensureControlPlaneAccess(origin, st)
	if err != nil {
		return a.fail(err)
	}
	target, accessToken, err := a.remoteWorkspaceTarget(st, accessToken, options.Workspace)
	if err != nil {
		return a.fail(err)
	}
	accounts, err := listRemoteServiceAccounts(st, st.State.ControlPlane.Origin, target.ID, accessToken, options.All)
	if err != nil {
		return a.fail(err)
	}
	tw := tabwriter.NewWriter(a.Out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "SLUG\tNAME\tSTATUS\tID")
	for _, account := range accounts {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", account.Slug, account.Name, account.Status, account.ID)
	}
	_ = tw.Flush()
	return 0
}

func (a App) serviceAccountDisable(st *store.FileStore, args []string) int {
	if err := st.RequireInitialized(); err != nil {
		return a.fail(err)
	}
	if err := rejectServiceAccountControlPlaneMutation(st); err != nil {
		return a.fail(err)
	}
	options, err := parseServiceAccountSelectArgs(args, "disable")
	if err != nil {
		return a.fail(err)
	}
	origin := loginOrigin(args, st)
	accessToken, err := ensureControlPlaneAccess(origin, st)
	if err != nil {
		return a.fail(err)
	}
	target, accessToken, err := a.remoteWorkspaceTarget(st, accessToken, options.Workspace)
	if err != nil {
		return a.fail(err)
	}
	account, err := requireRemoteServiceAccount(st, st.State.ControlPlane.Origin, target.ID, accessToken, options.ServiceAccount)
	if err != nil {
		return a.fail(err)
	}
	disabled, err := disableRemoteServiceAccount(st, st.State.ControlPlane.Origin, accessToken, account.ID)
	if err != nil {
		return a.fail(err)
	}
	fmt.Fprintf(a.Out, "✓ Disabled service account %s in workspace %s\n", disabled.Slug, target.Slug)
	return 0
}

func (a App) serviceAccountGrant(st *store.FileStore, args []string) int {
	if err := st.RequireInitialized(); err != nil {
		return a.fail(err)
	}
	if err := rejectServiceAccountControlPlaneMutation(st); err != nil {
		return a.fail(err)
	}
	options, err := parseServiceAccountGrantArgs(args)
	if err != nil {
		return a.fail(err)
	}
	origin := loginOrigin(args, st)
	accessToken, err := ensureControlPlaneAccess(origin, st)
	if err != nil {
		return a.fail(err)
	}
	target, accessToken, err := a.remoteWorkspaceTarget(st, accessToken, options.Workspace)
	if err != nil {
		return a.fail(err)
	}
	scopePattern, err := workspacePrefixedPattern(workspacePathTarget{Slug: target.Slug, KnownSlugs: knownWorkspaceSlugs(st)}, options.ScopePattern, "service-account grant")
	if err != nil {
		return a.fail(err)
	}
	account, err := requireRemoteServiceAccount(st, st.State.ControlPlane.Origin, target.ID, accessToken, options.ServiceAccount)
	if err != nil {
		return a.fail(err)
	}
	policy, created, err := ensureRemoteServiceAccountPolicy(st, st.State.ControlPlane.Origin, accessToken, target.ID, account.Slug, serviceAccountGrantOptions{
		ScopePattern:  scopePattern,
		SecretPattern: options.SecretPattern,
		Actions:       options.Actions,
		ApprovalMode:  options.ApprovalMode,
		ExpiresAt:     options.ExpiresAt,
	})
	if err != nil {
		return a.fail(err)
	}
	if created {
		fmt.Fprintf(a.Out, "✓ Added service policy %s for service account %s on %s/%s\n", policy.ID, account.Slug, policy.ScopePattern, policy.SecretPattern)
	} else {
		fmt.Fprintf(a.Out, "✓ Service policy %s already grants service account %s on %s/%s\n", policy.ID, account.Slug, policy.ScopePattern, policy.SecretPattern)
	}
	return 0
}

func (a App) serviceAccountLogin(st *store.FileStore, args []string) int {
	if err := st.RequireInitialized(); err != nil {
		return a.fail(err)
	}
	options, err := parseServiceAccountSelectArgs(args, "login")
	if err != nil {
		return a.fail(err)
	}
	origin := loginOrigin(args, st)
	if err := validateControlPlaneOrigin(origin); err != nil {
		return a.fail(err)
	}
	device, err := st.ActiveDevice()
	if err != nil {
		return a.fail(err)
	}
	start, err := startServiceAccountDeviceCodeLogin(origin, options.Workspace, options.ServiceAccount, *device)
	if err != nil {
		return a.fail(err)
	}
	fmt.Fprintf(a.Out, "Open %s\n", start.VerificationURIComplete)
	fmt.Fprintf(a.Out, "Code: %s\n", start.UserCode)
	result, err := pollDeviceCodeLogin(st, origin, start)
	if err != nil {
		return a.fail(err)
	}
	if result.ServiceAccountID == "" || result.ServiceAccountSlug == "" {
		return a.fail(errors.New("control plane approved login without service account metadata"))
	}
	if err := st.LinkServiceAccountControlPlane(origin, result.OrgID, result.WorkspaceSlug, result.UserID, result.ServiceAccountID, result.ServiceAccountSlug, result.ServiceAccountName, result.DeviceID, device.ID, result.AccessToken, result.RefreshToken, result.ExpiresIn, result.RefreshExpiresAt); err != nil {
		return a.fail(err)
	}
	fmt.Fprintf(a.Out, "✓ Linked service account %s to workspace %s\n", result.ServiceAccountSlug, result.WorkspaceSlug)
	return 0
}

func (a App) logout(st *store.FileStore, args []string) int {
	if err := st.RequireInitialized(); err != nil {
		return a.fail(err)
	}
	if st.State.ControlPlane == nil {
		fmt.Fprintln(a.Out, "✓ Already logged out")
		return 0
	}
	refreshToken, err := st.ControlPlaneRefreshToken()
	if err == nil {
		_ = logoutDeviceSession(st, st.State.ControlPlane.Origin, refreshToken)
	}
	if err := st.ClearControlPlane(); err != nil {
		return a.fail(err)
	}
	fmt.Fprintln(a.Out, "✓ Logged out")
	return 0
}

func (a App) workspace(st *store.FileStore, args []string) int {
	if len(args) == 0 {
		return a.fail(errors.New("workspace subcommand required"))
	}
	if err := st.RequireInitialized(); err != nil {
		return a.fail(err)
	}
	if st.State.ControlPlane == nil {
		return a.fail(errors.New("asiri is not linked to a control plane"))
	}
	accessToken, err := ensureControlPlaneAccess(st.State.ControlPlane.Origin, st)
	if err != nil {
		return a.fail(err)
	}
	switch args[0] {
	case "list":
		workspaceResult, err := listRemoteWorkspaceOverview(st, st.State.ControlPlane.Origin, accessToken, true, false)
		if err != nil {
			return a.fail(err)
		}
		workspaces := workspaceResult.Organizations
		if st.State.ControlPlane.Source != "service-account" && workspaceResult.Secrets == nil {
			return a.fail(errors.New("control plane did not return workspace secret metadata"))
		}
		keySummaries := workspaceKeySummaries(st, workspaces, workspaceResult.Secrets, st.State.ControlPlane.WorkspaceID, st.State.ControlPlane.Source != "service-account")
		tw := tabwriter.NewWriter(a.Out, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "WORKSPACE\tROLE\tTHIS DEVICE\tACCOUNT WRITE\tKEYS\tNEXT\tID")
		hasUntrusted := false
		for _, workspace := range workspaces {
			if !workspaceDeviceTrusted(workspace, st.State.ControlPlane.WorkspaceID) {
				hasUntrusted = true
			}
			keySummary := keySummaries[workspace.Slug]
			accountWrite := boolPointerLabel(workspace.CanWrite)
			if st.State.ControlPlane.Source == "service-account" {
				accountWrite = "no"
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", workspace.Slug, workspaceRoleLabel(workspace, st.State.UserID), deviceTrustLabelForWorkspace(workspace, st.State.ControlPlane.WorkspaceID), accountWrite, keySummary.Keys, keySummary.Next, workspace.ID)
		}
		if err := tw.Flush(); err != nil {
			return a.fail(err)
		}
		if hasUntrusted {
			fmt.Fprintln(a.Out, "\nThis device controls pull and workspace-scoped push. Use the NEXT command to trust it where needed.")
		}
		return 0
	case "use":
		return a.fail(errors.New("workspace use has been removed; pass --workspace <slug> to workspace-scoped commands"))
	default:
		return a.fail(fmt.Errorf("unknown workspace command %q", args[0]))
	}
}

func (a App) setup(st *store.FileStore, args []string) int {
	if len(args) == 0 {
		return a.fail(errors.New("setup subcommand required"))
	}
	switch args[0] {
	case "doctor":
		return a.setupDoctor(st, args[1:])
	default:
		return a.fail(fmt.Errorf("unknown setup command %q", args[0]))
	}
}

type setupDoctorCheck struct {
	Name   string
	Status string
	Detail string
	Next   string
}

type setupDoctorWorkspace struct {
	Workspace string
	Role      string
	Device    string
	Keys      string
	Recovery  string
	Next      string
}

func (a App) setupDoctor(st *store.FileStore, args []string) int {
	workspaceFilters, remaining, err := splitWorkspaceFilters(args, "setup doctor")
	if err != nil {
		return a.fail(err)
	}
	if err := rejectUnknownArgs(remaining); err != nil {
		return a.fail(err)
	}
	if _, err := localWorkspaceFilterSet(workspaceFilters, "setup doctor"); err != nil {
		return a.fail(err)
	}

	fmt.Fprint(a.Out, "Asiri setup doctor\n\n")
	nextSteps := []string{}
	seenSteps := map[string]bool{}
	addStep := func(step string) {
		step = strings.TrimSpace(step)
		if step == "" || step == "-" || seenSteps[step] {
			return
		}
		seenSteps[step] = true
		nextSteps = append(nextSteps, step)
	}
	printChecks := func(rows []setupDoctorCheck) {
		tw := tabwriter.NewWriter(a.Out, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "CHECK\tSTATUS\tDETAIL\tNEXT")
		for _, row := range rows {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", row.Name, row.Status, printable(row.Detail), printable(row.Next))
			addStep(row.Next)
		}
		_ = tw.Flush()
	}
	printNextSteps := func() {
		if len(nextSteps) == 0 {
			fmt.Fprintln(a.Out, "\nNext steps:\n- Setup looks ready for visible trusted workspaces.")
			return
		}
		fmt.Fprintln(a.Out, "\nNext steps:")
		for _, step := range nextSteps {
			fmt.Fprintf(a.Out, "- %s\n", step)
		}
	}

	checks := []setupDoctorCheck{}
	if err := st.RequireInitialized(); err != nil {
		printChecks([]setupDoctorCheck{
			{Name: "local vault", Status: "missing", Detail: err.Error(), Next: "asiri init --device <name>"},
			{Name: "control plane", Status: "skipped", Detail: "local vault is required first", Next: "asiri login"},
		})
		printNextSteps()
		return 0
	}
	device, deviceErr := st.ActiveDevice()
	if deviceErr != nil {
		checks = append(checks, setupDoctorCheck{Name: "local device", Status: "missing", Detail: deviceErr.Error(), Next: "asiri device enroll --name <name>"})
		printChecks(checks)
		printNextSteps()
		return 0
	}
	checks = append(checks, setupDoctorCheck{Name: "local vault", Status: "ok", Detail: "initialized", Next: "-"})
	checks = append(checks, setupDoctorCheck{Name: "local device", Status: "ok", Detail: device.Name, Next: "-"})

	if st.State.ControlPlane == nil {
		checks = append(checks, setupDoctorCheck{Name: "control plane", Status: "missing", Detail: "not linked", Next: "asiri login"})
		printChecks(checks)
		printNextSteps()
		return 0
	}
	checks = append(checks, setupDoctorCheck{Name: "control plane", Status: "linked", Detail: st.State.ControlPlane.Origin, Next: "-"})
	if st.State.ControlPlane.Source == "service-account" {
		checks = append(checks, setupDoctorCheck{Name: "session", Status: "service-account", Detail: "read-only service account session", Next: "-"})
		printChecks(checks)
		printNextSteps()
		return 0
	}

	accessToken, err := ensureControlPlaneAccess(st.State.ControlPlane.Origin, st)
	if err != nil {
		checks = append(checks, setupDoctorCheck{Name: "session", Status: "failed", Detail: err.Error(), Next: "asiri login --force"})
		printChecks(checks)
		printNextSteps()
		return 0
	}
	checks = append(checks, setupDoctorCheck{Name: "session", Status: "ok", Detail: st.State.ControlPlane.WorkspaceSlug, Next: "-"})
	printChecks(checks)

	workspaceResult, err := listRemoteWorkspaceOverview(st, st.State.ControlPlane.Origin, accessToken, true, false)
	if err != nil {
		fmt.Fprintf(a.Out, "\nWorkspace checks unavailable: %s\n", err)
		addStep("asiri login --force")
		printNextSteps()
		return 0
	}
	workspaces := workspaceResult.Organizations
	filterSet := map[string]bool{}
	for _, slug := range workspaceFilters {
		filterSet[slug] = true
	}
	targets := make([]remoteWorkspaceResponse, 0, len(workspaces))
	foundFilters := map[string]bool{}
	for _, workspace := range workspaces {
		if len(filterSet) > 0 && !filterSet[workspace.Slug] {
			continue
		}
		targets = append(targets, workspace)
		if len(filterSet) > 0 {
			foundFilters[workspace.Slug] = true
		}
	}
	if len(filterSet) > 0 {
		missing := make([]string, 0)
		for slug := range filterSet {
			if !foundFilters[slug] {
				missing = append(missing, slug)
			}
		}
		if len(missing) > 0 {
			sort.Strings(missing)
			return a.fail(fmt.Errorf("workspace %s is not visible", strings.Join(missing, ", ")))
		}
	}

	remoteSecrets := workspaceResult.Secrets
	secretsKnown := remoteSecrets != nil
	if !secretsKnown {
		fmt.Fprintln(a.Err, "asiri: remote key coverage unavailable: control plane did not return workspace secret metadata")
	}
	keySummaries := workspaceKeySummaries(st, targets, remoteSecrets, st.State.ControlPlane.WorkspaceID, secretsKnown)
	rows := make([]setupDoctorWorkspace, 0, len(targets))
	for _, workspace := range targets {
		keySummary := keySummaries[workspace.Slug]
		recoveryStatus := a.setupDoctorRecoveryStatus(st, accessToken, workspace)
		next := setupDoctorWorkspaceNext(st, workspace, st.State.ControlPlane.WorkspaceID, keySummary.Keys, recoveryStatus)
		rows = append(rows, setupDoctorWorkspace{
			Workspace: workspace.Slug,
			Role:      workspaceRoleLabel(workspace, st.State.UserID),
			Device:    deviceTrustLabelForWorkspace(workspace, st.State.ControlPlane.WorkspaceID),
			Keys:      keySummary.Keys,
			Recovery:  recoveryStatus,
			Next:      next,
		})
		addStep(next)
	}

	fmt.Fprintln(a.Out, "\nWorkspaces:")
	tw := tabwriter.NewWriter(a.Out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "WORKSPACE\tROLE\tTHIS DEVICE\tKEYS\tRECOVERY\tNEXT")
	for _, row := range rows {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", row.Workspace, row.Role, row.Device, row.Keys, row.Recovery, row.Next)
	}
	if err := tw.Flush(); err != nil {
		return a.fail(err)
	}
	printNextSteps()
	return 0
}

func (a App) setupDoctorRecoveryStatus(st *store.FileStore, accessToken string, workspace remoteWorkspaceResponse) string {
	if !workspaceDeviceTrusted(workspace, st.State.ControlPlane.WorkspaceID) {
		return "skipped"
	}
	if st.State.Recoveries != nil {
		if recovery, ok := st.State.Recoveries[workspace.ID]; ok && recovery.RecipientID != "" {
			return "configured"
		}
	}
	if workspace.ID != st.State.ControlPlane.WorkspaceID {
		return "unknown"
	}
	recovery, err := getActiveRemoteRecoveryRecipient(st, st.State.ControlPlane.Origin, workspace.ID, accessToken)
	if err != nil {
		return "failed"
	}
	if recovery == nil {
		return "not-configured"
	}
	return "configured"
}

func setupDoctorWorkspaceNext(st *store.FileStore, workspace remoteWorkspaceResponse, activeWorkspaceID, keys, recovery string) string {
	if st.State.ControlPlane != nil && st.State.ControlPlane.Source == "service-account" {
		return "-"
	}
	if !workspaceDeviceTrusted(workspace, activeWorkspaceID) {
		if workspaceCanApproveDevice(workspace) {
			return deviceTrustCommand(st, workspace.Slug)
		}
		return "ask owner to approve this device"
	}
	switch keys {
	case "unknown":
		return fmt.Sprintf("asiri setup doctor --workspace %s", workspace.Slug)
	case "needs rewrap", "needs cleanup":
		return workspaceNextAction(st, workspace, activeWorkspaceID, keys)
	case "unwrapped":
		if recovery == "configured" {
			return fmt.Sprintf("asiri recovery restore --workspace %s --key-file <path>", workspace.Slug)
		}
		return fmt.Sprintf("use an existing trusted device: asiri rewrap --workspace %s", workspace.Slug)
	}
	switch recovery {
	case "unknown":
		return fmt.Sprintf("asiri recovery status --workspace %s", workspace.Slug)
	case "not-configured":
		if workspace.Role == "owner" {
			return fmt.Sprintf("asiri recovery setup --workspace %s --output-file <path>", workspace.Slug)
		}
		return "ask owner to configure recovery"
	case "failed":
		return fmt.Sprintf("asiri recovery status --workspace %s", workspace.Slug)
	}
	return "-"
}

func (a App) push(st *store.FileStore, args []string) int {
	if err := st.RequireInitialized(); err != nil {
		return a.fail(err)
	}
	if st.State.ControlPlane == nil {
		return a.fail(errors.New("asiri is not linked to a control plane"))
	}
	if err := rejectServiceAccountControlPlaneMutation(st); err != nil {
		return a.fail(err)
	}
	pushOptions, err := parsePushArgs(args)
	if err != nil {
		return a.fail(err)
	}
	accessToken, err := ensureControlPlaneAccess(st.State.ControlPlane.Origin, st)
	if err != nil {
		return a.fail(err)
	}
	var target remoteWorkspaceResponse
	var restoreDryRunState func()
	if pushOptions.DryRun {
		target, accessToken, restoreDryRunState, err = a.pushWorkspaceTargetDryRun(st, accessToken, pushOptions.Workspace)
		if restoreDryRunState != nil {
			defer restoreDryRunState()
		}
	} else {
		target, accessToken, err = a.pushWorkspaceTarget(st, accessToken, pushOptions.Workspace)
	}
	if err != nil {
		return a.fail(err)
	}
	refs := st.ActiveSecretRefs()
	if len(refs) == 0 {
		fmt.Fprintln(a.Out, "No local active secrets to push")
		return 0
	}
	selectedRefs, err := selectPushRefs(st, refs, target, pushOptions)
	if err != nil {
		return a.fail(err)
	}
	if len(selectedRefs) == 0 {
		return a.fail(fmt.Errorf("no local active secrets under workspace %s; local prefixes are %s", target.Slug, strings.Join(localSecretWorkspacePrefixes(refs), ", ")))
	}
	if binding, ok := st.RemoteBindingForPrefix(target.Slug); ok && binding.WorkspaceID != target.ID {
		return a.fail(fmt.Errorf("workspace prefix %s is bound to another control-plane workspace", target.Slug))
	}
	options, err := remoteWriteOptions(st, st.State.ControlPlane.Origin, accessToken, selectedRefs)
	if err != nil {
		return a.fail(err)
	}
	if !options.ActiveWorkspace.CanWrite {
		return a.fail(fmt.Errorf("workspace %s cannot write %s", target.Slug, fullPathList(options.ActiveWorkspace.Paths)))
	}
	if pushOptions.DryRun {
		if st.State.RemoteBindings == nil {
			st.State.RemoteBindings = map[string]asiri.RemoteWorkspaceBinding{}
		}
		st.State.RemoteBindings[target.Slug] = asiri.RemoteWorkspaceBinding{
			WorkspaceID:   target.ID,
			WorkspaceSlug: target.Slug,
			BoundAt:       time.Now().UTC(),
		}
	} else {
		if err := st.BindWorkspacePrefix(target.Slug, target.ID, target.Slug); err != nil {
			return a.fail(err)
		}
	}
	recovery, err := getActiveRemoteRecoveryRecipient(st, st.State.ControlPlane.Origin, target.ID, accessToken)
	if err != nil {
		return a.fail(err)
	}
	versions, err := st.RemoteSecretVersionsForRefsWithRecovery(target.Slug, selectedRefs, recovery)
	if err != nil {
		return a.fail(err)
	}
	devices, err := listRemoteDevices(st, st.State.ControlPlane.Origin, target.ID, accessToken, false)
	if err != nil {
		return a.fail(fmt.Errorf("trusted device discovery failed; refusing to push incomplete wrapped-key coverage: %w", err))
	}
	if err := addTrustedDeviceWrappedKeysToVersions(st, versions, devices); err != nil {
		return a.fail(err)
	}
	recoveryRecipientID := ""
	if recovery != nil {
		recoveryRecipientID = recovery.RecipientID
	}
	remoteSecrets, err := listRemoteSecrets(st, st.State.ControlPlane.Origin, target.ID, accessToken, recoveryRecipientID, false)
	if err != nil {
		return a.fail(err)
	}
	remoteMetadata, status, err := listRemoteSecretMetadata(st, st.State.ControlPlane.Origin, target.ID, accessToken, true)
	if err != nil {
		return a.fail(err)
	}
	if status != http.StatusNotFound {
		remoteSecrets = mergeRemoteSecretRecords(remoteSecrets, remoteMetadata)
	}
	reconciled, err := reconcilePushVersions(versions, remoteSecrets)
	if pushOptions.DryRun {
		printPushDryRun(a.Out, target.Slug, reconciled)
		if err != nil {
			return a.fail(err)
		}
		return 0
	}
	if err != nil {
		return a.fail(err)
	}
	for _, version := range reconciled.Upload {
		if err := postJSONBearer(st, st.State.ControlPlane.Origin+"/v1/secrets", accessToken, version, nil); err != nil {
			return a.fail(err)
		}
	}
	rewrappedKeys := 0
	rewrappedSecrets := 0
	for _, candidate := range reconciled.Rewrap {
		if err := addRemoteWrappedKeys(st, st.State.ControlPlane.Origin, candidate.SecretID, accessToken, candidate.Missing, false); err != nil {
			return a.fail(err)
		}
		rewrappedSecrets++
		rewrappedKeys += len(candidate.Missing)
	}
	if recovery != nil {
		if st.State.Recoveries == nil {
			st.State.Recoveries = map[string]asiri.RecoveryConfig{}
		}
		nextRecovery := *recovery
		if existing, ok := st.State.Recoveries[target.ID]; ok && existing.RecipientID == recovery.RecipientID {
			nextRecovery.WrappedSecretCount = existing.WrappedSecretCount
			nextRecovery.LastWrappedAt = existing.LastWrappedAt
		}
		if pushOptions.HasTargets() && nextRecovery.WrappedSecretCount < len(versions) {
			nextRecovery.WrappedSecretCount = len(versions)
			nextRecovery.LastWrappedAt = time.Now().UTC()
		}
		st.State.Recoveries[target.ID] = nextRecovery
		if !pushOptions.HasTargets() {
			if err := st.MarkRecoveryWrapped(target.Slug, len(versions)); err != nil {
				return a.fail(err)
			}
		}
	} else if st.ActiveRecovery() != nil {
		delete(st.State.Recoveries, target.ID)
	}
	st.Audit(st.State.UserID, "control_plane_push", "allowed", "", "", "pushed encrypted local secret versions", map[string]string{"count": fmt.Sprintf("%d", len(reconciled.Upload)), "workspace": target.Slug, "skipped": fmt.Sprintf("%d", reconciled.SkippedExisting+reconciled.SkippedOlder), "rewrappedKeys": fmt.Sprintf("%d", rewrappedKeys)})
	if err := st.Save(); err != nil {
		return a.fail(err)
	}
	if len(reconciled.Upload) == 0 {
		fmt.Fprintf(a.Out, "No new local secret versions to push to workspace %s", target.Slug)
		if reconciled.SkippedExisting+reconciled.SkippedOlder > 0 {
			fmt.Fprintf(a.Out, " (%d skipped)", reconciled.SkippedExisting+reconciled.SkippedOlder)
		}
		fmt.Fprintln(a.Out)
	} else if len(selectedRefs) != len(refs) || pushOptions.HasTargets() {
		fmt.Fprintf(a.Out, "✓ Pushed %d encrypted secret version(s) to workspace %s; %d skipped\n", len(reconciled.Upload), target.Slug, reconciled.SkippedExisting+reconciled.SkippedOlder)
	} else {
		fmt.Fprintf(a.Out, "✓ Pushed %d encrypted secret version(s) to workspace %s; %d skipped\n", len(reconciled.Upload), target.Slug, reconciled.SkippedExisting+reconciled.SkippedOlder)
	}
	if rewrappedKeys > 0 {
		fmt.Fprintf(a.Out, "✓ Rewrapped %d trusted-device key(s) across %d existing secret version(s)\n", rewrappedKeys, rewrappedSecrets)
	}
	return 0
}

type pushOptions struct {
	Workspace string
	Scopes    []string
	Secrets   []string
	Version   int
	DryRun    bool
}

func (o pushOptions) HasTargets() bool {
	return len(o.Scopes) > 0 || len(o.Secrets) > 0 || o.Version > 0
}

func parsePushArgs(args []string) (pushOptions, error) {
	workspaceArg, remaining, err := splitWorkspaceFlag(args, "push", true)
	if err != nil {
		return pushOptions{}, err
	}
	options := pushOptions{Workspace: workspaceArg}
	for i := 0; i < len(remaining); i++ {
		arg := remaining[i]
		switch arg {
		case "--yes":
			// Backward-compatible no-op for older scripts.
		case "--dry-run":
			options.DryRun = true
		case "--scope":
			if i+1 >= len(remaining) || strings.HasPrefix(remaining[i+1], "-") {
				return pushOptions{}, errors.New("push --scope requires a scope")
			}
			options.Scopes = append(options.Scopes, remaining[i+1])
			i++
		case "--secret":
			if i+1 >= len(remaining) || strings.HasPrefix(remaining[i+1], "-") {
				return pushOptions{}, errors.New("push --secret requires scope/name")
			}
			options.Secrets = append(options.Secrets, remaining[i+1])
			i++
		case "--version":
			if i+1 >= len(remaining) || strings.HasPrefix(remaining[i+1], "-") {
				return pushOptions{}, errors.New("push --version requires a positive integer")
			}
			version, err := strconv.Atoi(remaining[i+1])
			if err != nil || version <= 0 {
				return pushOptions{}, errors.New("push --version requires a positive integer")
			}
			options.Version = version
			i++
		default:
			if strings.HasPrefix(arg, "-") {
				return pushOptions{}, fmt.Errorf("unknown option %q", arg)
			}
			return pushOptions{}, fmt.Errorf("unexpected push argument %q; use --scope or --secret", arg)
		}
	}
	if options.Version > 0 && (len(options.Secrets) != 1 || len(options.Scopes) != 0) {
		return pushOptions{}, errors.New("push --version requires exactly one --secret and no --scope")
	}
	return options, nil
}

func selectPushRefs(st *store.FileStore, refs []store.LocalSecretRef, target remoteWorkspaceResponse, options pushOptions) ([]store.LocalSecretRef, error) {
	if !options.HasTargets() {
		selected := make([]store.LocalSecretRef, 0, len(refs))
		for _, ref := range refs {
			if store.WorkspacePrefix(ref.Scope) == target.Slug {
				selected = append(selected, ref)
			}
		}
		return selected, nil
	}
	pathTarget := workspacePathTarget{Slug: target.Slug, KnownSlugs: knownWorkspaceSlugs(st)}
	selected := map[string]store.LocalSecretRef{}
	addRef := func(ref store.LocalSecretRef) {
		key := store.SecretKey(ref.Scope, ref.Name)
		selected[key] = ref
	}
	for _, shortScope := range options.Scopes {
		scope, err := workspacePrefixedScope(pathTarget, shortScope, "push")
		if err != nil {
			return nil, err
		}
		for _, ref := range refs {
			if ref.Scope == scope {
				addRef(ref)
			}
		}
	}
	for _, shortSecret := range options.Secrets {
		fullPath, err := workspacePrefixedPath(pathTarget, shortSecret, "push")
		if err != nil {
			return nil, err
		}
		scope, name, err := store.ParseSecretPath(fullPath)
		if err != nil {
			return nil, err
		}
		secret, ok := st.State.Secrets[store.SecretKey(scope, name)]
		if !ok {
			return nil, fmt.Errorf("local secret %s not found", fullPath)
		}
		version := secret.ActiveVersion
		if options.Version > 0 {
			version = options.Version
		}
		addRef(store.LocalSecretRef{Scope: scope, Name: name, Version: version})
	}
	selectedRefs := make([]store.LocalSecretRef, 0, len(selected))
	for _, ref := range selected {
		selectedRefs = append(selectedRefs, ref)
	}
	sort.Slice(selectedRefs, func(i, j int) bool {
		left := store.SecretKey(selectedRefs[i].Scope, selectedRefs[i].Name)
		right := store.SecretKey(selectedRefs[j].Scope, selectedRefs[j].Name)
		if left == right {
			return selectedRefs[i].Version < selectedRefs[j].Version
		}
		return left < right
	})
	if len(selectedRefs) == 0 {
		return nil, errors.New("no local active secrets matched push target")
	}
	return selectedRefs, nil
}

type pushReconcileResult struct {
	Upload          []store.RemoteSecretVersion
	Rewrap          []pushRewrapCandidate
	SkippedExisting int
	SkippedOlder    int
	Conflicts       []string
}

type pushRewrapCandidate struct {
	SecretID string
	Missing  []store.RemoteWrappedKey
}

func reconcilePushVersions(local []store.RemoteSecretVersion, remote []remoteSecretRecord) (pushReconcileResult, error) {
	result := pushReconcileResult{Upload: []store.RemoteSecretVersion{}}
	byVersion := map[string]remoteSecretRecord{}
	maxVersion := map[string]int{}
	for _, item := range remote {
		key := store.SecretKey(item.Scope, item.Name)
		if item.Version > maxVersion[key] {
			maxVersion[key] = item.Version
		}
		byVersion[pushVersionKey(item.Scope, item.Name, item.Version)] = item
	}
	conflicts := []string{}
	for _, item := range local {
		key := store.SecretKey(item.Scope, item.Name)
		if existing, ok := byVersion[pushVersionKey(item.Scope, item.Name, item.Version)]; ok {
			if existing.Status == "active" && remoteSecretEnvelopeComparable(existing) && remoteSecretEnvelopeMatches(item, existing) {
				missing := missingRemoteWrappedKeys(item.WrappedKeys, existing.WrappedKeys)
				if len(missing) == 0 {
					result.SkippedExisting++
					continue
				}
				if allDeviceWrappedKeys(missing) {
					result.Rewrap = append(result.Rewrap, pushRewrapCandidate{SecretID: existing.ID, Missing: missing})
					result.SkippedExisting++
					continue
				}
			}
			conflicts = append(conflicts, fmt.Sprintf("%s v%d", key, item.Version))
			continue
		}
		if maxVersion[key] > item.Version {
			result.SkippedOlder++
			continue
		}
		result.Upload = append(result.Upload, item)
	}
	sort.Strings(conflicts)
	result.Conflicts = conflicts
	if len(conflicts) > 0 {
		return result, fmt.Errorf("remote secret version conflict for %s; pull first or rotate locally to a newer version", strings.Join(conflicts, ", "))
	}
	return result, nil
}

func addTrustedDeviceWrappedKeysToVersions(st *store.FileStore, versions []store.RemoteSecretVersion, devices []remoteDeviceResponse) error {
	targets := make([]remoteDeviceResponse, 0)
	for _, device := range devices {
		if device.Status == "trusted" && device.ID != "" && device.EncryptionPublicKey != "" {
			targets = append(targets, device)
		}
	}
	sort.Slice(targets, func(i, j int) bool {
		return targets[i].ID < targets[j].ID
	})
	for i := range versions {
		for _, device := range targets {
			if remoteVersionHasRecipient(versions[i], device.ID) {
				continue
			}
			wrapped, err := st.RemoteWrappedKeyForSecretVersionPublicKey(versions[i].Scope, versions[i].Name, versions[i].Version, device.ID, device.EncryptionPublicKey)
			if err != nil {
				return err
			}
			versions[i].WrappedKeys = append(versions[i].WrappedKeys, wrapped)
		}
	}
	return nil
}

func remoteVersionHasRecipient(version store.RemoteSecretVersion, deviceID string) bool {
	for _, key := range version.WrappedKeys {
		if key.RecipientType == "device" && key.RecipientID == deviceID {
			return true
		}
	}
	return false
}

func pushVersionKey(scope, name string, version int) string {
	return store.SecretKey(scope, name) + "\x00" + strconv.Itoa(version)
}

func listOutputRowKey(scope, name string, version int, includeInactive bool) string {
	if includeInactive {
		return pushVersionKey(scope, name, version)
	}
	return store.SecretKey(scope, name)
}

func remoteSecretEnvelopeMatches(local store.RemoteSecretVersion, remote remoteSecretRecord) bool {
	return local.Algorithm == remote.Algorithm &&
		local.Nonce == remote.Nonce &&
		local.Ciphertext == remote.Ciphertext &&
		local.AAD == remote.AAD
}

func remoteSecretEnvelopeComparable(remote remoteSecretRecord) bool {
	return remote.Algorithm != "" && remote.Nonce != "" && remote.Ciphertext != "" && remote.AAD != ""
}

func remoteSecretWrappedKeysMatch(local []store.RemoteWrappedKey, remote []store.RemoteWrappedKey) bool {
	return len(missingRemoteWrappedKeys(local, remote)) == 0
}

func missingRemoteWrappedKeys(local []store.RemoteWrappedKey, remote []store.RemoteWrappedKey) []store.RemoteWrappedKey {
	remoteKeys := map[string]bool{}
	for _, key := range remote {
		remoteKeys[remoteWrappedKeyIdentity(key)] = true
	}
	missing := []store.RemoteWrappedKey{}
	for _, key := range local {
		if !remoteKeys[remoteWrappedKeyIdentity(key)] {
			missing = append(missing, key)
		}
	}
	return missing
}

func allDeviceWrappedKeys(keys []store.RemoteWrappedKey) bool {
	for _, key := range keys {
		if key.RecipientType != "device" {
			return false
		}
	}
	return true
}

func remoteWrappedKeyIdentity(key store.RemoteWrappedKey) string {
	return key.RecipientType + "\x00" + key.RecipientID + "\x00" + key.WrapAlgorithm
}

func printPushDryRun(out io.Writer, workspace string, result pushReconcileResult) {
	fmt.Fprintf(out, "Would push %d encrypted secret version(s) to workspace %s", len(result.Upload), workspace)
	skipped := result.SkippedExisting + result.SkippedOlder
	if skipped > 0 {
		fmt.Fprintf(out, "; %d would be skipped", skipped)
	}
	fmt.Fprintln(out)
	rewrappedKeys := 0
	for _, candidate := range result.Rewrap {
		rewrappedKeys += len(candidate.Missing)
	}
	if rewrappedKeys > 0 {
		fmt.Fprintf(out, "Would rewrap %d trusted-device key(s) across %d existing secret version(s)\n", rewrappedKeys, len(result.Rewrap))
	}
	if len(result.Conflicts) > 0 {
		fmt.Fprintf(out, "Conflicts (pull first or rotate locally to a newer version):\n")
		for _, c := range result.Conflicts {
			fmt.Fprintf(out, "  %s\n", c)
		}
	}
}

func (a App) pull(st *store.FileStore, args []string) int {
	if err := st.RequireInitialized(); err != nil {
		return a.fail(err)
	}
	if st.State.ControlPlane == nil {
		return a.fail(errors.New("asiri is not linked to a control plane"))
	}
	options, err := parsePullArgs(args)
	if err != nil {
		return a.fail(err)
	}
	accessToken, err := ensureControlPlaneAccess(st.State.ControlPlane.Origin, st)
	if err != nil {
		return a.fail(err)
	}
	workspaces, err := listRemoteWorkspaces(st, st.State.ControlPlane.Origin, accessToken)
	if err != nil {
		return a.fail(err)
	}
	targets, results := pullTargets(st.State.ControlPlane, workspaces, options)
	currentAccessToken := accessToken
	activeWorkspaceID := st.State.ControlPlane.WorkspaceID
	for _, target := range targets {
		if !pullWorkspaceCanPull(target.Workspace, activeWorkspaceID) {
			result := "skipped"
			if target.Explicit {
				result = "failed"
			}
			results = append(results, pullResult{Workspace: target.Workspace.Slug, Result: result, Note: "this device is not trusted for this workspace"})
			continue
		}
		imported, remote, token, err := a.pullOneWorkspace(st, currentAccessToken, target.Workspace, options.Force)
		if token != "" {
			currentAccessToken = token
		}
		if err != nil {
			results = append(results, pullResult{Workspace: target.Workspace.Slug, Result: "failed", Note: err.Error()})
			continue
		}
		results = append(results, pullResult{Workspace: target.Workspace.Slug, Result: "pulled", Imported: imported, Remote: remote})
	}
	writePullResults(a.Out, results)
	return 0
}

func (a App) pullOneWorkspace(st *store.FileStore, accessToken string, workspace remoteWorkspaceResponse, force bool) (int, int, string, error) {
	imported, remote, nextToken, _, err := a.pullOneWorkspaceWithBundle(st, accessToken, workspace, force)
	return imported, remote, nextToken, err
}

func (a App) pullOneWorkspaceWithBundle(st *store.FileStore, accessToken string, workspace remoteWorkspaceResponse, force bool) (int, int, string, syncBundleResponse, error) {
	nextToken := ""
	if workspace.ID != st.State.ControlPlane.WorkspaceID {
		if st.State.ControlPlane.Source == "service-account" {
			return 0, 0, "", syncBundleResponse{}, errors.New("service account sessions cannot switch workspace")
		}
		device, err := st.ActiveDevice()
		if err != nil {
			return 0, 0, "", syncBundleResponse{}, err
		}
		result, err := switchRemoteWorkspace(st, st.State.ControlPlane.Origin, accessToken, workspace.ID, *device)
		if err != nil {
			return 0, 0, "", syncBundleResponse{}, err
		}
		if err := st.LinkControlPlaneForDevice(st.State.ControlPlane.Origin, result.OrgID, result.WorkspaceSlug, result.UserID, result.DeviceID, device.ID, result.AccessToken, result.RefreshToken, result.ExpiresIn, result.RefreshExpiresAt); err != nil {
			return 0, 0, "", syncBundleResponse{}, err
		}
		nextToken = result.AccessToken
		accessToken = result.AccessToken
	}
	var bundle syncBundleResponse
	endpoint := fmt.Sprintf("%s/v1/sync?orgId=%s&deviceId=%s", strings.TrimRight(st.State.ControlPlane.Origin, "/"), url.QueryEscape(st.State.ControlPlane.WorkspaceID), url.QueryEscape(st.State.ControlPlane.DeviceID))
	if err := getJSONBearer(st, endpoint, accessToken, &bundle); err != nil {
		return 0, 0, nextToken, bundle, err
	}
	imported, err := a.importRemoteVersions(st, bundle.EncryptedSecrets, force)
	if err != nil {
		var partial *store.RemoteImportPartialError
		if !errors.As(err, &partial) {
			return 0, 0, nextToken, bundle, err
		}
		if imported == 0 {
			return 0, 0, nextToken, bundle, err
		}
		fmt.Fprintf(a.Err, "Warning: %s\n", partial.Error())
	}
	importServiceAccountSyncPolicies(st, bundle.Policies)
	st.Audit(st.State.UserID, "control_plane_sync", "allowed", "", "", "fetched encrypted pull bundle", map[string]string{"secrets": fmt.Sprintf("%d", len(bundle.EncryptedSecrets)), "workspace": st.State.ControlPlane.WorkspaceSlug})
	if err := st.Save(); err != nil {
		return 0, 0, nextToken, bundle, err
	}
	return imported, len(bundle.EncryptedSecrets), nextToken, bundle, nil
}

type pullOptions struct {
	Force      bool
	Workspaces []string
}

type pullTarget struct {
	Workspace remoteWorkspaceResponse
	Explicit  bool
}

type pullResult struct {
	Workspace string
	Result    string
	Imported  int
	Remote    int
	Note      string
}

func parsePullArgs(args []string) (pullOptions, error) {
	var options pullOptions
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--force":
			options.Force = true
		case "--workspace", "-w":
			if i+1 >= len(args) || strings.HasPrefix(args[i+1], "-") {
				return options, errors.New("pull --workspace requires a workspace slug")
			}
			options.Workspaces = append(options.Workspaces, args[i+1])
			i++
		default:
			return options, fmt.Errorf("unknown pull option %q", args[i])
		}
	}
	return options, nil
}

func pullTargets(active *asiri.ControlPlaneLink, workspaces []remoteWorkspaceResponse, options pullOptions) ([]pullTarget, []pullResult) {
	if active == nil {
		return nil, []pullResult{{Workspace: "-", Result: "failed", Note: "asiri is not linked to a control plane"}}
	}
	if active.Source == "service-account" {
		activeWorkspace := remoteWorkspaceResponse{ID: active.WorkspaceID, Slug: active.WorkspaceSlug, CurrentDeviceTrusted: boolPtr(true), CanPull: boolPtr(true)}
		for _, workspace := range workspaces {
			if workspace.ID == active.WorkspaceID || workspace.Slug == active.WorkspaceSlug {
				activeWorkspace = workspace
				break
			}
		}
		if len(options.Workspaces) == 0 {
			return []pullTarget{{Workspace: activeWorkspace}}, nil
		}
		targets := []pullTarget{}
		results := []pullResult{}
		for _, requested := range options.Workspaces {
			if requested != active.WorkspaceSlug && requested != active.WorkspaceID {
				results = append(results, pullResult{Workspace: requested, Result: "failed", Note: "service account sessions cannot switch workspace"})
				continue
			}
			targets = append(targets, pullTarget{Workspace: activeWorkspace, Explicit: true})
		}
		return targets, results
	}
	if len(options.Workspaces) > 0 {
		targets := make([]pullTarget, 0, len(options.Workspaces))
		results := []pullResult{}
		for _, requested := range options.Workspaces {
			if active.Source == "service-account" && requested != active.WorkspaceSlug {
				results = append(results, pullResult{Workspace: requested, Result: "failed", Note: "service account sessions cannot switch workspace"})
				continue
			}
			workspace, ok := findWorkspace(workspaces, requested)
			if !ok {
				results = append(results, pullResult{Workspace: requested, Result: "failed", Note: "workspace is not visible"})
				continue
			}
			targets = append(targets, pullTarget{Workspace: workspace, Explicit: true})
		}
		return targets, results
	}
	if active.Source == "service-account" {
		if workspace, ok := findWorkspace(workspaces, active.WorkspaceSlug); ok {
			return []pullTarget{{Workspace: workspace}}, nil
		}
		return []pullTarget{{Workspace: remoteWorkspaceResponse{ID: active.WorkspaceID, Slug: active.WorkspaceSlug, CanPull: boolPtr(true), CurrentDeviceTrusted: boolPtr(true)}}}, nil
	}
	targets := make([]pullTarget, 0, len(workspaces))
	for _, workspace := range workspaces {
		targets = append(targets, pullTarget{Workspace: workspace})
	}
	return targets, nil
}

func findWorkspace(workspaces []remoteWorkspaceResponse, value string) (remoteWorkspaceResponse, bool) {
	for _, workspace := range workspaces {
		if workspace.Slug == value {
			return workspace, true
		}
	}
	return remoteWorkspaceResponse{}, false
}

func pullWorkspaceCanPull(workspace remoteWorkspaceResponse, activeWorkspaceID string) bool {
	return workspaceDeviceTrusted(workspace, activeWorkspaceID)
}

func boolPtr(value bool) *bool {
	return &value
}

type workspaceKeySummary struct {
	Keys string
	Next string
}

func workspaceKeySummaries(st *store.FileStore, workspaces []remoteWorkspaceResponse, secrets []visibleRemoteSecretRecord, activeWorkspaceID string, secretsKnown bool) map[string]workspaceKeySummary {
	type counts struct {
		Total              int
		Missing            int
		Repairable         int
		RemoteOnlyUnusable int
		Unknown            int
	}
	byWorkspace := map[string]counts{}
	for _, secret := range secrets {
		item := byWorkspace[secret.WorkspaceSlug]
		item.Total++
		if secret.WrappedToCurrentDevice == nil {
			item.Unknown++
		} else if !*secret.WrappedToCurrentDevice {
			item.Missing++
			if localSecretVersionExists(st, secret.Scope, secret.Name, secret.Version) {
				item.Repairable++
			} else if !localActiveSecretExists(st, secret.Scope, secret.Name) {
				item.RemoteOnlyUnusable++
			}
		}
		byWorkspace[secret.WorkspaceSlug] = item
	}
	summaries := map[string]workspaceKeySummary{}
	for _, workspace := range workspaces {
		keys := "unknown"
		if workspaceDeviceTrusted(workspace, activeWorkspaceID) && secretsKnown {
			item := byWorkspace[workspace.Slug]
			switch {
			case item.Total == 0:
				keys = "no secrets"
			case item.Unknown > 0:
				keys = "unknown"
			case item.Repairable > 0:
				keys = "needs rewrap"
			case item.Missing > 0:
				keys = "unwrapped"
			default:
				keys = "ready"
			}
		}
		summaries[workspace.Slug] = workspaceKeySummary{Keys: keys, Next: workspaceNextAction(st, workspace, activeWorkspaceID, keys)}
	}
	return summaries
}

func workspaceNextAction(st *store.FileStore, workspace remoteWorkspaceResponse, activeWorkspaceID, keys string) string {
	if st.State.ControlPlane != nil && st.State.ControlPlane.Source == "service-account" {
		return "-"
	}
	if !workspaceDeviceTrusted(workspace, activeWorkspaceID) {
		if workspaceCanApproveDevice(workspace) {
			return deviceTrustCommand(st, workspace.Slug)
		}
		return "ask owner to approve"
	}
	if keys == "needs rewrap" {
		return fmt.Sprintf("asiri rewrap --workspace %s", workspace.Slug)
	}
	if keys == "unwrapped" {
		return "rewrap on a device with local keys"
	}
	return "-"
}

func workspaceDeviceTrusted(workspace remoteWorkspaceResponse, activeWorkspaceID string) bool {
	if workspace.CurrentDeviceTrusted != nil {
		return *workspace.CurrentDeviceTrusted
	}
	if workspace.CanPull != nil {
		return *workspace.CanPull
	}
	return workspace.ID != "" && workspace.ID == activeWorkspaceID
}

func workspaceCanApproveDevice(workspace remoteWorkspaceResponse) bool {
	if workspace.CanApproveDevice != nil {
		return *workspace.CanApproveDevice
	}
	return workspace.Role == "owner"
}

func deviceTrustLabelForWorkspace(workspace remoteWorkspaceResponse, activeWorkspaceID string) string {
	if workspaceDeviceTrusted(workspace, activeWorkspaceID) {
		return "trusted"
	}
	if workspace.CurrentDeviceTrusted == nil && workspace.CanPull == nil {
		return "unknown"
	}
	return "not trusted"
}

func remoteSecretKeyLabel(st *store.FileStore, secret visibleRemoteSecretRecord) string {
	if secret.WrappedToCurrentDevice == nil {
		return "unknown"
	}
	if *secret.WrappedToCurrentDevice {
		return "wrapped"
	}
	if secret.CurrentDeviceID == "" {
		return "not trusted"
	}
	if localSecretVersionExists(st, secret.Scope, secret.Name, secret.Version) {
		return "needs rewrap"
	}
	return "unwrapped"
}

func writePullResults(out io.Writer, results []pullResult) {
	tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "WORKSPACE\tRESULT\tIMPORTED\tREMOTE\tNOTE")
	for _, result := range results {
		fmt.Fprintf(tw, "%s\t%s\t%d\t%d\t%s\n", result.Workspace, result.Result, result.Imported, result.Remote, result.Note)
	}
	_ = tw.Flush()
}

func (a App) importRemoteVersions(st *store.FileStore, versions []store.RemoteSecretVersion, force bool) (int, error) {
	if len(versions) == 0 {
		return 0, nil
	}
	return st.ImportRemoteSecretVersions(versions, force)
}

func importServiceAccountSyncPolicies(st *store.FileStore, policies []syncPolicyResponse) {
	if st == nil || st.State.ControlPlane == nil || st.State.ControlPlane.Source != "service-account" || st.State.ControlPlane.ServiceAccountSlug == "" {
		return
	}
	serviceAccount := store.NormalizeSubjectLabel(st.State.ControlPlane.ServiceAccountSlug)
	kept := make([]asiri.Policy, 0, len(st.State.Policies))
	for _, policy := range st.State.Policies {
		if store.NormalizeSubjectLabel(policy.Subject) != serviceAccount {
			kept = append(kept, policy)
		}
	}
	for _, policy := range policies {
		if policy.SubjectType != "service" || store.NormalizeSubjectLabel(policy.SubjectID) != serviceAccount || policy.ScopePattern == "" || policy.SecretPattern == "" || len(policy.Actions) == 0 || policy.ApprovalMode != "none" {
			continue
		}
		createdAt := policy.CreatedAt
		if createdAt.IsZero() {
			createdAt = time.Now().UTC()
		}
		id := policy.ID
		if id == "" {
			id = store.NewID("pol")
		}
		kept = append(kept, asiri.Policy{
			ID:            id,
			Subject:       serviceAccount,
			ScopePattern:  policy.ScopePattern,
			SecretPattern: policy.SecretPattern,
			Actions:       policy.Actions,
			ApprovalMode:  policy.ApprovalMode,
			CreatedAt:     createdAt,
			ExpiresAt:     policy.ExpiresAt,
		})
	}
	st.State.Policies = kept
}

func (a App) rekey(st *store.FileStore, args []string) int {
	if err := st.RequireInitialized(); err != nil {
		return a.fail(err)
	}
	if st.State.ControlPlane == nil {
		return a.fail(errors.New("asiri is not linked to a control plane"))
	}
	if err := rejectServiceAccountControlPlaneMutation(st); err != nil {
		return a.fail(err)
	}
	workspaceArg, remaining, err := splitWorkspaceFlag(args, "rekey", true)
	if err != nil {
		return a.fail(err)
	}
	if err := rejectUnknownArgs(remaining, "--yes"); err != nil {
		return a.fail(err)
	}
	accessToken, err := ensureControlPlaneAccess(st.State.ControlPlane.Origin, st)
	if err != nil {
		return a.fail(err)
	}
	target, accessToken, err := a.remoteWorkspaceTarget(st, accessToken, workspaceArg)
	if err != nil {
		return a.fail(err)
	}
	if binding, ok := st.RemoteBindingForPrefix(target.Slug); !ok || binding.WorkspaceID != target.ID {
		return a.fail(fmt.Errorf("workspace prefix %s must be pushed or pulled before rekey", target.Slug))
	}
	refs := st.ActiveSecretRefs()
	selectedRefs := make([]store.LocalSecretRef, 0, len(refs))
	for _, ref := range refs {
		if store.WorkspacePrefix(ref.Scope) == target.Slug {
			selectedRefs = append(selectedRefs, ref)
		}
	}
	if len(selectedRefs) == 0 {
		fmt.Fprintln(a.Out, "No local active secrets to rekey")
		return 0
	}
	options, err := remoteWriteOptions(st, st.State.ControlPlane.Origin, accessToken, selectedRefs)
	if err != nil {
		return a.fail(err)
	}
	if !options.ActiveWorkspace.CanWrite {
		return a.fail(fmt.Errorf("workspace %s cannot write %s", target.Slug, fullPathList(options.ActiveWorkspace.Paths)))
	}
	if _, err := getActiveRemoteRecoveryRecipient(st, st.State.ControlPlane.Origin, target.ID, accessToken); err != nil {
		return a.fail(err)
	}
	rotated, err := st.RotateDataKeysForPrefix(target.Slug)
	if err != nil {
		return a.fail(err)
	}
	if rotated == 0 {
		fmt.Fprintln(a.Out, "No local active secrets to rekey")
		return 0
	}
	fmt.Fprintf(a.Out, "✓ Re-encrypted %d local secret(s) with new scoped data keys\n", rotated)
	return a.push(st, args)
}

func (a App) rewrap(st *store.FileStore, args []string) int {
	if err := st.RequireInitialized(); err != nil {
		return a.fail(err)
	}
	if st.State.ControlPlane == nil {
		return a.fail(errors.New("asiri is not linked to a control plane"))
	}
	if err := rejectServiceAccountControlPlaneMutation(st); err != nil {
		return a.fail(err)
	}
	workspaceArg, remaining, err := splitWorkspaceFlag(args, "rewrap", true)
	if err != nil {
		return a.fail(err)
	}
	if err := rejectUnknownArgs(remaining); err != nil {
		return a.fail(err)
	}
	accessToken, err := ensureControlPlaneAccess(st.State.ControlPlane.Origin, st)
	if err != nil {
		return a.fail(err)
	}
	target, accessToken, err := a.remoteWorkspaceTarget(st, accessToken, workspaceArg)
	if err != nil {
		return a.fail(err)
	}
	stats, err := a.rewrapWorkspace(st, accessToken, target)
	if err != nil {
		return a.fail(err)
	}
	st.Audit(st.State.UserID, "control_plane_rewrap", "allowed", "", "", "wrapped local data keys to trusted remote devices", map[string]string{"secrets": fmt.Sprintf("%d", stats.Updated), "wrappedKeys": fmt.Sprintf("%d", stats.Added), "workspace": target.Slug})
	if err := st.Save(); err != nil {
		return a.fail(err)
	}
	if stats.Added == 0 && stats.SkippedMissingLocal > 0 {
		fmt.Fprintf(a.Out, "No remote secrets can be rewrapped from this machine; %d active remote secret version(s) are missing matching local key material\n", stats.SkippedMissingLocal)
		return 0
	}
	if stats.Added == 0 {
		fmt.Fprintln(a.Out, "No trusted devices need wrapped keys")
		return 0
	}
	fmt.Fprintf(a.Out, "✓ Rewrapped %d key(s) across %d secret version(s) in workspace %s\n", stats.Added, stats.Updated, target.Slug)
	return 0
}

type rewrapStats struct {
	Updated             int
	Added               int
	SkippedMissingLocal int
}

func (a App) rewrapWorkspace(st *store.FileStore, accessToken string, target remoteWorkspaceResponse) (rewrapStats, error) {
	devices, err := listRemoteDevices(st, st.State.ControlPlane.Origin, target.ID, accessToken, false)
	if err != nil {
		return rewrapStats{}, err
	}
	encryptedSecrets, err := listRemoteSecrets(st, st.State.ControlPlane.Origin, target.ID, accessToken, "", false)
	if err != nil {
		return rewrapStats{}, err
	}
	metadataSecrets, status, err := listRemoteSecretMetadata(st, st.State.ControlPlane.Origin, target.ID, accessToken, false)
	if err != nil {
		return rewrapStats{}, err
	}
	secrets := encryptedSecrets
	if status != http.StatusNotFound {
		secrets = mergeRemoteSecretRecords(metadataSecrets, encryptedSecrets)
	}
	targets := map[string]remoteDeviceResponse{}
	for _, device := range devices {
		if device.Status == "trusted" && device.EncryptionPublicKey != "" {
			targets[device.ID] = device
		}
	}
	if len(targets) == 0 {
		return rewrapStats{}, nil
	}
	stats := rewrapStats{}
	for _, secret := range secrets {
		if secret.Status != "active" {
			continue
		}
		if !localSecretVersionExists(st, secret.Scope, secret.Name, secret.Version) {
			stats.SkippedMissingLocal++
			continue
		}
		missing := make([]store.RemoteWrappedKey, 0)
		for _, device := range targets {
			if remoteSecretHasRecipient(secret, device.ID) {
				continue
			}
			wrapped, err := st.RemoteWrappedKeyForSecretVersionPublicKey(secret.Scope, secret.Name, secret.Version, device.ID, device.EncryptionPublicKey)
			if err != nil {
				return rewrapStats{}, err
			}
			missing = append(missing, wrapped)
		}
		if len(missing) == 0 {
			continue
		}
		if err := addRemoteWrappedKeys(st, st.State.ControlPlane.Origin, secret.ID, accessToken, missing, true); err != nil {
			return rewrapStats{}, err
		}
		stats.Updated++
		stats.Added += len(missing)
	}
	return stats, nil
}

func (a App) recovery(st *store.FileStore, args []string) int {
	if len(args) == 0 {
		return a.fail(errors.New("recovery subcommand required"))
	}
	if err := st.RequireInitialized(); err != nil {
		return a.fail(err)
	}
	switch args[0] {
	case "status":
		if st.State.ControlPlane == nil {
			return a.fail(errors.New("asiri is not linked to a control plane"))
		}
		workspaceFilters, remaining, err := splitWorkspaceFilters(args[1:], "recovery status")
		if err != nil {
			return a.fail(err)
		}
		if err := rejectUnknownArgs(remaining); err != nil {
			return a.fail(err)
		}
		accessToken, err := ensureControlPlaneAccess(st.State.ControlPlane.Origin, st)
		if err != nil {
			return a.fail(err)
		}
		workspaces, err := listRemoteWorkspaces(st, st.State.ControlPlane.Origin, accessToken)
		if err != nil {
			return a.fail(err)
		}
		targets := make([]remoteWorkspaceResponse, 0, len(workspaces))
		if len(workspaceFilters) == 0 {
			targets = append(targets, workspaces...)
		} else {
			for _, requested := range workspaceFilters {
				target, err := requireRemoteWorkspace(workspaces, requested)
				if err != nil {
					return a.fail(err)
				}
				targets = append(targets, target)
			}
		}
		type recoveryStatusRow struct {
			Workspace   string
			Status      string
			Fingerprint string
			Wrapped     int
			Note        string
		}
		rows := []recoveryStatusRow{}
		currentToken := accessToken
		saveNeeded := false
		if st.State.Recoveries == nil {
			st.State.Recoveries = map[string]asiri.RecoveryConfig{}
		}
		activeWorkspaceID := st.State.ControlPlane.WorkspaceID
		for _, target := range targets {
			if !pullWorkspaceCanPull(target, activeWorkspaceID) {
				rows = append(rows, recoveryStatusRow{Workspace: target.Slug, Status: "skipped", Note: "this device is not trusted for this workspace"})
				continue
			}
			token, err := a.ensureWorkspaceSession(st, currentToken, target)
			if err != nil {
				rows = append(rows, recoveryStatusRow{Workspace: target.Slug, Status: "failed", Note: err.Error()})
				continue
			}
			currentToken = token
			if st.State.ControlPlane != nil {
				target.ID = st.State.ControlPlane.WorkspaceID
				target.Slug = st.State.ControlPlane.WorkspaceSlug
			}
			recovery, err := getActiveRemoteRecoveryRecipient(st, st.State.ControlPlane.Origin, target.ID, currentToken)
			if err != nil {
				rows = append(rows, recoveryStatusRow{Workspace: target.Slug, Status: "failed", Note: err.Error()})
				continue
			}
			if recovery == nil {
				if _, ok := st.State.Recoveries[target.ID]; ok {
					delete(st.State.Recoveries, target.ID)
					saveNeeded = true
				}
				rows = append(rows, recoveryStatusRow{Workspace: target.Slug, Status: "not-configured"})
				continue
			}
			if existing, ok := st.State.Recoveries[target.ID]; ok && existing.RecipientID == recovery.RecipientID {
				recovery.CreatedAt = existing.CreatedAt
				recovery.LastWrappedAt = existing.LastWrappedAt
				recovery.WrappedSecretCount = existing.WrappedSecretCount
			}
			st.State.Recoveries[target.ID] = *recovery
			saveNeeded = true
			rows = append(rows, recoveryStatusRow{Workspace: target.Slug, Status: "configured", Fingerprint: recovery.PublicKeyFingerprint, Wrapped: st.RecoveryWrappedCountForPrefix(target.Slug)})
		}
		if saveNeeded {
			if err := st.Save(); err != nil {
				return a.fail(err)
			}
		}
		tw := tabwriter.NewWriter(a.Out, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "WORKSPACE\tSTATUS\tFINGERPRINT\tWRAPPED\tNOTE")
		for _, row := range rows {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t%s\n", row.Workspace, row.Status, row.Fingerprint, row.Wrapped, row.Note)
		}
		if err := tw.Flush(); err != nil {
			return a.fail(err)
		}
		return 0
	case "setup":
		if st.State.ControlPlane == nil {
			return a.fail(errors.New("asiri is not linked to a control plane"))
		}
		if err := rejectServiceAccountControlPlaneMutation(st); err != nil {
			return a.fail(err)
		}
		workspaceArg, remaining, err := splitWorkspaceFlag(args[1:], "recovery setup", true)
		if err != nil {
			return a.fail(err)
		}
		if err := rejectUnknownArgs(remaining, "--force", "--output-file"); err != nil {
			return a.fail(err)
		}
		outputPath, hasOutput, err := optionalFlagValue(remaining, "--output-file")
		if err != nil {
			return a.fail(err)
		}
		outFile, isTerminalOutput := a.Out.(*os.File)
		if !hasOutput && (!isTerminalOutput || !term.IsTerminal(int(outFile.Fd()))) {
			return a.fail(errors.New("recovery setup requires --output-file in non-interactive mode"))
		}
		accessToken, err := ensureControlPlaneAccess(st.State.ControlPlane.Origin, st)
		if err != nil {
			return a.fail(err)
		}
		target, accessToken, err := a.remoteWorkspaceTarget(st, accessToken, workspaceArg)
		if err != nil {
			return a.fail(err)
		}
		force := hasFlag(remaining, "--force")
		remoteRecovery, err := getActiveRemoteRecoveryRecipient(st, st.State.ControlPlane.Origin, target.ID, accessToken)
		if err != nil {
			return a.fail(err)
		}
		if !force && remoteRecovery != nil {
			return a.fail(fmt.Errorf("recovery is already configured for workspace %s; use --force to replace it", target.Slug))
		}
		setup, err := st.GenerateRecoverySetup()
		if err != nil {
			return a.fail(err)
		}
		var outputFile *os.File
		removeOutputOnFailure := false
		if hasOutput {
			outputFile, err = reserveExclusiveSecretFile(outputPath)
			if err != nil {
				return a.fail(err)
			}
			removeOutputOnFailure = true
			defer func() {
				_ = outputFile.Close()
				if removeOutputOnFailure {
					_ = os.Remove(outputPath)
				}
			}()
		}
		previousRecipientID := ""
		if remoteRecovery != nil {
			previousRecipientID = remoteRecovery.RecipientID
		}
		replacements, covered, err := a.prepareRemoteRecoveryReplacementKeys(st, accessToken, setup.Config, previousRecipientID)
		if err != nil {
			return a.fail(err)
		}
		if hasOutput {
			if err := writeReservedSecretFile(outputFile, []byte(setup.Key+"\n")); err != nil {
				return a.fail(err)
			}
			removeOutputOnFailure = false
			fmt.Fprintf(a.Out, "Recovery key written to %s\n", outputPath)
		} else {
			fmt.Fprintln(a.Out, "Recovery key:")
			fmt.Fprintln(a.Out, setup.Key)
			fmt.Fprintln(a.Out, "Copy this key to a secure place, for example a password app or a printed copy. Asiri will not show it again.")
		}
		if remoteRecovery != nil {
			if err := replaceRemoteRecoveryRecipient(st, st.State.ControlPlane.Origin, accessToken, setup, replacements); err != nil {
				return a.fail(fmt.Errorf("recovery key delivered, but remote replacement failed: %w", err))
			}
		} else if err := registerRemoteRecoveryRecipient(st, st.State.ControlPlane.Origin, accessToken, setup, replacements); err != nil {
			return a.fail(fmt.Errorf("recovery key delivered, but remote registration failed: %w", err))
		}
		st.CommitRecoverySetup(setup)
		if covered > 0 {
			if err := st.MarkRecoveryWrapped(st.State.ControlPlane.WorkspaceSlug, covered); err != nil {
				return a.fail(err)
			}
		} else if err := st.Save(); err != nil {
			return a.fail(err)
		}
		fmt.Fprintf(a.Out, "✓ Recovery configured (%s)\n", setup.Fingerprint)
		if len(replacements) > 0 {
			fmt.Fprintf(a.Out, "✓ Added recovery wrapping to %d remote secret(s)\n", len(replacements))
		}
		return 0
	case "restore":
		return a.recoveryRestore(st, args[1:])
	default:
		return a.fail(fmt.Errorf("unknown recovery command %q", args[0]))
	}
}
func (a App) recoveryRestore(st *store.FileStore, args []string) int {
	if st.State.ControlPlane == nil {
		return a.fail(errors.New("asiri is not linked to a control plane"))
	}
	if err := rejectServiceAccountControlPlaneMutation(st); err != nil {
		return a.fail(err)
	}
	workspaceArg, remaining, err := splitWorkspaceFlag(args, "recovery restore", true)
	if err != nil {
		return a.fail(err)
	}
	if err := rejectUnknownArgs(remaining, "--stdin", "--key-file", "--force"); err != nil {
		return a.fail(err)
	}
	recoveryKey, err := a.readSensitiveInput(remaining, "Recovery key", "--key-file", "--key")
	if err != nil {
		return a.fail(err)
	}
	identity, err := store.RecoveryKeyIdentityForKey(recoveryKey)
	if err != nil {
		return a.fail(err)
	}
	accessToken, err := ensureControlPlaneAccess(st.State.ControlPlane.Origin, st)
	if err != nil {
		return a.fail(err)
	}
	target, accessToken, err := a.remoteWorkspaceTarget(st, accessToken, workspaceArg)
	if err != nil {
		return a.fail(err)
	}
	secrets, err := listRemoteSecrets(st, st.State.ControlPlane.Origin, target.ID, accessToken, identity.RecipientID, false)
	if err != nil {
		return a.fail(err)
	}
	activeVersions := remoteRecordsToVersions(secrets)
	if len(activeVersions) == 0 {
		if err := commitRecoveryIdentity(st, identity, 0); err != nil {
			return a.fail(err)
		}
		fmt.Fprintln(a.Out, "No remote active secrets to restore")
		return 0
	}
	imported, identity, err := st.ImportRecoveryRemoteSecretVersions(activeVersions, recoveryKey, hasFlag(remaining, "--force"))
	if err != nil {
		return a.fail(err)
	}
	rewrapped, err := a.addRecoveredDeviceWrappedKeys(st, accessToken, secrets, identity.RecipientID)
	if err != nil {
		return a.fail(err)
	}
	if err := commitRecoveryIdentity(st, identity, imported); err != nil {
		return a.fail(err)
	}
	fmt.Fprintf(a.Out, "✓ Restored %d remote secret(s) and registered this device on %d secret(s)\n", imported, rewrapped)
	return 0
}

func commitRecoveryIdentity(st *store.FileStore, identity store.RecoveryKeyIdentity, wrappedCount int) error {
	if st.State.Recoveries == nil {
		st.State.Recoveries = map[string]asiri.RecoveryConfig{}
	}
	now := time.Now().UTC()
	st.State.Recoveries[st.State.ControlPlane.WorkspaceID] = asiri.RecoveryConfig{
		RecipientID:          identity.RecipientID,
		PublicKey:            identity.PublicKey,
		PublicKeyFingerprint: identity.Fingerprint,
		CreatedAt:            now,
		WrappedSecretCount:   wrappedCount,
		LastWrappedAt:        now,
	}
	return st.Save()
}

func (a App) addRecoveredDeviceWrappedKeys(st *store.FileStore, accessToken string, secrets []remoteSecretRecord, recoveryRecipientID string) (int, error) {
	device, err := st.ActiveDevice()
	if err != nil {
		return 0, err
	}
	updated := 0
	for _, secret := range secrets {
		if secret.Status != "active" {
			continue
		}
		if !remoteSecretHasRecoveryRecipient(secret, recoveryRecipientID) || remoteSecretHasRecipient(secret, st.State.ControlPlane.DeviceID) {
			continue
		}
		if !localSecretVersionExists(st, secret.Scope, secret.Name, secret.Version) {
			continue
		}
		wrapped, err := st.RemoteWrappedKeyForSecretVersionPublicKey(secret.Scope, secret.Name, secret.Version, st.State.ControlPlane.DeviceID, device.EncryptionPublicKey)
		if err != nil {
			return updated, err
		}
		if err := addRecoveryRestoredWrappedKeys(st, st.State.ControlPlane.Origin, secret.ID, accessToken, recoveryRecipientID, []store.RemoteWrappedKey{wrapped}); err != nil {
			return updated, err
		}
		updated += 1
	}
	return updated, nil
}

func (a App) prepareRemoteRecoveryReplacementKeys(st *store.FileStore, accessToken string, recovery asiri.RecoveryConfig, previousRecoveryRecipientID string) ([]recoveryRecipientReplacement, int, error) {
	if st.State.ControlPlane == nil {
		return nil, 0, nil
	}
	if binding, ok := st.RemoteBindingForPrefix(st.State.ControlPlane.WorkspaceSlug); !ok || binding.WorkspaceID != st.State.ControlPlane.WorkspaceID {
		return nil, 0, nil
	}
	secrets, err := listRemoteSecrets(st, st.State.ControlPlane.Origin, st.State.ControlPlane.WorkspaceID, accessToken, previousRecoveryRecipientID, false)
	if err != nil {
		if previousRecoveryRecipientID != "" && strings.Contains(err.Error(), "HTTP 403") {
			secrets, err = listRemoteSecrets(st, st.State.ControlPlane.Origin, st.State.ControlPlane.WorkspaceID, accessToken, "", false)
		}
		if err != nil {
			return nil, 0, err
		}
	}
	replacements := make([]recoveryRecipientReplacement, 0, len(secrets))
	covered := 0
	for _, secret := range secrets {
		if secret.Status != "active" || !localSecretVersionExists(st, secret.Scope, secret.Name, secret.Version) {
			continue
		}
		if remoteSecretHasRecoveryRecipient(secret, recovery.RecipientID) {
			covered += 1
			continue
		}
		key, err := st.RecoveryWrappedKeyForSecretVersionWithConfig(secret.Scope, secret.Name, secret.Version, recovery)
		if err != nil {
			return nil, 0, err
		}
		replacements = append(replacements, recoveryRecipientReplacement{SecretID: secret.ID, WrappedKey: key})
		covered += 1
	}
	return replacements, covered, nil
}

type deviceTrustOptions struct {
	Workspace string
	All       bool
	Origin    string
}

func parseDeviceTrustArgs(args []string) (deviceTrustOptions, error) {
	options := deviceTrustOptions{}
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--workspace":
			if i+1 >= len(args) || strings.HasPrefix(args[i+1], "--") {
				return options, errors.New("--workspace requires a slug")
			}
			slug, err := localWorkspaceSlug(args[i+1])
			if err != nil {
				return options, err
			}
			options.Workspace = slug
			i++
		case "--all":
			options.All = true
		case "--origin":
			if i+1 >= len(args) || strings.HasPrefix(args[i+1], "--") {
				return options, errors.New("--origin requires a URL")
			}
			options.Origin = strings.TrimRight(args[i+1], "/")
			i++
		default:
			return options, fmt.Errorf("unknown device trust argument %q", args[i])
		}
	}
	if options.All && options.Workspace != "" {
		return options, errors.New("use either --workspace or --all, not both")
	}
	if !options.All && options.Workspace == "" {
		return options, errors.New("device trust requires --workspace or --all")
	}
	return options, nil
}

func deviceTrustOrigin(st *store.FileStore, explicit string) string {
	if explicit != "" {
		return explicit
	}
	if origin := strings.TrimRight(os.Getenv("ASIRI_CONTROL_PLANE_ORIGIN"), "/"); origin != "" {
		return origin
	}
	if st.State.ControlPlane != nil && st.State.ControlPlane.Origin != "" {
		return st.State.ControlPlane.Origin
	}
	return defaultControlPlaneOrigin
}

func (a App) whoami(st *store.FileStore, args []string) int {
	if err := rejectUnknownArgs(args); err != nil {
		return a.fail(err)
	}
	if err := st.RequireInitialized(); err != nil {
		return a.fail(err)
	}
	if st.State.ControlPlane == nil {
		return a.fail(errors.New("asiri is not linked to a control plane"))
	}
	accessToken, err := ensureControlPlaneAccess(st.State.ControlPlane.Origin, st)
	if err != nil {
		return a.fail(err)
	}
	var result remoteWhoamiResponse
	endpoint := strings.TrimRight(st.State.ControlPlane.Origin, "/") + "/v1/whoami"
	if err := getJSONBearer(st, endpoint, accessToken, &result); err != nil {
		return a.fail(err)
	}
	localDeviceName := "-"
	if device, err := st.ActiveDevice(); err == nil && device.Name != "" {
		localDeviceName = device.Name
	}
	workspaceSlug := firstNonEmpty(result.Workspace.Slug, st.State.ControlPlane.WorkspaceSlug)
	remoteDeviceID := firstNonEmpty(result.Device.ID, result.Session.DeviceID, st.State.ControlPlane.DeviceID)
	tw := tabwriter.NewWriter(a.Out, 0, 0, 2, ' ', 0)
	fmt.Fprintf(tw, "USER ID\t%s\n", printable(firstNonEmpty(result.User.ID, st.State.ControlPlane.UserID)))
	fmt.Fprintf(tw, "EMAIL\t%s\n", printable(result.User.Email))
	fmt.Fprintf(tw, "NAME\t%s\n", printable(result.User.DisplayName))
	fmt.Fprintf(tw, "ROLE\t%s\n", printable(result.User.Role))
	fmt.Fprintf(tw, "STATUS\t%s\n", printable(result.User.Status))
	fmt.Fprintf(tw, "WORKSPACE\t%s\n", printable(workspaceSlug))
	if result.Session.ServiceAccountSlug != "" || st.State.ControlPlane.ServiceAccountSlug != "" {
		fmt.Fprintf(tw, "IDENTITY\tservice account\n")
		fmt.Fprintf(tw, "SERVICE ACCOUNT\t%s\n", printable(firstNonEmpty(result.Session.ServiceAccountSlug, st.State.ControlPlane.ServiceAccountSlug)))
		if firstNonEmpty(result.Session.ServiceAccountName, st.State.ControlPlane.ServiceAccountName) != "" {
			fmt.Fprintf(tw, "SERVICE ACCOUNT NAME\t%s\n", printable(firstNonEmpty(result.Session.ServiceAccountName, st.State.ControlPlane.ServiceAccountName)))
		}
		if firstNonEmpty(result.Session.ApprovedByUserID, st.State.ControlPlane.ApprovedByUserID) != "" {
			fmt.Fprintf(tw, "APPROVED BY\t%s\n", printable(firstNonEmpty(result.Session.ApprovedByUserID, st.State.ControlPlane.ApprovedByUserID)))
		}
	}
	fmt.Fprintf(tw, "LOCAL DEVICE\t%s\n", printable(localDeviceName))
	fmt.Fprintf(tw, "REMOTE DEVICE\t%s\n", printable(remoteDeviceID))
	fmt.Fprintf(tw, "ORIGIN\t%s\n", printable(st.State.ControlPlane.Origin))
	if err := tw.Flush(); err != nil {
		return a.fail(err)
	}
	return 0
}

func (a App) deviceStatus(st *store.FileStore, args []string) int {
	if err := st.RequireInitialized(); err != nil {
		return a.fail(err)
	}
	if st.State.ControlPlane == nil {
		return a.fail(errors.New("asiri is not linked to a control plane"))
	}
	workspaceFilters, remaining, err := splitWorkspaceFilters(args, "device status")
	if err != nil {
		return a.fail(err)
	}
	if err := rejectUnknownArgs(remaining); err != nil {
		return a.fail(err)
	}
	accessToken, err := ensureControlPlaneAccess(st.State.ControlPlane.Origin, st)
	if err != nil {
		return a.fail(err)
	}
	includeSecrets := st.State.ControlPlane.Source != "service-account"
	workspaceResult, err := listRemoteWorkspaceOverview(st, st.State.ControlPlane.Origin, accessToken, includeSecrets, false)
	if err != nil {
		return a.fail(err)
	}
	workspaces := workspaceResult.Organizations
	targets := make([]remoteWorkspaceResponse, 0, len(workspaces))
	if len(workspaceFilters) == 0 {
		targets = append(targets, workspaces...)
	} else {
		for _, requested := range workspaceFilters {
			target, err := requireRemoteWorkspace(workspaces, requested)
			if err != nil {
				return a.fail(err)
			}
			targets = append(targets, target)
		}
	}
	remoteSecrets := workspaceResult.Secrets
	var secretsErr error
	secretsKnown := false
	if includeSecrets {
		secretsKnown = remoteSecrets != nil
		if !secretsKnown {
			secretsErr = errors.New("control plane did not return workspace secret metadata")
		}
	}
	keySummaries := workspaceKeySummaries(st, targets, remoteSecrets, st.State.ControlPlane.WorkspaceID, secretsKnown)
	fmt.Fprintf(a.Out, "This device: %s\n", currentDeviceDescription(st))
	tw := tabwriter.NewWriter(a.Out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "WORKSPACE\tROLE\tTHIS DEVICE\tACCOUNT WRITE\tKEYS\tNEXT\tREMOTE DEVICE")
	for _, workspace := range targets {
		keySummary := keySummaries[workspace.Slug]
		remoteDevice := workspace.CurrentDeviceID
		if remoteDevice == "" {
			remoteDevice = "-"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", workspace.Slug, workspaceRoleLabel(workspace, st.State.UserID), deviceTrustLabelForWorkspace(workspace, st.State.ControlPlane.WorkspaceID), boolPointerLabel(workspace.CanWrite), keySummary.Keys, keySummary.Next, remoteDevice)
	}
	if err := tw.Flush(); err != nil {
		return a.fail(err)
	}
	if secretsErr != nil {
		fmt.Fprintf(a.Err, "asiri: remote key coverage unavailable: %s\n", secretsErr)
	}
	return 0
}

func (a App) deviceTrust(st *store.FileStore, args []string) int {
	if err := st.RequireInitialized(); err != nil {
		return a.fail(err)
	}
	if err := rejectServiceAccountControlPlaneMutation(st); err != nil {
		return a.fail(err)
	}
	options, err := parseDeviceTrustArgs(args)
	if err != nil {
		return a.fail(err)
	}
	origin := deviceTrustOrigin(st, options.Origin)
	if err := validateControlPlaneOrigin(origin); err != nil {
		return a.fail(err)
	}
	device, err := st.ActiveDevice()
	if err != nil {
		return a.fail(err)
	}
	if options.All {
		if st.State.ControlPlane == nil {
			return a.fail(errors.New("device trust --all requires an existing control-plane session"))
		}
		accessToken, err := ensureControlPlaneAccess(st.State.ControlPlane.Origin, st)
		if err != nil {
			return a.fail(err)
		}
		workspaces, err := listRemoteWorkspaces(st, st.State.ControlPlane.Origin, accessToken)
		if err != nil {
			return a.fail(err)
		}
		original := remoteWorkspaceResponse{ID: st.State.ControlPlane.WorkspaceID, Slug: st.State.ControlPlane.WorkspaceSlug, CurrentDeviceTrusted: boolPtr(true), CanPull: boolPtr(true)}
		eligible := make([]remoteWorkspaceResponse, 0)
		tw := tabwriter.NewWriter(a.Out, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "WORKSPACE\tTHIS DEVICE\tAPPROVAL\tNEXT")
		for _, workspace := range workspaces {
			switch {
			case workspaceDeviceTrusted(workspace, st.State.ControlPlane.WorkspaceID):
				fmt.Fprintf(tw, "%s\ttrusted\tskipped\t-\n", workspace.Slug)
			case !workspaceCanApproveDevice(workspace):
				fmt.Fprintf(tw, "%s\tnot trusted\tskipped\task owner to approve\n", workspace.Slug)
			default:
				eligible = append(eligible, workspace)
				fmt.Fprintf(tw, "%s\tnot trusted\teligible\tbrowser approval\n", workspace.Slug)
			}
		}
		if err := tw.Flush(); err != nil {
			return a.fail(err)
		}
		if len(eligible) == 0 {
			fmt.Fprintln(a.Out, "No eligible workspaces need this device.")
			return 0
		}
		currentToken := accessToken
		for _, workspace := range eligible {
			result, err := a.trustDeviceInWorkspace(st, origin, workspace.Slug, *device)
			if err != nil {
				return a.fail(err)
			}
			currentToken = result.AccessToken
		}
		if original.ID != "" && st.State.ControlPlane != nil && st.State.ControlPlane.WorkspaceID != original.ID {
			if _, err := a.ensureWorkspaceSession(st, currentToken, original); err != nil {
				fmt.Fprintf(a.Err, "asiri: could not restore original workspace session: %s\n", err)
			}
		}
		return 0
	}
	if st.State.ControlPlane != nil {
		accessToken, err := ensureControlPlaneAccess(st.State.ControlPlane.Origin, st)
		if err != nil {
			return a.fail(err)
		}
		workspaces, err := listRemoteWorkspaces(st, st.State.ControlPlane.Origin, accessToken)
		if err != nil {
			return a.fail(err)
		}
		if target, ok := findWorkspace(workspaces, options.Workspace); ok {
			if workspaceDeviceTrusted(target, st.State.ControlPlane.WorkspaceID) {
				fmt.Fprintf(a.Out, "This device is already trusted for workspace %s\n", options.Workspace)
				return 0
			}
			if !workspaceCanApproveDevice(target) {
				return a.fail(fmt.Errorf("this account cannot approve devices for workspace %s", options.Workspace))
			}
		}
	}
	if _, err := a.trustDeviceInWorkspace(st, origin, options.Workspace, *device); err != nil {
		return a.fail(err)
	}
	return 0
}

func (a App) trustDeviceInWorkspace(st *store.FileStore, origin, workspaceSlug string, device asiri.Device) (deviceCodeTokenResponse, error) {
	start, err := startDeviceCodeLogin(origin, workspaceSlug, device)
	if err != nil {
		return deviceCodeTokenResponse{}, err
	}
	fmt.Fprintf(a.Out, "\nTrust this device for workspace %s\n", workspaceSlug)
	fmt.Fprintf(a.Out, "Open %s\n", start.VerificationURIComplete)
	fmt.Fprintf(a.Out, "Code: %s\n", start.UserCode)
	result, err := pollDeviceCodeLogin(st, origin, start)
	if err != nil {
		return result, err
	}
	if result.WorkspaceSlug != workspaceSlug {
		return result, fmt.Errorf("control plane approved workspace %s, expected %s", result.WorkspaceSlug, workspaceSlug)
	}
	if err := st.LinkControlPlaneForDevice(origin, result.OrgID, result.WorkspaceSlug, result.UserID, result.DeviceID, device.ID, result.AccessToken, result.RefreshToken, result.ExpiresIn, result.RefreshExpiresAt); err != nil {
		return result, err
	}
	fmt.Fprintf(a.Out, "✓ This device is trusted for workspace %s\n", result.WorkspaceSlug)
	target := remoteWorkspaceResponse{ID: result.OrgID, Slug: result.WorkspaceSlug, CurrentDeviceTrusted: boolPtr(true), CanPull: boolPtr(true), CurrentDeviceID: result.DeviceID}
	stats, err := a.rewrapWorkspace(st, result.AccessToken, target)
	if err != nil {
		fmt.Fprintf(a.Err, "asiri: trusted device, but automatic rewrap could not run: %s\n", err)
		return result, nil
	}
	if stats.Added > 0 {
		st.Audit(st.State.UserID, "control_plane_rewrap", "allowed", "", "", "automatically wrapped local data keys after device trust", map[string]string{"secrets": fmt.Sprintf("%d", stats.Updated), "wrappedKeys": fmt.Sprintf("%d", stats.Added), "workspace": result.WorkspaceSlug})
		if err := st.Save(); err != nil {
			return result, err
		}
		fmt.Fprintf(a.Out, "✓ Automatically rewrapped %d key(s) across %d secret version(s) in workspace %s\n", stats.Added, stats.Updated, result.WorkspaceSlug)
	} else if stats.SkippedMissingLocal > 0 {
		fmt.Fprintf(a.Out, "No local key material available to rewrap %d active remote secret version(s) in workspace %s\n", stats.SkippedMissingLocal, result.WorkspaceSlug)
	}
	return result, nil
}

func (a App) device(st *store.FileStore, args []string) int {
	if len(args) == 0 {
		return a.fail(errors.New("device subcommand required"))
	}
	switch args[0] {
	case "name":
		if err := rejectUnknownArgs(args[1:]); err != nil {
			return a.fail(err)
		}
		if err := st.RequireInitialized(); err != nil {
			return a.fail(err)
		}
		device, err := st.ActiveDevice()
		if err != nil {
			return a.fail(err)
		}
		if device.Name == "" {
			return a.fail(errors.New("local device has no name"))
		}
		fmt.Fprintln(a.Out, device.Name)
		return 0
	case "enroll":
		if err := st.RequireInitialized(); err != nil {
			return a.fail(err)
		}
		if err := rejectServiceAccountLocalMutation(st); err != nil {
			return a.fail(err)
		}
		name := flagValue(args[1:], "--name", "")
		if name == "" {
			return a.fail(errors.New("--name is required"))
		}
		device, refs, err := createDevice(name)
		if err != nil {
			return a.fail(err)
		}
		st.State.Devices = append(st.State.Devices, device)
		st.State.LocalDeviceID = device.ID
		for _, ref := range refs {
			st.AddKeyRef(ref.Purpose, ref.Account)
		}
		st.Audit(st.State.UserID, "device_enrolled", "allowed", "", "", "local device trusted", map[string]string{"device": name})
		if err := st.Save(); err != nil {
			return a.fail(err)
		}
		fmt.Fprintf(a.Out, "✓ Device %s enrolled and trusted (%s)\n", name, device.ID)
		return 0
	case "status":
		return a.deviceStatus(st, args[1:])
	case "trust":
		return a.deviceTrust(st, args[1:])
	case "list":
		if err := st.RequireInitialized(); err != nil {
			return a.fail(err)
		}
		workspaceFilters, remaining, err := splitWorkspaceFilters(args[1:], "device list")
		if err != nil {
			return a.fail(err)
		}
		if err := rejectUnknownArgs(remaining, "--local", "--remote", "--include-revoked"); err != nil {
			return a.fail(err)
		}
		local := hasFlag(remaining, "--local")
		remote := hasFlag(remaining, "--remote")
		includeRevoked := hasFlag(remaining, "--include-revoked")
		if local && remote {
			return a.fail(errors.New("use either --local or --remote, not both"))
		}
		if remote || (!local && st.State.ControlPlane != nil) {
			if st.State.ControlPlane == nil {
				return a.fail(errors.New("asiri is not linked to a control plane"))
			}
			accessToken, err := ensureControlPlaneAccess(st.State.ControlPlane.Origin, st)
			if err != nil {
				return a.fail(err)
			}
			workspaces, err := listRemoteWorkspaces(st, st.State.ControlPlane.Origin, accessToken)
			if err != nil {
				return a.fail(err)
			}
			targets := make([]remoteWorkspaceResponse, 0, len(workspaces))
			if len(workspaceFilters) == 0 {
				targets = append(targets, workspaces...)
			} else {
				for _, requested := range workspaceFilters {
					target, err := requireRemoteWorkspace(workspaces, requested)
					if err != nil {
						return a.fail(err)
					}
					targets = append(targets, target)
				}
			}
			type deviceListRow struct {
				Workspace string
				ID        string
				Name      string
				Kind      string
				Status    string
				Note      string
			}
			rows := []deviceListRow{}
			currentToken := accessToken
			activeWorkspaceID := st.State.ControlPlane.WorkspaceID
			for _, target := range targets {
				if !pullWorkspaceCanPull(target, activeWorkspaceID) {
					rows = append(rows, deviceListRow{Workspace: target.Slug, Status: "skipped", Note: "this device is not trusted for this workspace"})
					continue
				}
				token, err := a.ensureWorkspaceSession(st, currentToken, target)
				if err != nil {
					rows = append(rows, deviceListRow{Workspace: target.Slug, Status: "failed", Note: err.Error()})
					continue
				}
				currentToken = token
				if st.State.ControlPlane != nil {
					target.ID = st.State.ControlPlane.WorkspaceID
					target.Slug = st.State.ControlPlane.WorkspaceSlug
				}
				devices, err := listRemoteDevices(st, st.State.ControlPlane.Origin, target.ID, currentToken, includeRevoked)
				if err != nil {
					rows = append(rows, deviceListRow{Workspace: target.Slug, Status: "failed", Note: err.Error()})
					continue
				}
				for _, device := range devices {
					if !includeRevoked && device.Status == "revoked" {
						continue
					}
					rows = append(rows, deviceListRow{Workspace: target.Slug, ID: device.ID, Name: device.Name, Kind: device.Kind, Status: device.Status})
				}
			}
			tw := tabwriter.NewWriter(a.Out, 0, 0, 2, ' ', 0)
			fmt.Fprintln(tw, "WORKSPACE\tID\tNAME\tKIND\tSTATUS\tNOTE")
			for _, row := range rows {
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", row.Workspace, row.ID, row.Name, row.Kind, row.Status, row.Note)
			}
			if err := tw.Flush(); err != nil {
				return a.fail(err)
			}
			return 0
		}
		if len(workspaceFilters) > 0 {
			return a.fail(errors.New("device list --workspace requires a control-plane session or --remote"))
		}
		if len(st.State.Devices) == 0 {
			fmt.Fprintln(a.Out, "No devices enrolled")
			return 0
		}
		for _, device := range st.State.Devices {
			if !includeRevoked && device.Status == asiri.DeviceRevoked {
				continue
			}
			fmt.Fprintf(a.Out, "%s\t%s\t%s\t%s\n", device.ID, device.Name, device.Kind, device.Status)
		}
		return 0
	case "revoke":
		remote := hasFlag(args[1:], "--remote")
		revokeArgs := args[1:]
		if remote {
			workspaceArg, remaining, err := splitWorkspaceFlag(revokeArgs, "device revoke", true)
			if err != nil {
				return a.fail(err)
			}
			if err := rejectUnknownArgs(remaining, "--remote"); err != nil {
				return a.fail(err)
			}
			deviceRef := firstPositional(remaining)
			if deviceRef == "" {
				return a.fail(errors.New("device revoke requires a device name or id"))
			}
			if err := st.RequireInitialized(); err != nil {
				return a.fail(err)
			}
			if st.State.ControlPlane == nil {
				return a.fail(errors.New("asiri is not linked to a control plane"))
			}
			if err := rejectServiceAccountControlPlaneMutation(st); err != nil {
				return a.fail(err)
			}
			accessToken, err := ensureControlPlaneAccess(st.State.ControlPlane.Origin, st)
			if err != nil {
				return a.fail(err)
			}
			target, accessToken, err := a.remoteWorkspaceTarget(st, accessToken, workspaceArg)
			if err != nil {
				return a.fail(err)
			}
			device, err := revokeRemoteDevice(st, st.State.ControlPlane.Origin, deviceRef, accessToken)
			if err != nil {
				return a.fail(err)
			}
			revokedActive := device.ID == st.State.ControlPlane.DeviceID
			label := device.Name
			if label == "" {
				label = device.ID
			}
			if revokedActive {
				if err := st.QuarantineLocalKeys("remote device revoked; local key material cleared"); err != nil {
					return a.fail(fmt.Errorf("remote device revoked, but local key cleanup failed: %w", err))
				}
			}
			fmt.Fprintf(a.Out, "✓ Remote device %s revoked in workspace %s; rotate affected secrets after suspected compromise\n", label, target.Slug)
			return 0
		}
		if workspaceArg, _, err := splitWorkspaceFlag(revokeArgs, "device revoke", false); err != nil {
			return a.fail(err)
		} else if workspaceArg != "" {
			return a.fail(errors.New("device revoke --workspace requires --remote"))
		}
		if err := rejectUnknownArgs(revokeArgs); err != nil {
			return a.fail(err)
		}
		if err := rejectServiceAccountLocalMutation(st); err != nil {
			return a.fail(err)
		}
		deviceRef := firstPositional(revokeArgs)
		if deviceRef == "" {
			return a.fail(errors.New("device revoke requires a device name or id"))
		}
		if err := st.RevokeDevice(deviceRef); err != nil {
			return a.fail(err)
		}
		fmt.Fprintf(a.Out, "✓ Device %s revoked; rotate affected secrets after suspected compromise\n", deviceRef)
		return 0
	default:
		return a.fail(fmt.Errorf("unknown device command %q", args[0]))
	}
}

func (a App) add(st *store.FileStore, args []string) int {
	if err := rejectServiceAccountLocalMutation(st); err != nil {
		return a.fail(err)
	}
	workspaceArg, remaining, err := splitWorkspaceFlag(args, "add", true)
	if err != nil {
		return a.fail(err)
	}
	if len(remaining) == 0 {
		return a.fail(errors.New("add requires scope/name"))
	}
	if err := rejectUnknownArgs(remaining[1:], "--stdin", "--value-file", "--value"); err != nil {
		return a.fail(err)
	}
	target, err := a.workspacePathTarget(st, workspaceArg, "add")
	if err != nil {
		return a.fail(err)
	}
	fullPath, err := workspacePrefixedPath(target, remaining[0], "add")
	if err != nil {
		return a.fail(err)
	}
	value, err := a.readSensitiveInput(remaining[1:], "Secret value", "--value-file", "--value")
	if err != nil {
		return a.fail(err)
	}
	secret, err := st.AddSecret(fullPath, value)
	if err != nil {
		return a.fail(err)
	}
	fmt.Fprintf(a.Out, "✓ Stored %s in workspace %s as encrypted version %d (%s)\n", shortSecretPath(secret.Scope, secret.Name), target.Slug, secret.ActiveVersion, store.Mask(value))
	return 0
}

func (a App) get(st *store.FileStore, args []string) int {
	workspaceArg, remaining, err := splitWorkspaceFlag(args, "get", true)
	if err != nil {
		return a.fail(err)
	}
	if len(remaining) == 0 {
		return a.fail(errors.New("get requires scope/name"))
	}
	if err := rejectUnknownArgs(remaining[1:], "--agent"); err != nil {
		return a.fail(err)
	}
	target, err := a.workspacePathTarget(st, workspaceArg, "get")
	if err != nil {
		return a.fail(err)
	}
	fullPath, err := workspacePrefixedPath(target, remaining[0], "get")
	if err != nil {
		return a.fail(err)
	}
	agentExplicit := hasFlag(remaining[1:], "--agent")
	agent, _, err := optionalFlagValue(remaining[1:], "--agent")
	if err != nil {
		return a.fail(err)
	}
	agent, runtimeType, err := runtimeSubject(st, agent, "", agentExplicit)
	if err != nil {
		return a.fail(err)
	}
	if agent != "" {
		allowed, reason := st.CheckPolicy(agent, fullPath, "read")
		if !allowed {
			secret, err := st.SecretMetadata(fullPath)
			if err == nil {
				metadata := runtimeAuditMetadata(st, secret.Scope, agent, runtimeType, nil)
				st.Audit(agent, "secret_read", "denied", secret.Scope, secret.NameHash, reason, metadata)
			} else {
				metadata := runtimeAuditMetadata(st, "", agent, runtimeType, nil)
				st.Audit(agent, "secret_read", "denied", "", "", reason, metadata)
			}
			_ = st.Save()
			a.syncRuntimeAuditBestEffort(st)
			return a.fail(errors.New(reason))
		}
	}
	value, secret, err := st.GetSecret(fullPath)
	if err != nil {
		return a.fail(err)
	}
	actor := st.State.UserID
	if agent != "" {
		actor = agent
	}
	st.Audit(actor, "secret_read", "allowed", secret.Scope, secret.NameHash, "raw read", runtimeAuditMetadata(st, secret.Scope, agent, runtimeType, nil))
	if err := st.Save(); err != nil {
		return a.fail(err)
	}
	a.syncRuntimeAuditBestEffort(st)
	fmt.Fprintln(a.Out, value)
	return 0
}

func (a App) list(st *store.FileStore, args []string) int {
	if err := st.RequireInitialized(); err != nil {
		return a.fail(err)
	}
	workspaceFilters, remaining, err := splitWorkspaceFilters(args, "list")
	if err != nil {
		return a.fail(err)
	}
	if err := rejectUnknownArgs(remaining, "--local", "--remote", "--status", "--include-inactive"); err != nil {
		return a.fail(err)
	}
	statusFilter, _, err := optionalFlagValue(remaining, "--status")
	if err != nil {
		return a.fail(err)
	}
	if statusFilter != "" && !validListStatus(statusFilter) {
		return a.fail(fmt.Errorf("unknown list status %q", statusFilter))
	}
	localOnly := hasFlag(remaining, "--local")
	remoteOnly := hasFlag(remaining, "--remote")
	includeInactive := hasFlag(remaining, "--include-inactive")
	if localOnly && remoteOnly {
		return a.fail(errors.New("use either --local or --remote, not both"))
	}
	filter := strings.Trim(firstPositionalSkippingFlagValues(remaining, "--status"), "/")
	var workspaceSet map[string]bool
	if localOnly {
		workspaceSet, err = localWorkspaceFilterSet(workspaceFilters, "list")
	} else {
		workspaceSet, err = a.workspaceFilterSet(st, workspaceFilters, "list")
	}
	if err != nil {
		return a.fail(err)
	}
	if err := a.rejectWorkspacePrefixedFilter(st, filter, workspaceSet, "list", !localOnly); err != nil {
		return a.fail(err)
	}
	rows := make(map[string]listRow)
	for _, secret := range st.State.Secrets {
		version := activeVersion(secret)
		if version == nil {
			continue
		}
		rowKey := listOutputRowKey(secret.Scope, secret.Name, version.Version, includeInactive)
		workspace := store.WorkspacePrefix(secret.Scope)
		rows[rowKey] = listRow{
			Path:          shortSecretPath(secret.Scope, secret.Name),
			Version:       secret.ActiveVersion,
			NameHash:      secret.NameHash,
			Status:        "local-only",
			VersionStatus: version.Status,
			Keys:          "local",
			Workspace:     workspace,
			WorkspaceID:   boundWorkspaceID(st, workspace),
			HasLocal:      true,
			HasRemote:     false,
			RemoteStatus:  "",
		}
	}
	if st.State.ControlPlane != nil && !localOnly && st.State.ControlPlane.Source != "service-account" {
		accessToken, err := ensureControlPlaneAccess(st.State.ControlPlane.Origin, st)
		if err != nil {
			if remoteOnly || len(rows) == 0 {
				return a.fail(err)
			}
			fmt.Fprintf(a.Err, "asiri: remote list unavailable: %s\n", err)
		} else {
			remoteSecrets, err := listVisibleRemoteSecrets(st, st.State.ControlPlane.Origin, accessToken, includeInactive)
			if err != nil {
				if remoteOnly || len(rows) == 0 {
					return a.fail(err)
				}
				fmt.Fprintf(a.Err, "asiri: remote list unavailable: %s\n", err)
			} else {
				for _, secret := range remoteSecrets {
					if !includeInactive && secret.Status != "active" {
						continue
					}
					rowKey := listOutputRowKey(secret.Scope, secret.Name, secret.Version, includeInactive)
					row := rows[rowKey]
					if row.Path == "" {
						row = listRow{Path: shortSecretPath(secret.Scope, secret.Name), NameHash: store.HashSecretName(secret.Scope, secret.Name), Workspace: secret.WorkspaceSlug, WorkspaceID: secret.OrgID}
					}
					row.Version = maxInt(row.Version, secret.Version)
					row.VersionStatus = secret.Status
					row.HasRemote = true
					row.WorkspaceID = secret.OrgID
					row.Keys = remoteSecretKeyLabel(st, secret)
					row.RemoteStatus = "read-only"
					if secret.CanWrite {
						row.RemoteStatus = "writable"
					}
					if row.HasLocal {
						row.Status = "synced"
					} else {
						row.Status = "remote-only"
					}
					rows[rowKey] = row
				}
			}
		}
	}
	keys := make([]string, 0, len(rows))
	for key, row := range rows {
		if !matchesListFilter(row, filter, workspaceSet, statusFilter, localOnly, remoteOnly) {
			continue
		}
		keys = append(keys, key)
	}
	sort.Strings(keys)
	if len(keys) == 0 {
		if localOnly {
			fmt.Fprintln(a.Out, "No local secrets found.")
			return 0
		}
		fmt.Fprintln(a.Out, "No secrets found.")
		return 0
	}
	w := tabwriter.NewWriter(a.Out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "WORKSPACE\tPATH\tVER\tHASH\tSTATE\tVERSION_STATUS\tKEYS")
	actionSummary := newListActionSummary()
	for _, key := range keys {
		row := rows[key]
		status := row.Status
		if row.RemoteStatus != "" {
			status += "," + row.RemoteStatus
		}
		versionStatus := row.VersionStatus
		if versionStatus == "" {
			versionStatus = "active"
		}
		fmt.Fprintf(w, "%s\t%s\tv%d\t%s\t%s\t%s\t%s\n", row.Workspace, row.Path, row.Version, row.NameHash, status, versionStatus, row.Keys)
		actionSummary.Add(row)
	}
	if err := w.Flush(); err != nil {
		return a.fail(err)
	}
	actionSummary.Write(a.Out)
	return 0
}

func (a App) rotate(st *store.FileStore, args []string) int {
	if err := rejectServiceAccountLocalMutation(st); err != nil {
		return a.fail(err)
	}
	workspaceArg, remaining, err := splitWorkspaceFlag(args, "rotate", true)
	if err != nil {
		return a.fail(err)
	}
	if len(remaining) == 0 {
		return a.fail(errors.New("rotate requires scope/name"))
	}
	if err := rejectUnknownArgs(remaining[1:], "--stdin", "--value-file", "--value"); err != nil {
		return a.fail(err)
	}
	target, err := a.workspacePathTarget(st, workspaceArg, "rotate")
	if err != nil {
		return a.fail(err)
	}
	fullPath, err := workspacePrefixedPath(target, remaining[0], "rotate")
	if err != nil {
		return a.fail(err)
	}
	value, err := a.readSensitiveInput(remaining[1:], "Secret value", "--value-file", "--value")
	if err != nil {
		return a.fail(err)
	}
	secret, err := st.AddSecret(fullPath, value)
	if err != nil {
		return a.fail(err)
	}
	fmt.Fprintf(a.Out, "✓ Rotated %s in workspace %s to encrypted version %d (%s)\n", shortSecretPath(secret.Scope, secret.Name), target.Slug, secret.ActiveVersion, store.Mask(value))
	return 0
}

func (a App) remove(st *store.FileStore, args []string) int {
	workspaceArg, remaining, err := splitWorkspaceFlag(args, "rm", true)
	if err != nil {
		return a.fail(err)
	}
	if hasFlag(remaining, "--remote") {
		return a.remoteSecretDeleteForWorkspace(st, workspaceArg, removeStandaloneFlag(remaining, "--remote"), "rm --remote")
	}
	if err := rejectServiceAccountLocalMutation(st); err != nil {
		return a.fail(err)
	}
	if len(remaining) == 0 {
		return a.fail(errors.New("rm requires scope/name"))
	}
	if err := rejectUnknownArgs(remaining[1:]); err != nil {
		return a.fail(err)
	}
	target, err := a.workspacePathTarget(st, workspaceArg, "rm")
	if err != nil {
		return a.fail(err)
	}
	fullPath, err := workspacePrefixedPath(target, remaining[0], "rm")
	if err != nil {
		return a.fail(err)
	}
	if err := st.RemoveSecret(fullPath); err != nil {
		return a.fail(err)
	}
	fmt.Fprintf(a.Out, "✓ Removed %s from workspace %s\n", remaining[0], target.Slug)
	return 0
}

func (a App) secret(st *store.FileStore, args []string) int {
	if len(args) == 0 {
		return a.fail(errors.New("secret subcommand required"))
	}
	switch args[0] {
	case "delete":
		return a.remoteSecretDelete(st, args[1:])
	case "restore":
		return a.remoteSecretRestore(st, args[1:])
	default:
		return a.fail(fmt.Errorf("unknown secret command %q", args[0]))
	}
}

func (a App) remoteSecretDelete(st *store.FileStore, args []string) int {
	workspaceArg, remaining, err := splitWorkspaceFlag(args, "secret delete", true)
	if err != nil {
		return a.fail(err)
	}
	return a.remoteSecretDeleteForWorkspace(st, workspaceArg, remaining, "secret delete")
}

func (a App) remoteSecretDeleteForWorkspace(st *store.FileStore, workspaceArg string, remaining []string, command string) int {
	if err := rejectUnknownArgs(remaining, "--dry-run", "--confirm-token", "--where", "--remote-only-unwrapped", "--yes"); err != nil {
		return a.fail(err)
	}
	confirmToken, _, err := optionalFlagValue(remaining, "--confirm-token")
	if err != nil {
		return a.fail(err)
	}
	where, _, err := optionalFlagValue(remaining, "--where")
	if err != nil {
		return a.fail(err)
	}
	bulkRemoteOnlyUnwrapped := hasFlag(remaining, "--remote-only-unwrapped")
	bulkRemoteOnly := where == "remote-only"
	if where != "" && where != "remote-only" {
		return a.fail(errors.New("--where accepts only remote-only"))
	}
	if bulkRemoteOnly && bulkRemoteOnlyUnwrapped {
		return a.fail(errors.New("choose one remote-only mode"))
	}
	positionals := positionalArgsSkippingFlagValues(remaining, "--confirm-token", "--where")
	if (bulkRemoteOnly || bulkRemoteOnlyUnwrapped) && len(positionals) > 0 {
		return a.fail(fmt.Errorf("%s remote-only mode does not accept scope/name", command))
	}
	if !bulkRemoteOnly && !bulkRemoteOnlyUnwrapped && len(positionals) == 0 {
		return a.fail(fmt.Errorf("%s requires scope/name", command))
	}
	if !bulkRemoteOnly && !bulkRemoteOnlyUnwrapped && len(positionals) > 1 {
		return a.fail(fmt.Errorf("%s accepts one scope/name", command))
	}
	if err := st.RequireInitialized(); err != nil {
		return a.fail(err)
	}
	if st.State.ControlPlane == nil {
		return a.fail(errors.New("asiri is not linked to a control plane"))
	}
	if err := rejectServiceAccountControlPlaneMutation(st); err != nil {
		return a.fail(err)
	}
	accessToken, err := ensureControlPlaneAccess(st.State.ControlPlane.Origin, st)
	if err != nil {
		return a.fail(err)
	}
	target, accessToken, err := a.remoteWorkspaceTarget(st, accessToken, workspaceArg)
	if err != nil {
		return a.fail(err)
	}
	if bulkRemoteOnly || bulkRemoteOnlyUnwrapped {
		return a.remoteSecretDeleteRemoteOnly(st, accessToken, target, remoteDeleteBulkMode{RemoteOnly: bulkRemoteOnly, RemoteOnlyUnwrapped: bulkRemoteOnlyUnwrapped}, remoteDeleteConfirmationOptions{DryRun: hasFlag(remaining, "--dry-run"), Token: confirmToken, Yes: hasFlag(remaining, "--yes")})
	}
	shortPath := strings.Trim(positionals[0], "/")
	known := knownWorkspaceSlugs(st)
	known[target.Slug] = true
	fullPath, err := workspacePrefixedPath(workspacePathTarget{Slug: target.Slug, KnownSlugs: known}, shortPath, "secret delete")
	if err != nil {
		return a.fail(err)
	}
	scope, name, err := store.ParseSecretPath(fullPath)
	if err != nil {
		return a.fail(err)
	}
	remoteSecret, err := resolveActiveRemoteSecret(st, st.State.ControlPlane.Origin, accessToken, target, scope, name)
	if err != nil {
		return a.fail(err)
	}
	plan := newRemoteDeletePlan(target, []visibleRemoteSecretRecord{remoteSecret})
	deviceID := st.State.ControlPlane.DeviceID
	if deviceID == "" {
		return a.fail(errors.New("control-plane session is missing current device id"))
	}
	if hasFlag(remaining, "--dry-run") {
		if err := preflightRemoteSecretDelete(st, st.State.ControlPlane.Origin, remoteSecret.ID, remoteSecret.Version, deviceID, accessToken); err != nil {
			return a.fail(err)
		}
		printRemoteDeletePlan(a.Out, plan)
		return 0
	}
	if hasFlag(remaining, "--yes") {
		// Backward-compatible noninteractive confirmation for existing scripts.
	} else if confirmToken != "" {
		if err := verifyRemoteDeleteConfirmationToken(plan, confirmToken); err != nil {
			return a.fail(err)
		}
	} else {
		if err := a.confirmRemoteSecretDelete(shortPath, target.Slug, remoteSecret.Version); err != nil {
			return a.fail(err)
		}
	}
	deleted, err := deleteRemoteSecret(st, st.State.ControlPlane.Origin, remoteSecret.ID, remoteSecret.Version, deviceID, accessToken)
	if err != nil {
		return a.fail(err)
	}
	fmt.Fprintf(a.Out, "✓ Marked remote secret %s deleted in workspace %s (v%d)\n", shortPath, target.Slug, deleted.Version)
	return 0
}

func (a App) remoteSecretRestore(st *store.FileStore, args []string) int {
	workspaceArg, remaining, err := splitWorkspaceFlag(args, "secret restore", true)
	if err != nil {
		return a.fail(err)
	}
	if err := rejectUnknownArgs(remaining, "--yes"); err != nil {
		return a.fail(err)
	}
	positionals := positionalArgsSkippingFlagValues(remaining)
	if len(positionals) != 1 {
		return a.fail(errors.New("secret restore requires one scope/name"))
	}
	if err := st.RequireInitialized(); err != nil {
		return a.fail(err)
	}
	if st.State.ControlPlane == nil {
		return a.fail(errors.New("asiri is not linked to a control plane"))
	}
	if err := rejectServiceAccountControlPlaneMutation(st); err != nil {
		return a.fail(err)
	}
	accessToken, err := ensureControlPlaneAccess(st.State.ControlPlane.Origin, st)
	if err != nil {
		return a.fail(err)
	}
	target, accessToken, err := a.remoteWorkspaceTarget(st, accessToken, workspaceArg)
	if err != nil {
		return a.fail(err)
	}
	shortPath := strings.Trim(positionals[0], "/")
	known := knownWorkspaceSlugs(st)
	known[target.Slug] = true
	fullPath, err := workspacePrefixedPath(workspacePathTarget{Slug: target.Slug, KnownSlugs: known}, shortPath, "secret restore")
	if err != nil {
		return a.fail(err)
	}
	scope, name, err := store.ParseSecretPath(fullPath)
	if err != nil {
		return a.fail(err)
	}
	remoteSecret, err := resolveDeletedRemoteSecret(st, st.State.ControlPlane.Origin, accessToken, target, scope, name)
	if err != nil {
		return a.fail(err)
	}
	if !hasFlag(remaining, "--yes") {
		if err := a.confirmRemoteSecretRestore(shortPath, target.Slug, remoteSecret.Version); err != nil {
			return a.fail(err)
		}
	}
	deviceID := st.State.ControlPlane.DeviceID
	if deviceID == "" {
		return a.fail(errors.New("control-plane session is missing current device id"))
	}
	restored, err := restoreRemoteSecret(st, st.State.ControlPlane.Origin, remoteSecret.ID, remoteSecret.Version, deviceID, accessToken)
	if err != nil {
		return a.fail(err)
	}
	fmt.Fprintf(a.Out, "✓ Restored remote secret %s in workspace %s (v%d)\n", shortPath, target.Slug, restored.Version)
	return 0
}

type remoteDeleteBulkMode struct {
	RemoteOnly          bool
	RemoteOnlyUnwrapped bool
}

type remoteDeleteConfirmationOptions struct {
	DryRun bool
	Token  string
	Yes    bool
}

func (a App) remoteSecretDeleteRemoteOnly(st *store.FileStore, accessToken string, target remoteWorkspaceResponse, mode remoteDeleteBulkMode, confirm remoteDeleteConfirmationOptions) int {
	deviceID := st.State.ControlPlane.DeviceID
	if deviceID == "" {
		return a.fail(errors.New("control-plane session is missing current device id"))
	}
	secrets, err := listVisibleRemoteSecrets(st, st.State.ControlPlane.Origin, accessToken, false)
	if err != nil {
		return a.fail(err)
	}
	candidates := remoteOnlyDeleteCandidates(st, target, secrets, mode.RemoteOnlyUnwrapped)
	if len(candidates) == 0 {
		fmt.Fprintf(a.Out, "No remote-only active secrets found in workspace %s\n", target.Slug)
		return 0
	}
	plan := newRemoteDeletePlan(target, candidates)
	if confirm.DryRun {
		for _, secret := range candidates {
			if err := preflightRemoteSecretDelete(st, st.State.ControlPlane.Origin, secret.ID, secret.Version, deviceID, accessToken); err != nil {
				return a.fail(fmt.Errorf("failed to preflight delete %s: %w", shortSecretPath(secret.Scope, secret.Name), err))
			}
		}
		printRemoteDeletePlan(a.Out, plan)
		return 0
	}
	if confirm.Yes {
		// Backward-compatible noninteractive confirmation for existing scripts.
	} else if confirm.Token != "" {
		if err := verifyRemoteDeleteConfirmationToken(plan, confirm.Token); err != nil {
			return a.fail(err)
		}
	} else {
		label := "Remote-only active secrets"
		if mode.RemoteOnlyUnwrapped {
			label = "Remote-only unwrapped active secrets"
		}
		fmt.Fprintf(a.Out, "%s in workspace %s:\n", label, target.Slug)
		for _, secret := range candidates {
			fmt.Fprintf(a.Out, "  %s v%d\n", shortSecretPath(secret.Scope, secret.Name), secret.Version)
		}
		if err := a.confirmBulkRemoteSecretDelete(target.Slug, len(candidates)); err != nil {
			return a.fail(err)
		}
	}
	for _, secret := range candidates {
		if err := preflightRemoteSecretDelete(st, st.State.ControlPlane.Origin, secret.ID, secret.Version, deviceID, accessToken); err != nil {
			return a.fail(fmt.Errorf("failed to preflight delete %s: %w", shortSecretPath(secret.Scope, secret.Name), err))
		}
	}
	deletedRecords := []visibleRemoteSecretRecord{}
	for _, secret := range candidates {
		deletedSecret, err := deleteRemoteSecret(st, st.State.ControlPlane.Origin, secret.ID, secret.Version, deviceID, accessToken)
		if err != nil {
			if rollbackErr := rollbackRemoteSecretDeletes(st, st.State.ControlPlane.Origin, deletedRecords, &secret, deviceID, accessToken); rollbackErr != nil {
				return a.fail(fmt.Errorf("failed to delete %s: %w; rollback failed: %v", shortSecretPath(secret.Scope, secret.Name), err, rollbackErr))
			}
			return a.fail(fmt.Errorf("failed to delete %s after preflight; restored %d earlier delete(s) and checked failed target: %w", shortSecretPath(secret.Scope, secret.Name), len(deletedRecords), err))
		}
		deletedRecords = append(deletedRecords, deletedSecret)
	}
	finalLabel := "remote-only active"
	if mode.RemoteOnlyUnwrapped {
		finalLabel = "remote-only unwrapped active"
	}
	fmt.Fprintf(a.Out, "✓ Marked %d %s secret(s) deleted in workspace %s\n", len(deletedRecords), finalLabel, target.Slug)
	return 0
}

func rollbackRemoteSecretDeletes(st *store.FileStore, origin string, deleted []visibleRemoteSecretRecord, maybeDeleted *visibleRemoteSecretRecord, deviceID, accessToken string) error {
	var failures []string
	if maybeDeleted != nil {
		secret := *maybeDeleted
		if _, err := restoreRemoteSecret(st, origin, secret.ID, secret.Version, deviceID, accessToken); err != nil {
			if remoteRestoreAlreadyActive(err) {
				active, activeErr := remoteSecretRecordActive(st, origin, accessToken, secret.ID)
				if activeErr != nil {
					failures = append(failures, fmt.Sprintf("%s: %v; active check failed: %v", shortSecretPath(secret.Scope, secret.Name), err, activeErr))
				} else if !active {
					failures = append(failures, fmt.Sprintf("%s: %v; secret is not active after restore check", shortSecretPath(secret.Scope, secret.Name), err))
				}
			} else {
				failures = append(failures, fmt.Sprintf("%s: %v", shortSecretPath(secret.Scope, secret.Name), err))
			}
		}
	}
	for i := len(deleted) - 1; i >= 0; i-- {
		secret := deleted[i]
		if _, err := restoreRemoteSecret(st, origin, secret.ID, secret.Version, deviceID, accessToken); err != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", shortSecretPath(secret.Scope, secret.Name), err))
		}
	}
	if len(failures) > 0 {
		return errors.New(strings.Join(failures, "; "))
	}
	return nil
}

func remoteRestoreAlreadyActive(err error) bool {
	return strings.Contains(err.Error(), "HTTP 409")
}

func remoteSecretRecordActive(st *store.FileStore, origin, accessToken, secretID string) (bool, error) {
	secrets, err := listVisibleRemoteSecrets(st, origin, accessToken, true)
	if err != nil {
		return false, err
	}
	for _, secret := range secrets {
		if secret.ID == secretID {
			return secret.Status == "active", nil
		}
	}
	return false, errors.New("remote secret not found")
}

func (a App) confirmRemoteSecretDelete(shortPath, workspace string, version int) error {
	confirmation := fmt.Sprintf("delete %s %s v%d", workspace, shortPath, version)
	fmt.Fprintf(a.Out, "Type %s to delete remote secret: ", confirmation)
	reader := bufio.NewReader(a.In)
	value, err := reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	value = strings.TrimSuffix(value, "\n")
	value = strings.TrimSuffix(value, "\r")
	if value != confirmation {
		return errors.New("confirmation did not match; remote secret was not deleted")
	}
	return nil
}

func (a App) confirmBulkRemoteSecretDelete(workspace string, count int) error {
	confirmation := fmt.Sprintf("delete %s %d", workspace, count)
	fmt.Fprintf(a.Out, "Type %s to delete these remote secrets: ", confirmation)
	reader := bufio.NewReader(a.In)
	value, err := reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	value = strings.TrimSuffix(value, "\n")
	value = strings.TrimSuffix(value, "\r")
	if value != confirmation {
		return errors.New("confirmation did not match; remote secrets were not deleted")
	}
	return nil
}

func (a App) confirmRemoteSecretRestore(shortPath, workspace string, version int) error {
	confirmation := fmt.Sprintf("restore %s %s v%d", workspace, shortPath, version)
	fmt.Fprintf(a.Out, "Type %s to restore remote secret: ", confirmation)
	reader := bufio.NewReader(a.In)
	value, err := reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	value = strings.TrimSuffix(value, "\n")
	value = strings.TrimSuffix(value, "\r")
	if value != confirmation {
		return errors.New("confirmation did not match; remote secret was not restored")
	}
	return nil
}

type remoteDeletePlan struct {
	WorkspaceID   string
	WorkspaceSlug string
	ExpiresAt     time.Time
	Secrets       []remoteDeletePlanSecret
}

type remoteDeletePlanSecret struct {
	ID      string
	Scope   string
	Name    string
	Version int
}

func newRemoteDeletePlan(target remoteWorkspaceResponse, secrets []visibleRemoteSecretRecord) remoteDeletePlan {
	planSecrets := make([]remoteDeletePlanSecret, 0, len(secrets))
	for _, secret := range secrets {
		planSecrets = append(planSecrets, remoteDeletePlanSecret{ID: secret.ID, Scope: secret.Scope, Name: secret.Name, Version: secret.Version})
	}
	sort.Slice(planSecrets, func(i, j int) bool {
		if planSecrets[i].ID == planSecrets[j].ID {
			return planSecrets[i].Version < planSecrets[j].Version
		}
		return planSecrets[i].ID < planSecrets[j].ID
	})
	return remoteDeletePlan{WorkspaceID: target.ID, WorkspaceSlug: target.Slug, ExpiresAt: time.Now().UTC().Add(15 * time.Minute), Secrets: planSecrets}
}

func printRemoteDeletePlan(out io.Writer, plan remoteDeletePlan) {
	fmt.Fprintf(out, "Remote delete dry run for workspace %s:\n", plan.WorkspaceSlug)
	for _, secret := range plan.Secrets {
		fmt.Fprintf(out, "  %s v%d (%s)\n", shortSecretPath(secret.Scope, secret.Name), secret.Version, secret.ID)
	}
	fmt.Fprintf(out, "Confirmation token: %s\n", remoteDeleteConfirmationToken(plan))
	fmt.Fprintf(out, "Token expires at: %s\n", plan.ExpiresAt.Format(time.RFC3339))
	fmt.Fprintln(out, "No remote secrets were deleted.")
}

func remoteDeleteConfirmationToken(plan remoteDeletePlan) string {
	digest := sha256.Sum256([]byte(remoteDeletePlanDigestInput(plan)))
	return fmt.Sprintf("del_%d_%s", plan.ExpiresAt.Unix(), hex.EncodeToString(digest[:])[:24])
}

func verifyRemoteDeleteConfirmationToken(plan remoteDeletePlan, token string) error {
	expiresAt, err := remoteDeleteTokenExpiry(token)
	if err != nil {
		return err
	}
	if time.Now().UTC().After(expiresAt) {
		return errors.New("confirmation token expired; rerun remote delete dry-run")
	}
	plan.ExpiresAt = expiresAt
	if token != remoteDeleteConfirmationToken(plan) {
		return errors.New("confirmation token did not match current remote delete plan; rerun dry-run")
	}
	return nil
}

func remoteDeleteTokenExpiry(token string) (time.Time, error) {
	parts := strings.Split(token, "_")
	if len(parts) != 3 || parts[0] != "del" || parts[2] == "" {
		return time.Time{}, errors.New("invalid confirmation token; run remote delete dry-run first")
	}
	expiresUnix, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil || expiresUnix <= 0 {
		return time.Time{}, errors.New("invalid confirmation token; run remote delete dry-run first")
	}
	return time.Unix(expiresUnix, 0).UTC(), nil
}

func remoteDeletePlanDigestInput(plan remoteDeletePlan) string {
	var b strings.Builder
	fmt.Fprintf(&b, "asiri-remote-delete-v1\n%s\n%s\n%d\n", plan.WorkspaceID, plan.WorkspaceSlug, plan.ExpiresAt.Unix())
	for _, secret := range plan.Secrets {
		fmt.Fprintf(&b, "%s\n%s\n%s\n%d\n", secret.ID, secret.Scope, secret.Name, secret.Version)
	}
	return b.String()
}

func (a App) grant(st *store.FileStore, args []string) int {
	if err := rejectServiceAccountLocalMutation(st); err != nil {
		return a.fail(err)
	}
	workspaceArg, remaining, err := splitWorkspaceFlag(args, "grant", true)
	if err != nil {
		return a.fail(err)
	}
	if len(remaining) < 2 {
		return a.fail(errors.New("grant requires subject and scope/name"))
	}
	actions := []string{}
	if hasFlag(remaining[2:], "--inject-only") {
		actions = append(actions, "inject")
	}
	if hasFlag(remaining[2:], "--read") {
		actions = append(actions, "read")
	}
	if hasFlag(remaining[2:], "--mount") {
		actions = append(actions, "mount")
	}
	if hasFlag(remaining[2:], "--broker") {
		actions = append(actions, "broker")
	}
	if len(actions) == 0 {
		return a.fail(errors.New("grant requires --inject-only, --read, --mount, or --broker"))
	}
	if err := rejectUnknownArgs(remaining[2:], "--inject-only", "--read", "--mount", "--broker"); err != nil {
		return a.fail(err)
	}
	target, err := a.workspacePathTarget(st, workspaceArg, "grant")
	if err != nil {
		return a.fail(err)
	}
	fullPath, err := workspacePrefixedPath(target, remaining[1], "grant")
	if err != nil {
		return a.fail(err)
	}
	policy, err := st.Grant(remaining[0], fullPath, actions)
	if err != nil {
		return a.fail(err)
	}
	fmt.Fprintf(a.Out, "✓ Policy %s grants %s %s on %s/%s\n", policy.ID, policy.Subject, strings.Join(policy.Actions, ","), policy.ScopePattern, policy.SecretPattern)
	return 0
}

func (a App) deny(st *store.FileStore, args []string) int {
	if err := rejectServiceAccountLocalMutation(st); err != nil {
		return a.fail(err)
	}
	workspaceArg, remaining, err := splitWorkspaceFlag(args, "deny", true)
	if err != nil {
		return a.fail(err)
	}
	if len(remaining) < 2 {
		return a.fail(errors.New("deny requires subject and scope pattern"))
	}
	if err := rejectUnknownArgs(remaining[2:]); err != nil {
		return a.fail(err)
	}
	target, err := a.workspacePathTarget(st, workspaceArg, "deny")
	if err != nil {
		return a.fail(err)
	}
	pattern, err := workspacePrefixedPattern(target, remaining[1], "deny")
	if err != nil {
		return a.fail(err)
	}
	policy, err := st.Deny(remaining[0], pattern)
	if err != nil {
		return a.fail(err)
	}
	fmt.Fprintf(a.Out, "✓ Policy %s requires owner approval for %s on %s/%s\n", policy.ID, policy.Subject, policy.ScopePattern, policy.SecretPattern)
	return 0
}

func (a App) policy(st *store.FileStore, args []string) int {
	if len(args) == 0 || args[0] != "list" {
		return a.fail(errors.New("policy list is the supported policy subcommand"))
	}
	if err := st.RequireInitialized(); err != nil {
		return a.fail(err)
	}
	workspaceFilters, remaining, err := splitWorkspaceFilters(args[1:], "policy list")
	if err != nil {
		return a.fail(err)
	}
	if err := rejectUnknownArgs(remaining); err != nil {
		return a.fail(err)
	}
	workspaceSet, err := a.workspaceFilterSet(st, workspaceFilters, "policy list")
	if err != nil {
		return a.fail(err)
	}
	for _, policy := range st.State.Policies {
		if len(workspaceSet) > 0 && !workspaceSet[store.WorkspacePrefix(policy.ScopePattern)] {
			continue
		}
		fmt.Fprintf(a.Out, "%s\t%s\t%s/%s\t%s\t%s\n", policy.ID, policy.Subject, policy.ScopePattern, policy.SecretPattern, strings.Join(policy.Actions, ","), policy.ApprovalMode)
	}
	return 0
}

func (a App) run(st *store.FileStore, args []string) int {
	if err := st.RequireInitialized(); err != nil {
		return a.fail(err)
	}
	workspaceArg, remaining, err := splitWorkspaceFlag(args, "run", true)
	if err != nil {
		return a.fail(err)
	}
	target, err := a.workspacePathTarget(st, workspaceArg, "run")
	if err != nil {
		return a.fail(err)
	}
	if runUsesUnsafeArgv(remaining) {
		if runUsesExplicitEnvMapping(remaining) {
			return a.fail(errors.New("run cannot combine --unsafe-argv with --env"))
		}
		return a.runWithUnsafeArgv(st, target, remaining)
	}
	if runUsesExplicitEnvMapping(remaining) {
		return a.runWithEnvMappings(st, target, remaining)
	}
	for _, arg := range remaining {
		if strings.Contains(arg, "asiri://") {
			return a.fail(errors.New("asiri:// argument substitution is disabled; use --unsafe-argv"))
		}
	}
	return a.fail(errors.New("run requires --env or --unsafe-argv"))
}

func runUsesUnsafeArgv(args []string) bool {
	return runHasLeadingOption(args, "--unsafe-argv")
}

func runUsesExplicitEnvMapping(args []string) bool {
	return runHasLeadingOption(args, "--env", "--map")
}

func runHasLeadingOption(args []string, targets ...string) bool {
	target := map[string]bool{}
	for _, item := range targets {
		target[item] = true
	}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			return false
		}
		if target[arg] {
			return true
		}
		switch arg {
		case "--agent", "--env", "--map", "--workspace", "-w":
			i++
		case "--unsafe-argv":
		default:
			return false
		}
	}
	return false
}

func (a App) runWithEnvMappings(st *store.FileStore, target workspacePathTarget, remaining []string) int {
	var mappings []string
	var agent string
	agentExplicit := false
	cmdIndex := -1
	for i := 0; i < len(remaining); i++ {
		switch remaining[i] {
		case "--env", "--map":
			if i+1 >= len(remaining) {
				return a.fail(errors.New("--env requires NAME=scope/name"))
			}
			mappings = append(mappings, remaining[i+1])
			i++
		case "--agent":
			if i+1 >= len(remaining) {
				return a.fail(errors.New("--agent requires a subject"))
			}
			agentExplicit = true
			agent = remaining[i+1]
			i++
		case "--":
			cmdIndex = i + 1
			i = len(remaining)
		default:
			if strings.HasPrefix(remaining[i], "--") {
				return a.fail(fmt.Errorf("unknown run option %s", remaining[i]))
			}
		}
	}
	if len(mappings) == 0 {
		return a.fail(errors.New("run requires at least one explicit --env NAME=scope/name mapping"))
	}
	if cmdIndex < 0 || cmdIndex >= len(remaining) {
		return a.fail(errors.New("run requires -- <command...>"))
	}
	agent, runtimeType, err := runtimeSubject(st, agent, filepath.Base(remaining[cmdIndex]), agentExplicit)
	if err != nil {
		return a.fail(err)
	}
	type envResolvedSecret struct {
		resolvedSecret
		EnvName string
	}
	env := os.Environ()
	resolved := []envResolvedSecret{}
	for _, mapping := range mappings {
		name, path, ok := strings.Cut(mapping, "=")
		if !ok || name == "" || path == "" {
			return a.fail(fmt.Errorf("invalid env mapping %q", mapping))
		}
		fullPath, err := workspacePrefixedPath(target, path, "run")
		if err != nil {
			return a.fail(err)
		}
		allowed, reason := st.CheckPolicy(agent, fullPath, "inject")
		if !allowed {
			a.auditDeniedSecretUse(st, agent, runtimeType, fullPath, reason)
			_ = st.Save()
			a.syncRuntimeAuditBestEffort(st)
			return a.fail(fmt.Errorf("%s: %s cannot inject %s", reason, agent, fullPath))
		}
		value, secret, err := st.GetSecret(fullPath)
		if err != nil {
			return a.fail(err)
		}
		env = append(env, name+"="+value)
		resolved = append(resolved, envResolvedSecret{
			resolvedSecret: resolvedSecret{Path: fullPath, Scope: secret.Scope, Name: secret.Name, Hash: secret.NameHash, Value: value},
			EnvName:        name,
		})
	}
	for _, secret := range resolved {
		st.Audit(agent, "secret_injected", "allowed", secret.Scope, secret.Hash, "explicit env mapping", runtimeAuditMetadata(st, secret.Scope, agent, runtimeType, map[string]string{"env": secret.EnvName}))
	}
	if err := st.Save(); err != nil {
		return a.fail(err)
	}
	a.syncRuntimeAuditBestEffort(st)
	return a.execChild(remaining[cmdIndex], remaining[cmdIndex+1:], env)
}

func (a App) runWithUnsafeArgv(st *store.FileStore, target workspacePathTarget, remaining []string) int {
	agent, agentExplicit, commandArgs, err := parseUnsafeArgvArgs(remaining)
	if err != nil {
		return a.fail(err)
	}
	agent, runtimeType, err := runtimeSubject(st, agent, filepath.Base(commandArgs[0]), agentExplicit)
	if err != nil {
		return a.fail(err)
	}
	resolvedArgs := make([]string, len(commandArgs))
	resolvedArgs[0] = commandArgs[0]
	if strings.Contains(commandArgs[0], "asiri://") {
		return a.fail(errors.New("unsafe argv substitution is not allowed in the command name"))
	}
	resolvedSecrets := []resolvedSecret{}
	for i, arg := range commandArgs[1:] {
		resolved, err := a.resolveUnsafeArgvArg(st, target, agent, runtimeType, arg, &resolvedSecrets)
		if err != nil {
			_ = st.Save()
			a.syncRuntimeAuditBestEffort(st)
			return a.fail(err)
		}
		resolvedArgs[i+1] = resolved
	}
	for _, secret := range resolvedSecrets {
		st.Audit(agent, "secret_unsafe_argv_injected", "allowed", secret.Scope, secret.Hash, "unsafe argv materialization", runtimeAuditMetadata(st, secret.Scope, agent, runtimeType, map[string]string{"mode": "unsafe-argv"}))
	}
	if err := st.Save(); err != nil {
		return a.fail(err)
	}
	a.syncRuntimeAuditBestEffort(st)
	return a.execChild(resolvedArgs[0], resolvedArgs[1:], os.Environ())
}

func parseUnsafeArgvArgs(args []string) (string, bool, []string, error) {
	agent := ""
	agentExplicit := false
	unsafe := false
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--unsafe-argv":
			unsafe = true
		case "--agent":
			if i+1 >= len(args) {
				return "", false, nil, errors.New("--agent requires a subject")
			}
			agent = store.NormalizeSubjectLabel(args[i+1])
			agentExplicit = true
			i++
		case "--":
			if i+1 >= len(args) {
				return "", false, nil, errors.New("run requires a command")
			}
			if !unsafe {
				return "", false, nil, errors.New("--unsafe-argv is required for argument substitution")
			}
			return agent, agentExplicit, args[i+1:], nil
		default:
			if strings.HasPrefix(args[i], "--") {
				return "", false, nil, fmt.Errorf("unknown run option %s", args[i])
			}
			if !unsafe {
				return "", false, nil, errors.New("--unsafe-argv is required for argument substitution")
			}
			return agent, agentExplicit, args[i:], nil
		}
	}
	return "", false, nil, errors.New("run requires a command")
}

func (a App) resolveUnsafeArgvArg(st *store.FileStore, target workspacePathTarget, agent, runtimeType, arg string, resolvedSecrets *[]resolvedSecret) (string, error) {
	if !strings.Contains(arg, "asiri://") {
		return arg, nil
	}
	matches := asiriRefPattern.FindAllStringIndex(arg, -1)
	if len(matches) == 0 {
		return "", errors.New("invalid asiri:// reference; expected asiri://scope/name")
	}
	for offset := 0; ; {
		index := strings.Index(arg[offset:], "asiri://")
		if index < 0 {
			break
		}
		start := offset + index
		covered := false
		for _, match := range matches {
			if match[0] == start {
				covered = true
				break
			}
		}
		if !covered {
			return "", errors.New("invalid asiri:// reference; expected asiri://scope/name")
		}
		offset = start + len("asiri://")
	}
	var resolveErr error
	resolved := asiriRefPattern.ReplaceAllStringFunc(arg, func(ref string) string {
		if resolveErr != nil {
			return ref
		}
		value, err := a.resolveUnsafeArgvSecret(st, target, agent, runtimeType, strings.TrimPrefix(ref, "asiri://"), resolvedSecrets)
		if err != nil {
			resolveErr = err
			return ref
		}
		return value
	})
	if resolveErr != nil {
		return "", resolveErr
	}
	return resolved, nil
}

func (a App) resolveUnsafeArgvSecret(st *store.FileStore, target workspacePathTarget, agent, runtimeType, shortPath string, resolvedSecrets *[]resolvedSecret) (string, error) {
	fullPath, err := workspacePrefixedPath(target, shortPath, "run")
	if err != nil {
		return "", err
	}
	allowed, reason := st.CheckPolicy(agent, fullPath, "inject")
	scope, name, parseErr := store.ParseSecretPath(fullPath)
	metadataScope := ""
	if parseErr == nil {
		metadataScope = scope
	}
	metadata := runtimeAuditMetadata(st, metadataScope, agent, runtimeType, map[string]string{"mode": "unsafe-argv"})
	if !allowed {
		if parseErr == nil {
			st.Audit(agent, "secret_unsafe_argv_injected", "denied", scope, store.HashSecretName(scope, name), reason, metadata)
		} else {
			st.Audit(agent, "secret_unsafe_argv_injected", "denied", "", "", reason, metadata)
		}
		return "", fmt.Errorf("%s: %s cannot inject %s", reason, agent, fullPath)
	}
	value, secret, err := st.GetSecret(fullPath)
	if err != nil {
		return "", err
	}
	*resolvedSecrets = append(*resolvedSecrets, resolvedSecret{Path: fullPath, Scope: secret.Scope, Name: secret.Name, Hash: secret.NameHash, Value: value})
	return value, nil
}

func (a App) auditDeniedSecretUse(st *store.FileStore, agent, runtimeType, fullPath, reason string) {
	scope, name, err := store.ParseSecretPath(fullPath)
	if err != nil {
		metadata := runtimeAuditMetadata(st, "", agent, runtimeType, nil)
		st.Audit(agent, "secret_injected", "denied", "", "", reason, metadata)
		return
	}
	metadata := runtimeAuditMetadata(st, scope, agent, runtimeType, nil)
	st.Audit(agent, "secret_injected", "denied", scope, store.HashSecretName(scope, name), reason, metadata)
}

func (a App) execChild(name string, args []string, env []string) int {
	command := exec.Command(name, args...)
	command.Env = env
	command.Stdout = a.Out
	command.Stderr = a.Err
	command.Stdin = os.Stdin
	if err := command.Run(); err != nil {
		return a.fail(err)
	}
	return 0
}

type resolvedSecret struct {
	Path  string
	Scope string
	Name  string
	Hash  string
	Value string
}

func (a App) env(st *store.FileStore, args []string) int {
	if err := st.RequireInitialized(); err != nil {
		return a.fail(err)
	}
	workspaceArg, remaining, err := splitWorkspaceFlag(args, "env", true)
	if err != nil {
		return a.fail(err)
	}
	target, err := a.workspacePathTarget(st, workspaceArg, "env")
	if err != nil {
		return a.fail(err)
	}
	agentExplicit := hasFlag(remaining, "--agent")
	agent, pathSpec, commandArgs, err := parseSecretCommandArgs("env", remaining, false)
	if err != nil {
		return a.fail(err)
	}
	pathSpec, err = workspacePrefixedSelection(target, pathSpec, "env")
	if err != nil {
		return a.fail(err)
	}
	agent, runtimeType, err := runtimeSubject(st, agent, filepath.Base(commandArgs[0]), agentExplicit)
	if err != nil {
		return a.fail(err)
	}
	secrets, err := a.resolveSecretSelection(st, pathSpec, agent, runtimeType, "inject", "secret_env_exported")
	if err != nil {
		_ = st.Save()
		a.syncRuntimeAuditBestEffort(st)
		return a.fail(err)
	}
	envAdds := make(map[string]string, len(secrets))
	for _, secret := range secrets {
		if !envNamePattern.MatchString(secret.Name) {
			return a.fail(fmt.Errorf("secret name %q is not a valid environment variable name", secret.Name))
		}
		if _, exists := envAdds[secret.Name]; exists {
			return a.fail(fmt.Errorf("environment variable %s would collide", secret.Name))
		}
		envAdds[secret.Name] = secret.Value
	}
	env := os.Environ()
	for name, value := range envAdds {
		env = append(env, name+"="+value)
	}
	for _, secret := range secrets {
		st.Audit(agent, "secret_env_exported", "allowed", secret.Scope, secret.Hash, "inject materialization", runtimeAuditMetadata(st, secret.Scope, agent, runtimeType, nil))
	}
	if err := st.Save(); err != nil {
		return a.fail(err)
	}
	a.syncRuntimeAuditBestEffort(st)
	return a.execChild(commandArgs[0], commandArgs[1:], env)
}

func (a App) mount(st *store.FileStore, args []string) int {
	if err := st.RequireInitialized(); err != nil {
		return a.fail(err)
	}
	workspaceArg, remaining, err := splitWorkspaceFlag(args, "mount", true)
	if err != nil {
		return a.fail(err)
	}
	target, err := a.workspacePathTarget(st, workspaceArg, "mount")
	if err != nil {
		return a.fail(err)
	}
	agentExplicit := hasFlag(remaining, "--agent")
	agent, pathSpec, commandArgs, err := parseSecretCommandArgs("mount", remaining, true)
	if err != nil {
		return a.fail(err)
	}
	agent, runtimeType, err := runtimeSubject(st, agent, filepath.Base(commandArgs[0]), agentExplicit)
	if err != nil {
		return a.fail(err)
	}
	pathPart, explicitDest, hasExplicitDest := strings.Cut(pathSpec, ":")
	pathPart, err = workspacePrefixedSelection(target, pathPart, "mount")
	if err != nil {
		return a.fail(err)
	}
	secrets, err := a.resolveSecretSelection(st, pathPart, agent, runtimeType, "mount", "secret_mounted")
	if err != nil {
		_ = st.Save()
		a.syncRuntimeAuditBestEffort(st)
		return a.fail(err)
	}
	mountDir := mountDirFromArgs(remaining)
	createdTempDir := false
	if mountDir == "" && !hasExplicitDest {
		mountDir, err = os.MkdirTemp("", "asiri-secrets-*")
		if err != nil {
			return a.fail(err)
		}
		createdTempDir = true
	} else if mountDir != "" {
		if err := os.MkdirAll(mountDir, 0o700); err != nil {
			return a.fail(err)
		}
		_ = os.Chmod(mountDir, 0o700)
	}
	cleanupPaths := []string{}
	if createdTempDir {
		defer os.RemoveAll(mountDir)
	} else {
		defer func() {
			for _, path := range cleanupPaths {
				_ = os.Remove(path)
			}
		}()
	}
	if hasExplicitDest && len(secrets) != 1 {
		return a.fail(errors.New("explicit mount destination requires an exact single secret path"))
	}
	seenTargets := map[string]bool{}
	for _, secret := range secrets {
		target := ""
		if hasExplicitDest {
			if err := validateExplicitMountDest(explicitDest); err != nil {
				return a.fail(err)
			}
			target = explicitDest
			if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
				return a.fail(err)
			}
		} else {
			if err := validateSecretFileName(secret.Name); err != nil {
				return a.fail(err)
			}
			target = filepath.Join(mountDir, secret.Name)
		}
		if seenTargets[target] {
			return a.fail(fmt.Errorf("mount target %s would collide", target))
		}
		seenTargets[target] = true
		if err := writeExclusiveSecretFile(target, []byte(secret.Value)); err != nil {
			return a.fail(err)
		}
		cleanupPaths = append(cleanupPaths, target)
	}
	for _, secret := range secrets {
		st.Audit(agent, "secret_mounted", "allowed", secret.Scope, secret.Hash, "mount materialization", runtimeAuditMetadata(st, secret.Scope, agent, runtimeType, nil))
	}
	env := os.Environ()
	if !hasExplicitDest || mountDir != "" {
		env = append(env, "ASIRI_SECRETS_DIR="+mountDir)
	}
	if err := st.Save(); err != nil {
		return a.fail(err)
	}
	a.syncRuntimeAuditBestEffort(st)
	return a.execChild(commandArgs[0], commandArgs[1:], env)
}

func parseSecretCommandArgs(command string, args []string, allowDir bool) (string, string, []string, error) {
	agent := ""
	pathSpec := ""
	cmdIndex := -1
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--agent":
			if i+1 >= len(args) {
				return "", "", nil, errors.New("--agent requires a subject")
			}
			agent = store.NormalizeSubjectLabel(args[i+1])
			i++
		case "--dir":
			if !allowDir {
				return "", "", nil, fmt.Errorf("%s does not support --dir", command)
			}
			if i+1 >= len(args) {
				return "", "", nil, errors.New("--dir requires a directory")
			}
			i++
		case "--":
			cmdIndex = i + 1
			i = len(args)
		default:
			if strings.HasPrefix(args[i], "--") {
				return "", "", nil, fmt.Errorf("unknown %s option %s", command, args[i])
			}
			if pathSpec == "" {
				pathSpec = args[i]
			} else {
				return "", "", nil, fmt.Errorf("%s accepts one scope or secret path before --", command)
			}
		}
	}
	if pathSpec == "" {
		return "", "", nil, fmt.Errorf("%s requires a scope or secret path", command)
	}
	if cmdIndex < 0 || cmdIndex >= len(args) {
		return "", "", nil, fmt.Errorf("%s requires -- <command...>", command)
	}
	return store.NormalizeSubjectLabel(agent), pathSpec, args[cmdIndex:], nil
}

func mountDirFromArgs(args []string) string {
	for i := 0; i < len(args)-1; i++ {
		if args[i] == "--" {
			return ""
		}
		if args[i] == "--dir" {
			return args[i+1]
		}
	}
	return ""
}

func (a App) resolveSecretSelection(st *store.FileStore, pathSpec, agent, runtimeType, action, auditAction string) ([]resolvedSecret, error) {
	pathSpec = strings.Trim(pathSpec, "/")
	if pathSpec == "" {
		return nil, errors.New("secret path or scope is required")
	}
	if scope, name, err := store.ParseSecretPath(pathSpec); err == nil {
		key := store.SecretKey(scope, name)
		if _, ok := st.State.Secrets[key]; ok {
			secret, err := a.resolveOneSecret(st, agent, runtimeType, action, auditAction, pathSpec)
			if err != nil {
				return nil, err
			}
			return []resolvedSecret{secret}, nil
		}
	}
	keys := make([]string, 0)
	for key, secret := range st.State.Secrets {
		if secret.Scope == pathSpec {
			keys = append(keys, key)
		}
	}
	if len(keys) == 0 {
		if allowHint, allowScopeHint := remoteHintPolicy(st, pathSpec, agent, action); allowHint {
			if hint := a.remoteSelectionHint(st, pathSpec, agent, action, allowScopeHint); hint != "" {
				return nil, errors.New(hint)
			}
		}
		return nil, fmt.Errorf("no exact secret or direct child secrets found for %s", pathSpec)
	}
	sort.Strings(keys)
	resolved := make([]resolvedSecret, 0, len(keys))
	for _, key := range keys {
		secret := st.State.Secrets[key]
		item, err := a.resolveOneSecret(st, agent, runtimeType, action, auditAction, secret.Scope+"/"+secret.Name)
		if err != nil {
			return nil, err
		}
		resolved = append(resolved, item)
	}
	return resolved, nil
}

func remoteHintPolicy(st *store.FileStore, pathSpec, agent, action string) (bool, bool) {
	if agent == "" {
		return true, true
	}
	if allowed, _ := st.CheckPolicy(agent, pathSpec, action); allowed {
		return true, false
	}
	if remoteScopeHintPolicyAllowed(st, pathSpec, agent, action) {
		return true, true
	}
	return false, false
}

func remoteScopeHintPolicyAllowed(st *store.FileStore, pathSpec, agent, action string) bool {
	agent = store.NormalizeSubjectLabel(agent)
	pathSpec = strings.Trim(pathSpec, "/")
	now := time.Now().UTC()
	for _, policy := range st.State.Policies {
		if policy.ExpiresAt != nil && !policy.ExpiresAt.After(now) {
			continue
		}
		if policy.Subject == agent && store.MatchPattern(policy.ScopePattern, pathSpec) && policy.SecretPattern == "*" && cliStringSliceContains(policy.Actions, "deny") {
			return false
		}
	}
	for _, policy := range st.State.Policies {
		if policy.ExpiresAt != nil && !policy.ExpiresAt.After(now) {
			continue
		}
		if policy.Subject == agent && policy.ApprovalMode == "none" && store.MatchPattern(policy.ScopePattern, pathSpec) && policy.SecretPattern == "*" && cliStringSliceContains(policy.Actions, action) {
			return true
		}
	}
	return false
}

func cliStringSliceContains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func (a App) remoteSelectionHint(st *store.FileStore, pathSpec, agent, action string, allowScopeHint bool) string {
	if st.State.ControlPlane == nil || st.State.ControlPlane.Origin == "" {
		return ""
	}
	accessToken, err := ensureControlPlaneAccess(st.State.ControlPlane.Origin, st)
	if err != nil {
		return ""
	}
	secrets, err := listVisibleRemoteSecrets(st, st.State.ControlPlane.Origin, accessToken, false)
	if err != nil {
		return ""
	}
	matches := []visibleRemoteSecretRecord{}
	exactMatch := false
	if scope, name, err := store.ParseSecretPath(pathSpec); err == nil {
		for _, secret := range secrets {
			if secret.Status == "active" && secret.Scope == scope && secret.Name == name && remoteHintSecretAllowed(st, secret, agent, action) {
				matches = append(matches, secret)
			}
		}
		exactMatch = len(matches) > 0
	}
	if len(matches) == 0 && allowScopeHint {
		for _, secret := range secrets {
			if secret.Status == "active" && secret.Scope == pathSpec && remoteHintSecretAllowed(st, secret, agent, action) {
				matches = append(matches, secret)
			}
		}
	}
	if len(matches) == 0 {
		return ""
	}
	workspace := matches[0].WorkspaceSlug
	if workspace == "" {
		workspace = store.WorkspacePrefix(matches[0].Scope)
	}
	if exactMatch && len(matches) == 1 {
		secret := matches[0]
		if secret.WrappedToCurrentDevice != nil && *secret.WrappedToCurrentDevice {
			return fmt.Sprintf("secret %s exists remotely in workspace %s and is wrapped to this device, but it is not in the local vault; run `asiri pull --workspace %s` and retry", store.SecretKey(secret.Scope, secret.Name), workspace, workspace)
		}
		return fmt.Sprintf("secret %s exists remotely in workspace %s, but it is not locally usable on this device; run `asiri rewrap --workspace %s` from a device that can use it, then run `asiri pull --workspace %s` here", store.SecretKey(secret.Scope, secret.Name), workspace, workspace, workspace)
	}
	if allVisibleMatchesWrappedToCurrentDevice(matches) {
		return fmt.Sprintf("%d direct child secret(s) exist remotely under %s in workspace %s and are wrapped to this device, but are not in the local vault; run `asiri pull --workspace %s` and retry", len(matches), pathSpec, workspace, workspace)
	}
	return fmt.Sprintf("%d direct child secret(s) exist remotely under %s in workspace %s, but are not locally usable on this device; run `asiri rewrap --workspace %s` from a device that can use them, then run `asiri pull --workspace %s` here", len(matches), pathSpec, workspace, workspace, workspace)
}

func remoteHintSecretAllowed(st *store.FileStore, secret visibleRemoteSecretRecord, agent, action string) bool {
	allowed, _ := st.CheckPolicy(agent, store.SecretKey(secret.Scope, secret.Name), action)
	return allowed
}

func allVisibleMatchesWrappedToCurrentDevice(secrets []visibleRemoteSecretRecord) bool {
	for _, secret := range secrets {
		if secret.WrappedToCurrentDevice == nil || !*secret.WrappedToCurrentDevice {
			return false
		}
	}
	return true
}

func (a App) resolveOneSecret(st *store.FileStore, agent, runtimeType, action, auditAction, fullPath string) (resolvedSecret, error) {
	allowed, reason := st.CheckPolicy(agent, fullPath, action)
	scope, name, parseErr := store.ParseSecretPath(fullPath)
	metadataScope := ""
	if parseErr == nil {
		metadataScope = scope
	}
	metadata := runtimeAuditMetadata(st, metadataScope, agent, runtimeType, map[string]string{"mode": action})
	if !allowed {
		if parseErr == nil {
			st.Audit(agent, auditAction, "denied", scope, store.HashSecretName(scope, name), reason, metadata)
		} else {
			st.Audit(agent, auditAction, "denied", "", "", reason, metadata)
		}
		return resolvedSecret{}, fmt.Errorf("%s: %s cannot %s %s", reason, agent, action, fullPath)
	}
	value, secret, err := st.GetSecret(fullPath)
	if err != nil {
		return resolvedSecret{}, err
	}
	return resolvedSecret{Path: fullPath, Scope: secret.Scope, Name: secret.Name, Hash: secret.NameHash, Value: value}, nil
}

func validateSecretFileName(name string) error {
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, `/\\`) {
		return fmt.Errorf("secret name %q is not safe for file materialization", name)
	}
	return nil
}

func validateExplicitMountDest(dest string) error {
	if dest == "" {
		return errors.New("mount destination cannot be empty")
	}
	clean := filepath.Clean(dest)
	for _, part := range strings.Split(clean, string(os.PathSeparator)) {
		if part == ".." {
			return fmt.Errorf("mount destination %q must not contain path traversal", dest)
		}
	}
	return nil
}

func (a App) broker(st *store.FileStore, args []string) int {
	if len(args) == 0 || args[0] != "start" {
		return a.fail(errors.New("broker start is required"))
	}
	if err := st.RequireInitialized(); err != nil {
		return a.fail(err)
	}
	options, err := parseBrokerStartArgs(args[1:])
	if err != nil {
		return a.fail(err)
	}
	target, err := a.workspacePathTarget(st, options.Workspace, "broker start")
	if err != nil {
		return a.fail(err)
	}
	if options.Agent == "" && (st.State.ControlPlane == nil || st.State.ControlPlane.Source != "service-account") {
		return a.fail(errors.New("broker start requires --agent"))
	}
	subject, runtimeType, err := runtimeSubject(st, options.Agent, "", options.Agent != "")
	if err != nil {
		return a.fail(err)
	}
	if subject == "" {
		return a.fail(errors.New("broker start requires a subject"))
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	var mu sync.Mutex
	runtimeStore := brokerRuntimeStore{path: st.Path, current: st}
	requestAuditSync, waitAuditSync := a.startRuntimeAuditSyncWorker(ctx, st.Path, &mu)
	defer func() {
		stop()
		waitAuditSync()
	}()
	brokerOptions := broker.Options{
		Workspace:   target.Slug,
		Subject:     subject,
		SocketPath:  options.SocketPath,
		ListenAddr:  options.ListenAddr,
		ClientFile:  options.ClientFile,
		TokenTTL:    options.TokenTTL,
		IdleTimeout: options.IdleTimeout,
		MaxRuntime:  options.MaxRuntime,
		Once:        options.Once,
		OnReady: func(summary broker.Summary) {
			mu.Lock()
			_ = runtimeStore.audit(subject, "broker_started", "allowed", "", "", "local broker started", target.Slug, subject, runtimeType, "", map[string]string{"mode": summary.Mode})
			requestAuditSync()
			mu.Unlock()
			fmt.Fprintf(a.Out, "asiri broker ready\nmode\t%s\naddress\t%s\nclient\t%s\nworkspace\t%s\nsubject\t%s\nexpires\t%s\n", summary.Mode, summary.Address, summary.ClientFile, summary.Workspace, summary.Subject, summary.ExpiresAt.Format(time.RFC3339))
		},
		OnEvent: func(event broker.Event) {
			mu.Lock()
			_ = runtimeStore.audit(subject, event.Action, event.Result, "", "", event.Reason, target.Slug, subject, runtimeType, event.RequestID, nil)
			requestAuditSync()
			mu.Unlock()
		},
	}
	_, runErr := broker.Run(ctx, brokerOptions, func(requestCtx context.Context, request broker.ValueRequest) (broker.ValueResponse, error) {
		mu.Lock()
		defer mu.Unlock()
		return a.handleBrokerValueRequest(requestCtx, &runtimeStore, target, subject, runtimeType, request, requestAuditSync)
	})
	mu.Lock()
	result := "allowed"
	reason := "local broker stopped"
	if runErr != nil {
		result = "failed"
		reason = runErr.Error()
	}
	_ = runtimeStore.audit(subject, "broker_stopped", result, "", "", reason, target.Slug, subject, runtimeType, "", nil)
	a.syncRuntimeAuditBestEffort(runtimeStore.currentStore())
	mu.Unlock()
	if runErr != nil {
		return a.fail(runErr)
	}
	return 0
}

type brokerRuntimeStore struct {
	path    string
	current *store.FileStore
}

func (runtime *brokerRuntimeStore) currentStore() *store.FileStore {
	return runtime.current
}

func (runtime *brokerRuntimeStore) load() (*store.FileStore, error) {
	latest, err := store.Load(runtime.path)
	if err != nil {
		return nil, err
	}
	runtime.current = latest
	return latest, nil
}

func (runtime *brokerRuntimeStore) audit(actor, action, result, scope, nameHash, reason, workspaceSlug, label, labelType, requestID string, extra map[string]string) error {
	latest, err := runtime.load()
	if err != nil {
		return err
	}
	latest.Audit(actor, action, result, scope, nameHash, reason, brokerRuntimeAuditMetadata(latest, workspaceSlug, label, labelType, requestID, extra))
	if err := latest.Save(); err != nil {
		return err
	}
	runtime.current = latest
	return nil
}

func (a App) startRuntimeAuditSyncWorker(ctx context.Context, path string, mu *sync.Mutex) (func(), func()) {
	requested := make(chan struct{}, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-ctx.Done():
				return
			case <-requested:
				a.syncRuntimeAuditBestEffortFromPath(path, mu)
			}
		}
	}()
	requestSync := func() {
		select {
		case requested <- struct{}{}:
		default:
		}
	}
	wait := func() {
		<-done
	}
	return requestSync, wait
}

func (a App) syncRuntimeAuditBestEffortFromPath(path string, mu *sync.Mutex) {
	mu.Lock()
	st, err := store.Load(path)
	if err != nil || st.State.ControlPlane == nil {
		mu.Unlock()
		return
	}
	ids, events := pendingRuntimeAuditEvents(st)
	if len(events) == 0 {
		mu.Unlock()
		return
	}
	accessToken, ok := runtimeAuditAccessToken(st)
	if !ok {
		mu.Unlock()
		return
	}
	endpoint := strings.TrimRight(st.State.ControlPlane.Origin, "/") + "/v1/audit/batch"
	mu.Unlock()
	if err := postJSONBearerTimeout(st, endpoint, accessToken, runtimeAuditBatchRequest{Events: events}, nil, runtimeAuditSyncTimeout); err != nil {
		return
	}
	mu.Lock()
	defer mu.Unlock()
	latest, err := store.Load(path)
	if err != nil {
		return
	}
	latest.MarkAuditEventsRemoteSynced(ids, time.Now().UTC())
	_ = latest.Save()
}

type brokerStartOptions struct {
	Workspace   string
	Agent       string
	SocketPath  string
	ListenAddr  string
	ClientFile  string
	TokenTTL    time.Duration
	IdleTimeout time.Duration
	MaxRuntime  time.Duration
	Once        bool
}

func parseBrokerStartArgs(args []string) (brokerStartOptions, error) {
	options := brokerStartOptions{}
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--workspace", "-w":
			if i+1 >= len(args) || strings.HasPrefix(args[i+1], "--") {
				return options, errors.New("--workspace requires a slug")
			}
			options.Workspace = args[i+1]
			i++
		case "--agent":
			if i+1 >= len(args) || strings.HasPrefix(args[i+1], "--") {
				return options, errors.New("--agent requires a subject")
			}
			options.Agent = store.NormalizeSubjectLabel(args[i+1])
			i++
		case "--socket":
			if i+1 >= len(args) || strings.HasPrefix(args[i+1], "--") {
				return options, errors.New("--socket requires a path")
			}
			options.SocketPath = args[i+1]
			i++
		case "--listen":
			if i+1 >= len(args) || strings.HasPrefix(args[i+1], "--") {
				return options, errors.New("--listen requires an address")
			}
			options.ListenAddr = args[i+1]
			i++
		case "--client-file":
			if i+1 >= len(args) || strings.HasPrefix(args[i+1], "--") {
				return options, errors.New("--client-file requires a path")
			}
			options.ClientFile = args[i+1]
			i++
		case "--token-ttl":
			value, err := parseBrokerDurationFlag(args, &i, "--token-ttl")
			if err != nil {
				return options, err
			}
			options.TokenTTL = value
		case "--idle-timeout":
			value, err := parseBrokerDurationFlag(args, &i, "--idle-timeout")
			if err != nil {
				return options, err
			}
			options.IdleTimeout = value
		case "--max-runtime":
			value, err := parseBrokerDurationFlag(args, &i, "--max-runtime")
			if err != nil {
				return options, err
			}
			options.MaxRuntime = value
		case "--once":
			options.Once = true
		default:
			return options, fmt.Errorf("unknown broker start argument %q", args[i])
		}
	}
	if options.Workspace == "" {
		return options, errors.New("broker start requires --workspace")
	}
	return options, nil
}

func parseBrokerDurationFlag(args []string, index *int, flag string) (time.Duration, error) {
	if *index+1 >= len(args) || strings.HasPrefix(args[*index+1], "--") {
		return 0, fmt.Errorf("%s requires a duration", flag)
	}
	value, err := time.ParseDuration(args[*index+1])
	if err != nil {
		return 0, fmt.Errorf("%s must be a duration like 15m or 1h: %w", flag, err)
	}
	if value < time.Second {
		return 0, fmt.Errorf("%s must be at least 1s", flag)
	}
	*index = *index + 1
	return value, nil
}

func (a App) handleBrokerValueRequest(requestCtx context.Context, runtimeStore *brokerRuntimeStore, target workspacePathTarget, subject, runtimeType string, request broker.ValueRequest, requestAuditSync func()) (broker.ValueResponse, error) {
	if err := requestCtx.Err(); err != nil {
		return broker.ValueResponse{}, &broker.Error{Status: http.StatusUnauthorized, Code: "token_expired", Message: "broker token expired"}
	}
	st, err := runtimeStore.load()
	if err != nil {
		return broker.ValueResponse{}, err
	}
	requestID := strings.TrimSpace(request.RequestID)
	if requestID == "" || len(requestID) > 128 {
		_ = runtimeStore.audit(subject, "broker_request", "denied", "", "", "invalid broker request id", target.Slug, subject, runtimeType, "", nil)
		requestAuditSync()
		return broker.ValueResponse{}, &broker.Error{Status: http.StatusBadRequest, Code: "invalid_request_id", Message: "broker request requires a short requestId"}
	}
	if strings.TrimSpace(request.Workspace) != target.Slug {
		_ = runtimeStore.audit(subject, "broker_request", "denied", "", "", "broker workspace mismatch", target.Slug, subject, runtimeType, requestID, nil)
		requestAuditSync()
		return broker.ValueResponse{}, &broker.Error{Status: http.StatusForbidden, Code: "workspace_mismatch", Message: "broker workspace mismatch"}
	}
	if store.NormalizeSubjectLabel(request.Subject) != subject {
		_ = runtimeStore.audit(subject, "broker_request", "denied", "", "", "broker subject mismatch", target.Slug, subject, runtimeType, requestID, nil)
		requestAuditSync()
		return broker.ValueResponse{}, &broker.Error{Status: http.StatusForbidden, Code: "subject_mismatch", Message: "broker subject mismatch"}
	}
	shortPath := strings.TrimSpace(request.Path)
	if shortPath == "" {
		_ = runtimeStore.audit(subject, "broker_request", "denied", "", "", "missing broker secret path", target.Slug, subject, runtimeType, requestID, nil)
		requestAuditSync()
		return broker.ValueResponse{}, &broker.Error{Status: http.StatusBadRequest, Code: "missing_path", Message: "broker request requires a secret path"}
	}
	fullPath, err := workspacePrefixedPath(target, shortPath, "broker")
	if err != nil {
		_ = runtimeStore.audit(subject, "broker_request", "denied", "", "", "invalid broker secret path", target.Slug, subject, runtimeType, requestID, nil)
		requestAuditSync()
		return broker.ValueResponse{}, &broker.Error{Status: http.StatusBadRequest, Code: "invalid_path", Message: err.Error()}
	}
	allowed, reason := st.CheckPolicy(subject, fullPath, "broker")
	scope, name, parseErr := store.ParseSecretPath(fullPath)
	hash := ""
	if parseErr == nil {
		hash = store.HashSecretName(scope, name)
	}
	if !allowed {
		_ = runtimeStore.audit(subject, "secret_brokered", "denied", scope, hash, reason, target.Slug, subject, runtimeType, requestID, map[string]string{"mode": "broker"})
		requestAuditSync()
		return broker.ValueResponse{}, &broker.Error{Status: http.StatusForbidden, Code: "policy_denied", Message: reason}
	}
	value, secret, err := st.GetSecret(fullPath)
	if err != nil {
		message := err.Error()
		if hint := a.remoteSelectionHint(st, fullPath, subject, "broker", false); hint != "" {
			message = hint
		}
		_ = runtimeStore.audit(subject, "secret_brokered", "failed", scope, hash, "secret not locally usable", target.Slug, subject, runtimeType, requestID, map[string]string{"mode": "broker"})
		requestAuditSync()
		return broker.ValueResponse{}, &broker.Error{Status: http.StatusNotFound, Code: "secret_not_local", Message: message}
	}
	if err := runtimeStore.audit(subject, "secret_brokered", "allowed", secret.Scope, secret.NameHash, "broker value request", target.Slug, subject, runtimeType, requestID, map[string]string{"mode": "broker"}); err != nil {
		return broker.ValueResponse{}, err
	}
	if err := requestCtx.Err(); err != nil {
		return broker.ValueResponse{}, &broker.Error{Status: http.StatusUnauthorized, Code: "token_expired", Message: "broker token expired"}
	}
	requestAuditSync()
	return broker.ValueResponse{RequestID: requestID, Value: value}, nil
}

func brokerRuntimeAuditMetadata(st *store.FileStore, workspaceSlug, label, labelType, requestID string, extra map[string]string) map[string]string {
	metadata := runtimeAuditMetadata(st, "", label, labelType, extra)
	if metadata == nil {
		metadata = map[string]string{}
	}
	if workspaceSlug != "" {
		metadata["workspaceSlug"] = workspaceSlug
		if st != nil {
			if binding, ok := st.RemoteBindingForPrefix(workspaceSlug); ok && binding.WorkspaceID != "" {
				metadata["workspaceId"] = binding.WorkspaceID
			} else if st.State.ControlPlane != nil && st.State.ControlPlane.WorkspaceSlug == workspaceSlug {
				metadata["workspaceId"] = st.State.ControlPlane.WorkspaceID
			}
		}
	}
	if requestID != "" {
		metadata["requestId"] = requestID
	}
	return metadata
}

func (a App) audit(st *store.FileStore, args []string) int {
	if len(args) == 0 || args[0] != "tail" {
		return a.fail(errors.New("audit tail is required"))
	}
	if err := st.RequireInitialized(); err != nil {
		return a.fail(err)
	}
	workspaceFilters, remaining, err := splitWorkspaceFilters(args[1:], "audit tail")
	if err != nil {
		return a.fail(err)
	}
	if err := rejectUnknownArgs(remaining, "--limit"); err != nil {
		return a.fail(err)
	}
	workspaceSet, err := a.workspaceFilterSet(st, workspaceFilters, "audit tail")
	if err != nil {
		return a.fail(err)
	}
	limit := 20
	if value := flagValue(remaining, "--limit", ""); value != "" {
		parsed, err := strconv.Atoi(value)
		if err != nil || parsed < 1 {
			return a.fail(errors.New("--limit must be a positive integer"))
		}
		limit = parsed
	}
	printed := 0
	for _, event := range st.State.Audit {
		if printed >= limit {
			break
		}
		if len(workspaceSet) > 0 && !auditEventMatchesWorkspace(event, workspaceSet) {
			continue
		}
		fmt.Fprintf(a.Out, "%s\t%s\t%s\t%s\t%s\n", event.CreatedAt.Format(time.RFC3339), event.Actor, event.Action, event.Result, event.Reason)
		printed++
	}
	return 0
}

func auditEventMatchesWorkspace(event asiri.AuditEvent, workspaces map[string]bool) bool {
	if len(workspaces) == 0 {
		return true
	}
	if event.Metadata != nil {
		if workspaces[event.Metadata["workspaceSlug"]] || workspaces[event.Metadata["workspace"]] {
			return true
		}
	}
	return workspaces[store.WorkspacePrefix(event.Scope)]
}

func (a App) syncRuntimeAuditBestEffort(st *store.FileStore) {
	if st.State.ControlPlane == nil {
		return
	}
	ids, events := pendingRuntimeAuditEvents(st)
	if len(events) == 0 {
		return
	}
	accessToken, ok := runtimeAuditAccessToken(st)
	if !ok {
		return
	}
	endpoint := strings.TrimRight(st.State.ControlPlane.Origin, "/") + "/v1/audit/batch"
	if err := postJSONBearerTimeout(st, endpoint, accessToken, runtimeAuditBatchRequest{Events: events}, nil, runtimeAuditSyncTimeout); err != nil {
		return
	}
	st.MarkAuditEventsRemoteSynced(ids, time.Now().UTC())
	_ = st.Save()
}

var runtimeAuditSyncTimeout = 2 * time.Second

func runtimeAuditAccessToken(st *store.FileStore) (string, bool) {
	if st == nil || st.State.ControlPlane == nil {
		return "", false
	}
	if time.Until(st.State.ControlPlane.AccessTokenExpiresAt) <= 30*time.Second {
		return "", false
	}
	accessToken, err := st.ControlPlaneAccessToken()
	if err != nil || accessToken == "" {
		return "", false
	}
	return accessToken, true
}

type runtimeAuditBatchRequest struct {
	Events []runtimeAuditUploadEvent `json:"events"`
}

type runtimeAuditUploadEvent struct {
	OrgID          string            `json:"orgId"`
	Action         string            `json:"action"`
	Result         string            `json:"result"`
	Scope          string            `json:"scope,omitempty"`
	SecretNameHash string            `json:"secretNameHash,omitempty"`
	Reason         string            `json:"reason,omitempty"`
	CreatedAt      string            `json:"createdAt,omitempty"`
	Metadata       map[string]string `json:"metadata,omitempty"`
}

func pendingRuntimeAuditEvents(st *store.FileStore) ([]string, []runtimeAuditUploadEvent) {
	if st.State.ControlPlane == nil {
		return nil, nil
	}
	ids := []string{}
	events := []runtimeAuditUploadEvent{}
	for _, event := range st.State.Audit {
		if event.RemoteSyncedAt != nil || !isRuntimeAuditAction(event.Action) {
			continue
		}
		if event.Metadata == nil || event.Metadata["runtimeLabel"] == "" {
			continue
		}
		eventWorkspaceID := runtimeAuditEventWorkspaceID(st, event)
		if eventWorkspaceID == "" || eventWorkspaceID != st.State.ControlPlane.WorkspaceID {
			continue
		}
		metadata := copyStringMap(event.Metadata)
		metadata["localAuditId"] = event.ID
		metadata["reportedCreatedAt"] = event.CreatedAt.Format(time.RFC3339)
		ids = append(ids, event.ID)
		events = append(events, runtimeAuditUploadEvent{
			OrgID:          eventWorkspaceID,
			Action:         event.Action,
			Result:         event.Result,
			Scope:          event.Scope,
			SecretNameHash: event.SecretNameHash,
			Reason:         event.Reason,
			CreatedAt:      event.CreatedAt.Format(time.RFC3339),
			Metadata:       metadata,
		})
	}
	return ids, events
}

func runtimeAuditEventWorkspaceID(st *store.FileStore, event asiri.AuditEvent) string {
	if st == nil || st.State.ControlPlane == nil {
		return ""
	}
	if event.Metadata == nil {
		return ""
	}
	return event.Metadata["workspaceId"]
}

func isRuntimeAuditAction(action string) bool {
	switch action {
	case "secret_read", "secret_injected", "secret_env_exported", "secret_mounted", "secret_unsafe_argv_injected", "secret_brokered", "broker_request", "broker_started", "broker_stopped":
		return true
	default:
		return false
	}
}

func runtimeLabelType(agentExplicit bool) string {
	if agentExplicit {
		return "agent"
	}
	return "process"
}

func runtimeSubject(st *store.FileStore, current, fallback string, agentExplicit bool) (string, string, error) {
	if st != nil && st.State.ControlPlane != nil && st.State.ControlPlane.Source == "service-account" {
		serviceAccount := store.NormalizeSubjectLabel(st.State.ControlPlane.ServiceAccountSlug)
		if serviceAccount == "" {
			return "", "", errors.New("service account session is missing service account identity")
		}
		return serviceAccount, "service", nil
	}
	if current == "" {
		current = fallback
	}
	return store.NormalizeSubjectLabel(current), runtimeLabelType(agentExplicit), nil
}

func runtimeAuditMetadata(st *store.FileStore, scope, label, labelType string, extra map[string]string) map[string]string {
	label = store.NormalizeSubjectLabel(label)
	if label == "" {
		if len(extra) == 0 {
			return nil
		}
		return copyStringMap(extra)
	}
	if labelType == "" {
		labelType = "process"
	}
	metadata := map[string]string{
		"runtimeLabel":     label,
		"runtimeLabelType": labelType,
	}
	if workspaceID, workspaceSlug := runtimeAuditScopeWorkspace(st, scope); workspaceID != "" {
		metadata["workspaceId"] = workspaceID
		metadata["workspaceSlug"] = workspaceSlug
	}
	for key, value := range extra {
		metadata[key] = value
	}
	return metadata
}

func runtimeAuditScopeWorkspace(st *store.FileStore, scope string) (string, string) {
	if st == nil || scope == "" {
		return "", ""
	}
	binding, ok := st.RemoteBindingForPrefix(store.WorkspacePrefix(scope))
	if !ok || binding.WorkspaceID == "" {
		return "", ""
	}
	return binding.WorkspaceID, binding.WorkspaceSlug
}

func copyStringMap(input map[string]string) map[string]string {
	if len(input) == 0 {
		return nil
	}
	output := make(map[string]string, len(input))
	for key, value := range input {
		output[key] = value
	}
	return output
}

func (a App) local(st *store.FileStore, args []string) int {
	if len(args) == 0 {
		return a.fail(errors.New("local subcommand required"))
	}
	switch args[0] {
	case "wipe":
		return a.localWipe(st, args[1:])
	default:
		return a.fail(fmt.Errorf("unknown local command %q", args[0]))
	}
}

func (a App) localWipe(st *store.FileStore, args []string) int {
	if err := rejectUnknownArgs(args, "--yes"); err != nil {
		return a.fail(err)
	}
	if len(positionalArgs(args)) > 0 {
		return a.fail(errors.New("local wipe accepts only --yes"))
	}
	if err := rejectServiceAccountLocalMutation(st); err != nil {
		return a.fail(err)
	}
	if !hasFlag(args, "--yes") {
		if err := a.confirmLocalWipe(); err != nil {
			return a.fail(err)
		}
	}
	if err := wipeLocalState(st); err != nil {
		return a.fail(err)
	}
	fmt.Fprintln(a.Out, "✓ Local Asiri state wiped")
	return 0
}

func (a App) confirmLocalWipe() error {
	fmt.Fprint(a.Out, "Type wipe local to delete local Asiri state: ")
	reader := bufio.NewReader(a.In)
	value, err := reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	value = strings.TrimSuffix(value, "\n")
	value = strings.TrimSuffix(value, "\r")
	if value != "wipe local" {
		return errors.New("confirmation did not match; local state was not wiped")
	}
	return nil
}

func (a App) cache(st *store.FileStore, args []string) int {
	if len(args) == 0 || args[0] != "wipe" {
		return a.fail(errors.New("cache wipe is required"))
	}
	if err := rejectServiceAccountLocalMutation(st); err != nil {
		return a.fail(err)
	}
	if err := wipeLocalState(st); err != nil {
		return a.fail(err)
	}
	fmt.Fprintln(a.Out, "✓ Local Asiri cache wiped")
	return 0
}

func wipeLocalState(st *store.FileStore) error {
	if err := st.DeletePlatformKeys(); err != nil {
		return err
	}
	if err := os.Remove(st.Path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

type deviceCodeStartResponse struct {
	DeviceCode              string `json:"deviceCode"`
	UserCode                string `json:"userCode"`
	VerificationURI         string `json:"verificationUri"`
	VerificationURIComplete string `json:"verificationUriComplete"`
	WorkspaceSlug           string `json:"workspaceSlug"`
	ServiceAccountSlug      string `json:"serviceAccountSlug"`
	ExpiresIn               int    `json:"expiresIn"`
	Interval                int    `json:"interval"`
}

type pushWorkspacePlan struct {
	Prefix string
	Refs   []store.LocalSecretRef
}

type deviceCodeTokenResponse struct {
	Status             string `json:"status"`
	Error              string `json:"error"`
	Message            string `json:"message"`
	OrgID              string `json:"orgId"`
	WorkspaceSlug      string `json:"workspaceSlug"`
	UserID             string `json:"userId"`
	ServiceAccountID   string `json:"serviceAccountId"`
	ServiceAccountSlug string `json:"serviceAccountSlug"`
	ServiceAccountName string `json:"serviceAccountName"`
	ApprovedByUserID   string `json:"approvedByUserId"`
	DeviceID           string `json:"deviceId"`
	AccessToken        string `json:"accessToken"`
	RefreshToken       string `json:"refreshToken"`
	ExpiresIn          int    `json:"expiresIn"`
	RefreshExpiresAt   string `json:"refreshExpiresAt"`
	Interval           int    `json:"interval"`
}

type sessionRefreshResponse struct {
	Status             string `json:"status"`
	Error              string `json:"error"`
	OrgID              string `json:"orgId"`
	WorkspaceSlug      string `json:"workspaceSlug"`
	UserID             string `json:"userId"`
	ServiceAccountID   string `json:"serviceAccountId"`
	ServiceAccountSlug string `json:"serviceAccountSlug"`
	ServiceAccountName string `json:"serviceAccountName"`
	ApprovedByUserID   string `json:"approvedByUserId"`
	DeviceID           string `json:"deviceId"`
	AccessToken        string `json:"accessToken"`
	ExpiresIn          int    `json:"expiresIn"`
	RefreshExpiresAt   string `json:"refreshExpiresAt"`
}

type remoteWhoamiResponse struct {
	User      remoteUserResponse          `json:"user"`
	Workspace remoteWorkspaceResponse     `json:"workspace"`
	Device    remoteWhoamiDeviceResponse  `json:"device"`
	Session   remoteWhoamiSessionResponse `json:"session"`
}

type remoteUserResponse struct {
	ID          string `json:"id"`
	Email       string `json:"email"`
	DisplayName string `json:"displayName"`
	Role        string `json:"role"`
	Status      string `json:"status"`
}

type remoteWhoamiDeviceResponse struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Kind   string `json:"kind"`
	Status string `json:"status"`
}

type remoteWhoamiSessionResponse struct {
	IdentityType       string `json:"identityType"`
	WorkspaceID        string `json:"workspaceId"`
	DeviceID           string `json:"deviceId"`
	ServiceAccountID   string `json:"serviceAccountId"`
	ServiceAccountSlug string `json:"serviceAccountSlug"`
	ServiceAccountName string `json:"serviceAccountName"`
	ApprovedByUserID   string `json:"approvedByUserId"`
	Source             string `json:"source"`
	Status             string `json:"status"`
	ExpiresAt          string `json:"expiresAt"`
}

type remoteWorkspaceResponse struct {
	ID                   string `json:"id"`
	Name                 string `json:"name"`
	Slug                 string `json:"slug"`
	OwnerUserID          string `json:"ownerUserId"`
	Role                 string `json:"role"`
	CanPull              *bool  `json:"canPull"`
	CanWrite             *bool  `json:"canWrite"`
	CurrentDeviceTrusted *bool  `json:"currentDeviceTrusted"`
	CurrentDeviceID      string `json:"currentDeviceId"`
	CanApproveDevice     *bool  `json:"canApproveDevice"`
}

type remoteWorkspacesResponse struct {
	Organizations []remoteWorkspaceResponse   `json:"organizations"`
	ActiveOrgID   string                      `json:"activeOrgId"`
	Secrets       []visibleRemoteSecretRecord `json:"secrets,omitempty"`
}

type remoteServiceAccountResponse struct {
	ID              string `json:"id"`
	OrgID           string `json:"orgId"`
	Slug            string `json:"slug"`
	Name            string `json:"name"`
	Status          string `json:"status"`
	CreatedByUserID string `json:"createdByUserId"`
}

type remoteServiceAccountsResponse struct {
	ServiceAccounts []remoteServiceAccountResponse `json:"serviceAccounts"`
}

type remotePolicyResponse struct {
	ID            string   `json:"id"`
	OrgID         string   `json:"orgId"`
	SubjectType   string   `json:"subjectType"`
	SubjectID     string   `json:"subjectId"`
	ScopePattern  string   `json:"scopePattern"`
	SecretPattern string   `json:"secretPattern"`
	Actions       []string `json:"actions"`
	ApprovalMode  string   `json:"approvalMode"`
	ExpiresAt     string   `json:"expiresAt"`
}

type remotePoliciesResponse struct {
	Policies []remotePolicyResponse `json:"policies"`
}

type writeOptionsResponse struct {
	RequestedWorkspaceSlug string                 `json:"requestedWorkspaceSlug"`
	SourceWorkspace        *writeWorkspaceOption  `json:"sourceWorkspace"`
	ActiveWorkspace        writeWorkspaceOption   `json:"activeWorkspace"`
	WritableWorkspaces     []writeWorkspaceOption `json:"writableWorkspaces"`
}

type writeWorkspaceOption struct {
	ID       string            `json:"id"`
	Slug     string            `json:"slug"`
	CanWrite bool              `json:"canWrite"`
	Paths    []writePathOption `json:"paths"`
}

type writePathOption struct {
	Scope              string `json:"scope"`
	Name               string `json:"name"`
	FullPath           string `json:"fullPath"`
	RequiredCapability string `json:"requiredCapability"`
	CanWrite           bool   `json:"canWrite"`
}

type remoteDeviceResponse struct {
	ID                  string `json:"id"`
	Name                string `json:"name"`
	Kind                string `json:"kind"`
	Status              string `json:"status"`
	EncryptionPublicKey string `json:"encryptionPublicKey"`
}

type syncBundleResponse struct {
	OrgID            string                      `json:"orgId"`
	DeviceID         string                      `json:"deviceId"`
	IssuedAt         string                      `json:"issuedAt"`
	EncryptedSecrets []store.RemoteSecretVersion `json:"encryptedSecrets"`
	Policies         []syncPolicyResponse        `json:"policies"`
}

type syncPolicyResponse struct {
	ID            string     `json:"id"`
	SubjectType   string     `json:"subjectType"`
	SubjectID     string     `json:"subjectId"`
	ScopePattern  string     `json:"scopePattern"`
	SecretPattern string     `json:"secretPattern"`
	Actions       []string   `json:"actions"`
	ApprovalMode  string     `json:"approvalMode"`
	CreatedAt     time.Time  `json:"createdAt"`
	ExpiresAt     *time.Time `json:"expiresAt,omitempty"`
}

type remoteDevicesResponse struct {
	Devices []remoteDeviceResponse `json:"devices"`
}

type remoteSecretsResponse struct {
	Secrets []remoteSecretRecord `json:"secrets"`
}

type remoteSecretRecord struct {
	ID                string                   `json:"id"`
	OrgID             string                   `json:"orgId"`
	Scope             string                   `json:"scope"`
	Name              string                   `json:"name"`
	Version           int                      `json:"version"`
	Algorithm         string                   `json:"algorithm"`
	Nonce             string                   `json:"nonce"`
	Ciphertext        string                   `json:"ciphertext"`
	AAD               string                   `json:"aad"`
	Status            string                   `json:"status"`
	WrappedKeys       []store.RemoteWrappedKey `json:"wrappedKeys"`
	WrappedRecipients []remoteWrappedRecipient `json:"wrappedRecipients"`
	CreatedByDeviceID string                   `json:"createdByDeviceId"`
	CreatedAt         time.Time                `json:"createdAt"`
}

type remoteWrappedRecipient struct {
	RecipientType string `json:"recipientType"`
	RecipientID   string `json:"recipientId"`
	WrapAlgorithm string `json:"wrapAlgorithm"`
}

type recoveryRecipientReplacement struct {
	SecretID   string                 `json:"secretId"`
	WrappedKey store.RemoteWrappedKey `json:"wrappedKey"`
}

type remoteRecoveryRecipientResponse struct {
	RecipientID          string `json:"recipientId"`
	PublicKey            string `json:"publicKey"`
	PublicKeyFingerprint string `json:"publicKeyFingerprint"`
	Status               string `json:"status"`
}

type visibleRemoteSecretRecord struct {
	ID                     string                   `json:"id"`
	OrgID                  string                   `json:"orgId"`
	WorkspaceSlug          string                   `json:"workspaceSlug"`
	Scope                  string                   `json:"scope"`
	Name                   string                   `json:"name"`
	Version                int                      `json:"version"`
	Status                 string                   `json:"status"`
	CanWrite               bool                     `json:"canWrite"`
	WrappedToCurrentDevice *bool                    `json:"wrappedToCurrentDevice"`
	CurrentDeviceID        string                   `json:"currentDeviceId"`
	WrappedKeys            []store.RemoteWrappedKey `json:"wrappedKeys"`
	PurgeAfter             string                   `json:"purgeAfter"`
}

func startDeviceCodeLogin(origin, workspaceSlug string, device asiri.Device) (deviceCodeStartResponse, error) {
	return startDeviceCodeLoginWithServiceAccount(origin, workspaceSlug, "", device)
}

func startServiceAccountDeviceCodeLogin(origin, workspaceSlug, serviceAccountSlug string, device asiri.Device) (deviceCodeStartResponse, error) {
	return startDeviceCodeLoginWithServiceAccount(origin, workspaceSlug, serviceAccountSlug, device)
}

func startDeviceCodeLoginWithServiceAccount(origin, workspaceSlug, serviceAccountSlug string, device asiri.Device) (deviceCodeStartResponse, error) {
	body := map[string]string{
		"deviceName":          device.Name,
		"kind":                string(device.Kind),
		"encryptionPublicKey": device.EncryptionPublicKey,
		"signingPublicKey":    device.SigningPublicKey,
	}
	if workspaceSlug != "" {
		body["workspaceSlug"] = workspaceSlug
	}
	if serviceAccountSlug != "" {
		body["serviceAccountSlug"] = serviceAccountSlug
	}
	var result deviceCodeStartResponse
	if err := postJSON(origin+"/v1/auth/device-code/start", body, &result); err != nil {
		return result, err
	}
	if result.DeviceCode == "" || result.UserCode == "" || result.VerificationURIComplete == "" {
		return result, errors.New("control plane returned an incomplete device-code response")
	}
	if err := validateDeviceCodeApprovalOrigin(origin, result.VerificationURIComplete); err != nil {
		return result, err
	}
	if result.Interval <= 0 {
		result.Interval = 2
	}
	return result, nil
}

func validateDeviceCodeApprovalOrigin(controlPlaneOrigin, approvalURL string) error {
	controlPlane, err := url.Parse(controlPlaneOrigin)
	if err != nil || controlPlane.Scheme == "" || controlPlane.Host == "" {
		return fmt.Errorf("invalid control-plane origin %q", controlPlaneOrigin)
	}
	approval, err := url.Parse(approvalURL)
	if err != nil || approval.Scheme == "" || approval.Host == "" {
		return fmt.Errorf("control plane returned invalid approval URL %q", approvalURL)
	}
	controlPlaneURLOrigin := urlOrigin(controlPlane)
	approvalURLOrigin := urlOrigin(approval)
	if approvalURLOrigin != controlPlaneURLOrigin {
		if isLoopbackHost(controlPlane.Hostname()) && isLoopbackHost(approval.Hostname()) {
			return nil
		}
		return fmt.Errorf("device-code approval URL origin %s does not match control-plane origin %s", approvalURLOrigin, controlPlaneURLOrigin)
	}
	return nil
}

func urlOrigin(parsed *url.URL) string {
	return parsed.Scheme + "://" + parsed.Host
}

func pollDeviceCodeLogin(st *store.FileStore, origin string, start deviceCodeStartResponse) (deviceCodeTokenResponse, error) {
	deadline := time.Now().Add(time.Duration(start.ExpiresIn) * time.Second)
	if start.ExpiresIn <= 0 {
		deadline = time.Now().Add(10 * time.Minute)
	}
	interval := time.Duration(start.Interval) * time.Second
	if interval <= 0 {
		interval = 250 * time.Millisecond
	}
	for {
		var result deviceCodeTokenResponse
		status, err := postJSONDeviceCodeClaimStatus(st, origin+"/v1/auth/device-code/token", map[string]string{"deviceCode": start.DeviceCode}, credentialHash(start.DeviceCode), &result)
		if err != nil {
			return result, err
		}
		if status == http.StatusOK && result.Status == "approved" {
			if result.OrgID == "" || result.WorkspaceSlug == "" || result.UserID == "" || result.DeviceID == "" || result.AccessToken == "" || result.RefreshToken == "" {
				return result, errors.New("control plane approved login without link metadata")
			}
			return result, nil
		}
		if result.Error != "" && result.Error != "authorization_pending" {
			return result, fmt.Errorf("device-code login failed: %s", result.Error)
		}
		if time.Now().After(deadline) {
			return result, errors.New("device-code login timed out")
		}
		time.Sleep(interval)
	}
}

func refreshDeviceSession(origin string, st *store.FileStore) (sessionRefreshResponse, int, error) {
	var result sessionRefreshResponse
	refreshToken, err := st.ControlPlaneRefreshToken()
	if err != nil {
		return result, 0, err
	}
	status, err := postJSONDeviceSignedStatus(st, origin+"/v1/auth/session/refresh", map[string]string{"refreshToken": refreshToken}, credentialHash(refreshToken), &result)
	if err != nil {
		return result, status, err
	}
	if status == http.StatusOK {
		if result.Status != "approved" || result.AccessToken == "" || result.OrgID == "" || result.WorkspaceSlug == "" || result.UserID == "" || result.DeviceID == "" {
			return result, status, errors.New("control plane refreshed session without link metadata")
		}
	}
	return result, status, nil
}

func logoutDeviceSession(st *store.FileStore, origin, refreshToken string) error {
	_, err := postJSONDeviceSignedStatus(st, origin+"/v1/auth/session/logout", map[string]string{"refreshToken": refreshToken}, credentialHash(refreshToken), nil)
	return err
}

func listRemoteWorkspaces(st *store.FileStore, origin, accessToken string) ([]remoteWorkspaceResponse, error) {
	result, err := listRemoteWorkspaceOverview(st, origin, accessToken, false, false)
	if err != nil {
		return nil, err
	}
	return result.Organizations, nil
}

func listRemoteWorkspaceOverview(st *store.FileStore, origin, accessToken string, includeSecrets, includeInactive bool) (remoteWorkspacesResponse, error) {
	var result remoteWorkspacesResponse
	endpoint := strings.TrimRight(origin, "/") + "/v1/orgs"
	params := url.Values{}
	if includeSecrets {
		params.Set("includeSecrets", "1")
	}
	if includeInactive {
		params.Set("includeInactive", "1")
	}
	if encoded := params.Encode(); encoded != "" {
		endpoint += "?" + encoded
	}
	if err := getJSONBearer(st, endpoint, accessToken, &result); err != nil {
		return result, err
	}
	return result, nil
}

func createRemoteServiceAccount(st *store.FileStore, origin, accessToken, orgID, slug, name string) (remoteServiceAccountResponse, error) {
	var result remoteServiceAccountResponse
	body := map[string]string{"orgId": orgID, "slug": slug, "name": name}
	if err := postJSONBearer(st, strings.TrimRight(origin, "/")+"/v1/service-accounts", accessToken, body, &result); err != nil {
		return result, err
	}
	if result.ID == "" || result.Slug == "" {
		return result, errors.New("control plane created service account without metadata")
	}
	return result, nil
}

func listRemoteServiceAccounts(st *store.FileStore, origin, orgID, accessToken string, includeInactive bool) ([]remoteServiceAccountResponse, error) {
	var result remoteServiceAccountsResponse
	params := url.Values{"orgId": []string{orgID}}
	if includeInactive {
		params.Set("includeInactive", "1")
	}
	endpoint := fmt.Sprintf("%s/v1/service-accounts?%s", strings.TrimRight(origin, "/"), params.Encode())
	if err := getJSONBearer(st, endpoint, accessToken, &result); err != nil {
		return nil, err
	}
	return result.ServiceAccounts, nil
}

func findRemoteServiceAccount(accounts []remoteServiceAccountResponse, value string) (remoteServiceAccountResponse, bool) {
	for _, account := range accounts {
		if account.ID == value || account.Slug == value {
			return account, true
		}
	}
	return remoteServiceAccountResponse{}, false
}

func requireRemoteServiceAccount(st *store.FileStore, origin, orgID, accessToken, value string) (remoteServiceAccountResponse, error) {
	accounts, err := listRemoteServiceAccounts(st, origin, orgID, accessToken, true)
	if err != nil {
		return remoteServiceAccountResponse{}, err
	}
	account, ok := findRemoteServiceAccount(accounts, value)
	if !ok {
		return remoteServiceAccountResponse{}, fmt.Errorf("service account %s is not visible", value)
	}
	return account, nil
}

func disableRemoteServiceAccount(st *store.FileStore, origin, accessToken, accountID string) (remoteServiceAccountResponse, error) {
	var result remoteServiceAccountResponse
	endpoint := fmt.Sprintf("%s/v1/service-accounts/%s/disable", strings.TrimRight(origin, "/"), url.PathEscape(accountID))
	if err := postJSONBearer(st, endpoint, accessToken, map[string]string{}, &result); err != nil {
		return result, err
	}
	if result.ID == "" || result.Slug == "" {
		return result, errors.New("control plane disabled service account without metadata")
	}
	return result, nil
}

func listRemotePolicies(st *store.FileStore, origin, orgID, accessToken string) ([]remotePolicyResponse, error) {
	var result remotePoliciesResponse
	endpoint := fmt.Sprintf("%s/v1/policies?orgId=%s", strings.TrimRight(origin, "/"), url.QueryEscape(orgID))
	if err := getJSONBearer(st, endpoint, accessToken, &result); err != nil {
		return nil, err
	}
	return result.Policies, nil
}

func ensureRemoteServiceAccountPolicy(st *store.FileStore, origin, accessToken, orgID, serviceAccountSlug string, options serviceAccountGrantOptions) (remotePolicyResponse, bool, error) {
	policies, err := listRemotePolicies(st, origin, orgID, accessToken)
	if err != nil {
		return remotePolicyResponse{}, false, err
	}
	for _, policy := range policies {
		if policy.SubjectType == "service" &&
			policy.SubjectID == serviceAccountSlug &&
			policy.ScopePattern == options.ScopePattern &&
			policy.SecretPattern == options.SecretPattern &&
			policy.ApprovalMode == options.ApprovalMode &&
			normalizeTimestampForCompare(policy.ExpiresAt) == normalizeTimestampForCompare(options.ExpiresAt) &&
			sameStringSet(policy.Actions, options.Actions) {
			return policy, false, nil
		}
	}
	var result remotePolicyResponse
	body := map[string]any{
		"orgId":         orgID,
		"subjectType":   "service",
		"subjectId":     serviceAccountSlug,
		"scopePattern":  options.ScopePattern,
		"secretPattern": options.SecretPattern,
		"actions":       options.Actions,
		"approvalMode":  options.ApprovalMode,
	}
	if options.ExpiresAt != "" {
		body["expiresAt"] = options.ExpiresAt
	}
	if err := postJSONBearer(st, strings.TrimRight(origin, "/")+"/v1/policies", accessToken, body, &result); err != nil {
		return result, false, err
	}
	if result.ID == "" {
		return result, false, errors.New("control plane created policy without metadata")
	}
	return result, true, nil
}

func stringSliceContains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func sameStringSet(left, right []string) bool {
	return containsStringSet(left, right) && containsStringSet(right, left)
}

func containsStringSet(available, required []string) bool {
	availableSet := map[string]bool{}
	for _, value := range available {
		availableSet[value] = true
	}
	for _, value := range required {
		if !availableSet[value] {
			return false
		}
	}
	return true
}

func normalizeTimestampForCompare(value string) string {
	if value == "" {
		return ""
	}
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return value
	}
	return parsed.UTC().Format(time.RFC3339Nano)
}

func normalizeFutureTimestamp(value, flag string) (string, error) {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return "", fmt.Errorf("%s must be an RFC3339 timestamp", flag)
	}
	parsed = parsed.UTC()
	if !parsed.After(time.Now().UTC()) {
		return "", fmt.Errorf("%s must be in the future", flag)
	}
	return parsed.Format(time.RFC3339), nil
}

func stringMapsEqual(left, right map[string]string) bool {
	if len(left) != len(right) {
		return false
	}
	for key, leftValue := range left {
		if right[key] != leftValue {
			return false
		}
	}
	return true
}

func requireRemoteWorkspace(workspaces []remoteWorkspaceResponse, requested string) (remoteWorkspaceResponse, error) {
	workspace, ok := findWorkspace(workspaces, requested)
	if !ok {
		return remoteWorkspaceResponse{}, fmt.Errorf("workspace %s is not visible", requested)
	}
	return workspace, nil
}

func (a App) ensureWorkspaceSession(st *store.FileStore, accessToken string, workspace remoteWorkspaceResponse) (string, error) {
	if st.State.ControlPlane == nil {
		return "", errors.New("asiri is not linked to a control plane")
	}
	if workspace.ID == "" {
		return "", errors.New("workspace id is required")
	}
	if workspace.ID == st.State.ControlPlane.WorkspaceID {
		return accessToken, nil
	}
	device, err := st.ActiveDevice()
	if err != nil {
		return "", err
	}
	result, err := switchRemoteWorkspace(st, st.State.ControlPlane.Origin, accessToken, workspace.ID, *device)
	if err != nil {
		return "", err
	}
	if err := st.LinkControlPlaneForDevice(st.State.ControlPlane.Origin, result.OrgID, result.WorkspaceSlug, result.UserID, result.DeviceID, device.ID, result.AccessToken, result.RefreshToken, result.ExpiresIn, result.RefreshExpiresAt); err != nil {
		return "", err
	}
	return result.AccessToken, nil
}

func (a App) remoteWorkspaceTarget(st *store.FileStore, accessToken, requested string) (remoteWorkspaceResponse, string, error) {
	requested = strings.TrimSpace(requested)
	if _, err := localWorkspaceSlug(requested); err != nil {
		return remoteWorkspaceResponse{}, "", errors.New("--workspace requires a workspace slug")
	}
	if st.State.ControlPlane != nil && requested == st.State.ControlPlane.WorkspaceSlug {
		return remoteWorkspaceResponse{ID: st.State.ControlPlane.WorkspaceID, Slug: st.State.ControlPlane.WorkspaceSlug, CanPull: boolPtr(true), CanWrite: boolPtr(true), CurrentDeviceTrusted: boolPtr(true), CurrentDeviceID: st.State.ControlPlane.DeviceID}, accessToken, nil
	}
	workspaces, err := listRemoteWorkspaces(st, st.State.ControlPlane.Origin, accessToken)
	if err != nil {
		return remoteWorkspaceResponse{}, "", err
	}
	workspace, err := requireRemoteWorkspace(workspaces, requested)
	if err != nil {
		return remoteWorkspaceResponse{}, "", err
	}
	token, err := a.ensureWorkspaceSession(st, accessToken, workspace)
	if err != nil {
		if workspaceNeedsDeviceTrust(err) {
			return remoteWorkspaceResponse{}, "", fmt.Errorf("this device is not trusted for workspace %s; device %s; next: %s", requested, currentDeviceDescription(st), deviceTrustCommand(st, requested))
		}
		return remoteWorkspaceResponse{}, "", err
	}
	if st.State.ControlPlane != nil {
		workspace.ID = st.State.ControlPlane.WorkspaceID
		workspace.Slug = st.State.ControlPlane.WorkspaceSlug
	}
	return workspace, token, nil
}

func (a App) pushWorkspaceTarget(st *store.FileStore, accessToken, requested string) (remoteWorkspaceResponse, string, error) {
	requested = strings.TrimSpace(requested)
	if _, err := localWorkspaceSlug(requested); err != nil {
		return remoteWorkspaceResponse{}, "", errors.New("--workspace requires a workspace slug")
	}
	if st.State.ControlPlane != nil && requested == st.State.ControlPlane.WorkspaceSlug {
		return remoteWorkspaceResponse{ID: st.State.ControlPlane.WorkspaceID, Slug: st.State.ControlPlane.WorkspaceSlug, CanPull: boolPtr(true), CanWrite: boolPtr(true), CurrentDeviceTrusted: boolPtr(true), CurrentDeviceID: st.State.ControlPlane.DeviceID}, accessToken, nil
	}
	workspaces, err := listRemoteWorkspaces(st, st.State.ControlPlane.Origin, accessToken)
	if err != nil {
		return remoteWorkspaceResponse{}, "", err
	}
	workspace, err := requireRemoteWorkspace(workspaces, requested)
	if err != nil {
		return remoteWorkspaceResponse{}, "", err
	}
	if workspace.CanWrite != nil && !*workspace.CanWrite {
		return remoteWorkspaceResponse{}, "", fmt.Errorf("this account cannot write secrets in workspace %s", requested)
	}
	if !workspaceDeviceTrusted(workspace, st.State.ControlPlane.WorkspaceID) {
		return remoteWorkspaceResponse{}, "", fmt.Errorf("this device is not trusted for workspace %s; device %s; next: %s", requested, currentDeviceDescription(st), deviceTrustCommand(st, requested))
	}
	token, err := a.ensureWorkspaceSession(st, accessToken, workspace)
	if err != nil {
		if workspaceNeedsDeviceTrust(err) {
			return remoteWorkspaceResponse{}, "", fmt.Errorf("this device is not trusted for workspace %s; device %s; next: %s", requested, currentDeviceDescription(st), deviceTrustCommand(st, requested))
		}
		return remoteWorkspaceResponse{}, "", err
	}
	if st.State.ControlPlane != nil {
		workspace.ID = st.State.ControlPlane.WorkspaceID
		workspace.Slug = st.State.ControlPlane.WorkspaceSlug
		workspace.CurrentDeviceTrusted = boolPtr(true)
		workspace.CanPull = boolPtr(true)
	}
	return workspace, token, nil
}

func (a App) pushWorkspaceTargetDryRun(st *store.FileStore, accessToken, requested string) (remoteWorkspaceResponse, string, func(), error) {
	restore := snapshotPushDryRunState(st)
	requested = strings.TrimSpace(requested)
	if _, err := localWorkspaceSlug(requested); err != nil {
		restore()
		return remoteWorkspaceResponse{}, "", nil, errors.New("--workspace requires a workspace slug")
	}
	if st.State.ControlPlane != nil && requested == st.State.ControlPlane.WorkspaceSlug {
		return remoteWorkspaceResponse{ID: st.State.ControlPlane.WorkspaceID, Slug: st.State.ControlPlane.WorkspaceSlug, CanPull: boolPtr(true), CanWrite: boolPtr(true), CurrentDeviceTrusted: boolPtr(true), CurrentDeviceID: st.State.ControlPlane.DeviceID}, accessToken, restore, nil
	}
	workspaces, err := listRemoteWorkspaces(st, st.State.ControlPlane.Origin, accessToken)
	if err != nil {
		restore()
		return remoteWorkspaceResponse{}, "", nil, err
	}
	workspace, err := requireRemoteWorkspace(workspaces, requested)
	if err != nil {
		restore()
		return remoteWorkspaceResponse{}, "", nil, err
	}
	if workspace.CanWrite != nil && !*workspace.CanWrite {
		restore()
		return remoteWorkspaceResponse{}, "", nil, fmt.Errorf("this account cannot write secrets in workspace %s", requested)
	}
	if !workspaceDeviceTrusted(workspace, st.State.ControlPlane.WorkspaceID) {
		restore()
		return remoteWorkspaceResponse{}, "", nil, fmt.Errorf("this device is not trusted for workspace %s; device %s; next: %s", requested, currentDeviceDescription(st), deviceTrustCommand(st, requested))
	}
	device, err := st.ActiveDevice()
	if err != nil {
		restore()
		return remoteWorkspaceResponse{}, "", nil, err
	}
	result, err := switchRemoteWorkspace(st, st.State.ControlPlane.Origin, accessToken, workspace.ID, *device)
	if err != nil {
		restore()
		if workspaceNeedsDeviceTrust(err) {
			return remoteWorkspaceResponse{}, "", nil, fmt.Errorf("this device is not trusted for workspace %s; device %s; next: %s", requested, currentDeviceDescription(st), deviceTrustCommand(st, requested))
		}
		return remoteWorkspaceResponse{}, "", nil, err
	}
	st.State.ControlPlane = transientControlPlaneLink(st.State.ControlPlane, result, device.ID)
	workspace.ID = result.OrgID
	workspace.Slug = result.WorkspaceSlug
	workspace.CurrentDeviceTrusted = boolPtr(true)
	workspace.CanPull = boolPtr(true)
	workspace.CanWrite = boolPtr(true)
	return workspace, result.AccessToken, restore, nil
}

func snapshotPushDryRunState(st *store.FileStore) func() {
	var controlPlane *asiri.ControlPlaneLink
	if st.State.ControlPlane != nil {
		copy := *st.State.ControlPlane
		controlPlane = &copy
	}
	remoteBindings := map[string]asiri.RemoteWorkspaceBinding{}
	for key, value := range st.State.RemoteBindings {
		remoteBindings[key] = value
	}
	return func() {
		st.State.ControlPlane = controlPlane
		st.State.RemoteBindings = remoteBindings
	}
}

func transientControlPlaneLink(current *asiri.ControlPlaneLink, result deviceCodeTokenResponse, localDeviceID string) *asiri.ControlPlaneLink {
	origin := ""
	if current != nil {
		origin = current.Origin
	}
	expiresAt := time.Now().UTC().Add(time.Duration(result.ExpiresIn) * time.Second)
	if result.ExpiresIn <= 0 {
		expiresAt = time.Now().UTC().Add(time.Hour)
	}
	return &asiri.ControlPlaneLink{
		Origin:               origin,
		WorkspaceID:          result.OrgID,
		WorkspaceSlug:        result.WorkspaceSlug,
		UserID:               result.UserID,
		DeviceID:             result.DeviceID,
		LocalDeviceID:        localDeviceID,
		Source:               "device-code",
		AccessTokenExpiresAt: expiresAt,
		RefreshExpiresAt:     expiresAt,
		LinkedAt:             time.Now().UTC(),
	}
}

func workspaceNeedsDeviceTrust(err error) bool {
	if err == nil {
		return false
	}
	message := err.Error()
	return strings.Contains(message, "trusted matching device required") || strings.Contains(message, "control plane returned HTTP 403")
}

func switchRemoteWorkspace(st *store.FileStore, origin, accessToken, workspace string, device asiri.Device) (deviceCodeTokenResponse, error) {
	body := map[string]string{
		"workspace":           workspace,
		"deviceName":          device.Name,
		"kind":                string(device.Kind),
		"encryptionPublicKey": device.EncryptionPublicKey,
		"signingPublicKey":    device.SigningPublicKey,
	}
	var result deviceCodeTokenResponse
	status, err := postJSONBearerStatus(st, strings.TrimRight(origin, "/")+"/v1/auth/session/switch", accessToken, body, &result)
	if err != nil {
		return result, err
	}
	if status < 200 || status >= 300 {
		if result.Message != "" {
			return result, fmt.Errorf("control plane returned HTTP %d: %s", status, result.Message)
		}
		if result.Error != "" {
			return result, fmt.Errorf("control plane returned HTTP %d: %s", status, result.Error)
		}
		return result, fmt.Errorf("control plane returned HTTP %d", status)
	}
	if result.Status != "approved" || result.OrgID == "" || result.WorkspaceSlug == "" || result.UserID == "" || result.DeviceID == "" || result.AccessToken == "" || result.RefreshToken == "" {
		return result, errors.New("control plane switched workspace without link metadata")
	}
	return result, nil
}

func remoteWriteOptions(st *store.FileStore, origin, accessToken string, refs []store.LocalSecretRef) (writeOptionsResponse, error) {
	entries := make([]map[string]string, 0, len(refs))
	seen := map[string]bool{}
	for _, ref := range refs {
		key := store.SecretKey(ref.Scope, ref.Name)
		if seen[key] {
			continue
		}
		seen[key] = true
		entries = append(entries, map[string]string{"scope": ref.Scope, "name": ref.Name})
	}
	var result writeOptionsResponse
	if err := postJSONBearer(st, strings.TrimRight(origin, "/")+"/v1/sync/write-options", accessToken, map[string]any{"entries": entries}, &result); err != nil {
		return result, err
	}
	if result.RequestedWorkspaceSlug == "" || result.ActiveWorkspace.Slug == "" {
		return result, errors.New("control plane returned incomplete write options")
	}
	return result, nil
}

func fullPathList(paths []writePathOption) string {
	values := make([]string, 0, len(paths))
	for _, path := range paths {
		if path.FullPath != "" {
			values = append(values, path.FullPath)
		}
	}
	sort.Strings(values)
	return strings.Join(values, ", ")
}

func workspaceRoleLabel(workspace remoteWorkspaceResponse, userID string) string {
	if workspace.Role != "" && workspace.Role != "none" {
		return workspace.Role
	}
	if workspace.OwnerUserID != "" && workspace.OwnerUserID == userID {
		return "owner"
	}
	if workspace.Role == "none" {
		return "none"
	}
	return "member"
}

func boolPointerLabel(value *bool) string {
	if value == nil {
		return "unknown"
	}
	if *value {
		return "yes"
	}
	return "no"
}

func deviceTrustLabel(value *bool) string {
	if value == nil {
		return "unknown"
	}
	if *value {
		return "trusted"
	}
	return "not trusted"
}

func deviceTrustCommand(st *store.FileStore, workspaceSlug string) string {
	command := fmt.Sprintf("asiri device trust --workspace %s", workspaceSlug)
	if st != nil && st.State.ControlPlane != nil && st.State.ControlPlane.Origin != "" && st.State.ControlPlane.Origin != defaultControlPlaneOrigin {
		command += fmt.Sprintf(" --origin %s", st.State.ControlPlane.Origin)
	}
	return command
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func printable(value string) string {
	if strings.TrimSpace(value) == "" {
		return "-"
	}
	return value
}

func currentDeviceDescription(st *store.FileStore) string {
	if st == nil {
		return "unknown"
	}
	device, err := st.ActiveDevice()
	if err != nil {
		return "unknown"
	}
	fingerprint := store.PublicKeyFingerprint(device.EncryptionPublicKey)
	if device.Name == "" {
		return fingerprint
	}
	return fmt.Sprintf("%s (%s)", device.Name, fingerprint)
}

func ensureControlPlaneAccess(origin string, st *store.FileStore) (string, error) {
	if st.State.ControlPlane == nil {
		return "", errors.New("asiri is not linked to a control plane")
	}
	if err := validateControlPlaneOrigin(origin); err != nil {
		return "", err
	}
	cached, cachedErr := st.ControlPlaneAccessToken()
	cacheFresh := cachedErr == nil && time.Until(st.State.ControlPlane.AccessTokenExpiresAt) > time.Minute
	if cacheFresh {
		return cached, nil
	}
	return refreshControlPlaneAccess(origin, st)
}

func refreshControlPlaneAccess(origin string, st *store.FileStore) (string, error) {
	if st.State.ControlPlane == nil {
		return "", errors.New("asiri is not linked to a control plane")
	}
	if err := validateControlPlaneOrigin(origin); err != nil {
		return "", err
	}
	result, status, err := refreshDeviceSession(origin, st)
	if err != nil {
		return "", err
	}
	if remoteDeviceNotTrusted(status, result.Error) {
		if err := st.QuarantineLocalKeys("remote device is no longer trusted"); err != nil {
			return "", fmt.Errorf("remote device is no longer trusted, but local key cleanup failed: %w", err)
		}
		return "", errors.New("remote device is no longer trusted; local key material was cleared")
	}
	if status != http.StatusOK {
		return "", fmt.Errorf("control plane returned HTTP %d", status)
	}
	if err := st.RefreshControlPlane(result.AccessToken, result.ExpiresIn, result.RefreshExpiresAt); err != nil {
		return "", err
	}
	return st.ControlPlaneAccessToken()
}

func rejectServiceAccountControlPlaneMutation(st *store.FileStore) error {
	if st != nil && st.State.ControlPlane != nil && st.State.ControlPlane.Source == "service-account" {
		return errors.New("service account sessions are read-only for control-plane mutations")
	}
	return nil
}

func rejectServiceAccountLocalMutation(st *store.FileStore) error {
	if st != nil && st.State.ControlPlane != nil && st.State.ControlPlane.Source == "service-account" {
		return errors.New("service account sessions cannot mutate local vault or policy state")
	}
	return nil
}

func remoteDeviceNotTrusted(status int, values ...string) bool {
	if status != http.StatusForbidden {
		return false
	}
	for _, value := range values {
		normalized := strings.ToLower(strings.TrimSpace(value))
		if normalized == "device_not_trusted" || normalized == "device not trusted" || normalized == "device is not trusted" {
			return true
		}
	}
	return false
}

type controlPlaneFailureResponse struct {
	Error   string `json:"error"`
	Message string `json:"message"`
}

func parseControlPlaneFailure(responseBody []byte) controlPlaneFailureResponse {
	var failure controlPlaneFailureResponse
	if len(bytes.TrimSpace(responseBody)) > 0 {
		_ = json.Unmarshal(responseBody, &failure)
	}
	return failure
}

func cleanupRemoteDeviceNotTrusted(st *store.FileStore, status int, errorCode, message string) error {
	if !remoteDeviceNotTrusted(status, errorCode, message) {
		return nil
	}
	if err := st.QuarantineLocalKeys("remote device is no longer trusted"); err != nil {
		return fmt.Errorf("remote device is no longer trusted, but local key cleanup failed: %w", err)
	}
	return errors.New("remote device is no longer trusted; local key material was cleared")
}

func revokeRemoteDevice(st *store.FileStore, origin, deviceID, accessToken string) (remoteDeviceResponse, error) {
	var result remoteDeviceResponse
	endpoint := strings.TrimRight(origin, "/") + "/v1/devices/" + url.PathEscape(deviceID) + "/revoke"
	if err := postJSONBearer(st, endpoint, accessToken, map[string]string{}, &result); err != nil {
		return result, err
	}
	if result.Status != "revoked" {
		return result, errors.New("control plane did not revoke the device")
	}
	return result, nil
}

func listRemoteDevices(st *store.FileStore, origin, orgID, accessToken string, includeRevoked bool) ([]remoteDeviceResponse, error) {
	var result remoteDevicesResponse
	endpoint := fmt.Sprintf("%s/v1/devices?orgId=%s", strings.TrimRight(origin, "/"), url.QueryEscape(orgID))
	if includeRevoked {
		endpoint += "&includeInactive=1"
	}
	if err := getJSONBearer(st, endpoint, accessToken, &result); err != nil {
		return nil, err
	}
	return result.Devices, nil
}

func listRemoteSecrets(st *store.FileStore, origin, orgID, accessToken, recoveryRecipientID string, includeInactive bool) ([]remoteSecretRecord, error) {
	var result remoteSecretsResponse
	endpoint := fmt.Sprintf("%s/v1/secrets/encrypted?orgId=%s", strings.TrimRight(origin, "/"), url.QueryEscape(orgID))
	if recoveryRecipientID != "" {
		endpoint += "&recoveryRecipientId=" + url.QueryEscape(recoveryRecipientID)
	}
	if includeInactive {
		endpoint += "&includeInactive=1"
	}
	if err := getJSONBearer(st, endpoint, accessToken, &result); err != nil {
		return nil, err
	}
	return result.Secrets, nil
}

func listRemoteSecretMetadata(st *store.FileStore, origin, orgID, accessToken string, includeInactive bool) ([]remoteSecretRecord, int, error) {
	var result remoteSecretsResponse
	endpoint := fmt.Sprintf("%s/v1/secrets?orgId=%s", strings.TrimRight(origin, "/"), url.QueryEscape(orgID))
	if includeInactive {
		endpoint += "&includeInactive=1"
	}
	status, err := getJSONBearerStatus(st, endpoint, accessToken, &result)
	if err != nil {
		return nil, status, err
	}
	if status == http.StatusNotFound {
		return nil, status, nil
	}
	if status < 200 || status >= 300 {
		return nil, status, fmt.Errorf("control plane returned HTTP %d", status)
	}
	return result.Secrets, status, nil
}

func mergeRemoteSecretRecords(primary, secondary []remoteSecretRecord) []remoteSecretRecord {
	if len(secondary) == 0 {
		return primary
	}
	merged := make([]remoteSecretRecord, 0, len(primary)+len(secondary))
	seen := map[string]bool{}
	for _, item := range primary {
		merged = append(merged, item)
		seen[pushVersionKey(item.Scope, item.Name, item.Version)] = true
	}
	for _, item := range secondary {
		key := pushVersionKey(item.Scope, item.Name, item.Version)
		if seen[key] {
			continue
		}
		merged = append(merged, item)
	}
	return merged
}

func getActiveRemoteRecoveryRecipient(st *store.FileStore, origin, orgID, accessToken string) (*asiri.RecoveryConfig, error) {
	var result remoteRecoveryRecipientResponse
	endpoint := fmt.Sprintf("%s/v1/recovery-recipient?orgId=%s", strings.TrimRight(origin, "/"), url.QueryEscape(orgID))
	status, err := getJSONBearerStatus(st, endpoint, accessToken, &result)
	if err != nil {
		return nil, err
	}
	if status == http.StatusNotFound {
		return nil, nil
	}
	if status < 200 || status >= 300 {
		return nil, fmt.Errorf("control plane returned HTTP %d", status)
	}
	if result.Status != "active" || result.RecipientID == "" || result.PublicKey == "" || result.PublicKeyFingerprint == "" {
		return nil, errors.New("control plane returned incomplete recovery recipient metadata")
	}
	return &asiri.RecoveryConfig{
		RecipientID:          result.RecipientID,
		PublicKey:            result.PublicKey,
		PublicKeyFingerprint: result.PublicKeyFingerprint,
		CreatedAt:            time.Now().UTC(),
	}, nil
}

func listVisibleRemoteSecrets(st *store.FileStore, origin, accessToken string, includeInactive bool) ([]visibleRemoteSecretRecord, error) {
	result, err := listRemoteWorkspaceOverview(st, origin, accessToken, true, includeInactive)
	if err != nil {
		return nil, err
	}
	if result.Secrets == nil {
		return nil, errors.New("control plane did not return workspace secret metadata")
	}
	return result.Secrets, nil
}

func resolveActiveRemoteSecret(st *store.FileStore, origin, accessToken string, target remoteWorkspaceResponse, scope, name string) (visibleRemoteSecretRecord, error) {
	secrets, err := listVisibleRemoteSecrets(st, origin, accessToken, false)
	if err != nil {
		return visibleRemoteSecretRecord{}, err
	}
	matches := []visibleRemoteSecretRecord{}
	for _, secret := range secrets {
		if secret.Status != "active" || secret.Scope != scope || secret.Name != name {
			continue
		}
		if !visibleSecretInWorkspace(secret, target) {
			continue
		}
		matches = append(matches, secret)
	}
	fullPath := store.SecretKey(scope, name)
	if len(matches) == 0 {
		return visibleRemoteSecretRecord{}, fmt.Errorf("no active remote secret found for %s in workspace %s", fullPath, target.Slug)
	}
	if len(matches) > 1 {
		return visibleRemoteSecretRecord{}, fmt.Errorf("multiple active remote secrets found for %s in workspace %s", fullPath, target.Slug)
	}
	return matches[0], nil
}

func resolveDeletedRemoteSecret(st *store.FileStore, origin, accessToken string, target remoteWorkspaceResponse, scope, name string) (visibleRemoteSecretRecord, error) {
	secrets, err := listVisibleRemoteSecrets(st, origin, accessToken, true)
	if err != nil {
		return visibleRemoteSecretRecord{}, err
	}
	matches := []visibleRemoteSecretRecord{}
	for _, secret := range secrets {
		if secret.Status != "deleted" || secret.Scope != scope || secret.Name != name {
			continue
		}
		if !visibleSecretInWorkspace(secret, target) {
			continue
		}
		matches = append(matches, secret)
	}
	fullPath := store.SecretKey(scope, name)
	if len(matches) == 0 {
		return visibleRemoteSecretRecord{}, fmt.Errorf("no deleted remote secret found for %s in workspace %s", fullPath, target.Slug)
	}
	sort.Slice(matches, func(i, j int) bool {
		if matches[i].Version == matches[j].Version {
			return matches[i].ID < matches[j].ID
		}
		return matches[i].Version > matches[j].Version
	})
	return matches[0], nil
}

func visibleSecretInWorkspace(secret visibleRemoteSecretRecord, target remoteWorkspaceResponse) bool {
	if target.ID != "" && secret.OrgID != "" {
		return secret.OrgID == target.ID
	}
	if secret.WorkspaceSlug != "" {
		return secret.WorkspaceSlug == target.Slug
	}
	return store.WorkspacePrefix(secret.Scope) == target.Slug
}

func remoteOnlyDeleteCandidates(st *store.FileStore, target remoteWorkspaceResponse, secrets []visibleRemoteSecretRecord, requireUnwrapped bool) []visibleRemoteSecretRecord {
	candidates := []visibleRemoteSecretRecord{}
	for _, secret := range secrets {
		if secret.Status != "active" || !visibleSecretInWorkspace(secret, target) {
			continue
		}
		if requireUnwrapped && (secret.WrappedToCurrentDevice == nil || *secret.WrappedToCurrentDevice) {
			continue
		}
		if localActiveSecretExists(st, secret.Scope, secret.Name) {
			continue
		}
		candidates = append(candidates, secret)
	}
	sort.Slice(candidates, func(i, j int) bool {
		left := shortSecretPath(candidates[i].Scope, candidates[i].Name)
		right := shortSecretPath(candidates[j].Scope, candidates[j].Name)
		if left == right {
			return candidates[i].ID < candidates[j].ID
		}
		return left < right
	})
	return candidates
}

func deleteRemoteSecret(st *store.FileStore, origin, secretID string, version int, deviceID, accessToken string) (visibleRemoteSecretRecord, error) {
	result, err := requestRemoteSecretDelete(st, origin, secretID, version, deviceID, accessToken)
	if err != nil {
		return result, err
	}
	if result.Status != "deleted" {
		return result, errors.New("control plane did not mark the secret deleted")
	}
	return result, nil
}

func preflightRemoteSecretDelete(st *store.FileStore, origin, secretID string, version int, deviceID, accessToken string) error {
	result, err := requestRemoteSecretDeletePreflight(st, origin, secretID, version, deviceID, accessToken)
	if err != nil {
		return err
	}
	if result.ID == "" {
		return errors.New("control plane did not return delete preflight metadata")
	}
	return nil
}

func requestRemoteSecretDelete(st *store.FileStore, origin, secretID string, version int, deviceID, accessToken string) (visibleRemoteSecretRecord, error) {
	var result visibleRemoteSecretRecord
	endpoint := strings.TrimRight(origin, "/") + "/v1/secrets/" + url.PathEscape(secretID) + "/delete"
	body := map[string]any{"createdByDeviceId": deviceID, "version": version}
	if err := postJSONBearer(st, endpoint, accessToken, body, &result); err != nil {
		return result, err
	}
	return result, nil
}

func requestRemoteSecretDeletePreflight(st *store.FileStore, origin, secretID string, version int, deviceID, accessToken string) (visibleRemoteSecretRecord, error) {
	var result visibleRemoteSecretRecord
	endpoint := strings.TrimRight(origin, "/") + "/v1/secrets/" + url.PathEscape(secretID) + "/delete-preflight"
	body := map[string]any{"createdByDeviceId": deviceID, "version": version}
	if err := postJSONBearer(st, endpoint, accessToken, body, &result); err != nil {
		return result, err
	}
	return result, nil
}

func restoreRemoteSecret(st *store.FileStore, origin, secretID string, version int, deviceID, accessToken string) (visibleRemoteSecretRecord, error) {
	var result visibleRemoteSecretRecord
	endpoint := strings.TrimRight(origin, "/") + "/v1/secrets/" + url.PathEscape(secretID) + "/restore"
	body := map[string]any{"createdByDeviceId": deviceID, "version": version}
	if err := postJSONBearer(st, endpoint, accessToken, body, &result); err != nil {
		return result, err
	}
	if result.Status != "active" {
		return result, errors.New("control plane did not restore the secret")
	}
	return result, nil
}

func addRemoteWrappedKeys(st *store.FileStore, origin, secretID, accessToken string, wrappedKeys []store.RemoteWrappedKey, localRepair bool) error {
	endpoint := strings.TrimRight(origin, "/") + "/v1/secrets/" + url.PathEscape(secretID) + "/wrapped-keys"
	body := map[string]any{"wrappedKeys": wrappedKeys}
	if localRepair {
		body["localRepair"] = true
	}
	return postJSONBearer(st, endpoint, accessToken, body, nil)
}

func registerRemoteRecoveryRecipient(st *store.FileStore, origin, accessToken string, setup store.RecoverySetup, replacements []recoveryRecipientReplacement) error {
	if replacements == nil {
		replacements = []recoveryRecipientReplacement{}
	}
	endpoint := strings.TrimRight(origin, "/") + "/v1/recovery-recipient"
	return postJSONBearer(st, endpoint, accessToken, map[string]any{
		"orgId":                st.State.ControlPlane.WorkspaceID,
		"recipientId":          setup.RecipientID,
		"publicKey":            setup.PublicKey,
		"publicKeyFingerprint": setup.Fingerprint,
		"replacements":         replacements,
	}, nil)
}

func replaceRemoteRecoveryRecipient(st *store.FileStore, origin, accessToken string, setup store.RecoverySetup, replacements []recoveryRecipientReplacement) error {
	if replacements == nil {
		replacements = []recoveryRecipientReplacement{}
	}
	endpoint := strings.TrimRight(origin, "/") + "/v1/recovery-recipient/replace"
	return postJSONBearer(st, endpoint, accessToken, map[string]any{
		"orgId":                st.State.ControlPlane.WorkspaceID,
		"recipientId":          setup.RecipientID,
		"publicKey":            setup.PublicKey,
		"publicKeyFingerprint": setup.Fingerprint,
		"replacements":         replacements,
	}, nil)
}

func addRecoveryRestoredWrappedKeys(st *store.FileStore, origin, secretID, accessToken, recoveryRecipientID string, wrappedKeys []store.RemoteWrappedKey) error {
	endpoint := strings.TrimRight(origin, "/") + "/v1/secrets/" + url.PathEscape(secretID) + "/recovery-wrapped-keys"
	return postJSONBearer(st, endpoint, accessToken, map[string]any{"recoveryRecipientId": recoveryRecipientID, "wrappedKeys": wrappedKeys}, nil)
}

func remoteRecordsToVersions(records []remoteSecretRecord) []store.RemoteSecretVersion {
	versions := make([]store.RemoteSecretVersion, 0, len(records))
	for _, record := range records {
		if record.Status != "active" {
			continue
		}
		versions = append(versions, store.RemoteSecretVersion{
			ID:                record.ID,
			OrgID:             record.OrgID,
			Scope:             record.Scope,
			Name:              record.Name,
			Version:           record.Version,
			Algorithm:         record.Algorithm,
			Nonce:             record.Nonce,
			Ciphertext:        record.Ciphertext,
			AAD:               record.AAD,
			WrappedKeys:       record.WrappedKeys,
			Status:            record.Status,
			CreatedByDeviceID: record.CreatedByDeviceID,
			CreatedAt:         record.CreatedAt,
		})
	}
	return versions
}

func remoteSecretHasRecipient(secret remoteSecretRecord, deviceID string) bool {
	for _, key := range secret.WrappedKeys {
		if key.RecipientType == "device" && key.RecipientID == deviceID {
			return true
		}
	}
	for _, key := range secret.WrappedRecipients {
		if key.RecipientType == "device" && key.RecipientID == deviceID {
			return true
		}
	}
	return false
}

func remoteSecretHasRecoveryRecipient(secret remoteSecretRecord, recipientID string) bool {
	for _, key := range secret.WrappedKeys {
		if key.RecipientType == "recovery" && key.RecipientID == recipientID {
			return true
		}
	}
	for _, key := range secret.WrappedRecipients {
		if key.RecipientType == "recovery" && key.RecipientID == recipientID {
			return true
		}
	}
	return false
}

func localSecretVersionExists(st *store.FileStore, scope, name string, versionNumber int) bool {
	secret, ok := st.State.Secrets[store.SecretKey(scope, name)]
	if !ok {
		return false
	}
	for _, version := range secret.Versions {
		if version.Version == versionNumber && version.DataKeyAccount != "" {
			return true
		}
	}
	return false
}

func localActiveSecretExists(st *store.FileStore, scope, name string) bool {
	secret, ok := st.State.Secrets[store.SecretKey(scope, name)]
	if !ok {
		return false
	}
	return activeVersion(secret) != nil
}

func localSecretWorkspacePrefixes(refs []store.LocalSecretRef) []string {
	seen := map[string]bool{}
	for _, ref := range refs {
		prefix := store.WorkspacePrefix(ref.Scope)
		if prefix != "" {
			seen[prefix] = true
		}
	}
	values := make([]string, 0, len(seen))
	for prefix := range seen {
		values = append(values, prefix)
	}
	sort.Strings(values)
	return values
}

type listRow struct {
	Path          string
	Version       int
	NameHash      string
	Status        string
	VersionStatus string
	Keys          string
	Workspace     string
	WorkspaceID   string
	HasLocal      bool
	HasRemote     bool
	RemoteStatus  string
}

type listActionSummary struct {
	rewrapHere     map[string]int
	rewrapAtSource map[string]int
	trustDevice    map[string]int
}

func newListActionSummary() *listActionSummary {
	return &listActionSummary{
		rewrapHere:     map[string]int{},
		rewrapAtSource: map[string]int{},
		trustDevice:    map[string]int{},
	}
}

func (summary *listActionSummary) Add(row listRow) {
	switch row.Keys {
	case "needs rewrap":
		summary.rewrapHere[row.Workspace]++
	case "unwrapped":
		summary.rewrapAtSource[row.Workspace]++
	case "not trusted":
		summary.trustDevice[row.Workspace]++
	}
}

func (summary *listActionSummary) Write(out io.Writer) {
	workspaceSet := map[string]bool{}
	for workspace := range summary.rewrapHere {
		workspaceSet[workspace] = true
	}
	for workspace := range summary.rewrapAtSource {
		workspaceSet[workspace] = true
	}
	for workspace := range summary.trustDevice {
		workspaceSet[workspace] = true
	}
	if len(workspaceSet) == 0 {
		return
	}
	workspaces := make([]string, 0, len(workspaceSet))
	for workspace := range workspaceSet {
		workspaces = append(workspaces, workspace)
	}
	sort.Strings(workspaces)
	fmt.Fprintln(out, "\nNext:")
	for _, workspace := range workspaces {
		if count := summary.rewrapHere[workspace]; count > 0 {
			fmt.Fprintf(out, "  %s: run asiri rewrap --workspace %s here for %d repairable key(s).\n", workspace, workspace, count)
		}
		if count := summary.rewrapAtSource[workspace]; count > 0 {
			fmt.Fprintf(out, "  %s: run asiri rewrap --workspace %s on a device where these secrets are wrapped, then run asiri pull --workspace %s here for %d unwrapped key(s).\n", workspace, workspace, workspace, count)
		}
		if count := summary.trustDevice[workspace]; count > 0 {
			fmt.Fprintf(out, "  %s: run asiri device trust --workspace %s before pulling %d remote key(s).\n", workspace, workspace, count)
		}
	}
}

func activeVersion(secret asiri.Secret) *asiri.SecretVersion {
	for i := range secret.Versions {
		if secret.Versions[i].Version == secret.ActiveVersion && secret.Versions[i].Status == "active" {
			return &secret.Versions[i]
		}
	}
	return nil
}

func matchesListFilter(row listRow, filter string, workspaces map[string]bool, status string, localOnly, remoteOnly bool) bool {
	if localOnly && !row.HasLocal {
		return false
	}
	if remoteOnly && !row.HasRemote {
		return false
	}
	if len(workspaces) > 0 && !workspaces[row.Workspace] {
		return false
	}
	if status != "" && row.Status != status && row.RemoteStatus != status {
		return false
	}
	if filter == "" {
		return true
	}
	return strings.Contains(row.Path, filter)
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func shortSecretPath(scope, name string) string {
	prefix := store.WorkspacePrefix(scope)
	shortScope := scope
	if prefix != "" {
		shortScope = strings.TrimPrefix(scope, prefix+"/")
	}
	if shortScope == "" {
		return name
	}
	return store.SecretKey(shortScope, name)
}

func boundWorkspaceID(st *store.FileStore, workspaceSlug string) string {
	if st == nil || workspaceSlug == "" {
		return ""
	}
	if binding, ok := st.RemoteBindingForPrefix(workspaceSlug); ok {
		return binding.WorkspaceID
	}
	if st.State.ControlPlane != nil && st.State.ControlPlane.WorkspaceSlug == workspaceSlug {
		return st.State.ControlPlane.WorkspaceID
	}
	return ""
}

func postJSON(url string, body any, out any) error {
	status, err := postJSONStatus(url, body, out)
	if err != nil {
		return err
	}
	if status < 200 || status >= 300 {
		return fmt.Errorf("control plane returned HTTP %d", status)
	}
	return nil
}

func postJSONBearer(st *store.FileStore, url, bearer string, body any, out any) error {
	status, err := postJSONBearerStatus(st, url, bearer, body, out)
	if err != nil {
		return err
	}
	if status < 200 || status >= 300 {
		return fmt.Errorf("control plane returned HTTP %d", status)
	}
	return nil
}

func postJSONBearerStatus(st *store.FileStore, url, bearer string, body any, out any) (int, error) {
	return postJSONBearerStatusWithClient(st, http.DefaultClient, url, bearer, body, out)
}

func postJSONBearerTimeout(st *store.FileStore, url, bearer string, body any, out any, timeout time.Duration) error {
	status, err := postJSONBearerStatusWithClient(st, &http.Client{Timeout: timeout}, url, bearer, body, out)
	if err != nil {
		return err
	}
	if status < 200 || status >= 300 {
		return fmt.Errorf("control plane returned HTTP %d", status)
	}
	return nil
}

func postJSONBearerStatusWithClient(st *store.FileStore, client *http.Client, url, bearer string, body any, out any) (int, error) {
	encoded, err := json.Marshal(body)
	if err != nil {
		return 0, err
	}
	status, responseBody, err := sendPostJSONBearer(st, client, url, bearer, encoded)
	if err != nil {
		return status, err
	}
	if status == http.StatusUnauthorized {
		if refreshed, ok, err := refreshBearerAfterUnauthorized(st, bearer); err != nil {
			return status, err
		} else if ok {
			status, responseBody, err = sendPostJSONBearer(st, client, url, refreshed, encoded)
			if err != nil {
				return status, err
			}
		}
	}
	return decodeBearerResponse(status, responseBody, out, st)
}

func sendPostJSONBearer(st *store.FileStore, client *http.Client, url, bearer string, encoded []byte) (int, []byte, error) {
	request, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(encoded))
	if err != nil {
		return 0, nil, err
	}
	request.Header.Set("content-type", "application/json")
	request.Header.Set("accept", "application/json")
	request.Header.Set("authorization", "Bearer "+bearer)
	if err := signBearerRequest(st, request, encoded, bearer); err != nil {
		return 0, nil, err
	}
	response, err := client.Do(request)
	if err != nil {
		return 0, nil, err
	}
	defer response.Body.Close()
	responseBody, err := io.ReadAll(response.Body)
	if err != nil {
		return response.StatusCode, nil, err
	}
	return response.StatusCode, responseBody, nil
}

func getJSONBearer(st *store.FileStore, url, bearer string, out any) error {
	status, err := getJSONBearerStatus(st, url, bearer, out)
	if err != nil {
		return err
	}
	if status < 200 || status >= 300 {
		return fmt.Errorf("control plane returned HTTP %d", status)
	}
	return nil
}

func getJSONBearerStatus(st *store.FileStore, url, bearer string, out any) (int, error) {
	status, responseBody, err := sendGetJSONBearer(st, http.DefaultClient, url, bearer)
	if err != nil {
		return status, err
	}
	if status == http.StatusUnauthorized {
		if refreshed, ok, err := refreshBearerAfterUnauthorized(st, bearer); err != nil {
			return status, err
		} else if ok {
			status, responseBody, err = sendGetJSONBearer(st, http.DefaultClient, url, refreshed)
			if err != nil {
				return status, err
			}
		}
	}
	return decodeBearerResponse(status, responseBody, out, st)
}

func sendGetJSONBearer(st *store.FileStore, client *http.Client, url, bearer string) (int, []byte, error) {
	request, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return 0, nil, err
	}
	request.Header.Set("authorization", "Bearer "+bearer)
	if err := signBearerRequest(st, request, nil, bearer); err != nil {
		return 0, nil, err
	}
	response, err := client.Do(request)
	if err != nil {
		return 0, nil, err
	}
	defer response.Body.Close()
	responseBody, err := io.ReadAll(response.Body)
	if err != nil {
		return response.StatusCode, nil, err
	}
	return response.StatusCode, responseBody, nil
}

func decodeBearerResponse(status int, responseBody []byte, out any, st *store.FileStore) (int, error) {
	if status < 200 || status >= 300 {
		failure := parseControlPlaneFailure(responseBody)
		if err := cleanupRemoteDeviceNotTrusted(st, status, failure.Error, failure.Message); err != nil {
			return status, err
		}
		if status == http.StatusNotFound {
			return status, nil
		}
		if failure.Message != "" {
			return status, fmt.Errorf("control plane returned HTTP %d: %s", status, failure.Message)
		}
		if failure.Error != "" {
			return status, fmt.Errorf("control plane returned HTTP %d: %s", status, failure.Error)
		}
		return status, nil
	}
	if out != nil && len(bytes.TrimSpace(responseBody)) > 0 {
		if err := json.Unmarshal(responseBody, out); err != nil {
			return status, fmt.Errorf("control plane returned invalid JSON response: %w", err)
		}
	}
	return status, nil
}

func refreshBearerAfterUnauthorized(st *store.FileStore, bearer string) (string, bool, error) {
	if st == nil || st.State.ControlPlane == nil || st.State.ControlPlane.Origin == "" {
		return "", false, nil
	}
	current, err := st.ControlPlaneAccessToken()
	if err != nil || current != bearer {
		return "", false, nil
	}
	refreshed, err := refreshControlPlaneAccess(st.State.ControlPlane.Origin, st)
	if err != nil {
		return "", false, err
	}
	return refreshed, true, nil
}

func signBearerRequest(st *store.FileStore, request *http.Request, body []byte, bearer string) error {
	return signDeviceRequest(st, request, body, credentialHash(bearer))
}

func signDeviceRequest(st *store.FileStore, request *http.Request, body []byte, credentialHash string) error {
	if st.State.ControlPlane == nil || st.State.ControlPlane.DeviceID == "" {
		return errors.New("control plane device is not linked")
	}
	if credentialHash == "" {
		return errors.New("device request credential binding is required")
	}
	privateKey, err := st.DeviceSigningPrivateKey()
	if err != nil {
		return err
	}
	bodyDigest := sha256.Sum256(body)
	timestamp := time.Now().UTC().Format(time.RFC3339)
	nonceBytes := make([]byte, 16)
	if _, err := rand.Read(nonceBytes); err != nil {
		return err
	}
	nonce := base64.RawURLEncoding.EncodeToString(nonceBytes)
	canonical := strings.Join([]string{
		"asiri-device-request-v1",
		request.Method,
		request.URL.RequestURI(),
		hex.EncodeToString(bodyDigest[:]),
		timestamp,
		nonce,
		st.State.ControlPlane.DeviceID,
		credentialHash,
	}, "\n")
	canonicalDigest := sha256.Sum256([]byte(canonical))
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, canonicalDigest[:])
	if err != nil {
		return err
	}
	signature := make([]byte, 64)
	r.FillBytes(signature[:32])
	s.FillBytes(signature[32:])
	request.Header.Set("x-asiri-device", st.State.ControlPlane.DeviceID)
	request.Header.Set("x-asiri-timestamp", timestamp)
	request.Header.Set("x-asiri-nonce", nonce)
	request.Header.Set("x-asiri-signature", base64.RawURLEncoding.EncodeToString(signature))
	return nil
}

func signDeviceCodeClaimRequest(st *store.FileStore, request *http.Request, body []byte, credentialHash string) error {
	if credentialHash == "" {
		return errors.New("device-code claim credential binding is required")
	}
	privateKey, err := st.LocalDeviceSigningPrivateKey()
	if err != nil {
		return err
	}
	bodyDigest := sha256.Sum256(body)
	timestamp := time.Now().UTC().Format(time.RFC3339)
	nonceBytes := make([]byte, 16)
	if _, err := rand.Read(nonceBytes); err != nil {
		return err
	}
	nonce := base64.RawURLEncoding.EncodeToString(nonceBytes)
	canonical := strings.Join([]string{
		"asiri-device-code-claim-v1",
		request.Method,
		request.URL.RequestURI(),
		hex.EncodeToString(bodyDigest[:]),
		timestamp,
		nonce,
		credentialHash,
	}, "\n")
	canonicalDigest := sha256.Sum256([]byte(canonical))
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, canonicalDigest[:])
	if err != nil {
		return err
	}
	signature := make([]byte, 64)
	r.FillBytes(signature[:32])
	s.FillBytes(signature[32:])
	request.Header.Set("x-asiri-timestamp", timestamp)
	request.Header.Set("x-asiri-nonce", nonce)
	request.Header.Set("x-asiri-signature", base64.RawURLEncoding.EncodeToString(signature))
	return nil
}

func credentialHash(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}

func postJSONDeviceCodeClaimStatus(st *store.FileStore, url string, body any, credentialHash string, out any) (int, error) {
	encoded, err := json.Marshal(body)
	if err != nil {
		return 0, err
	}
	request, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(encoded))
	if err != nil {
		return 0, err
	}
	request.Header.Set("content-type", "application/json")
	request.Header.Set("accept", "application/json")
	if err := signDeviceCodeClaimRequest(st, request, encoded, credentialHash); err != nil {
		return 0, err
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return 0, err
	}
	defer response.Body.Close()
	if err := decodeJSONResponse(response, out); err != nil {
		return response.StatusCode, err
	}
	return response.StatusCode, nil
}

func postJSONDeviceSignedStatus(st *store.FileStore, url string, body any, credentialHash string, out any) (int, error) {
	encoded, err := json.Marshal(body)
	if err != nil {
		return 0, err
	}
	request, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(encoded))
	if err != nil {
		return 0, err
	}
	request.Header.Set("content-type", "application/json")
	request.Header.Set("accept", "application/json")
	if err := signDeviceRequest(st, request, encoded, credentialHash); err != nil {
		return 0, err
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return 0, err
	}
	defer response.Body.Close()
	if err := decodeJSONResponse(response, out); err != nil {
		return response.StatusCode, err
	}
	return response.StatusCode, nil
}

func postJSONStatus(url string, body any, out any) (int, error) {
	encoded, err := json.Marshal(body)
	if err != nil {
		return 0, err
	}
	request, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(encoded))
	if err != nil {
		return 0, err
	}
	request.Header.Set("content-type", "application/json")
	request.Header.Set("accept", "application/json")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return 0, err
	}
	defer response.Body.Close()
	if err := decodeJSONResponse(response, out); err != nil {
		return response.StatusCode, err
	}
	return response.StatusCode, nil
}

func decodeJSONResponse(response *http.Response, out any) error {
	if out == nil {
		return nil
	}
	responseBody, err := io.ReadAll(response.Body)
	if err != nil {
		return err
	}
	if len(bytes.TrimSpace(responseBody)) == 0 {
		return nil
	}
	if err := json.Unmarshal(responseBody, out); err != nil {
		return nonJSONControlPlaneResponseError(response, responseBody, err)
	}
	return nil
}

func nonJSONControlPlaneResponseError(response *http.Response, body []byte, decodeErr error) error {
	contentType := response.Header.Get("content-type")
	if response.Header.Get("cf-mitigated") != "" || bytes.Contains(body, []byte("Just a moment")) {
		return fmt.Errorf("control plane returned HTTP %d with a Cloudflare challenge instead of JSON; API routes should bypass WAF challenges and rely on rate limits", response.StatusCode)
	}
	if contentType != "" && !strings.Contains(strings.ToLower(contentType), "json") {
		return fmt.Errorf("control plane returned HTTP %d with non-JSON content type %q", response.StatusCode, contentType)
	}
	return decodeErr
}

func createDevice(name string) (asiri.Device, []asiri.KeyRef, error) {
	deviceID := store.NewID("dev")
	encryptionPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return asiri.Device{}, nil, err
	}
	signingPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return asiri.Device{}, nil, err
	}
	encryptionPrivateBytes, err := x509.MarshalECPrivateKey(encryptionPrivateKey)
	if err != nil {
		return asiri.Device{}, nil, err
	}
	signingPrivateBytes, err := x509.MarshalECPrivateKey(signingPrivateKey)
	if err != nil {
		return asiri.Device{}, nil, err
	}
	encryptionPublicBytes, err := x509.MarshalPKIXPublicKey(&encryptionPrivateKey.PublicKey)
	if err != nil {
		return asiri.Device{}, nil, err
	}
	signingPublicBytes, err := x509.MarshalPKIXPublicKey(&signingPrivateKey.PublicKey)
	if err != nil {
		return asiri.Device{}, nil, err
	}
	encryptionAccount := keystore.DeviceKeyAccount(deviceID, "encryption-private")
	signingAccount := keystore.DeviceKeyAccount(deviceID, "signing-private")
	if err := keystore.Store(encryptionAccount, base64.StdEncoding.EncodeToString(encryptionPrivateBytes)); err != nil {
		return asiri.Device{}, nil, err
	}
	if err := keystore.Store(signingAccount, base64.StdEncoding.EncodeToString(signingPrivateBytes)); err != nil {
		_ = keystore.Delete(encryptionAccount)
		return asiri.Device{}, nil, err
	}
	return asiri.Device{
			ID:                  deviceID,
			Name:                name,
			Kind:                "laptop",
			Status:              asiri.DeviceTrusted,
			EncryptionPublicKey: base64.StdEncoding.EncodeToString(encryptionPublicBytes),
			SigningPublicKey:    base64.StdEncoding.EncodeToString(signingPublicBytes),
			CreatedAt:           time.Now().UTC(),
		}, []asiri.KeyRef{
			{Purpose: "device-encryption-private-key", Account: encryptionAccount},
			{Purpose: "device-signing-private-key", Account: signingAccount},
		}, nil
}

func hasFlag(args []string, flag string) bool {
	for _, arg := range args {
		if arg == flag {
			return true
		}
	}
	return false
}

func removeStandaloneFlag(args []string, flag string) []string {
	out := make([]string, 0, len(args))
	for _, arg := range args {
		if arg == flag {
			continue
		}
		out = append(out, arg)
	}
	return out
}

func firstPositional(args []string) string {
	for _, arg := range args {
		if strings.HasPrefix(arg, "--") {
			continue
		}
		return arg
	}
	return ""
}

func positionalArgs(args []string) []string {
	positionals := []string{}
	for _, arg := range args {
		if arg == "--" {
			break
		}
		if strings.HasPrefix(arg, "-") {
			continue
		}
		positionals = append(positionals, arg)
	}
	return positionals
}

func positionalArgsSkippingFlagValues(args []string, flagsWithValues ...string) []string {
	valueFlags := map[string]bool{}
	for _, flag := range flagsWithValues {
		valueFlags[flag] = true
	}
	positionals := []string{}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			break
		}
		if strings.HasPrefix(arg, "-") {
			if valueFlags[arg] {
				i++
			}
			continue
		}
		positionals = append(positionals, arg)
	}
	return positionals
}

func firstPositionalSkippingFlagValues(args []string, flagsWithValues ...string) string {
	valueFlags := map[string]bool{}
	for _, flag := range flagsWithValues {
		valueFlags[flag] = true
	}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			return ""
		}
		if strings.HasPrefix(arg, "--") {
			if valueFlags[arg] {
				i++
			}
			continue
		}
		return arg
	}
	return ""
}

func flagValue(args []string, flag, fallback string) string {
	for i := range args {
		if args[i] == flag && i+1 < len(args) {
			return args[i+1]
		}
	}
	return fallback
}

func optionalFlagValue(args []string, flag string) (string, bool, error) {
	for i := range args {
		if args[i] != flag {
			continue
		}
		if i+1 >= len(args) || strings.HasPrefix(args[i+1], "--") {
			return "", true, fmt.Errorf("%s requires a value", flag)
		}
		return args[i+1], true, nil
	}
	return "", false, nil
}

func splitWorkspaceFlag(args []string, command string, required bool) (string, []string, error) {
	workspace := ""
	remaining := []string{}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			remaining = append(remaining, args[i:]...)
			break
		}
		if arg == "--workspace" || arg == "-w" {
			if workspace != "" {
				return "", nil, fmt.Errorf("%s accepts one --workspace value", command)
			}
			if i+1 >= len(args) || strings.HasPrefix(args[i+1], "-") {
				return "", nil, fmt.Errorf("%s --workspace requires a slug", command)
			}
			workspace = args[i+1]
			i++
			continue
		}
		remaining = append(remaining, arg)
	}
	if required && workspace == "" {
		return "", nil, fmt.Errorf("%s requires --workspace <slug>", command)
	}
	return workspace, remaining, nil
}

func splitWorkspaceFilters(args []string, command string) ([]string, []string, error) {
	workspaces := []string{}
	remaining := []string{}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			remaining = append(remaining, args[i:]...)
			break
		}
		if arg == "--workspace" || arg == "-w" {
			if i+1 >= len(args) || strings.HasPrefix(args[i+1], "-") {
				return nil, nil, fmt.Errorf("%s --workspace requires a slug", command)
			}
			workspaces = append(workspaces, args[i+1])
			i++
			continue
		}
		remaining = append(remaining, arg)
	}
	return workspaces, remaining, nil
}

func rejectUnknownArgs(args []string, allowedFlags ...string) error {
	allowed := map[string]bool{}
	for _, flag := range allowedFlags {
		allowed[flag] = true
	}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			return nil
		}
		if !strings.HasPrefix(arg, "-") {
			continue
		}
		if !allowed[arg] {
			return fmt.Errorf("unknown option %q", arg)
		}
		switch arg {
		case "--value-file", "--key-file", "--output-file", "--agent", "--dir", "--limit", "--scope", "--secret", "--version", "--where", "--confirm-token":
			i++
		}
	}
	return nil
}

func (a App) workspaceSlugTarget(st *store.FileStore, value, command string) (string, error) {
	slug, err := localWorkspaceSlug(value)
	if err == nil {
		return slug, nil
	}
	if st == nil || st.State.ControlPlane == nil {
		return "", fmt.Errorf("%s --workspace must be a workspace slug before login", command)
	}
	accessToken, accessErr := ensureControlPlaneAccess(st.State.ControlPlane.Origin, st)
	if accessErr != nil {
		return "", accessErr
	}
	workspaces, listErr := listRemoteWorkspaces(st, st.State.ControlPlane.Origin, accessToken)
	if listErr != nil {
		return "", listErr
	}
	workspace, ok := findWorkspace(workspaces, strings.TrimSpace(value))
	if !ok {
		return "", fmt.Errorf("workspace %s is not visible", value)
	}
	if workspace.Slug == "" {
		return "", fmt.Errorf("workspace %s does not have a slug", value)
	}
	return workspace.Slug, nil
}

func (a App) workspaceFilterSet(st *store.FileStore, values []string, command string) (map[string]bool, error) {
	if len(values) == 0 {
		return nil, nil
	}
	filters := map[string]bool{}
	for _, value := range values {
		slug, err := a.workspaceSlugTarget(st, value, command)
		if err != nil {
			return nil, err
		}
		filters[slug] = true
	}
	return filters, nil
}

func localWorkspaceFilterSet(values []string, command string) (map[string]bool, error) {
	if len(values) == 0 {
		return nil, nil
	}
	filters := map[string]bool{}
	for _, value := range values {
		slug, err := localWorkspaceSlug(value)
		if err != nil {
			return nil, fmt.Errorf("%s --workspace must be a workspace slug", command)
		}
		filters[slug] = true
	}
	return filters, nil
}

func (a App) rejectWorkspacePrefixedFilter(st *store.FileStore, filter string, workspaceSet map[string]bool, command string, includeRemoteKnown bool) error {
	trimmed := strings.Trim(filter, "/")
	if trimmed == "" {
		return nil
	}
	known := knownWorkspaceSlugs(st)
	for slug := range workspaceSet {
		known[slug] = true
	}
	if includeRemoteKnown && st != nil && st.State.ControlPlane != nil {
		if accessToken, err := ensureControlPlaneAccess(st.State.ControlPlane.Origin, st); err == nil {
			if workspaces, err := listRemoteWorkspaces(st, st.State.ControlPlane.Origin, accessToken); err == nil {
				for _, workspace := range workspaces {
					if workspace.Slug != "" {
						known[workspace.Slug] = true
					}
				}
			}
		}
	}
	prefix := store.WorkspacePrefix(trimmed)
	if !known[prefix] {
		return nil
	}
	short := strings.TrimPrefix(trimmed, prefix+"/")
	return fmt.Errorf("%s accepts short paths; use %q with --workspace %s, not %q", command, short, prefix, trimmed)
}

type workspacePathTarget struct {
	Slug       string
	KnownSlugs map[string]bool
}

func (target workspacePathTarget) knowsWorkspacePrefix(prefix string) bool {
	if prefix == "" {
		return false
	}
	return prefix == target.Slug || target.KnownSlugs[prefix]
}

func (a App) workspacePathTarget(st *store.FileStore, value, command string) (workspacePathTarget, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return workspacePathTarget{}, errors.New("--workspace requires a slug")
	}
	known := knownWorkspaceSlugs(st)
	if st != nil && st.State.ControlPlane != nil && time.Until(st.State.ControlPlane.AccessTokenExpiresAt) > 30*time.Second {
		if accessToken, err := st.ControlPlaneAccessToken(); err == nil && accessToken != "" {
			if workspaces, err := listRemoteWorkspaces(st, st.State.ControlPlane.Origin, accessToken); err == nil {
				for _, workspace := range workspaces {
					if workspace.Slug != "" {
						known[workspace.Slug] = true
					}
				}
				if workspace, ok := findWorkspace(workspaces, trimmed); ok {
					if workspace.Slug == "" {
						return workspacePathTarget{}, fmt.Errorf("workspace %s does not have a slug", value)
					}
					known[workspace.Slug] = true
					return workspacePathTarget{Slug: workspace.Slug, KnownSlugs: known}, nil
				}
			}
		}
	}
	slug, err := localWorkspaceSlug(trimmed)
	if err != nil {
		if st == nil || st.State.ControlPlane == nil {
			return workspacePathTarget{}, fmt.Errorf("%s --workspace must be a workspace slug before login", command)
		}
		return workspacePathTarget{}, fmt.Errorf("%s --workspace must be a workspace slug", command)
	}
	known[slug] = true
	return workspacePathTarget{Slug: slug, KnownSlugs: known}, nil
}

func knownWorkspaceSlugs(st *store.FileStore) map[string]bool {
	known := map[string]bool{}
	if st == nil {
		return known
	}
	if st.State.ControlPlane != nil && st.State.ControlPlane.WorkspaceSlug != "" {
		known[st.State.ControlPlane.WorkspaceSlug] = true
	}
	for prefix, binding := range st.State.RemoteBindings {
		if prefix != "" {
			known[prefix] = true
		}
		if binding.WorkspaceSlug != "" {
			known[binding.WorkspaceSlug] = true
		}
	}
	for _, secret := range st.State.Secrets {
		if prefix := store.WorkspacePrefix(secret.Scope); prefix != "" {
			known[prefix] = true
		}
	}
	for _, policy := range st.State.Policies {
		if prefix := store.WorkspacePrefix(policy.ScopePattern); prefix != "" {
			known[prefix] = true
		}
	}
	return known
}

func localWorkspaceSlug(value string) (string, error) {
	slug := strings.TrimSpace(value)
	if slug == "" {
		return "", errors.New("--workspace requires a slug")
	}
	if err := store.ValidateWorkspaceSlug(slug); err != nil {
		return "", err
	}
	return slug, nil
}

func workspacePrefixedPath(target workspacePathTarget, shortPath, command string) (string, error) {
	trimmed := strings.Trim(shortPath, "/")
	if trimmed == "" {
		return "", fmt.Errorf("%s requires a short scope/name path", command)
	}
	scope, name, err := store.ParseSecretPath(trimmed)
	if err != nil {
		return "", err
	}
	prefix := store.WorkspacePrefix(scope)
	if target.knowsWorkspacePrefix(prefix) {
		short := strings.TrimPrefix(trimmed, prefix+"/")
		return "", fmt.Errorf("%s accepts short paths; use %q with --workspace %s, not %q", command, short, target.Slug, trimmed)
	}
	return store.SecretKey(target.Slug+"/"+scope, name), nil
}

func workspacePrefixedPattern(target workspacePathTarget, shortPattern, command string) (string, error) {
	trimmed := strings.Trim(shortPattern, "/")
	if trimmed == "" {
		return "", fmt.Errorf("%s requires a short scope pattern", command)
	}
	prefix := store.WorkspacePrefix(trimmed)
	if target.knowsWorkspacePrefix(prefix) {
		short := strings.TrimPrefix(trimmed, prefix+"/")
		return "", fmt.Errorf("%s accepts short paths; use %q with --workspace %s, not %q", command, short, target.Slug, trimmed)
	}
	return target.Slug + "/" + trimmed, nil
}

func workspacePrefixedScope(target workspacePathTarget, shortScope, command string) (string, error) {
	trimmed := strings.Trim(shortScope, "/")
	if trimmed == "" {
		return "", fmt.Errorf("%s requires a short scope", command)
	}
	prefix := store.WorkspacePrefix(trimmed)
	if target.knowsWorkspacePrefix(prefix) {
		short := strings.TrimPrefix(trimmed, prefix+"/")
		return "", fmt.Errorf("%s accepts short paths; use %q with --workspace %s, not %q", command, short, target.Slug, trimmed)
	}
	return target.Slug + "/" + trimmed, nil
}

func workspacePrefixedSelection(target workspacePathTarget, shortSelection, command string) (string, error) {
	trimmed := strings.Trim(shortSelection, "/")
	if trimmed == "" {
		return "", fmt.Errorf("%s requires a short scope or scope/name path", command)
	}
	prefix := store.WorkspacePrefix(trimmed)
	if target.knowsWorkspacePrefix(prefix) {
		short := strings.TrimPrefix(trimmed, prefix+"/")
		return "", fmt.Errorf("%s accepts short paths; use %q with --workspace %s, not %q", command, short, target.Slug, trimmed)
	}
	return target.Slug + "/" + trimmed, nil
}

func (a App) readSensitiveInput(args []string, label, fileFlag string, rejectedFlags ...string) (string, error) {
	for _, flag := range rejectedFlags {
		if _, present, err := optionalFlagValue(args, flag); present || err != nil {
			if err != nil {
				return "", err
			}
			return "", fmt.Errorf("%s is unsafe because values in arguments can leak; use --stdin, %s, or the interactive prompt", flag, fileFlag)
		}
	}
	filePath, hasFile, err := optionalFlagValue(args, fileFlag)
	if err != nil {
		return "", err
	}
	hasStdin := hasFlag(args, "--stdin")
	if hasFile && hasStdin {
		return "", fmt.Errorf("use either --stdin or %s, not both", fileFlag)
	}
	if hasFile {
		bytes, err := os.ReadFile(filePath)
		if err != nil {
			return "", err
		}
		return normalizeSensitiveInput(string(bytes), label)
	}
	if hasStdin {
		bytes, err := io.ReadAll(a.In)
		if err != nil {
			return "", err
		}
		return normalizeSensitiveInput(string(bytes), label)
	}
	file, ok := a.In.(*os.File)
	if !ok || !term.IsTerminal(int(file.Fd())) {
		return "", fmt.Errorf("%s input requires --stdin or %s in non-interactive mode", strings.ToLower(label), fileFlag)
	}
	fmt.Fprintf(a.Err, "%s: ", label)
	bytes, err := term.ReadPassword(int(file.Fd()))
	fmt.Fprintln(a.Err)
	if err != nil {
		return "", err
	}
	return normalizeSensitiveInput(string(bytes), label)
}

func normalizeSensitiveInput(value, label string) (string, error) {
	value = strings.TrimRight(value, "\r\n")
	if value == "" {
		return "", fmt.Errorf("%s must not be empty", strings.ToLower(label))
	}
	return value, nil
}

func validateControlPlaneOrigin(origin string) error {
	parsed, err := url.Parse(origin)
	if err != nil || parsed.Scheme == "" || parsed.Hostname() == "" {
		return fmt.Errorf("invalid control-plane origin %q", origin)
	}
	switch parsed.Scheme {
	case "https":
		return nil
	case "http":
		if isLoopbackHost(parsed.Hostname()) || os.Getenv("ASIRI_ALLOW_INSECURE_ORIGIN") == "1" {
			return nil
		}
		return errors.New("control-plane origin must use HTTPS unless it is loopback")
	default:
		return fmt.Errorf("unsupported control-plane origin scheme %q", parsed.Scheme)
	}
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func validListStatus(status string) bool {
	switch status {
	case "local-only", "remote-only", "synced", "read-only", "writable":
		return true
	default:
		return false
	}
}

func writeExclusiveSecretFile(path string, value []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("mount target already exists: %s", path)
		}
		return err
	}
	defer file.Close()
	return writeReservedSecretFile(file, value)
}

func reserveExclusiveSecretFile(path string) (*os.File, error) {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return nil, fmt.Errorf("mount target already exists: %s", path)
		}
		return nil, err
	}
	return file, nil
}

func writeReservedSecretFile(file *os.File, value []byte) error {
	if _, err := file.Write(value); err != nil {
		return err
	}
	return file.Chmod(0o600)
}

func (a App) fail(err error) int {
	fmt.Fprintf(a.Err, "asiri: %s\n", err)
	return 1
}
