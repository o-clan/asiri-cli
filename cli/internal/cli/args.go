package cli

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/o-clan/asiri/cli/internal/store"
	"golang.org/x/term"
)

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
	if err := requireServiceAccountWorkspace(st, strings.TrimSpace(value)); err != nil {
		return "", err
	}
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
	workspaceResult, listErr := listRemoteWorkspaceOverview(st, st.State.ControlPlane.Origin, accessToken, strings.TrimSpace(value), false, false)
	if listErr != nil {
		return "", listErr
	}
	if len(workspaceResult.Organizations) == 0 {
		return "", fmt.Errorf("workspace %s is not visible", value)
	}
	workspace := workspaceResult.Organizations[0]
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

func (a App) rejectWorkspacePrefixedFilter(st *store.FileStore, filter string, workspaceSet map[string]bool, command string) error {
	trimmed := strings.Trim(filter, "/")
	if trimmed == "" {
		return nil
	}
	known := knownWorkspaceSlugs(st)
	for slug := range workspaceSet {
		known[slug] = true
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
	if err := requireServiceAccountWorkspace(st, trimmed); err != nil {
		return workspacePathTarget{}, err
	}
	known := knownWorkspaceSlugs(st)
	if st != nil && st.State.ControlPlane != nil && time.Until(st.State.ControlPlane.AccessTokenExpiresAt) > 30*time.Second {
		if accessToken, err := st.ControlPlaneAccessToken(); err == nil && accessToken != "" {
			if workspaceResult, err := listRemoteWorkspaceOverview(st, st.State.ControlPlane.Origin, accessToken, trimmed, false, false); err == nil {
				for _, workspace := range workspaceResult.Organizations {
					if workspace.Slug != "" {
						known[workspace.Slug] = true
					}
				}
				if len(workspaceResult.Organizations) == 1 {
					workspace := workspaceResult.Organizations[0]
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

func requireServiceAccountWorkspace(st *store.FileStore, requested string) error {
	if st == nil || st.State.ControlPlane == nil || st.State.ControlPlane.Source != "service-account" {
		return nil
	}
	if requested == st.State.ControlPlane.WorkspaceSlug {
		return nil
	}
	return fmt.Errorf("service account session is scoped to workspace %s", st.State.ControlPlane.WorkspaceSlug)
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
