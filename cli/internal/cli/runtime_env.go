package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/o-clan/asiri/cli/internal/store"
)

var envNamePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

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
	paths, err := a.selectedSecretPaths(st, pathSpec, agent, "inject")
	if err != nil {
		return a.fail(err)
	}
	envAdds := make(map[string]string, len(paths))
	prepared := []preparedSecretRelease{}
	for _, path := range paths {
		secret, err := st.SecretMetadata(path)
		if err != nil {
			return a.fail(err)
		}
		if !envNamePattern.MatchString(secret.Name) {
			return a.fail(fmt.Errorf("secret name %q is not a valid environment variable name", secret.Name))
		}
		if _, exists := envAdds[secret.Name]; exists {
			return a.fail(fmt.Errorf("environment variable %s would collide", secret.Name))
		}
		envAdds[secret.Name] = ""
		release, err := a.prepareSecretRelease(st, agent, runtimeType, "inject", "secret_env_exported", path, "inject materialization", map[string]string{"mode": "inject"})
		if err != nil {
			_ = st.Save()
			a.syncRuntimeAuditBestEffort(st)
			return a.fail(err)
		}
		prepared = append(prepared, release)
	}
	if err := a.gatePreparedSecretReleases(st, agent, prepared); err != nil {
		return a.fail(err)
	}
	for _, release := range prepared {
		value, secret, err := st.GetSecret(release.Path)
		if err != nil {
			a.auditFailedPreparedRelease(st, agent, release, "secret release failed after audit gate: "+err.Error())
			_ = st.Save()
			a.syncRuntimeAuditBestEffort(st)
			return a.fail(err)
		}
		envAdds[secret.Name] = value
	}
	env := os.Environ()
	for name, value := range envAdds {
		env = append(env, name+"="+value)
	}
	if err := st.Save(); err != nil {
		return a.fail(err)
	}
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
	paths, err := a.selectedSecretPaths(st, pathPart, agent, "mount")
	if err != nil {
		return a.fail(err)
	}
	if hasExplicitDest && len(paths) != 1 {
		return a.fail(errors.New("explicit mount destination requires an exact single secret path"))
	}
	type reservedMountTarget struct {
		release preparedSecretRelease
		path    string
		file    *os.File
	}
	reservedTargets := []reservedMountTarget{}
	defer func() {
		for _, target := range reservedTargets {
			if target.file != nil {
				_ = target.file.Close()
			}
		}
	}()
	seenTargets := map[string]bool{}
	for _, path := range paths {
		release, err := a.prepareSecretRelease(st, agent, runtimeType, "mount", "secret_mounted", path, "mount materialization", map[string]string{"mode": "mount"})
		if err != nil {
			_ = st.Save()
			a.syncRuntimeAuditBestEffort(st)
			return a.fail(err)
		}
		targetPath := ""
		if hasExplicitDest {
			if err := validateExplicitMountDest(explicitDest); err != nil {
				return a.fail(err)
			}
			targetPath = explicitDest
		} else {
			if err := validateSecretFileName(release.Secret.Name); err != nil {
				return a.fail(err)
			}
			targetPath = release.Secret.Name
		}
		if seenTargets[targetPath] {
			return a.fail(fmt.Errorf("mount target %s would collide", targetPath))
		}
		seenTargets[targetPath] = true
		reservedTargets = append(reservedTargets, reservedMountTarget{release: release, path: targetPath})
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
	for index := range reservedTargets {
		targetPath := reservedTargets[index].path
		if hasExplicitDest {
			if err := os.MkdirAll(filepath.Dir(targetPath), 0o700); err != nil {
				return a.fail(err)
			}
		} else {
			targetPath = filepath.Join(mountDir, targetPath)
			reservedTargets[index].path = targetPath
		}
		file, err := reserveExclusiveSecretFile(targetPath)
		if err != nil {
			return a.fail(err)
		}
		reservedTargets[index].file = file
		cleanupPaths = append(cleanupPaths, targetPath)
	}
	preparedReleases := make([]preparedSecretRelease, 0, len(reservedTargets))
	for _, target := range reservedTargets {
		preparedReleases = append(preparedReleases, target.release)
	}
	if err := a.gatePreparedSecretReleases(st, agent, preparedReleases); err != nil {
		return a.fail(err)
	}
	for index := range reservedTargets {
		value, _, err := st.GetSecretBytes(reservedTargets[index].release.Path)
		if err != nil {
			a.auditFailedPreparedRelease(st, agent, reservedTargets[index].release, "secret release failed after audit gate: "+err.Error())
			_ = st.Save()
			a.syncRuntimeAuditBestEffort(st)
			return a.fail(err)
		}
		if err := writeReservedSecretFile(reservedTargets[index].file, value); err != nil {
			a.auditFailedPreparedRelease(st, agent, reservedTargets[index].release, "secret file write failed after audit gate: "+err.Error())
			_ = st.Save()
			a.syncRuntimeAuditBestEffort(st)
			return a.fail(err)
		}
		_ = reservedTargets[index].file.Close()
		reservedTargets[index].file = nil
	}
	env := os.Environ()
	if !hasExplicitDest || mountDir != "" {
		env = append(env, "ASIRI_SECRETS_DIR="+mountDir)
	}
	if err := st.Save(); err != nil {
		return a.fail(err)
	}
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
	paths, err := a.selectedSecretPaths(st, pathSpec, agent, action)
	if err != nil {
		return nil, err
	}
	resolved := make([]resolvedSecret, 0, len(paths))
	for _, path := range paths {
		item, err := a.resolveOneSecret(st, agent, runtimeType, action, auditAction, path)
		if err != nil {
			return nil, err
		}
		resolved = append(resolved, item)
	}
	return resolved, nil
}

func (a App) selectedSecretPaths(st *store.FileStore, pathSpec, agent, action string) ([]string, error) {
	pathSpec = strings.Trim(pathSpec, "/")
	if pathSpec == "" {
		return nil, errors.New("secret path or scope is required")
	}
	if scope, name, err := store.ParseSecretPath(pathSpec); err == nil {
		key := store.SecretKey(scope, name)
		if _, ok := st.State.Secrets[key]; ok {
			return []string{pathSpec}, nil
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
	paths := make([]string, 0, len(keys))
	for _, key := range keys {
		secret := st.State.Secrets[key]
		paths = append(paths, secret.Scope+"/"+secret.Name)
	}
	return paths, nil
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
	requestedWorkspace := store.WorkspacePrefix(pathSpec)
	if requestedWorkspace == "" {
		return ""
	}
	secrets, err := listVisibleRemoteSecrets(st, st.State.ControlPlane.Origin, accessToken, requestedWorkspace, false)
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
	secret, err := st.SecretMetadata(fullPath)
	if err != nil {
		return resolvedSecret{}, err
	}
	auditReason := fmt.Sprintf("%s materialization", action)
	if action == "inject" {
		auditReason = "inject materialization"
	}
	if action == "mount" {
		auditReason = "mount materialization"
	}
	if err := a.gateSecretRelease(st, agent, auditAction, secret.Scope, secret.NameHash, auditReason, metadata); err != nil {
		return resolvedSecret{}, err
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
