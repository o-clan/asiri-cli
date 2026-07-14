package cli

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/o-clan/asiri/cli/internal/asiri"
	"github.com/o-clan/asiri/cli/internal/store"
)

var asiriRefPattern = regexp.MustCompile(`asiri://[A-Za-z0-9][A-Za-z0-9/_-]{1,96}/[A-Za-z0-9][A-Za-z0-9_.-]{1,96}`)

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
	env := os.Environ()
	prepared := []envPreparedSecret{}
	for _, mapping := range mappings {
		name, path, ok := strings.Cut(mapping, "=")
		if !ok || name == "" || path == "" {
			return a.fail(fmt.Errorf("invalid env mapping %q", mapping))
		}
		fullPath, err := workspacePrefixedPath(target, path, "run")
		if err != nil {
			return a.fail(err)
		}
		release, err := a.prepareSecretRelease(st, agent, runtimeType, "inject", "secret_injected", fullPath, "explicit env mapping", map[string]string{"env": name})
		if err != nil {
			_ = st.Save()
			a.syncRuntimeAuditBestEffort(st)
			return a.fail(err)
		}
		prepared = append(prepared, envPreparedSecret{preparedSecretRelease: release, EnvName: name})
	}
	preparedReleases := make([]preparedSecretRelease, 0, len(prepared))
	for _, item := range prepared {
		preparedReleases = append(preparedReleases, item.preparedSecretRelease)
	}
	if err := a.gatePreparedSecretReleases(st, agent, preparedReleases); err != nil {
		return a.fail(err)
	}
	for _, item := range prepared {
		value, _, err := st.GetSecret(item.Path)
		if err != nil {
			a.auditFailedPreparedRelease(st, agent, item.preparedSecretRelease, "secret release failed after audit gate: "+err.Error())
			_ = st.Save()
			a.syncRuntimeAuditBestEffort(st)
			return a.fail(err)
		}
		env = append(env, item.EnvName+"="+value)
	}
	if err := st.Save(); err != nil {
		return a.fail(err)
	}
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
	prepared := []preparedSecretRelease{}
	for i, arg := range commandArgs[1:] {
		if err := a.prepareUnsafeArgvArg(st, target, agent, runtimeType, arg, &prepared); err != nil {
			_ = st.Save()
			a.syncRuntimeAuditBestEffort(st)
			return a.fail(err)
		}
		resolvedArgs[i+1] = arg
	}
	if err := a.gatePreparedSecretReleases(st, agent, prepared); err != nil {
		return a.fail(err)
	}
	values := map[string]string{}
	for _, release := range prepared {
		if _, ok := values[release.Path]; ok {
			continue
		}
		value, _, err := st.GetSecret(release.Path)
		if err != nil {
			a.auditFailedPreparedRelease(st, agent, release, "secret release failed after audit gate: "+err.Error())
			_ = st.Save()
			a.syncRuntimeAuditBestEffort(st)
			return a.fail(err)
		}
		values[release.Path] = value
	}
	for i, arg := range resolvedArgs[1:] {
		resolved, err := replaceUnsafeArgvValues(target, arg, values)
		if err != nil {
			return a.fail(err)
		}
		resolvedArgs[i+1] = resolved
	}
	if err := st.Save(); err != nil {
		return a.fail(err)
	}
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

func (a App) prepareUnsafeArgvArg(st *store.FileStore, target workspacePathTarget, agent, runtimeType, arg string, releases *[]preparedSecretRelease) error {
	refs, err := unsafeArgvRefs(arg)
	if err != nil {
		return err
	}
	for _, ref := range refs {
		fullPath, err := workspacePrefixedPath(target, strings.TrimPrefix(ref, "asiri://"), "run")
		if err != nil {
			return err
		}
		release, err := a.prepareSecretRelease(st, agent, runtimeType, "inject", "secret_unsafe_argv_injected", fullPath, "unsafe argv materialization", map[string]string{"mode": "unsafe-argv"})
		if err != nil {
			return err
		}
		*releases = append(*releases, release)
	}
	return nil
}

func unsafeArgvRefs(arg string) ([]string, error) {
	if !strings.Contains(arg, "asiri://") {
		return nil, nil
	}
	matches := asiriRefPattern.FindAllStringIndex(arg, -1)
	if len(matches) == 0 {
		return nil, errors.New("invalid asiri:// reference; expected asiri://scope/name")
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
			return nil, errors.New("invalid asiri:// reference; expected asiri://scope/name")
		}
		offset = start + len("asiri://")
	}
	return asiriRefPattern.FindAllString(arg, -1), nil
}

func replaceUnsafeArgvValues(target workspacePathTarget, arg string, values map[string]string) (string, error) {
	if _, err := unsafeArgvRefs(arg); err != nil {
		return "", err
	}
	var resolveErr error
	resolved := asiriRefPattern.ReplaceAllStringFunc(arg, func(ref string) string {
		if resolveErr != nil {
			return ref
		}
		fullPath, err := workspacePrefixedPath(target, strings.TrimPrefix(ref, "asiri://"), "run")
		if err != nil {
			resolveErr = err
			return ref
		}
		value, ok := values[fullPath]
		if !ok {
			resolveErr = fmt.Errorf("secret %s was not prepared for unsafe argv materialization", fullPath)
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
	secret, err := st.SecretMetadata(fullPath)
	if err != nil {
		return "", err
	}
	if err := st.CheckSecretReadable(fullPath); err != nil {
		st.Audit(agent, "secret_unsafe_argv_injected", "failed", secret.Scope, secret.NameHash, "secret not locally usable: "+err.Error(), metadata)
		return "", err
	}
	if err := a.gateSecretRelease(st, agent, "secret_unsafe_argv_injected", secret.Scope, secret.NameHash, "unsafe argv materialization", metadata); err != nil {
		return "", err
	}
	value, _, err := st.GetSecret(fullPath)
	if err != nil {
		st.Audit(agent, "secret_unsafe_argv_injected", "failed", secret.Scope, secret.NameHash, "secret release failed after audit gate: "+err.Error(), metadata)
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

type preparedSecretRelease struct {
	Path        string
	Secret      asiri.Secret
	Metadata    map[string]string
	AuditAction string
	AuditReason string
}

type envPreparedSecret struct {
	preparedSecretRelease
	EnvName string
}

func (a App) prepareSecretRelease(st *store.FileStore, agent, runtimeType, action, auditAction, fullPath, auditReason string, extra map[string]string) (preparedSecretRelease, error) {
	allowed, reason := st.CheckPolicy(agent, fullPath, action)
	scope, name, parseErr := store.ParseSecretPath(fullPath)
	metadataScope := ""
	if parseErr == nil {
		metadataScope = scope
	}
	metadata := runtimeAuditMetadata(st, metadataScope, agent, runtimeType, extra)
	if !allowed {
		if parseErr == nil {
			st.Audit(agent, auditAction, "denied", scope, store.HashSecretName(scope, name), reason, metadata)
		} else {
			st.Audit(agent, auditAction, "denied", "", "", reason, metadata)
		}
		return preparedSecretRelease{}, fmt.Errorf("%s: %s cannot %s %s", reason, agent, action, fullPath)
	}
	secret, err := st.SecretMetadata(fullPath)
	if err != nil {
		return preparedSecretRelease{}, err
	}
	if err := st.CheckSecretReadable(fullPath); err != nil {
		st.Audit(agent, auditAction, "failed", secret.Scope, secret.NameHash, "secret not locally usable: "+err.Error(), metadata)
		return preparedSecretRelease{}, err
	}
	if auditReason == "" {
		auditReason = fmt.Sprintf("%s materialization", action)
	}
	return preparedSecretRelease{Path: fullPath, Secret: secret, Metadata: metadata, AuditAction: auditAction, AuditReason: auditReason}, nil
}

func (a App) gatePreparedSecretRelease(st *store.FileStore, actor string, release preparedSecretRelease) error {
	return a.gateSecretRelease(st, actor, release.AuditAction, release.Secret.Scope, release.Secret.NameHash, release.AuditReason, release.Metadata)
}

func (a App) gatePreparedSecretReleases(st *store.FileStore, actor string, releases []preparedSecretRelease) error {
	if len(releases) == 0 {
		return nil
	}
	strictReleases := []preparedSecretRelease{}
	bufferedReleases := []preparedSecretRelease{}
	for _, release := range releases {
		if st.ResolveEnvelopeAuditMode(release.Secret.Scope) == asiri.AuditModeStrict {
			strictReleases = append(strictReleases, release)
		} else {
			bufferedReleases = append(bufferedReleases, release)
		}
	}
	strictEventIDs := make([]string, 0, len(strictReleases))
	strictReleasesByEventID := map[string]preparedSecretRelease{}
	for _, release := range strictReleases {
		st.Audit(actor, release.AuditAction, "allowed", release.Secret.Scope, release.Secret.NameHash, release.AuditReason, release.Metadata)
		eventID := st.LatestAuditEventID()
		strictEventIDs = append(strictEventIDs, eventID)
		strictReleasesByEventID[eventID] = release
	}
	if len(strictEventIDs) > 0 {
		if err := st.SaveWithAuditLedger(); err != nil {
			return err
		}
		strictEvents := make([]asiri.AuditEvent, 0, len(strictEventIDs))
		for _, eventID := range strictEventIDs {
			event, ok := st.AuditEventByID(eventID)
			if !ok {
				return errors.New("strict audit event missing after local append")
			}
			strictEvents = append(strictEvents, event)
		}
		if err := a.syncRuntimeAuditStrictBatch(st, strictEvents); err != nil {
			for _, event := range strictEvents {
				release := strictReleasesByEventID[event.ID]
				failedMetadata := copyStringMap(release.Metadata)
				if failedMetadata == nil {
					failedMetadata = map[string]string{}
				}
				failedMetadata["blockedLocalAuditId"] = event.ID
				failedMetadata["blockedEventDigest"] = event.Digest
				st.Audit(actor, release.AuditAction, "failed", release.Secret.Scope, release.Secret.NameHash, "secret release blocked because strict audit ack failed: "+err.Error(), failedMetadata)
			}
			if saveErr := st.SaveWithAuditLedger(); saveErr != nil {
				return fmt.Errorf("strict audit ack required before secret release: %w; failed to persist failed audit record: %v", err, saveErr)
			}
			return fmt.Errorf("strict audit ack required before secret release: %w", err)
		}
	}
	for _, release := range bufferedReleases {
		st.Audit(actor, release.AuditAction, "allowed", release.Secret.Scope, release.Secret.NameHash, release.AuditReason, release.Metadata)
	}
	if len(bufferedReleases) > 0 {
		if err := st.SaveWithAuditLedger(); err != nil {
			return err
		}
		a.syncRuntimeAuditBestEffort(st)
	}
	return nil
}

func (a App) auditFailedPreparedRelease(st *store.FileStore, actor string, release preparedSecretRelease, reason string) {
	st.Audit(actor, release.AuditAction, "failed", release.Secret.Scope, release.Secret.NameHash, reason, release.Metadata)
}
