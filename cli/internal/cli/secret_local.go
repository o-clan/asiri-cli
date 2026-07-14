package cli

import (
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/o-clan/asiri/cli/internal/asiri"
	"github.com/o-clan/asiri/cli/internal/store"
)

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
	secret, err := st.SecretMetadata(fullPath)
	if err != nil {
		return a.fail(err)
	}
	actor := st.State.UserID
	if agent != "" {
		actor = agent
	}
	auditLabel := agent
	auditLabelType := runtimeType
	if auditLabel == "" {
		auditLabel = actor
		auditLabelType = "user"
	}
	metadata := runtimeAuditMetadata(st, secret.Scope, auditLabel, auditLabelType, nil)
	if err := st.CheckSecretReadable(fullPath); err != nil {
		st.Audit(actor, "secret_read", "failed", secret.Scope, secret.NameHash, "secret not locally usable: "+err.Error(), metadata)
		_ = st.Save()
		a.syncRuntimeAuditBestEffort(st)
		return a.fail(err)
	}
	if err := a.gateSecretRelease(st, actor, "secret_read", secret.Scope, secret.NameHash, "raw read", metadata); err != nil {
		return a.fail(err)
	}
	value, _, err := st.GetSecret(fullPath)
	if err != nil {
		st.Audit(actor, "secret_read", "failed", secret.Scope, secret.NameHash, "secret release failed after audit gate: "+err.Error(), metadata)
		_ = st.Save()
		a.syncRuntimeAuditBestEffort(st)
		return a.fail(err)
	}
	fmt.Fprintln(a.Out, value)
	return 0
}

func (a App) list(st *store.FileStore, args []string) int {
	if err := st.RequireInitialized(); err != nil {
		return a.fail(err)
	}
	workspaceArg, remaining, err := splitWorkspaceFlag(args, "list", true)
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
	if err := requireServiceAccountWorkspace(st, workspaceArg); err != nil {
		return a.fail(err)
	}
	filter := strings.Trim(firstPositionalSkippingFlagValues(remaining, "--status"), "/")
	var workspaceSet map[string]bool
	if localOnly {
		workspaceSet, err = localWorkspaceFilterSet([]string{workspaceArg}, "list")
	} else {
		workspaceSet, err = a.workspaceFilterSet(st, []string{workspaceArg}, "list")
	}
	if err != nil {
		return a.fail(err)
	}
	if err := a.rejectWorkspacePrefixedFilter(st, filter, workspaceSet, "list"); err != nil {
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
			remoteSecrets, err := listVisibleRemoteSecrets(st, st.State.ControlPlane.Origin, accessToken, workspaceArg, includeInactive)
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
	return ""
}
