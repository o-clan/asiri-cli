package cli

import (
	"errors"
	"fmt"
	"strings"

	"github.com/o-clan/asiri/cli/internal/store"
)

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
	workspaceArg, remaining, err := splitWorkspaceFlag(args[1:], "policy list", true)
	if err != nil {
		return a.fail(err)
	}
	if err := rejectUnknownArgs(remaining); err != nil {
		return a.fail(err)
	}
	workspaceSet, err := a.workspaceFilterSet(st, []string{workspaceArg}, "policy list")
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
