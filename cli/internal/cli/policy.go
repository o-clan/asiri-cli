package cli

import (
	"errors"
	"fmt"
	"strings"

	"github.com/o-clan/asiri/cli/internal/store"
)

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
		kind := "legacy-inert"
		if strings.HasPrefix(store.NormalizeSubjectLabel(policy.Subject), "service-account:") {
			kind = "service-account"
		}
		fmt.Fprintf(a.Out, "%s\t%s\t%s/%s\t%s\t%s\t%s\n", policy.ID, policy.Subject, policy.ScopePattern, policy.SecretPattern, strings.Join(policy.Actions, ","), policy.ApprovalMode, kind)
	}
	return 0
}
