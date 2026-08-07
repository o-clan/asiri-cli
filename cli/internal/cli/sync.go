package cli

import (
	"errors"
	"fmt"

	"github.com/o-clan/asiri/cli/internal/store"
)

func (a App) sync(st *store.FileStore, args []string) int {
	if err := st.RequireInitialized(); err != nil {
		return a.fail(err)
	}
	if st.State.ControlPlane == nil {
		return a.fail(errors.New("asiri is not linked to a control plane"))
	}
	workspace, remaining, err := splitWorkspaceFlag(args, "sync", true)
	if err != nil {
		return a.fail(err)
	}
	if err := rejectUnknownArgs(remaining); err != nil {
		return a.fail(err)
	}
	pullArgs := []string{"--workspace", workspace, "--force"}
	if code := a.pullForSync(st, pullArgs); code != 0 {
		return code
	}
	if st.State.ControlPlane.Source == "service-account" {
		fmt.Fprintf(a.Out, "✓ Synchronized receive-only workspace %s with the control-plane ledger\n", workspace)
		return 0
	}
	if code := a.pushForSync(st, []string{"--workspace", workspace}); code != 0 {
		return code
	}
	fmt.Fprintf(a.Out, "✓ Finished reconciliation for workspace %s against the control-plane ledger\n", workspace)
	return 0
}
