package cli

import (
	"errors"
	"fmt"
	"strings"
	"text/tabwriter"

	"github.com/o-clan/asiri/cli/internal/store"
)

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
		if err := rejectUnknownArgs(args[1:]); err != nil {
			return a.fail(err)
		}
		workspaceResult, err := listRemoteWorkspaceOverview(st, st.State.ControlPlane.Origin, accessToken, "", true, false)
		if err != nil {
			return a.fail(err)
		}
		workspaces := workspaceResult.Organizations
		if st.State.ControlPlane.Source != "service-account" && workspaceResult.Secrets == nil {
			return a.fail(errors.New("control plane did not return workspace secret metadata"))
		}
		keySummaries := workspaceKeySummaries(st, workspaces, workspaceResult.Secrets, st.State.ControlPlane.Source != "service-account")
		tw := tabwriter.NewWriter(a.Out, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "WORKSPACE\tROLE\tTHIS DEVICE\tACCOUNT WRITE\tKEYS\tNEXT\tID")
		hasUntrusted := false
		for _, workspace := range workspaces {
			if !workspaceDeviceTrusted(workspace) {
				hasUntrusted = true
			}
			keySummary := keySummaries[workspace.Slug]
			accountWrite := boolPointerLabel(workspace.CanWrite)
			if st.State.ControlPlane.Source == "service-account" {
				accountWrite = "no"
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", workspace.Slug, workspaceRoleLabel(workspace, st.State.UserID), deviceTrustLabelForWorkspace(workspace), accountWrite, keySummary.Keys, keySummary.Next, workspace.ID)
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
	workspaceArg, remaining, err := splitWorkspaceFlag(args, "setup doctor", true)
	if err != nil {
		return a.fail(err)
	}
	if err := rejectUnknownArgs(remaining); err != nil {
		return a.fail(err)
	}
	if _, err := localWorkspaceSlug(workspaceArg); err != nil {
		return a.fail(err)
	}
	if err := requireServiceAccountWorkspace(st, workspaceArg); err != nil {
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
			fmt.Fprintln(a.Out, "\nNext steps:\n- Setup looks ready for this workspace.")
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
		checks = append(checks, setupDoctorCheck{Name: "session", Status: "failed", Detail: err.Error(), Next: "asiri login"})
		printChecks(checks)
		printNextSteps()
		return 0
	}
	checks = append(checks, setupDoctorCheck{Name: "session", Status: "ok", Detail: "authenticated user session", Next: "-"})
	printChecks(checks)

	workspaceResult, err := listRemoteWorkspaceOverview(st, st.State.ControlPlane.Origin, accessToken, workspaceArg, true, false)
	if err != nil {
		fmt.Fprintf(a.Out, "\nWorkspace checks unavailable: %s\n", err)
		addStep("asiri login")
		printNextSteps()
		return 0
	}
	workspaces := workspaceResult.Organizations
	filterSet := map[string]bool{workspaceArg: true}
	targets := make([]remoteWorkspaceResponse, 0, len(workspaces))
	foundFilters := map[string]bool{}
	for _, workspace := range workspaces {
		if !filterSet[workspace.Slug] {
			continue
		}
		targets = append(targets, workspace)
		foundFilters[workspace.Slug] = true
	}
	if !foundFilters[workspaceArg] {
		return a.fail(fmt.Errorf("workspace %s is not visible", workspaceArg))
	}

	remoteSecrets := workspaceResult.Secrets
	secretsKnown := remoteSecrets != nil
	if !secretsKnown {
		fmt.Fprintln(a.Err, "asiri: remote key coverage unavailable: control plane did not return workspace secret metadata")
	}
	keySummaries := workspaceKeySummaries(st, targets, remoteSecrets, secretsKnown)
	rows := make([]setupDoctorWorkspace, 0, len(targets))
	for _, workspace := range targets {
		keySummary := keySummaries[workspace.Slug]
		recoveryStatus := a.setupDoctorRecoveryStatus(st, accessToken, workspace)
		next := setupDoctorWorkspaceNext(st, workspace, keySummary.Keys, recoveryStatus)
		rows = append(rows, setupDoctorWorkspace{
			Workspace: workspace.Slug,
			Role:      workspaceRoleLabel(workspace, st.State.UserID),
			Device:    deviceTrustLabelForWorkspace(workspace),
			Keys:      keySummary.Keys,
			Recovery:  recoveryStatus,
			Next:      next,
		})
		if explicitWorkspaceDeviceStatus(workspace) == "revoked" {
			for _, step := range revokedDeviceRecoverySteps(st, workspace.Slug) {
				addStep(step)
			}
		} else {
			addStep(next)
		}
	}

	fmt.Fprintln(a.Out, "\nWorkspace:")
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
	if !workspaceDeviceTrusted(workspace) {
		return "skipped"
	}
	if st.State.Recoveries != nil {
		if recovery, ok := st.State.Recoveries[workspace.ID]; ok && recovery.RecipientID != "" {
			return "configured"
		}
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

func setupDoctorWorkspaceNext(st *store.FileStore, workspace remoteWorkspaceResponse, keys, recovery string) string {
	if st.State.ControlPlane != nil && st.State.ControlPlane.Source == "service-account" {
		return "-"
	}
	if explicitWorkspaceDeviceStatus(workspace) == "revoked" {
		return "replace revoked device keys"
	}
	if !workspaceDeviceTrusted(workspace) {
		if workspaceCanApproveDevice(workspace) {
			return deviceTrustCommand(st, workspace.Slug)
		}
		return "ask owner to approve this device"
	}
	switch keys {
	case "unknown":
		return fmt.Sprintf("asiri setup doctor --workspace %s", workspace.Slug)
	case "needs rewrap", "needs cleanup":
		return workspaceNextAction(st, workspace, keys)
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

func findWorkspace(workspaces []remoteWorkspaceResponse, value string) (remoteWorkspaceResponse, bool) {
	for _, workspace := range workspaces {
		if workspace.Slug == value {
			return workspace, true
		}
	}
	return remoteWorkspaceResponse{}, false
}

func boolPtr(value bool) *bool {
	return &value
}

type workspaceKeySummary struct {
	Keys string
	Next string
}

func workspaceKeySummaries(st *store.FileStore, workspaces []remoteWorkspaceResponse, secrets []visibleRemoteSecretRecord, secretsKnown bool) map[string]workspaceKeySummary {
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
		if workspaceDeviceTrusted(workspace) && secretsKnown {
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
		summaries[workspace.Slug] = workspaceKeySummary{Keys: keys, Next: workspaceNextAction(st, workspace, keys)}
	}
	return summaries
}

func workspaceNextAction(st *store.FileStore, workspace remoteWorkspaceResponse, keys string) string {
	if st.State.ControlPlane != nil && st.State.ControlPlane.Source == "service-account" {
		return "-"
	}
	if explicitWorkspaceDeviceStatus(workspace) == "revoked" {
		return "replace revoked device keys"
	}
	if !workspaceDeviceTrusted(workspace) {
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

func workspaceDeviceTrusted(workspace remoteWorkspaceResponse) bool {
	if status := explicitWorkspaceDeviceStatus(workspace); status != "" {
		return status == "trusted"
	}
	if workspace.CurrentDeviceTrusted != nil {
		return *workspace.CurrentDeviceTrusted
	}
	if workspace.CanPull != nil {
		return *workspace.CanPull
	}
	return false
}

func explicitWorkspaceDeviceStatus(workspace remoteWorkspaceResponse) string {
	status := strings.ReplaceAll(strings.ToLower(strings.TrimSpace(workspace.CurrentDeviceStatus)), "_", "-")
	switch status {
	case "trusted", "pending", "revoked", "not-enrolled":
		return status
	default:
		return ""
	}
}

func workspaceCanApproveDevice(workspace remoteWorkspaceResponse) bool {
	if workspace.CanApproveDevice != nil {
		return *workspace.CanApproveDevice
	}
	return workspace.Role == "owner"
}

func deviceTrustLabelForWorkspace(workspace remoteWorkspaceResponse) string {
	if status := explicitWorkspaceDeviceStatus(workspace); status != "" {
		return status
	}
	if workspaceDeviceTrusted(workspace) {
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
