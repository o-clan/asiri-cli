package cli

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/o-clan/asiri/cli/internal/store"
)

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
	deviceID := target.CurrentDeviceID
	if deviceID == "" {
		return a.fail(errors.New("control-plane session is missing current device id"))
	}
	if hasFlag(remaining, "--dry-run") {
		if err := preflightRemoteSecretDelete(st, st.State.ControlPlane.Origin, target.ID, remoteSecret.ID, remoteSecret.Version, deviceID, accessToken); err != nil {
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
	deleted, err := deleteRemoteSecret(st, st.State.ControlPlane.Origin, target.ID, remoteSecret.ID, remoteSecret.Version, deviceID, accessToken)
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
	deviceID := target.CurrentDeviceID
	if deviceID == "" {
		return a.fail(errors.New("control-plane session is missing current device id"))
	}
	restored, err := restoreRemoteSecret(st, st.State.ControlPlane.Origin, target.ID, remoteSecret.ID, remoteSecret.Version, deviceID, accessToken)
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
	deviceID := target.CurrentDeviceID
	if deviceID == "" {
		return a.fail(errors.New("control-plane session is missing current device id"))
	}
	secrets, err := listVisibleRemoteSecrets(st, st.State.ControlPlane.Origin, accessToken, target.Slug, false)
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
			if err := preflightRemoteSecretDelete(st, st.State.ControlPlane.Origin, target.ID, secret.ID, secret.Version, deviceID, accessToken); err != nil {
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
		if err := preflightRemoteSecretDelete(st, st.State.ControlPlane.Origin, target.ID, secret.ID, secret.Version, deviceID, accessToken); err != nil {
			return a.fail(fmt.Errorf("failed to preflight delete %s: %w", shortSecretPath(secret.Scope, secret.Name), err))
		}
	}
	deletedRecords := []visibleRemoteSecretRecord{}
	for _, secret := range candidates {
		deletedSecret, err := deleteRemoteSecret(st, st.State.ControlPlane.Origin, target.ID, secret.ID, secret.Version, deviceID, accessToken)
		if err != nil {
			if rollbackErr := rollbackRemoteSecretDeletes(st, st.State.ControlPlane.Origin, target.ID, deletedRecords, &secret, deviceID, accessToken); rollbackErr != nil {
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

func rollbackRemoteSecretDeletes(st *store.FileStore, origin, orgID string, deleted []visibleRemoteSecretRecord, maybeDeleted *visibleRemoteSecretRecord, deviceID, accessToken string) error {
	var failures []string
	if maybeDeleted != nil {
		secret := *maybeDeleted
		if _, err := restoreRemoteSecret(st, origin, orgID, secret.ID, secret.Version, deviceID, accessToken); err != nil {
			if remoteRestoreAlreadyActive(err) {
				workspace := firstNonEmpty(secret.WorkspaceSlug, store.WorkspacePrefix(secret.Scope), orgID)
				active, activeErr := remoteSecretRecordActive(st, origin, workspace, accessToken, secret.ID)
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
		if _, err := restoreRemoteSecret(st, origin, orgID, secret.ID, secret.Version, deviceID, accessToken); err != nil {
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

func remoteSecretRecordActive(st *store.FileStore, origin, workspace, accessToken, secretID string) (bool, error) {
	secrets, err := listVisibleRemoteSecrets(st, origin, workspace, accessToken, true)
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
