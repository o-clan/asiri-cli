package cli

import (
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/o-clan/asiri/cli/internal/asiri"
	"github.com/o-clan/asiri/cli/internal/store"
)

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
	target, accessToken, err := a.remoteWorkspaceTarget(st, accessToken, options.Workspace)
	if err != nil {
		return a.fail(err)
	}
	imported, remote, _, err := a.pullOneWorkspace(st, accessToken, target, options.Force)
	if err != nil {
		return a.fail(err)
	}
	writePullResults(a.Out, []pullResult{{Workspace: target.Slug, Result: "pulled", Imported: imported, Remote: remote}})
	return 0
}

func (a App) pullOneWorkspace(st *store.FileStore, accessToken string, workspace remoteWorkspaceResponse, force bool) (int, int, string, error) {
	imported, remote, nextToken, _, err := a.pullOneWorkspaceWithBundle(st, accessToken, workspace, force)
	return imported, remote, nextToken, err
}

func (a App) pullOneWorkspaceWithBundle(st *store.FileStore, accessToken string, workspace remoteWorkspaceResponse, force bool) (int, int, string, syncBundleResponse, error) {
	if workspace.ID == "" || workspace.Slug == "" || workspace.CurrentDeviceID == "" {
		return 0, 0, "", syncBundleResponse{}, errors.New("pull requires a trusted target workspace device")
	}
	if _, err := st.RegisterRemoteWorkspace(workspace.Slug, workspace.Alias, workspace.Kind, workspace.ID); err != nil {
		return 0, 0, "", syncBundleResponse{}, err
	}
	var bundle syncBundleResponse
	endpoint := fmt.Sprintf("%s/v1/sync?orgId=%s&deviceId=%s", strings.TrimRight(st.State.ControlPlane.Origin, "/"), url.QueryEscape(workspace.ID), url.QueryEscape(workspace.CurrentDeviceID))
	if err := getJSONBearer(st, endpoint, accessToken, &bundle); err != nil {
		return 0, 0, "", bundle, err
	}
	imported, err := a.importRemoteVersions(st, workspace, bundle.EncryptedSecrets, force)
	if err != nil {
		var partial *store.RemoteImportPartialError
		if !errors.As(err, &partial) {
			return 0, 0, "", bundle, err
		}
		if imported == 0 {
			return 0, 0, "", bundle, err
		}
		fmt.Fprintf(a.Err, "Warning: %s\n", partial.Error())
	}
	importServiceAccountSyncPolicies(st, bundle.Policies)
	st.SetEnvelopeAuditModes(bundle.Scopes)
	st.Audit(st.State.UserID, "control_plane_sync", "allowed", "", "", "fetched encrypted pull bundle", map[string]string{"secrets": fmt.Sprintf("%d", len(bundle.EncryptedSecrets)), "workspace": workspace.Slug})
	if err := st.Save(); err != nil {
		return 0, 0, "", bundle, err
	}
	return imported, len(bundle.EncryptedSecrets), "", bundle, nil
}

type pullOptions struct {
	Force     bool
	Workspace string
}

type pullResult struct {
	Workspace string
	Result    string
	Imported  int
	Remote    int
	Note      string
}

func parsePullArgs(args []string) (pullOptions, error) {
	workspace, remaining, err := splitWorkspaceFlag(args, "pull", true)
	if err != nil {
		return pullOptions{}, err
	}
	if err := rejectUnknownArgs(remaining, "--force"); err != nil {
		return pullOptions{}, err
	}
	return pullOptions{Force: hasFlag(remaining, "--force"), Workspace: workspace}, nil
}

func writePullResults(out io.Writer, results []pullResult) {
	tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "WORKSPACE\tRESULT\tIMPORTED\tREMOTE\tNOTE")
	for _, result := range results {
		fmt.Fprintf(tw, "%s\t%s\t%d\t%d\t%s\n", result.Workspace, result.Result, result.Imported, result.Remote, result.Note)
	}
	_ = tw.Flush()
}

func (a App) importRemoteVersions(st *store.FileStore, workspace remoteWorkspaceResponse, versions []store.RemoteSecretVersion, force bool) (int, error) {
	if len(versions) == 0 {
		return 0, nil
	}
	return st.ImportRemoteSecretVersions(workspace.ID, workspace.Slug, workspace.CurrentDeviceID, versions, force)
}

func importServiceAccountSyncPolicies(st *store.FileStore, policies []syncPolicyResponse) {
	if st == nil || st.State.ControlPlane == nil || st.State.ControlPlane.Source != "service-account" || st.State.ControlPlane.ServiceAccountSlug == "" {
		return
	}
	serviceAccountSlug := store.NormalizeSubjectLabel(st.State.ControlPlane.ServiceAccountSlug)
	runtimeSubject := store.ServiceAccountRuntimeSubject(st.State.ControlPlane.ServiceAccountID)
	if runtimeSubject == "" {
		return
	}
	kept := make([]asiri.Policy, 0, len(st.State.Policies))
	for _, policy := range st.State.Policies {
		if store.NormalizeSubjectLabel(policy.Subject) != runtimeSubject {
			kept = append(kept, policy)
		}
	}
	for _, policy := range policies {
		if policy.SubjectType != "service" || store.NormalizeSubjectLabel(policy.SubjectID) != serviceAccountSlug || policy.ScopePattern == "" || policy.SecretPattern == "" || len(policy.Actions) == 0 || policy.ApprovalMode != "none" {
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
			Subject:       runtimeSubject,
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
