package cli

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/o-clan/asiri/cli/internal/store"
)

func listRemoteWorkspaceOverview(st *store.FileStore, origin, accessToken, workspace string, includeSecrets, includeInactive bool) (remoteWorkspacesResponse, error) {
	var result remoteWorkspacesResponse
	endpoint := strings.TrimRight(origin, "/") + "/v1/orgs"
	params := url.Values{}
	if workspace != "" {
		params.Set("workspace", workspace)
	}
	if includeSecrets {
		params.Set("includeSecrets", "1")
	}
	if includeInactive {
		params.Set("includeInactive", "1")
	}
	if encoded := params.Encode(); encoded != "" {
		endpoint += "?" + encoded
	}
	if err := getJSONBearer(st, endpoint, accessToken, &result); err != nil {
		return result, err
	}
	return result, nil
}

func requireRemoteWorkspace(workspaces []remoteWorkspaceResponse, requested string) (remoteWorkspaceResponse, error) {
	workspace, ok := findWorkspace(workspaces, requested)
	if !ok {
		return remoteWorkspaceResponse{}, fmt.Errorf("workspace %s is not visible", requested)
	}
	return workspace, nil
}

func (a App) remoteWorkspaceTarget(st *store.FileStore, accessToken, requested string) (remoteWorkspaceResponse, string, error) {
	requested = strings.TrimSpace(requested)
	if err := requireServiceAccountWorkspace(st, requested); err != nil {
		return remoteWorkspaceResponse{}, "", err
	}
	if _, err := localWorkspaceSlug(requested); err != nil {
		return remoteWorkspaceResponse{}, "", errors.New("--workspace requires a workspace slug")
	}
	workspaceResult, err := listRemoteWorkspaceOverview(st, st.State.ControlPlane.Origin, accessToken, requested, false, false)
	if err != nil {
		return remoteWorkspaceResponse{}, "", err
	}
	workspace, err := requireRemoteWorkspace(workspaceResult.Organizations, requested)
	if err != nil {
		return remoteWorkspaceResponse{}, "", err
	}
	if st.State.ControlPlane.Source == "service-account" && workspace.ID != st.State.ControlPlane.WorkspaceID {
		return remoteWorkspaceResponse{}, "", fmt.Errorf("service account session is scoped to workspace %s", st.State.ControlPlane.WorkspaceSlug)
	}
	if explicitWorkspaceDeviceStatus(workspace) == "revoked" {
		return remoteWorkspaceResponse{}, "", revokedDeviceRecoveryError(st, requested)
	}
	if !workspaceDeviceTrusted(workspace) || workspace.CurrentDeviceID == "" {
		return remoteWorkspaceResponse{}, "", fmt.Errorf("this device is not trusted for workspace %s; device %s; next: %s", requested, currentDeviceDescription(st), deviceTrustCommand(st, requested))
	}
	return workspace, latestControlPlaneBearer(st, accessToken), nil
}

func (a App) pushWorkspaceTarget(st *store.FileStore, accessToken, requested string) (remoteWorkspaceResponse, string, error) {
	requested = strings.TrimSpace(requested)
	if _, err := localWorkspaceSlug(requested); err != nil {
		return remoteWorkspaceResponse{}, "", errors.New("--workspace requires a workspace slug")
	}
	workspace, token, err := a.remoteWorkspaceTarget(st, accessToken, requested)
	if err != nil {
		return remoteWorkspaceResponse{}, "", err
	}
	if workspace.CanWrite != nil && !*workspace.CanWrite {
		return remoteWorkspaceResponse{}, "", fmt.Errorf("this account cannot write secrets in workspace %s", requested)
	}
	return workspace, token, nil
}

func remoteWriteOptions(st *store.FileStore, origin, accessToken string, target remoteWorkspaceResponse, refs []store.LocalSecretRef) (writeOptionsResponse, error) {
	entries := make([]map[string]string, 0, len(refs))
	seen := map[string]bool{}
	for _, ref := range refs {
		key := store.SecretKey(ref.Scope, ref.Name)
		if seen[key] {
			continue
		}
		seen[key] = true
		entries = append(entries, map[string]string{"scope": ref.Scope, "name": ref.Name})
	}
	var result writeOptionsResponse
	if err := postJSONBearer(st, strings.TrimRight(origin, "/")+"/v1/sync/write-options", accessToken, map[string]any{"orgId": target.ID, "entries": entries}, &result); err != nil {
		return result, err
	}
	if result.RequestedWorkspaceSlug == "" || result.Workspace.Slug == "" {
		return result, errors.New("control plane returned incomplete write options")
	}
	if result.Workspace.ID != target.ID || result.Workspace.Slug != target.Slug || result.RequestedWorkspaceSlug != target.Slug {
		return result, errors.New("control plane returned write options for a different workspace")
	}
	return result, nil
}

func fullPathList(paths []writePathOption) string {
	values := make([]string, 0, len(paths))
	for _, path := range paths {
		if path.FullPath != "" {
			values = append(values, path.FullPath)
		}
	}
	sort.Strings(values)
	return strings.Join(values, ", ")
}

func workspaceRoleLabel(workspace remoteWorkspaceResponse, userID string) string {
	if workspace.Role != "" && workspace.Role != "none" {
		return workspace.Role
	}
	if workspace.OwnerUserID != "" && workspace.OwnerUserID == userID {
		return "owner"
	}
	if workspace.Role == "none" {
		return "none"
	}
	return "member"
}

func boolPointerLabel(value *bool) string {
	if value == nil {
		return "unknown"
	}
	if *value {
		return "yes"
	}
	return "no"
}

func deviceTrustLabel(value *bool) string {
	if value == nil {
		return "unknown"
	}
	if *value {
		return "trusted"
	}
	return "not trusted"
}

func deviceTrustCommand(st *store.FileStore, workspaceSlug string) string {
	command := fmt.Sprintf("asiri device trust --workspace %s", workspaceSlug)
	if st != nil && st.State.ControlPlane != nil && st.State.ControlPlane.Origin != "" && st.State.ControlPlane.Origin != defaultControlPlaneOrigin {
		command += fmt.Sprintf(" --origin %s", st.State.ControlPlane.Origin)
	}
	return command
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func printable(value string) string {
	if strings.TrimSpace(value) == "" {
		return "-"
	}
	return value
}

func currentDeviceDescription(st *store.FileStore) string {
	if st == nil {
		return "unknown"
	}
	device, err := st.ActiveDevice()
	if err != nil {
		return "unknown"
	}
	fingerprint := store.PublicKeyFingerprint(device.EncryptionPublicKey)
	if device.Name == "" {
		return fingerprint
	}
	return fmt.Sprintf("%s (%s)", device.Name, fingerprint)
}

func ensureControlPlaneAccess(origin string, st *store.FileStore) (string, error) {
	if st.State.ControlPlane == nil {
		return "", errors.New("asiri is not linked to a control plane")
	}
	if err := validateControlPlaneOrigin(origin); err != nil {
		return "", err
	}
	cached, cachedErr := st.ControlPlaneAccessToken()
	cacheFresh := cachedErr == nil && time.Until(st.State.ControlPlane.AccessTokenExpiresAt) > time.Minute
	if cacheFresh {
		return cached, nil
	}
	return refreshControlPlaneAccess(origin, st)
}

func refreshControlPlaneAccess(origin string, st *store.FileStore) (string, error) {
	if st.State.ControlPlane == nil {
		return "", errors.New("asiri is not linked to a control plane")
	}
	if err := validateControlPlaneOrigin(origin); err != nil {
		return "", err
	}
	result, status, err := refreshDeviceSession(origin, st)
	if err != nil {
		return "", err
	}
	if remoteDeviceRevoked(status, result.Error, result.Message) {
		return "", revokedDeviceRecoveryError(st, "")
	}
	if remoteDeviceNotTrusted(status, result.Error, result.Message) {
		return "", untrustedSessionRecoveryError(st)
	}
	if status != http.StatusOK {
		return "", fmt.Errorf("control plane returned HTTP %d", status)
	}
	if err := st.RefreshControlPlane(result.AccessToken, result.ExpiresIn, result.RefreshExpiresAt); err != nil {
		return "", err
	}
	return st.ControlPlaneAccessToken()
}

func rejectServiceAccountControlPlaneMutation(st *store.FileStore) error {
	if st != nil && st.State.ControlPlane != nil && st.State.ControlPlane.Source == "service-account" {
		return errors.New("service account sessions are read-only for control-plane mutations")
	}
	return nil
}

func rejectServiceAccountLocalMutation(st *store.FileStore) error {
	if st != nil && st.State.ControlPlane != nil && st.State.ControlPlane.Source == "service-account" {
		return errors.New("service account sessions cannot mutate local vault or policy state")
	}
	return nil
}

func remoteDeviceNotTrusted(status int, values ...string) bool {
	if status != http.StatusForbidden {
		return false
	}
	for _, value := range values {
		normalized := strings.ToLower(strings.TrimSpace(value))
		if normalized == "device_not_trusted" || normalized == "device not trusted" || normalized == "device is not trusted" {
			return true
		}
	}
	return false
}

func remoteDeviceRevoked(status int, values ...string) bool {
	if status != http.StatusForbidden {
		return false
	}
	for _, value := range values {
		normalized := strings.ToLower(strings.TrimSpace(value))
		if normalized == "device_revoked" || normalized == "device revoked" || normalized == "device has been revoked" {
			return true
		}
	}
	return false
}

func recoveryLoginCommand(st *store.FileStore) string {
	command := "asiri login"
	if st != nil && st.State.ControlPlane != nil {
		origin := strings.TrimRight(st.State.ControlPlane.Origin, "/")
		if origin != "" && origin != defaultControlPlaneOrigin {
			command += " --origin " + origin
		}
	}
	return command
}

func untrustedSessionRecoveryError(st *store.FileStore) error {
	steps := []string{"asiri logout", recoveryLoginCommand(st)}
	lines := []string{"remote access no longer trusts the linked device session. The local vault, secrets, and device keys were preserved. Start a fresh session with the existing device keys:"}
	for index, step := range steps {
		lines = append(lines, fmt.Sprintf("%d. %s", index+1, step))
	}
	return errors.New(strings.Join(lines, "\n"))
}

func revokedDeviceRecoverySteps(st *store.FileStore, workspace string) []string {
	steps := []string{
		"asiri logout",
		"asiri device enroll --name <new-name>",
		recoveryLoginCommand(st),
	}
	if workspace != "" {
		steps = append(steps, fmt.Sprintf("asiri rewrap --workspace %s", workspace))
	}
	return steps
}

func revokedDeviceRecoveryError(st *store.FileStore, workspace string) error {
	detail := "remote access reports this device key pair as revoked and it cannot be approved again"
	if workspace != "" {
		detail = fmt.Sprintf("this device key pair was revoked for workspace %s and cannot be approved again", workspace)
	}
	lines := []string{detail + ". The local vault and secrets were preserved. Recover with fresh device keys:"}
	for index, step := range revokedDeviceRecoverySteps(st, workspace) {
		lines = append(lines, fmt.Sprintf("%d. %s", index+1, step))
	}
	return errors.New(strings.Join(lines, "\n"))
}
