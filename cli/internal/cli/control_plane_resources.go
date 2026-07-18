package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/o-clan/asiri/cli/internal/asiri"
	"github.com/o-clan/asiri/cli/internal/store"
)

type controlPlaneFailureResponse struct {
	Error   string `json:"error"`
	Message string `json:"message"`
}

func parseControlPlaneFailure(responseBody []byte) controlPlaneFailureResponse {
	var failure controlPlaneFailureResponse
	if len(bytes.TrimSpace(responseBody)) > 0 {
		_ = json.Unmarshal(responseBody, &failure)
	}
	return failure
}

func revokeRemoteDevice(st *store.FileStore, origin, orgID, deviceID, accessToken string) (remoteDeviceResponse, error) {
	var result remoteDeviceResponse
	endpoint := strings.TrimRight(origin, "/") + "/v1/devices/" + url.PathEscape(deviceID) + "/revoke"
	if err := postJSONBearer(st, endpoint, accessToken, map[string]string{"orgId": orgID}, &result); err != nil {
		return result, err
	}
	if result.Status != "revoked" {
		return result, errors.New("control plane did not revoke the device")
	}
	return result, nil
}

func requireRemoteDeviceInWorkspace(devices []remoteDeviceResponse, requested, workspaceSlug string) (remoteDeviceResponse, error) {
	for _, device := range devices {
		if device.ID == requested {
			return device, nil
		}
	}
	matches := []remoteDeviceResponse{}
	for _, device := range devices {
		if device.Name == requested {
			matches = append(matches, device)
		}
	}
	if len(matches) == 1 {
		return matches[0], nil
	}
	if len(matches) > 1 {
		return remoteDeviceResponse{}, fmt.Errorf("multiple devices named %s exist in workspace %s; use a device id", requested, workspaceSlug)
	}
	return remoteDeviceResponse{}, fmt.Errorf("device %s was not found in workspace %s", requested, workspaceSlug)
}

func listRemoteDevices(st *store.FileStore, origin, orgID, accessToken string, includeRevoked bool) ([]remoteDeviceResponse, error) {
	var result remoteDevicesResponse
	endpoint := fmt.Sprintf("%s/v1/devices?orgId=%s", strings.TrimRight(origin, "/"), url.QueryEscape(orgID))
	if includeRevoked {
		endpoint += "&includeInactive=1"
	}
	if err := getJSONBearer(st, endpoint, accessToken, &result); err != nil {
		return nil, err
	}
	return result.Devices, nil
}

func getRemoteWorkspaceTree(st *store.FileStore, origin, workspace, accessToken string, includeRevoked bool) (remoteWorkspaceTreeResponse, error) {
	var result remoteWorkspaceTreeResponse
	endpoint := fmt.Sprintf("%s/v1/workspace-tree?workspace=%s", strings.TrimRight(origin, "/"), url.QueryEscape(workspace))
	if includeRevoked {
		endpoint += "&includeRevoked=1"
	}
	if err := getJSONBearer(st, endpoint, accessToken, &result); err != nil {
		return result, err
	}
	if err := validateRemoteWorkspaceTree(result, workspace, includeRevoked); err != nil {
		return result, err
	}
	return result, nil
}

func validateRemoteWorkspaceTree(tree remoteWorkspaceTreeResponse, workspace string, includeRevoked bool) error {
	if tree.Workspace.ID == "" || tree.Workspace.Slug != workspace {
		return errors.New("control plane returned a workspace tree for the wrong workspace")
	}
	if tree.Workspace.SecretCount < 0 {
		return errors.New("control plane returned an invalid workspace secret count")
	}
	for _, user := range tree.Users {
		if user.ID == "" || user.SecretCount < 0 || user.SecretCount > tree.Workspace.SecretCount {
			return errors.New("control plane returned invalid workspace user counts")
		}
		for _, device := range user.Devices {
			if device.ID == "" || (!includeRevoked && device.Status == "revoked") {
				return errors.New("control plane returned invalid workspace device metadata")
			}
			for _, account := range device.ServiceAccountAuth {
				if account.ID == "" || account.Slug == "" {
					return errors.New("control plane returned invalid service account authentication metadata")
				}
			}
		}
		for _, access := range user.Access {
			if access.SecretCount < 0 || access.SecretCount > tree.Workspace.SecretCount || (access.Scope != workspace && !strings.HasPrefix(access.Scope, workspace+"/")) {
				return errors.New("control plane returned invalid workspace access metadata")
			}
		}
	}
	return nil
}

func listRemoteWrappingDevices(st *store.FileStore, origin, orgID, scope, secretName, accessToken string) ([]remoteDeviceResponse, error) {
	endpoint := fmt.Sprintf("%s/v1/devices?orgId=%s&scope=%s&secretName=%s", strings.TrimRight(origin, "/"), url.QueryEscape(orgID), url.QueryEscape(scope), url.QueryEscape(secretName))
	for attempt := 0; attempt < 3; attempt++ {
		var result remoteDevicesResponse
		status, headers, err := getJSONBearerStatusWithHeaders(st, endpoint, accessToken, &result)
		if status != http.StatusTooManyRequests {
			if err != nil {
				return nil, fmt.Errorf("authorized wrapping target discovery failed: %w", err)
			}
			if status < 200 || status >= 300 {
				return nil, fmt.Errorf("authorized wrapping target discovery failed: control plane returned HTTP %d", status)
			}
			return result.Devices, nil
		}
		if attempt == 2 {
			if err != nil {
				return nil, fmt.Errorf("authorized wrapping target discovery failed after rate-limit retries: %w", err)
			}
			return nil, errors.New("authorized wrapping target discovery failed after rate-limit retries: control plane returned HTTP 429")
		}
		time.Sleep(rateLimitRetryDelay(headers, time.Now()))
	}
	return nil, errors.New("authorized wrapping target discovery failed")
}

func listRemoteWrappingTargets(st *store.FileStore, origin, orgID, accessToken string) (map[string][]remoteDeviceResponse, bool, error) {
	var result remoteWrappingTargetsResponse
	endpoint := fmt.Sprintf("%s/v1/devices/wrapping-targets?orgId=%s", strings.TrimRight(origin, "/"), url.QueryEscape(orgID))
	status, err := getJSONBearerStatus(st, endpoint, accessToken, &result)
	if err != nil {
		return nil, false, fmt.Errorf("authorized wrapping target discovery failed: %w", err)
	}
	if status == http.StatusNotFound {
		return nil, false, nil
	}
	if status < 200 || status >= 300 {
		return nil, false, fmt.Errorf("authorized wrapping target discovery failed: control plane returned HTTP %d", status)
	}
	targets := make(map[string][]remoteDeviceResponse, len(result.Targets))
	for _, target := range result.Targets {
		targets[target.SecretID] = target.Devices
	}
	return targets, true, nil
}

func rateLimitRetryDelay(headers http.Header, now time.Time) time.Duration {
	const maximumDelay = time.Minute
	clamp := func(delay time.Duration) time.Duration {
		if delay > maximumDelay {
			return maximumDelay
		}
		return delay
	}
	retryAfter := strings.TrimSpace(headers.Get("Retry-After"))
	if seconds, err := strconv.Atoi(retryAfter); err == nil && seconds >= 0 {
		return clamp(time.Duration(seconds) * time.Second)
	}
	if retryAt, err := http.ParseTime(retryAfter); err == nil {
		if delay := retryAt.Sub(now); delay > 0 {
			return clamp(delay)
		}
		return 0
	}
	if reset, err := strconv.ParseInt(strings.TrimSpace(headers.Get("X-RateLimit-Reset")), 10, 64); err == nil {
		if delay := time.Unix(reset, 0).Sub(now); delay > 0 {
			return clamp(delay)
		}
		return 0
	}
	return time.Minute
}

func listRemoteSecrets(st *store.FileStore, origin, orgID, accessToken, recoveryRecipientID string, includeInactive bool) ([]remoteSecretRecord, error) {
	var result remoteSecretsResponse
	endpoint := fmt.Sprintf("%s/v1/secrets/encrypted?orgId=%s", strings.TrimRight(origin, "/"), url.QueryEscape(orgID))
	if recoveryRecipientID != "" {
		endpoint += "&recoveryRecipientId=" + url.QueryEscape(recoveryRecipientID)
	}
	if includeInactive {
		endpoint += "&includeInactive=1"
	}
	if err := getJSONBearer(st, endpoint, accessToken, &result); err != nil {
		return nil, err
	}
	return result.Secrets, nil
}

func listRemoteSecretMetadata(st *store.FileStore, origin, orgID, accessToken string, includeInactive bool) ([]remoteSecretRecord, int, error) {
	var result remoteSecretsResponse
	endpoint := fmt.Sprintf("%s/v1/secrets?orgId=%s", strings.TrimRight(origin, "/"), url.QueryEscape(orgID))
	if includeInactive {
		endpoint += "&includeInactive=1"
	}
	status, err := getJSONBearerStatus(st, endpoint, accessToken, &result)
	if err != nil {
		return nil, status, err
	}
	if status == http.StatusNotFound {
		return nil, status, nil
	}
	if status < 200 || status >= 300 {
		return nil, status, fmt.Errorf("control plane returned HTTP %d", status)
	}
	return result.Secrets, status, nil
}

func mergeRemoteSecretRecords(primary, secondary []remoteSecretRecord) []remoteSecretRecord {
	if len(secondary) == 0 {
		return primary
	}
	merged := make([]remoteSecretRecord, 0, len(primary)+len(secondary))
	seen := map[string]bool{}
	for _, item := range primary {
		merged = append(merged, item)
		seen[pushVersionKey(item.Scope, item.Name, item.Version)] = true
	}
	for _, item := range secondary {
		key := pushVersionKey(item.Scope, item.Name, item.Version)
		if seen[key] {
			continue
		}
		merged = append(merged, item)
	}
	return merged
}

func getActiveRemoteRecoveryRecipient(st *store.FileStore, origin, orgID, accessToken string) (*asiri.RecoveryConfig, error) {
	var result remoteRecoveryRecipientResponse
	endpoint := fmt.Sprintf("%s/v1/recovery-recipient?orgId=%s", strings.TrimRight(origin, "/"), url.QueryEscape(orgID))
	status, err := getJSONBearerStatus(st, endpoint, accessToken, &result)
	if err != nil {
		return nil, err
	}
	if status == http.StatusNotFound {
		return nil, nil
	}
	if status < 200 || status >= 300 {
		return nil, fmt.Errorf("control plane returned HTTP %d", status)
	}
	if result.Status != "active" || result.RecipientID == "" || result.PublicKey == "" || result.PublicKeyFingerprint == "" {
		return nil, errors.New("control plane returned incomplete recovery recipient metadata")
	}
	return &asiri.RecoveryConfig{
		RecipientID:          result.RecipientID,
		PublicKey:            result.PublicKey,
		PublicKeyFingerprint: result.PublicKeyFingerprint,
		CreatedAt:            time.Now().UTC(),
	}, nil
}

func listVisibleRemoteSecrets(st *store.FileStore, origin, accessToken, workspace string, includeInactive bool) ([]visibleRemoteSecretRecord, error) {
	result, err := listRemoteWorkspaceOverview(st, origin, accessToken, workspace, true, includeInactive)
	if err != nil {
		return nil, err
	}
	if result.Secrets == nil {
		return nil, errors.New("control plane did not return workspace secret metadata")
	}
	return result.Secrets, nil
}

func resolveActiveRemoteSecret(st *store.FileStore, origin, accessToken string, target remoteWorkspaceResponse, scope, name string) (visibleRemoteSecretRecord, error) {
	secrets, err := listVisibleRemoteSecrets(st, origin, accessToken, target.Slug, false)
	if err != nil {
		return visibleRemoteSecretRecord{}, err
	}
	matches := []visibleRemoteSecretRecord{}
	for _, secret := range secrets {
		if secret.Status != "active" || secret.Scope != scope || secret.Name != name {
			continue
		}
		if !visibleSecretInWorkspace(secret, target) {
			continue
		}
		matches = append(matches, secret)
	}
	fullPath := store.SecretKey(scope, name)
	if len(matches) == 0 {
		return visibleRemoteSecretRecord{}, fmt.Errorf("no active remote secret found for %s in workspace %s", fullPath, target.Slug)
	}
	if len(matches) > 1 {
		return visibleRemoteSecretRecord{}, fmt.Errorf("multiple active remote secrets found for %s in workspace %s", fullPath, target.Slug)
	}
	return matches[0], nil
}

func resolveDeletedRemoteSecret(st *store.FileStore, origin, accessToken string, target remoteWorkspaceResponse, scope, name string) (visibleRemoteSecretRecord, error) {
	secrets, err := listVisibleRemoteSecrets(st, origin, accessToken, target.Slug, true)
	if err != nil {
		return visibleRemoteSecretRecord{}, err
	}
	matches := []visibleRemoteSecretRecord{}
	for _, secret := range secrets {
		if secret.Status != "deleted" || secret.Scope != scope || secret.Name != name {
			continue
		}
		if !visibleSecretInWorkspace(secret, target) {
			continue
		}
		matches = append(matches, secret)
	}
	fullPath := store.SecretKey(scope, name)
	if len(matches) == 0 {
		return visibleRemoteSecretRecord{}, fmt.Errorf("no deleted remote secret found for %s in workspace %s", fullPath, target.Slug)
	}
	sort.Slice(matches, func(i, j int) bool {
		if matches[i].Version == matches[j].Version {
			return matches[i].ID < matches[j].ID
		}
		return matches[i].Version > matches[j].Version
	})
	return matches[0], nil
}

func visibleSecretInWorkspace(secret visibleRemoteSecretRecord, target remoteWorkspaceResponse) bool {
	if target.ID != "" && secret.OrgID != "" {
		return secret.OrgID == target.ID
	}
	if secret.WorkspaceSlug != "" {
		return secret.WorkspaceSlug == target.Slug
	}
	return store.WorkspacePrefix(secret.Scope) == target.Slug
}

func remoteOnlyDeleteCandidates(st *store.FileStore, target remoteWorkspaceResponse, secrets []visibleRemoteSecretRecord, requireUnwrapped bool) []visibleRemoteSecretRecord {
	candidates := []visibleRemoteSecretRecord{}
	for _, secret := range secrets {
		if secret.Status != "active" || !visibleSecretInWorkspace(secret, target) {
			continue
		}
		if requireUnwrapped && (secret.WrappedToCurrentDevice == nil || *secret.WrappedToCurrentDevice) {
			continue
		}
		if localActiveSecretExists(st, secret.Scope, secret.Name) {
			continue
		}
		candidates = append(candidates, secret)
	}
	sort.Slice(candidates, func(i, j int) bool {
		left := shortSecretPath(candidates[i].Scope, candidates[i].Name)
		right := shortSecretPath(candidates[j].Scope, candidates[j].Name)
		if left == right {
			return candidates[i].ID < candidates[j].ID
		}
		return left < right
	})
	return candidates
}

func deleteRemoteSecret(st *store.FileStore, origin, orgID, secretID string, version int, deviceID, accessToken string) (visibleRemoteSecretRecord, error) {
	result, err := requestRemoteSecretDelete(st, origin, orgID, secretID, version, deviceID, accessToken)
	if err != nil {
		return result, err
	}
	if result.Status != "deleted" {
		return result, errors.New("control plane did not mark the secret deleted")
	}
	return result, nil
}

func preflightRemoteSecretDelete(st *store.FileStore, origin, orgID, secretID string, version int, deviceID, accessToken string) error {
	result, err := requestRemoteSecretDeletePreflight(st, origin, orgID, secretID, version, deviceID, accessToken)
	if err != nil {
		return err
	}
	if result.ID == "" {
		return errors.New("control plane did not return delete preflight metadata")
	}
	return nil
}

func requestRemoteSecretDelete(st *store.FileStore, origin, orgID, secretID string, version int, deviceID, accessToken string) (visibleRemoteSecretRecord, error) {
	var result visibleRemoteSecretRecord
	endpoint := strings.TrimRight(origin, "/") + "/v1/secrets/" + url.PathEscape(secretID) + "/delete"
	body := map[string]any{"orgId": orgID, "createdByDeviceId": deviceID, "version": version}
	if err := postJSONBearer(st, endpoint, accessToken, body, &result); err != nil {
		return result, err
	}
	return result, nil
}

func requestRemoteSecretDeletePreflight(st *store.FileStore, origin, orgID, secretID string, version int, deviceID, accessToken string) (visibleRemoteSecretRecord, error) {
	var result visibleRemoteSecretRecord
	endpoint := strings.TrimRight(origin, "/") + "/v1/secrets/" + url.PathEscape(secretID) + "/delete-preflight"
	body := map[string]any{"orgId": orgID, "createdByDeviceId": deviceID, "version": version}
	if err := postJSONBearer(st, endpoint, accessToken, body, &result); err != nil {
		return result, err
	}
	return result, nil
}

func restoreRemoteSecret(st *store.FileStore, origin, orgID, secretID string, version int, deviceID, accessToken string) (visibleRemoteSecretRecord, error) {
	var result visibleRemoteSecretRecord
	endpoint := strings.TrimRight(origin, "/") + "/v1/secrets/" + url.PathEscape(secretID) + "/restore"
	body := map[string]any{"orgId": orgID, "createdByDeviceId": deviceID, "version": version}
	if err := postJSONBearer(st, endpoint, accessToken, body, &result); err != nil {
		return result, err
	}
	if result.Status != "active" {
		return result, errors.New("control plane did not restore the secret")
	}
	return result, nil
}

func addRemoteWrappedKeys(st *store.FileStore, origin, orgID, secretID, accessToken string, wrappedKeys []store.RemoteWrappedKey, localRepair bool) error {
	endpoint := strings.TrimRight(origin, "/") + "/v1/secrets/" + url.PathEscape(secretID) + "/wrapped-keys"
	body := map[string]any{"orgId": orgID, "wrappedKeys": wrappedKeys}
	if localRepair {
		body["localRepair"] = true
	}
	return postJSONBearer(st, endpoint, accessToken, body, nil)
}

type remoteWrappedKeyBatchEntry struct {
	SecretID    string                   `json:"secretId"`
	WrappedKeys []store.RemoteWrappedKey `json:"wrappedKeys"`
	LocalRepair bool                     `json:"localRepair"`
}

func addRemoteWrappedKeysBatch(st *store.FileStore, origin, orgID, accessToken string, entries []remoteWrappedKeyBatchEntry) (bool, error) {
	endpoint := strings.TrimRight(origin, "/") + "/v1/secrets/wrapped-keys/batch"
	status, err := postJSONBearerStatus(st, endpoint, accessToken, map[string]any{"orgId": orgID, "entries": entries}, nil)
	if err != nil {
		return false, err
	}
	if status == http.StatusNotFound {
		return false, nil
	}
	if status < 200 || status >= 300 {
		return false, fmt.Errorf("control plane returned HTTP %d", status)
	}
	return true, nil
}

func registerRemoteRecoveryRecipient(st *store.FileStore, origin, orgID, deviceID, accessToken string, setup store.RecoverySetup, replacements []recoveryRecipientReplacement) error {
	if replacements == nil {
		replacements = []recoveryRecipientReplacement{}
	}
	endpoint := strings.TrimRight(origin, "/") + "/v1/recovery-recipient"
	return postJSONBearer(st, endpoint, accessToken, map[string]any{
		"orgId":                orgID,
		"createdByDeviceId":    deviceID,
		"recipientId":          setup.RecipientID,
		"publicKey":            setup.PublicKey,
		"publicKeyFingerprint": setup.Fingerprint,
		"replacements":         replacements,
	}, nil)
}

func replaceRemoteRecoveryRecipient(st *store.FileStore, origin, orgID, deviceID, accessToken string, setup store.RecoverySetup, replacements []recoveryRecipientReplacement) error {
	if replacements == nil {
		replacements = []recoveryRecipientReplacement{}
	}
	endpoint := strings.TrimRight(origin, "/") + "/v1/recovery-recipient/replace"
	return postJSONBearer(st, endpoint, accessToken, map[string]any{
		"orgId":                orgID,
		"createdByDeviceId":    deviceID,
		"recipientId":          setup.RecipientID,
		"publicKey":            setup.PublicKey,
		"publicKeyFingerprint": setup.Fingerprint,
		"replacements":         replacements,
	}, nil)
}

func addRecoveryRestoredWrappedKeys(st *store.FileStore, origin, orgID, secretID, accessToken, recoveryRecipientID string, wrappedKeys []store.RemoteWrappedKey) error {
	endpoint := strings.TrimRight(origin, "/") + "/v1/secrets/" + url.PathEscape(secretID) + "/recovery-wrapped-keys"
	return postJSONBearer(st, endpoint, accessToken, map[string]any{"orgId": orgID, "recoveryRecipientId": recoveryRecipientID, "wrappedKeys": wrappedKeys}, nil)
}

func remoteRecordsToVersions(records []remoteSecretRecord) []store.RemoteSecretVersion {
	versions := make([]store.RemoteSecretVersion, 0, len(records))
	for _, record := range records {
		if record.Status != "active" {
			continue
		}
		versions = append(versions, store.RemoteSecretVersion{
			ID:                record.ID,
			OrgID:             record.OrgID,
			Scope:             record.Scope,
			Name:              record.Name,
			Version:           record.Version,
			Algorithm:         record.Algorithm,
			Nonce:             record.Nonce,
			Ciphertext:        record.Ciphertext,
			AAD:               record.AAD,
			WrappedKeys:       record.WrappedKeys,
			Status:            record.Status,
			CreatedByDeviceID: record.CreatedByDeviceID,
			CreatedAt:         record.CreatedAt,
		})
	}
	return versions
}

func remoteSecretHasRecipient(secret remoteSecretRecord, deviceID string) bool {
	for _, key := range secret.WrappedKeys {
		if key.RecipientType == "device" && key.RecipientID == deviceID {
			return true
		}
	}
	for _, key := range secret.WrappedRecipients {
		if key.RecipientType == "device" && key.RecipientID == deviceID {
			return true
		}
	}
	return false
}

func remoteSecretHasRecoveryRecipient(secret remoteSecretRecord, recipientID string) bool {
	for _, key := range secret.WrappedKeys {
		if key.RecipientType == "recovery" && key.RecipientID == recipientID {
			return true
		}
	}
	for _, key := range secret.WrappedRecipients {
		if key.RecipientType == "recovery" && key.RecipientID == recipientID {
			return true
		}
	}
	return false
}

func localSecretVersionExists(st *store.FileStore, scope, name string, versionNumber int) bool {
	secret, ok := st.State.Secrets[store.SecretKey(scope, name)]
	if !ok {
		return false
	}
	for _, version := range secret.Versions {
		if version.Version == versionNumber && version.DataKeyAccount != "" {
			return true
		}
	}
	return false
}

func localActiveSecretExists(st *store.FileStore, scope, name string) bool {
	secret, ok := st.State.Secrets[store.SecretKey(scope, name)]
	if !ok {
		return false
	}
	return activeVersion(secret) != nil
}

func localSecretWorkspacePrefixes(refs []store.LocalSecretRef) []string {
	seen := map[string]bool{}
	for _, ref := range refs {
		prefix := store.WorkspacePrefix(ref.Scope)
		if prefix != "" {
			seen[prefix] = true
		}
	}
	values := make([]string, 0, len(seen))
	for prefix := range seen {
		values = append(values, prefix)
	}
	sort.Strings(values)
	return values
}
