package cli

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/o-clan/asiri/cli/internal/asiri"
	"github.com/o-clan/asiri/cli/internal/store"
)

func (a App) audit(st *store.FileStore, args []string) int {
	if len(args) == 0 || args[0] != "tail" {
		return a.fail(errors.New("audit tail is required"))
	}
	if err := st.RequireInitialized(); err != nil {
		return a.fail(err)
	}
	workspaceArg, remaining, err := splitWorkspaceFlag(args[1:], "audit tail", true)
	if err != nil {
		return a.fail(err)
	}
	if err := rejectUnknownArgs(remaining, "--limit"); err != nil {
		return a.fail(err)
	}
	workspaceSet, err := a.workspaceFilterSet(st, []string{workspaceArg}, "audit tail")
	if err != nil {
		return a.fail(err)
	}
	limit := 20
	if value := flagValue(remaining, "--limit", ""); value != "" {
		parsed, err := strconv.Atoi(value)
		if err != nil || parsed < 1 {
			return a.fail(errors.New("--limit must be a positive integer"))
		}
		limit = parsed
	}
	printed := 0
	for _, event := range st.State.Audit {
		if printed >= limit {
			break
		}
		if len(workspaceSet) > 0 && !auditEventMatchesWorkspace(event, workspaceSet) {
			continue
		}
		syncStatus := auditSyncStatus(st, event)
		fmt.Fprintf(a.Out, "%s\t%s\t%s\t%s\t%s\t%s\n", event.CreatedAt.Format(time.RFC3339), event.Actor, event.Action, event.Result, syncStatus, event.Reason)
		printed++
	}
	return 0
}

func auditSyncStatus(st *store.FileStore, event asiri.AuditEvent) string {
	if event.RemoteSyncedAt != nil {
		return "synced"
	}
	if isRuntimeAuditAction(event.Action) && event.Metadata != nil && event.Metadata["runtimeLabel"] != "" && runtimeAuditEventWorkspaceID(st, event) != "" {
		return "pending"
	}
	return "local"
}

func auditEventMatchesWorkspace(event asiri.AuditEvent, workspaces map[string]bool) bool {
	if len(workspaces) == 0 {
		return true
	}
	if event.Metadata != nil {
		if workspaces[event.Metadata["workspaceSlug"]] || workspaces[event.Metadata["workspace"]] {
			return true
		}
	}
	return workspaces[store.WorkspacePrefix(event.Scope)]
}

func (a App) syncRuntimeAuditBestEffort(st *store.FileStore) {
	if st.State.ControlPlane == nil {
		return
	}
	_, events := pendingRuntimeAuditEvents(st)
	if len(events) == 0 {
		return
	}
	accessToken, ok := runtimeAuditAccessToken(st)
	if !ok {
		return
	}
	endpoint := strings.TrimRight(st.State.ControlPlane.Origin, "/") + "/v1/audit/batch"
	updated := false
	for _, batch := range runtimeAuditBatchesByWorkspace(events) {
		var response runtimeAuditBatchResponse
		if err := postJSONBearerTimeout(st, endpoint, accessToken, runtimeAuditBatchRequest{OrgID: batch[0].OrgID, Events: batch}, &response, runtimeAuditSyncTimeout); err != nil {
			continue
		}
		// A 2xx without matching acks stays pending; the ack is the durable sync boundary.
		acks := runtimeAuditRemoteAcks(batch, response.Acks)
		if len(acks) == 0 {
			continue
		}
		st.MarkAuditEventsRemoteAcked(acks)
		updated = true
	}
	if updated {
		_ = st.Save()
	}
}

var runtimeAuditSyncTimeout = 2 * time.Second

func runtimeAuditAccessToken(st *store.FileStore) (string, bool) {
	if st == nil || st.State.ControlPlane == nil {
		return "", false
	}
	if time.Until(st.State.ControlPlane.AccessTokenExpiresAt) <= 30*time.Second {
		return "", false
	}
	accessToken, err := st.ControlPlaneAccessToken()
	if err != nil || accessToken == "" {
		return "", false
	}
	return accessToken, true
}

type runtimeAuditBatchRequest struct {
	OrgID  string                    `json:"orgId"`
	Events []runtimeAuditUploadEvent `json:"events"`
}

type runtimeAuditBatchResponse struct {
	Acks []runtimeAuditAck `json:"acks"`
}

type runtimeAuditAck struct {
	LocalAuditID    string `json:"localAuditId"`
	EventDigest     string `json:"eventDigest"`
	ServerEventID   string `json:"serverEventId"`
	ServerCreatedAt string `json:"serverCreatedAt"`
}

type runtimeAuditUploadEvent struct {
	LocalAuditID   string            `json:"localAuditId,omitempty"`
	EventDigest    string            `json:"eventDigest,omitempty"`
	OrgID          string            `json:"orgId"`
	Action         string            `json:"action"`
	Result         string            `json:"result"`
	Scope          string            `json:"scope,omitempty"`
	SecretNameHash string            `json:"secretNameHash,omitempty"`
	Reason         string            `json:"reason,omitempty"`
	CreatedAt      string            `json:"createdAt,omitempty"`
	Metadata       map[string]string `json:"metadata,omitempty"`
}

func pendingRuntimeAuditEvents(st *store.FileStore) ([]string, []runtimeAuditUploadEvent) {
	if st.State.ControlPlane == nil {
		return nil, nil
	}
	ids := []string{}
	events := []runtimeAuditUploadEvent{}
	for _, event := range st.State.Audit {
		if event.RemoteSyncedAt != nil || !isRuntimeAuditAction(event.Action) {
			continue
		}
		if event.Metadata == nil || event.Metadata["runtimeLabel"] == "" {
			continue
		}
		eventWorkspaceID := runtimeAuditEventWorkspaceID(st, event)
		if eventWorkspaceID == "" {
			continue
		}
		ids = append(ids, event.ID)
		events = append(events, runtimeAuditUploadEventFromEvent(eventWorkspaceID, event))
	}
	return ids, events
}

func runtimeAuditUploadEventFromEvent(orgID string, event asiri.AuditEvent) runtimeAuditUploadEvent {
	metadata := copyStringMap(event.Metadata)
	if metadata == nil {
		metadata = map[string]string{}
	}
	digest := event.Digest
	if digest == "" {
		digest = store.AuditEventDigest(event)
	}
	metadata["localAuditId"] = event.ID
	metadata["eventDigest"] = digest
	metadata["reportedCreatedAt"] = event.CreatedAt.Format(time.RFC3339)
	return runtimeAuditUploadEvent{
		LocalAuditID:   event.ID,
		EventDigest:    digest,
		OrgID:          orgID,
		Action:         event.Action,
		Result:         event.Result,
		Scope:          event.Scope,
		SecretNameHash: event.SecretNameHash,
		Reason:         event.Reason,
		CreatedAt:      event.CreatedAt.Format(time.RFC3339),
		Metadata:       metadata,
	}
}

func runtimeAuditBatchesByWorkspace(events []runtimeAuditUploadEvent) [][]runtimeAuditUploadEvent {
	order := []string{}
	grouped := map[string][]runtimeAuditUploadEvent{}
	for _, event := range events {
		if _, ok := grouped[event.OrgID]; !ok {
			order = append(order, event.OrgID)
		}
		grouped[event.OrgID] = append(grouped[event.OrgID], event)
	}
	batches := make([][]runtimeAuditUploadEvent, 0, len(order))
	for _, orgID := range order {
		batches = append(batches, grouped[orgID])
	}
	return batches
}

func runtimeAuditRemoteAcks(events []runtimeAuditUploadEvent, acks []runtimeAuditAck) []store.RemoteAuditAck {
	expected := map[string]string{}
	for _, event := range events {
		if event.LocalAuditID != "" && event.EventDigest != "" {
			expected[event.LocalAuditID] = event.EventDigest
		}
	}
	out := []store.RemoteAuditAck{}
	seen := map[string]bool{}
	for _, ack := range acks {
		if expected[ack.LocalAuditID] == "" || expected[ack.LocalAuditID] != ack.EventDigest {
			continue
		}
		if seen[ack.LocalAuditID] {
			continue
		}
		seen[ack.LocalAuditID] = true
		syncedAt, _ := time.Parse(time.RFC3339, ack.ServerCreatedAt)
		if syncedAt.IsZero() {
			syncedAt = time.Now().UTC()
		}
		out = append(out, store.RemoteAuditAck{LocalAuditID: ack.LocalAuditID, EventDigest: ack.EventDigest, RemoteEventID: ack.ServerEventID, SyncedAt: syncedAt})
	}
	return out
}

func (a App) gateSecretRelease(st *store.FileStore, actor, auditAction, scope, secretNameHash, reason string, metadata map[string]string) error {
	st.Audit(actor, auditAction, "allowed", scope, secretNameHash, reason, metadata)
	eventID := st.LatestAuditEventID()
	if err := st.SaveWithAuditLedger(); err != nil {
		return err
	}
	if st.ResolveEnvelopeAuditMode(scope) != asiri.AuditModeStrict {
		a.syncRuntimeAuditBestEffort(st)
		return nil
	}
	event, ok := st.AuditEventByID(eventID)
	if !ok {
		return errors.New("strict audit event missing after local append")
	}
	if err := a.syncRuntimeAuditStrict(st, event); err != nil {
		failedMetadata := copyStringMap(metadata)
		if failedMetadata == nil {
			failedMetadata = map[string]string{}
		}
		failedMetadata["blockedLocalAuditId"] = event.ID
		failedMetadata["blockedEventDigest"] = event.Digest
		st.Audit(actor, auditAction, "failed", scope, secretNameHash, "secret release blocked because strict audit ack failed: "+err.Error(), failedMetadata)
		if saveErr := st.SaveWithAuditLedger(); saveErr != nil {
			return fmt.Errorf("strict audit ack required before secret release: %w; failed to persist failed audit record: %v", err, saveErr)
		}
		return fmt.Errorf("strict audit ack required before secret release: %w", err)
	}
	return nil
}

func (a App) syncRuntimeAuditStrict(st *store.FileStore, event asiri.AuditEvent) error {
	return a.syncRuntimeAuditStrictBatch(st, []asiri.AuditEvent{event})
}

func (a App) syncRuntimeAuditStrictBatch(st *store.FileStore, events []asiri.AuditEvent) error {
	if len(events) == 0 {
		return nil
	}
	if st.State.ControlPlane == nil {
		return errors.New("control plane is not linked")
	}
	// The account session is only the authentication credential here. The
	// requested secret workspace travels in the audit event orgId, so strict
	// ack must never switch or overwrite the user's active CLI workspace.
	accessToken, err := ensureControlPlaneAccess(st.State.ControlPlane.Origin, st)
	if err != nil {
		return err
	}
	uploads := make([]runtimeAuditUploadEvent, 0, len(events))
	for _, event := range events {
		orgID := runtimeAuditEventWorkspaceID(st, event)
		if orgID == "" {
			return errors.New("audit event is not attributable to a workspace")
		}
		uploads = append(uploads, runtimeAuditUploadEventFromEvent(orgID, event))
	}
	endpoint := strings.TrimRight(st.State.ControlPlane.Origin, "/") + "/v1/audit/batch"
	allAcks := []store.RemoteAuditAck{}
	for _, batch := range runtimeAuditBatchesByWorkspace(uploads) {
		var response runtimeAuditBatchResponse
		if err := postJSONBearerTimeout(st, endpoint, accessToken, runtimeAuditBatchRequest{OrgID: batch[0].OrgID, Events: batch}, &response, runtimeAuditSyncTimeout); err != nil {
			return err
		}
		acks := runtimeAuditRemoteAcks(batch, response.Acks)
		if len(acks) != len(batch) {
			return errors.New("control plane did not return matching audit acks")
		}
		allAcks = append(allAcks, acks...)
	}
	st.MarkAuditEventsRemoteAcked(allAcks)
	return st.SaveWithAuditLedger()
}

func runtimeAuditEventWorkspaceID(st *store.FileStore, event asiri.AuditEvent) string {
	if st == nil || st.State.ControlPlane == nil {
		return ""
	}
	if event.Metadata == nil {
		return ""
	}
	return event.Metadata["workspaceId"]
}

func isRuntimeAuditAction(action string) bool {
	switch action {
	case "secret_read", "secret_injected", "secret_env_exported", "secret_mounted", "secret_unsafe_argv_injected", "secret_brokered", "broker_request", "broker_started", "broker_stopped":
		return true
	default:
		return false
	}
}

func runtimeLabelType(agentExplicit bool) string {
	if agentExplicit {
		return "agent"
	}
	return "process"
}

func runtimeSubject(st *store.FileStore, current, fallback string, agentExplicit bool) (string, string, error) {
	if st != nil && st.State.ControlPlane != nil && st.State.ControlPlane.Source == "service-account" {
		serviceAccount := store.ServiceAccountRuntimeSubject(st.State.ControlPlane.ServiceAccountID)
		if serviceAccount == "" {
			return "", "", errors.New("service account session is missing service account identity")
		}
		return serviceAccount, "service", nil
	}
	if current == "" {
		current = fallback
	}
	return store.NormalizeSubjectLabel(current), runtimeLabelType(agentExplicit), nil
}

func runtimeAuditMetadata(st *store.FileStore, scope, label, labelType string, extra map[string]string) map[string]string {
	label = store.NormalizeSubjectLabel(label)
	if label == "" {
		if len(extra) == 0 {
			return nil
		}
		return copyStringMap(extra)
	}
	if labelType == "" {
		labelType = "process"
	}
	metadata := map[string]string{
		"runtimeLabel":     label,
		"runtimeLabelType": labelType,
	}
	if workspaceID, workspaceSlug := runtimeAuditScopeWorkspace(st, scope); workspaceID != "" {
		metadata["workspaceId"] = workspaceID
		metadata["workspaceSlug"] = workspaceSlug
	}
	for key, value := range extra {
		metadata[key] = value
	}
	return metadata
}

func runtimeAuditScopeWorkspace(st *store.FileStore, scope string) (string, string) {
	if st == nil || scope == "" {
		return "", ""
	}
	binding, ok := st.RemoteBindingForPrefix(store.WorkspacePrefix(scope))
	if !ok || binding.WorkspaceID == "" {
		return "", ""
	}
	return binding.WorkspaceID, binding.WorkspaceSlug
}

func copyStringMap(input map[string]string) map[string]string {
	if len(input) == 0 {
		return nil
	}
	output := make(map[string]string, len(input))
	for key, value := range input {
		output[key] = value
	}
	return output
}
