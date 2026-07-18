package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/o-clan/asiri/cli/internal/asiri"
	"github.com/o-clan/asiri/cli/internal/store"
)

func TestRuntimeAuditSyncReportsRuntimeLabelMetadata(t *testing.T) {
	tmp := t.TempDir()
	oldHome := os.Getenv("ASIRI_HOME")
	oldPath := os.Getenv("PATH")
	t.Cleanup(func() {
		_ = os.Setenv("ASIRI_HOME", oldHome)
		_ = os.Setenv("PATH", oldPath)
	})
	if err := os.Setenv("ASIRI_HOME", tmp); err != nil {
		t.Fatal(err)
	}
	binDir := t.TempDir()
	marker := filepath.Join(tmp, "ran")
	wranglerPath := filepath.Join(binDir, "wrangler")
	if err := os.WriteFile(wranglerPath, []byte(fmt.Sprintf("#!/bin/sh\ntest \"$WRANGLER_SECRET\" = env_secret\ntouch %q\necho runtime-sync-ok\n", marker)), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Setenv("PATH", binDir+string(os.PathListSeparator)+oldPath); err != nil {
		t.Fatal(err)
	}

	var uploaded []runtimeAuditBatchRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/session/refresh":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status":           "approved",
				"orgId":            "org_runtime",
				"workspaceSlug":    "runtime-ws",
				"userId":           "usr_owner",
				"deviceId":         "dev_remote",
				"accessToken":      "at_refreshed",
				"expiresIn":        3600,
				"refreshExpiresAt": time.Now().UTC().Add(7 * 24 * time.Hour).Format(time.RFC3339),
			})
		case "/v1/audit/batch":
			if r.Header.Get("authorization") != "Bearer at_runtime" {
				t.Fatalf("unexpected audit auth header: %s", r.Header.Get("authorization"))
			}
			var batch runtimeAuditBatchRequest
			if err := json.NewDecoder(r.Body).Decode(&batch); err != nil {
				t.Fatal(err)
			}
			assertAuditBatchWorkspace(t, batch, "org_runtime")
			uploaded = append(uploaded, batch)
			w.WriteHeader(http.StatusCreated)
			acks := []runtimeAuditAck{}
			for index, event := range batch.Events {
				acks = append(acks, runtimeAuditAck{
					LocalAuditID:    event.LocalAuditID,
					EventDigest:     event.EventDigest,
					ServerEventID:   fmt.Sprintf("aud_remote_%d", index),
					ServerCreatedAt: time.Now().UTC().Format(time.RFC3339),
				})
			}
			_ = json.NewEncoder(w).Encode(runtimeAuditBatchResponse{Acks: acks})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	var out bytes.Buffer
	var errb bytes.Buffer
	app := New(&out, &errb)
	for _, step := range [][]string{
		{"init", "--device", "qa-laptop", "--workspace", "qa"},
		{"add", "--workspace", "qa", "cloudflare/WRANGLER_SECRET", "--value-file", testSecretFile(t, "env_secret")},
		{"grant", "--workspace", "qa", "wrangler", "cloudflare/WRANGLER_SECRET", "--inject-only"},
	} {
		out.Reset()
		errb.Reset()
		if code := app.Run(step); code != 0 {
			t.Fatalf("%v failed with code %d stderr=%s", step, code, errb.String())
		}
	}
	st, err := store.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	device, err := st.ActiveDevice()
	if err != nil {
		t.Fatal(err)
	}
	if err := st.LinkControlPlaneForDevice(server.URL, "org_runtime", "runtime-ws", "usr_owner", "dev_remote", device.ID, "at_runtime", "rt_runtime", 3600, time.Now().UTC().Add(7*24*time.Hour).Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
	st.State.RemoteBindings["qa"] = asiri.RemoteWorkspaceBinding{WorkspaceID: "org_runtime", WorkspaceSlug: "runtime-ws", BoundAt: time.Now().UTC()}
	if err := st.Save(); err != nil {
		t.Fatal(err)
	}

	out.Reset()
	errb.Reset()
	if code := app.Run([]string{"run", "--workspace", "qa", "--env", "WRANGLER_SECRET=cloudflare/WRANGLER_SECRET", "--", "wrangler", "deploy"}); code != 0 {
		t.Fatalf("runtime command failed: %s", errb.String())
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("runtime command marker missing: %v", err)
	}
	if len(uploaded) != 1 || len(uploaded[0].Events) != 1 {
		t.Fatalf("expected one uploaded runtime audit event, got %#v", uploaded)
	}
	event := uploaded[0].Events[0]
	if event.OrgID != "org_runtime" || event.Action != "secret_injected" || event.Result != "allowed" {
		t.Fatalf("unexpected uploaded event: %#v", event)
	}
	if event.Metadata["runtimeLabel"] != "wrangler" || event.Metadata["runtimeLabelType"] != "process" || event.Metadata["workspaceId"] != "org_runtime" || event.Metadata["workspaceSlug"] != "runtime-ws" || event.Metadata["localAuditId"] == "" || event.Metadata["reportedCreatedAt"] == "" {
		t.Fatalf("runtime label metadata missing: %#v", event.Metadata)
	}
	raw, err := json.Marshal(uploaded)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "env_secret") {
		t.Fatalf("uploaded audit leaked secret value: %s", string(raw))
	}
	st, err = store.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	synced := false
	for _, item := range st.State.Audit {
		if item.Action == "secret_injected" && item.Metadata["runtimeLabel"] == "wrangler" {
			synced = item.RemoteSyncedAt != nil
			break
		}
	}
	if !synced {
		t.Fatalf("local runtime audit event was not marked synced")
	}
}

func TestRuntimeAuditSyncFailureDoesNotBlockLocalUse(t *testing.T) {
	tmp := t.TempDir()
	oldHome := os.Getenv("ASIRI_HOME")
	oldPath := os.Getenv("PATH")
	oldAuditSyncTimeout := runtimeAuditSyncTimeout
	t.Cleanup(func() {
		_ = os.Setenv("ASIRI_HOME", oldHome)
		_ = os.Setenv("PATH", oldPath)
		runtimeAuditSyncTimeout = oldAuditSyncTimeout
	})
	runtimeAuditSyncTimeout = 25 * time.Millisecond
	if err := os.Setenv("ASIRI_HOME", tmp); err != nil {
		t.Fatal(err)
	}
	binDir := t.TempDir()
	marker := filepath.Join(tmp, "ran")
	wranglerPath := filepath.Join(binDir, "wrangler")
	if err := os.WriteFile(wranglerPath, []byte(fmt.Sprintf("#!/bin/sh\ntest \"$WRANGLER_SECRET\" = env_secret\ntouch %q\necho runtime-offline-ok\n", marker)), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Setenv("PATH", binDir+string(os.PathListSeparator)+oldPath); err != nil {
		t.Fatal(err)
	}

	auditAttempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/session/refresh":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status":           "approved",
				"orgId":            "org_runtime",
				"workspaceSlug":    "runtime-ws",
				"userId":           "usr_owner",
				"deviceId":         "dev_remote",
				"accessToken":      "at_refreshed",
				"expiresIn":        3600,
				"refreshExpiresAt": time.Now().UTC().Add(7 * 24 * time.Hour).Format(time.RFC3339),
			})
		case "/v1/audit/batch":
			auditAttempts++
			time.Sleep(150 * time.Millisecond)
			http.Error(w, "offline", http.StatusServiceUnavailable)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	var out bytes.Buffer
	var errb bytes.Buffer
	app := New(&out, &errb)
	for _, step := range [][]string{
		{"init", "--device", "qa-laptop", "--workspace", "qa"},
		{"add", "--workspace", "qa", "cloudflare/WRANGLER_SECRET", "--value-file", testSecretFile(t, "env_secret")},
		{"grant", "--workspace", "qa", "wrangler", "cloudflare/WRANGLER_SECRET", "--inject-only"},
	} {
		out.Reset()
		errb.Reset()
		if code := app.Run(step); code != 0 {
			t.Fatalf("%v failed with code %d stderr=%s", step, code, errb.String())
		}
	}
	st, err := store.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	device, err := st.ActiveDevice()
	if err != nil {
		t.Fatal(err)
	}
	if err := st.LinkControlPlaneForDevice(server.URL, "org_runtime", "runtime-ws", "usr_owner", "dev_remote", device.ID, "at_runtime", "rt_runtime", 3600, time.Now().UTC().Add(7*24*time.Hour).Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
	st.State.RemoteBindings["qa"] = asiri.RemoteWorkspaceBinding{WorkspaceID: "org_runtime", WorkspaceSlug: "runtime-ws", BoundAt: time.Now().UTC()}
	if err := st.Save(); err != nil {
		t.Fatal(err)
	}

	out.Reset()
	errb.Reset()
	if code := app.Run([]string{"run", "--workspace", "qa", "--env", "WRANGLER_SECRET=cloudflare/WRANGLER_SECRET", "--", "wrangler", "deploy"}); code != 0 {
		t.Fatalf("runtime command should ignore audit upload failure: %s", errb.String())
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("runtime command marker missing: %v", err)
	}
	if auditAttempts == 0 {
		t.Fatalf("expected an audit upload attempt")
	}
	st, err = store.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	startedAt := time.Now()
	app.syncRuntimeAuditBestEffort(st)
	if elapsed := time.Since(startedAt); elapsed > 250*time.Millisecond {
		t.Fatalf("audit sync timeout was not bounded: %s", elapsed)
	}
	foundPending := false
	for _, item := range st.State.Audit {
		if item.Action == "secret_injected" && item.Metadata["runtimeLabel"] == "wrangler" {
			foundPending = item.RemoteSyncedAt == nil
			break
		}
	}
	if !foundPending {
		t.Fatalf("failed upload should leave runtime audit event pending")
	}
}

func TestRuntimeAuditBestEffortSyncIsolatesWorkspaceFailures(t *testing.T) {
	tmp := t.TempDir()
	oldHome := os.Getenv("ASIRI_HOME")
	t.Cleanup(func() {
		_ = os.Setenv("ASIRI_HOME", oldHome)
	})
	if err := os.Setenv("ASIRI_HOME", tmp); err != nil {
		t.Fatal(err)
	}

	acksByWorkspace := map[string]int{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/audit/batch":
			var batch runtimeAuditBatchRequest
			if err := json.NewDecoder(r.Body).Decode(&batch); err != nil {
				t.Fatal(err)
			}
			if len(batch.Events) == 0 {
				t.Fatal("empty audit batch")
			}
			orgID := batch.Events[0].OrgID
			assertAuditBatchWorkspace(t, batch, orgID)
			for _, event := range batch.Events {
				if event.OrgID != orgID {
					t.Fatalf("best-effort sync should upload one workspace per batch: %#v", batch.Events)
				}
			}
			acksByWorkspace[orgID]++
			if orgID == "org_old" {
				http.Error(w, "workspace no longer reportable", http.StatusForbidden)
				return
			}
			response := runtimeAuditBatchResponse{}
			for index, event := range batch.Events {
				response.Acks = append(response.Acks, runtimeAuditAck{
					LocalAuditID:    event.LocalAuditID,
					EventDigest:     event.EventDigest,
					ServerEventID:   fmt.Sprintf("aud_buffered_%d", index),
					ServerCreatedAt: time.Now().UTC().Format(time.RFC3339),
				})
			}
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(response)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	var out bytes.Buffer
	var errb bytes.Buffer
	app := New(&out, &errb)
	if code := app.Run([]string{"init", "--device", "qa-laptop", "--workspace", "qa"}); code != 0 {
		t.Fatalf("init failed with code %d stderr=%s", code, errb.String())
	}
	st, err := store.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	device, err := st.ActiveDevice()
	if err != nil {
		t.Fatal(err)
	}
	if err := st.LinkControlPlaneForDevice(server.URL, "org_current", "current", "usr_owner", "dev_remote", device.ID, "at_runtime", "rt_runtime", 3600, time.Now().UTC().Add(7*24*time.Hour).Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
	st.Audit(device.ID, "secret_read", "allowed", "current/app/prod", "hash_current", "runtime read", map[string]string{"runtimeLabel": "tool", "workspaceId": "org_current"})
	currentID := st.LatestAuditEventID()
	st.Audit(device.ID, "secret_read", "allowed", "old/app/prod", "hash_old", "runtime read", map[string]string{"runtimeLabel": "tool", "workspaceId": "org_old"})
	oldID := st.LatestAuditEventID()
	if err := st.SaveWithAuditLedger(); err != nil {
		t.Fatal(err)
	}

	app.syncRuntimeAuditBestEffort(st)

	st, err = store.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	current, ok := st.AuditEventByID(currentID)
	if !ok {
		t.Fatal("current audit event missing")
	}
	old, ok := st.AuditEventByID(oldID)
	if !ok {
		t.Fatal("old audit event missing")
	}
	if current.RemoteSyncedAt == nil {
		t.Fatalf("current workspace audit should sync despite old workspace failure: %#v", current)
	}
	if old.RemoteSyncedAt != nil {
		t.Fatalf("old workspace audit should remain pending after failed upload: %#v", old)
	}
	if acksByWorkspace["org_current"] != 1 || acksByWorkspace["org_old"] != 1 {
		t.Fatalf("expected isolated workspace uploads, got %#v", acksByWorkspace)
	}
}

func TestStrictEnvelopeAuditAckGatesRuntimeRelease(t *testing.T) {
	for _, tc := range []struct {
		name    string
		ack     bool
		wantRun bool
	}{
		{name: "matching ack releases", ack: true, wantRun: true},
		{name: "missing ack blocks", ack: false, wantRun: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tmp := t.TempDir()
			oldHome := os.Getenv("ASIRI_HOME")
			oldPath := os.Getenv("PATH")
			t.Cleanup(func() {
				_ = os.Setenv("ASIRI_HOME", oldHome)
				_ = os.Setenv("PATH", oldPath)
			})
			if err := os.Setenv("ASIRI_HOME", tmp); err != nil {
				t.Fatal(err)
			}
			binDir := t.TempDir()
			marker := filepath.Join(tmp, "ran")
			wranglerPath := filepath.Join(binDir, "wrangler")
			if err := os.WriteFile(wranglerPath, []byte(fmt.Sprintf("#!/bin/sh\ntest \"$WRANGLER_SECRET\" = env_secret\ntouch %q\necho strict-ok\n", marker)), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Setenv("PATH", binDir+string(os.PathListSeparator)+oldPath); err != nil {
				t.Fatal(err)
			}

			uploadedStrictEvents := []runtimeAuditUploadEvent{}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/v1/auth/session/refresh":
					_ = json.NewEncoder(w).Encode(map[string]any{
						"status":           "approved",
						"orgId":            "org_runtime",
						"workspaceSlug":    "runtime-ws",
						"userId":           "usr_owner",
						"deviceId":         "dev_remote",
						"accessToken":      "at_refreshed",
						"expiresIn":        3600,
						"refreshExpiresAt": time.Now().UTC().Add(7 * 24 * time.Hour).Format(time.RFC3339),
					})
				case "/v1/audit/batch":
					var batch runtimeAuditBatchRequest
					if err := json.NewDecoder(r.Body).Decode(&batch); err != nil {
						t.Fatal(err)
					}
					assertAuditBatchWorkspace(t, batch, "org_runtime")
					uploadedStrictEvents = append(uploadedStrictEvents, batch.Events...)
					response := runtimeAuditBatchResponse{}
					if tc.ack {
						for index, event := range batch.Events {
							response.Acks = append(response.Acks, runtimeAuditAck{
								LocalAuditID:    event.LocalAuditID,
								EventDigest:     event.EventDigest,
								ServerEventID:   fmt.Sprintf("aud_strict_%d", index),
								ServerCreatedAt: time.Now().UTC().Format(time.RFC3339),
							})
						}
					}
					w.WriteHeader(http.StatusCreated)
					_ = json.NewEncoder(w).Encode(response)
				default:
					http.NotFound(w, r)
				}
			}))
			defer server.Close()

			var out bytes.Buffer
			var errb bytes.Buffer
			app := New(&out, &errb)
			for _, step := range [][]string{
				{"init", "--device", "qa-laptop", "--workspace", "qa"},
				{"add", "--workspace", "qa", "cloudflare/WRANGLER_SECRET", "--value-file", testSecretFile(t, "env_secret")},
				{"grant", "--workspace", "qa", "wrangler", "cloudflare/WRANGLER_SECRET", "--inject-only"},
			} {
				out.Reset()
				errb.Reset()
				if code := app.Run(step); code != 0 {
					t.Fatalf("%v failed with code %d stderr=%s", step, code, errb.String())
				}
			}
			st, err := store.LoadDefault()
			if err != nil {
				t.Fatal(err)
			}
			device, err := st.ActiveDevice()
			if err != nil {
				t.Fatal(err)
			}
			if err := st.LinkControlPlaneForDevice(server.URL, "org_runtime", "runtime-ws", "usr_owner", "dev_remote", device.ID, "at_runtime", "rt_runtime", 3600, time.Now().UTC().Add(7*24*time.Hour).Format(time.RFC3339)); err != nil {
				t.Fatal(err)
			}
			st.State.RemoteBindings["qa"] = asiri.RemoteWorkspaceBinding{WorkspaceID: "org_runtime", WorkspaceSlug: "runtime-ws", BoundAt: time.Now().UTC()}
			st.SetEnvelopeAuditModes([]asiri.ScopeAuditMode{{Path: "qa/cloudflare", ResolvedAuditMode: asiri.AuditModeStrict}})
			if err := st.Save(); err != nil {
				t.Fatal(err)
			}

			out.Reset()
			errb.Reset()
			code := app.Run([]string{"run", "--workspace", "qa", "--env", "WRANGLER_SECRET=cloudflare/WRANGLER_SECRET", "--", "wrangler", "deploy"})
			if tc.wantRun {
				if code != 0 {
					t.Fatalf("strict runtime command failed: %s", errb.String())
				}
				if _, err := os.Stat(marker); err != nil {
					t.Fatalf("strict runtime command marker missing: %v", err)
				}
			} else {
				if code == 0 {
					t.Fatalf("strict runtime command should have failed closed")
				}
				if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("strict runtime command should not have run, stat err=%v", err)
				}
			}
			st, err = store.LoadDefault()
			if err != nil {
				t.Fatal(err)
			}
			foundRuntimeAudit := false
			foundRetryableAllowedAudit := false
			for _, item := range st.State.Audit {
				if item.Action != "secret_injected" || item.Metadata["runtimeLabel"] != "wrangler" {
					continue
				}
				if tc.wantRun {
					foundRuntimeAudit = true
					if item.Result != "allowed" || item.RemoteSyncedAt == nil {
						t.Fatalf("strict released audit should be allowed and acked: %#v", item)
					}
				} else {
					if len(uploadedStrictEvents) != 1 {
						t.Fatalf("expected one strict upload, got %d", len(uploadedStrictEvents))
					}
					if item.ID == uploadedStrictEvents[0].LocalAuditID {
						if item.Result != "allowed" || item.RemoteSyncedAt != nil || item.Digest != uploadedStrictEvents[0].EventDigest {
							t.Fatalf("original strict release audit should stay retryable: %#v", item)
						}
						foundRetryableAllowedAudit = true
						if foundRuntimeAudit {
							break
						}
						continue
					}
					foundRuntimeAudit = true
					if item.Result != "failed" || item.RemoteSyncedAt != nil {
						t.Fatalf("blocked strict release should be a local failed event, got %#v", item)
					}
					if item.Metadata["blockedLocalAuditId"] != uploadedStrictEvents[0].LocalAuditID || item.Metadata["blockedEventDigest"] != uploadedStrictEvents[0].EventDigest {
						t.Fatalf("blocked strict release should reference original audit event, got %#v", item.Metadata)
					}
				}
				if tc.wantRun || (foundRuntimeAudit && foundRetryableAllowedAudit) {
					break
				}
			}
			if !foundRuntimeAudit {
				t.Fatalf("expected strict runtime audit event")
			}
			if !tc.wantRun && !foundRetryableAllowedAudit {
				t.Fatalf("expected original strict runtime audit to stay retryable")
			}
		})
	}
}

func TestStrictEnvelopeAuditAckRequiresCompleteBatchBeforeRuntimeRelease(t *testing.T) {
	tmp := t.TempDir()
	oldHome := os.Getenv("ASIRI_HOME")
	t.Cleanup(func() {
		_ = os.Setenv("ASIRI_HOME", oldHome)
	})
	if err := os.Setenv("ASIRI_HOME", tmp); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(tmp, "ran")
	uploadedStrictEvents := []runtimeAuditUploadEvent{}
	batchSizes := []int{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/session/refresh":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status":           "approved",
				"orgId":            "org_runtime",
				"workspaceSlug":    "runtime-ws",
				"userId":           "usr_owner",
				"deviceId":         "dev_remote",
				"accessToken":      "at_refreshed",
				"expiresIn":        3600,
				"refreshExpiresAt": time.Now().UTC().Add(7 * 24 * time.Hour).Format(time.RFC3339),
			})
		case "/v1/audit/batch":
			var batch runtimeAuditBatchRequest
			if err := json.NewDecoder(r.Body).Decode(&batch); err != nil {
				t.Fatal(err)
			}
			assertAuditBatchWorkspace(t, batch, "org_runtime")
			batchSizes = append(batchSizes, len(batch.Events))
			uploadedStrictEvents = append(uploadedStrictEvents, batch.Events...)
			response := runtimeAuditBatchResponse{}
			if len(batch.Events) > 0 {
				response.Acks = append(response.Acks, runtimeAuditAck{
					LocalAuditID:    batch.Events[0].LocalAuditID,
					EventDigest:     batch.Events[0].EventDigest,
					ServerEventID:   "aud_partial",
					ServerCreatedAt: time.Now().UTC().Format(time.RFC3339),
				})
			}
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(response)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	var out bytes.Buffer
	var errb bytes.Buffer
	app := New(&out, &errb)
	for _, step := range [][]string{
		{"init", "--device", "qa-laptop", "--workspace", "qa"},
		{"add", "--workspace", "qa", "app/ONE", "--value-file", testSecretFile(t, "one")},
		{"add", "--workspace", "qa", "app/TWO", "--value-file", testSecretFile(t, "two")},
		{"grant", "--workspace", "qa", "sh", "app/ONE", "--inject-only"},
		{"grant", "--workspace", "qa", "sh", "app/TWO", "--inject-only"},
	} {
		out.Reset()
		errb.Reset()
		if code := app.Run(step); code != 0 {
			t.Fatalf("%v failed with code %d stderr=%s", step, code, errb.String())
		}
	}
	st, err := store.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	device, err := st.ActiveDevice()
	if err != nil {
		t.Fatal(err)
	}
	if err := st.LinkControlPlaneForDevice(server.URL, "org_runtime", "runtime-ws", "usr_owner", "dev_remote", device.ID, "at_runtime", "rt_runtime", 3600, time.Now().UTC().Add(7*24*time.Hour).Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
	st.State.RemoteBindings["qa"] = asiri.RemoteWorkspaceBinding{WorkspaceID: "org_runtime", WorkspaceSlug: "runtime-ws", BoundAt: time.Now().UTC()}
	st.SetEnvelopeAuditModes([]asiri.ScopeAuditMode{{Path: "qa/app", ResolvedAuditMode: asiri.AuditModeStrict}})
	if err := st.Save(); err != nil {
		t.Fatal(err)
	}

	out.Reset()
	errb.Reset()
	code := app.Run([]string{"run", "--workspace", "qa", "--env", "ONE=app/ONE", "--env", "TWO=app/TWO", "--", "sh", "-c", "test \"$ONE\" = one && test \"$TWO\" = two && touch " + marker})
	if code == 0 {
		t.Fatal("strict runtime command should fail without every batch ack")
	}
	if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("strict runtime command should not have run, stat err=%v", err)
	}
	if len(batchSizes) != 1 || batchSizes[0] != 2 {
		t.Fatalf("expected one strict audit batch with two events, got %#v", batchSizes)
	}
	if len(uploadedStrictEvents) != 2 {
		t.Fatalf("expected two strict uploads, got %d", len(uploadedStrictEvents))
	}
	st, err = store.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	uploadedIDs := map[string]bool{}
	for _, event := range uploadedStrictEvents {
		uploadedIDs[event.LocalAuditID] = true
	}
	retryableAllowed := 0
	failedBlocked := 0
	for _, event := range st.State.Audit {
		if event.Action != "secret_injected" || event.Metadata["runtimeLabel"] != "sh" {
			continue
		}
		if uploadedIDs[event.ID] {
			if event.Result != "allowed" || event.RemoteSyncedAt != nil {
				t.Fatalf("partial strict batch must leave original event retryable: %#v", event)
			}
			retryableAllowed++
			continue
		}
		if event.Result == "failed" && uploadedIDs[event.Metadata["blockedLocalAuditId"]] && event.RemoteSyncedAt == nil {
			failedBlocked++
		}
	}
	if retryableAllowed != 2 || failedBlocked != 2 {
		t.Fatalf("expected two retryable originals and two failed blockers, got retryable=%d failed=%d", retryableAllowed, failedBlocked)
	}
}

func TestStrictEnvelopeAuditAckFailureDoesNotAuditBufferedPeers(t *testing.T) {
	tmp := t.TempDir()
	oldHome := os.Getenv("ASIRI_HOME")
	t.Cleanup(func() {
		_ = os.Setenv("ASIRI_HOME", oldHome)
	})
	if err := os.Setenv("ASIRI_HOME", tmp); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(tmp, "ran")
	uploadedStrictEvents := []runtimeAuditUploadEvent{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/session/refresh":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status":           "approved",
				"orgId":            "org_runtime",
				"workspaceSlug":    "runtime-ws",
				"userId":           "usr_owner",
				"deviceId":         "dev_remote",
				"accessToken":      "at_refreshed",
				"expiresIn":        3600,
				"refreshExpiresAt": time.Now().UTC().Add(7 * 24 * time.Hour).Format(time.RFC3339),
			})
		case "/v1/audit/batch":
			var batch runtimeAuditBatchRequest
			if err := json.NewDecoder(r.Body).Decode(&batch); err != nil {
				t.Fatal(err)
			}
			assertAuditBatchWorkspace(t, batch, "org_runtime")
			uploadedStrictEvents = append(uploadedStrictEvents, batch.Events...)
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(runtimeAuditBatchResponse{})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	var out bytes.Buffer
	var errb bytes.Buffer
	app := New(&out, &errb)
	for _, step := range [][]string{
		{"init", "--device", "qa-laptop", "--workspace", "qa"},
		{"add", "--workspace", "qa", "strict/ONE", "--value-file", testSecretFile(t, "one")},
		{"add", "--workspace", "qa", "buffered/TWO", "--value-file", testSecretFile(t, "two")},
		{"grant", "--workspace", "qa", "sh", "strict/ONE", "--inject-only"},
		{"grant", "--workspace", "qa", "sh", "buffered/TWO", "--inject-only"},
	} {
		out.Reset()
		errb.Reset()
		if code := app.Run(step); code != 0 {
			t.Fatalf("%v failed with code %d stderr=%s", step, code, errb.String())
		}
	}
	st, err := store.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	device, err := st.ActiveDevice()
	if err != nil {
		t.Fatal(err)
	}
	if err := st.LinkControlPlaneForDevice(server.URL, "org_runtime", "runtime-ws", "usr_owner", "dev_remote", device.ID, "at_runtime", "rt_runtime", 3600, time.Now().UTC().Add(7*24*time.Hour).Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
	st.State.RemoteBindings["qa"] = asiri.RemoteWorkspaceBinding{WorkspaceID: "org_runtime", WorkspaceSlug: "runtime-ws", BoundAt: time.Now().UTC()}
	st.SetEnvelopeAuditModes([]asiri.ScopeAuditMode{{Path: "qa/strict", ResolvedAuditMode: asiri.AuditModeStrict}})
	if err := st.Save(); err != nil {
		t.Fatal(err)
	}

	out.Reset()
	errb.Reset()
	code := app.Run([]string{"run", "--workspace", "qa", "--env", "ONE=strict/ONE", "--env", "TWO=buffered/TWO", "--", "sh", "-c", "test \"$ONE\" = one && test \"$TWO\" = two && touch " + marker})
	if code == 0 {
		t.Fatal("mixed strict runtime command should fail without strict ack")
	}
	if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("mixed strict runtime command should not have run, stat err=%v", err)
	}
	if len(uploadedStrictEvents) != 1 {
		t.Fatalf("expected one strict upload, got %d", len(uploadedStrictEvents))
	}
	st, err = store.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	for _, event := range st.State.Audit {
		if event.Action == "secret_injected" && event.Scope == "qa/buffered" && event.Result == "allowed" {
			t.Fatalf("buffered peer must not audit allowed materialization after strict ack failure: %#v", event)
		}
	}
}

func TestStrictEnvelopeAuditAckAllowsDirectHumanRead(t *testing.T) {
	tmp := t.TempDir()
	oldHome := os.Getenv("ASIRI_HOME")
	t.Cleanup(func() {
		_ = os.Setenv("ASIRI_HOME", oldHome)
	})
	if err := os.Setenv("ASIRI_HOME", tmp); err != nil {
		t.Fatal(err)
	}
	var refreshes atomic.Int32
	var switchCalls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/session/refresh":
			refreshes.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status":           "approved",
				"orgId":            "org_other",
				"workspaceSlug":    "other-ws",
				"userId":           "usr_owner",
				"deviceId":         "dev_other",
				"accessToken":      "at_other_refreshed",
				"expiresIn":        3600,
				"refreshExpiresAt": time.Now().UTC().Add(7 * 24 * time.Hour).Format(time.RFC3339),
			})
		case "/v1/auth/session/switch":
			switchCalls.Add(1)
			http.Error(w, "strict audit ack must not switch workspace", http.StatusInternalServerError)
		case "/v1/audit/batch":
			if r.Header.Get("authorization") != "Bearer at_other_refreshed" {
				http.Error(w, "expected refreshed access token", http.StatusUnauthorized)
				return
			}
			var batch runtimeAuditBatchRequest
			if err := json.NewDecoder(r.Body).Decode(&batch); err != nil {
				t.Fatal(err)
			}
			assertAuditBatchWorkspace(t, batch, "org_runtime")
			response := runtimeAuditBatchResponse{}
			for index, event := range batch.Events {
				if event.OrgID != "org_runtime" {
					t.Fatalf("strict human read uploaded to wrong workspace: %#v", event)
				}
				if event.Metadata["runtimeLabel"] == "" || event.Metadata["runtimeLabelType"] != "user" || event.Metadata["workspaceId"] != "org_runtime" {
					t.Fatalf("strict human read metadata missing: %#v", event.Metadata)
				}
				response.Acks = append(response.Acks, runtimeAuditAck{
					LocalAuditID:    event.LocalAuditID,
					EventDigest:     event.EventDigest,
					ServerEventID:   fmt.Sprintf("aud_human_%d", index),
					ServerCreatedAt: time.Now().UTC().Format(time.RFC3339),
				})
			}
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(response)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	var out bytes.Buffer
	var errb bytes.Buffer
	app := New(&out, &errb)
	for _, step := range [][]string{
		{"init", "--device", "qa-laptop", "--workspace", "qa"},
		{"add", "--workspace", "qa", "cloudflare/API_KEY", "--value-file", testSecretFile(t, "human_secret")},
	} {
		out.Reset()
		errb.Reset()
		if code := app.Run(step); code != 0 {
			t.Fatalf("%v failed with code %d stderr=%s", step, code, errb.String())
		}
	}
	st, err := store.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	device, err := st.ActiveDevice()
	if err != nil {
		t.Fatal(err)
	}
	if err := st.LinkControlPlaneForDevice(server.URL, "org_other", "other-ws", "usr_owner", "dev_other", device.ID, "at_other", "rt_other", 3600, time.Now().UTC().Add(7*24*time.Hour).Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
	st.State.ControlPlane.AccessTokenExpiresAt = time.Now().UTC().Add(10 * time.Second)
	st.State.RemoteBindings["qa"] = asiri.RemoteWorkspaceBinding{WorkspaceID: "org_runtime", WorkspaceSlug: "runtime-ws", BoundAt: time.Now().UTC()}
	st.SetEnvelopeAuditModes([]asiri.ScopeAuditMode{{Path: "qa/cloudflare", ResolvedAuditMode: asiri.AuditModeStrict}})
	if err := st.Save(); err != nil {
		t.Fatal(err)
	}

	out.Reset()
	errb.Reset()
	if code := app.Run([]string{"get", "--workspace", "qa", "cloudflare/API_KEY"}); code != 0 {
		t.Fatalf("strict human read failed: %s", errb.String())
	}
	if strings.TrimSpace(out.String()) != "human_secret" {
		t.Fatalf("strict human read returned unexpected value: %q", out.String())
	}
	if refreshes.Load() == 0 {
		t.Fatal("expected strict human read to refresh stale access token")
	}
	if switchCalls.Load() != 0 {
		t.Fatal("strict human read should not switch the active control-plane workspace")
	}
}

func TestPendingRuntimeAuditEventsStayInOriginalWorkspace(t *testing.T) {
	createdAt := time.Now().UTC()
	st := &store.FileStore{State: asiri.State{
		ControlPlane: &asiri.ControlPlaneLink{
			WorkspaceID:   "org_two",
			WorkspaceSlug: "two",
		},
		RemoteBindings: map[string]asiri.RemoteWorkspaceBinding{
			"one": {WorkspaceID: "org_one", WorkspaceSlug: "one", BoundAt: createdAt},
		},
	}}
	metadata := runtimeAuditMetadata(st, "one/cloudflare", "wrangler", "process", nil)
	if metadata["workspaceId"] != "org_one" || metadata["workspaceSlug"] != "one" {
		t.Fatalf("runtime audit metadata should use bound scope workspace: %#v", metadata)
	}
	st.State.Audit = []asiri.AuditEvent{
		{
			ID:             "aud_one",
			Actor:          "wrangler",
			Action:         "secret_injected",
			Result:         "allowed",
			Scope:          "one/cloudflare",
			SecretNameHash: "hash_one",
			Reason:         "explicit env mapping",
			Metadata:       metadata,
			CreatedAt:      createdAt,
		},
		{
			ID:             "aud_legacy",
			Actor:          "wrangler",
			Action:         "secret_injected",
			Result:         "allowed",
			Scope:          "one/cloudflare",
			SecretNameHash: "hash_legacy",
			Reason:         "explicit env mapping",
			Metadata: map[string]string{
				"runtimeLabel":     "wrangler",
				"runtimeLabelType": "process",
			},
			CreatedAt: createdAt,
		},
	}

	ids, events := pendingRuntimeAuditEvents(st)
	if len(ids) != 1 || ids[0] != "aud_one" || len(events) != 1 {
		t.Fatalf("expected explicitly attributed target workspace event to upload: ids=%#v events=%#v", ids, events)
	}
	if events[0].OrgID != "org_one" || events[0].Metadata["workspaceId"] != "org_one" || events[0].Metadata["workspaceSlug"] != "one" {
		t.Fatalf("uploaded event should keep target workspace attribution: %#v", events[0])
	}

	st.State.ControlPlane.WorkspaceID = "org_one"
	st.State.ControlPlane.WorkspaceSlug = "one"
	ids, events = pendingRuntimeAuditEvents(st)
	if len(ids) != 1 || ids[0] != "aud_one" || len(events) != 1 {
		t.Fatalf("expected only explicitly attributed target workspace event to remain uploadable: ids=%#v events=%#v", ids, events)
	}
	if events[0].OrgID != "org_one" || events[0].Metadata["workspaceId"] != "org_one" || events[0].Metadata["workspaceSlug"] != "one" {
		t.Fatalf("uploaded event should keep original workspace attribution: %#v", events[0])
	}
}

func TestPendingRuntimeAuditEventsIncludeBrokerLifecycle(t *testing.T) {
	createdAt := time.Now().UTC()
	st := &store.FileStore{State: asiri.State{
		ControlPlane: &asiri.ControlPlaneLink{
			WorkspaceID:   "org_runtime",
			WorkspaceSlug: "qa",
		},
		RemoteBindings: map[string]asiri.RemoteWorkspaceBinding{
			"qa": {WorkspaceID: "org_runtime", WorkspaceSlug: "qa", BoundAt: createdAt},
		},
	}}
	st.State.Audit = []asiri.AuditEvent{
		{
			ID:        "aud_broker_started",
			Actor:     "codex",
			Action:    "broker_started",
			Result:    "allowed",
			Reason:    "local broker started",
			Metadata:  brokerRuntimeAuditMetadata(st, "qa", "codex", "agent", "", nil),
			CreatedAt: createdAt,
		},
		{
			ID:        "aud_broker_stopped",
			Actor:     "codex",
			Action:    "broker_stopped",
			Result:    "allowed",
			Reason:    "local broker stopped",
			Metadata:  brokerRuntimeAuditMetadata(st, "qa", "codex", "agent", "", nil),
			CreatedAt: createdAt,
		},
	}

	ids, events := pendingRuntimeAuditEvents(st)
	if len(ids) != 2 || len(events) != 2 {
		t.Fatalf("expected broker lifecycle audit events to upload: ids=%#v events=%#v", ids, events)
	}
	if events[0].Action != "broker_started" || events[1].Action != "broker_stopped" {
		t.Fatalf("unexpected broker lifecycle actions: %#v", events)
	}
	for _, event := range events {
		if event.OrgID != "org_runtime" || event.Metadata["workspaceId"] != "org_runtime" || event.Metadata["workspaceSlug"] != "qa" {
			t.Fatalf("broker lifecycle event missing workspace attribution: %#v", event)
		}
	}
}
