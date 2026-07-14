package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/o-clan/asiri/cli/internal/asiri"
	"github.com/o-clan/asiri/cli/internal/store"
)

func TestRecoverySetupShowsKeyOnceAndWrapsRemoteSecrets(t *testing.T) {
	tmp := t.TempDir()
	old := os.Getenv("ASIRI_HOME")
	t.Cleanup(func() { _ = os.Setenv("ASIRI_HOME", old) })
	if err := os.Setenv("ASIRI_HOME", tmp); err != nil {
		t.Fatal(err)
	}
	secretPushSeen := false
	recoveryCreateSeen := false
	var recoveryCreateBody map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		switch r.URL.Path {
		case "/v1/auth/device-code/start":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"deviceCode":              "dc_recovery",
				"userCode":                "RECV-1234",
				"verificationUriComplete": serverURL(r) + "/auth/device?code=RECV-1234",
				"expiresIn":               30,
				"interval":                0,
			})
		case "/v1/auth/device-code/token":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status":           "approved",
				"orgId":            "org_recovery",
				"workspaceSlug":    "oclan-co",
				"userId":           "usr_owner",
				"deviceId":         "dev_recovery",
				"accessToken":      "at_recovery",
				"refreshToken":     "rt_recovery",
				"expiresIn":        3600,
				"refreshExpiresAt": time.Now().UTC().Add(7 * 24 * time.Hour).Format(time.RFC3339),
			})
		case "/v1/orgs":
			assertWorkspaceOverviewTarget(t, r, "oclan-co")
			_ = json.NewEncoder(w).Encode(map[string]any{"organizations": []map[string]any{{
				"id": "org_recovery", "slug": "oclan-co", "role": "owner", "canPull": true, "canWrite": true, "currentDeviceTrusted": true, "currentDeviceId": "dev_recovery",
			}}})
		case "/v1/sync/write-options":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"requestedWorkspaceSlug": "oclan-co",
				"workspace": map[string]any{
					"id":       "org_recovery",
					"slug":     "oclan-co",
					"canWrite": true,
					"paths": []map[string]any{{
						"fullPath": "oclan-co/local/asiri/API_KEY",
						"canWrite": true,
					}},
				},
			})
		case "/v1/secrets":
			if r.Method == http.MethodPost {
				secretPushSeen = true
				var body map[string]any
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					t.Fatal(err)
				}
				wrapped, ok := body["wrappedKeys"].([]any)
				if !ok || len(wrapped) != 1 {
					t.Fatalf("initial push should contain only the device wrapped key: %#v", body["wrappedKeys"])
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"id": "secv_recovery", "status": "active"})
				return
			}
			if r.Method != http.MethodGet {
				http.NotFound(w, r)
				return
			}
			if r.URL.Query().Get("orgId") != "org_recovery" {
				t.Fatalf("unexpected secrets query: %s", r.URL.RawQuery)
			}
			if !secretPushSeen {
				_ = json.NewEncoder(w).Encode(map[string]any{"secrets": []map[string]any{}})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"secrets": []map[string]any{{
					"id":      "secv_recovery",
					"orgId":   "org_recovery",
					"scope":   "oclan-co/local/asiri",
					"name":    "API_KEY",
					"version": 1,
					"status":  "active",
					"wrappedKeys": []map[string]any{{
						"recipientType": "device",
						"recipientId":   "dev_recovery",
						"wrapAlgorithm": "p256-hkdf-aes256gcm",
						"wrappedKey":    "wrapped",
					}},
				}},
			})
		case "/v1/secrets/encrypted":
			if r.Method != http.MethodGet {
				http.NotFound(w, r)
				return
			}
			if r.URL.Query().Get("orgId") != "org_recovery" {
				t.Fatalf("unexpected secrets query: %s", r.URL.RawQuery)
			}
			if !secretPushSeen {
				_ = json.NewEncoder(w).Encode(map[string]any{"secrets": []map[string]any{}})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"secrets": []map[string]any{{
					"id":      "secv_recovery",
					"orgId":   "org_recovery",
					"scope":   "oclan-co/local/asiri",
					"name":    "API_KEY",
					"version": 1,
					"status":  "active",
					"wrappedKeys": []map[string]any{{
						"recipientType": "device",
						"recipientId":   "dev_recovery",
						"wrapAlgorithm": "p256-hkdf-aes256gcm",
						"wrappedKey":    "wrapped",
					}},
				}},
			})
		case "/v1/recovery-recipient":
			recoveryCreateSeen = true
			if r.Method != http.MethodPost {
				http.NotFound(w, r)
				return
			}
			if r.Header.Get("authorization") != "Bearer at_recovery" {
				t.Fatalf("unexpected recovery recipient auth header: %s", r.Header.Get("authorization"))
			}
			if err := json.NewDecoder(r.Body).Decode(&recoveryCreateBody); err != nil {
				t.Fatal(err)
			}
			recipientID, _ := recoveryCreateBody["recipientId"].(string)
			publicKey, _ := recoveryCreateBody["publicKey"].(string)
			fingerprint, _ := recoveryCreateBody["publicKeyFingerprint"].(string)
			if recoveryCreateBody["orgId"] != "org_recovery" || !strings.HasPrefix(recipientID, "rec_") || publicKey == "" || fingerprint == "" {
				t.Fatalf("unexpected recovery recipient registration body: %#v", recoveryCreateBody)
			}
			if _, ok := recoveryCreateBody["key"]; ok {
				t.Fatalf("registration body should not include raw key: %#v", recoveryCreateBody)
			}
			replacements, ok := recoveryCreateBody["replacements"].([]any)
			if !ok || len(replacements) != 1 {
				t.Fatalf("expected one recovery replacement: %#v", recoveryCreateBody["replacements"])
			}
			replacement, _ := replacements[0].(map[string]any)
			wrapped, _ := replacement["wrappedKey"].(map[string]any)
			if wrapped["recipientType"] != "recovery" || wrapped["wrapAlgorithm"] != "recovery-hkdf-aes256gcm" || !strings.HasPrefix(fmt.Sprint(wrapped["recipientId"]), "rec_") {
				t.Fatalf("unexpected recovery wrapped key: %#v", wrapped)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"recipientId":          recoveryCreateBody["recipientId"],
				"publicKeyFingerprint": recoveryCreateBody["publicKeyFingerprint"],
				"status":               "active",
			})
		case "/v1/devices":
			_ = json.NewEncoder(w).Encode(map[string]any{"devices": []map[string]any{}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	var out bytes.Buffer
	var errb bytes.Buffer
	app := New(&out, &errb)
	for _, step := range [][]string{
		{"init", "--device", "qa-laptop"},
		{"add", "--workspace", "oclan-co", "local/asiri/API_KEY", "--value-file", testSecretFile(t, "secret_value")},
		{"login", "--origin", server.URL},
		{"push", "--workspace", "oclan-co"},
	} {
		out.Reset()
		errb.Reset()
		if code := app.Run(step); code != 0 {
			t.Fatalf("%v failed with code %d stderr=%s", step, code, errb.String())
		}
	}
	out.Reset()
	errb.Reset()
	recoveryKeyPath := filepath.Join(tmp, "recovery.key")
	if code := app.Run([]string{"recovery", "setup", "--workspace", "oclan-co", "--output-file", recoveryKeyPath}); code != 0 {
		t.Fatalf("recovery setup failed: %s", errb.String())
	}
	if !secretPushSeen || !recoveryCreateSeen {
		t.Fatal("expected push and recovery create endpoints")
	}
	all := out.String()
	if !strings.Contains(all, "Recovery key written") || !strings.Contains(all, "Added recovery wrapping to 1 remote secret") {
		t.Fatalf("recovery output missing expected copy or wrapping result: %s", all)
	}
	keyBytes, err := os.ReadFile(recoveryKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	recoveryKey := strings.TrimSpace(string(keyBytes))
	if recoveryKey == "" {
		t.Fatalf("recovery setup did not write a recovery key: %s", all)
	}
	if strings.Contains(all, recoveryKey) {
		t.Fatal("recovery setup printed raw recovery key")
	}
	if strings.Contains(fmt.Sprint(recoveryCreateBody), recoveryKey) {
		t.Fatal("recovery registration sent raw recovery key")
	}
	bytes, err := os.ReadFile(filepath.Join(tmp, "local-state.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(bytes), recoveryKey) {
		t.Fatal("local state persisted raw recovery key")
	}
}

func TestRecoverySetupFreshLinkedWorkspaceSendsEmptyReplacements(t *testing.T) {
	tmp := t.TempDir()
	old := os.Getenv("ASIRI_HOME")
	t.Cleanup(func() { _ = os.Setenv("ASIRI_HOME", old) })
	if err := os.Setenv("ASIRI_HOME", tmp); err != nil {
		t.Fatal(err)
	}
	recoveryCreateSeen := false
	remoteSecretListSeen := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		switch r.URL.Path {
		case "/v1/auth/device-code/start":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"deviceCode":              "dc_empty_recovery",
				"userCode":                "RNEW-1234",
				"verificationUriComplete": serverURL(r) + "/auth/device?code=RNEW-1234",
				"expiresIn":               30,
				"interval":                0,
			})
		case "/v1/auth/device-code/token":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status":           "approved",
				"orgId":            "org_empty_recovery",
				"workspaceSlug":    "oclan-co",
				"userId":           "usr_owner",
				"deviceId":         "dev_empty_recovery",
				"accessToken":      "at_empty_recovery",
				"refreshToken":     "rt_empty_recovery",
				"expiresIn":        3600,
				"refreshExpiresAt": time.Now().UTC().Add(7 * 24 * time.Hour).Format(time.RFC3339),
			})
		case "/v1/orgs":
			assertWorkspaceOverviewTarget(t, r, "oclan-co")
			_ = json.NewEncoder(w).Encode(map[string]any{"organizations": []map[string]any{{
				"id": "org_empty_recovery", "slug": "oclan-co", "role": "owner", "canPull": true, "canWrite": true, "currentDeviceTrusted": true, "currentDeviceId": "dev_empty_recovery",
			}}})
		case "/v1/secrets/encrypted":
			remoteSecretListSeen = true
			_ = json.NewEncoder(w).Encode(map[string]any{"secrets": []map[string]any{}})
		case "/v1/recovery-recipient":
			if r.Method == http.MethodGet {
				http.NotFound(w, r)
				return
			}
			if r.Method != http.MethodPost {
				http.NotFound(w, r)
				return
			}
			recoveryCreateSeen = true
			if r.Header.Get("authorization") != "Bearer at_empty_recovery" {
				t.Fatalf("unexpected recovery recipient auth header: %s", r.Header.Get("authorization"))
			}
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			replacements, ok := body["replacements"].([]any)
			if !ok || len(replacements) != 0 {
				t.Fatalf("fresh workspace should send empty recovery replacements array: %#v", body["replacements"])
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"recipientId":          body["recipientId"],
				"publicKeyFingerprint": body["publicKeyFingerprint"],
				"status":               "active",
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	var out bytes.Buffer
	var errb bytes.Buffer
	app := New(&out, &errb)
	for _, step := range [][]string{
		{"init", "--device", "qa-laptop"},
		{"login", "--origin", server.URL},
	} {
		out.Reset()
		errb.Reset()
		if code := app.Run(step); code != 0 {
			t.Fatalf("%v failed with code %d stderr=%s", step, code, errb.String())
		}
	}
	staleStore, err := store.Load(filepath.Join(tmp, "local-state.json"))
	if err != nil {
		t.Fatal(err)
	}
	staleSetup, err := staleStore.SetupRecovery(staleStore.State.ControlPlane.WorkspaceID, staleStore.State.ControlPlane.WorkspaceSlug, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := staleStore.Save(); err != nil {
		t.Fatal(err)
	}
	recoveryKeyPath := filepath.Join(tmp, "recovery.key")
	out.Reset()
	errb.Reset()
	if code := app.Run([]string{"recovery", "setup", "--workspace", "oclan-co", "--output-file", recoveryKeyPath}); code != 0 {
		t.Fatalf("fresh workspace recovery setup failed: %s", errb.String())
	}
	if !recoveryCreateSeen {
		t.Fatal("expected recovery create endpoint")
	}
	if remoteSecretListSeen {
		t.Fatal("fresh workspace without a remote binding should not list remote secrets")
	}
	if keyBytes, err := os.ReadFile(recoveryKeyPath); err != nil {
		t.Fatal(err)
	} else if strings.TrimSpace(string(keyBytes)) == "" {
		t.Fatal("recovery setup should write the recovery key")
	}
	st, err := store.Load(filepath.Join(tmp, "local-state.json"))
	if err != nil {
		t.Fatal(err)
	}
	if recovery := st.RecoveryForWorkspace(st.State.ControlPlane.WorkspaceID); recovery == nil {
		t.Fatal("fresh workspace recovery setup should commit local recovery metadata")
	} else if recovery.RecipientID == staleSetup.RecipientID {
		t.Fatal("fresh workspace recovery setup should replace stale local recovery metadata after server success")
	}
}

func TestRecoveryStatusPreservesSameRecipientLocalWrappingCounters(t *testing.T) {
	tmp := t.TempDir()
	old := os.Getenv("ASIRI_HOME")
	t.Cleanup(func() { _ = os.Setenv("ASIRI_HOME", old) })
	if err := os.Setenv("ASIRI_HOME", tmp); err != nil {
		t.Fatal(err)
	}
	var activeRecovery *asiri.RecoveryConfig
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		switch r.URL.Path {
		case "/v1/auth/device-code/start":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"deviceCode":              "dc_status_recovery",
				"userCode":                "RSTS-1234",
				"verificationUriComplete": serverURL(r) + "/auth/device?code=RSTS-1234",
				"expiresIn":               30,
				"interval":                0,
			})
		case "/v1/auth/device-code/token":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status":           "approved",
				"orgId":            "org_status_recovery",
				"workspaceSlug":    "oclan-co",
				"userId":           "usr_owner",
				"deviceId":         "dev_status_recovery",
				"accessToken":      "at_status_recovery",
				"refreshToken":     "rt_status_recovery",
				"expiresIn":        3600,
				"refreshExpiresAt": time.Now().UTC().Add(7 * 24 * time.Hour).Format(time.RFC3339),
			})
		case "/v1/orgs":
			assertWorkspaceOverviewTarget(t, r, "oclan-co")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"activeOrgId": "org_status_recovery",
				"organizations": []map[string]any{
					{"id": "org_status_recovery", "name": "O Clan", "slug": "oclan-co", "ownerUserId": "usr_owner", "role": "owner", "canPull": true, "canWrite": true, "currentDeviceTrusted": true, "currentDeviceId": "dev_status_recovery"},
				},
			})
		case "/v1/recovery-recipient":
			if r.Method != http.MethodGet {
				http.NotFound(w, r)
				return
			}
			if r.Header.Get("authorization") != "Bearer at_status_recovery" {
				t.Fatalf("unexpected recovery status auth header: %s", r.Header.Get("authorization"))
			}
			if activeRecovery == nil {
				http.NotFound(w, r)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"recipientId":          activeRecovery.RecipientID,
				"publicKey":            activeRecovery.PublicKey,
				"publicKeyFingerprint": activeRecovery.PublicKeyFingerprint,
				"status":               "active",
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	var out bytes.Buffer
	var errb bytes.Buffer
	app := New(&out, &errb)
	for _, step := range [][]string{
		{"init", "--device", "qa-laptop"},
		{"login", "--origin", server.URL},
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
	if _, err := st.SetupRecovery(st.State.ControlPlane.WorkspaceID, st.State.ControlPlane.WorkspaceSlug, false); err != nil {
		t.Fatal(err)
	}
	if err := st.Save(); err != nil {
		t.Fatal(err)
	}
	if err := st.MarkRecoveryWrapped(st.State.ControlPlane.WorkspaceID, "oclan-co", 3); err != nil {
		t.Fatal(err)
	}
	recovery := st.RecoveryForWorkspace(st.State.ControlPlane.WorkspaceID)
	if recovery == nil {
		t.Fatal("expected local recovery metadata")
	}
	activeRecovery = recovery

	out.Reset()
	errb.Reset()
	if code := app.Run([]string{"recovery", "status", "--workspace", "oclan-co"}); code != 0 {
		t.Fatalf("recovery status failed: %s", errb.String())
	}
	statusFields := strings.Fields(out.String())
	if !strings.Contains(out.String(), "oclan-co") || !strings.Contains(out.String(), "configured") || !containsString(statusFields, "3") {
		t.Fatalf("recovery status should preserve local wrapping count, got: %s", out.String())
	}
	reloaded, err := store.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	if count := reloaded.RecoveryWrappedCount("org_status_recovery"); count != 3 {
		t.Fatalf("recovery status should persist local wrapping count, got %d", count)
	}
}

func TestTargetedPushPreservesRecoveryWrappedCount(t *testing.T) {
	tmp := t.TempDir()
	old := os.Getenv("ASIRI_HOME")
	t.Cleanup(func() { _ = os.Setenv("ASIRI_HOME", old) })
	if err := os.Setenv("ASIRI_HOME", tmp); err != nil {
		t.Fatal(err)
	}
	var activeRecovery *asiri.RecoveryConfig
	pushSeen := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		switch r.URL.Path {
		case "/v1/auth/device-code/start":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"deviceCode":              "dc_targeted_push",
				"userCode":                "TPUS-1234",
				"verificationUriComplete": serverURL(r) + "/auth/device?code=TPUS-1234",
				"expiresIn":               30,
				"interval":                0,
			})
		case "/v1/auth/device-code/token":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status":           "approved",
				"orgId":            "org_targeted_push",
				"workspaceSlug":    "oclan-co",
				"userId":           "usr_owner",
				"deviceId":         "dev_targeted_push",
				"accessToken":      "at_targeted_push",
				"refreshToken":     "rt_targeted_push",
				"expiresIn":        3600,
				"refreshExpiresAt": time.Now().UTC().Add(7 * 24 * time.Hour).Format(time.RFC3339),
			})
		case "/v1/orgs":
			assertWorkspaceOverviewTarget(t, r, "oclan-co")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"activeOrgId": "org_targeted_push",
				"organizations": []map[string]any{
					{"id": "org_targeted_push", "name": "O Clan", "slug": "oclan-co", "ownerUserId": "usr_owner", "role": "owner", "canPull": true, "canWrite": true, "currentDeviceTrusted": true, "currentDeviceId": "dev_targeted_push"},
				},
			})
		case "/v1/sync/write-options":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"requestedWorkspaceSlug": "oclan-co",
				"workspace": map[string]any{
					"id":       "org_targeted_push",
					"slug":     "oclan-co",
					"canWrite": true,
					"paths": []map[string]any{{
						"fullPath": "oclan-co/local/asiri/API_KEY",
						"canWrite": true,
					}},
				},
			})
		case "/v1/recovery-recipient":
			if activeRecovery == nil {
				http.NotFound(w, r)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"recipientId":          activeRecovery.RecipientID,
				"publicKey":            activeRecovery.PublicKey,
				"publicKeyFingerprint": activeRecovery.PublicKeyFingerprint,
				"status":               "active",
			})
		case "/v1/devices":
			_ = json.NewEncoder(w).Encode(map[string]any{"devices": []map[string]any{}})
		case "/v1/secrets/encrypted":
			if activeRecovery == nil || r.URL.Query().Get("recoveryRecipientId") != activeRecovery.RecipientID {
				t.Fatalf("targeted push should request recovery-wrapped remote state, got query %s", r.URL.RawQuery)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"secrets": []map[string]any{}})
		case "/v1/secrets":
			if r.Method != http.MethodPost {
				http.NotFound(w, r)
				return
			}
			pushSeen++
			_ = json.NewEncoder(w).Encode(map[string]any{"id": "secv_targeted_push", "status": "active"})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	var out bytes.Buffer
	var errb bytes.Buffer
	app := New(&out, &errb)
	for _, step := range [][]string{
		{"init", "--device", "qa-laptop"},
		{"add", "--workspace", "oclan-co", "local/asiri/API_KEY", "--value-file", testSecretFile(t, "secret_value")},
		{"add", "--workspace", "oclan-co", "prod/asiri/OTHER_KEY", "--value-file", testSecretFile(t, "other_value")},
		{"login", "--origin", server.URL},
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
	if _, err := st.SetupRecovery(st.State.ControlPlane.WorkspaceID, st.State.ControlPlane.WorkspaceSlug, false); err != nil {
		t.Fatal(err)
	}
	if err := st.Save(); err != nil {
		t.Fatal(err)
	}
	if err := st.MarkRecoveryWrapped(st.State.ControlPlane.WorkspaceID, "oclan-co", 3); err != nil {
		t.Fatal(err)
	}
	activeRecovery = st.RecoveryForWorkspace(st.State.ControlPlane.WorkspaceID)
	out.Reset()
	errb.Reset()
	if code := app.Run([]string{"push", "--workspace", "oclan-co", "--secret", "local/asiri/API_KEY"}); code != 0 {
		t.Fatalf("targeted push failed: %s", errb.String())
	}
	if pushSeen == 0 {
		t.Fatal("expected targeted push to upload selected secret")
	}
	reloaded, err := store.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	if count := reloaded.RecoveryWrappedCount("org_targeted_push"); count != 3 {
		t.Fatalf("targeted push should preserve existing recovery wrapped count, got %d", count)
	}
	resetRecovery := reloaded.State.Recoveries["org_targeted_push"]
	resetRecovery.WrappedSecretCount = 0
	resetRecovery.LastWrappedAt = time.Time{}
	reloaded.State.Recoveries["org_targeted_push"] = resetRecovery
	if err := reloaded.Save(); err != nil {
		t.Fatal(err)
	}
	activeRecovery = &resetRecovery
	out.Reset()
	errb.Reset()
	if code := app.Run([]string{"push", "--workspace", "oclan-co", "--secret", "prod/asiri/OTHER_KEY"}); code != 0 {
		t.Fatalf("first targeted push failed: %s", errb.String())
	}
	reloaded, err = store.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	if count := reloaded.RecoveryWrappedCount("org_targeted_push"); count != 1 {
		t.Fatalf("first targeted push should record selected recovery wrapped count, got %d", count)
	}
}

func TestRecoverySetupSkipsWrappingWhenRemoteRegistrationFails(t *testing.T) {
	tmp := t.TempDir()
	old := os.Getenv("ASIRI_HOME")
	t.Cleanup(func() { _ = os.Setenv("ASIRI_HOME", old) })
	if err := os.Setenv("ASIRI_HOME", tmp); err != nil {
		t.Fatal(err)
	}
	recoveryCreateSeen := false
	var pushedSecret map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		switch r.URL.Path {
		case "/v1/auth/device-code/start":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"deviceCode":              "dc_recovery_registration_fail",
				"userCode":                "RFAIL-1234",
				"verificationUriComplete": serverURL(r) + "/auth/device?code=RFAIL-1234",
				"expiresIn":               30,
				"interval":                0,
			})
		case "/v1/auth/device-code/token":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status":           "approved",
				"orgId":            "org_recovery",
				"workspaceSlug":    "oclan-co",
				"userId":           "usr_owner",
				"deviceId":         "dev_recovery",
				"accessToken":      "at_recovery",
				"refreshToken":     "rt_recovery",
				"expiresIn":        3600,
				"refreshExpiresAt": time.Now().UTC().Add(7 * 24 * time.Hour).Format(time.RFC3339),
			})
		case "/v1/orgs":
			assertWorkspaceOverviewTarget(t, r, "oclan-co")
			_ = json.NewEncoder(w).Encode(map[string]any{"organizations": []map[string]any{{
				"id": "org_recovery", "slug": "oclan-co", "role": "owner", "canPull": true, "canWrite": true, "currentDeviceTrusted": true, "currentDeviceId": "dev_recovery",
			}}})
		case "/v1/sync/write-options":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"requestedWorkspaceSlug": "oclan-co",
				"workspace": map[string]any{
					"id":       "org_recovery",
					"slug":     "oclan-co",
					"canWrite": true,
					"paths": []map[string]any{{
						"fullPath": "oclan-co/local/asiri/API_KEY",
						"canWrite": true,
					}},
				},
			})
		case "/v1/secrets":
			if r.Method == http.MethodPost {
				if err := json.NewDecoder(r.Body).Decode(&pushedSecret); err != nil {
					t.Fatal(err)
				}
				pushedSecret["id"] = "secv_recovery"
				pushedSecret["status"] = "active"
				_ = json.NewEncoder(w).Encode(map[string]any{"id": "secv_recovery", "status": "active"})
				return
			}
			http.NotFound(w, r)
		case "/v1/secrets/encrypted":
			if pushedSecret == nil {
				_ = json.NewEncoder(w).Encode(map[string]any{"secrets": []map[string]any{}})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"secrets": []map[string]any{pushedSecret}})
		case "/v1/devices":
			_ = json.NewEncoder(w).Encode(map[string]any{"devices": []map[string]any{}})
		case "/v1/recovery-recipient":
			if r.Method == http.MethodGet {
				http.NotFound(w, r)
				return
			}
			if r.Method != http.MethodPost {
				http.NotFound(w, r)
				return
			}
			recoveryCreateSeen = true
			http.Error(w, `{"error":"owner required"}`, http.StatusForbidden)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	var out bytes.Buffer
	var errb bytes.Buffer
	app := New(&out, &errb)
	for _, step := range [][]string{
		{"init", "--device", "qa-laptop"},
		{"add", "--workspace", "oclan-co", "local/asiri/API_KEY", "--value-file", testSecretFile(t, "secret_value")},
		{"login", "--origin", server.URL},
		{"push", "--workspace", "oclan-co"},
	} {
		out.Reset()
		errb.Reset()
		if code := app.Run(step); code != 0 {
			t.Fatalf("%v failed with code %d stderr=%s", step, code, errb.String())
		}
	}
	out.Reset()
	errb.Reset()
	recoveryKeyPath := filepath.Join(tmp, "recovery.key")
	if code := app.Run([]string{"recovery", "setup", "--workspace", "oclan-co", "--output-file", recoveryKeyPath}); code == 0 {
		t.Fatal("recovery setup should fail when remote registration fails")
	}
	if !recoveryCreateSeen {
		t.Fatal("expected recovery registration endpoint")
	}
	if !strings.Contains(errb.String(), "recovery key delivered, but remote registration failed") {
		t.Fatalf("expected registration failure warning, got %s", errb.String())
	}
	if keyBytes, err := os.ReadFile(recoveryKeyPath); err != nil {
		t.Fatal(err)
	} else if strings.TrimSpace(string(keyBytes)) == "" {
		t.Fatal("recovery key should remain available after delivery")
	}
	st, err := store.Load(filepath.Join(tmp, "local-state.json"))
	if err != nil {
		t.Fatal(err)
	}
	if st.RecoveryForWorkspace(st.State.ControlPlane.WorkspaceID) != nil {
		t.Fatalf("local recovery config should not be active after remote registration failure: %#v", st.State.Recoveries)
	}
}

func TestRecoverySetupFailsWhenRemoteReplacementFails(t *testing.T) {
	tmp := t.TempDir()
	old := os.Getenv("ASIRI_HOME")
	t.Cleanup(func() { _ = os.Setenv("ASIRI_HOME", old) })
	if err := os.Setenv("ASIRI_HOME", tmp); err != nil {
		t.Fatal(err)
	}
	recoveryReplaceSeen := false
	remoteRecoveryActive := false
	var pushedSecret map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		switch r.URL.Path {
		case "/v1/auth/device-code/start":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"deviceCode":              "dc_recovery_wrap_fail",
				"userCode":                "RWFL-1234",
				"verificationUriComplete": serverURL(r) + "/auth/device?code=RWFL-1234",
				"expiresIn":               30,
				"interval":                0,
			})
		case "/v1/auth/device-code/token":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status":           "approved",
				"orgId":            "org_recovery",
				"workspaceSlug":    "oclan-co",
				"userId":           "usr_owner",
				"deviceId":         "dev_recovery",
				"accessToken":      "at_recovery",
				"refreshToken":     "rt_recovery",
				"expiresIn":        3600,
				"refreshExpiresAt": time.Now().UTC().Add(7 * 24 * time.Hour).Format(time.RFC3339),
			})
		case "/v1/orgs":
			assertWorkspaceOverviewTarget(t, r, "oclan-co")
			_ = json.NewEncoder(w).Encode(map[string]any{"organizations": []map[string]any{{
				"id": "org_recovery", "slug": "oclan-co", "role": "owner", "canPull": true, "canWrite": true, "currentDeviceTrusted": true, "currentDeviceId": "dev_recovery",
			}}})
		case "/v1/sync/write-options":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"requestedWorkspaceSlug": "oclan-co",
				"workspace": map[string]any{
					"id":       "org_recovery",
					"slug":     "oclan-co",
					"canWrite": true,
					"paths": []map[string]any{{
						"fullPath": "oclan-co/local/asiri/API_KEY",
						"canWrite": true,
					}},
				},
			})
		case "/v1/secrets":
			if r.Method == http.MethodPost {
				if err := json.NewDecoder(r.Body).Decode(&pushedSecret); err != nil {
					t.Fatal(err)
				}
				pushedSecret["id"] = "secv_recovery"
				pushedSecret["status"] = "active"
				_ = json.NewEncoder(w).Encode(map[string]any{"id": "secv_recovery", "status": "active"})
				return
			}
			http.NotFound(w, r)
		case "/v1/secrets/encrypted":
			if pushedSecret == nil {
				_ = json.NewEncoder(w).Encode(map[string]any{"secrets": []map[string]any{}})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"secrets": []map[string]any{pushedSecret}})
		case "/v1/devices":
			_ = json.NewEncoder(w).Encode(map[string]any{"devices": []map[string]any{}})
		case "/v1/recovery-recipient":
			if r.Method != http.MethodGet || !remoteRecoveryActive {
				http.NotFound(w, r)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"recipientId":          "rec_existing",
				"publicKey":            "remote-public-key",
				"publicKeyFingerprint": "remote-fingerprint",
				"status":               "active",
			})
		case "/v1/recovery-recipient/replace":
			recoveryReplaceSeen = true
			http.Error(w, `{"error":"replacement failed"}`, http.StatusInternalServerError)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	var out bytes.Buffer
	var errb bytes.Buffer
	app := New(&out, &errb)
	for _, step := range [][]string{
		{"init", "--device", "qa-laptop"},
		{"add", "--workspace", "oclan-co", "local/asiri/API_KEY", "--value-file", testSecretFile(t, "secret_value")},
		{"login", "--origin", server.URL},
		{"push", "--workspace", "oclan-co"},
	} {
		out.Reset()
		errb.Reset()
		if code := app.Run(step); code != 0 {
			t.Fatalf("%v failed with code %d stderr=%s", step, code, errb.String())
		}
	}
	remoteRecoveryActive = true
	out.Reset()
	errb.Reset()
	recoveryKeyPath := filepath.Join(tmp, "recovery.key")
	if code := app.Run([]string{"recovery", "setup", "--workspace", "oclan-co", "--force", "--output-file", recoveryKeyPath}); code == 0 {
		t.Fatal("recovery setup should fail when remote replacement fails")
	}
	if !recoveryReplaceSeen {
		t.Fatal("expected recovery replacement endpoint")
	}
	if !strings.Contains(errb.String(), "recovery key delivered, but remote replacement failed") {
		t.Fatalf("expected replacement failure, got %s", errb.String())
	}
	if keyBytes, err := os.ReadFile(recoveryKeyPath); err != nil {
		t.Fatal(err)
	} else if strings.TrimSpace(string(keyBytes)) == "" {
		t.Fatal("recovery key should remain available after delivery")
	}
	st, err := store.Load(filepath.Join(tmp, "local-state.json"))
	if err != nil {
		t.Fatal(err)
	}
	if st.RecoveryForWorkspace(st.State.ControlPlane.WorkspaceID) != nil {
		t.Fatalf("local recovery config should not be active after remote wrapping failure: %#v", st.State.Recoveries)
	}
}

func TestRecoverySetupForceCommitsWhenPreviousRecipientIsRetired(t *testing.T) {
	tmp := t.TempDir()
	old := os.Getenv("ASIRI_HOME")
	t.Cleanup(func() { _ = os.Setenv("ASIRI_HOME", old) })
	if err := os.Setenv("ASIRI_HOME", tmp); err != nil {
		t.Fatal(err)
	}
	var registeredRecipients []string
	replacementCount := 0
	staleRecoveryListRejected := false
	unscopedRecoveryListSeen := false
	var pushedSecret map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		switch r.URL.Path {
		case "/v1/auth/device-code/start":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"deviceCode":              "dc_recovery_force",
				"userCode":                "RFOR-1234",
				"verificationUriComplete": serverURL(r) + "/auth/device?code=RFOR-1234",
				"expiresIn":               30,
				"interval":                0,
			})
		case "/v1/auth/device-code/token":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status":           "approved",
				"orgId":            "org_recovery",
				"workspaceSlug":    "oclan-co",
				"userId":           "usr_owner",
				"deviceId":         "dev_recovery",
				"accessToken":      "at_recovery",
				"refreshToken":     "rt_recovery",
				"expiresIn":        3600,
				"refreshExpiresAt": time.Now().UTC().Add(7 * 24 * time.Hour).Format(time.RFC3339),
			})
		case "/v1/orgs":
			assertWorkspaceOverviewTarget(t, r, "oclan-co")
			_ = json.NewEncoder(w).Encode(map[string]any{"organizations": []map[string]any{{
				"id": "org_recovery", "slug": "oclan-co", "role": "owner", "canPull": true, "canWrite": true, "currentDeviceTrusted": true, "currentDeviceId": "dev_recovery",
			}}})
		case "/v1/sync/write-options":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"requestedWorkspaceSlug": "oclan-co",
				"workspace": map[string]any{
					"id":       "org_recovery",
					"slug":     "oclan-co",
					"canWrite": true,
					"paths": []map[string]any{{
						"fullPath": "oclan-co/local/asiri/API_KEY",
						"canWrite": true,
					}},
				},
			})
		case "/v1/secrets":
			if r.Method == http.MethodPost {
				if err := json.NewDecoder(r.Body).Decode(&pushedSecret); err != nil {
					t.Fatal(err)
				}
				pushedSecret["id"] = "secv_recovery"
				pushedSecret["status"] = "active"
				_ = json.NewEncoder(w).Encode(map[string]any{"id": "secv_recovery", "status": "active"})
				return
			}
			http.NotFound(w, r)
		case "/v1/recovery-recipient":
			if r.Method == http.MethodGet {
				if len(registeredRecipients) == 0 {
					http.NotFound(w, r)
					return
				}
				_ = json.NewEncoder(w).Encode(map[string]any{
					"recipientId":          registeredRecipients[len(registeredRecipients)-1],
					"publicKey":            "remote-public-key",
					"publicKeyFingerprint": "remote-fingerprint",
					"status":               "active",
				})
				return
			}
			if r.Method != http.MethodPost {
				http.NotFound(w, r)
				return
			}
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			recipientID, _ := body["recipientId"].(string)
			registeredRecipients = append(registeredRecipients, recipientID)
			replacements, ok := body["replacements"].([]any)
			if !ok || len(replacements) != 1 {
				t.Fatalf("expected one replacement in initial setup: %#v", body["replacements"])
			}
			replacementCount += 1
			_ = json.NewEncoder(w).Encode(map[string]any{
				"recipientId":          recipientID,
				"publicKeyFingerprint": body["publicKeyFingerprint"],
				"status":               "active",
			})
		case "/v1/recovery-recipient/replace":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			recipientID, _ := body["recipientId"].(string)
			registeredRecipients = append(registeredRecipients, recipientID)
			replacements, ok := body["replacements"].([]any)
			if !ok || len(replacements) != 1 {
				t.Fatalf("expected one replacement in forced setup: %#v", body["replacements"])
			}
			replacementCount += 1
			_ = json.NewEncoder(w).Encode(map[string]any{
				"recipientId":          recipientID,
				"publicKeyFingerprint": body["publicKeyFingerprint"],
				"status":               "active",
			})
		case "/v1/secrets/encrypted":
			if r.URL.Query().Get("orgId") != "org_recovery" {
				t.Fatalf("unexpected secrets query: %s", r.URL.RawQuery)
			}
			recoveryRecipientID := r.URL.Query().Get("recoveryRecipientId")
			if len(registeredRecipients) >= 1 && recoveryRecipientID == registeredRecipients[0] {
				staleRecoveryListRejected = true
				http.Error(w, `{"error":"recovery recipient is not registered for this workspace"}`, http.StatusForbidden)
				return
			}
			if len(registeredRecipients) >= 1 && recoveryRecipientID == "" {
				unscopedRecoveryListSeen = true
			}
			if pushedSecret == nil {
				_ = json.NewEncoder(w).Encode(map[string]any{"secrets": []map[string]any{}})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"secrets": []map[string]any{pushedSecret}})
		case "/v1/devices":
			_ = json.NewEncoder(w).Encode(map[string]any{"devices": []map[string]any{}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	var out bytes.Buffer
	var errb bytes.Buffer
	app := New(&out, &errb)
	for _, step := range [][]string{
		{"init", "--device", "qa-laptop"},
		{"add", "--workspace", "oclan-co", "local/asiri/API_KEY", "--value-file", testSecretFile(t, "secret_value")},
		{"login", "--origin", server.URL},
		{"push", "--workspace", "oclan-co"},
	} {
		out.Reset()
		errb.Reset()
		if code := app.Run(step); code != 0 {
			t.Fatalf("%v failed with code %d stderr=%s", step, code, errb.String())
		}
	}
	for _, step := range [][]string{
		{"recovery", "setup", "--workspace", "oclan-co", "--output-file", filepath.Join(tmp, "recovery-1.key")},
		{"recovery", "setup", "--workspace", "oclan-co", "--force", "--output-file", filepath.Join(tmp, "recovery-2.key")},
	} {
		out.Reset()
		errb.Reset()
		if code := app.Run(step); code != 0 {
			t.Fatalf("%v failed with code %d stderr=%s", step, code, errb.String())
		}
	}
	if len(registeredRecipients) != 2 || registeredRecipients[0] == registeredRecipients[1] {
		t.Fatalf("expected two distinct recovery registrations: %#v", registeredRecipients)
	}
	if replacementCount != 2 {
		t.Fatalf("expected both setup runs to replace recovery wrapping, got %d", replacementCount)
	}
	if !staleRecoveryListRejected || !unscopedRecoveryListSeen {
		t.Fatalf("forced setup should fall back after stale recovery recipient rejection, rejected=%v unscoped=%v", staleRecoveryListRejected, unscopedRecoveryListSeen)
	}
	st, err := store.Load(filepath.Join(tmp, "local-state.json"))
	if err != nil {
		t.Fatal(err)
	}
	if recovery := st.RecoveryForWorkspace(st.State.ControlPlane.WorkspaceID); recovery == nil || recovery.RecipientID != registeredRecipients[1] {
		t.Fatalf("forced replacement should commit the new local recovery config: %#v", st.State.Recoveries)
	}
}

func TestRecoveryRestoreUsesSuppliedKeyWhenLocalMetadataIsStale(t *testing.T) {
	tmp := t.TempDir()
	old := os.Getenv("ASIRI_HOME")
	t.Cleanup(func() { _ = os.Setenv("ASIRI_HOME", old) })
	if err := os.Setenv("ASIRI_HOME", tmp); err != nil {
		t.Fatal(err)
	}
	remoteListSeen := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		switch r.URL.Path {
		case "/v1/auth/device-code/start":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"deviceCode":              "dc_recovery_restore",
				"userCode":                "REST-1234",
				"verificationUriComplete": serverURL(r) + "/auth/device?code=REST-1234",
				"expiresIn":               30,
				"interval":                0,
			})
		case "/v1/auth/device-code/token":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status":           "approved",
				"orgId":            "org_recovery",
				"workspaceSlug":    "oclan-co",
				"userId":           "usr_owner",
				"deviceId":         "dev_recovery",
				"accessToken":      "at_recovery",
				"refreshToken":     "rt_recovery",
				"expiresIn":        3600,
				"refreshExpiresAt": time.Now().UTC().Add(7 * 24 * time.Hour).Format(time.RFC3339),
			})
		case "/v1/orgs":
			assertWorkspaceOverviewTarget(t, r, "oclan-co")
			_ = json.NewEncoder(w).Encode(map[string]any{"organizations": []map[string]any{{
				"id": "org_recovery", "slug": "oclan-co", "role": "owner", "canPull": true, "canWrite": true, "currentDeviceTrusted": true, "currentDeviceId": "dev_recovery",
			}}})
		case "/v1/secrets/encrypted":
			remoteListSeen = true
			if got := r.URL.Query().Get("recoveryRecipientId"); !strings.HasPrefix(got, "rec_") {
				t.Fatalf("restore should list by supplied recovery key identity, got %q", got)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"secrets": []any{}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	var out bytes.Buffer
	var errb bytes.Buffer
	app := New(&out, &errb)
	for _, step := range [][]string{
		{"init", "--device", "qa-laptop"},
		{"login", "--origin", server.URL},
	} {
		out.Reset()
		errb.Reset()
		if code := app.Run(step); code != 0 {
			t.Fatalf("%v failed with code %d stderr=%s", step, code, errb.String())
		}
	}
	st, err := store.Load(filepath.Join(tmp, "local-state.json"))
	if err != nil {
		t.Fatal(err)
	}
	oldSetup, err := st.SetupRecovery(st.State.ControlPlane.WorkspaceID, st.State.ControlPlane.WorkspaceSlug, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.SetupRecovery(st.State.ControlPlane.WorkspaceID, st.State.ControlPlane.WorkspaceSlug, true); err != nil {
		t.Fatal(err)
	}
	if err := st.Save(); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(tmp, "old-recovery.key")
	if err := os.WriteFile(keyPath, []byte(oldSetup.Key+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	errb.Reset()
	if code := app.Run([]string{"recovery", "restore", "--workspace", "oclan-co", "--key-file", keyPath}); code != 0 {
		t.Fatalf("restore should let the server decide whether the supplied key is active: %s", errb.String())
	}
	if !remoteListSeen {
		t.Fatal("restore should ask the server about the supplied recovery key")
	}
	if !strings.Contains(out.String(), "No remote active secrets to restore") {
		t.Fatalf("unexpected restore output: %s", out.String())
	}
	st, err = store.Load(filepath.Join(tmp, "local-state.json"))
	if err != nil {
		t.Fatal(err)
	}
	if recovery := st.RecoveryForWorkspace(st.State.ControlPlane.WorkspaceID); recovery == nil || recovery.RecipientID != oldSetup.RecipientID {
		t.Fatalf("restore should refresh local recovery metadata from the supplied key: %#v", st.State.Recoveries)
	}
}

func TestRecoverySetupDoesNotPersistWhenKeyDeliveryFails(t *testing.T) {
	tmp := t.TempDir()
	old := os.Getenv("ASIRI_HOME")
	t.Cleanup(func() { _ = os.Setenv("ASIRI_HOME", old) })
	if err := os.Setenv("ASIRI_HOME", tmp); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	app := New(&out, &errb)
	remoteReplacementSeen := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		switch r.URL.Path {
		case "/v1/auth/device-code/start":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"deviceCode":              "dc_recovery_fail",
				"userCode":                "FAIL-1234",
				"verificationUriComplete": serverURL(r) + "/auth/device?code=FAIL-1234",
				"expiresIn":               30,
				"interval":                0,
			})
		case "/v1/auth/device-code/token":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status":           "approved",
				"orgId":            "org_recovery",
				"workspaceSlug":    "oclan-co",
				"userId":           "usr_owner",
				"deviceId":         "dev_recovery",
				"accessToken":      "at_recovery",
				"refreshToken":     "rt_recovery",
				"expiresIn":        3600,
				"refreshExpiresAt": time.Now().UTC().Add(7 * 24 * time.Hour).Format(time.RFC3339),
			})
		case "/v1/secrets/encrypted":
			_ = json.NewEncoder(w).Encode(map[string]any{"secrets": []map[string]any{}})
		case "/v1/recovery-recipient/replace":
			remoteReplacementSeen = true
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "active"})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	for _, step := range [][]string{
		{"init", "--device", "qa-laptop"},
		{"login", "--origin", server.URL},
	} {
		out.Reset()
		errb.Reset()
		if code := app.Run(step); code != 0 {
			t.Fatalf("%v failed: %s", step, errb.String())
		}
	}
	existingKeyPath := filepath.Join(tmp, "recovery.key")
	if err := os.WriteFile(existingKeyPath, []byte("existing\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	errb.Reset()
	if code := app.Run([]string{"recovery", "setup", "--workspace", "oclan-co", "--output-file", existingKeyPath}); code == 0 {
		t.Fatal("recovery setup should fail when key output cannot be created")
	}
	if remoteReplacementSeen {
		t.Fatal("remote recovery replacement should not run when key delivery fails")
	}
	st, err := store.Load(filepath.Join(tmp, "local-state.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(st.State.Recoveries) != 0 {
		t.Fatalf("workspace recovery config persisted after key delivery failure: %#v", st.State.Recoveries)
	}
}
