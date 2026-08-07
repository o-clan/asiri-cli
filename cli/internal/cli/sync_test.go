package cli

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/o-clan/asiri/cli/internal/store"
)

func TestSyncAllowsHumanReceiveOnlyAndNoOpWorkspaces(t *testing.T) {
	for _, tc := range []struct {
		name           string
		localWorkspace string
		canWrite       bool
		wantPublish    string
	}{
		{name: "read-only human", localWorkspace: "oclan-co", canWrite: false, wantPublish: "No writable local secret versions to publish for workspace oclan-co"},
		{name: "no active secrets in target", localWorkspace: "google-com", canWrite: true, wantPublish: "No local active secrets to publish for workspace oclan-co"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			previousHome := os.Getenv("ASIRI_HOME")
			t.Cleanup(func() { _ = os.Setenv("ASIRI_HOME", previousHome) })
			if err := os.Setenv("ASIRI_HOME", home); err != nil {
				t.Fatal(err)
			}

			syncRequests := 0
			pushPlanSeen := false
			pushCommitSeen := false
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("content-type", "application/json")
				switch r.URL.Path {
				case "/v1/auth/device-code/start":
					_ = json.NewEncoder(w).Encode(map[string]any{
						"deviceCode": "dc_sync_human", "userCode": "SYNC-1234",
						"verificationUriComplete": serverURL(r) + "/auth/device?code=SYNC-1234",
						"expiresIn":               30, "interval": 0,
					})
				case "/v1/auth/device-code/token":
					_ = json.NewEncoder(w).Encode(map[string]any{
						"status": "approved", "orgId": "org_oclan", "workspaceSlug": "oclan-co",
						"userId": "usr_member", "deviceId": "dev_member",
						"accessToken": "at_sync_human", "refreshToken": "rt_sync_human",
						"expiresIn": 3600, "refreshExpiresAt": time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339),
					})
				case "/v1/orgs":
					_ = json.NewEncoder(w).Encode(map[string]any{"organizations": []map[string]any{{
						"id": "org_oclan", "slug": "oclan-co", "role": "member", "canPull": true, "canWrite": tc.canWrite,
						"currentDeviceTrusted": true, "currentDeviceId": "dev_member",
					}}})
				case "/v1/sync":
					syncRequests++
					_ = json.NewEncoder(w).Encode(map[string]any{
						"orgId": "org_oclan", "deviceId": "dev_member", "issuedAt": time.Now().UTC().Format(time.RFC3339),
						"encryptedSecrets": []map[string]any{}, "tombstones": []map[string]any{},
						"policies": []map[string]any{}, "scopes": []map[string]any{},
					})
				case "/v1/sync/push-plan":
					pushPlanSeen = true
					http.Error(w, "unexpected push plan", http.StatusInternalServerError)
				case "/v1/secrets/batch":
					pushCommitSeen = true
					http.Error(w, "unexpected push", http.StatusInternalServerError)
				default:
					http.NotFound(w, r)
				}
			}))
			defer server.Close()

			var out bytes.Buffer
			var errOut bytes.Buffer
			app := New(&out, &errOut)
			for _, step := range [][]string{
				{"init", "--device", "sync-device", "--workspace", tc.localWorkspace},
				{"add", "--workspace", tc.localWorkspace, "prod/api/API_KEY", "--value-file", testSecretFile(t, "sync-fixture")},
				{"login", "--origin", server.URL},
			} {
				out.Reset()
				errOut.Reset()
				if code := app.Run(step); code != 0 {
					t.Fatalf("%v failed with code %d: %s", step, code, errOut.String())
				}
			}
			if tc.localWorkspace == "oclan-co" {
				linkLocalWorkspaceForTest(t, "oclan-co", "org_oclan")
			}

			out.Reset()
			errOut.Reset()
			if code := app.Run([]string{"sync", "--workspace", "oclan-co"}); code != 0 {
				t.Fatalf("sync failed with code %d: %s", code, errOut.String())
			}
			if syncRequests != 1 {
				t.Fatalf("expected one receive phase, got %d", syncRequests)
			}
			if pushPlanSeen || pushCommitSeen {
				t.Fatal("receive-only or no-op sync must not enter the remote push phase")
			}
			for _, expected := range []string{tc.wantPublish, "Finished reconciliation for workspace oclan-co against the control-plane ledger"} {
				if !strings.Contains(out.String(), expected) {
					t.Fatalf("sync output missing %q: %s", expected, out.String())
				}
			}
		})
	}
}

func TestSyncPartialImportRestoresTombstonedSecretsOnDisk(t *testing.T) {
	home := t.TempDir()
	previousHome := os.Getenv("ASIRI_HOME")
	t.Cleanup(func() { _ = os.Setenv("ASIRI_HOME", previousHome) })
	if err := os.Setenv("ASIRI_HOME", home); err != nil {
		t.Fatal(err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		switch r.URL.Path {
		case "/v1/auth/device-code/start":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"deviceCode": "dc_sync_partial", "userCode": "SYNC-PARTIAL",
				"verificationUriComplete": serverURL(r) + "/auth/device?code=SYNC-PARTIAL",
				"expiresIn":               30, "interval": 0,
			})
		case "/v1/auth/device-code/token":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status": "approved", "orgId": "org_oclan", "workspaceSlug": "oclan-co",
				"userId": "usr_owner", "deviceId": "dev_owner",
				"accessToken": "at_sync_partial", "refreshToken": "rt_sync_partial",
				"expiresIn": 3600, "refreshExpiresAt": time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339),
			})
		case "/v1/orgs":
			_ = json.NewEncoder(w).Encode(map[string]any{"organizations": []map[string]any{{
				"id": "org_oclan", "slug": "oclan-co", "role": "owner", "canPull": true, "canWrite": true,
				"currentDeviceTrusted": true, "currentDeviceId": "dev_owner",
			}}})
		case "/v1/sync":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"orgId": "org_oclan", "deviceId": "dev_owner", "issuedAt": time.Now().UTC().Format(time.RFC3339),
				"encryptedSecrets": []map[string]any{{"orgId": "org_oclan", "scope": "oclan-co/prod", "name": ""}},
				"tombstones": []map[string]any{{
					"orgId": "org_oclan", "scope": "oclan-co/prod", "name": "API_KEY",
					"deletedThroughVersion": 1, "deletedAt": time.Now().UTC().Format(time.RFC3339),
				}},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	var out bytes.Buffer
	var errOut bytes.Buffer
	app := New(&out, &errOut)
	for _, step := range [][]string{
		{"init", "--device", "sync-device", "--workspace", "oclan-co"},
		{"add", "--workspace", "oclan-co", "prod/API_KEY", "--value-file", testSecretFile(t, "local-value")},
		{"login", "--origin", server.URL},
	} {
		out.Reset()
		errOut.Reset()
		if code := app.Run(step); code != 0 {
			t.Fatalf("%v failed with code %d: %s", step, code, errOut.String())
		}
	}
	linkLocalWorkspaceForTest(t, "oclan-co", "org_oclan")

	out.Reset()
	errOut.Reset()
	if code := app.Run([]string{"sync", "--workspace", "oclan-co"}); code == 0 {
		t.Fatalf("partial sync unexpectedly succeeded: %s", out.String())
	}
	reloaded, err := store.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	secret := reloaded.State.Secrets[store.SecretKey("oclan-co/prod", "API_KEY")]
	if secret.ActiveVersion != 1 || len(secret.Versions) != 1 || secret.Versions[0].Status != "active" {
		t.Fatalf("failed sync persisted tombstone mutation: %#v", secret)
	}
	if len(reloaded.State.SecretTombstones) != 0 {
		t.Fatalf("failed sync persisted deletion ledger: %#v", reloaded.State.SecretTombstones)
	}
}
