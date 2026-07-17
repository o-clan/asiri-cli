package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/o-clan/asiri/cli/internal/asiri"
	"github.com/o-clan/asiri/cli/internal/store"
)

func TestPushAndPullUseBearerAccessToken(t *testing.T) {
	tmp := t.TempDir()
	old := os.Getenv("ASIRI_HOME")
	t.Cleanup(func() { _ = os.Setenv("ASIRI_HOME", old) })
	if err := os.Setenv("ASIRI_HOME", tmp); err != nil {
		t.Fatal(err)
	}
	secretPushCount := 0
	wrappingDiscoveryCount := 0
	syncSeen := false
	devicePublicKey := ""
	var pushedSecret map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		switch r.URL.Path {
		case "/v1/auth/device-code/start":
			var body map[string]string
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if body["localWorkspaceSlug"] != "" || body["workspaceSlug"] != "" {
				t.Fatalf("unexpected workspace hint: %#v", body)
			}
			devicePublicKey = body["encryptionPublicKey"]
			_ = json.NewEncoder(w).Encode(map[string]any{
				"deviceCode":              "dc_push",
				"userCode":                "PUSH-1234",
				"verificationUri":         serverURL(r) + "/auth/device",
				"verificationUriComplete": serverURL(r) + "/auth/device?code=PUSH-1234",
				"expiresIn":               30,
				"interval":                0,
			})
		case "/v1/auth/device-code/token":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status":           "approved",
				"orgId":            "org_remote",
				"workspaceSlug":    "oclan-co",
				"userId":           "usr_owner",
				"deviceId":         "dev_remote",
				"accessToken":      "at_push",
				"refreshToken":     "rt_push",
				"expiresIn":        3600,
				"refreshExpiresAt": time.Now().UTC().Add(7 * 24 * time.Hour).Format(time.RFC3339),
			})
		case "/v1/orgs":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"activeOrgId": "org_remote",
				"organizations": []map[string]any{
					{"id": "org_remote", "name": "O Clan", "slug": "oclan-co", "ownerUserId": "usr_owner", "role": "owner", "canPull": true, "canWrite": true, "currentDeviceTrusted": true, "currentDeviceId": "dev_remote"},
				},
			})
		case "/v1/sync/write-options":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"requestedWorkspaceSlug": "oclan-co",
				"workspace": map[string]any{
					"id":       "org_remote",
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
				secretPushCount++
				if r.Header.Get("authorization") != "Bearer at_push" {
					t.Fatalf("unexpected push auth header: %s", r.Header.Get("authorization"))
				}
				var body map[string]any
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					t.Fatal(err)
				}
				if body["orgId"] != "org_remote" || body["createdByDeviceId"] != "dev_remote" || body["scope"] != "oclan-co/local/asiri" || body["name"] != "API_KEY" {
					t.Fatalf("unexpected pushed secret body: %#v", body)
				}
				wrapped, ok := body["wrappedKeys"].([]any)
				if !ok || len(wrapped) != 2 {
					t.Fatalf("missing wrapped keys: %#v", body["wrappedKeys"])
				}
				recipients := map[string]bool{}
				for _, item := range wrapped {
					wrappedKey := item.(map[string]any)
					if wrappedKey["wrapAlgorithm"] != "p256-hkdf-aes256gcm" {
						t.Fatalf("unexpected wrapped key: %#v", wrappedKey)
					}
					recipients[fmt.Sprint(wrappedKey["recipientId"])] = true
				}
				if !recipients["dev_remote"] || !recipients["dev_other"] {
					t.Fatalf("unexpected wrapped recipients: %#v", wrapped)
				}
				pushedSecret = body
				pushedSecret["id"] = "secv_remote"
				pushedSecret["status"] = "active"
				pushedSecret["createdAt"] = time.Now().UTC().Format(time.RFC3339)
				_ = json.NewEncoder(w).Encode(map[string]any{"id": "secv_remote", "status": "active"})
				return
			}
			if r.Method != http.MethodGet {
				http.NotFound(w, r)
				return
			}
			if pushedSecret == nil {
				_ = json.NewEncoder(w).Encode(map[string]any{"secrets": []map[string]any{}})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"secrets": []map[string]any{pushedSecret}})
		case "/v1/secrets/encrypted":
			if r.Method != http.MethodGet {
				http.NotFound(w, r)
				return
			}
			if pushedSecret == nil {
				_ = json.NewEncoder(w).Encode(map[string]any{"secrets": []map[string]any{}})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"secrets": []map[string]any{pushedSecret}})
		case "/v1/sync":
			syncSeen = true
			if r.Header.Get("authorization") != "Bearer at_push" {
				t.Fatalf("unexpected sync auth header: %s", r.Header.Get("authorization"))
			}
			if r.URL.Query().Get("orgId") != "org_remote" || r.URL.Query().Get("deviceId") != "dev_remote" {
				t.Fatalf("unexpected sync query: %s", r.URL.RawQuery)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"orgId":            "org_remote",
				"deviceId":         "dev_remote",
				"issuedAt":         time.Now().UTC().Format(time.RFC3339),
				"encryptedSecrets": []map[string]any{pushedSecret},
			})
		case "/v1/devices":
			wrappingDiscoveryCount++
			if wrappingDiscoveryCount == 1 {
				w.Header().Set("Retry-After", "0")
				http.Error(w, `{"error":"rate limited"}`, http.StatusTooManyRequests)
				return
			}
			if r.Header.Get("authorization") != "Bearer at_push" {
				t.Fatalf("unexpected device list auth header: %s", r.Header.Get("authorization"))
			}
			if r.URL.Query().Get("scope") != "oclan-co/local/asiri" || r.URL.Query().Get("secretName") != "API_KEY" {
				t.Fatalf("wrapping targets must be requested for one secret: %s", r.URL.RawQuery)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"devices": []map[string]any{
					{"id": "dev_remote", "name": "qa-laptop", "status": "trusted", "kind": "laptop", "encryptionPublicKey": devicePublicKey},
					{"id": "dev_other", "name": "server", "status": "trusted", "kind": "server", "encryptionPublicKey": devicePublicKey},
				},
			})
		case "/v1/secrets/secv_remote/wrapped-keys":
			t.Fatal("rewrap endpoint should not be called after push wrapped all trusted devices")
			if r.Header.Get("authorization") != "Bearer at_push" {
				t.Fatalf("unexpected rewrap auth header: %s", r.Header.Get("authorization"))
			}
			var body map[string][]map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if len(body["wrappedKeys"]) != 1 || body["wrappedKeys"][0]["recipientId"] != "dev_other" {
				t.Fatalf("unexpected rewrap body: %#v", body)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"id": "secv_remote", "status": "active"})
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
		{"push", "--workspace", "oclan-co"},
		{"pull", "--workspace", "oclan-co"},
		{"rewrap", "--workspace", "oclan-co"},
	} {
		out.Reset()
		errb.Reset()
		if code := app.Run(step); code != 0 {
			t.Fatalf("%v failed with code %d stderr=%s", step, code, errb.String())
		}
	}
	if secretPushCount != 1 || !syncSeen {
		t.Fatalf("expected push and pull endpoints to be called")
	}
	if wrappingDiscoveryCount < 2 {
		t.Fatal("push did not retry rate-limited wrapping target discovery")
	}
	if strings.Contains(out.String(), "secret_value") || strings.Contains(errb.String(), "secret_value") {
		t.Fatalf("push/pull leaked secret stdout=%q stderr=%q", out.String(), errb.String())
	}
}

func TestPushDryRunFirstWorkspaceEvaluatesRemoteState(t *testing.T) {
	for _, tc := range []struct {
		name                 string
		conflict             bool
		metadataOnlyConflict bool
		wantCode             int
		wantOut              []string
		wantErr              string
	}{
		{
			name:     "conflict",
			conflict: true,
			wantCode: 1,
			wantOut:  []string{"Would push 0 encrypted secret version(s)", "Conflicts", "oclan-co/local/asiri/API_KEY v1"},
			wantErr:  "remote secret version conflict",
		},
		{
			name:     "no-op",
			wantCode: 0,
			wantOut:  []string{"Would push 0 encrypted secret version(s)", "1 would be skipped", "Would rewrap 1 trusted-device key(s) across 1 existing secret version(s)"},
		},
		{
			name:                 "metadata-only-inactive-conflict",
			metadataOnlyConflict: true,
			wantCode:             1,
			wantOut:              []string{"Would push 0 encrypted secret version(s)", "Conflicts", "oclan-co/local/asiri/API_KEY v1"},
			wantErr:              "remote secret version conflict",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tmp := t.TempDir()
			old := os.Getenv("ASIRI_HOME")
			t.Cleanup(func() { _ = os.Setenv("ASIRI_HOME", old) })
			if err := os.Setenv("ASIRI_HOME", tmp); err != nil {
				t.Fatal(err)
			}
			var remoteVersion *asiri.SecretVersion
			writeOptionsSeen := false
			devicesSeen := false
			encryptedSeen := false
			metadataSeen := false
			postSeen := false
			rewrapPostSeen := false
			devicePublicKey := ""
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("content-type", "application/json")
				switch r.URL.Path {
				case "/v1/auth/device-code/start":
					var body map[string]string
					if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
						t.Fatal(err)
					}
					devicePublicKey = body["encryptionPublicKey"]
					_ = json.NewEncoder(w).Encode(map[string]any{
						"deviceCode":              "dc_dry_run",
						"userCode":                "DRY-1234",
						"verificationUriComplete": serverURL(r) + "/auth/device?code=DRY-1234",
						"expiresIn":               30,
						"interval":                0,
					})
				case "/v1/auth/device-code/token":
					_ = json.NewEncoder(w).Encode(map[string]any{
						"status":           "approved",
						"orgId":            "org_dry_run",
						"workspaceSlug":    "oclan-co",
						"userId":           "usr_owner",
						"deviceId":         "dev_dry_run",
						"accessToken":      "at_dry_run",
						"refreshToken":     "rt_dry_run",
						"expiresIn":        3600,
						"refreshExpiresAt": time.Now().UTC().Add(7 * 24 * time.Hour).Format(time.RFC3339),
					})
				case "/v1/orgs":
					assertWorkspaceOverviewTarget(t, r, "oclan-co")
					_ = json.NewEncoder(w).Encode(map[string]any{
						"activeOrgId": "org_dry_run",
						"organizations": []map[string]any{
							{"id": "org_dry_run", "name": "O Clan", "slug": "oclan-co", "ownerUserId": "usr_owner", "role": "owner", "canPull": true, "canWrite": true, "currentDeviceTrusted": true, "currentDeviceId": "dev_dry_run"},
						},
					})
				case "/v1/sync/write-options":
					writeOptionsSeen = true
					_ = json.NewEncoder(w).Encode(map[string]any{
						"requestedWorkspaceSlug": "oclan-co",
						"workspace": map[string]any{
							"id":       "org_dry_run",
							"slug":     "oclan-co",
							"canWrite": true,
							"paths": []map[string]any{{
								"fullPath": "oclan-co/local/asiri/API_KEY",
								"canWrite": true,
							}},
						},
					})
				case "/v1/recovery-recipient":
					http.NotFound(w, r)
				case "/v1/devices":
					devicesSeen = true
					_ = json.NewEncoder(w).Encode(map[string]any{
						"devices": []map[string]any{
							{"id": "dev_dry_run", "name": "qa-laptop", "status": "trusted", "kind": "laptop", "encryptionPublicKey": devicePublicKey},
							{"id": "dev_other", "name": "server", "status": "trusted", "kind": "server", "encryptionPublicKey": devicePublicKey},
						},
					})
				case "/v1/secrets/encrypted":
					encryptedSeen = true
					if r.URL.Query().Get("orgId") != "org_dry_run" {
						t.Fatalf("unexpected secrets query: %s", r.URL.RawQuery)
					}
					if remoteVersion == nil {
						t.Fatal("remote version was not prepared before dry-run push")
					}
					if tc.metadataOnlyConflict {
						_ = json.NewEncoder(w).Encode(map[string]any{"secrets": []map[string]any{}})
						return
					}
					ciphertext := remoteVersion.Ciphertext
					if tc.conflict {
						ciphertext = "conflicting-ciphertext"
					}
					_ = json.NewEncoder(w).Encode(map[string]any{
						"secrets": []map[string]any{{
							"id":         "sec_dry_run",
							"orgId":      "org_dry_run",
							"scope":      "oclan-co/local/asiri",
							"name":       "API_KEY",
							"version":    remoteVersion.Version,
							"algorithm":  remoteVersion.Algorithm,
							"nonce":      remoteVersion.Nonce,
							"ciphertext": ciphertext,
							"aad":        remoteVersion.AAD,
							"status":     "active",
							"wrappedKeys": []map[string]any{{
								"recipientType": "device",
								"recipientId":   "dev_dry_run",
								"wrapAlgorithm": "p256-hkdf-aes256gcm",
								"wrappedKey":    "remote-wrapped",
							}},
						}},
					})
				case "/v1/secrets":
					if r.Method == http.MethodGet {
						metadataSeen = true
						if r.URL.Query().Get("includeInactive") != "1" {
							t.Fatalf("metadata preflight should request inactive records, got query %s", r.URL.RawQuery)
						}
						status := "active"
						if tc.metadataOnlyConflict {
							status = "stale"
						}
						_ = json.NewEncoder(w).Encode(map[string]any{
							"secrets": []map[string]any{{
								"id":        "sec_dry_run_meta",
								"orgId":     "org_dry_run",
								"scope":     "oclan-co/local/asiri",
								"name":      "API_KEY",
								"version":   remoteVersion.Version,
								"algorithm": remoteVersion.Algorithm,
								"status":    status,
							}},
						})
						return
					}
					if r.Method == http.MethodPost {
						postSeen = true
					}
					http.NotFound(w, r)
				case "/v1/secrets/sec_dry_run/wrapped-keys":
					if r.Method == http.MethodPost {
						rewrapPostSeen = true
					}
					http.NotFound(w, r)
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
			secret := st.State.Secrets[store.SecretKey("oclan-co/local/asiri", "API_KEY")]
			if len(secret.Versions) != 1 {
				t.Fatalf("expected one local secret version, got %#v", secret.Versions)
			}
			remoteVersion = &secret.Versions[0]
			out.Reset()
			errb.Reset()
			code := app.Run([]string{"push", "--workspace", "oclan-co", "--dry-run"})
			if code != tc.wantCode {
				t.Fatalf("dry-run push got code %d want %d stdout=%s stderr=%s", code, tc.wantCode, out.String(), errb.String())
			}
			for _, want := range tc.wantOut {
				if !strings.Contains(out.String(), want) {
					t.Fatalf("dry-run output missing %q: %s", want, out.String())
				}
			}
			if tc.wantErr != "" && !strings.Contains(errb.String(), tc.wantErr) {
				t.Fatalf("dry-run error missing %q: %s", tc.wantErr, errb.String())
			}
			if !writeOptionsSeen || !devicesSeen || !encryptedSeen || !metadataSeen || postSeen || rewrapPostSeen {
				t.Fatalf("dry-run should evaluate write options, devices, encrypted state, and metadata without posting, write=%v devices=%v encrypted=%v metadata=%v post=%v rewrapPost=%v", writeOptionsSeen, devicesSeen, encryptedSeen, metadataSeen, postSeen, rewrapPostSeen)
			}
			reloaded, err := store.LoadDefault()
			if err != nil {
				t.Fatal(err)
			}
			if _, ok := reloaded.RemoteBindingForPrefix("oclan-co"); ok {
				t.Fatal("dry-run should not persist a workspace prefix binding")
			}
		})
	}
}

func TestPushDryRunRemoteWorkspaceDoesNotSwitchAccountSession(t *testing.T) {
	tmp := t.TempDir()
	old := os.Getenv("ASIRI_HOME")
	t.Cleanup(func() { _ = os.Setenv("ASIRI_HOME", old) })
	if err := os.Setenv("ASIRI_HOME", tmp); err != nil {
		t.Fatal(err)
	}
	switchSeen := false
	encryptedSeen := false
	refreshSeen := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		switch r.URL.Path {
		case "/v1/auth/device-code/start":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"deviceCode":              "dc_dry_switch",
				"userCode":                "DRYS-1234",
				"verificationUriComplete": serverURL(r) + "/auth/device?code=DRYS-1234",
				"expiresIn":               30,
				"interval":                0,
			})
		case "/v1/auth/device-code/token":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status":           "approved",
				"orgId":            "org_oclan",
				"workspaceSlug":    "oclan-co",
				"userId":           "usr_owner",
				"deviceId":         "dev_oclan",
				"accessToken":      "at_oclan",
				"refreshToken":     "rt_oclan",
				"expiresIn":        3600,
				"refreshExpiresAt": time.Now().UTC().Add(7 * 24 * time.Hour).Format(time.RFC3339),
			})
		case "/v1/auth/session/refresh":
			refreshSeen++
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status":           "approved",
				"orgId":            "org_oclan",
				"workspaceSlug":    "oclan-co",
				"userId":           "usr_owner",
				"deviceId":         "dev_oclan",
				"accessToken":      "at_refreshed",
				"expiresIn":        3600,
				"refreshExpiresAt": time.Now().UTC().Add(7 * 24 * time.Hour).Format(time.RFC3339),
			})
		case "/v1/orgs":
			assertWorkspaceOverviewTarget(t, r, "asiri-dev")
			if r.Header.Get("authorization") == "Bearer at_oclan" {
				w.WriteHeader(http.StatusUnauthorized)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": "expired"})
				return
			}
			if r.Header.Get("authorization") != "Bearer at_refreshed" {
				t.Fatalf("workspace discovery should use the refreshed account token, got %s", r.Header.Get("authorization"))
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"organizations": []map[string]any{{"id": "org_asiri", "name": "Asiri Dev", "slug": "asiri-dev", "ownerUserId": "usr_owner", "role": "owner", "canPull": true, "canWrite": true, "currentDeviceTrusted": true, "currentDeviceId": "dev_asiri"}},
			})
		case "/v1/auth/session/switch":
			switchSeen = true
			var body map[string]string
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if body["workspace"] != "org_asiri" {
				t.Fatalf("unexpected switch body: %#v", body)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status":           "approved",
				"orgId":            "org_asiri",
				"workspaceSlug":    "asiri-dev",
				"userId":           "usr_owner",
				"deviceId":         "dev_asiri",
				"accessToken":      "at_asiri",
				"refreshToken":     "rt_asiri",
				"expiresIn":        3600,
				"refreshExpiresAt": time.Now().UTC().Add(7 * 24 * time.Hour).Format(time.RFC3339),
			})
		case "/v1/sync/write-options":
			if r.Header.Get("authorization") != "Bearer at_refreshed" {
				t.Fatalf("dry-run should reuse the refreshed account token, got %s", r.Header.Get("authorization"))
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"requestedWorkspaceSlug": "asiri-dev",
				"workspace": map[string]any{
					"id":       "org_asiri",
					"slug":     "asiri-dev",
					"canWrite": true,
					"paths": []map[string]any{{
						"fullPath": "asiri-dev/local/asiri/API_KEY",
						"canWrite": true,
					}},
				},
			})
		case "/v1/recovery-recipient":
			if r.URL.Query().Get("orgId") != "org_asiri" {
				t.Fatalf("unexpected recovery query: %s", r.URL.RawQuery)
			}
			http.NotFound(w, r)
		case "/v1/devices":
			_ = json.NewEncoder(w).Encode(map[string]any{"devices": []map[string]any{}})
		case "/v1/secrets/encrypted":
			encryptedSeen = true
			if r.Header.Get("authorization") != "Bearer at_refreshed" || r.URL.Query().Get("orgId") != "org_asiri" {
				t.Fatalf("unexpected encrypted secrets request auth=%s query=%s", r.Header.Get("authorization"), r.URL.RawQuery)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"secrets": []map[string]any{}})
		case "/v1/secrets":
			if r.Method == http.MethodPost {
				t.Fatal("dry-run should not post secrets")
			}
			http.NotFound(w, r)
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
		{"add", "--workspace", "asiri-dev", "local/asiri/API_KEY", "--value-file", testSecretFile(t, "secret_value")},
		{"login", "--origin", server.URL},
	} {
		out.Reset()
		errb.Reset()
		if code := app.Run(step); code != 0 {
			t.Fatalf("%v failed with code %d stderr=%s", step, code, errb.String())
		}
	}
	out.Reset()
	errb.Reset()
	if code := app.Run([]string{"push", "--workspace", "asiri-dev", "--dry-run"}); code != 0 {
		t.Fatalf("remote workspace dry-run failed: %s", errb.String())
	}
	if switchSeen || !encryptedSeen || refreshSeen != 1 {
		t.Fatalf("dry-run should refresh one account session without switching, switch=%v encrypted=%v refreshes=%d", switchSeen, encryptedSeen, refreshSeen)
	}
	reloaded, err := store.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.State.ControlPlane == nil || reloaded.State.ControlPlane.WorkspaceID != "org_oclan" || reloaded.State.ControlPlane.WorkspaceSlug != "oclan-co" {
		t.Fatalf("dry-run changed the account session: %#v", reloaded.State.ControlPlane)
	}
	if _, ok := reloaded.RemoteBindingForPrefix("asiri-dev"); ok {
		t.Fatal("dry-run should not persist remote workspace binding")
	}
}

func TestPushFailsWhenTrustedDeviceDiscoveryUnavailable(t *testing.T) {
	tmp := t.TempDir()
	old := os.Getenv("ASIRI_HOME")
	t.Cleanup(func() { _ = os.Setenv("ASIRI_HOME", old) })
	if err := os.Setenv("ASIRI_HOME", tmp); err != nil {
		t.Fatal(err)
	}
	postSeen := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		switch r.URL.Path {
		case "/v1/auth/device-code/start":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"deviceCode":              "dc_devices_fail",
				"userCode":                "DVC-FAIL",
				"verificationUriComplete": serverURL(r) + "/auth/device?code=DVC-FAIL",
				"expiresIn":               30,
				"interval":                0,
			})
		case "/v1/auth/device-code/token":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status":           "approved",
				"orgId":            "org_devices_fail",
				"workspaceSlug":    "oclan-co",
				"userId":           "usr_owner",
				"deviceId":         "dev_devices_fail",
				"accessToken":      "at_devices_fail",
				"refreshToken":     "rt_devices_fail",
				"expiresIn":        3600,
				"refreshExpiresAt": time.Now().UTC().Add(7 * 24 * time.Hour).Format(time.RFC3339),
			})
		case "/v1/orgs":
			assertWorkspaceOverviewTarget(t, r, "oclan-co")
			_ = json.NewEncoder(w).Encode(map[string]any{"organizations": []map[string]any{{
				"id": "org_devices_fail", "slug": "oclan-co", "role": "owner", "canPull": true, "canWrite": true, "currentDeviceTrusted": true, "currentDeviceId": "dev_devices_fail",
			}}})
		case "/v1/sync/write-options":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"requestedWorkspaceSlug": "oclan-co",
				"workspace": map[string]any{
					"id":       "org_devices_fail",
					"slug":     "oclan-co",
					"canWrite": true,
					"paths": []map[string]any{{
						"fullPath": "oclan-co/local/asiri/API_KEY",
						"canWrite": true,
					}},
				},
			})
		case "/v1/recovery-recipient":
			http.NotFound(w, r)
		case "/v1/devices":
			http.Error(w, `{"error":"temporarily unavailable"}`, http.StatusServiceUnavailable)
		case "/v1/secrets":
			if r.Method == http.MethodPost {
				postSeen = true
			}
			http.NotFound(w, r)
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
	} {
		out.Reset()
		errb.Reset()
		if code := app.Run(step); code != 0 {
			t.Fatalf("%v failed with code %d stderr=%s", step, code, errb.String())
		}
	}

	out.Reset()
	errb.Reset()
	if code := app.Run([]string{"push", "--workspace", "oclan-co"}); code == 0 {
		t.Fatal("push should fail when trusted-device discovery fails")
	}
	if postSeen {
		t.Fatal("push should not upload secrets after trusted-device discovery fails")
	}
	if !strings.Contains(errb.String(), "trusted device discovery failed") {
		t.Fatalf("missing device discovery failure: %s", errb.String())
	}
}

func TestParsePushArgsAcceptsLegacyYes(t *testing.T) {
	options, err := parsePushArgs([]string{"--workspace", "oclan-co", "--yes", "--dry-run", "--secret", "prod/github/SYNC_KEY"})
	if err != nil {
		t.Fatal(err)
	}
	if options.Workspace != "oclan-co" || !options.DryRun || len(options.Secrets) != 1 || options.Secrets[0] != "prod/github/SYNC_KEY" {
		t.Fatalf("unexpected parsed push options: %#v", options)
	}
}

func TestRateLimitRetryDelayIsCapped(t *testing.T) {
	headers := http.Header{"Retry-After": []string{"3600"}}
	if delay := rateLimitRetryDelay(headers, time.Now()); delay != time.Minute {
		t.Fatalf("expected one-minute retry cap, got %s", delay)
	}
}

func TestPushTargetSelectionSupportsScopesSecretsAndVersions(t *testing.T) {
	tmp := t.TempDir()
	old := os.Getenv("ASIRI_HOME")
	t.Cleanup(func() { _ = os.Setenv("ASIRI_HOME", old) })
	if err := os.Setenv("ASIRI_HOME", tmp); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	var errb bytes.Buffer
	app := New(&out, &errb)
	for _, step := range [][]string{
		{"init", "--device", "qa-laptop"},
		{"add", "--workspace", "oclan-co", "local/asiri/API_KEY", "--value-file", testSecretFile(t, "secret_value")},
		{"add", "--workspace", "oclan-co", "prod/github/SYNC_KEY", "--value-file", testSecretFile(t, "sync_value")},
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
	refs := st.ActiveSecretRefs()
	target := remoteWorkspaceResponse{Slug: "oclan-co"}
	secretRefs, err := selectPushRefs(st, refs, target, pushOptions{Secrets: []string{"prod/github/SYNC_KEY"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(secretRefs) != 1 || secretRefs[0].Scope != "oclan-co/prod/github" || secretRefs[0].Name != "SYNC_KEY" {
		t.Fatalf("unexpected secret refs: %#v", secretRefs)
	}
	scopeRefs, err := selectPushRefs(st, refs, target, pushOptions{Scopes: []string{"local/asiri"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(scopeRefs) != 1 || scopeRefs[0].Scope != "oclan-co/local/asiri" || scopeRefs[0].Name != "API_KEY" {
		t.Fatalf("unexpected scope refs: %#v", scopeRefs)
	}
	versionRefs, err := selectPushRefs(st, refs, target, pushOptions{Secrets: []string{"prod/github/SYNC_KEY"}, Version: 1})
	if err != nil {
		t.Fatal(err)
	}
	if len(versionRefs) != 1 || versionRefs[0].Version != 1 {
		t.Fatalf("unexpected version refs: %#v", versionRefs)
	}
}

func TestPushReconcileRejectsIncompleteRemoteEnvelope(t *testing.T) {
	result, err := reconcilePushVersions([]store.RemoteSecretVersion{{
		OrgID:      "org_remote",
		Scope:      "oclan-co/prod/github",
		Name:       "SYNC_KEY",
		Version:    1,
		Algorithm:  "aes-256-gcm",
		Nonce:      "nonce",
		Ciphertext: "ciphertext",
		AAD:        "aad",
	}}, []remoteSecretRecord{{
		OrgID:   "org_remote",
		Scope:   "oclan-co/prod/github",
		Name:    "SYNC_KEY",
		Version: 1,
		Status:  "active",
	}})
	if err == nil {
		t.Fatal("incomplete encrypted remote envelope should conflict")
	}
	if len(result.Upload) != 0 || result.SkippedExisting != 0 {
		t.Fatalf("incomplete remote envelope should not upload or skip: %#v", result)
	}
}

func TestPushReconcileRepairsMissingDeviceRecipient(t *testing.T) {
	localWrapped := store.RemoteWrappedKey{RecipientType: "device", RecipientID: "dev_remote", WrapAlgorithm: "p256-hkdf-aes256gcm", WrappedKey: "wrapped-local"}
	remoteWrapped := store.RemoteWrappedKey{RecipientType: "device", RecipientID: "dev_other", WrapAlgorithm: "p256-hkdf-aes256gcm", WrappedKey: "wrapped-remote"}
	result, err := reconcilePushVersions([]store.RemoteSecretVersion{{
		OrgID:       "org_remote",
		Scope:       "oclan-co/prod/github",
		Name:        "SYNC_KEY",
		Version:     1,
		Algorithm:   "aes-256-gcm",
		Nonce:       "nonce",
		Ciphertext:  "ciphertext",
		AAD:         "aad",
		WrappedKeys: []store.RemoteWrappedKey{localWrapped},
	}}, []remoteSecretRecord{{
		ID:          "secv_existing",
		OrgID:       "org_remote",
		Scope:       "oclan-co/prod/github",
		Name:        "SYNC_KEY",
		Version:     1,
		Algorithm:   "aes-256-gcm",
		Nonce:       "nonce",
		Ciphertext:  "ciphertext",
		AAD:         "aad",
		Status:      "active",
		WrappedKeys: []store.RemoteWrappedKey{remoteWrapped},
	}})
	if err != nil {
		t.Fatalf("same envelope with a missing device recipient should be repairable: %v", err)
	}
	if len(result.Upload) != 0 || result.SkippedExisting != 1 || len(result.Rewrap) != 1 {
		t.Fatalf("wrapped recipient mismatch should schedule rewrap: %#v", result)
	}
	if result.Rewrap[0].SecretID == "" || len(result.Rewrap[0].Missing) != 1 || result.Rewrap[0].Missing[0].RecipientID != "dev_remote" {
		t.Fatalf("unexpected rewrap candidate: %#v", result.Rewrap)
	}
}

func TestPushReconcileSkipsRemoteWrappedRecipientSuperset(t *testing.T) {
	localWrapped := store.RemoteWrappedKey{RecipientType: "device", RecipientID: "dev_remote", WrapAlgorithm: "p256-hkdf-aes256gcm", WrappedKey: "wrapped-local"}
	extraWrapped := store.RemoteWrappedKey{RecipientType: "device", RecipientID: "dev_other", WrapAlgorithm: "p256-hkdf-aes256gcm", WrappedKey: "wrapped-extra"}
	result, err := reconcilePushVersions([]store.RemoteSecretVersion{{
		OrgID:       "org_remote",
		Scope:       "oclan-co/prod/github",
		Name:        "SYNC_KEY",
		Version:     1,
		Algorithm:   "aes-256-gcm",
		Nonce:       "nonce",
		Ciphertext:  "ciphertext",
		AAD:         "aad",
		WrappedKeys: []store.RemoteWrappedKey{localWrapped},
	}}, []remoteSecretRecord{{
		OrgID:       "org_remote",
		Scope:       "oclan-co/prod/github",
		Name:        "SYNC_KEY",
		Version:     1,
		Algorithm:   "aes-256-gcm",
		Nonce:       "nonce",
		Ciphertext:  "ciphertext",
		AAD:         "aad",
		Status:      "active",
		WrappedKeys: []store.RemoteWrappedKey{localWrapped, extraWrapped},
	}})
	if err != nil {
		t.Fatalf("remote wrapped recipient superset should skip: %v", err)
	}
	if len(result.Upload) != 0 || result.SkippedExisting != 1 {
		t.Fatalf("remote wrapped recipient superset should skip existing: %#v", result)
	}
}
