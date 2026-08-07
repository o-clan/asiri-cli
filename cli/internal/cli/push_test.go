package cli

import (
	"bytes"
	"encoding/json"
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

func TestPushAndPullUseBearerAccessToken(t *testing.T) {
	if os.Getenv("ASIRI_MOUNT_BYTE_COMPARE_HELPER") == "1" {
		if len(os.Args) < 2 {
			t.Fatal("mount byte compare helper requires two paths")
		}
		mounted, err := os.ReadFile(os.Args[len(os.Args)-2])
		if err != nil {
			t.Fatal(err)
		}
		source, err := os.ReadFile(os.Args[len(os.Args)-1])
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(mounted, source) {
			t.Fatalf("mounted bytes changed: got %d bytes, want %d", len(mounted), len(source))
		}
		return
	}
	tmp := t.TempDir()
	old := os.Getenv("ASIRI_HOME")
	t.Cleanup(func() { _ = os.Setenv("ASIRI_HOME", old) })
	if err := os.Setenv("ASIRI_HOME", tmp); err != nil {
		t.Fatal(err)
	}
	sourceValue := testOpenSSHPrivateKey(t)
	sourcePath := testSecretBytesFile(t, sourceValue)
	mountedPath := filepath.Join(tmp, "mounted-private-key")
	secretPushCount := 0
	pushPlanCount := 0
	perSecretDiscoveryCount := 0
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
		case "/v1/sync/push-plan":
			pushPlanCount++
			encryptedSecrets := []map[string]any{}
			secretMetadata := []map[string]any{}
			if pushedSecret != nil {
				encryptedSecrets = append(encryptedSecrets, pushedSecret)
				secretMetadata = append(secretMetadata, pushedSecret)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"requestedWorkspaceSlug": "oclan-co",
				"workspace": map[string]any{
					"id":       "org_remote",
					"slug":     "oclan-co",
					"canWrite": true,
					"paths": []map[string]any{{
						"fullPath": "oclan-co/local/asiri/API_KEY",
						"scope":    "oclan-co/local/asiri",
						"name":     "API_KEY",
						"canWrite": true,
					}},
				},
				"targets": []map[string]any{{
					"scope": "oclan-co/local/asiri",
					"name":  "API_KEY",
					"devices": []map[string]any{
						{"id": "dev_remote", "name": "qa-laptop", "status": "trusted", "kind": "laptop", "encryptionPublicKey": devicePublicKey},
						{"id": "dev_other", "name": "server", "status": "trusted", "kind": "server", "encryptionPublicKey": devicePublicKey},
					},
				}},
				"recovery":         nil,
				"encryptedSecrets": encryptedSecrets,
				"secrets":          secretMetadata,
			})
		case "/v1/secrets/batch":
			secretPushCount++
			if r.Header.Get("authorization") != "Bearer at_push" {
				t.Fatalf("unexpected push auth header: %s", r.Header.Get("authorization"))
			}
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			uploads, ok := body["uploads"].([]any)
			if !ok || len(uploads) != 1 {
				t.Fatalf("unexpected push batch: %#v", body)
			}
			pushedSecret = uploads[0].(map[string]any)
			if pushedSecret["orgId"] != "org_remote" || pushedSecret["createdByDeviceId"] != "dev_remote" || pushedSecret["scope"] != "oclan-co/local/asiri" || pushedSecret["name"] != "API_KEY" {
				t.Fatalf("unexpected pushed secret body: %#v", pushedSecret)
			}
			wrapped, ok := pushedSecret["wrappedKeys"].([]any)
			if !ok || len(wrapped) != 2 {
				t.Fatalf("missing wrapped keys: %#v", pushedSecret["wrappedKeys"])
			}
			pushedSecret["id"] = "secv_remote"
			pushedSecret["status"] = "active"
			pushedSecret["createdAt"] = time.Now().UTC().Format(time.RFC3339)
			_ = json.NewEncoder(w).Encode(map[string]any{"saved": []map[string]any{{"id": "secv_remote", "status": "active"}}, "rewrapped": []map[string]any{}})
		case "/v1/secrets":
			if r.Method == http.MethodPost {
				t.Fatal("push must not post individual secrets")
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
			perSecretDiscoveryCount++
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
		{"init", "--device", "qa-laptop", "--workspace", "oclan-co"},
		{"add", "--workspace", "oclan-co", "local/asiri/API_KEY", "--value-file", sourcePath},
		{"login", "--origin", server.URL},
	} {
		out.Reset()
		errb.Reset()
		if code := app.Run(step); code != 0 {
			t.Fatalf("%v failed with code %d stderr=%s", step, code, errb.String())
		}
	}
	linkLocalWorkspaceForTest(t, "oclan-co")
	for _, step := range [][]string{
		{"push", "--workspace", "oclan-co"},
		{"push", "--workspace", "oclan-co"},
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
	delete(st.State.Secrets, store.SecretKey("oclan-co/local/asiri", "API_KEY"))
	if err := st.Save(); err != nil {
		t.Fatal(err)
	}
	oldCompareHelper := os.Getenv("ASIRI_MOUNT_BYTE_COMPARE_HELPER")
	t.Cleanup(func() { _ = os.Setenv("ASIRI_MOUNT_BYTE_COMPARE_HELPER", oldCompareHelper) })
	if err := os.Setenv("ASIRI_MOUNT_BYTE_COMPARE_HELPER", "1"); err != nil {
		t.Fatal(err)
	}
	for _, step := range [][]string{
		{"pull", "--workspace", "oclan-co"},
		{"rewrap", "--workspace", "oclan-co"},
		{"mount", "--workspace", "oclan-co", "local/asiri/API_KEY:" + mountedPath, "--", os.Args[0], "-test.run=^TestPushAndPullUseBearerAccessToken$", "--", mountedPath, sourcePath},
	} {
		out.Reset()
		errb.Reset()
		if code := app.Run(step); code != 0 {
			t.Fatalf("%v failed with code %d stderr=%s", step, code, errb.String())
		}
	}
	if secretPushCount != 1 || pushPlanCount != 2 || perSecretDiscoveryCount != 1 || !syncSeen {
		t.Fatalf("expected push and pull endpoints to be called")
	}
	if strings.Contains(out.String(), "BEGIN OPENSSH PRIVATE KEY") || strings.Contains(errb.String(), "BEGIN OPENSSH PRIVATE KEY") {
		t.Fatalf("push/pull leaked secret stdout=%q stderr=%q", out.String(), errb.String())
	}
}

func TestPushBatchesMultipleSecretsIntoOnePlanAndOneCommit(t *testing.T) {
	tmp := t.TempDir()
	old := os.Getenv("ASIRI_HOME")
	t.Cleanup(func() { _ = os.Setenv("ASIRI_HOME", old) })
	if err := os.Setenv("ASIRI_HOME", tmp); err != nil {
		t.Fatal(err)
	}
	planCalls := 0
	commitCalls := 0
	legacyCalls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		switch r.URL.Path {
		case "/v1/auth/device-code/start":
			_ = json.NewEncoder(w).Encode(map[string]any{"deviceCode": "dc_batch_push", "userCode": "BPSH-1234", "verificationUriComplete": serverURL(r) + "/auth/device?code=BPSH-1234", "expiresIn": 30, "interval": 0})
		case "/v1/auth/device-code/token":
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "approved", "orgId": "org_batch_push", "workspaceSlug": "oclan-co", "userId": "usr_owner", "deviceId": "dev_batch_push", "accessToken": "at_batch_push", "refreshToken": "rt_batch_push", "expiresIn": 3600, "refreshExpiresAt": time.Now().UTC().Add(7 * 24 * time.Hour).Format(time.RFC3339)})
		case "/v1/orgs":
			_ = json.NewEncoder(w).Encode(map[string]any{"organizations": []map[string]any{{"id": "org_batch_push", "slug": "oclan-co", "role": "owner", "canPull": true, "canWrite": true, "currentDeviceTrusted": true, "currentDeviceId": "dev_batch_push"}}})
		case "/v1/sync/push-plan":
			planCalls++
			_ = json.NewEncoder(w).Encode(map[string]any{
				"requestedWorkspaceSlug": "oclan-co",
				"workspace": map[string]any{"id": "org_batch_push", "slug": "oclan-co", "canWrite": true, "paths": []map[string]any{
					{"scope": "oclan-co/local/asiri", "name": "FIRST_KEY", "fullPath": "oclan-co/local/asiri/FIRST_KEY", "canWrite": true},
					{"scope": "oclan-co/local/asiri", "name": "SECOND_KEY", "fullPath": "oclan-co/local/asiri/SECOND_KEY", "canWrite": true},
				}},
				"targets": []map[string]any{
					{"scope": "oclan-co/local/asiri", "name": "FIRST_KEY", "devices": []map[string]any{}},
					{"scope": "oclan-co/local/asiri", "name": "SECOND_KEY", "devices": []map[string]any{}},
				},
				"recovery": nil, "encryptedSecrets": []map[string]any{}, "secrets": []map[string]any{},
			})
		case "/v1/secrets/batch":
			commitCalls++
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if uploads, ok := body["uploads"].([]any); !ok || len(uploads) != 2 {
				t.Fatalf("expected both secrets in one commit: %#v", body)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"saved": []map[string]any{{"id": "sec_first"}, {"id": "sec_second"}}, "rewrapped": []map[string]any{}})
		case "/v1/devices", "/v1/secrets", "/v1/secrets/encrypted", "/v1/sync/write-options":
			legacyCalls++
			http.NotFound(w, r)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	var out, errb bytes.Buffer
	app := New(&out, &errb)
	for _, step := range [][]string{
		{"init", "--device", "qa-laptop", "--workspace", "oclan-co"},
		{"add", "--workspace", "oclan-co", "local/asiri/FIRST_KEY", "--value-file", testSecretFile(t, "first")},
		{"add", "--workspace", "oclan-co", "local/asiri/SECOND_KEY", "--value-file", testSecretFile(t, "second")},
		{"login", "--origin", server.URL},
	} {
		out.Reset()
		errb.Reset()
		if code := app.Run(step); code != 0 {
			t.Fatalf("%v failed with code %d stderr=%s", step, code, errb.String())
		}
	}
	linkLocalWorkspaceForTest(t, "oclan-co")
	out.Reset()
	errb.Reset()
	if code := app.Run([]string{"push", "--workspace", "oclan-co"}); code != 0 {
		t.Fatalf("batched push failed: %s", errb.String())
	}
	if planCalls != 1 || commitCalls != 1 || legacyCalls != 0 {
		t.Fatalf("push request fan-out regressed: plans=%d commits=%d legacy=%d", planCalls, commitCalls, legacyCalls)
	}
}

func TestPushRejectsOversizedAtomicPayloadBeforeSending(t *testing.T) {
	_, err := encodeRemotePushBatch(remotePushBatchRequest{
		OrgID: "org_large_push",
		Uploads: []store.RemoteSecretVersion{{
			Scope:      "large/prod/api",
			Name:       "LARGE_KEY",
			Ciphertext: strings.Repeat("x", 256),
		}},
		Rewraps: []remotePushBatchRewrap{},
	}, 128)
	if err == nil {
		t.Fatal("oversized atomic push payload was accepted")
	}
	for _, expected := range []string{"atomic push payload", "above", "--scope", "--secret"} {
		if !strings.Contains(err.Error(), expected) {
			t.Fatalf("size error %q does not contain %q", err, expected)
		}
	}
}

func TestPushDryRunLinkedWorkspaceEvaluatesRemoteState(t *testing.T) {
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
				case "/v1/sync/push-plan":
					writeOptionsSeen = true
					devicesSeen = true
					encryptedSeen = true
					metadataSeen = true
					if remoteVersion == nil {
						t.Fatal("remote version was not prepared before dry-run push")
					}
					ciphertext := remoteVersion.Ciphertext
					if tc.conflict {
						ciphertext = "conflicting-ciphertext"
					}
					encryptedSecrets := []map[string]any{}
					if !tc.metadataOnlyConflict {
						encryptedSecrets = append(encryptedSecrets, map[string]any{
							"id": "sec_dry_run", "orgId": "org_dry_run", "scope": "oclan-co/local/asiri", "name": "API_KEY",
							"version": remoteVersion.Version, "algorithm": remoteVersion.Algorithm, "nonce": remoteVersion.Nonce,
							"ciphertext": ciphertext, "aad": remoteVersion.AAD, "status": "active",
							"wrappedKeys": []map[string]any{{"recipientType": "device", "recipientId": "dev_dry_run", "wrapAlgorithm": "p256-hkdf-aes256gcm", "wrappedKey": "remote-wrapped"}},
						})
					}
					metadataStatus := "active"
					if tc.metadataOnlyConflict {
						metadataStatus = "stale"
					}
					_ = json.NewEncoder(w).Encode(map[string]any{
						"requestedWorkspaceSlug": "oclan-co",
						"workspace": map[string]any{
							"id":       "org_dry_run",
							"slug":     "oclan-co",
							"canWrite": true,
							"paths": []map[string]any{{
								"fullPath": "oclan-co/local/asiri/API_KEY",
								"scope":    "oclan-co/local/asiri",
								"name":     "API_KEY",
								"canWrite": true,
							}},
						},
						"targets": []map[string]any{{"scope": "oclan-co/local/asiri", "name": "API_KEY", "devices": []map[string]any{
							{"id": "dev_dry_run", "name": "qa-laptop", "status": "trusted", "kind": "laptop", "encryptionPublicKey": devicePublicKey},
							{"id": "dev_other", "name": "server", "status": "trusted", "kind": "server", "encryptionPublicKey": devicePublicKey},
						}}},
						"recovery":         nil,
						"encryptedSecrets": encryptedSecrets,
						"secrets": []map[string]any{{
							"id": "sec_dry_run_meta", "orgId": "org_dry_run", "scope": "oclan-co/local/asiri", "name": "API_KEY",
							"version": remoteVersion.Version, "algorithm": remoteVersion.Algorithm, "status": metadataStatus,
						}},
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
				{"init", "--device", "qa-laptop", "--workspace", "oclan-co"},
				{"add", "--workspace", "oclan-co", "local/asiri/API_KEY", "--value-file", testSecretFile(t, "secret_value")},
				{"login", "--origin", server.URL},
			} {
				out.Reset()
				errb.Reset()
				if code := app.Run(step); code != 0 {
					t.Fatalf("%v failed with code %d stderr=%s", step, code, errb.String())
				}
			}
			linkLocalWorkspaceForTest(t, "oclan-co")
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
			if binding, ok := reloaded.RemoteBindingForPrefix("oclan-co"); !ok || binding.WorkspaceID != reloaded.State.ControlPlane.WorkspaceID {
				t.Fatalf("dry-run changed the existing workspace prefix binding: %#v", binding)
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
		case "/v1/sync/push-plan":
			if r.Header.Get("authorization") != "Bearer at_refreshed" {
				t.Fatalf("dry-run should reuse the refreshed account token, got %s", r.Header.Get("authorization"))
			}
			encryptedSeen = true
			_ = json.NewEncoder(w).Encode(map[string]any{
				"requestedWorkspaceSlug": "asiri-dev",
				"workspace": map[string]any{
					"id":       "org_asiri",
					"slug":     "asiri-dev",
					"canWrite": true,
					"paths": []map[string]any{{
						"fullPath": "asiri-dev/local/asiri/API_KEY",
						"scope":    "asiri-dev/local/asiri",
						"name":     "API_KEY",
						"canWrite": true,
					}},
				},
				"targets":  []map[string]any{{"scope": "asiri-dev/local/asiri", "name": "API_KEY", "devices": []map[string]any{}}},
				"recovery": nil, "encryptedSecrets": []map[string]any{}, "secrets": []map[string]any{},
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
		{"init", "--device", "qa-laptop", "--workspace", "asiri-dev"},
		{"add", "--workspace", "asiri-dev", "local/asiri/API_KEY", "--value-file", testSecretFile(t, "secret_value")},
		{"login", "--origin", server.URL},
	} {
		out.Reset()
		errb.Reset()
		if code := app.Run(step); code != 0 {
			t.Fatalf("%v failed with code %d stderr=%s", step, code, errb.String())
		}
	}
	linkLocalWorkspaceForTest(t, "asiri-dev", "org_asiri")
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
	if binding, ok := reloaded.RemoteBindingForPrefix("asiri-dev"); !ok || binding.WorkspaceID != "org_asiri" {
		t.Fatalf("dry-run changed the existing remote workspace binding: %#v", binding)
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
		case "/v1/sync/push-plan":
			http.Error(w, `{"error":"temporarily unavailable"}`, http.StatusServiceUnavailable)
		case "/v1/secrets/batch":
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
		{"init", "--device", "qa-laptop", "--workspace", "oclan-co"},
		{"add", "--workspace", "oclan-co", "local/asiri/API_KEY", "--value-file", testSecretFile(t, "secret_value")},
		{"login", "--origin", server.URL},
	} {
		out.Reset()
		errb.Reset()
		if code := app.Run(step); code != 0 {
			t.Fatalf("%v failed with code %d stderr=%s", step, code, errb.String())
		}
	}

	linkLocalWorkspaceForTest(t, "oclan-co")
	out.Reset()
	errb.Reset()
	if code := app.Run([]string{"push", "--workspace", "oclan-co"}); code == 0 {
		t.Fatal("push should fail when trusted-device discovery fails")
	}
	if postSeen {
		t.Fatal("push should not upload secrets after trusted-device discovery fails")
	}
	if !strings.Contains(errb.String(), "control plane returned HTTP 503") {
		t.Fatalf("missing push-plan failure: %s", errb.String())
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
		{"init", "--device", "qa-laptop", "--workspace", "oclan-co"},
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

func TestPushReconcileBlocksTombstonedVersionAndNamesTheKey(t *testing.T) {
	local := []store.RemoteSecretVersion{{OrgID: "org_remote", Scope: "oclan-co/prod/github", Name: "SYNC_KEY", Version: 1}}
	tombstones := []asiri.SecretTombstone{{WorkspaceID: "org_remote", Scope: "oclan-co/prod/github", Name: "SYNC_KEY", DeletedThroughVersion: 1}}
	result, err := reconcilePushVersionsWithTombstones(local, nil, tombstones, nil, "org_remote")
	if err == nil || !strings.Contains(err.Error(), "oclan-co/prod/github/SYNC_KEY v1") || !strings.Contains(err.Error(), "asiri sync --workspace oclan-co") || !strings.Contains(err.Error(), "add or rotate") {
		t.Fatalf("expected actionable tombstone conflict, got result=%#v err=%v", result, err)
	}
	if len(result.Upload) != 0 || len(result.Recreate) != 0 {
		t.Fatalf("tombstoned version must not be uploaded: %#v", result)
	}
}

func TestPushReconcileStillNamesTombstonedVersionAfterRecreation(t *testing.T) {
	local := []store.RemoteSecretVersion{{OrgID: "org_remote", Scope: "oclan-co/prod/github", Name: "SYNC_KEY", Version: 1}}
	remote := []remoteSecretRecord{{
		OrgID: "org_remote", Scope: "oclan-co/prod/github", Name: "SYNC_KEY", Version: 2, Status: "active",
		Algorithm: "aes-256-gcm", Nonce: "nonce-v2", Ciphertext: "ciphertext-v2", AAD: "aad-v2",
	}}
	tombstones := []asiri.SecretTombstone{{WorkspaceID: "org_remote", Scope: "oclan-co/prod/github", Name: "SYNC_KEY", DeletedThroughVersion: 1}}
	result, err := reconcilePushVersionsWithTombstones(local, remote, tombstones, nil, "org_remote")
	if err == nil || !strings.Contains(err.Error(), "oclan-co/prod/github/SYNC_KEY v1") || !strings.Contains(err.Error(), "asiri sync --workspace oclan-co") {
		t.Fatalf("expected the recreated path to retain its tombstone hint, got result=%#v err=%v", result, err)
	}
	if result.SkippedOlder != 0 || len(result.Upload) != 0 {
		t.Fatalf("tombstoned version must not be silently treated as an older upload: %#v", result)
	}

	matchingV2 := []store.RemoteSecretVersion{{
		OrgID: "org_remote", Scope: "oclan-co/prod/github", Name: "SYNC_KEY", Version: 2,
		Algorithm: "aes-256-gcm", Nonce: "nonce-v2", Ciphertext: "ciphertext-v2", AAD: "aad-v2",
	}}
	result, err = reconcilePushVersionsWithTombstones(matchingV2, remote, tombstones, nil, "org_remote")
	if err != nil || result.SkippedExisting != 1 || len(result.Upload) != 0 {
		t.Fatalf("matching recreated v2 should remain idempotent, got result=%#v err=%v", result, err)
	}
	newerV3 := []store.RemoteSecretVersion{{OrgID: "org_remote", Scope: "oclan-co/prod/github", Name: "SYNC_KEY", Version: 3}}
	result, err = reconcilePushVersionsWithTombstones(newerV3, remote, tombstones, nil, "org_remote")
	if err != nil || len(result.Upload) != 1 || result.Upload[0].Version != 3 {
		t.Fatalf("normal rotation after recreated v2 should remain publishable, got result=%#v err=%v", result, err)
	}
}

func TestWritablePushRefsKeepsOnlyAuthorizedSyncPaths(t *testing.T) {
	refs := []store.LocalSecretRef{
		{Scope: "oclan-co/prod", Name: "READ_ONLY", Version: 1},
		{Scope: "oclan-co/prod", Name: "WRITABLE", Version: 2},
	}
	paths := []writePathOption{
		{Scope: "oclan-co/prod", Name: "READ_ONLY", CanWrite: false},
		{Scope: "oclan-co/prod", Name: "WRITABLE", CanWrite: true},
	}
	writable, err := writablePushRefs(refs, paths)
	if err != nil || len(writable) != 1 || writable[0].Name != "WRITABLE" {
		t.Fatalf("expected only the authorized sync path, got %#v err=%v", writable, err)
	}
	if _, err := writablePushRefs(refs, paths[:1]); err == nil {
		t.Fatal("missing path permissions must fail closed")
	}
}

func TestPushReconcileAllowsReconciledRecreationAfterAdditionalLocalRotations(t *testing.T) {
	reconciledAt := time.Now().UTC().Add(-time.Minute)
	local := []store.RemoteSecretVersion{{OrgID: "org_remote", Scope: "oclan-co/prod/github", Name: "SYNC_KEY", Version: 2, CreatedAt: reconciledAt.Add(time.Second)}}
	tombstone := asiri.SecretTombstone{WorkspaceID: "org_remote", Scope: "oclan-co/prod/github", Name: "SYNC_KEY", DeletedThroughVersion: 1}
	if _, err := reconcilePushVersionsWithTombstones(local, nil, []asiri.SecretTombstone{tombstone}, nil, "org_remote"); err == nil {
		t.Fatal("an unreconciled device must not recreate a tombstoned secret")
	}
	localTombstone := tombstone
	localTombstone.ReconciledAt = reconciledAt
	localLedger := map[string]asiri.SecretTombstone{store.SecretTombstoneKey("org_remote", tombstone.Scope, tombstone.Name): localTombstone}
	result, err := reconcilePushVersionsWithTombstones(local, nil, []asiri.SecretTombstone{tombstone}, localLedger, "org_remote")
	if err != nil {
		t.Fatalf("reconciled next version should be publishable: %v", err)
	}
	if len(result.Upload) != 1 || len(result.Recreate) != 1 || result.Recreate[0].DeletedThroughVersion != 1 {
		t.Fatalf("expected v2 upload with recreation proof, got %#v", result)
	}
	local[0].Version = 3
	local[0].CreatedAt = reconciledAt.Add(2 * time.Second)
	result, err = reconcilePushVersionsWithTombstones(local, nil, []asiri.SecretTombstone{tombstone}, localLedger, "org_remote")
	if err != nil || len(result.Upload) != 1 || result.Upload[0].Version != 3 || len(result.Recreate) != 1 {
		t.Fatalf("recreated secret rotated again before push should remain publishable, got result=%#v err=%v", result, err)
	}
	local[0].Version = 2
	local[0].CreatedAt = reconciledAt.Add(-time.Second)
	if _, err := reconcilePushVersionsWithTombstones(local, nil, []asiri.SecretTombstone{tombstone}, localLedger, "org_remote"); err == nil {
		t.Fatal("a version created before tombstone reconciliation must not masquerade as an explicit recreation")
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

func TestPushReconcileUsesMetadataToAvoidRedundantRewrap(t *testing.T) {
	currentWrapped := store.RemoteWrappedKey{RecipientType: "device", RecipientID: "dev_current", WrapAlgorithm: "p256-hkdf-aes256gcm", WrappedKey: "wrapped-current"}
	otherWrapped := store.RemoteWrappedKey{RecipientType: "device", RecipientID: "dev_other", WrapAlgorithm: "p256-hkdf-aes256gcm", WrappedKey: "wrapped-other"}
	encrypted := remoteSecretRecord{
		ID: "secv_existing", OrgID: "org_remote", Scope: "oclan-co/prod/github", Name: "SYNC_KEY", Version: 1,
		Algorithm: "aes-256-gcm", Nonce: "nonce", Ciphertext: "ciphertext", AAD: "aad", Status: "active",
		WrappedKeys: []store.RemoteWrappedKey{currentWrapped},
	}
	metadata := remoteSecretRecord{
		ID: "secv_existing", OrgID: "org_remote", Scope: "oclan-co/prod/github", Name: "SYNC_KEY", Version: 1, Status: "active",
		WrappedRecipients: []remoteWrappedRecipient{
			{RecipientType: "device", RecipientID: "dev_current", WrapAlgorithm: "p256-hkdf-aes256gcm"},
			{RecipientType: "device", RecipientID: "dev_other", WrapAlgorithm: "p256-hkdf-aes256gcm"},
		},
	}

	result, err := reconcilePushVersions([]store.RemoteSecretVersion{{
		OrgID: "org_remote", Scope: "oclan-co/prod/github", Name: "SYNC_KEY", Version: 1,
		Algorithm: "aes-256-gcm", Nonce: "nonce", Ciphertext: "ciphertext", AAD: "aad",
		WrappedKeys: []store.RemoteWrappedKey{currentWrapped, otherWrapped},
	}}, mergeRemoteSecretRecords([]remoteSecretRecord{encrypted}, []remoteSecretRecord{metadata}))
	if err != nil {
		t.Fatalf("recipient metadata should make an unchanged secret comparable: %v", err)
	}
	if len(result.Upload) != 0 || len(result.Rewrap) != 0 || result.SkippedExisting != 1 {
		t.Fatalf("known remote recipients should avoid a redundant commit: %#v", result)
	}
}
