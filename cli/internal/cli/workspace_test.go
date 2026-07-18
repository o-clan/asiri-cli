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

func TestWorkspaceTreeUsesOneCompactRequestAndRendersTextAndJSON(t *testing.T) {
	tmp := t.TempDir()
	old := os.Getenv("ASIRI_HOME")
	t.Cleanup(func() { _ = os.Setenv("ASIRI_HOME", old) })
	if err := os.Setenv("ASIRI_HOME", tmp); err != nil {
		t.Fatal(err)
	}
	treeRequests := 0
	includeRevokedSeen := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		switch r.URL.Path {
		case "/v1/auth/device-code/start":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"deviceCode": "dc_workspace_tree", "userCode": "TREE-1234",
				"verificationUriComplete": serverURL(r) + "/auth/device?code=TREE-1234", "expiresIn": 30, "interval": 0,
			})
		case "/v1/auth/device-code/token":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status": "approved", "orgId": "org_oclan", "workspaceSlug": "oclan-co", "userId": "usr_owner", "deviceId": "dev_owner",
				"accessToken": "at_workspace_tree", "refreshToken": "rt_workspace_tree", "expiresIn": 3600,
				"refreshExpiresAt": time.Now().UTC().Add(7 * 24 * time.Hour).Format(time.RFC3339),
			})
		case "/v1/workspace-tree":
			treeRequests++
			if r.Header.Get("authorization") != "Bearer at_workspace_tree" {
				t.Fatalf("unexpected tree auth header: %s", r.Header.Get("authorization"))
			}
			if r.URL.Query().Get("workspace") != "oclan-co" {
				t.Fatalf("unexpected tree workspace: %s", r.URL.RawQuery)
			}
			includeRevokedSeen = r.URL.Query().Get("includeRevoked") == "1"
			devices := []map[string]any{{"id": "dev_owner", "name": "owner-laptop", "kind": "laptop", "status": "trusted", "serviceAccountAuth": []map[string]any{{"id": "svc_runtime", "slug": "runtime", "name": "Runtime"}}}}
			if includeRevokedSeen {
				devices = append(devices, map[string]any{"id": "dev_old", "name": "old-laptop", "kind": "laptop", "status": "revoked"})
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"workspace": map[string]any{"id": "org_oclan", "slug": "oclan-co", "secretCount": 3},
				"users": []map[string]any{
					{"id": "usr_owner", "displayName": "Owner", "email": "owner@example.com", "role": "owner", "status": "active", "accessibleSecretCount": 3, "devices": devices, "access": []map[string]any{{"targetType": "envelope", "scope": "oclan-co", "includeDescendants": true, "matchedSecretCount": 3}}},
					{"id": "usr_member", "displayName": "Member", "email": "member@example.com", "role": "member", "status": "active", "accessibleSecretCount": 1, "devices": []map[string]any{}, "access": []map[string]any{{"grantId": "grant_1", "targetType": "secret", "scope": "oclan-co/prod/api", "secretName": "TOKEN", "matchedSecretCount": 1}}},
				},
			})
		case "/v1/orgs":
			t.Fatal("workspace tree should not require a separate workspace-list request")
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	var out bytes.Buffer
	var errb bytes.Buffer
	app := New(&out, &errb)
	for _, step := range [][]string{{"init", "--device", "owner-laptop"}, {"login", "--origin", server.URL}} {
		out.Reset()
		errb.Reset()
		if code := app.Run(step); code != 0 {
			t.Fatalf("%v failed with code %d stderr=%s", step, code, errb.String())
		}
	}

	out.Reset()
	errb.Reset()
	if code := app.Run([]string{"workspace", "tree", "--workspace", "oclan-co"}); code != 0 {
		t.Fatalf("workspace tree failed with code %d stderr=%s", code, errb.String())
	}
	for _, expected := range []string{"oclan-co · 3 secrets", "Owner <owner@example.com> · owner · 3 accessible", "owner-laptop · laptop · trusted · service session: runtime", "/ · recursive · 3 secrets", "Member <member@example.com> · member · 1 accessible", "prod/api/TOKEN · secret · 1 secret", "none"} {
		if !strings.Contains(out.String(), expected) {
			t.Fatalf("workspace tree missing %q: %s", expected, out.String())
		}
	}
	if treeRequests != 1 {
		t.Fatalf("expected one tree request, got %d", treeRequests)
	}

	out.Reset()
	errb.Reset()
	if code := app.Run([]string{"workspace", "tree", "--workspace", "oclan-co", "--json"}); code != 0 {
		t.Fatalf("workspace tree JSON failed with code %d stderr=%s", code, errb.String())
	}
	var tree remoteWorkspaceTreeResponse
	if err := json.Unmarshal(out.Bytes(), &tree); err != nil {
		t.Fatalf("invalid workspace tree JSON: %v output=%s", err, out.String())
	}
	if tree.Workspace.SecretCount != 3 || len(tree.Users) != 2 || tree.Users[1].SecretCount != 1 {
		t.Fatalf("unexpected workspace tree JSON: %#v", tree)
	}

	out.Reset()
	errb.Reset()
	if code := app.Run([]string{"workspace", "tree", "--workspace", "oclan-co", "--include-revoked"}); code != 0 {
		t.Fatalf("workspace tree with revoked devices failed with code %d stderr=%s", code, errb.String())
	}
	if !includeRevokedSeen || !strings.Contains(out.String(), "old-laptop · laptop · revoked") {
		t.Fatalf("workspace tree did not include revoked device: %s", out.String())
	}

	requestsBeforeInvalid := treeRequests
	out.Reset()
	errb.Reset()
	if code := app.Run([]string{"workspace", "tree", "--workspace", "oclan-co", "--unexpected"}); code == 0 {
		t.Fatal("workspace tree should reject unknown flags")
	}
	if treeRequests != requestsBeforeInvalid {
		t.Fatal("workspace tree made a request before rejecting unknown flags")
	}
}

func TestValidateRemoteWorkspaceTreeRejectsMalformedMetadata(t *testing.T) {
	valid := remoteWorkspaceTreeResponse{
		Workspace: remoteWorkspaceTreeWorkspace{ID: "org_1", Slug: "olom-dev", SecretCount: 2},
		Users: []remoteWorkspaceTreeUser{{
			ID: "usr_1", SecretCount: 1,
			Devices: []remoteWorkspaceTreeDevice{{ID: "dev_1", Status: "trusted", ServiceAccountAuth: []remoteWorkspaceTreeServiceAccount{{ID: "svc_1", Slug: "runtime"}}}},
			Access:  []remoteWorkspaceTreeAccess{{Scope: "olom-dev/prod", SecretCount: 1}},
		}},
	}
	if err := validateRemoteWorkspaceTree(valid, "olom-dev", false); err != nil {
		t.Fatalf("valid tree rejected: %v", err)
	}
	tests := []struct {
		name string
		edit func(*remoteWorkspaceTreeResponse)
	}{
		{"wrong workspace", func(tree *remoteWorkspaceTreeResponse) { tree.Workspace.Slug = "other" }},
		{"negative total", func(tree *remoteWorkspaceTreeResponse) { tree.Workspace.SecretCount = -1 }},
		{"impossible user count", func(tree *remoteWorkspaceTreeResponse) { tree.Users[0].SecretCount = 3 }},
		{"foreign scope", func(tree *remoteWorkspaceTreeResponse) { tree.Users[0].Access[0].Scope = "other/prod" }},
		{"unexpected revoked device", func(tree *remoteWorkspaceTreeResponse) { tree.Users[0].Devices[0].Status = "revoked" }},
		{"invalid service account auth", func(tree *remoteWorkspaceTreeResponse) { tree.Users[0].Devices[0].ServiceAccountAuth[0].Slug = "" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := valid
			candidate.Users = append([]remoteWorkspaceTreeUser(nil), valid.Users...)
			candidate.Users[0].Devices = append([]remoteWorkspaceTreeDevice(nil), valid.Users[0].Devices...)
			candidate.Users[0].Devices[0].ServiceAccountAuth = append([]remoteWorkspaceTreeServiceAccount(nil), valid.Users[0].Devices[0].ServiceAccountAuth...)
			candidate.Users[0].Access = append([]remoteWorkspaceTreeAccess(nil), valid.Users[0].Access...)
			test.edit(&candidate)
			if err := validateRemoteWorkspaceTree(candidate, "olom-dev", false); err == nil {
				t.Fatal("malformed tree accepted")
			}
		})
	}
}

func TestWorkspaceListAndUseDoesNotBindLocalPrefixBeforePushOrSync(t *testing.T) {
	tmp := t.TempDir()
	old := os.Getenv("ASIRI_HOME")
	t.Cleanup(func() { _ = os.Setenv("ASIRI_HOME", old) })
	if err := os.Setenv("ASIRI_HOME", tmp); err != nil {
		t.Fatal(err)
	}
	switchSeen := false
	switchBackSeen := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		switch r.URL.Path {
		case "/v1/auth/device-code/start":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"deviceCode":              "dc_workspace",
				"userCode":                "WORK-1234",
				"verificationUri":         serverURL(r) + "/auth/device",
				"verificationUriComplete": serverURL(r) + "/auth/device?code=WORK-1234",
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
		case "/v1/orgs":
			auth := r.Header.Get("authorization")
			if auth != "Bearer at_oclan" && auth != "Bearer at_personal" && auth != "Bearer at_oclan2" {
				t.Fatalf("unexpected org list auth header: %s", auth)
			}
			active := "org_oclan"
			if auth == "Bearer at_personal" {
				active = "org_personal"
			}
			response := map[string]any{
				"activeOrgId": active,
				"organizations": []map[string]any{
					{"id": "org_oclan", "name": "O Clan", "slug": "oclan-co", "ownerUserId": "usr_owner", "role": "owner", "canPull": true, "canWrite": true},
					{"id": "org_personal", "name": "Peter Dev", "slug": "peter-dev", "ownerUserId": "usr_owner", "role": "owner", "canPull": true, "canWrite": true},
				},
			}
			if r.URL.Query().Get("includeSecrets") == "1" {
				response["secrets"] = []map[string]any{}
			}
			_ = json.NewEncoder(w).Encode(response)
		case "/v1/auth/session/switch":
			var body map[string]string
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if body["deviceName"] != "qa-laptop" || body["encryptionPublicKey"] == "" || body["signingPublicKey"] == "" {
				t.Fatalf("unexpected switch body: %#v", body)
			}
			switch body["workspace"] {
			case "peter-dev":
				switchSeen = true
				if r.Header.Get("authorization") != "Bearer at_oclan" {
					t.Fatalf("unexpected switch auth header: %s", r.Header.Get("authorization"))
				}
				_ = json.NewEncoder(w).Encode(map[string]any{
					"status":           "approved",
					"orgId":            "org_personal",
					"workspaceSlug":    "peter-dev",
					"userId":           "usr_owner",
					"deviceId":         "dev_personal",
					"accessToken":      "at_personal",
					"refreshToken":     "rt_personal",
					"expiresIn":        3600,
					"refreshExpiresAt": time.Now().UTC().Add(7 * 24 * time.Hour).Format(time.RFC3339),
				})
			case "oclan-co":
				switchBackSeen = true
				if r.Header.Get("authorization") != "Bearer at_personal" {
					t.Fatalf("unexpected switch-back auth header: %s", r.Header.Get("authorization"))
				}
				_ = json.NewEncoder(w).Encode(map[string]any{
					"status":           "approved",
					"orgId":            "org_oclan",
					"workspaceSlug":    "oclan-co",
					"userId":           "usr_owner",
					"deviceId":         "dev_oclan",
					"accessToken":      "at_oclan2",
					"refreshToken":     "rt_oclan2",
					"expiresIn":        3600,
					"refreshExpiresAt": time.Now().UTC().Add(7 * 24 * time.Hour).Format(time.RFC3339),
				})
			default:
				t.Fatalf("unexpected workspace switch target: %#v", body)
			}
		case "/v1/sync/write-options":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"requestedWorkspaceSlug": "oclan-co",
				"sourceWorkspace": map[string]any{
					"id":       "org_oclan",
					"slug":     "oclan-co",
					"canWrite": true,
					"paths": []map[string]any{{
						"fullPath": "oclan-co/local/asiri/API_KEY",
						"canWrite": true,
					}},
				},
				"workspace": map[string]any{
					"id":       "org_personal",
					"slug":     "peter-dev",
					"canWrite": false,
					"paths": []map[string]any{{
						"fullPath": "peter-dev/local/asiri/API_KEY",
						"canWrite": false,
					}},
				},
				"writableWorkspaces": []map[string]any{{
					"id":       "org_oclan",
					"slug":     "oclan-co",
					"canWrite": true,
					"paths": []map[string]any{{
						"fullPath": "oclan-co/local/asiri/API_KEY",
						"canWrite": true,
					}},
				}},
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
	if _, ok := st.RemoteBindingForPrefix("oclan-co"); ok {
		t.Fatalf("login should not bind local prefix before push or pull: %#v", st.State.RemoteBindings)
	}
	out.Reset()
	errb.Reset()
	if code := app.Run([]string{"add", "--workspace", "oclan-co", "peter-dev/local/asiri/API_KEY", "--value-file", testSecretFile(t, "secret_value")}); code == 0 {
		t.Fatal("visible workspace-prefixed path should fail")
	}
	if !strings.Contains(errb.String(), "add accepts short paths") {
		t.Fatalf("expected short-path guidance for visible workspace prefix, got %s", errb.String())
	}
	out.Reset()
	errb.Reset()
	if code := app.Run([]string{"workspace", "list"}); code != 0 {
		t.Fatalf("workspace list failed: %s", errb.String())
	}
	if strings.Contains(out.String(), "ACTIVE") || strings.Contains(out.String(), "PULL") || !strings.Contains(out.String(), "WORKSPACE") || !strings.Contains(out.String(), "THIS DEVICE") || !strings.Contains(out.String(), "ACCOUNT WRITE") || !strings.Contains(out.String(), "oclan-co") || !strings.Contains(out.String(), "owner") || !strings.Contains(out.String(), "trusted") || !strings.Contains(out.String(), "peter-dev") {
		t.Fatalf("workspace list output missing expected workspaces: %s", out.String())
	}
	out.Reset()
	errb.Reset()
	if code := app.Run([]string{"workspace", "use", "peter-dev"}); code == 0 {
		t.Fatalf("workspace use should be removed")
	}
	if switchSeen || !strings.Contains(errb.String(), "--workspace") {
		t.Fatalf("workspace use should not switch sessions: stdout=%s stderr=%s", out.String(), errb.String())
	}
	out.Reset()
	errb.Reset()
	if code := app.Run([]string{"push"}); code == 0 {
		t.Fatalf("push should require explicit workspace")
	}
	if switchBackSeen || !strings.Contains(errb.String(), "push requires --workspace") {
		t.Fatalf("push block did not explain explicit workspace requirement: %s", errb.String())
	}
	st, err = store.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := st.RemoteBindingForPrefix("oclan-co"); ok || st.State.ControlPlane == nil || st.State.ControlPlane.WorkspaceID != "org_oclan" {
		t.Fatalf("prefix binding or control-plane transport changed unexpectedly: %#v", st.State)
	}
}

func TestWorkspaceListUsesCombinedWorkspaceOverview(t *testing.T) {
	tmp := t.TempDir()
	old := os.Getenv("ASIRI_HOME")
	t.Cleanup(func() { _ = os.Setenv("ASIRI_HOME", old) })
	if err := os.Setenv("ASIRI_HOME", tmp); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		switch r.URL.Path {
		case "/v1/orgs":
			assertWorkspaceOverviewTarget(t, r, "")
			if r.URL.Query().Get("includeSecrets") != "1" {
				t.Fatalf("workspace list should request combined overview, got %s", r.URL.RawQuery)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"activeOrgId": "org_remote",
				"organizations": []map[string]any{{
					"id": "org_remote", "name": "O Clan", "slug": "oclan-co", "ownerUserId": "usr_owner", "role": "owner", "canPull": true, "canWrite": true, "currentDeviceTrusted": true,
				}},
				"secrets": []map[string]any{{
					"id": "sec_remote", "orgId": "org_remote", "workspaceSlug": "oclan-co", "scope": "oclan-co/local/asiri", "name": "API_KEY", "version": 1, "status": "active", "canWrite": true, "wrappedToCurrentDevice": true, "currentDeviceId": "dev_remote",
				}},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	var out, errb bytes.Buffer
	app := New(&out, &errb)
	if code := app.Run([]string{"init", "--device", "qa-laptop"}); code != 0 {
		t.Fatalf("init failed: %s", errb.String())
	}
	st, err := store.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	device, err := st.ActiveDevice()
	if err != nil {
		t.Fatal(err)
	}
	if err := st.LinkControlPlaneForDevice(server.URL, "org_remote", "oclan-co", "usr_owner", "dev_remote", device.ID, "at_cached", "rt_cached", 3600, time.Now().UTC().Add(7*24*time.Hour).Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	errb.Reset()
	if code := app.Run([]string{"workspace", "list"}); code != 0 {
		t.Fatalf("workspace list failed: %s", errb.String())
	}
	if !strings.Contains(out.String(), "oclan-co") || !strings.Contains(out.String(), "ready") {
		t.Fatalf("workspace list did not use included secret metadata: %s", out.String())
	}
}
