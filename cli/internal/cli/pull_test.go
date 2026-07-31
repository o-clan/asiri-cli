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

	"github.com/o-clan/asiri/cli/internal/store"
)

func TestPullRequiresExactlyOneWorkspace(t *testing.T) {
	if _, err := parsePullArgs(nil); err == nil || !strings.Contains(err.Error(), "requires --workspace") {
		t.Fatalf("pull without workspace should fail, got %v", err)
	}
	if _, err := parsePullArgs([]string{"--workspace", "prod", "--workspace", "staging"}); err == nil || !strings.Contains(err.Error(), "accepts one --workspace") {
		t.Fatalf("pull with two workspaces should fail, got %v", err)
	}
}

func TestValidateSyncBundleTarget(t *testing.T) {
	workspace := remoteWorkspaceResponse{ID: "org_testamy", CurrentDeviceID: "dev_testamy"}
	tests := []struct {
		name   string
		bundle syncBundleResponse
		ok     bool
	}{
		{name: "exact target", bundle: syncBundleResponse{OrgID: "org_testamy", DeviceID: "dev_testamy"}, ok: true},
		{name: "missing workspace", bundle: syncBundleResponse{DeviceID: "dev_testamy"}},
		{name: "missing device", bundle: syncBundleResponse{OrgID: "org_testamy"}},
		{name: "different workspace", bundle: syncBundleResponse{OrgID: "org_other", DeviceID: "dev_testamy"}},
		{name: "different device", bundle: syncBundleResponse{OrgID: "org_testamy", DeviceID: "dev_other"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateSyncBundleTarget(test.bundle, workspace)
			if test.ok && err != nil {
				t.Fatalf("exact bundle rejected: %v", err)
			}
			if !test.ok && err == nil {
				t.Fatal("invalid bundle identity accepted")
			}
		})
	}
}

func TestPullTargetsOneWorkspaceWithoutSwitchingSession(t *testing.T) {
	tmp := t.TempDir()
	old := os.Getenv("ASIRI_HOME")
	t.Cleanup(func() { _ = os.Setenv("ASIRI_HOME", old) })
	if err := os.Setenv("ASIRI_HOME", tmp); err != nil {
		t.Fatal(err)
	}
	switchRecallSeen := false
	switchAsiriSeen := false
	restoreSeen := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		switch r.URL.Path {
		case "/v1/auth/device-code/start":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"deviceCode":              "dc_pull_all",
				"userCode":                "PULL-ALL",
				"verificationUri":         serverURL(r) + "/auth/device",
				"verificationUriComplete": serverURL(r) + "/auth/device?code=PULL-ALL",
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
			var body map[string]string
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			token := "at_oclan_refreshed"
			if body["refreshToken"] == "rt_oclan2" {
				token = "at_oclan_refreshed2"
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status":           "approved",
				"orgId":            "org_oclan",
				"workspaceSlug":    "oclan-co",
				"userId":           "usr_owner",
				"deviceId":         "dev_oclan",
				"accessToken":      token,
				"expiresIn":        3600,
				"refreshExpiresAt": time.Now().UTC().Add(7 * 24 * time.Hour).Format(time.RFC3339),
			})
		case "/v1/orgs":
			auth := r.Header.Get("authorization")
			if auth != "Bearer at_oclan" && auth != "Bearer at_oclan2" && auth != "Bearer at_recall" {
				t.Fatalf("unexpected org list auth header: %s", auth)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"activeOrgId": "org_oclan",
				"organizations": []map[string]any{
					{"id": "org_oclan", "name": "O Clan", "slug": "oclan-co", "ownerUserId": "usr_owner", "role": "owner", "canPull": true, "canWrite": true, "currentDeviceTrusted": true, "currentDeviceId": "dev_oclan"},
					{"id": "org_asiri", "name": "Asiri Dev", "slug": "asiri-dev", "ownerUserId": "usr_owner", "role": "owner", "canPull": false, "canWrite": true, "currentDeviceTrusted": false},
					{"id": "org_recall", "name": "Recallstack", "slug": "recallstack-com", "ownerUserId": "usr_other", "role": "member", "canPull": true, "canWrite": false, "currentDeviceTrusted": true, "currentDeviceId": "dev_recall"},
				},
			})
		case "/v1/auth/session/switch":
			var body map[string]string
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			switch body["workspace"] {
			case "org_recall":
				switchRecallSeen = true
				if r.Header.Get("authorization") != "Bearer at_oclan" {
					t.Fatalf("unexpected recall switch auth header: %s", r.Header.Get("authorization"))
				}
				_ = json.NewEncoder(w).Encode(map[string]any{
					"status":           "approved",
					"orgId":            "org_recall",
					"workspaceSlug":    "recallstack-com",
					"userId":           "usr_owner",
					"deviceId":         "dev_recall",
					"accessToken":      "at_recall",
					"refreshToken":     "rt_recall",
					"expiresIn":        3600,
					"refreshExpiresAt": time.Now().UTC().Add(7 * 24 * time.Hour).Format(time.RFC3339),
				})
			case "org_asiri":
				switchAsiriSeen = true
				t.Fatal("ineligible workspace should not be switched to during pull")
			case "org_oclan":
				restoreSeen = true
				if r.Header.Get("authorization") != "Bearer at_recall" {
					t.Fatalf("unexpected restore auth header: %s", r.Header.Get("authorization"))
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
				t.Fatalf("unexpected switch target: %#v", body)
			}
		case "/v1/sync":
			auth := r.Header.Get("authorization")
			orgID := r.URL.Query().Get("orgId")
			deviceID := r.URL.Query().Get("deviceId")
			if orgID == "org_oclan" {
				if auth != "Bearer at_oclan" || deviceID != "dev_oclan" {
					t.Fatalf("unexpected active sync request auth=%s query=%s", auth, r.URL.RawQuery)
				}
			} else if orgID == "org_recall" {
				if auth != "Bearer at_oclan" || deviceID != "dev_recall" {
					t.Fatalf("unexpected recall sync request auth=%s query=%s", auth, r.URL.RawQuery)
				}
			} else {
				t.Fatalf("unexpected sync org: %s", orgID)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"orgId":            orgID,
				"deviceId":         deviceID,
				"issuedAt":         time.Now().UTC().Format(time.RFC3339),
				"encryptedSecrets": []map[string]any{},
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
	out.Reset()
	errb.Reset()
	if code := app.Run([]string{"pull", "--workspace", "recallstack-com"}); code != 0 {
		t.Fatalf("pull failed with code %d stderr=%s stdout=%s", code, errb.String(), out.String())
	}
	allOutput := out.String()
	for _, expected := range []string{"WORKSPACE", "pulled", "recallstack-com"} {
		if !strings.Contains(allOutput, expected) {
			t.Fatalf("pull output missing %q: %s", expected, allOutput)
		}
	}
	if switchRecallSeen || switchAsiriSeen || restoreSeen {
		t.Fatalf("unexpected switch behavior: recall=%v asiri=%v restore=%v", switchRecallSeen, switchAsiriSeen, restoreSeen)
	}

	out.Reset()
	errb.Reset()
	if code := app.Run([]string{"pull", "--workspace", "asiri-dev"}); code == 0 {
		t.Fatalf("untrusted workspace pull should fail, stderr=%s stdout=%s", errb.String(), out.String())
	}
	if !strings.Contains(errb.String(), "this device is not trusted for workspace asiri-dev") {
		t.Fatalf("explicit ineligible pull error unexpected: %s", errb.String())
	}
}

func TestPullAdoptsUnboundLocalWorkspaceWithHostedCanonicalSlug(t *testing.T) {
	tmp := t.TempDir()
	old := os.Getenv("ASIRI_HOME")
	t.Cleanup(func() { _ = os.Setenv("ASIRI_HOME", old) })
	if err := os.Setenv("ASIRI_HOME", tmp); err != nil {
		t.Fatal(err)
	}

	syncRequests := 0
	var remoteVersions []store.RemoteSecretVersion
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		switch r.URL.Path {
		case "/v1/auth/device-code/start":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"deviceCode":              "dc_testamy",
				"userCode":                "TESTAMY-123",
				"verificationUri":         serverURL(r) + "/auth/device",
				"verificationUriComplete": serverURL(r) + "/auth/device?code=TESTAMY-123",
				"expiresIn":               30,
				"interval":                0,
			})
		case "/v1/auth/device-code/token":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status":           "approved",
				"orgId":            "org_testamy",
				"workspaceSlug":    "testamy-com",
				"userId":           "usr_owner",
				"deviceId":         "dev_testamy",
				"accessToken":      "at_testamy",
				"refreshToken":     "rt_testamy",
				"expiresIn":        3600,
				"refreshExpiresAt": time.Now().UTC().Add(7 * 24 * time.Hour).Format(time.RFC3339),
			})
		case "/v1/orgs":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"activeOrgId": "org_testamy",
				"organizations": []map[string]any{{
					"id": "org_testamy", "name": "Testamy", "slug": "testamy-com", "kind": "domain",
					"ownerUserId": "usr_owner", "role": "owner", "canPull": true, "canWrite": true,
					"currentDeviceTrusted": true, "currentDeviceId": "dev_testamy",
				}},
			})
		case "/v1/sync":
			syncRequests++
			if r.Header.Get("authorization") != "Bearer at_testamy" || r.URL.Query().Get("orgId") != "org_testamy" || r.URL.Query().Get("deviceId") != "dev_testamy" {
				t.Fatalf("unexpected sync request auth=%s query=%s", r.Header.Get("authorization"), r.URL.RawQuery)
			}
			bundleOrgID := "org_testamy"
			if syncRequests == 1 {
				bundleOrgID = "org_other"
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"orgId": bundleOrgID, "deviceId": "dev_testamy", "issuedAt": time.Now().UTC().Format(time.RFC3339),
				"encryptedSecrets": remoteVersions,
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
		{"workspace", "create", "testamy-com"},
		{"add", "--workspace", "testamy-com", "common/LOCAL_KEY", "--value-file", testSecretFile(t, "local-value")},
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
	device, err := st.ActiveDevice()
	if err != nil {
		t.Fatal(err)
	}
	remoteVersions = []store.RemoteSecretVersion{pullTestRemoteVersion(t, tmp, "dev_testamy", device.EncryptionPublicKey)}

	out.Reset()
	errb.Reset()
	if code := app.Run([]string{"pull", "--workspace", "testamy-com"}); code == 0 {
		t.Fatalf("pull accepted a mismatched sync bundle: stderr=%s stdout=%s", errb.String(), out.String())
	}
	if !strings.Contains(errb.String(), "different workspace or device") {
		t.Fatalf("unexpected mismatched bundle error: %s", errb.String())
	}
	st, err = store.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	workspace, ok := st.LocalWorkspace("testamy-com")
	if !ok || workspace.RemoteWorkspaceID != "" {
		t.Fatalf("mismatched bundle changed local workspace identity: %#v", workspace)
	}
	if _, ok := st.RemoteBindingForPrefix("testamy-com"); ok {
		t.Fatal("mismatched bundle bound the local workspace prefix")
	}

	out.Reset()
	errb.Reset()
	if code := app.Run([]string{"pull", "--workspace", "testamy-com"}); code != 0 {
		t.Fatalf("pull failed with code %d stderr=%s stdout=%s", code, errb.String(), out.String())
	}
	if syncRequests != 2 {
		t.Fatalf("expected two hosted workspace sync requests, got %d", syncRequests)
	}

	st, err = store.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	binding, ok := st.RemoteBindingForPrefix("testamy-com")
	if !ok || binding.WorkspaceID != "org_testamy" {
		t.Fatalf("local workspace was not bound to hosted identity: %#v", binding)
	}
	workspace, ok = st.LocalWorkspace("testamy-com")
	if !ok || workspace.RemoteWorkspaceID != "org_testamy" || workspace.Kind != "domain" {
		t.Fatalf("local workspace did not adopt hosted metadata: %#v", workspace)
	}
	value, _, err := st.GetSecret("testamy-com/common/LOCAL_KEY")
	if err != nil {
		t.Fatal(err)
	}
	if value != "local-value" {
		t.Fatalf("local secret changed during workspace adoption")
	}
	active := st.State.Secrets[store.SecretKey("testamy-com/common", "LOCAL_KEY")].Versions[0]
	if active.AAD != remoteVersions[0].AAD || active.Ciphertext != remoteVersions[0].Ciphertext {
		t.Fatal("equal local value did not reconcile to the hosted encrypted version")
	}
}

func pullTestRemoteVersion(t *testing.T, root, targetDeviceID, targetPublicKey string) store.RemoteSecretVersion {
	t.Helper()
	source, err := store.Load(filepath.Join(root, "remote-source", "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := source.InitializeLocal(); err != nil {
		t.Fatal(err)
	}
	device, refs, err := createDevice("remote-source", "laptop")
	if err != nil {
		t.Fatal(err)
	}
	source.State.Devices = append(source.State.Devices, device)
	source.State.LocalDeviceID = device.ID
	for _, ref := range refs {
		source.AddKeyRef(ref.Purpose, ref.Account)
	}
	if err := source.Save(); err != nil {
		t.Fatal(err)
	}
	if _, err := source.AddSecret("testamy-com/common/LOCAL_KEY", "local-value"); err != nil {
		t.Fatal(err)
	}
	expires := time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339)
	if err := source.LinkControlPlaneForDevice("http://control.test", "org_testamy", "testamy-com", "usr_owner", "dev_source", device.ID, "at_source", "rt_source", 3600, expires); err != nil {
		t.Fatal(err)
	}
	if err := source.BindWorkspacePrefix("testamy-com", "org_testamy", "testamy-com"); err != nil {
		t.Fatal(err)
	}
	versions, err := source.RemoteSecretVersionsForPrefix("org_testamy", "testamy-com", "dev_source", "testamy-com")
	if err != nil || len(versions) != 1 {
		t.Fatalf("unexpected remote source versions: count=%d err=%v", len(versions), err)
	}
	wrapped, err := source.RemoteWrappedKeyForSecretVersionPublicKey("org_testamy", versions[0].Scope, versions[0].Name, versions[0].Version, targetDeviceID, targetPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	versions[0].WrappedKeys = []store.RemoteWrappedKey{wrapped}
	return versions[0]
}
