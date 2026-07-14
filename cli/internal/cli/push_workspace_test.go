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

func TestPushOffersConfirmedWorkspacePrefixRenameWhenSourceWorkspaceIsNotVisible(t *testing.T) {
	tmp := t.TempDir()
	old := os.Getenv("ASIRI_HOME")
	t.Cleanup(func() { _ = os.Setenv("ASIRI_HOME", old) })
	if err := os.Setenv("ASIRI_HOME", tmp); err != nil {
		t.Fatal(err)
	}
	writeOptionsSeen := false
	secretPushSeen := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		switch r.URL.Path {
		case "/v1/auth/device-code/start":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"deviceCode":              "dc_remap",
				"userCode":                "REMP-1234",
				"verificationUri":         serverURL(r) + "/auth/device",
				"verificationUriComplete": serverURL(r) + "/auth/device?code=REMP-1234",
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
		case "/v1/sync/write-options":
			writeOptionsSeen = true
			var body map[string][]map[string]string
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if len(body["entries"]) != 1 || body["entries"][0]["scope"] != "google-com/recipe-app" || body["entries"][0]["name"] != "API_KEY" {
				t.Fatalf("unexpected write options body: %#v", body)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"requestedWorkspaceSlug": "google-com",
				"workspace": map[string]any{
					"id":       "org_oclan",
					"slug":     "oclan-co",
					"canWrite": true,
					"paths": []map[string]any{{
						"scope":              "oclan-co/recipe-app",
						"name":               "API_KEY",
						"fullPath":           "oclan-co/recipe-app/API_KEY",
						"requiredCapability": "secret:create",
						"canWrite":           true,
					}},
				},
				"writableWorkspaces": []map[string]any{{
					"id":       "org_oclan",
					"slug":     "oclan-co",
					"canWrite": true,
					"paths": []map[string]any{{
						"fullPath": "oclan-co/recipe-app/API_KEY",
					}},
				}},
			})
		case "/v1/secrets":
			secretPushSeen = true
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if body["orgId"] != "org_oclan" || body["scope"] != "oclan-co/recipe-app" || body["name"] != "API_KEY" {
				t.Fatalf("unexpected remapped push body: %#v", body)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"id": "secv_remap", "status": "active"})
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
		{"add", "--workspace", "google-com", "recipe-app/API_KEY", "--value-file", testSecretFile(t, "secret_value")},
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
	if code := app.Run([]string{"push"}); code == 0 {
		t.Fatalf("push should require an explicit workspace")
	}
	if writeOptionsSeen || secretPushSeen {
		t.Fatal("push without workspace should fail before remote calls")
	}
	if !strings.Contains(errb.String(), "push requires --workspace") {
		t.Fatalf("push did not explain required workspace: %s", errb.String())
	}
	st, err := store.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := st.RemoteBindingForPrefix("oclan-co"); ok {
		t.Fatalf("push without workspace should not bind any prefix: %#v", st.State.RemoteBindings)
	}
	if _, _, err := st.GetSecret("google-com/recipe-app/API_KEY"); err != nil {
		t.Fatal(err)
	}
}

func TestPushReportsRequestedWorkspaceWriteDenial(t *testing.T) {
	tmp := t.TempDir()
	old := os.Getenv("ASIRI_HOME")
	t.Cleanup(func() { _ = os.Setenv("ASIRI_HOME", old) })
	if err := os.Setenv("ASIRI_HOME", tmp); err != nil {
		t.Fatal(err)
	}
	secretPushSeen := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		switch r.URL.Path {
		case "/v1/auth/device-code/start":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"deviceCode":              "dc_alt",
				"userCode":                "ALTS-1234",
				"verificationUriComplete": serverURL(r) + "/auth/device?code=ALTS-1234",
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
			assertWorkspaceOverviewTarget(t, r, "oclan-co")
			_ = json.NewEncoder(w).Encode(map[string]any{"organizations": []map[string]any{{
				"id": "org_oclan", "slug": "oclan-co", "role": "owner", "canPull": true, "canWrite": true, "currentDeviceTrusted": true, "currentDeviceId": "dev_oclan",
			}}})
		case "/v1/sync/write-options":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"requestedWorkspaceSlug": "oclan-co",
				"workspace": map[string]any{
					"id":       "org_oclan",
					"slug":     "oclan-co",
					"canWrite": false,
					"paths": []map[string]any{{
						"fullPath": "oclan-co/recipe-app/API_KEY",
						"canWrite": false,
					}},
				},
			})
		case "/v1/secrets":
			secretPushSeen = true
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
		{"add", "--workspace", "oclan-co", "recipe-app/API_KEY", "--value-file", testSecretFile(t, "secret_value")},
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
		t.Fatalf("push should fail when the target workspace cannot write")
	}
	if secretPushSeen {
		t.Fatal("push should not upload when the target workspace cannot write")
	}
	if !strings.Contains(errb.String(), "workspace oclan-co cannot write") {
		t.Fatalf("push did not explain workspace write failure: %s", errb.String())
	}
}

func TestPushRefusesToMoveVisibleReadOnlyWorkspaceSecrets(t *testing.T) {
	tmp := t.TempDir()
	old := os.Getenv("ASIRI_HOME")
	t.Cleanup(func() { _ = os.Setenv("ASIRI_HOME", old) })
	if err := os.Setenv("ASIRI_HOME", tmp); err != nil {
		t.Fatal(err)
	}
	secretPushSeen := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		switch r.URL.Path {
		case "/v1/auth/device-code/start":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"deviceCode":              "dc_readonly",
				"userCode":                "READ-1234",
				"verificationUriComplete": serverURL(r) + "/auth/device?code=READ-1234",
				"expiresIn":               30,
				"interval":                0,
			})
		case "/v1/auth/device-code/token":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status":           "approved",
				"orgId":            "org_oclan",
				"workspaceSlug":    "oclan-co",
				"userId":           "usr_member",
				"deviceId":         "dev_member",
				"accessToken":      "at_member",
				"refreshToken":     "rt_member",
				"expiresIn":        3600,
				"refreshExpiresAt": time.Now().UTC().Add(7 * 24 * time.Hour).Format(time.RFC3339),
			})
		case "/v1/orgs":
			assertWorkspaceOverviewTarget(t, r, "oclan-co")
			_ = json.NewEncoder(w).Encode(map[string]any{"organizations": []map[string]any{{
				"id": "org_oclan", "slug": "oclan-co", "role": "member", "canPull": true, "canWrite": true, "currentDeviceTrusted": true, "currentDeviceId": "dev_member",
			}}})
		case "/v1/sync/write-options":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"requestedWorkspaceSlug": "google-com",
				"sourceWorkspace": map[string]any{
					"id":       "org_google",
					"slug":     "google-com",
					"canWrite": false,
					"paths": []map[string]any{{
						"fullPath": "google-com/recipe-app/API_KEY",
						"canWrite": false,
					}},
				},
				"workspace": map[string]any{
					"id":       "org_oclan",
					"slug":     "oclan-co",
					"canWrite": true,
					"paths": []map[string]any{{
						"fullPath": "oclan-co/recipe-app/API_KEY",
						"canWrite": true,
					}},
				},
				"writableWorkspaces": []map[string]any{{
					"id":       "org_oclan",
					"slug":     "oclan-co",
					"canWrite": true,
					"paths": []map[string]any{{
						"fullPath": "oclan-co/recipe-app/API_KEY",
						"canWrite": true,
					}},
				}},
			})
		case "/v1/secrets":
			secretPushSeen = true
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
		{"add", "--workspace", "google-com", "recipe-app/API_KEY", "--value-file", testSecretFile(t, "secret_value")},
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
		t.Fatalf("push should fail when local prefixes do not match the requested workspace")
	}
	if secretPushSeen {
		t.Fatal("push should not upload mismatched workspace material")
	}
	if !strings.Contains(errb.String(), "no local active secrets under workspace oclan-co") || !strings.Contains(errb.String(), "google-com") {
		t.Fatalf("push did not explain workspace prefix mismatch: %s", errb.String())
	}
}

func TestPushExplainsMissingWorkspaceDeviceTrust(t *testing.T) {
	tmp := t.TempDir()
	old := os.Getenv("ASIRI_HOME")
	t.Cleanup(func() { _ = os.Setenv("ASIRI_HOME", old) })
	if err := os.Setenv("ASIRI_HOME", tmp); err != nil {
		t.Fatal(err)
	}
	switchSeen := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		switch r.URL.Path {
		case "/v1/auth/device-code/start":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"deviceCode":              "dc_push_trust",
				"userCode":                "TRUST-123",
				"verificationUri":         serverURL(r) + "/auth/device",
				"verificationUriComplete": serverURL(r) + "/auth/device?code=TRUST-123",
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
			_ = json.NewEncoder(w).Encode(map[string]any{
				"activeOrgId": "org_oclan",
				"organizations": []map[string]any{
					{"id": "org_oclan", "name": "O Clan", "slug": "oclan-co", "ownerUserId": "usr_owner", "role": "owner", "canPull": true, "canWrite": true},
					{"id": "org_asiri", "name": "Asiri Dev", "slug": "asiri-dev", "ownerUserId": "usr_owner", "role": "owner", "canPull": false, "canWrite": true},
				},
			})
		case "/v1/auth/session/switch":
			switchSeen = true
			var body map[string]string
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if body["workspace"] != "org_asiri" {
				t.Fatalf("unexpected switch target: %#v", body)
			}
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"error":   "request_failed",
				"message": "trusted matching device required; approve this device in the target workspace first",
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
	if code := app.Run([]string{"push", "--workspace", "asiri-dev", "--yes"}); code == 0 {
		t.Fatal("push should fail when the target workspace does not trust this device")
	}
	if switchSeen {
		t.Fatal("push should fail before attempting a workspace switch")
	}
	for _, expected := range []string{"this device is not trusted for workspace asiri-dev", "device qa-laptop", "asiri device trust --workspace asiri-dev --origin " + server.URL} {
		if !strings.Contains(errb.String(), expected) {
			t.Fatalf("push error missing %q: %s", expected, errb.String())
		}
	}
}
