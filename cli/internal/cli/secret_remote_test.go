package cli

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/o-clan/asiri/cli/internal/store"
)

func TestRemoteSecretDeleteMarksActiveRemoteVersionDeleted(t *testing.T) {
	tmp := t.TempDir()
	old := os.Getenv("ASIRI_HOME")
	t.Cleanup(func() { _ = os.Setenv("ASIRI_HOME", old) })
	if err := os.Setenv("ASIRI_HOME", tmp); err != nil {
		t.Fatal(err)
	}
	workspaceOverviewSeen := false
	preflightSeen := false
	deleteSeen := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		switch r.URL.Path {
		case "/v1/auth/device-code/start":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"deviceCode":              "dc_delete",
				"userCode":                "DEL-1234",
				"verificationUriComplete": serverURL(r) + "/auth/device?code=DEL-1234",
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
				"accessToken":      "at_delete",
				"refreshToken":     "rt_delete",
				"expiresIn":        3600,
				"refreshExpiresAt": time.Now().UTC().Add(7 * 24 * time.Hour).Format(time.RFC3339),
			})
		case "/v1/orgs":
			assertWorkspaceOverviewTarget(t, r, "oclan-co")
			if r.Header.Get("authorization") != "Bearer at_delete" {
				t.Fatalf("unexpected workspace overview auth header: %s", r.Header.Get("authorization"))
			}
			if r.URL.Query().Get("includeSecrets") != "1" {
				_ = json.NewEncoder(w).Encode(map[string]any{
					"activeOrgId":   "org_oclan",
					"organizations": []map[string]any{{"id": "org_oclan", "slug": "oclan-co", "role": "owner", "canPull": true, "canWrite": true, "currentDeviceTrusted": true, "currentDeviceId": "dev_oclan"}},
				})
				return
			}
			workspaceOverviewSeen = true
			_ = json.NewEncoder(w).Encode(map[string]any{
				"activeOrgId":   "org_oclan",
				"organizations": []map[string]any{{"id": "org_oclan", "slug": "oclan-co", "role": "owner", "canPull": true, "canWrite": true, "currentDeviceTrusted": true, "currentDeviceId": "dev_oclan"}},
				"secrets": []map[string]any{
					{"id": "sec_delete", "orgId": "org_oclan", "workspaceSlug": "oclan-co", "scope": "oclan-co/local/asiri", "name": "PUSHED", "version": 2, "status": "active", "canWrite": true},
					{"id": "sec_other", "orgId": "org_other", "workspaceSlug": "other-co", "scope": "other-co/local/asiri", "name": "PUSHED", "version": 1, "status": "active", "canWrite": true},
				},
			})
		case "/v1/secrets/sec_delete/delete-preflight":
			preflightSeen = true
			if r.Method != http.MethodPost {
				t.Fatalf("expected POST preflight, got %s", r.Method)
			}
			if r.Header.Get("authorization") != "Bearer at_delete" {
				t.Fatalf("unexpected preflight auth header: %s", r.Header.Get("authorization"))
			}
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if body["orgId"] != "org_oclan" || body["createdByDeviceId"] != "dev_oclan" || body["version"] != float64(2) {
				t.Fatalf("preflight request used wrong body: %#v", body)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id": "sec_delete", "orgId": "org_oclan", "scope": "oclan-co/local/asiri", "name": "PUSHED", "version": 2, "status": "active",
			})
		case "/v1/secrets/sec_delete/delete":
			deleteSeen = true
			if r.Method != http.MethodPost {
				t.Fatalf("expected POST delete, got %s", r.Method)
			}
			if r.Header.Get("authorization") != "Bearer at_delete" {
				t.Fatalf("unexpected delete auth header: %s", r.Header.Get("authorization"))
			}
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if body["orgId"] != "org_oclan" || body["createdByDeviceId"] != "dev_oclan" || body["version"] != float64(2) {
				t.Fatalf("delete request used wrong body: %#v", body)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id": "sec_delete", "orgId": "org_oclan", "scope": "oclan-co/local/asiri", "name": "PUSHED", "version": 2, "status": "deleted",
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
		{"init", "--device", "qa-laptop", "--workspace", "oclan-co"},
		{"add", "--workspace", "oclan-co", "local/asiri/PUSHED", "--value-file", testSecretFile(t, "secret_value")},
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
	if code := app.Run([]string{"secret", "delete", "--workspace", "oclan-co", "local/asiri/PUSHED", "--dry-run"}); code != 0 {
		t.Fatalf("remote secret delete dry-run failed: %s", errb.String())
	}
	if deleteSeen {
		t.Fatal("remote secret delete dry-run should not call delete endpoint")
	}
	if !preflightSeen {
		t.Fatal("remote secret delete dry-run should call delete preflight")
	}
	token := remoteDeleteTokenFromOutput(t, out.String())
	out.Reset()
	errb.Reset()
	if code := app.Run([]string{"secret", "delete", "--workspace", "oclan-co", "local/asiri/PUSHED", "--confirm-token", token}); code != 0 {
		t.Fatalf("remote secret delete failed: %s", errb.String())
	}
	if !workspaceOverviewSeen || !deleteSeen {
		t.Fatalf("expected workspace overview lookup and delete request, overview=%v delete=%v", workspaceOverviewSeen, deleteSeen)
	}
	for _, expected := range []string{"Marked remote secret", "local/asiri/PUSHED", "oclan-co", "v2"} {
		if !strings.Contains(out.String(), expected) {
			t.Fatalf("delete output missing %q: %s", expected, out.String())
		}
	}
	st, err := store.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := st.State.Secrets[store.SecretKey("oclan-co/local/asiri", "PUSHED")]; !ok {
		t.Fatal("remote delete should not remove the local secret")
	}
}

func TestRemoteSecretDeleteConfirmationAndPathGuards(t *testing.T) {
	tmp := t.TempDir()
	old := os.Getenv("ASIRI_HOME")
	t.Cleanup(func() { _ = os.Setenv("ASIRI_HOME", old) })
	if err := os.Setenv("ASIRI_HOME", tmp); err != nil {
		t.Fatal(err)
	}
	overviewCount := 0
	deleteCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		switch r.URL.Path {
		case "/v1/auth/device-code/start":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"deviceCode":              "dc_confirm_delete",
				"userCode":                "CDEL-123",
				"verificationUriComplete": serverURL(r) + "/auth/device?code=CDEL-123",
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
				"accessToken":      "at_confirm_delete",
				"refreshToken":     "rt_confirm_delete",
				"expiresIn":        3600,
				"refreshExpiresAt": time.Now().UTC().Add(7 * 24 * time.Hour).Format(time.RFC3339),
			})
		case "/v1/orgs":
			assertWorkspaceOverviewTarget(t, r, "oclan-co")
			if r.URL.Query().Get("includeSecrets") != "1" {
				_ = json.NewEncoder(w).Encode(map[string]any{
					"activeOrgId":   "org_oclan",
					"organizations": []map[string]any{{"id": "org_oclan", "slug": "oclan-co", "role": "owner", "canPull": true, "canWrite": true, "currentDeviceTrusted": true, "currentDeviceId": "dev_oclan"}},
				})
				return
			}
			overviewCount++
			_ = json.NewEncoder(w).Encode(map[string]any{
				"activeOrgId":   "org_oclan",
				"organizations": []map[string]any{{"id": "org_oclan", "slug": "oclan-co", "role": "owner", "canPull": true, "canWrite": true, "currentDeviceTrusted": true, "currentDeviceId": "dev_oclan"}},
				"secrets": []map[string]any{
					{"id": "sec_confirm", "orgId": "org_oclan", "workspaceSlug": "oclan-co", "scope": "oclan-co/local/asiri", "name": "PUSHED", "version": 1, "status": "active", "canWrite": true},
				},
			})
		case "/v1/secrets/sec_confirm/delete":
			deleteCount++
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if body["orgId"] != "org_oclan" || body["createdByDeviceId"] != "dev_oclan" || body["version"] != float64(1) {
				t.Fatalf("confirmed delete request used wrong body: %#v", body)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id": "sec_confirm", "orgId": "org_oclan", "scope": "oclan-co/local/asiri", "name": "PUSHED", "version": 1, "status": "deleted",
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
		{"init", "--device", "qa-laptop", "--workspace", "oclan-co"},
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
	if code := app.Run([]string{"secret", "delete", "--workspace", "oclan-co", "oclan-co/local/asiri/PUSHED"}); code == 0 {
		t.Fatal("workspace-prefixed remote delete path should fail")
	}
	if !strings.Contains(errb.String(), "accepts short paths") {
		t.Fatalf("prefixed path error was not clear: %s", errb.String())
	}
	if overviewCount != 0 || deleteCount != 0 {
		t.Fatalf("prefixed path should fail before remote lookup, overview=%d delete=%d", overviewCount, deleteCount)
	}
	app.In = strings.NewReader("wrong\n")
	out.Reset()
	errb.Reset()
	if code := app.Run([]string{"secret", "delete", "--workspace", "oclan-co", "local/asiri/PUSHED"}); code == 0 {
		t.Fatal("remote delete should fail when confirmation does not match")
	}
	if !strings.Contains(errb.String(), "confirmation did not match") {
		t.Fatalf("confirmation error was not clear: %s", errb.String())
	}
	if deleteCount != 0 {
		t.Fatalf("confirmation mismatch should not delete, deleteCount=%d", deleteCount)
	}
	app.In = strings.NewReader("delete oclan-co local/asiri/PUSHED v1 \n")
	out.Reset()
	errb.Reset()
	if code := app.Run([]string{"secret", "delete", "--workspace", "oclan-co", "local/asiri/PUSHED"}); code == 0 {
		t.Fatal("remote delete should fail when confirmation has trailing whitespace")
	}
	if !strings.Contains(errb.String(), "confirmation did not match") {
		t.Fatalf("whitespace confirmation error was not clear: %s", errb.String())
	}
	if deleteCount != 0 {
		t.Fatalf("whitespace confirmation mismatch should not delete, deleteCount=%d", deleteCount)
	}
	app.In = strings.NewReader("delete oclan-co local/asiri/PUSHED v1\n")
	out.Reset()
	errb.Reset()
	if code := app.Run([]string{"secret", "delete", "--workspace", "oclan-co", "local/asiri/PUSHED"}); code != 0 {
		t.Fatalf("confirmed remote delete failed: %s", errb.String())
	}
	if deleteCount != 1 {
		t.Fatalf("expected one confirmed delete, got %d", deleteCount)
	}
}

func TestRemoteSecretRestoreRestoresDeletedRemoteVersion(t *testing.T) {
	tmp := t.TempDir()
	old := os.Getenv("ASIRI_HOME")
	t.Cleanup(func() { _ = os.Setenv("ASIRI_HOME", old) })
	if err := os.Setenv("ASIRI_HOME", tmp); err != nil {
		t.Fatal(err)
	}
	restoreSeen := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		switch r.URL.Path {
		case "/v1/auth/device-code/start":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"deviceCode":              "dc_restore_delete",
				"userCode":                "RDEL-123",
				"verificationUriComplete": serverURL(r) + "/auth/device?code=RDEL-123",
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
				"accessToken":      "at_restore_delete",
				"refreshToken":     "rt_restore_delete",
				"expiresIn":        3600,
				"refreshExpiresAt": time.Now().UTC().Add(7 * 24 * time.Hour).Format(time.RFC3339),
			})
		case "/v1/orgs":
			assertWorkspaceOverviewTarget(t, r, "oclan-co")
			if r.URL.Query().Get("includeSecrets") != "1" {
				_ = json.NewEncoder(w).Encode(map[string]any{
					"activeOrgId":   "org_oclan",
					"organizations": []map[string]any{{"id": "org_oclan", "slug": "oclan-co", "role": "owner", "canPull": true, "canWrite": true, "currentDeviceTrusted": true, "currentDeviceId": "dev_oclan"}},
				})
				return
			}
			if r.URL.Query().Get("includeInactive") != "1" {
				t.Fatalf("restore lookup should include inactive secrets: %s", r.URL.RawQuery)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"activeOrgId":   "org_oclan",
				"organizations": []map[string]any{{"id": "org_oclan", "slug": "oclan-co", "role": "owner", "canPull": true, "canWrite": true, "currentDeviceTrusted": true, "currentDeviceId": "dev_oclan"}},
				"secrets": []map[string]any{
					{"id": "sec_restore", "orgId": "org_oclan", "workspaceSlug": "oclan-co", "scope": "oclan-co/local/asiri", "name": "PUSHED", "version": 2, "status": "deleted", "canWrite": true},
				},
			})
		case "/v1/secrets/sec_restore/restore":
			restoreSeen = true
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if body["orgId"] != "org_oclan" || body["createdByDeviceId"] != "dev_oclan" || body["version"] != float64(2) {
				t.Fatalf("restore request used wrong body: %#v", body)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id": "sec_restore", "orgId": "org_oclan", "scope": "oclan-co/local/asiri", "name": "PUSHED", "version": 2, "status": "active",
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
		{"init", "--device", "qa-laptop", "--workspace", "oclan-co"},
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
	if code := app.Run([]string{"secret", "restore", "--workspace", "oclan-co", "local/asiri/PUSHED", "--yes"}); code != 0 {
		t.Fatalf("remote secret restore failed: %s", errb.String())
	}
	if !restoreSeen {
		t.Fatal("expected restore request")
	}
	for _, expected := range []string{"Restored remote secret", "local/asiri/PUSHED", "oclan-co", "v2"} {
		if !strings.Contains(out.String(), expected) {
			t.Fatalf("restore output missing %q: %s", expected, out.String())
		}
	}
}

func TestRemoteSecretDeleteFailureModes(t *testing.T) {
	for _, tc := range []struct {
		name       string
		secrets    []map[string]any
		deleteCode int
		deleteBody map[string]any
		want       string
	}{
		{
			name: "missing active remote secret",
			secrets: []map[string]any{
				{"id": "sec_stale", "orgId": "org_oclan", "workspaceSlug": "oclan-co", "scope": "oclan-co/local/asiri", "name": "PUSHED", "version": 1, "status": "stale", "canWrite": true},
			},
			want: "no active remote secret found",
		},
		{
			name: "permission failure",
			secrets: []map[string]any{
				{"id": "sec_forbidden", "orgId": "org_oclan", "workspaceSlug": "oclan-co", "scope": "oclan-co/local/asiri", "name": "PUSHED", "version": 1, "status": "active", "canWrite": true},
			},
			deleteCode: http.StatusForbidden,
			deleteBody: map[string]any{"error": "forbidden", "message": "secret delete denied"},
			want:       "secret delete denied",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tmp := t.TempDir()
			old := os.Getenv("ASIRI_HOME")
			t.Cleanup(func() { _ = os.Setenv("ASIRI_HOME", old) })
			if err := os.Setenv("ASIRI_HOME", tmp); err != nil {
				t.Fatal(err)
			}
			deleteSeen := false
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("content-type", "application/json")
				switch r.URL.Path {
				case "/v1/auth/device-code/start":
					_ = json.NewEncoder(w).Encode(map[string]any{
						"deviceCode":              "dc_fail_delete",
						"userCode":                "FDEL-123",
						"verificationUriComplete": serverURL(r) + "/auth/device?code=FDEL-123",
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
						"accessToken":      "at_fail_delete",
						"refreshToken":     "rt_fail_delete",
						"expiresIn":        3600,
						"refreshExpiresAt": time.Now().UTC().Add(7 * 24 * time.Hour).Format(time.RFC3339),
					})
				case "/v1/orgs":
					if r.URL.Query().Get("includeSecrets") != "1" {
						_ = json.NewEncoder(w).Encode(map[string]any{
							"activeOrgId":   "org_oclan",
							"organizations": []map[string]any{{"id": "org_oclan", "slug": "oclan-co", "role": "owner", "canPull": true, "canWrite": true, "currentDeviceTrusted": true, "currentDeviceId": "dev_oclan"}},
						})
						return
					}
					_ = json.NewEncoder(w).Encode(map[string]any{
						"activeOrgId":   "org_oclan",
						"organizations": []map[string]any{{"id": "org_oclan", "slug": "oclan-co", "role": "owner", "canPull": true, "canWrite": true, "currentDeviceTrusted": true, "currentDeviceId": "dev_oclan"}},
						"secrets":       tc.secrets,
					})
				case "/v1/secrets/sec_forbidden/delete":
					deleteSeen = true
					w.WriteHeader(tc.deleteCode)
					_ = json.NewEncoder(w).Encode(tc.deleteBody)
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
			app.In = strings.NewReader("delete oclan-co local/asiri/PUSHED v1\n")
			if code := app.Run([]string{"secret", "delete", "--workspace", "oclan-co", "local/asiri/PUSHED"}); code == 0 {
				t.Fatal("remote delete failure mode should fail")
			}
			if !strings.Contains(errb.String(), tc.want) {
				t.Fatalf("error missing %q: %s", tc.want, errb.String())
			}
			if tc.deleteCode == 0 && deleteSeen {
				t.Fatal("missing active secret should not call delete")
			}
			if tc.deleteCode != 0 && !deleteSeen {
				t.Fatal("permission failure should call delete endpoint")
			}
		})
	}
}

func TestRemoteSecretBulkDeleteOnlyRemoteOnlyUnwrapped(t *testing.T) {
	tmp := t.TempDir()
	old := os.Getenv("ASIRI_HOME")
	t.Cleanup(func() { _ = os.Setenv("ASIRI_HOME", old) })
	if err := os.Setenv("ASIRI_HOME", tmp); err != nil {
		t.Fatal(err)
	}
	deletedIDs := []string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		switch r.URL.Path {
		case "/v1/auth/device-code/start":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"deviceCode":              "dc_bulk_delete",
				"userCode":                "BDEL-123",
				"verificationUriComplete": serverURL(r) + "/auth/device?code=BDEL-123",
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
				"accessToken":      "at_bulk_delete",
				"refreshToken":     "rt_bulk_delete",
				"expiresIn":        3600,
				"refreshExpiresAt": time.Now().UTC().Add(7 * 24 * time.Hour).Format(time.RFC3339),
			})
		case "/v1/orgs":
			assertWorkspaceOverviewTarget(t, r, "oclan-co")
			if r.URL.Query().Get("includeSecrets") != "1" {
				_ = json.NewEncoder(w).Encode(map[string]any{
					"activeOrgId":   "org_oclan",
					"organizations": []map[string]any{{"id": "org_oclan", "slug": "oclan-co", "role": "owner", "canPull": true, "canWrite": true, "currentDeviceTrusted": true, "currentDeviceId": "dev_oclan"}},
				})
				return
			}
			wrapped := true
			unwrapped := false
			_ = json.NewEncoder(w).Encode(map[string]any{
				"activeOrgId":   "org_oclan",
				"organizations": []map[string]any{{"id": "org_oclan", "slug": "oclan-co", "role": "owner", "canPull": true, "canWrite": true, "currentDeviceTrusted": true, "currentDeviceId": "dev_oclan"}},
				"secrets": []map[string]any{
					{"id": "sec_candidate_a", "orgId": "org_oclan", "workspaceSlug": "oclan-co", "scope": "oclan-co/local/asiri", "name": "GHOST_A", "version": 1, "status": "active", "canWrite": true, "wrappedToCurrentDevice": unwrapped},
					{"id": "sec_candidate_b", "orgId": "org_oclan", "workspaceSlug": "oclan-co", "scope": "oclan-co/prod", "name": "GHOST_B", "version": 1, "status": "active", "canWrite": true, "wrappedToCurrentDevice": unwrapped},
					{"id": "sec_wrapped", "orgId": "org_oclan", "workspaceSlug": "oclan-co", "scope": "oclan-co/prod", "name": "WRAPPED", "version": 1, "status": "active", "canWrite": true, "wrappedToCurrentDevice": wrapped},
					{"id": "sec_stale", "orgId": "org_oclan", "workspaceSlug": "oclan-co", "scope": "oclan-co/prod", "name": "STALE", "version": 1, "status": "stale", "canWrite": true, "wrappedToCurrentDevice": unwrapped},
					{"id": "sec_other", "orgId": "org_other", "workspaceSlug": "other-co", "scope": "other-co/prod", "name": "GHOST", "version": 1, "status": "active", "canWrite": true, "wrappedToCurrentDevice": unwrapped},
					{"id": "sec_local", "orgId": "org_oclan", "workspaceSlug": "oclan-co", "scope": "oclan-co/local/asiri", "name": "LOCAL_COPY", "version": 1, "status": "active", "canWrite": true, "wrappedToCurrentDevice": unwrapped},
				},
			})
		case "/v1/secrets/sec_candidate_a/delete-preflight", "/v1/secrets/sec_candidate_b/delete-preflight":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if body["orgId"] != "org_oclan" || body["createdByDeviceId"] != "dev_oclan" || body["version"] != float64(1) {
				t.Fatalf("bulk preflight used wrong body: %#v", body)
			}
			id := strings.TrimPrefix(strings.TrimSuffix(r.URL.Path, "/delete-preflight"), "/v1/secrets/")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id": id, "orgId": "org_oclan", "scope": "oclan-co/prod", "name": "GHOST", "version": 1, "status": "active",
			})
		case "/v1/secrets/sec_candidate_a/delete", "/v1/secrets/sec_candidate_b/delete":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if body["orgId"] != "org_oclan" || body["createdByDeviceId"] != "dev_oclan" || body["version"] != float64(1) {
				t.Fatalf("bulk delete used wrong body: %#v", body)
			}
			id := strings.TrimPrefix(strings.TrimSuffix(r.URL.Path, "/delete"), "/v1/secrets/")
			deletedIDs = append(deletedIDs, id)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id": id, "orgId": "org_oclan", "scope": "oclan-co/prod", "name": "GHOST", "version": 1, "status": "deleted",
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
		{"init", "--device", "qa-laptop", "--workspace", "oclan-co"},
		{"add", "--workspace", "oclan-co", "local/asiri/LOCAL_COPY", "--value-file", testSecretFile(t, "secret_value")},
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
	if code := app.Run([]string{"secret", "delete", "--workspace", "oclan-co", "--remote-only-unwrapped", "--dry-run"}); code != 0 {
		t.Fatalf("bulk remote delete dry-run failed: %s", errb.String())
	}
	token := remoteDeleteTokenFromOutput(t, out.String())
	out.Reset()
	errb.Reset()
	if code := app.Run([]string{"secret", "delete", "--workspace", "oclan-co", "--remote-only-unwrapped", "--confirm-token", token}); code != 0 {
		t.Fatalf("bulk remote delete failed: %s", errb.String())
	}
	sort.Strings(deletedIDs)
	if got := strings.Join(deletedIDs, ","); got != "sec_candidate_a,sec_candidate_b" {
		t.Fatalf("bulk delete selected wrong ids: %s", got)
	}
	if !strings.Contains(out.String(), "Marked 2 remote-only unwrapped active secret") {
		t.Fatalf("bulk delete output missing count: %s", out.String())
	}
	st, err := store.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := st.State.Secrets[store.SecretKey("oclan-co/local/asiri", "LOCAL_COPY")]; !ok {
		t.Fatal("bulk remote delete should not remove local secrets")
	}
}

func TestRemoteRemoveDeletesRemoteOnlyRecordsWithToken(t *testing.T) {
	tmp := t.TempDir()
	old := os.Getenv("ASIRI_HOME")
	t.Cleanup(func() { _ = os.Setenv("ASIRI_HOME", old) })
	if err := os.Setenv("ASIRI_HOME", tmp); err != nil {
		t.Fatal(err)
	}
	deleteCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		switch r.URL.Path {
		case "/v1/auth/device-code/start":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"deviceCode":              "dc_rm_remote",
				"userCode":                "RMR-123",
				"verificationUriComplete": serverURL(r) + "/auth/device?code=RMR-123",
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
				"accessToken":      "at_rm_remote",
				"refreshToken":     "rt_rm_remote",
				"expiresIn":        3600,
				"refreshExpiresAt": time.Now().UTC().Add(7 * 24 * time.Hour).Format(time.RFC3339),
			})
		case "/v1/orgs":
			assertWorkspaceOverviewTarget(t, r, "oclan-co")
			if r.URL.Query().Get("includeSecrets") != "1" {
				_ = json.NewEncoder(w).Encode(map[string]any{
					"activeOrgId":   "org_oclan",
					"organizations": []map[string]any{{"id": "org_oclan", "slug": "oclan-co", "role": "owner", "canPull": true, "canWrite": true, "currentDeviceTrusted": true, "currentDeviceId": "dev_oclan"}},
				})
				return
			}
			wrapped := true
			_ = json.NewEncoder(w).Encode(map[string]any{
				"activeOrgId":   "org_oclan",
				"organizations": []map[string]any{{"id": "org_oclan", "slug": "oclan-co", "role": "owner", "canPull": true, "canWrite": true, "currentDeviceTrusted": true, "currentDeviceId": "dev_oclan"}},
				"secrets": []map[string]any{
					{"id": "sec_wrapped_remote_only", "orgId": "org_oclan", "workspaceSlug": "oclan-co", "scope": "oclan-co/prod", "name": "WRAPPED_ONLY", "version": 3, "status": "active", "canWrite": true, "wrappedToCurrentDevice": wrapped},
				},
			})
		case "/v1/secrets/sec_wrapped_remote_only/delete-preflight":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if body["orgId"] != "org_oclan" || body["createdByDeviceId"] != "dev_oclan" || body["version"] != float64(3) {
				t.Fatalf("remote rm used wrong preflight body: %#v", body)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id": "sec_wrapped_remote_only", "orgId": "org_oclan", "scope": "oclan-co/prod", "name": "WRAPPED_ONLY", "version": 3, "status": "active",
			})
		case "/v1/secrets/sec_wrapped_remote_only/delete":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if body["orgId"] != "org_oclan" || body["createdByDeviceId"] != "dev_oclan" || body["version"] != float64(3) {
				t.Fatalf("remote rm used wrong delete body: %#v", body)
			}
			deleteCount++
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id": "sec_wrapped_remote_only", "orgId": "org_oclan", "scope": "oclan-co/prod", "name": "WRAPPED_ONLY", "version": 3, "status": "deleted",
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
		{"init", "--device", "qa-laptop", "--workspace", "oclan-co"},
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
	if code := app.Run([]string{"rm", "--remote", "--workspace", "oclan-co", "--where", "remote-only", "--dry-run"}); code != 0 {
		t.Fatalf("remote rm dry-run failed: %s", errb.String())
	}
	if !strings.Contains(out.String(), "WRAPPED_ONLY v3") {
		t.Fatalf("dry-run did not show remote-only secret: %s", out.String())
	}
	token := remoteDeleteTokenFromOutput(t, out.String())
	out.Reset()
	errb.Reset()
	if code := app.Run([]string{"rm", "--remote", "--workspace", "oclan-co", "--where", "remote-only", "--confirm-token", token}); code != 0 {
		t.Fatalf("remote rm failed: %s", errb.String())
	}
	if deleteCount != 1 {
		t.Fatalf("expected one remote delete, got %d", deleteCount)
	}
	if !strings.Contains(out.String(), "Marked 1 remote-only active secret") {
		t.Fatalf("remote rm output missing count: %s", out.String())
	}
	out.Reset()
	errb.Reset()
	if code := app.Run([]string{"secret", "delete", "--workspace", "oclan-co", "--where", "remote-only", "--dry-run"}); code != 0 {
		t.Fatalf("secret delete remote-only dry-run failed: %s", errb.String())
	}
	token = remoteDeleteTokenFromOutput(t, out.String())
	out.Reset()
	errb.Reset()
	if code := app.Run([]string{"secret", "delete", "--workspace", "oclan-co", "--where", "remote-only", "--confirm-token", token}); code != 0 {
		t.Fatalf("secret delete remote-only failed: %s", errb.String())
	}
	if deleteCount != 2 {
		t.Fatalf("expected two remote deletes after second command, got %d", deleteCount)
	}
}

func TestRemoteSecretBulkDeletePreflightsBeforeMutation(t *testing.T) {
	tmp := t.TempDir()
	old := os.Getenv("ASIRI_HOME")
	t.Cleanup(func() { _ = os.Setenv("ASIRI_HOME", old) })
	if err := os.Setenv("ASIRI_HOME", tmp); err != nil {
		t.Fatal(err)
	}
	actualDeletes := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		switch r.URL.Path {
		case "/v1/auth/device-code/start":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"deviceCode":              "dc_bulk_preflight",
				"userCode":                "BPRE-123",
				"verificationUriComplete": serverURL(r) + "/auth/device?code=BPRE-123",
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
				"accessToken":      "at_bulk_preflight",
				"refreshToken":     "rt_bulk_preflight",
				"expiresIn":        3600,
				"refreshExpiresAt": time.Now().UTC().Add(7 * 24 * time.Hour).Format(time.RFC3339),
			})
		case "/v1/orgs":
			assertWorkspaceOverviewTarget(t, r, "oclan-co")
			if r.URL.Query().Get("includeSecrets") != "1" {
				_ = json.NewEncoder(w).Encode(map[string]any{
					"activeOrgId":   "org_oclan",
					"organizations": []map[string]any{{"id": "org_oclan", "slug": "oclan-co", "role": "owner", "canPull": true, "canWrite": true, "currentDeviceTrusted": true, "currentDeviceId": "dev_oclan"}},
				})
				return
			}
			unwrapped := false
			_ = json.NewEncoder(w).Encode(map[string]any{
				"activeOrgId":   "org_oclan",
				"organizations": []map[string]any{{"id": "org_oclan", "slug": "oclan-co", "role": "owner", "canPull": true, "canWrite": true, "currentDeviceTrusted": true, "currentDeviceId": "dev_oclan"}},
				"secrets": []map[string]any{
					{"id": "sec_preflight_a", "orgId": "org_oclan", "workspaceSlug": "oclan-co", "scope": "oclan-co/prod", "name": "A", "version": 1, "status": "active", "canWrite": true, "wrappedToCurrentDevice": unwrapped},
					{"id": "sec_preflight_b", "orgId": "org_oclan", "workspaceSlug": "oclan-co", "scope": "oclan-co/prod", "name": "B", "version": 1, "status": "active", "canWrite": true, "wrappedToCurrentDevice": unwrapped},
				},
			})
		case "/v1/secrets/sec_preflight_a/delete-preflight", "/v1/secrets/sec_preflight_b/delete-preflight":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if body["orgId"] != "org_oclan" || body["createdByDeviceId"] != "dev_oclan" || body["version"] != float64(1) {
				t.Fatalf("bulk preflight request used wrong body: %#v", body)
			}
			id := strings.TrimPrefix(strings.TrimSuffix(r.URL.Path, "/delete-preflight"), "/v1/secrets/")
			if id == "sec_preflight_b" {
				w.WriteHeader(http.StatusForbidden)
				_ = json.NewEncoder(w).Encode(map[string]any{"error": "forbidden", "message": "secret delete denied"})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"id": id, "orgId": "org_oclan", "scope": "oclan-co/prod", "name": "A", "version": 1, "status": "active"})
		case "/v1/secrets/sec_preflight_a/delete", "/v1/secrets/sec_preflight_b/delete":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if body["orgId"] != "org_oclan" || body["createdByDeviceId"] != "dev_oclan" || body["version"] != float64(1) {
				t.Fatalf("bulk delete request used wrong body: %#v", body)
			}
			id := strings.TrimPrefix(strings.TrimSuffix(r.URL.Path, "/delete"), "/v1/secrets/")
			actualDeletes++
			_ = json.NewEncoder(w).Encode(map[string]any{"id": id, "orgId": "org_oclan", "scope": "oclan-co/prod", "name": "A", "version": 1, "status": "deleted"})
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
	if code := app.Run([]string{"secret", "delete", "--workspace", "oclan-co", "--where", "remote-only", "--dry-run"}); code == 0 {
		t.Fatal("bulk dry-run should fail when preflight fails")
	}
	if actualDeletes != 0 {
		t.Fatalf("bulk dry-run should not mutate when preflight fails, got %d delete(s)", actualDeletes)
	}
	if !strings.Contains(errb.String(), "secret delete denied") {
		t.Fatalf("bulk dry-run preflight error was not clear: %s", errb.String())
	}
	out.Reset()
	errb.Reset()
	if code := app.Run([]string{"secret", "delete", "--workspace", "oclan-co", "--where", "remote-only", "--yes"}); code == 0 {
		t.Fatal("bulk delete should fail when preflight fails")
	}
	if actualDeletes != 0 {
		t.Fatalf("bulk delete should not mutate before all preflights pass, got %d delete(s)", actualDeletes)
	}
	if !strings.Contains(errb.String(), "secret delete denied") {
		t.Fatalf("bulk preflight error was not clear: %s", errb.String())
	}
}

func TestRemoteSecretBulkDeleteRestoresEarlierDeletesWhenLaterDeleteFails(t *testing.T) {
	tmp := t.TempDir()
	old := os.Getenv("ASIRI_HOME")
	t.Cleanup(func() { _ = os.Setenv("ASIRI_HOME", old) })
	if err := os.Setenv("ASIRI_HOME", tmp); err != nil {
		t.Fatal(err)
	}
	deletedIDs := []string{}
	restoredIDs := []string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		switch r.URL.Path {
		case "/v1/auth/device-code/start":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"deviceCode":              "dc_bulk_rollback",
				"userCode":                "BROLL-123",
				"verificationUriComplete": serverURL(r) + "/auth/device?code=BROLL-123",
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
				"accessToken":      "at_bulk_rollback",
				"refreshToken":     "rt_bulk_rollback",
				"expiresIn":        3600,
				"refreshExpiresAt": time.Now().UTC().Add(7 * 24 * time.Hour).Format(time.RFC3339),
			})
		case "/v1/orgs":
			assertWorkspaceOverviewTarget(t, r, "oclan-co")
			if r.URL.Query().Get("includeSecrets") != "1" {
				_ = json.NewEncoder(w).Encode(map[string]any{
					"activeOrgId":   "org_oclan",
					"organizations": []map[string]any{{"id": "org_oclan", "slug": "oclan-co", "role": "owner", "canPull": true, "canWrite": true, "currentDeviceTrusted": true, "currentDeviceId": "dev_oclan"}},
				})
				return
			}
			unwrapped := false
			_ = json.NewEncoder(w).Encode(map[string]any{
				"activeOrgId":   "org_oclan",
				"organizations": []map[string]any{{"id": "org_oclan", "slug": "oclan-co", "role": "owner", "canPull": true, "canWrite": true, "currentDeviceTrusted": true, "currentDeviceId": "dev_oclan"}},
				"secrets": []map[string]any{
					{"id": "sec_rollback_a", "orgId": "org_oclan", "workspaceSlug": "oclan-co", "scope": "oclan-co/prod", "name": "A", "version": 1, "status": "active", "canWrite": true, "wrappedToCurrentDevice": unwrapped},
					{"id": "sec_rollback_b", "orgId": "org_oclan", "workspaceSlug": "oclan-co", "scope": "oclan-co/prod", "name": "B", "version": 1, "status": "active", "canWrite": true, "wrappedToCurrentDevice": unwrapped},
				},
			})
		case "/v1/secrets/sec_rollback_a/delete-preflight", "/v1/secrets/sec_rollback_b/delete-preflight":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if body["orgId"] != "org_oclan" || body["createdByDeviceId"] != "dev_oclan" || body["version"] != float64(1) {
				t.Fatalf("rollback preflight request used wrong body: %#v", body)
			}
			id := strings.TrimPrefix(strings.TrimSuffix(r.URL.Path, "/delete-preflight"), "/v1/secrets/")
			_ = json.NewEncoder(w).Encode(map[string]any{"id": id, "orgId": "org_oclan", "scope": "oclan-co/prod", "name": strings.TrimPrefix(id, "sec_rollback_"), "version": 1, "status": "active"})
		case "/v1/secrets/sec_rollback_a/delete":
			assertSecretMutationBody(t, r, "org_oclan", "dev_oclan", 1)
			deletedIDs = append(deletedIDs, "sec_rollback_a")
			_ = json.NewEncoder(w).Encode(map[string]any{"id": "sec_rollback_a", "orgId": "org_oclan", "scope": "oclan-co/prod", "name": "A", "version": 1, "status": "deleted"})
		case "/v1/secrets/sec_rollback_b/delete":
			assertSecretMutationBody(t, r, "org_oclan", "dev_oclan", 1)
			deletedIDs = append(deletedIDs, "sec_rollback_b")
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": "delete_failed", "message": "delete failed after preflight"})
		case "/v1/secrets/sec_rollback_a/restore":
			assertSecretMutationBody(t, r, "org_oclan", "dev_oclan", 1)
			restoredIDs = append(restoredIDs, "sec_rollback_a")
			_ = json.NewEncoder(w).Encode(map[string]any{"id": "sec_rollback_a", "orgId": "org_oclan", "scope": "oclan-co/prod", "name": "A", "version": 1, "status": "active"})
		case "/v1/secrets/sec_rollback_b/restore":
			assertSecretMutationBody(t, r, "org_oclan", "dev_oclan", 1)
			restoredIDs = append(restoredIDs, "sec_rollback_b")
			_ = json.NewEncoder(w).Encode(map[string]any{"id": "sec_rollback_b", "orgId": "org_oclan", "scope": "oclan-co/prod", "name": "B", "version": 1, "status": "active"})
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
	if code := app.Run([]string{"secret", "delete", "--workspace", "oclan-co", "--where", "remote-only", "--yes"}); code == 0 {
		t.Fatal("bulk delete should fail when a post-preflight delete fails")
	}
	if got := strings.Join(deletedIDs, ","); got != "sec_rollback_a,sec_rollback_b" {
		t.Fatalf("unexpected delete attempts: %s", got)
	}
	if got := strings.Join(restoredIDs, ","); got != "sec_rollback_b,sec_rollback_a" {
		t.Fatalf("expected rollback restore for failed and first delete, got %s", got)
	}
	if !strings.Contains(errb.String(), "restored 1 earlier delete") || !strings.Contains(errb.String(), "checked failed target") {
		t.Fatalf("rollback message was not clear: %s", errb.String())
	}
}

func TestRemoteSecretBulkDeleteConfirmation(t *testing.T) {
	tmp := t.TempDir()
	old := os.Getenv("ASIRI_HOME")
	t.Cleanup(func() { _ = os.Setenv("ASIRI_HOME", old) })
	if err := os.Setenv("ASIRI_HOME", tmp); err != nil {
		t.Fatal(err)
	}
	deleteCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		switch r.URL.Path {
		case "/v1/auth/device-code/start":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"deviceCode":              "dc_bulk_confirm",
				"userCode":                "BCONF-123",
				"verificationUriComplete": serverURL(r) + "/auth/device?code=BCONF-123",
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
				"accessToken":      "at_bulk_confirm",
				"refreshToken":     "rt_bulk_confirm",
				"expiresIn":        3600,
				"refreshExpiresAt": time.Now().UTC().Add(7 * 24 * time.Hour).Format(time.RFC3339),
			})
		case "/v1/orgs":
			assertWorkspaceOverviewTarget(t, r, "oclan-co")
			if r.URL.Query().Get("includeSecrets") != "1" {
				_ = json.NewEncoder(w).Encode(map[string]any{
					"activeOrgId":   "org_oclan",
					"organizations": []map[string]any{{"id": "org_oclan", "slug": "oclan-co", "role": "owner", "canPull": true, "canWrite": true, "currentDeviceTrusted": true, "currentDeviceId": "dev_oclan"}},
				})
				return
			}
			unwrapped := false
			_ = json.NewEncoder(w).Encode(map[string]any{
				"activeOrgId":   "org_oclan",
				"organizations": []map[string]any{{"id": "org_oclan", "slug": "oclan-co", "role": "owner", "canPull": true, "canWrite": true, "currentDeviceTrusted": true, "currentDeviceId": "dev_oclan"}},
				"secrets": []map[string]any{
					{"id": "sec_confirm_bulk", "orgId": "org_oclan", "workspaceSlug": "oclan-co", "scope": "oclan-co/prod", "name": "GHOST", "version": 1, "status": "active", "canWrite": true, "wrappedToCurrentDevice": unwrapped},
				},
			})
		case "/v1/secrets/sec_confirm_bulk/delete-preflight":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if body["orgId"] != "org_oclan" || body["createdByDeviceId"] != "dev_oclan" || body["version"] != float64(1) {
				t.Fatalf("bulk preflight used wrong body: %#v", body)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id": "sec_confirm_bulk", "orgId": "org_oclan", "scope": "oclan-co/prod", "name": "GHOST", "version": 1, "status": "active",
			})
		case "/v1/secrets/sec_confirm_bulk/delete":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if body["orgId"] != "org_oclan" || body["createdByDeviceId"] != "dev_oclan" || body["version"] != float64(1) {
				t.Fatalf("confirmed bulk delete used wrong body: %#v", body)
			}
			deleteCount++
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id": "sec_confirm_bulk", "orgId": "org_oclan", "scope": "oclan-co/prod", "name": "GHOST", "version": 1, "status": "deleted",
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
		{"init", "--device", "qa-laptop", "--workspace", "oclan-co"},
		{"login", "--origin", server.URL},
	} {
		out.Reset()
		errb.Reset()
		if code := app.Run(step); code != 0 {
			t.Fatalf("%v failed with code %d stderr=%s", step, code, errb.String())
		}
	}
	app.In = strings.NewReader("delete oclan-co 2\n")
	out.Reset()
	errb.Reset()
	if code := app.Run([]string{"secret", "delete", "--workspace", "oclan-co", "--remote-only-unwrapped"}); code == 0 {
		t.Fatal("bulk remote delete should fail when confirmation does not match")
	}
	if !strings.Contains(out.String(), "prod/GHOST") {
		t.Fatalf("bulk confirmation should print affected paths: %s", out.String())
	}
	if !strings.Contains(errb.String(), "confirmation did not match") {
		t.Fatalf("bulk confirmation mismatch was not clear: %s", errb.String())
	}
	if deleteCount != 0 {
		t.Fatalf("bulk confirmation mismatch should not delete, got %d delete(s)", deleteCount)
	}
	app.In = strings.NewReader("delete oclan-co 1\n")
	out.Reset()
	errb.Reset()
	if code := app.Run([]string{"secret", "delete", "--workspace", "oclan-co", "--remote-only-unwrapped"}); code != 0 {
		t.Fatalf("confirmed bulk remote delete failed: %s", errb.String())
	}
	if deleteCount != 1 {
		t.Fatalf("expected one confirmed bulk delete, got %d", deleteCount)
	}
}
