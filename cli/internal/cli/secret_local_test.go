package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRawReadDoesNotPrintSecretWhenAuditSaveFails(t *testing.T) {
	tmp := t.TempDir()
	old := os.Getenv("ASIRI_HOME")
	t.Cleanup(func() { _ = os.Setenv("ASIRI_HOME", old) })
	if err := os.Setenv("ASIRI_HOME", tmp); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	app := New(&out, &errb)
	for _, step := range [][]string{
		{"init", "--device", "qa-laptop"},
		{"add", "--workspace", "oclan-co", "local/asiri/API_KEY", "--value-file", testSecretFile(t, "do_not_print")},
	} {
		out.Reset()
		errb.Reset()
		if code := app.Run(step); code != 0 {
			t.Fatalf("%v failed: %s", step, errb.String())
		}
	}
	statePath := filepath.Join(tmp, "local-state.json")
	if err := os.Chmod(statePath, 0o400); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(statePath, 0o600) })
	out.Reset()
	errb.Reset()
	if code := app.Run([]string{"get", "--workspace", "oclan-co", "local/asiri/API_KEY"}); code == 0 {
		t.Fatal("expected raw read to fail when audit save fails")
	}
	if strings.Contains(out.String(), "do_not_print") {
		t.Fatalf("secret printed despite audit save failure: %s", out.String())
	}
}

func TestListMergesRequestedWorkspaceRemoteSecrets(t *testing.T) {
	tmp := t.TempDir()
	old := os.Getenv("ASIRI_HOME")
	t.Cleanup(func() { _ = os.Setenv("ASIRI_HOME", old) })
	if err := os.Setenv("ASIRI_HOME", tmp); err != nil {
		t.Fatal(err)
	}
	workspaceOverviewSeen := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		switch r.URL.Path {
		case "/v1/auth/device-code/start":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"deviceCode":              "dc_list",
				"userCode":                "LIST-1234",
				"verificationUriComplete": serverURL(r) + "/auth/device?code=LIST-1234",
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
				"accessToken":      "at_list",
				"refreshToken":     "rt_list",
				"expiresIn":        3600,
				"refreshExpiresAt": time.Now().UTC().Add(7 * 24 * time.Hour).Format(time.RFC3339),
			})
		case "/v1/orgs":
			workspaceOverviewSeen = true
			workspace := r.URL.Query().Get("workspace")
			if workspace == "peter-dev" {
				_ = json.NewEncoder(w).Encode(map[string]any{
					"organizations": []map[string]any{{"id": "org_personal", "slug": "peter-dev", "role": "owner", "canPull": false, "canWrite": true, "currentDeviceTrusted": false}},
					"secrets":       []map[string]any{},
				})
				return
			}
			assertWorkspaceOverviewTarget(t, r, "oclan-co")
			if r.Header.Get("authorization") != "Bearer at_list" {
				t.Fatalf("unexpected workspace overview auth header: %s", r.Header.Get("authorization"))
			}
			if r.URL.Query().Get("includeSecrets") != "1" {
				t.Fatalf("list should request remote secret metadata, got %s", r.URL.RawQuery)
			}
			secrets := []map[string]any{
				{"id": "sec_synced", "orgId": "org_oclan", "workspaceSlug": "oclan-co", "scope": "oclan-co/local/asiri", "name": "PUSHED", "version": 1, "status": "active", "canWrite": true},
			}
			if r.URL.Query().Get("includeInactive") == "1" {
				secrets = append(secrets,
					map[string]any{"id": "sec_history_old", "orgId": "org_oclan", "workspaceSlug": "oclan-co", "scope": "oclan-co/local/asiri", "name": "HISTORY", "version": 1, "status": "stale", "canWrite": true},
					map[string]any{"id": "sec_history_active", "orgId": "org_oclan", "workspaceSlug": "oclan-co", "scope": "oclan-co/local/asiri", "name": "HISTORY", "version": 2, "status": "active", "canWrite": true},
				)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"activeOrgId":   "org_oclan",
				"organizations": []map[string]any{{"id": "org_oclan", "slug": "oclan-co", "role": "owner", "canPull": true, "canWrite": true, "currentDeviceTrusted": true, "currentDeviceId": "dev_oclan"}},
				"secrets":       secrets,
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
		{"add", "--workspace", "oclan-co", "local/asiri/PUSHED", "--value-file", testSecretFile(t, "secret_value")},
		{"add", "--workspace", "oclan-co", "local/asiri/UNPUSHED", "--value-file", testSecretFile(t, "secret_value")},
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
	if code := app.Run([]string{"list", "--workspace", "oclan-co"}); code != 0 {
		t.Fatalf("list failed: %s", errb.String())
	}
	if !workspaceOverviewSeen {
		t.Fatal("expected workspace overview endpoint")
	}
	all := out.String()
	for _, expected := range []string{"oclan-co", "local/asiri/PUSHED", "synced,writable", "local/asiri/UNPUSHED", "local-only"} {
		if !strings.Contains(all, expected) {
			t.Fatalf("list output missing %q: %s", expected, all)
		}
	}
	if strings.Contains(all, "REMOTE_ONLY") || strings.Contains(all, "remote-only,read-only") {
		t.Fatalf("list output included filtered workspace remote secret: %s", all)
	}
	out.Reset()
	errb.Reset()
	if code := app.Run([]string{"list", "--workspace", "oclan-co", "--include-inactive"}); code != 0 {
		t.Fatalf("inactive list failed: %s", errb.String())
	}
	historyLines := []string{}
	for _, line := range strings.Split(out.String(), "\n") {
		if strings.Contains(line, "local/asiri/HISTORY") {
			historyLines = append(historyLines, line)
		}
	}
	if len(historyLines) != 2 {
		t.Fatalf("expected inactive history versions to render as separate rows, got %d in %s", len(historyLines), out.String())
	}
	if !(strings.Contains(historyLines[0], "v1") && strings.Contains(historyLines[0], "stale") || strings.Contains(historyLines[1], "v1") && strings.Contains(historyLines[1], "stale")) {
		t.Fatalf("expected stale history row in %v", historyLines)
	}
	if !(strings.Contains(historyLines[0], "v2") && strings.Contains(historyLines[0], "active") || strings.Contains(historyLines[1], "v2") && strings.Contains(historyLines[1], "active")) {
		t.Fatalf("expected active history row in %v", historyLines)
	}
	out.Reset()
	errb.Reset()
	if code := app.Run([]string{"list", "--workspace", "peter-dev"}); code != 0 {
		t.Fatalf("workspace-filtered list failed: %s", errb.String())
	}
	if strings.Contains(out.String(), "REMOTE_ONLY") || strings.Contains(out.String(), "local/asiri") {
		t.Fatalf("workspace filter output unexpected: %s", out.String())
	}
	out.Reset()
	errb.Reset()
	if code := app.Run([]string{"list", "--local", "--workspace", "oclan-co"}); code != 0 {
		t.Fatalf("local-filtered list failed: %s", errb.String())
	}
	if strings.Contains(out.String(), "REMOTE_ONLY") || !strings.Contains(out.String(), "UNPUSHED") {
		t.Fatalf("local filter output unexpected: %s", out.String())
	}
}

func TestListLocalDoesNotRequireRemoteAuth(t *testing.T) {
	tmp := t.TempDir()
	old := os.Getenv("ASIRI_HOME")
	t.Cleanup(func() { _ = os.Setenv("ASIRI_HOME", old) })
	if err := os.Setenv("ASIRI_HOME", tmp); err != nil {
		t.Fatal(err)
	}
	remoteCallsAfterLogin := 0
	loginComplete := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		if loginComplete {
			remoteCallsAfterLogin++
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": "expired"})
			return
		}
		switch r.URL.Path {
		case "/v1/auth/device-code/start":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"deviceCode":              "dc_local_list",
				"userCode":                "LLST-123",
				"verificationUriComplete": serverURL(r) + "/auth/device?code=LLST-123",
				"expiresIn":               30,
				"interval":                0,
			})
		case "/v1/auth/device-code/token":
			loginComplete = true
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status":           "approved",
				"orgId":            "org_oclan",
				"workspaceSlug":    "oclan-co",
				"userId":           "usr_owner",
				"deviceId":         "dev_oclan",
				"accessToken":      "at_local_list",
				"refreshToken":     "rt_local_list",
				"expiresIn":        3600,
				"refreshExpiresAt": time.Now().UTC().Add(7 * 24 * time.Hour).Format(time.RFC3339),
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
	if code := app.Run([]string{"list", "--local", "--workspace", "oclan-co"}); code != 0 {
		t.Fatalf("local list failed: %s", errb.String())
	}
	if remoteCallsAfterLogin != 0 {
		t.Fatalf("local list should not call remote endpoints, got %d call(s)", remoteCallsAfterLogin)
	}
	if !strings.Contains(out.String(), "No local secrets found.") {
		t.Fatalf("local list output did not explain empty local vault: %s", out.String())
	}
	out.Reset()
	errb.Reset()
	if code := app.Run([]string{"list", "--local", "--workspace", "org_oclan"}); code == 0 {
		t.Fatal("local list should reject workspace ids without remote lookup")
	}
	if remoteCallsAfterLogin != 0 {
		t.Fatalf("local list with invalid workspace should not call remote endpoints, got %d call(s)", remoteCallsAfterLogin)
	}
}

func TestListExplainsRewrapLocationForUnusableRemoteKeys(t *testing.T) {
	tmp := t.TempDir()
	old := os.Getenv("ASIRI_HOME")
	t.Cleanup(func() { _ = os.Setenv("ASIRI_HOME", old) })
	if err := os.Setenv("ASIRI_HOME", tmp); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		switch r.URL.Path {
		case "/v1/auth/device-code/start":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"deviceCode":              "dc_list_actions",
				"userCode":                "LACT-123",
				"verificationUriComplete": serverURL(r) + "/auth/device?code=LACT-123",
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
				"accessToken":      "at_list_actions",
				"refreshToken":     "rt_list_actions",
				"expiresIn":        3600,
				"refreshExpiresAt": time.Now().UTC().Add(7 * 24 * time.Hour).Format(time.RFC3339),
			})
		case "/v1/orgs":
			assertWorkspaceOverviewTarget(t, r, "oclan-co")
			if r.URL.Query().Get("includeSecrets") != "1" {
				t.Fatalf("list actions should request remote secret metadata, got %s", r.URL.RawQuery)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"activeOrgId":   "org_oclan",
				"organizations": []map[string]any{{"id": "org_oclan", "slug": "oclan-co", "role": "owner", "canPull": true, "canWrite": true, "currentDeviceTrusted": true, "currentDeviceId": "dev_oclan"}},
				"secrets": []map[string]any{
					{"id": "sec_needs_rewrap", "orgId": "org_oclan", "workspaceSlug": "oclan-co", "scope": "oclan-co/local/asiri", "name": "LOCAL_NEEDS_REWRAP", "version": 1, "status": "active", "canWrite": true, "wrappedToCurrentDevice": false, "currentDeviceId": "dev_oclan"},
					{"id": "sec_unwrapped", "orgId": "org_oclan", "workspaceSlug": "oclan-co", "scope": "oclan-co/local/asiri", "name": "REMOTE_ONLY_UNWRAPPED", "version": 1, "status": "active", "canWrite": true, "wrappedToCurrentDevice": false, "currentDeviceId": "dev_oclan"},
					{"id": "sec_not_trusted", "orgId": "org_asiri", "workspaceSlug": "asiri-dev", "scope": "asiri-dev/prod", "name": "REMOTE_NOT_TRUSTED", "version": 1, "status": "active", "canWrite": true, "wrappedToCurrentDevice": false},
				},
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
		{"add", "--workspace", "oclan-co", "local/asiri/LOCAL_NEEDS_REWRAP", "--value-file", testSecretFile(t, "secret_value")},
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
	if code := app.Run([]string{"list", "--workspace", "oclan-co"}); code != 0 {
		t.Fatalf("list failed: %s", errb.String())
	}
	all := out.String()
	for _, expected := range []string{
		"LOCAL_NEEDS_REWRAP", "synced,writable", "needs rewrap",
		"REMOTE_ONLY_UNWRAPPED", "remote-only,writable", "unwrapped",
		"Next:",
		"run asiri rewrap --workspace oclan-co here",
		"run asiri rewrap --workspace oclan-co on a device where these secrets are wrapped, then run asiri pull --workspace oclan-co here",
	} {
		if !strings.Contains(all, expected) {
			t.Fatalf("list output missing %q: %s", expected, all)
		}
	}
	if strings.Contains(all, "REMOTE_NOT_TRUSTED") {
		t.Fatalf("workspace-scoped list included another workspace: %s", all)
	}
}

func TestLocalWipeDoesNotCallRemoteAPIs(t *testing.T) {
	tmp := t.TempDir()
	old := os.Getenv("ASIRI_HOME")
	t.Cleanup(func() { _ = os.Setenv("ASIRI_HOME", old) })
	if err := os.Setenv("ASIRI_HOME", tmp); err != nil {
		t.Fatal(err)
	}
	remoteCallsAfterLogin := 0
	loginComplete := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		if loginComplete {
			remoteCallsAfterLogin++
			http.NotFound(w, r)
			return
		}
		switch r.URL.Path {
		case "/v1/auth/device-code/start":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"deviceCode":              "dc_local_wipe",
				"userCode":                "WIPE-123",
				"verificationUriComplete": serverURL(r) + "/auth/device?code=WIPE-123",
				"expiresIn":               30,
				"interval":                0,
			})
		case "/v1/auth/device-code/token":
			loginComplete = true
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status":           "approved",
				"orgId":            "org_oclan",
				"workspaceSlug":    "oclan-co",
				"userId":           "usr_owner",
				"deviceId":         "dev_oclan",
				"accessToken":      "at_local_wipe",
				"refreshToken":     "rt_local_wipe",
				"expiresIn":        3600,
				"refreshExpiresAt": time.Now().UTC().Add(7 * 24 * time.Hour).Format(time.RFC3339),
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
	out.Reset()
	errb.Reset()
	if code := app.Run([]string{"local", "wipe", "--yes"}); code != 0 {
		t.Fatalf("local wipe failed: %s", errb.String())
	}
	if remoteCallsAfterLogin != 0 {
		t.Fatalf("local wipe should not call remote endpoints, got %d call(s)", remoteCallsAfterLogin)
	}
	if _, err := os.Stat(filepath.Join(tmp, ".asiri", "local-state.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("local wipe should remove state file, stat err=%v", err)
	}
}
