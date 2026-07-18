package cli

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/o-clan/asiri/cli/internal/asiri"
	"github.com/o-clan/asiri/cli/internal/store"
)

func TestDeviceEnrollRequiresLogoutBeforeCreatingKeys(t *testing.T) {
	tmp := t.TempDir()
	old := os.Getenv("ASIRI_HOME")
	t.Cleanup(func() { _ = os.Setenv("ASIRI_HOME", old) })
	if err := os.Setenv("ASIRI_HOME", tmp); err != nil {
		t.Fatal(err)
	}

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
	if _, err := st.AddSecret("prod/local/API_KEY", "preserved-secret"); err != nil {
		t.Fatal(err)
	}
	if err := st.LinkControlPlaneForDevice("http://control.test", "org_prod", "prod", "usr_owner", "dev_remote", device.ID, "at_old", "rt_old", 3600, time.Now().UTC().Add(24*time.Hour).Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
	devicesBefore := append([]asiri.Device(nil), st.State.Devices...)
	keyRefsBefore := append([]asiri.KeyRef(nil), st.State.KeyRefs...)
	localDeviceIDBefore := st.State.LocalDeviceID

	out.Reset()
	errb.Reset()
	if code := app.Run([]string{"device", "enroll", "--name", "replacement"}); code == 0 {
		t.Fatal("device enroll should require logout while a session is linked")
	}
	if !strings.Contains(errb.String(), "asiri logout first") || !strings.Contains(errb.String(), "local vault and secrets are preserved") {
		t.Fatalf("device enroll missing safe logout guidance: %s", errb.String())
	}

	reloaded, err := store.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(reloaded.State.Devices, devicesBefore) || reloaded.State.LocalDeviceID != localDeviceIDBefore {
		t.Fatalf("rejected enrollment changed local devices: devices=%#v local=%s", reloaded.State.Devices, reloaded.State.LocalDeviceID)
	}
	if !reflect.DeepEqual(reloaded.State.KeyRefs, keyRefsBefore) {
		t.Fatalf("rejected enrollment created or removed key refs: got=%#v want=%#v", reloaded.State.KeyRefs, keyRefsBefore)
	}
	if value, _, err := reloaded.GetSecret("prod/local/API_KEY"); err != nil || value != "preserved-secret" {
		t.Fatalf("rejected enrollment made the local secret unusable: value=%q err=%v", value, err)
	}
}

func TestDeviceNamePrintsActiveLocalDevice(t *testing.T) {
	tmp := t.TempDir()
	old := os.Getenv("ASIRI_HOME")
	t.Cleanup(func() { _ = os.Setenv("ASIRI_HOME", old) })
	if err := os.Setenv("ASIRI_HOME", tmp); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	var errb bytes.Buffer
	app := New(&out, &errb)
	if code := app.Run([]string{"init", "--device", "qa-laptop"}); code != 0 {
		t.Fatalf("init failed: %s", errb.String())
	}

	out.Reset()
	errb.Reset()
	if code := app.Run([]string{"device", "name"}); code != 0 {
		t.Fatalf("device name failed: %s", errb.String())
	}
	if strings.TrimSpace(out.String()) != "qa-laptop" {
		t.Fatalf("unexpected device name output: %q", out.String())
	}
}

func TestDeviceEnrollPersistsExplicitKind(t *testing.T) {
	tmp := t.TempDir()
	old := os.Getenv("ASIRI_HOME")
	t.Cleanup(func() { _ = os.Setenv("ASIRI_HOME", old) })
	if err := os.Setenv("ASIRI_HOME", tmp); err != nil {
		t.Fatal(err)
	}

	var out, errb bytes.Buffer
	app := New(&out, &errb)
	if code := app.Run([]string{"init", "--device", "initial", "--kind", "laptop"}); code != 0 {
		t.Fatalf("init failed: %s", errb.String())
	}
	if code := app.Run([]string{"device", "enroll", "--name", "replacement", "--kind", "agent-host"}); code != 0 {
		t.Fatalf("device enroll failed: %s", errb.String())
	}
	st, err := store.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	device, err := st.ActiveDevice()
	if err != nil {
		t.Fatal(err)
	}
	if device.Name != "replacement" || device.Kind != "agent-host" {
		t.Fatalf("explicit device metadata was not persisted: name=%q kind=%q", device.Name, device.Kind)
	}
}

func TestDeviceListRequiresExplicitRemoteWorkspaceWhenLinked(t *testing.T) {
	tmp := t.TempDir()
	old := os.Getenv("ASIRI_HOME")
	t.Cleanup(func() { _ = os.Setenv("ASIRI_HOME", old) })
	if err := os.Setenv("ASIRI_HOME", tmp); err != nil {
		t.Fatal(err)
	}

	deviceListSeen := false
	includeRevokedSeen := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		switch r.URL.Path {
		case "/v1/auth/device-code/start":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"deviceCode":              "dc_devices",
				"userCode":                "DEVS-1234",
				"verificationUri":         serverURL(r) + "/auth/device",
				"verificationUriComplete": serverURL(r) + "/auth/device?code=DEVS-1234",
				"expiresIn":               30,
				"interval":                0,
			})
		case "/v1/auth/device-code/token":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status":           "approved",
				"orgId":            "org_remote",
				"workspaceSlug":    "oclan-co",
				"userId":           "usr_owner",
				"deviceId":         "dev_remote_current",
				"accessToken":      "at_devices",
				"refreshToken":     "rt_devices",
				"expiresIn":        3600,
				"refreshExpiresAt": time.Now().UTC().Add(7 * 24 * time.Hour).Format(time.RFC3339),
			})
		case "/v1/orgs":
			if r.Header.Get("authorization") != "Bearer at_devices" {
				t.Fatalf("unexpected org list auth header: %s", r.Header.Get("authorization"))
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"activeOrgId": "org_remote",
				"organizations": []map[string]any{
					{"id": "org_remote", "name": "O Clan", "slug": "oclan-co", "ownerUserId": "usr_owner", "role": "owner", "canPull": true, "canWrite": true, "currentDeviceTrusted": true, "currentDeviceId": "dev_remote_current", "canApproveDevice": true},
				},
			})
		case "/v1/devices":
			deviceListSeen = true
			if r.URL.Query().Get("includeInactive") == "1" {
				includeRevokedSeen = true
			}
			if r.URL.Query().Get("orgId") != "org_remote" {
				t.Fatalf("unexpected device list query: %s", r.URL.RawQuery)
			}
			if r.Header.Get("authorization") != "Bearer at_devices" {
				t.Fatalf("unexpected device list auth header: %s", r.Header.Get("authorization"))
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"devices": []map[string]any{
					{"id": "dev_remote_current", "name": "manor-box", "status": "trusted", "kind": "laptop"},
					{"id": "dev_remote_server", "name": "prod-server", "status": "trusted", "kind": "server"},
					{"id": "dev_remote_old", "name": "old-laptop", "status": "revoked", "kind": "laptop"},
				},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	var out, errb bytes.Buffer
	app := New(&out, &errb)
	for _, step := range [][]string{
		{"init", "--device", "manor-box"},
		{"login", "--origin", server.URL},
	} {
		out.Reset()
		errb.Reset()
		if code := app.Run(step); code != 0 {
			t.Fatalf("%v failed: %s", step, errb.String())
		}
	}

	out.Reset()
	errb.Reset()
	if code := app.Run([]string{"device", "list", "--remote", "--workspace", "oclan-co"}); code != 0 {
		t.Fatalf("device list failed: %s", errb.String())
	}
	if !deviceListSeen {
		t.Fatal("device list should call the remote device endpoint when linked")
	}
	for _, expected := range []string{"WORKSPACE", "oclan-co", "dev_remote_current", "manor-box", "dev_remote_server", "prod-server"} {
		if !strings.Contains(out.String(), expected) {
			t.Fatalf("remote device list missing %q: %s", expected, out.String())
		}
	}
	for _, unexpected := range []string{"dev_remote_old", "old-laptop", "revoked"} {
		if strings.Contains(out.String(), unexpected) {
			t.Fatalf("remote device list should hide revoked device %q by default: %s", unexpected, out.String())
		}
	}

	out.Reset()
	errb.Reset()
	if code := app.Run([]string{"device", "list", "--remote", "--workspace", "oclan-co", "--include-revoked"}); code != 0 {
		t.Fatalf("device list --include-revoked failed: %s", errb.String())
	}
	if !includeRevokedSeen {
		t.Fatal("device list --include-revoked should request inactive remote devices")
	}
	for _, expected := range []string{"dev_remote_old", "old-laptop", "revoked"} {
		if !strings.Contains(out.String(), expected) {
			t.Fatalf("remote device list with --include-revoked missing %q: %s", expected, out.String())
		}
	}

	out.Reset()
	errb.Reset()
	if code := app.Run([]string{"device", "list", "--local"}); code != 0 {
		t.Fatalf("device list --local failed: %s", errb.String())
	}
	if !strings.Contains(out.String(), "manor-box") || strings.Contains(out.String(), "prod-server") {
		t.Fatalf("local device list should only show local device records: %s", out.String())
	}
}

func TestRemoteSelfRevokeKeepsLocalRuntimeAndAuthSession(t *testing.T) {
	tmp := t.TempDir()
	old := os.Getenv("ASIRI_HOME")
	t.Cleanup(func() { _ = os.Setenv("ASIRI_HOME", old) })
	if err := os.Setenv("ASIRI_HOME", tmp); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/device-code/start":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"deviceCode":              "dc_self",
				"userCode":                "SELF-1234",
				"verificationUri":         serverURL(r) + "/auth/device",
				"verificationUriComplete": serverURL(r) + "/auth/device?code=SELF-1234",
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
				"accessToken":      "at_self",
				"refreshToken":     "rt_self",
				"expiresIn":        3600,
				"refreshExpiresAt": time.Now().UTC().Add(7 * 24 * time.Hour).Format(time.RFC3339),
			})
		case "/v1/orgs":
			assertWorkspaceOverviewTarget(t, r, "oclan-co")
			_ = json.NewEncoder(w).Encode(map[string]any{"organizations": []map[string]any{{
				"id": "org_remote", "slug": "oclan-co", "role": "owner", "canPull": true, "canWrite": true, "currentDeviceTrusted": true, "currentDeviceId": "dev_remote",
			}}})
		case "/v1/devices":
			if r.URL.Query().Get("orgId") != "org_remote" {
				t.Fatalf("unexpected remote device query: %s", r.URL.RawQuery)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"devices": []map[string]any{{"id": "dev_remote", "name": "qa-laptop", "status": "trusted"}}})
		case "/v1/devices/dev_remote/revoke":
			if r.Header.Get("authorization") != "Bearer at_self" {
				t.Fatalf("unexpected remote revoke auth header: %s", r.Header.Get("authorization"))
			}
			assertRequestWorkspace(t, r, "org_remote")
			_ = json.NewEncoder(w).Encode(map[string]any{"id": "dev_remote", "name": "qa-laptop", "status": "revoked"})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	var out, errb bytes.Buffer
	app := New(&out, &errb)
	for _, step := range [][]string{
		{"init", "--device", "qa-laptop"},
		{"add", "--workspace", "oclan-co", "local/asiri/API_KEY", "--value-file", testSecretFile(t, "blocked_after_revoke")},
		{"login", "--origin", server.URL},
		{"device", "revoke", "--workspace", "oclan-co", "dev_remote", "--remote"},
	} {
		out.Reset()
		errb.Reset()
		if code := app.Run(step); code != 0 {
			t.Fatalf("%v failed: %s", step, errb.String())
		}
	}
	st, err := store.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	if st.State.ControlPlane == nil {
		t.Fatal("workspace device revocation should not clear the account session")
	}
	if len(st.State.KeyRefs) == 0 {
		t.Fatal("workspace device revocation should not clear local key refs")
	}
	if value, _, err := st.GetSecret("oclan-co/local/asiri/API_KEY"); err != nil || value != "blocked_after_revoke" {
		t.Fatalf("workspace device revocation should preserve local decryption, value=%q err=%v", value, err)
	}
}

func TestRemoteRevokeConflictKeepsLocalRuntime(t *testing.T) {
	tmp := t.TempDir()
	old := os.Getenv("ASIRI_HOME")
	t.Cleanup(func() { _ = os.Setenv("ASIRI_HOME", old) })
	if err := os.Setenv("ASIRI_HOME", tmp); err != nil {
		t.Fatal(err)
	}
	revokeSeen := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/orgs":
			assertWorkspaceOverviewTarget(t, r, "oclan-co")
			_ = json.NewEncoder(w).Encode(map[string]any{"organizations": []map[string]any{{
				"id": "org_remote", "slug": "oclan-co", "role": "owner", "canPull": true, "canWrite": true, "currentDeviceTrusted": true, "currentDeviceId": "dev_remote",
			}}})
		case "/v1/devices":
			if r.URL.Query().Get("orgId") != "org_remote" {
				t.Fatalf("unexpected remote device query: %s", r.URL.RawQuery)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"devices": []map[string]any{{"id": "dev_remote", "name": "qa-laptop", "status": "trusted"}}})
		case "/v1/devices/dev_remote/revoke":
			revokeSeen = true
			if r.Header.Get("authorization") != "Bearer at_test" {
				t.Fatalf("unexpected remote revoke auth header: %s", r.Header.Get("authorization"))
			}
			assertRequestWorkspace(t, r, "org_remote")
			w.WriteHeader(http.StatusConflict)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"error":               "request_failed",
				"message":             "device revocation would leave 1 active secret version(s) without any trusted device or recovery key; configure recovery or rewrap another trusted device first",
				"affectedSecretCount": 1,
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
	if err := st.LinkControlPlaneForDevice(server.URL, "org_remote", "oclan-co", "usr_owner", "dev_remote", device.ID, "at_test", "rt_test", 3600, time.Now().UTC().Add(7*24*time.Hour).Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	errb.Reset()
	if code := app.Run([]string{"device", "revoke", "--workspace", "oclan-co", "dev_remote", "--remote"}); code == 0 {
		t.Fatalf("remote revoke should fail")
	}
	if !revokeSeen {
		t.Fatalf("expected remote revoke endpoint to be called")
	}
	if !strings.Contains(errb.String(), "without any trusted device or recovery key") {
		t.Fatalf("remote revoke conflict should include server guidance: %s", errb.String())
	}
	reloaded, err := store.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.State.ControlPlane == nil {
		t.Fatalf("failed remote revoke should keep control-plane link")
	}
	if len(reloaded.State.KeyRefs) == 0 {
		t.Fatalf("failed remote revoke should keep local key refs")
	}
}

func TestRemoteRevokeRejectsDeviceOutsideRequestedWorkspace(t *testing.T) {
	tmp := t.TempDir()
	old := os.Getenv("ASIRI_HOME")
	t.Cleanup(func() { _ = os.Setenv("ASIRI_HOME", old) })
	if err := os.Setenv("ASIRI_HOME", tmp); err != nil {
		t.Fatal(err)
	}
	mutationSeen := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		switch r.URL.Path {
		case "/v1/orgs":
			_ = json.NewEncoder(w).Encode(map[string]any{"organizations": []map[string]any{{
				"id": "org_target", "slug": "target", "role": "owner", "canPull": true, "canWrite": true, "currentDeviceTrusted": true, "currentDeviceId": "dev_target",
			}}})
		case "/v1/devices":
			if r.URL.Query().Get("orgId") != "org_target" {
				t.Fatalf("unexpected device list workspace: %s", r.URL.RawQuery)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"devices": []map[string]any{{"id": "dev_target", "name": "target-device", "status": "trusted"}}})
		case "/v1/devices/dev_foreign/revoke":
			mutationSeen = true
			_ = json.NewEncoder(w).Encode(map[string]any{"id": "dev_foreign", "status": "revoked"})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	var out, errb bytes.Buffer
	app := New(&out, &errb)
	if code := app.Run([]string{"init", "--device", "target-device"}); code != 0 {
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
	if err := st.LinkControlPlaneForDevice(server.URL, "org_target", "target", "usr_owner", "dev_target", device.ID, "at_target", "rt_target", 3600, time.Now().UTC().Add(7*24*time.Hour).Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	errb.Reset()
	if code := app.Run([]string{"device", "revoke", "--remote", "--workspace", "target", "dev_foreign"}); code == 0 {
		t.Fatal("foreign workspace device should not be revoked")
	}
	if mutationSeen {
		t.Fatal("foreign device revoke endpoint should not be called")
	}
	if !strings.Contains(errb.String(), "was not found in workspace target") {
		t.Fatalf("unexpected foreign-device error: %s", errb.String())
	}
}

func TestRemoteWorkspaceRevocationDoesNotClearLocalKeyMaterial(t *testing.T) {
	tmp := t.TempDir()
	old := os.Getenv("ASIRI_HOME")
	t.Cleanup(func() { _ = os.Setenv("ASIRI_HOME", old) })
	if err := os.Setenv("ASIRI_HOME", tmp); err != nil {
		t.Fatal(err)
	}
	revoked := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		switch r.URL.Path {
		case "/v1/auth/device-code/start":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"deviceCode":              "dc_revoked",
				"userCode":                "REVOKE-1",
				"verificationUriComplete": serverURL(r) + "/auth/device?code=REVOKE-1",
				"expiresIn":               30,
				"interval":                0,
			})
		case "/v1/auth/device-code/token":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status":           "approved",
				"orgId":            "org_revoked",
				"workspaceSlug":    "oclan-co",
				"userId":           "usr_owner",
				"deviceId":         "dev_revoked",
				"accessToken":      "at_revoked",
				"refreshToken":     "rt_revoked",
				"expiresIn":        3600,
				"refreshExpiresAt": time.Now().UTC().Add(7 * 24 * time.Hour).Format(time.RFC3339),
			})
		case "/v1/auth/session/refresh":
			revoked = true
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": "device_not_trusted"})
		case "/v1/orgs":
			revoked = true
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": "device_not_trusted", "message": "device_not_trusted"})
		case "/v1/sync":
			revoked = true
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": "device_not_trusted"})
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
	if code := app.Run([]string{"pull", "--workspace", "oclan-co"}); code == 0 {
		t.Fatalf("expected revoked device pull failure, stdout=%s", out.String())
	}
	if !revoked || !strings.Contains(errb.String(), "device_not_trusted") {
		t.Fatalf("expected workspace trust failure, revoked=%v stderr=%s", revoked, errb.String())
	}
	st, err := store.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	if st.State.ControlPlane == nil || len(st.State.KeyRefs) == 0 {
		t.Fatalf("workspace revocation cleared the account session or local keys: %#v", st.State)
	}
	if value, _, err := st.GetSecret("oclan-co/local/asiri/API_KEY"); err != nil || value != "secret_value" {
		t.Fatalf("workspace revocation should preserve local vault access, value=%q err=%v", value, err)
	}
}

func TestDeviceStatusShowsTrustAndKeyCoverage(t *testing.T) {
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
				"deviceCode":              "dc_status",
				"userCode":                "STAT-123",
				"verificationUri":         serverURL(r) + "/auth/device",
				"verificationUriComplete": serverURL(r) + "/auth/device?code=STAT-123",
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
			if r.URL.Query().Get("includeSecrets") != "1" {
				t.Fatalf("device status should request workspace secret metadata, got %s", r.URL.RawQuery)
			}
			assertWorkspaceOverviewTarget(t, r, "oclan-co")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"activeOrgId": "org_oclan",
				"organizations": []map[string]any{
					{"id": "org_oclan", "slug": "oclan-co", "ownerUserId": "usr_owner", "role": "owner", "canPull": true, "currentDeviceTrusted": true, "currentDeviceId": "dev_oclan", "canWrite": true, "canApproveDevice": true},
					{"id": "org_asiri", "slug": "asiri-dev", "ownerUserId": "usr_owner", "role": "owner", "canPull": false, "currentDeviceTrusted": false, "canWrite": true, "canApproveDevice": true},
					{"id": "org_recall", "slug": "recallstack-com", "ownerUserId": "usr_owner", "role": "owner", "canPull": true, "currentDeviceTrusted": true, "currentDeviceId": "dev_recall", "canWrite": true, "canApproveDevice": true},
				},
				"secrets": []map[string]any{
					{"id": "sec_ready", "orgId": "org_oclan", "workspaceSlug": "oclan-co", "scope": "oclan-co/local", "name": "READY", "version": 1, "status": "active", "canWrite": true, "wrappedToCurrentDevice": true},
					{"id": "sec_needs", "orgId": "org_recall", "workspaceSlug": "recallstack-com", "scope": "recallstack-com/prod", "name": "OLD", "version": 1, "status": "active", "canWrite": true, "wrappedToCurrentDevice": false},
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
	if code := app.Run([]string{"device", "status", "--workspace", "oclan-co"}); code != 0 {
		t.Fatalf("device status failed: %s", errb.String())
	}
	status := out.String()
	for _, expected := range []string{"This device: qa-laptop", "WORKSPACE", "THIS DEVICE", "ACCOUNT WRITE", "KEYS", "NEXT", "oclan-co", "ready"} {
		if !strings.Contains(status, expected) {
			t.Fatalf("device status output missing %q: %s", expected, status)
		}
	}
	if strings.Contains(status, "asiri-dev") || strings.Contains(status, "recallstack-com") {
		t.Fatalf("device status included unrequested workspaces: %s", status)
	}
}

func TestDeviceTrustStopsBeforeStartingCodeForRevokedKeys(t *testing.T) {
	tmp := t.TempDir()
	old := os.Getenv("ASIRI_HOME")
	t.Cleanup(func() { _ = os.Setenv("ASIRI_HOME", old) })
	if err := os.Setenv("ASIRI_HOME", tmp); err != nil {
		t.Fatal(err)
	}

	deviceCodeStarted := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		switch r.URL.Path {
		case "/v1/orgs":
			assertWorkspaceOverviewTarget(t, r, "prod")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"organizations": []map[string]any{{
					"id": "org_prod", "slug": "prod", "role": "owner", "canPull": false, "canWrite": true,
					"currentDeviceTrusted": false, "currentDeviceStatus": "revoked", "canApproveDevice": true,
				}},
			})
		case "/v1/auth/device-code/start":
			deviceCodeStarted = true
			http.Error(w, "unexpected device-code start", http.StatusInternalServerError)
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
	if err := st.LinkControlPlaneForDevice(server.URL, "org_prod", "prod", "usr_owner", "dev_revoked", device.ID, "at_cached", "rt_cached", 3600, time.Now().UTC().Add(24*time.Hour).Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}

	out.Reset()
	errb.Reset()
	if code := app.Run([]string{"device", "trust", "--workspace", "prod"}); code == 0 {
		t.Fatal("device trust should reject permanently revoked keys")
	}
	if deviceCodeStarted {
		t.Fatal("device trust should not start a device code for revoked keys")
	}
	requireOrderedText(t, errb.String(),
		"asiri logout",
		"asiri device enroll --name <new-name>",
		"asiri login --origin "+server.URL,
		"asiri rewrap --workspace prod",
	)
}

func TestDeviceTrustTargetsOneWorkspaceWithoutChangingSession(t *testing.T) {
	tmp := t.TempDir()
	old := os.Getenv("ASIRI_HOME")
	t.Cleanup(func() { _ = os.Setenv("ASIRI_HOME", old) })
	if err := os.Setenv("ASIRI_HOME", tmp); err != nil {
		t.Fatal(err)
	}
	targetedStarts := []string{}
	restoreSeen := false
	legacyCleanupSeen := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		switch r.URL.Path {
		case "/v1/auth/device-code/start":
			var body map[string]string
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			workspaceSlug := body["workspaceSlug"]
			targetedStarts = append(targetedStarts, workspaceSlug)
			if workspaceSlug == "asiri-dev" {
				_ = json.NewEncoder(w).Encode(map[string]any{
					"deviceCode":              "dc_asiri",
					"userCode":                "ASIR-123",
					"verificationUri":         serverURL(r) + "/auth/device",
					"verificationUriComplete": serverURL(r) + "/auth/device?code=ASIR-123",
					"expiresIn":               30,
					"interval":                0,
				})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"deviceCode":              "dc_login",
				"userCode":                "LOGN-123",
				"verificationUri":         serverURL(r) + "/auth/device",
				"verificationUriComplete": serverURL(r) + "/auth/device?code=LOGN-123",
				"expiresIn":               30,
				"interval":                0,
			})
		case "/v1/auth/device-code/token":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if body["deviceCode"] == "dc_asiri" {
				if body["trustOnly"] != true {
					t.Fatalf("device trust must request a trust-only claim: %#v", body)
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
				return
			}
			if _, ok := body["trustOnly"]; ok {
				t.Fatalf("account login must not request a trust-only claim: %#v", body)
			}
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
		case "/v1/auth/session/logout":
			var body map[string]string
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if body["refreshToken"] != "rt_asiri" || r.Header.Get("x-asiri-device") != "dev_asiri" {
				t.Fatalf("legacy cleanup targeted the wrong session: body=%#v device=%s", body, r.Header.Get("x-asiri-device"))
			}
			legacyCleanupSeen = true
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "logged_out"})
		case "/v1/orgs":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"activeOrgId": "org_oclan",
				"organizations": []map[string]any{
					{"id": "org_oclan", "slug": "oclan-co", "ownerUserId": "usr_owner", "role": "owner", "canPull": true, "currentDeviceTrusted": true, "currentDeviceId": "dev_oclan", "canWrite": true, "canApproveDevice": true},
					{"id": "org_asiri", "slug": "asiri-dev", "ownerUserId": "usr_owner", "role": "owner", "canPull": false, "currentDeviceTrusted": false, "canWrite": true, "canApproveDevice": true},
					{"id": "org_recall", "slug": "recallstack-com", "ownerUserId": "usr_other", "role": "member", "canPull": false, "currentDeviceTrusted": false, "canWrite": true, "canApproveDevice": false},
				},
			})
		case "/v1/auth/session/switch":
			restoreSeen = true
			var body map[string]string
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if body["workspace"] != "org_oclan" {
				t.Fatalf("unexpected restore target: %#v", body)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status":           "approved",
				"orgId":            "org_oclan",
				"workspaceSlug":    "oclan-co",
				"userId":           "usr_owner",
				"deviceId":         "dev_oclan",
				"accessToken":      "at_oclan_restored",
				"refreshToken":     "rt_oclan_restored",
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
	before, err := store.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	beforeAccess, err := before.ControlPlaneAccessToken()
	if err != nil {
		t.Fatal(err)
	}
	beforeRefresh, err := before.ControlPlaneRefreshToken()
	if err != nil {
		t.Fatal(err)
	}
	out.Reset()
	errb.Reset()
	if code := app.Run([]string{"device", "trust", "--workspace", "asiri-dev"}); code != 0 {
		t.Fatalf("device trust failed: %s", errb.String())
	}
	if !reflect.DeepEqual(targetedStarts, []string{"", "asiri-dev"}) {
		t.Fatalf("unexpected device-code targets: %#v", targetedStarts)
	}
	if restoreSeen {
		t.Fatal("device trust must not switch or restore sessions")
	}
	if !legacyCleanupSeen {
		t.Fatal("device trust should revoke a temporary session returned by a legacy backend")
	}
	output := out.String()
	for _, expected := range []string{"Trust this device for workspace asiri-dev", "✓ This device is trusted for workspace asiri-dev"} {
		if !strings.Contains(output, expected) {
			t.Fatalf("device trust output missing %q: %s", expected, output)
		}
	}
	st, err := store.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	if st.State.ControlPlane == nil || st.State.ControlPlane.WorkspaceID != "org_oclan" {
		t.Fatalf("device trust changed the account session: %#v", st.State.ControlPlane)
	}
	afterAccess, err := st.ControlPlaneAccessToken()
	if err != nil {
		t.Fatal(err)
	}
	afterRefresh, err := st.ControlPlaneRefreshToken()
	if err != nil {
		t.Fatal(err)
	}
	if afterAccess != beforeAccess || afterRefresh != beforeRefresh {
		t.Fatal("device trust replaced the stored account credentials")
	}
}

func TestDeviceTrustClaimUsesNewBackendWithoutSessionCleanup(t *testing.T) {
	tmp := t.TempDir()
	old := os.Getenv("ASIRI_HOME")
	t.Cleanup(func() { _ = os.Setenv("ASIRI_HOME", old) })
	if err := os.Setenv("ASIRI_HOME", tmp); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	var errb bytes.Buffer
	app := New(&out, &errb)
	if code := app.Run([]string{"init", "--device", "qa-laptop"}); code != 0 {
		t.Fatalf("init failed: %s", errb.String())
	}
	st, err := store.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	logoutSeen := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		switch r.URL.Path {
		case "/v1/auth/device-code/token":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if body["deviceCode"] != "dc_trust_only" || body["trustOnly"] != true {
				t.Fatalf("unexpected trust-only claim: %#v", body)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status":        "approved",
				"sessionIssued": false,
				"orgId":         "org_target",
				"workspaceSlug": "target",
				"userId":        "usr_owner",
				"deviceId":      "dev_target",
			})
		case "/v1/auth/session/logout":
			logoutSeen = true
			http.Error(w, "unexpected logout", http.StatusInternalServerError)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	result, err := pollDeviceCodeTrust(st, server.URL, deviceCodeStartResponse{DeviceCode: "dc_trust_only", ExpiresIn: 5})
	if err != nil {
		t.Fatal(err)
	}
	if logoutSeen || result.SessionIssued == nil || *result.SessionIssued || result.AccessToken != "" || result.RefreshToken != "" {
		t.Fatalf("new backend trust claim created cleanup work: result=%#v logout=%v", result, logoutSeen)
	}
}

func TestDeviceTrustRejectsApprovalForDifferentAccount(t *testing.T) {
	tmp := t.TempDir()
	old := os.Getenv("ASIRI_HOME")
	t.Cleanup(func() { _ = os.Setenv("ASIRI_HOME", old) })
	if err := os.Setenv("ASIRI_HOME", tmp); err != nil {
		t.Fatal(err)
	}
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

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		switch r.URL.Path {
		case "/v1/auth/device-code/start":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"deviceCode": "dc_other_user", "userCode": "OTHR-1234",
				"verificationUriComplete": serverURL(r) + "/auth/device?code=OTHR-1234",
				"expiresIn":               30, "interval": 0,
			})
		case "/v1/auth/device-code/token":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status": "approved", "sessionIssued": false,
				"orgId": "org_target", "workspaceSlug": "target",
				"userId": "usr_other", "deviceId": "dev_target",
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	if err := st.LinkControlPlaneForDevice(server.URL, "org_source", "source", "usr_expected", "dev_source", device.ID, "at", "rt", 3600, time.Now().UTC().Add(24*time.Hour).Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}

	if _, err := app.trustDeviceInWorkspace(st, server.URL, "at", "target", *device); err == nil || !strings.Contains(err.Error(), "different account") {
		t.Fatalf("cross-account device trust should fail, got %v", err)
	}
}

func TestDeviceTrustStopsWhenLegacySessionCleanupFails(t *testing.T) {
	tmp := t.TempDir()
	old := os.Getenv("ASIRI_HOME")
	t.Cleanup(func() { _ = os.Setenv("ASIRI_HOME", old) })
	if err := os.Setenv("ASIRI_HOME", tmp); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	var errb bytes.Buffer
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
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		switch r.URL.Path {
		case "/v1/auth/device-code/token":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status":        "approved",
				"orgId":         "org_target",
				"workspaceSlug": "target",
				"userId":        "usr_owner",
				"deviceId":      "dev_target",
				"accessToken":   "at_temporary",
				"refreshToken":  "rt_temporary",
			})
		case "/v1/auth/session/logout":
			if r.Header.Get("x-asiri-device") != "dev_target" {
				t.Fatalf("temporary cleanup used the wrong device: %s", r.Header.Get("x-asiri-device"))
			}
			w.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": "cleanup_unavailable"})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	if err := st.LinkControlPlaneForDevice(server.URL, "org_original", "original", "usr_owner", "dev_original", device.ID, "at_original", "rt_original", 3600, time.Now().UTC().Add(7*24*time.Hour).Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}

	_, err = pollDeviceCodeTrust(st, server.URL, deviceCodeStartResponse{DeviceCode: "dc_legacy_cleanup", ExpiresIn: 5})
	if err == nil || !strings.Contains(err.Error(), "temporary server session could not be revoked") {
		t.Fatalf("expected cleanup failure, got %v", err)
	}
	accessToken, accessErr := st.ControlPlaneAccessToken()
	refreshToken, refreshErr := st.ControlPlaneRefreshToken()
	if accessErr != nil || refreshErr != nil || accessToken != "at_original" || refreshToken != "rt_original" {
		t.Fatalf("cleanup failure changed the original credentials: access=%q refresh=%q errors=%v/%v", accessToken, refreshToken, accessErr, refreshErr)
	}
}
