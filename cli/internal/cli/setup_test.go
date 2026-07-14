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

func TestSetupDoctorBeforeInitPrintsBootstrapSteps(t *testing.T) {
	tmp := t.TempDir()
	old := os.Getenv("ASIRI_HOME")
	t.Cleanup(func() { _ = os.Setenv("ASIRI_HOME", old) })
	if err := os.Setenv("ASIRI_HOME", tmp); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	var errb bytes.Buffer
	app := New(&out, &errb)
	if code := app.Run([]string{"setup", "doctor", "--workspace", "personal"}); code != 0 {
		t.Fatalf("setup doctor should diagnose missing init without failing: %s", errb.String())
	}
	got := out.String()
	for _, expected := range []string{"Asiri setup doctor", "local vault", "missing", "asiri init --device <name>", "asiri login"} {
		if !strings.Contains(got, expected) {
			t.Fatalf("setup doctor output missing %q: %s", expected, got)
		}
	}
}

func TestSetupDoctorExpiredSessionRecommendsLoginWithoutForce(t *testing.T) {
	tmp := t.TempDir()
	old := os.Getenv("ASIRI_HOME")
	t.Cleanup(func() { _ = os.Setenv("ASIRI_HOME", old) })
	if err := os.Setenv("ASIRI_HOME", tmp); err != nil {
		t.Fatal(err)
	}

	workspaceRequested := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		switch r.URL.Path {
		case "/v1/auth/session/refresh":
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": "invalid_refresh_token"})
		case "/v1/orgs":
			workspaceRequested = true
			http.Error(w, "unexpected workspace request", http.StatusInternalServerError)
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
	if _, err := st.AddSecret("prod/local/API_KEY", "preserved-secret"); err != nil {
		t.Fatal(err)
	}
	if err := st.LinkControlPlaneForDevice(server.URL, "org_prod", "prod", "usr_owner", "dev_remote", device.ID, "at_old", "rt_old", 3600, time.Now().UTC().Add(24*time.Hour).Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
	st.State.ControlPlane.AccessTokenExpiresAt = time.Now().UTC().Add(-time.Minute)
	if err := st.Save(); err != nil {
		t.Fatal(err)
	}
	keyRefsBefore := append([]asiri.KeyRef(nil), st.State.KeyRefs...)

	out.Reset()
	errb.Reset()
	if code := app.Run([]string{"setup", "doctor", "--workspace", "prod"}); code != 0 {
		t.Fatalf("setup doctor should report an expired session without failing: %s", errb.String())
	}
	if workspaceRequested {
		t.Fatal("setup doctor should stop after the expired session check")
	}
	result := out.String()
	if !strings.Contains(result, "session") || !strings.Contains(result, "failed") || !strings.Contains(result, "asiri login") {
		t.Fatalf("setup doctor missing normal login recovery: %s", result)
	}
	if strings.Contains(result, "login --force") || strings.Contains(result, "device enroll") || strings.Contains(result, "wipe") {
		t.Fatalf("expired-session guidance should not rotate or delete keys: %s", result)
	}

	reloaded, err := store.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(reloaded.State.KeyRefs, keyRefsBefore) {
		t.Fatalf("setup doctor changed key refs after an expired session: got=%#v want=%#v", reloaded.State.KeyRefs, keyRefsBefore)
	}
	if value, _, err := reloaded.GetSecret("prod/local/API_KEY"); err != nil || value != "preserved-secret" {
		t.Fatalf("setup doctor made the local secret unusable: value=%q err=%v", value, err)
	}
}

func TestSetupDoctorReportsTrustedDeviceNextSteps(t *testing.T) {
	tmp := t.TempDir()
	old := os.Getenv("ASIRI_HOME")
	t.Cleanup(func() { _ = os.Setenv("ASIRI_HOME", old) })
	if err := os.Setenv("ASIRI_HOME", tmp); err != nil {
		t.Fatal(err)
	}

	recoveryChecked := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/session/refresh":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status":           "approved",
				"orgId":            "org_prod",
				"workspaceSlug":    "prod",
				"userId":           "usr_owner",
				"deviceId":         "dev_remote",
				"accessToken":      "at_doctor",
				"expiresIn":        3600,
				"refreshExpiresAt": time.Now().UTC().Add(7 * 24 * time.Hour).Format(time.RFC3339),
			})
		case "/v1/orgs":
			if r.Header.Get("authorization") != "Bearer at_cached" || r.Header.Get("x-asiri-device") != "dev_remote" || r.Header.Get("x-asiri-signature") == "" {
				t.Fatalf("workspace list missing signed trusted session: auth=%s device=%s", r.Header.Get("authorization"), r.Header.Get("x-asiri-device"))
			}
			if r.URL.Query().Get("includeSecrets") != "1" {
				t.Fatalf("setup doctor should request workspace secret metadata, got %s", r.URL.RawQuery)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"activeOrgId": "org_prod",
				"organizations": []map[string]any{
					{"id": "org_prod", "name": "Production", "slug": "prod", "role": "owner", "canPull": true, "canWrite": true, "currentDeviceTrusted": true, "currentDeviceId": "dev_remote", "canApproveDevice": true},
					{"id": "org_staging", "name": "Staging", "slug": "staging", "role": "owner", "canPull": false, "canWrite": true, "currentDeviceTrusted": false, "canApproveDevice": true},
					{"id": "org_shared", "name": "Shared", "slug": "shared", "role": "member", "canPull": false, "canWrite": false, "currentDeviceTrusted": false, "canApproveDevice": false},
				},
				"secrets": []map[string]any{{
					"id":                     "sec_prod",
					"orgId":                  "org_prod",
					"workspaceSlug":          "prod",
					"scope":                  "prod/api",
					"name":                   "TOKEN",
					"version":                1,
					"status":                 "active",
					"canWrite":               true,
					"wrappedToCurrentDevice": true,
					"currentDeviceId":        "dev_remote",
				}},
			})
		case "/v1/recovery-recipient":
			recoveryChecked = true
			if r.URL.Query().Get("orgId") != "org_prod" {
				t.Fatalf("setup doctor should only query requested workspace recovery, got %s", r.URL.RawQuery)
			}
			http.Error(w, "not configured", http.StatusNotFound)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	var out bytes.Buffer
	var errb bytes.Buffer
	app := New(&out, &errb)
	if code := app.Run([]string{"init", "--device", "trusted-cli"}); code != 0 {
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
	if err := st.LinkControlPlaneForDevice(server.URL, "org_prod", "prod", "usr_owner", "dev_remote", device.ID, "at_cached", "rt_cached", 3600, time.Now().UTC().Add(7*24*time.Hour).Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}

	out.Reset()
	errb.Reset()
	if code := app.Run([]string{"setup", "doctor", "--workspace", "prod"}); code != 0 {
		t.Fatalf("setup doctor failed: %s", errb.String())
	}
	if !recoveryChecked {
		t.Fatal("setup doctor should check requested workspace recovery")
	}
	got := out.String()
	for _, expected := range []string{
		"prod", "ready", "not-configured", "asiri recovery setup --workspace prod --output-file <path>",
	} {
		if !strings.Contains(got, expected) {
			t.Fatalf("setup doctor output missing %q: %s", expected, got)
		}
	}
}

func TestSetupDoctorReportsRevokedCurrentDeviceRecovery(t *testing.T) {
	tmp := t.TempDir()
	old := os.Getenv("ASIRI_HOME")
	t.Cleanup(func() { _ = os.Setenv("ASIRI_HOME", old) })
	if err := os.Setenv("ASIRI_HOME", tmp); err != nil {
		t.Fatal(err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		if r.URL.Path != "/v1/orgs" {
			http.NotFound(w, r)
			return
		}
		assertWorkspaceOverviewTarget(t, r, "prod")
		if r.URL.Query().Get("includeSecrets") != "1" {
			t.Fatalf("setup doctor should request secret metadata: %s", r.URL.RawQuery)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"organizations": []map[string]any{{
				"id": "org_prod", "slug": "prod", "role": "owner", "canPull": false, "canWrite": true,
				"currentDeviceTrusted": false, "currentDeviceStatus": "revoked", "canApproveDevice": true,
			}},
			"secrets": []map[string]any{},
		})
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
	if code := app.Run([]string{"setup", "doctor", "--workspace", "prod"}); code != 0 {
		t.Fatalf("setup doctor failed: %s", errb.String())
	}
	result := out.String()
	for _, expected := range []string{"revoked", "replace revoked device keys"} {
		if !strings.Contains(result, expected) {
			t.Fatalf("setup doctor output missing %q: %s", expected, result)
		}
	}
	requireOrderedText(t, result,
		"asiri logout",
		"asiri device enroll --name <new-name>",
		"asiri login --origin "+server.URL,
		"asiri rewrap --workspace prod",
	)
	for _, unsafe := range []string{"asiri device trust", "login --force", "asiri init", "wipe"} {
		if strings.Contains(result, unsafe) {
			t.Fatalf("revoked-device recovery should not suggest %q: %s", unsafe, result)
		}
	}
}

func TestSetupDoctorReportsMissingWorkspaceFilter(t *testing.T) {
	tmp := t.TempDir()
	old := os.Getenv("ASIRI_HOME")
	t.Cleanup(func() { _ = os.Setenv("ASIRI_HOME", old) })
	if err := os.Setenv("ASIRI_HOME", tmp); err != nil {
		t.Fatal(err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/session/refresh":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status":           "approved",
				"orgId":            "org_prod",
				"workspaceSlug":    "prod",
				"userId":           "usr_owner",
				"deviceId":         "dev_remote",
				"accessToken":      "at_doctor",
				"expiresIn":        3600,
				"refreshExpiresAt": time.Now().UTC().Add(7 * 24 * time.Hour).Format(time.RFC3339),
			})
		case "/v1/orgs":
			assertWorkspaceOverviewTarget(t, r, "prdo")
			_ = json.NewEncoder(w).Encode(map[string]any{"organizations": []map[string]any{}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	var out bytes.Buffer
	var errb bytes.Buffer
	app := New(&out, &errb)
	if code := app.Run([]string{"init", "--device", "trusted-cli"}); code != 0 {
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
	if err := st.LinkControlPlaneForDevice(server.URL, "org_prod", "prod", "usr_owner", "dev_remote", device.ID, "at_cached", "rt_cached", 3600, time.Now().UTC().Add(7*24*time.Hour).Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}

	out.Reset()
	errb.Reset()
	if code := app.Run([]string{"setup", "doctor", "--workspace", "prdo"}); code == 0 {
		t.Fatal("setup doctor should fail when any requested workspace is not visible")
	}
	if !strings.Contains(errb.String(), "workspace prdo is not visible") {
		t.Fatalf("setup doctor should report the missing workspace filter: %s", errb.String())
	}
}

func TestSetupDoctorDoesNotMarkUnknownChecksReady(t *testing.T) {
	tmp := t.TempDir()
	old := os.Getenv("ASIRI_HOME")
	t.Cleanup(func() { _ = os.Setenv("ASIRI_HOME", old) })
	if err := os.Setenv("ASIRI_HOME", tmp); err != nil {
		t.Fatal(err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/session/refresh":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status":           "approved",
				"orgId":            "org_prod",
				"workspaceSlug":    "prod",
				"userId":           "usr_owner",
				"deviceId":         "dev_remote",
				"accessToken":      "at_doctor",
				"expiresIn":        3600,
				"refreshExpiresAt": time.Now().UTC().Add(7 * 24 * time.Hour).Format(time.RFC3339),
			})
		case "/v1/orgs":
			assertWorkspaceOverviewTarget(t, r, "stage")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"organizations": []map[string]any{{"id": "org_stage", "name": "Staging", "slug": "stage", "role": "owner", "canPull": true, "canWrite": true, "currentDeviceTrusted": true, "currentDeviceId": "dev_stage", "canApproveDevice": true}},
			})
		case "/v1/recovery-recipient":
			http.Error(w, "not configured", http.StatusNotFound)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	var out bytes.Buffer
	var errb bytes.Buffer
	app := New(&out, &errb)
	if code := app.Run([]string{"init", "--device", "trusted-cli"}); code != 0 {
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
	if err := st.LinkControlPlaneForDevice(server.URL, "org_prod", "prod", "usr_owner", "dev_remote", device.ID, "at_cached", "rt_cached", 3600, time.Now().UTC().Add(7*24*time.Hour).Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}

	out.Reset()
	errb.Reset()
	if code := app.Run([]string{"setup", "doctor", "--workspace", "stage"}); code != 0 {
		t.Fatalf("setup doctor failed: %s", errb.String())
	}
	got := out.String()
	for _, expected := range []string{
		"stage", "unknown", "asiri setup doctor --workspace stage",
	} {
		if !strings.Contains(got, expected) {
			t.Fatalf("setup doctor output missing %q: %s", expected, got)
		}
	}
	if strings.Contains(got, "Setup looks ready") {
		t.Fatalf("setup doctor should not report ready when checks are unknown: %s", got)
	}
}

func TestWorkspaceDeviceStatusLabelsAreExplicit(t *testing.T) {
	for _, tc := range []struct {
		status  string
		label   string
		trusted bool
	}{
		{status: "trusted", label: "trusted", trusted: true},
		{status: "pending", label: "pending"},
		{status: "revoked", label: "revoked"},
		{status: "not-enrolled", label: "not-enrolled"},
		{status: "not_enrolled", label: "not-enrolled"},
	} {
		workspace := remoteWorkspaceResponse{CurrentDeviceStatus: tc.status}
		if got := deviceTrustLabelForWorkspace(workspace); got != tc.label {
			t.Fatalf("status %q label mismatch: got=%q want=%q", tc.status, got, tc.label)
		}
		if got := workspaceDeviceTrusted(workspace); got != tc.trusted {
			t.Fatalf("status %q trusted mismatch: got=%v want=%v", tc.status, got, tc.trusted)
		}
	}

	legacyFalse := false
	if got := deviceTrustLabelForWorkspace(remoteWorkspaceResponse{CurrentDeviceTrusted: &legacyFalse}); got != "not trusted" {
		t.Fatalf("legacy servers should retain the honest fallback label, got %q", got)
	}
}
