package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/o-clan/asiri/cli/internal/asiri"
	"github.com/o-clan/asiri/cli/internal/keystore"
	"github.com/o-clan/asiri/cli/internal/store"
	"github.com/zalando/go-keyring"
)

func TestMain(m *testing.M) {
	keyring.MockInit()
	os.Exit(m.Run())
}

func testSecretFile(t *testing.T, value string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "secret.txt")
	if err := os.WriteFile(path, []byte(value+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestDefaultControlPlaneOriginMatchesLocalDev(t *testing.T) {
	if defaultControlPlaneOrigin != "http://127.0.0.1:4173" {
		t.Fatalf("source default control-plane origin must match local dev, got %s", defaultControlPlaneOrigin)
	}
}

func TestInitFallsBackToLocalFileKeyStoreWhenPlatformKeyringUnavailable(t *testing.T) {
	tmp := t.TempDir()
	oldHome := os.Getenv("ASIRI_HOME")
	t.Cleanup(func() {
		_ = os.Setenv("ASIRI_HOME", oldHome)
		keystore.ClearConfiguredFileKeyStoreDir()
		keyring.MockInit()
	})
	_ = os.Setenv("ASIRI_HOME", tmp)
	keystore.ClearConfiguredFileKeyStoreDir()
	keyring.MockInitWithError(errors.New("no platform keyring"))

	var out, errb bytes.Buffer
	app := New(&out, &errb)
	if code := app.Run([]string{"init", "--device", "headless-box"}); code != 0 {
		t.Fatalf("init failed: %s", errb.String())
	}
	if !strings.Contains(out.String(), "using local file key store") {
		t.Fatalf("init did not explain file keystore fallback: %s", out.String())
	}
	statePath := filepath.Join(tmp, "local-state.json")
	st, err := store.Load(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if st.State.KeyStore != store.KeyStoreFile {
		t.Fatalf("expected file keystore state, got %q", st.State.KeyStore)
	}
	keyStoreDir := store.DefaultFileKeyStoreDir(statePath)
	entries, err := os.ReadDir(keyStoreDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected device private keys in file keystore, got %d entries", len(entries))
	}

	keystore.ClearConfiguredFileKeyStoreDir()
	out.Reset()
	errb.Reset()
	app = New(&out, &errb)
	app.In = strings.NewReader("secret_value\n")
	if code := app.Run([]string{"add", "--workspace", "personal", "dev/API_KEY", "--stdin"}); code != 0 {
		t.Fatalf("add failed after reloading file keystore state: %s", errb.String())
	}

	keystore.ClearConfiguredFileKeyStoreDir()
	out.Reset()
	errb.Reset()
	app = New(&out, &errb)
	if code := app.Run([]string{"get", "--workspace", "personal", "dev/API_KEY"}); code != 0 {
		t.Fatalf("get failed after reloading file keystore state: %s", errb.String())
	}
	if strings.TrimSpace(out.String()) != "secret_value" {
		t.Fatalf("unexpected secret value: %q", out.String())
	}
}

func TestLoginOriginSelection(t *testing.T) {
	old := os.Getenv("ASIRI_CONTROL_PLANE_ORIGIN")
	t.Cleanup(func() { _ = os.Setenv("ASIRI_CONTROL_PLANE_ORIGIN", old) })
	_ = os.Unsetenv("ASIRI_CONTROL_PLANE_ORIGIN")

	st := &store.FileStore{State: asiri.State{ControlPlane: &asiri.ControlPlaneLink{Origin: "http://127.0.0.1:4173"}}}
	if got := loginOrigin(nil, st); got != "http://127.0.0.1:4173" {
		t.Fatalf("login should refresh the saved control-plane origin, got %s", got)
	}
	if got := loginOrigin([]string{"--force"}, st); got != defaultControlPlaneOrigin {
		t.Fatalf("forced login should use the default origin instead of stale saved origin, got %s", got)
	}
	_ = os.Setenv("ASIRI_CONTROL_PLANE_ORIGIN", "http://127.0.0.1:8787/")
	if got := loginOrigin([]string{"--force"}, st); got != "http://127.0.0.1:8787" {
		t.Fatalf("forced login should honor environment origin, got %s", got)
	}
	if got := loginOrigin([]string{"--origin", "http://127.0.0.1:9999/"}, st); got != "http://127.0.0.1:9999" {
		t.Fatalf("explicit origin should win, got %s", got)
	}
}

func TestServiceAccountControlPlaneSessionsRejectMutations(t *testing.T) {
	serviceStore := &store.FileStore{State: asiri.State{ControlPlane: &asiri.ControlPlaneLink{Source: "service-account"}}}
	if err := rejectServiceAccountControlPlaneMutation(serviceStore); err == nil {
		t.Fatal("service account sessions should reject control-plane mutations")
	}
	if err := rejectServiceAccountLocalMutation(serviceStore); err == nil {
		t.Fatal("service account sessions should reject local mutations")
	}

	humanStore := &store.FileStore{State: asiri.State{ControlPlane: &asiri.ControlPlaneLink{Source: "device-code"}}}
	if err := rejectServiceAccountControlPlaneMutation(humanStore); err != nil {
		t.Fatalf("human sessions should allow control-plane mutations: %v", err)
	}
	if err := rejectServiceAccountLocalMutation(humanStore); err != nil {
		t.Fatalf("human sessions should allow local mutations: %v", err)
	}
}

func TestServiceAccountRemoteDeleteCommandsAreRejectedBeforeNetwork(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
	}{
		{name: "secret delete", args: []string{"secret", "delete", "--workspace", "prod", "prod/api/KEY", "--dry-run"}},
		{name: "remote rm", args: []string{"rm", "--remote", "--workspace", "prod", "prod/api/KEY", "--dry-run"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tmp := t.TempDir()
			old := os.Getenv("ASIRI_HOME")
			t.Cleanup(func() { _ = os.Setenv("ASIRI_HOME", old) })
			if err := os.Setenv("ASIRI_HOME", tmp); err != nil {
				t.Fatal(err)
			}
			var out bytes.Buffer
			var errb bytes.Buffer
			app := New(&out, &errb)
			if code := app.Run([]string{"init", "--device", "service-host"}); code != 0 {
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
			remoteHit := false
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				remoteHit = true
				http.Error(w, "unexpected", http.StatusInternalServerError)
			}))
			defer server.Close()
			if err := st.LinkServiceAccountControlPlane(server.URL, "org_prod", "prod", "usr_owner", "svc_prod", "prod-api", "Production API", "wdev_prod", device.ID, "at_service", "rt_service", 3600, time.Now().UTC().Add(7*24*time.Hour).Format(time.RFC3339)); err != nil {
				t.Fatal(err)
			}
			out.Reset()
			errb.Reset()
			if code := app.Run(tc.args); code == 0 {
				t.Fatalf("%v should fail for service account sessions", tc.args)
			}
			if remoteHit {
				t.Fatal("remote delete command should not call remote endpoints for service account sessions")
			}
			if !strings.Contains(errb.String(), "service account sessions are read-only for control-plane mutations") {
				t.Fatalf("unexpected error: %s", errb.String())
			}
		})
	}
}

func TestServiceAccountManagementCommandsAreRejectedBeforeNetwork(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
	}{
		{name: "create", args: []string{"service-account", "create", "--workspace", "prod", "--slug", "prod-api-next", "--name", "Production API Next"}},
		{name: "disable", args: []string{"service-account", "disable", "--workspace", "prod", "--service-account", "prod-api"}},
		{name: "grant", args: []string{"service-account", "grant", "--workspace", "prod", "--service-account", "prod-api", "--scope", "api", "--secret", "*", "--inject-only"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tmp := t.TempDir()
			old := os.Getenv("ASIRI_HOME")
			t.Cleanup(func() { _ = os.Setenv("ASIRI_HOME", old) })
			if err := os.Setenv("ASIRI_HOME", tmp); err != nil {
				t.Fatal(err)
			}
			var out bytes.Buffer
			var errb bytes.Buffer
			app := New(&out, &errb)
			if code := app.Run([]string{"init", "--device", "service-host"}); code != 0 {
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
			remoteHit := false
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				remoteHit = true
				http.Error(w, "unexpected", http.StatusInternalServerError)
			}))
			defer server.Close()
			if err := st.LinkServiceAccountControlPlane(server.URL, "org_prod", "prod", "usr_owner", "svc_prod", "prod-api", "Production API", "wdev_prod", device.ID, "at_service", "rt_service", 3600, time.Now().UTC().Add(7*24*time.Hour).Format(time.RFC3339)); err != nil {
				t.Fatal(err)
			}

			out.Reset()
			errb.Reset()
			if code := app.Run(tc.args); code == 0 {
				t.Fatalf("%v should fail for service account sessions", tc.args)
			}
			if remoteHit {
				t.Fatal("service-account management command should not call remote endpoints for service account sessions")
			}
			if !strings.Contains(errb.String(), "service account sessions are read-only for control-plane mutations") {
				t.Fatalf("unexpected error: %s", errb.String())
			}
		})
	}
}

func TestServiceAccountGrantRejectsInvalidExpiryFlags(t *testing.T) {
	future := time.Now().UTC().Add(time.Hour).Format(time.RFC3339)
	options, err := parseServiceAccountGrantArgs([]string{"--workspace", "prod", "--service-account", "prod-api", "--scope", "api", "--secret", "*", "--inject-only", "--expires-at", future})
	if err != nil {
		t.Fatalf("valid future expiry flags should parse: %v", err)
	}
	if options.ExpiresAt == "" || !strings.HasSuffix(options.ExpiresAt, "Z") {
		t.Fatalf("expiry flag should be normalized to UTC RFC3339, got %q", options.ExpiresAt)
	}
	if _, err := parseServiceAccountGrantArgs([]string{"--workspace", "prod", "--service-account", "prod-api", "--scope", "api", "--secret", "*", "--inject-only", "--expires-at", time.Now().UTC().Add(-time.Minute).Format(time.RFC3339)}); err == nil {
		t.Fatal("expired policy expiry should fail")
	}
}

func TestServiceAccountLoginRejectsInvalidArgs(t *testing.T) {
	if _, err := parseServiceAccountSelectArgs([]string{"--service-account", "prod-api"}, "login"); err == nil {
		t.Fatal("service-account login should require workspace")
	}
	if _, err := parseServiceAccountSelectArgs([]string{"--workspace", "prod"}, "login"); err == nil {
		t.Fatal("service-account login should require service account")
	}
	if _, err := parseServiceAccountSelectArgs([]string{"--workspace", "prod", "--service-account", "prod-api"}, "login"); err != nil {
		t.Fatalf("valid service-account login args should parse: %v", err)
	}
}

func TestTrustedCLIConfiguresServiceAccounts(t *testing.T) {
	tmp := t.TempDir()
	old := os.Getenv("ASIRI_HOME")
	t.Cleanup(func() { _ = os.Setenv("ASIRI_HOME", old) })
	if err := os.Setenv("ASIRI_HOME", tmp); err != nil {
		t.Fatal(err)
	}

	refreshes := 0
	createSeen := false
	policyCreateCount := 0
	policies := []map[string]any{}
	accounts := []map[string]any{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/session/refresh":
			refreshes++
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status":           "approved",
				"orgId":            "org_setup",
				"workspaceSlug":    "prod",
				"userId":           "usr_owner",
				"deviceId":         "dev_remote",
				"accessToken":      "at_setup",
				"expiresIn":        3600,
				"refreshExpiresAt": time.Now().UTC().Add(7 * 24 * time.Hour).Format(time.RFC3339),
			})
		case "/v1/service-accounts":
			if r.Method == http.MethodGet {
				if r.URL.Query().Get("orgId") != "org_setup" {
					t.Fatalf("unexpected service account list org: %s", r.URL.RawQuery)
				}
				if r.Header.Get("authorization") != "Bearer at_cached" || r.Header.Get("x-asiri-device") != "dev_remote" || r.Header.Get("x-asiri-signature") == "" {
					t.Fatalf("service account list missing signed trusted session: auth=%s device=%s", r.Header.Get("authorization"), r.Header.Get("x-asiri-device"))
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"serviceAccounts": accounts})
				return
			}
			if r.Method != http.MethodPost {
				http.NotFound(w, r)
				return
			}
			createSeen = true
			if r.Header.Get("authorization") != "Bearer at_cached" || r.Header.Get("x-asiri-device") != "dev_remote" || r.Header.Get("x-asiri-signature") == "" {
				t.Fatalf("service account create missing signed trusted session: auth=%s device=%s", r.Header.Get("authorization"), r.Header.Get("x-asiri-device"))
			}
			var body map[string]string
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if body["orgId"] != "org_setup" || body["slug"] != "prod-api" || body["name"] != "Production API" {
				t.Fatalf("unexpected service account create body: %#v", body)
			}
			account := map[string]any{
				"id":              "svc_prod",
				"orgId":           "org_setup",
				"slug":            "prod-api",
				"name":            "Production API",
				"status":          "active",
				"createdByUserId": "usr_owner",
			}
			accounts = append(accounts, account)
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(account)
		case "/v1/service-accounts/svc_prod/disable":
			if r.Method != http.MethodPost {
				http.NotFound(w, r)
				return
			}
			if r.Header.Get("authorization") != "Bearer at_cached" || r.Header.Get("x-asiri-device") != "dev_remote" || r.Header.Get("x-asiri-signature") == "" {
				t.Fatalf("service account disable missing signed trusted session: auth=%s device=%s", r.Header.Get("authorization"), r.Header.Get("x-asiri-device"))
			}
			accounts[0]["status"] = "disabled"
			_ = json.NewEncoder(w).Encode(accounts[0])
		case "/v1/policies":
			if r.Method == http.MethodGet {
				if r.URL.Query().Get("orgId") != "org_setup" {
					t.Fatalf("unexpected policy list org: %s", r.URL.RawQuery)
				}
				if r.Header.Get("authorization") != "Bearer at_cached" || r.Header.Get("x-asiri-device") != "dev_remote" || r.Header.Get("x-asiri-signature") == "" {
					t.Fatalf("policy list missing signed trusted session: auth=%s device=%s", r.Header.Get("authorization"), r.Header.Get("x-asiri-device"))
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"policies": policies})
				return
			}
			if r.Method != http.MethodPost {
				http.NotFound(w, r)
				return
			}
			policyCreateCount++
			if r.Header.Get("authorization") != "Bearer at_cached" || r.Header.Get("x-asiri-device") != "dev_remote" || r.Header.Get("x-asiri-signature") == "" {
				t.Fatalf("policy create missing signed trusted session: auth=%s device=%s", r.Header.Get("authorization"), r.Header.Get("x-asiri-device"))
			}
			var body struct {
				OrgID         string   `json:"orgId"`
				SubjectType   string   `json:"subjectType"`
				SubjectID     string   `json:"subjectId"`
				ScopePattern  string   `json:"scopePattern"`
				SecretPattern string   `json:"secretPattern"`
				Actions       []string `json:"actions"`
				ApprovalMode  string   `json:"approvalMode"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if body.OrgID != "org_setup" || body.SubjectType != "service" || body.SubjectID != "prod-api" || body.ScopePattern != "prod/api" || body.SecretPattern != "*" || !reflect.DeepEqual(body.Actions, []string{"inject"}) || body.ApprovalMode != "none" {
				t.Fatalf("unexpected policy body: %#v", body)
			}
			policy := map[string]any{
				"id":            "pol_prod",
				"orgId":         body.OrgID,
				"subjectType":   body.SubjectType,
				"subjectId":     body.SubjectID,
				"scopePattern":  body.ScopePattern,
				"secretPattern": body.SecretPattern,
				"actions":       body.Actions,
				"approvalMode":  body.ApprovalMode,
			}
			policies = append(policies, policy)
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(policy)
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
	if err := st.LinkControlPlaneForDevice(server.URL, "org_setup", "prod", "usr_owner", "dev_remote", device.ID, "at_cached", "rt_cached", 3600, time.Now().UTC().Add(7*24*time.Hour).Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}

	out.Reset()
	errb.Reset()
	if code := app.Run([]string{"service-account", "create", "--workspace", "prod", "--slug", "prod-api", "--name", "Production API"}); code != 0 {
		t.Fatalf("service account create failed: %s", errb.String())
	}
	if !createSeen || !strings.Contains(out.String(), "Created service account prod-api") {
		t.Fatalf("service account create did not complete as expected, seen=%v output=%s", createSeen, out.String())
	}

	out.Reset()
	errb.Reset()
	if code := app.Run([]string{"service-account", "list", "--workspace", "prod"}); code != 0 {
		t.Fatalf("service account list failed: %s", errb.String())
	}
	if refreshes != 0 || !strings.Contains(out.String(), "prod-api") || !strings.Contains(out.String(), "Production API") {
		t.Fatalf("service account list did not complete as expected, refreshes=%d output=%s", refreshes, out.String())
	}

	out.Reset()
	errb.Reset()
	if code := app.Run([]string{"service-account", "grant", "--workspace", "prod", "--service-account", "prod-api", "--scope", "api", "--secret", "*", "--inject-only"}); code != 0 {
		t.Fatalf("service account grant failed: %s", errb.String())
	}
	if policyCreateCount != 1 || !strings.Contains(out.String(), "Added service policy") {
		t.Fatalf("service account grant did not complete as expected, creates=%d output=%s", policyCreateCount, out.String())
	}

	out.Reset()
	errb.Reset()
	if code := app.Run([]string{"service-account", "grant", "--workspace", "prod", "--service-account", "prod-api", "--scope", "api", "--secret", "*", "--inject-only"}); code != 0 {
		t.Fatalf("service account grant reuse failed: %s", errb.String())
	}
	if policyCreateCount != 1 || !strings.Contains(out.String(), "already grants") {
		t.Fatalf("service account grant should reuse existing policy, policyCreates=%d output=%s", policyCreateCount, out.String())
	}

	out.Reset()
	errb.Reset()
	if code := app.Run([]string{"service-account", "disable", "--workspace", "prod", "--service-account", "prod-api"}); code != 0 {
		t.Fatalf("service account disable failed: %s", errb.String())
	}
	if !strings.Contains(out.String(), "Disabled service account prod-api") {
		t.Fatalf("service account disable did not complete as expected: %s", out.String())
	}
}

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
	if code := app.Run([]string{"setup", "doctor"}); code != 0 {
		t.Fatalf("setup doctor should diagnose missing init without failing: %s", errb.String())
	}
	got := out.String()
	for _, expected := range []string{"Asiri setup doctor", "local vault", "missing", "asiri init --device <name>", "asiri login"} {
		if !strings.Contains(got, expected) {
			t.Fatalf("setup doctor output missing %q: %s", expected, got)
		}
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
				t.Fatalf("setup doctor should only query active workspace recovery, got %s", r.URL.RawQuery)
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
	if code := app.Run([]string{"setup", "doctor"}); code != 0 {
		t.Fatalf("setup doctor failed: %s", errb.String())
	}
	if !recoveryChecked {
		t.Fatal("setup doctor should check active workspace recovery")
	}
	got := out.String()
	for _, expected := range []string{
		"prod", "ready", "not-configured", "asiri recovery setup --workspace prod --output-file <path>",
		"staging", "not trusted", "asiri device trust --workspace staging",
		"shared", "ask owner to approve this device",
	} {
		if !strings.Contains(got, expected) {
			t.Fatalf("setup doctor output missing %q: %s", expected, got)
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
			_ = json.NewEncoder(w).Encode(map[string]any{
				"activeOrgId": "org_prod",
				"organizations": []map[string]any{{
					"id": "org_prod", "name": "Production", "slug": "prod", "role": "owner", "canPull": true, "canWrite": true, "currentDeviceTrusted": true, "currentDeviceId": "dev_remote", "canApproveDevice": true,
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
	if code := app.Run([]string{"setup", "doctor", "--workspace", "prod", "--workspace", "prdo"}); code == 0 {
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
			_ = json.NewEncoder(w).Encode(map[string]any{
				"activeOrgId": "org_prod",
				"organizations": []map[string]any{
					{"id": "org_prod", "name": "Production", "slug": "prod", "role": "owner", "canPull": true, "canWrite": true, "currentDeviceTrusted": true, "currentDeviceId": "dev_remote", "canApproveDevice": true},
					{"id": "org_stage", "name": "Staging", "slug": "stage", "role": "owner", "canPull": true, "canWrite": true, "currentDeviceTrusted": true, "currentDeviceId": "dev_stage", "canApproveDevice": true},
				},
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
	if code := app.Run([]string{"setup", "doctor"}); code != 0 {
		t.Fatalf("setup doctor failed: %s", errb.String())
	}
	got := out.String()
	for _, expected := range []string{
		"prod", "unknown", "asiri setup doctor --workspace prod",
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

func TestHumanLoginRefusesActiveServiceAccountSession(t *testing.T) {
	tmp := t.TempDir()
	old := os.Getenv("ASIRI_HOME")
	t.Cleanup(func() { _ = os.Setenv("ASIRI_HOME", old) })
	if err := os.Setenv("ASIRI_HOME", tmp); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	var errb bytes.Buffer
	app := New(&out, &errb)
	if code := app.Run([]string{"init", "--device", "service-host"}); code != 0 {
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
	if err := st.LinkServiceAccountControlPlane("http://control.test", "org_prod", "prod", "usr_owner", "svc_prod", "prod-api", "Production API", "wdev_prod", device.ID, "at_service", "rt_service", 3600, time.Now().UTC().Add(7*24*time.Hour).Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}

	remoteHit := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		remoteHit = true
		http.Error(w, "unexpected", http.StatusInternalServerError)
	}))
	defer server.Close()

	out.Reset()
	errb.Reset()
	if code := app.Run([]string{"login", "--origin", server.URL}); code == 0 {
		t.Fatal("human login should fail while a service account session is active")
	}
	if remoteHit {
		t.Fatal("human login should not start remote refresh or device-code flow for service account sessions")
	}
	if !strings.Contains(errb.String(), "service account session active; run asiri logout first") {
		t.Fatalf("unexpected error: %s", errb.String())
	}
}

func TestServiceAccountWipeCommandsAreRejected(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
	}{
		{name: "local wipe", args: []string{"local", "wipe", "--yes"}},
		{name: "cache wipe", args: []string{"cache", "wipe"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tmp := t.TempDir()
			old := os.Getenv("ASIRI_HOME")
			t.Cleanup(func() { _ = os.Setenv("ASIRI_HOME", old) })
			if err := os.Setenv("ASIRI_HOME", tmp); err != nil {
				t.Fatal(err)
			}

			var out bytes.Buffer
			var errb bytes.Buffer
			app := New(&out, &errb)
			if code := app.Run([]string{"init", "--device", "service-host"}); code != 0 {
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
			if err := st.LinkServiceAccountControlPlane("http://control.test", "org_prod", "prod", "usr_owner", "svc_prod", "prod-api", "Production API", "wdev_prod", device.ID, "at_service", "rt_service", 3600, time.Now().UTC().Add(7*24*time.Hour).Format(time.RFC3339)); err != nil {
				t.Fatal(err)
			}

			out.Reset()
			errb.Reset()
			if code := app.Run(tc.args); code == 0 {
				t.Fatalf("%v should fail for service account sessions", tc.args)
			}
			if !strings.Contains(errb.String(), "service account sessions cannot mutate local vault or policy state") {
				t.Fatalf("unexpected error: %s", errb.String())
			}
			if _, err := os.Stat(filepath.Join(tmp, "local-state.json")); err != nil {
				t.Fatalf("state file should remain after rejected wipe: %v", err)
			}
		})
	}
}

func TestServiceAccountPullTargetsStayOnBoundWorkspace(t *testing.T) {
	active := &asiri.ControlPlaneLink{Source: "service-account", WorkspaceID: "org_prod", WorkspaceSlug: "prod"}
	workspaces := []remoteWorkspaceResponse{
		{ID: "org_prod", Slug: "prod", CurrentDeviceTrusted: boolPtr(true), CanPull: boolPtr(true)},
		{ID: "org_staging", Slug: "staging", CurrentDeviceTrusted: boolPtr(true), CanPull: boolPtr(true)},
	}

	targets, results := pullTargets(active, workspaces, pullOptions{})
	if len(results) != 0 || len(targets) != 1 || targets[0].Workspace.Slug != "prod" {
		t.Fatalf("default service account pull should target only active workspace, targets=%#v results=%#v", targets, results)
	}

	targets, results = pullTargets(active, workspaces, pullOptions{Workspaces: []string{"staging", "prod"}})
	if len(targets) != 1 || targets[0].Workspace.Slug != "prod" || len(results) != 1 || results[0].Result != "failed" {
		t.Fatalf("explicit service account pull should fail non-active workspace and keep active target, targets=%#v results=%#v", targets, results)
	}
}

func TestServiceAccountRuntimeUsesSyncedServicePolicies(t *testing.T) {
	expiredAt := time.Now().UTC().Add(-time.Minute)
	validUntil := time.Now().UTC().Add(time.Hour)
	st := &store.FileStore{State: asiri.State{
		ControlPlane: &asiri.ControlPlaneLink{Source: "service-account", ServiceAccountSlug: "prod-api"},
		Policies: []asiri.Policy{{
			ID:            "pol_stale",
			Subject:       "prod-api",
			ScopePattern:  "prod/*",
			SecretPattern: "*",
			Actions:       []string{"read"},
			ApprovalMode:  "none",
			CreatedAt:     time.Now().UTC(),
		}},
	}}
	importServiceAccountSyncPolicies(st, []syncPolicyResponse{{
		ID:            "pol_expired_read",
		SubjectType:   "service",
		SubjectID:     "prod-api",
		ScopePattern:  "prod/api",
		SecretPattern: "DATABASE_URL",
		Actions:       []string{"read"},
		ApprovalMode:  "none",
		CreatedAt:     time.Now().UTC(),
		ExpiresAt:     &expiredAt,
	}, {
		ID:            "pol_inject",
		SubjectType:   "service",
		SubjectID:     "prod-api",
		ScopePattern:  "prod/api",
		SecretPattern: "DATABASE_URL",
		Actions:       []string{"inject"},
		ApprovalMode:  "none",
		CreatedAt:     time.Now().UTC(),
		ExpiresAt:     &validUntil,
	}})

	subject, labelType, err := runtimeSubject(st, "other-agent", "process-name", true)
	if err != nil {
		t.Fatal(err)
	}
	if subject != "prod-api" || labelType != "service" {
		t.Fatalf("service account runtime subject mismatch: subject=%s type=%s", subject, labelType)
	}
	if allowed, _ := st.CheckPolicy(subject, "prod/api/DATABASE_URL", "read"); allowed {
		t.Fatal("synced inject-only service account policy should not allow raw read")
	}
	if allowed, reason := st.CheckPolicy(subject, "prod/api/DATABASE_URL", "inject"); !allowed {
		t.Fatalf("synced service account policy should allow inject: %s", reason)
	}
	if st.State.Policies[1].ExpiresAt == nil || !st.State.Policies[1].ExpiresAt.Equal(validUntil) {
		t.Fatalf("synced service account policy should preserve expiry: %#v", st.State.Policies[1].ExpiresAt)
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

func TestWhoamiUsesFreshCachedControlPlaneToken(t *testing.T) {
	tmp := t.TempDir()
	old := os.Getenv("ASIRI_HOME")
	t.Cleanup(func() { _ = os.Setenv("ASIRI_HOME", old) })
	if err := os.Setenv("ASIRI_HOME", tmp); err != nil {
		t.Fatal(err)
	}

	refreshCalls := 0
	whoamiSeen := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		switch r.URL.Path {
		case "/v1/auth/session/refresh":
			refreshCalls++
			http.Error(w, "unexpected refresh", http.StatusInternalServerError)
		case "/v1/whoami":
			whoamiSeen = true
			if r.Header.Get("authorization") != "Bearer at_cached" || r.Header.Get("x-asiri-device") != "dev_remote" || r.Header.Get("x-asiri-signature") == "" {
				t.Fatalf("whoami request missing signed cached session: auth=%s device=%s", r.Header.Get("authorization"), r.Header.Get("x-asiri-device"))
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"user": map[string]any{
					"id":          "usr_owner",
					"email":       "peter@example.com",
					"displayName": "Peter Owner",
					"role":        "user",
					"status":      "active",
				},
				"workspace": map[string]any{
					"id":   "org_remote",
					"name": "O Clan",
					"slug": "oclan-co",
				},
				"device": map[string]any{
					"id":     "dev_remote",
					"name":   "qa-laptop",
					"kind":   "laptop",
					"status": "trusted",
				},
				"session": map[string]any{
					"workspaceId": "org_remote",
					"deviceId":    "dev_remote",
					"status":      "active",
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
	if code := app.Run([]string{"whoami"}); code != 0 {
		t.Fatalf("whoami failed: %s", errb.String())
	}
	if refreshCalls != 0 || !whoamiSeen {
		t.Fatalf("expected cached whoami without refresh, refreshes=%d whoami=%v", refreshCalls, whoamiSeen)
	}
	got := out.String()
	for _, expected := range []string{"peter@example.com", "Peter Owner", "oclan-co", "LOCAL DEVICE", "qa-laptop", "REMOTE DEVICE", "dev_remote"} {
		if !strings.Contains(got, expected) {
			t.Fatalf("whoami output missing %q: %s", expected, got)
		}
	}
}

func TestWhoamiShowsServiceAccountName(t *testing.T) {
	tmp := t.TempDir()
	old := os.Getenv("ASIRI_HOME")
	t.Cleanup(func() { _ = os.Setenv("ASIRI_HOME", old) })
	if err := os.Setenv("ASIRI_HOME", tmp); err != nil {
		t.Fatal(err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		if r.URL.Path != "/v1/whoami" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"user": map[string]any{
				"id":     "usr_owner",
				"status": "active",
			},
			"workspace": map[string]any{
				"id":   "org_prod",
				"slug": "prod",
			},
			"session": map[string]any{
				"identityType":       "service_account",
				"workspaceId":        "org_prod",
				"deviceId":           "wdev_prod",
				"serviceAccountSlug": "prod-api",
				"serviceAccountName": "Production API",
				"approvedByUserId":   "usr_owner",
				"status":             "active",
			},
		})
	}))
	defer server.Close()

	var out bytes.Buffer
	var errb bytes.Buffer
	app := New(&out, &errb)
	if code := app.Run([]string{"init", "--device", "service-host"}); code != 0 {
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
	if err := st.LinkServiceAccountControlPlane(server.URL, "org_prod", "prod", "usr_owner", "svc_prod", "prod-api", "Production API", "wdev_prod", device.ID, "at_service", "rt_service", 3600, time.Now().UTC().Add(7*24*time.Hour).Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}

	out.Reset()
	errb.Reset()
	if code := app.Run([]string{"whoami"}); code != 0 {
		t.Fatalf("whoami failed: %s", errb.String())
	}
	got := out.String()
	for _, expected := range []string{"IDENTITY", "service account", "SERVICE ACCOUNT", "prod-api", "SERVICE ACCOUNT NAME", "Production API", "APPROVED BY", "usr_owner"} {
		if !strings.Contains(got, expected) {
			t.Fatalf("whoami output missing %q: %s", expected, got)
		}
	}
}

func TestEnsureControlPlaneAccessRefreshesNearExpiryToken(t *testing.T) {
	tmp := t.TempDir()
	old := os.Getenv("ASIRI_HOME")
	t.Cleanup(func() { _ = os.Setenv("ASIRI_HOME", old) })
	if err := os.Setenv("ASIRI_HOME", tmp); err != nil {
		t.Fatal(err)
	}

	refreshSeen := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		if r.URL.Path != "/v1/auth/session/refresh" {
			http.NotFound(w, r)
			return
		}
		refreshSeen = true
		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if body["refreshToken"] != "rt_cached" {
			t.Fatalf("unexpected refresh body: %#v", body)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":           "approved",
			"orgId":            "org_remote",
			"workspaceSlug":    "oclan-co",
			"userId":           "usr_owner",
			"deviceId":         "dev_remote",
			"accessToken":      "at_refreshed",
			"expiresIn":        3600,
			"refreshExpiresAt": time.Now().UTC().Add(7 * 24 * time.Hour).Format(time.RFC3339),
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
	if err := st.LinkControlPlaneForDevice(server.URL, "org_remote", "oclan-co", "usr_owner", "dev_remote", device.ID, "at_cached", "rt_cached", 30, time.Now().UTC().Add(7*24*time.Hour).Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}

	token, err := ensureControlPlaneAccess(server.URL, st)
	if err != nil {
		t.Fatal(err)
	}
	if token != "at_refreshed" || !refreshSeen {
		t.Fatalf("expected near-expiry token refresh, token=%q refresh=%v", token, refreshSeen)
	}
	stored, err := st.ControlPlaneAccessToken()
	if err != nil {
		t.Fatal(err)
	}
	if stored != "at_refreshed" {
		t.Fatalf("expected refreshed token to be stored, got %q", stored)
	}
}

func TestBearerUnauthorizedRefreshesFreshCachedToken(t *testing.T) {
	tmp := t.TempDir()
	old := os.Getenv("ASIRI_HOME")
	t.Cleanup(func() { _ = os.Setenv("ASIRI_HOME", old) })
	if err := os.Setenv("ASIRI_HOME", tmp); err != nil {
		t.Fatal(err)
	}

	whoamiCalls := 0
	refreshCalls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		switch r.URL.Path {
		case "/v1/auth/session/refresh":
			refreshCalls++
			var body map[string]string
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if body["refreshToken"] != "rt_cached" {
				t.Fatalf("unexpected refresh body: %#v", body)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status":           "approved",
				"orgId":            "org_remote",
				"workspaceSlug":    "oclan-co",
				"userId":           "usr_owner",
				"deviceId":         "dev_remote",
				"accessToken":      "at_refreshed",
				"expiresIn":        3600,
				"refreshExpiresAt": time.Now().UTC().Add(7 * 24 * time.Hour).Format(time.RFC3339),
			})
		case "/v1/whoami":
			whoamiCalls++
			if whoamiCalls == 1 {
				if r.Header.Get("authorization") != "Bearer at_cached" {
					t.Fatalf("unexpected first whoami auth: %s", r.Header.Get("authorization"))
				}
				w.WriteHeader(http.StatusUnauthorized)
				_ = json.NewEncoder(w).Encode(map[string]any{"error": "not_authenticated"})
				return
			}
			if r.Header.Get("authorization") != "Bearer at_refreshed" || r.Header.Get("x-asiri-device") != "dev_remote" || r.Header.Get("x-asiri-signature") == "" {
				t.Fatalf("whoami retry missing signed refreshed session: auth=%s device=%s", r.Header.Get("authorization"), r.Header.Get("x-asiri-device"))
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"user": map[string]any{"email": "peter@example.com", "displayName": "Peter Owner"},
				"workspace": map[string]any{
					"id": "org_remote", "slug": "oclan-co", "role": "owner", "deviceStatus": "trusted",
				},
				"device":  map[string]any{"id": "dev_remote", "name": "qa-laptop", "kind": "laptop", "status": "trusted"},
				"session": map[string]any{"source": "device-code", "status": "active"},
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

	if code := app.Run([]string{"whoami"}); code != 0 {
		t.Fatalf("whoami failed after refresh retry: %s", errb.String())
	}
	if refreshCalls != 1 || whoamiCalls != 2 {
		t.Fatalf("expected one refresh retry, refresh=%d whoami=%d", refreshCalls, whoamiCalls)
	}
	st, err = store.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	stored, err := st.ControlPlaneAccessToken()
	if err != nil {
		t.Fatal(err)
	}
	if stored != "at_refreshed" {
		t.Fatalf("expected refreshed access token to be stored, got %q", stored)
	}
}

func TestDeviceCodeApprovalOriginMustMatchControlPlaneOrigin(t *testing.T) {
	device := asiri.Device{
		Name:                "qa-laptop",
		Kind:                "laptop",
		EncryptionPublicKey: "enc",
		SigningPublicKey:    "sig",
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/auth/device-code/start" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"deviceCode":              "dc_test",
			"userCode":                "ABCD-2345",
			"verificationUri":         "https://asiri.dev/dashboard/",
			"verificationUriComplete": "https://asiri.dev/dashboard/?code=ABCD-2345",
			"expiresIn":               30,
			"interval":                2,
		})
	}))
	defer server.Close()

	_, err := startDeviceCodeLogin(server.URL, "local", device)
	if err == nil || !strings.Contains(err.Error(), "does not match control-plane origin") {
		t.Fatalf("expected mismatched approval origin error, got %v", err)
	}
}

func TestDeviceCodeApprovalAllowsLocalWorkerAndDashboardPorts(t *testing.T) {
	for _, testcase := range []struct {
		controlPlane string
		approval     string
	}{
		{
			controlPlane: "http://127.0.0.1:8787",
			approval:     "http://127.0.0.1:4173/dashboard/?code=ABCD-2345",
		},
		{
			controlPlane: "http://localhost:8787",
			approval:     "http://127.0.0.1:4173/dashboard/?code=ABCD-2345",
		},
	} {
		if err := validateDeviceCodeApprovalOrigin(testcase.controlPlane, testcase.approval); err != nil {
			t.Fatalf("expected local approval origin to be accepted for %#v: %v", testcase, err)
		}
	}
}

func TestLoginReportsCloudflareChallengeInsteadOfJSONDecodeError(t *testing.T) {
	tmp := t.TempDir()
	old := os.Getenv("ASIRI_HOME")
	t.Cleanup(func() { _ = os.Setenv("ASIRI_HOME", old) })
	if err := os.Setenv("ASIRI_HOME", tmp); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/auth/device-code/start" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("content-type", "text/html; charset=UTF-8")
		w.Header().Set("cf-mitigated", "challenge")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`<!DOCTYPE html><html><head><title>Just a moment...</title></head><body>Enable JavaScript and cookies to continue</body></html>`))
	}))
	defer server.Close()

	var out, errb bytes.Buffer
	app := New(&out, &errb)
	if code := app.Run([]string{"init", "--device", "qa-laptop"}); code != 0 {
		t.Fatalf("init failed: %s", errb.String())
	}
	out.Reset()
	errb.Reset()
	if code := app.Run([]string{"login", "--origin", server.URL}); code == 0 {
		t.Fatal("login should fail when the control plane returns a Cloudflare challenge")
	}
	got := errb.String()
	for _, expected := range []string{"Cloudflare challenge", "instead of JSON", "rate limits"} {
		if !strings.Contains(got, expected) {
			t.Fatalf("login error missing %q: %s", expected, got)
		}
	}
	if strings.Contains(got, "invalid character '<'") {
		t.Fatalf("login leaked raw JSON decode error: %s", got)
	}
}

func TestDeviceListDefaultsToRemoteWhenLinked(t *testing.T) {
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
	if code := app.Run([]string{"device", "list"}); code != 0 {
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
	if code := app.Run([]string{"device", "list", "--include-revoked"}); code != 0 {
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

func TestRemoteSelfRevokeClearsLocalRuntime(t *testing.T) {
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
		case "/v1/devices/dev_remote/revoke":
			if r.Header.Get("authorization") != "Bearer at_self" {
				t.Fatalf("unexpected remote revoke auth header: %s", r.Header.Get("authorization"))
			}
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
	if st.State.ControlPlane != nil {
		t.Fatalf("remote self-revoke should clear control-plane link: %#v", st.State.ControlPlane)
	}
	if len(st.State.KeyRefs) != 0 {
		t.Fatalf("remote self-revoke should clear local key refs: %#v", st.State.KeyRefs)
	}
	if _, _, err := st.GetSecret("oclan-co/local/asiri/API_KEY"); err == nil {
		t.Fatal("remote self-revoke should block local decryption")
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
		case "/v1/devices/dev_remote/revoke":
			revokeSeen = true
			if r.Header.Get("authorization") != "Bearer at_test" {
				t.Fatalf("unexpected remote revoke auth header: %s", r.Header.Get("authorization"))
			}
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

func TestCLIEndToEndLocalRuntime(t *testing.T) {
	tmp := t.TempDir()
	old := os.Getenv("ASIRI_HOME")
	t.Cleanup(func() { _ = os.Setenv("ASIRI_HOME", old) })
	if err := os.Setenv("ASIRI_HOME", tmp); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	var errb bytes.Buffer
	app := New(&out, &errb)
	steps := [][]string{
		{"init", "--device", "qa-laptop"},
		{"add", "--workspace", "qa", "openai/api_key", "--value-file", testSecretFile(t, "qa_secret_value")},
		{"grant", "--workspace", "qa", "codex", "openai/api_key", "--inject-only"},
		{"run", "--workspace", "qa", "--agent", "codex", "--env", "OPENAI_API_KEY=openai/api_key", "--", "sh", "-c", "test \"$OPENAI_API_KEY\" = qa_secret_value"},
		{"broker", "start", "--once"},
	}
	for _, step := range steps {
		if code := app.Run(step); code != 0 {
			t.Fatalf("%v failed with code %d stderr=%s", step, code, errb.String())
		}
	}
	if strings.Contains(out.String(), "qa_secret_value") {
		t.Fatalf("asiri output leaked secret: %s", out.String())
	}
	if code := app.Run([]string{"get", "--workspace", "qa", "openai/api_key", "--agent", "codex"}); code == 0 {
		t.Fatalf("agent raw read should be denied without explicit --read grant")
	}
	if !strings.Contains(errb.String(), "raw read requires") {
		t.Fatalf("expected raw read denial, got stderr=%s", errb.String())
	}
}

func TestAuditTailWorkspaceFilterMatchesWorkspaceMetadata(t *testing.T) {
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
	st.Audit("local-human", "control_plane_push", "allowed", "", "", "qa push", map[string]string{"workspace": "qa"})
	st.Audit("local-human", "control_plane_rewrap", "allowed", "", "", "qa rewrap", map[string]string{"workspaceSlug": "qa"})
	st.Audit("local-human", "control_plane_push", "allowed", "", "", "prod push", map[string]string{"workspace": "prod"})
	if err := st.Save(); err != nil {
		t.Fatal(err)
	}

	out.Reset()
	errb.Reset()
	if code := app.Run([]string{"audit", "tail", "--workspace", "qa", "--limit", "10"}); code != 0 {
		t.Fatalf("audit tail failed: %s", errb.String())
	}
	audit := out.String()
	if !strings.Contains(audit, "qa push") || !strings.Contains(audit, "qa rewrap") {
		t.Fatalf("workspace audit filter missed matching events: %s", audit)
	}
	if strings.Contains(audit, "prod push") {
		t.Fatalf("workspace audit filter included another workspace: %s", audit)
	}
}

func TestShortPathRejectsKnownDifferentWorkspacePrefix(t *testing.T) {
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
	if err := st.BindWorkspacePrefix("other", "org_other", "other"); err != nil {
		t.Fatal(err)
	}

	out.Reset()
	errb.Reset()
	if code := app.Run([]string{"add", "--workspace", "qa", "other/openai/api_key", "--value-file", testSecretFile(t, "secret_value")}); code == 0 {
		t.Fatal("known different workspace prefix should be rejected")
	}
	if !strings.Contains(errb.String(), "add accepts short paths") {
		t.Fatalf("expected short-path guidance, got %s", errb.String())
	}
}

func TestInitRejectsWorkspaceSlug(t *testing.T) {
	tmp := t.TempDir()
	old := os.Getenv("ASIRI_HOME")
	t.Cleanup(func() { _ = os.Setenv("ASIRI_HOME", old) })
	if err := os.Setenv("ASIRI_HOME", tmp); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	var errb bytes.Buffer
	app := New(&out, &errb)
	if code := app.Run([]string{"init", "--workspace", "oclan-co", "--device", "qa-laptop"}); code == 0 {
		t.Fatal("init should reject workspace slugs")
	}
	if !strings.Contains(errb.String(), "local vaults do not have workspace slugs") {
		t.Fatalf("expected workspace rejection, got stderr=%s", errb.String())
	}
}

func TestLoginUsesDeviceCodeFlow(t *testing.T) {
	tmp := t.TempDir()
	old := os.Getenv("ASIRI_HOME")
	t.Cleanup(func() { _ = os.Setenv("ASIRI_HOME", old) })
	if err := os.Setenv("ASIRI_HOME", tmp); err != nil {
		t.Fatal(err)
	}
	startSeen := false
	tokenSeen := false
	refreshSeen := false
	remoteRevokeSeen := false
	logoutSeen := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		switch r.URL.Path {
		case "/v1/auth/device-code/start":
			startSeen = true
			var body map[string]string
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if body["localWorkspaceSlug"] != "" || body["workspaceSlug"] != "" || body["deviceName"] != "qa-laptop" || body["encryptionPublicKey"] == "" || body["signingPublicKey"] == "" {
				t.Fatalf("unexpected start body: %#v", body)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"deviceCode":              "dc_test",
				"userCode":                "ABCD-2345",
				"verificationUri":         serverURL(r) + "/auth/device",
				"verificationUriComplete": serverURL(r) + "/auth/device?code=ABCD-2345",
				"expiresIn":               30,
				"interval":                0,
			})
		case "/v1/auth/device-code/token":
			tokenSeen = true
			var body map[string]string
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if body["deviceCode"] != "dc_test" {
				t.Fatalf("unexpected token body: %#v", body)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status":           "approved",
				"orgId":            "org_remote",
				"workspaceSlug":    "oclan-co",
				"userId":           "usr_owner",
				"deviceId":         "dev_remote",
				"accessToken":      "at_test",
				"refreshToken":     "rt_test",
				"expiresIn":        3600,
				"refreshExpiresAt": time.Now().UTC().Add(7 * 24 * time.Hour).Format(time.RFC3339),
			})
		case "/v1/auth/session/refresh":
			refreshSeen = true
			var body map[string]string
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if body["refreshToken"] != "rt_test" {
				t.Fatalf("unexpected refresh body: %#v", body)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status":           "approved",
				"orgId":            "org_remote",
				"workspaceSlug":    "oclan-co",
				"userId":           "usr_owner",
				"deviceId":         "dev_remote",
				"accessToken":      "at_refreshed",
				"expiresIn":        3600,
				"refreshExpiresAt": time.Now().UTC().Add(7 * 24 * time.Hour).Format(time.RFC3339),
			})
		case "/v1/devices/dev_other/revoke":
			remoteRevokeSeen = true
			if r.Header.Get("authorization") != "Bearer at_refreshed" {
				t.Fatalf("unexpected remote revoke auth header: %s", r.Header.Get("authorization"))
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id":     "dev_other",
				"name":   "ci-runner",
				"status": "revoked",
			})
		case "/v1/auth/session/logout":
			logoutSeen = true
			if r.Header.Get("x-asiri-device") != "dev_remote" || r.Header.Get("x-asiri-signature") == "" {
				t.Fatalf("logout request missing signed device proof")
			}
			var body map[string]string
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if body["refreshToken"] != "rt_test" {
				t.Fatalf("unexpected logout body: %#v", body)
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"status": "logged_out"})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	var out bytes.Buffer
	var errb bytes.Buffer
	app := New(&out, &errb)
	if code := app.Run([]string{"init", "--device", "qa-laptop"}); code != 0 {
		t.Fatalf("init failed: %s", errb.String())
	}
	out.Reset()
	errb.Reset()
	if code := app.Run([]string{"login", "--origin", server.URL}); code != 0 {
		t.Fatalf("login failed: %s", errb.String())
	}
	if !startSeen || !tokenSeen {
		t.Fatalf("expected start and token endpoints to be called")
	}
	if !strings.Contains(out.String(), "ABCD-2345") || !strings.Contains(out.String(), "oclan-co") {
		t.Fatalf("login output missing code or workspace: %s", out.String())
	}
	st, err := store.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	if st.State.ControlPlane == nil || st.State.ControlPlane.DeviceID != "dev_remote" || st.State.ControlPlane.WorkspaceSlug != "oclan-co" {
		t.Fatalf("control-plane link not persisted: %#v", st.State.ControlPlane)
	}
	bytes, err := os.ReadFile(filepath.Join(tmp, "local-state.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(bytes), "rt_test") || strings.Contains(string(bytes), "at_test") {
		t.Fatalf("local state persisted session token: %s", string(bytes))
	}
	out.Reset()
	errb.Reset()
	if code := app.Run([]string{"login", "--origin", server.URL}); code != 0 {
		t.Fatalf("refresh login failed: %s", errb.String())
	}
	if !refreshSeen {
		t.Fatalf("expected refresh endpoint to be called")
	}
	if strings.Contains(out.String(), "ABCD-2345") || !strings.Contains(out.String(), "session refreshed") {
		t.Fatalf("refresh login should not start device-code flow: %s", out.String())
	}
	out.Reset()
	errb.Reset()
	if code := app.Run([]string{"device", "revoke", "--workspace", "oclan-co", "dev_other", "--remote"}); code != 0 {
		t.Fatalf("remote device revoke failed: %s", errb.String())
	}
	if !remoteRevokeSeen {
		t.Fatalf("expected remote revoke endpoint to be called")
	}
	if !strings.Contains(out.String(), "ci-runner") || !strings.Contains(out.String(), "oclan-co") {
		t.Fatalf("remote revoke output missing device or workspace: %s", out.String())
	}
	out.Reset()
	errb.Reset()
	if code := app.Run([]string{"logout"}); code != 0 {
		t.Fatalf("logout failed: %s", errb.String())
	}
	if !logoutSeen {
		t.Fatalf("expected logout endpoint to be called")
	}
	st, err = store.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	if st.State.ControlPlane != nil {
		t.Fatalf("control-plane link not cleared: %#v", st.State.ControlPlane)
	}
}

func TestRemoteRevocationClearsLocalKeyMaterial(t *testing.T) {
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
			_ = json.NewEncoder(w).Encode(map[string]any{"error": "request_failed", "message": "device not trusted"})
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
	if code := app.Run([]string{"pull"}); code == 0 {
		t.Fatalf("expected revoked device pull failure, stdout=%s", out.String())
	}
	if !revoked || !strings.Contains(errb.String(), "local key material was cleared") {
		t.Fatalf("expected remote revocation cleanup, revoked=%v stderr=%s", revoked, errb.String())
	}
	st, err := store.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	if st.State.ControlPlane != nil || len(st.State.KeyRefs) != 0 {
		t.Fatalf("revoked device kept control-plane link or key refs: %#v", st.State)
	}
	if _, _, err := st.GetSecret("oclan-co/local/asiri/API_KEY"); err == nil {
		t.Fatal("revoked local vault still decrypted existing secret")
	}
}

func serverURL(r *http.Request) string {
	return "http://" + r.Host
}

func remoteDeleteTokenFromOutput(t *testing.T, output string) string {
	t.Helper()
	for _, line := range strings.Split(output, "\n") {
		token, ok := strings.CutPrefix(line, "Confirmation token: ")
		if ok && strings.HasPrefix(token, "del_") {
			return token
		}
	}
	t.Fatalf("missing confirmation token in output: %s", output)
	return ""
}

func TestPushAndPullUseBearerAccessToken(t *testing.T) {
	tmp := t.TempDir()
	old := os.Getenv("ASIRI_HOME")
	t.Cleanup(func() { _ = os.Setenv("ASIRI_HOME", old) })
	if err := os.Setenv("ASIRI_HOME", tmp); err != nil {
		t.Fatal(err)
	}
	secretPushCount := 0
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
					{"id": "org_remote", "name": "O Clan", "slug": "oclan-co", "ownerUserId": "usr_owner", "role": "owner", "canPull": true, "canWrite": true},
				},
			})
		case "/v1/sync/write-options":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"requestedWorkspaceSlug": "oclan-co",
				"activeWorkspace": map[string]any{
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
			if r.Header.Get("authorization") != "Bearer at_push" {
				t.Fatalf("unexpected device list auth header: %s", r.Header.Get("authorization"))
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
		{"pull"},
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
					_ = json.NewEncoder(w).Encode(map[string]any{
						"activeOrgId": "org_dry_run",
						"organizations": []map[string]any{
							{"id": "org_dry_run", "name": "O Clan", "slug": "oclan-co", "ownerUserId": "usr_owner", "role": "owner", "canPull": true, "canWrite": true},
						},
					})
				case "/v1/sync/write-options":
					writeOptionsSeen = true
					_ = json.NewEncoder(w).Encode(map[string]any{
						"requestedWorkspaceSlug": "oclan-co",
						"activeWorkspace": map[string]any{
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

func TestPushDryRunRemoteWorkspaceDoesNotPersistSessionSwitch(t *testing.T) {
	tmp := t.TempDir()
	old := os.Getenv("ASIRI_HOME")
	t.Cleanup(func() { _ = os.Setenv("ASIRI_HOME", old) })
	if err := os.Setenv("ASIRI_HOME", tmp); err != nil {
		t.Fatal(err)
	}
	switchSeen := false
	encryptedSeen := false
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
		case "/v1/orgs":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"activeOrgId": "org_oclan",
				"organizations": []map[string]any{
					{"id": "org_oclan", "name": "O Clan", "slug": "oclan-co", "ownerUserId": "usr_owner", "role": "owner", "canPull": true, "canWrite": true, "currentDeviceTrusted": true},
					{"id": "org_asiri", "name": "Asiri Dev", "slug": "asiri-dev", "ownerUserId": "usr_owner", "role": "owner", "canPull": true, "canWrite": true, "currentDeviceTrusted": true},
				},
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
			if r.Header.Get("authorization") != "Bearer at_asiri" {
				t.Fatalf("dry-run should use transient switched token, got %s", r.Header.Get("authorization"))
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"requestedWorkspaceSlug": "asiri-dev",
				"activeWorkspace": map[string]any{
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
			if r.Header.Get("authorization") != "Bearer at_asiri" || r.URL.Query().Get("orgId") != "org_asiri" {
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
	if !switchSeen || !encryptedSeen {
		t.Fatalf("dry-run should switch transiently and evaluate remote state, switch=%v encrypted=%v", switchSeen, encryptedSeen)
	}
	reloaded, err := store.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.State.ControlPlane == nil || reloaded.State.ControlPlane.WorkspaceID != "org_oclan" || reloaded.State.ControlPlane.WorkspaceSlug != "oclan-co" {
		t.Fatalf("dry-run persisted workspace session switch: %#v", reloaded.State.ControlPlane)
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
		case "/v1/sync/write-options":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"requestedWorkspaceSlug": "oclan-co",
				"activeWorkspace": map[string]any{
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

func TestRewrapSkipsRemoteVersionMissingLocally(t *testing.T) {
	tmp := t.TempDir()
	old := os.Getenv("ASIRI_HOME")
	t.Cleanup(func() { _ = os.Setenv("ASIRI_HOME", old) })
	if err := os.Setenv("ASIRI_HOME", tmp); err != nil {
		t.Fatal(err)
	}
	devicePublicKey := ""
	rewrapSeen := false
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
				"deviceCode":              "dc_rewrap_skip",
				"userCode":                "SKIP-1234",
				"verificationUriComplete": serverURL(r) + "/auth/device?code=SKIP-1234",
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
				"accessToken":      "at_rewrap_skip",
				"refreshToken":     "rt_rewrap_skip",
				"expiresIn":        3600,
				"refreshExpiresAt": time.Now().UTC().Add(7 * 24 * time.Hour).Format(time.RFC3339),
			})
		case "/v1/devices":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"devices": []map[string]any{
					{"id": "dev_remote", "name": "qa-laptop", "status": "trusted", "kind": "laptop", "encryptionPublicKey": devicePublicKey},
					{"id": "dev_other", "name": "server", "status": "trusted", "kind": "server", "encryptionPublicKey": devicePublicKey},
				},
			})
		case "/v1/secrets/encrypted":
			if r.Method != http.MethodGet {
				http.NotFound(w, r)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"secrets": []map[string]any{}})
		case "/v1/secrets":
			if r.Method != http.MethodGet {
				http.NotFound(w, r)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"secrets": []map[string]any{{
					"id":         "secv_remote_newer",
					"orgId":      "org_remote",
					"scope":      "oclan-co/local/asiri",
					"name":       "API_KEY",
					"version":    2,
					"algorithm":  "aes-256-gcm",
					"nonce":      "unused",
					"ciphertext": "unused",
					"aad":        "org_remote:oclan-co/local/asiri:API_KEY:2:dev_remote",
					"status":     "active",
					"wrappedRecipients": []map[string]any{{
						"recipientType": "device",
						"recipientId":   "dev_remote",
						"wrapAlgorithm": "p256-hkdf-aes256gcm",
					}},
				}},
			})
		case "/v1/secrets/secv_remote_newer/wrapped-keys":
			rewrapSeen = true
			t.Fatal("rewrap should skip remote versions that are not stored locally")
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
		{"rewrap", "--workspace", "oclan-co"},
	} {
		out.Reset()
		errb.Reset()
		if code := app.Run(step); code != 0 {
			t.Fatalf("%v failed with code %d stderr=%s", step, code, errb.String())
		}
	}
	if rewrapSeen {
		t.Fatal("rewrap endpoint should not be called")
	}
	if !strings.Contains(out.String(), "missing matching local key material") {
		t.Fatalf("rewrap output missing skip result: %s", out.String())
	}
}

func TestRewrapAddsCurrentTrustedDeviceWhenLocalKeyExists(t *testing.T) {
	tmp := t.TempDir()
	old := os.Getenv("ASIRI_HOME")
	t.Cleanup(func() { _ = os.Setenv("ASIRI_HOME", old) })
	if err := os.Setenv("ASIRI_HOME", tmp); err != nil {
		t.Fatal(err)
	}
	devicePublicKey := ""
	rewrapSeen := false
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
				"deviceCode":              "dc_rewrap_current",
				"userCode":                "CURR-1234",
				"verificationUriComplete": serverURL(r) + "/auth/device?code=CURR-1234",
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
				"accessToken":      "at_rewrap_current",
				"refreshToken":     "rt_rewrap_current",
				"expiresIn":        3600,
				"refreshExpiresAt": time.Now().UTC().Add(7 * 24 * time.Hour).Format(time.RFC3339),
			})
		case "/v1/devices":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"devices": []map[string]any{
					{"id": "dev_remote", "name": "qa-laptop", "status": "trusted", "kind": "laptop", "encryptionPublicKey": devicePublicKey},
				},
			})
		case "/v1/secrets/encrypted":
			_ = json.NewEncoder(w).Encode(map[string]any{"secrets": []map[string]any{}})
		case "/v1/secrets":
			if r.Method != http.MethodGet {
				http.NotFound(w, r)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"secrets": []map[string]any{{
				"id":        "secv_current_missing",
				"orgId":     "org_remote",
				"scope":     "oclan-co/local/asiri",
				"name":      "API_KEY",
				"version":   1,
				"algorithm": "aes-256-gcm",
				"status":    "active",
				"wrappedRecipients": []map[string]any{{
					"recipientType": "device",
					"recipientId":   "dev_old",
					"wrapAlgorithm": "p256-hkdf-aes256gcm",
				}},
			}}})
		case "/v1/secrets/secv_current_missing/wrapped-keys":
			rewrapSeen = true
			var body struct {
				WrappedKeys []map[string]any `json:"wrappedKeys"`
				LocalRepair bool             `json:"localRepair"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if !body.LocalRepair {
				t.Fatalf("current device rewrap should request local repair: %#v", body)
			}
			if len(body.WrappedKeys) != 1 || body.WrappedKeys[0]["recipientId"] != "dev_remote" {
				t.Fatalf("current device rewrap used wrong recipient: %#v", body)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"id": "secv_current_missing", "status": "active"})
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
	if err := st.BindWorkspacePrefix("oclan-co", "org_remote", "oclan-co"); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	errb.Reset()
	if code := app.Run([]string{"rewrap", "--workspace", "oclan-co"}); code != 0 {
		t.Fatalf("rewrap failed with code %d stderr=%s", code, errb.String())
	}
	if !rewrapSeen {
		t.Fatal("expected current device rewrap endpoint")
	}
	if !strings.Contains(out.String(), "Rewrapped 1") {
		t.Fatalf("rewrap output missing success count: %s", out.String())
	}
}

func TestRecoverySetupShowsKeyOnceAndWrapsRemoteSecrets(t *testing.T) {
	tmp := t.TempDir()
	old := os.Getenv("ASIRI_HOME")
	t.Cleanup(func() { _ = os.Setenv("ASIRI_HOME", old) })
	if err := os.Setenv("ASIRI_HOME", tmp); err != nil {
		t.Fatal(err)
	}
	secretPushSeen := false
	recoveryCreateSeen := false
	var recoveryCreateBody map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		switch r.URL.Path {
		case "/v1/auth/device-code/start":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"deviceCode":              "dc_recovery",
				"userCode":                "RECV-1234",
				"verificationUriComplete": serverURL(r) + "/auth/device?code=RECV-1234",
				"expiresIn":               30,
				"interval":                0,
			})
		case "/v1/auth/device-code/token":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status":           "approved",
				"orgId":            "org_recovery",
				"workspaceSlug":    "oclan-co",
				"userId":           "usr_owner",
				"deviceId":         "dev_recovery",
				"accessToken":      "at_recovery",
				"refreshToken":     "rt_recovery",
				"expiresIn":        3600,
				"refreshExpiresAt": time.Now().UTC().Add(7 * 24 * time.Hour).Format(time.RFC3339),
			})
		case "/v1/sync/write-options":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"requestedWorkspaceSlug": "oclan-co",
				"activeWorkspace": map[string]any{
					"id":       "org_recovery",
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
				secretPushSeen = true
				var body map[string]any
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					t.Fatal(err)
				}
				wrapped, ok := body["wrappedKeys"].([]any)
				if !ok || len(wrapped) != 1 {
					t.Fatalf("initial push should contain only the device wrapped key: %#v", body["wrappedKeys"])
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"id": "secv_recovery", "status": "active"})
				return
			}
			if r.Method != http.MethodGet {
				http.NotFound(w, r)
				return
			}
			if r.URL.Query().Get("orgId") != "org_recovery" {
				t.Fatalf("unexpected secrets query: %s", r.URL.RawQuery)
			}
			if !secretPushSeen {
				_ = json.NewEncoder(w).Encode(map[string]any{"secrets": []map[string]any{}})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"secrets": []map[string]any{{
					"id":      "secv_recovery",
					"orgId":   "org_recovery",
					"scope":   "oclan-co/local/asiri",
					"name":    "API_KEY",
					"version": 1,
					"status":  "active",
					"wrappedKeys": []map[string]any{{
						"recipientType": "device",
						"recipientId":   "dev_recovery",
						"wrapAlgorithm": "p256-hkdf-aes256gcm",
						"wrappedKey":    "wrapped",
					}},
				}},
			})
		case "/v1/secrets/encrypted":
			if r.Method != http.MethodGet {
				http.NotFound(w, r)
				return
			}
			if r.URL.Query().Get("orgId") != "org_recovery" {
				t.Fatalf("unexpected secrets query: %s", r.URL.RawQuery)
			}
			if !secretPushSeen {
				_ = json.NewEncoder(w).Encode(map[string]any{"secrets": []map[string]any{}})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"secrets": []map[string]any{{
					"id":      "secv_recovery",
					"orgId":   "org_recovery",
					"scope":   "oclan-co/local/asiri",
					"name":    "API_KEY",
					"version": 1,
					"status":  "active",
					"wrappedKeys": []map[string]any{{
						"recipientType": "device",
						"recipientId":   "dev_recovery",
						"wrapAlgorithm": "p256-hkdf-aes256gcm",
						"wrappedKey":    "wrapped",
					}},
				}},
			})
		case "/v1/recovery-recipient":
			recoveryCreateSeen = true
			if r.Method != http.MethodPost {
				http.NotFound(w, r)
				return
			}
			if r.Header.Get("authorization") != "Bearer at_recovery" {
				t.Fatalf("unexpected recovery recipient auth header: %s", r.Header.Get("authorization"))
			}
			if err := json.NewDecoder(r.Body).Decode(&recoveryCreateBody); err != nil {
				t.Fatal(err)
			}
			recipientID, _ := recoveryCreateBody["recipientId"].(string)
			publicKey, _ := recoveryCreateBody["publicKey"].(string)
			fingerprint, _ := recoveryCreateBody["publicKeyFingerprint"].(string)
			if recoveryCreateBody["orgId"] != "org_recovery" || !strings.HasPrefix(recipientID, "rec_") || publicKey == "" || fingerprint == "" {
				t.Fatalf("unexpected recovery recipient registration body: %#v", recoveryCreateBody)
			}
			if _, ok := recoveryCreateBody["key"]; ok {
				t.Fatalf("registration body should not include raw key: %#v", recoveryCreateBody)
			}
			replacements, ok := recoveryCreateBody["replacements"].([]any)
			if !ok || len(replacements) != 1 {
				t.Fatalf("expected one recovery replacement: %#v", recoveryCreateBody["replacements"])
			}
			replacement, _ := replacements[0].(map[string]any)
			wrapped, _ := replacement["wrappedKey"].(map[string]any)
			if wrapped["recipientType"] != "recovery" || wrapped["wrapAlgorithm"] != "recovery-hkdf-aes256gcm" || !strings.HasPrefix(fmt.Sprint(wrapped["recipientId"]), "rec_") {
				t.Fatalf("unexpected recovery wrapped key: %#v", wrapped)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"recipientId":          recoveryCreateBody["recipientId"],
				"publicKeyFingerprint": recoveryCreateBody["publicKeyFingerprint"],
				"status":               "active",
			})
		case "/v1/devices":
			_ = json.NewEncoder(w).Encode(map[string]any{"devices": []map[string]any{}})
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
	} {
		out.Reset()
		errb.Reset()
		if code := app.Run(step); code != 0 {
			t.Fatalf("%v failed with code %d stderr=%s", step, code, errb.String())
		}
	}
	out.Reset()
	errb.Reset()
	recoveryKeyPath := filepath.Join(tmp, "recovery.key")
	if code := app.Run([]string{"recovery", "setup", "--workspace", "oclan-co", "--output-file", recoveryKeyPath}); code != 0 {
		t.Fatalf("recovery setup failed: %s", errb.String())
	}
	if !secretPushSeen || !recoveryCreateSeen {
		t.Fatal("expected push and recovery create endpoints")
	}
	all := out.String()
	if !strings.Contains(all, "Recovery key written") || !strings.Contains(all, "Added recovery wrapping to 1 remote secret") {
		t.Fatalf("recovery output missing expected copy or wrapping result: %s", all)
	}
	keyBytes, err := os.ReadFile(recoveryKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	recoveryKey := strings.TrimSpace(string(keyBytes))
	if recoveryKey == "" {
		t.Fatalf("recovery setup did not write a recovery key: %s", all)
	}
	if strings.Contains(all, recoveryKey) {
		t.Fatal("recovery setup printed raw recovery key")
	}
	if strings.Contains(fmt.Sprint(recoveryCreateBody), recoveryKey) {
		t.Fatal("recovery registration sent raw recovery key")
	}
	bytes, err := os.ReadFile(filepath.Join(tmp, "local-state.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(bytes), recoveryKey) {
		t.Fatal("local state persisted raw recovery key")
	}
}

func TestRecoverySetupFreshLinkedWorkspaceSendsEmptyReplacements(t *testing.T) {
	tmp := t.TempDir()
	old := os.Getenv("ASIRI_HOME")
	t.Cleanup(func() { _ = os.Setenv("ASIRI_HOME", old) })
	if err := os.Setenv("ASIRI_HOME", tmp); err != nil {
		t.Fatal(err)
	}
	recoveryCreateSeen := false
	remoteSecretListSeen := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		switch r.URL.Path {
		case "/v1/auth/device-code/start":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"deviceCode":              "dc_empty_recovery",
				"userCode":                "RNEW-1234",
				"verificationUriComplete": serverURL(r) + "/auth/device?code=RNEW-1234",
				"expiresIn":               30,
				"interval":                0,
			})
		case "/v1/auth/device-code/token":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status":           "approved",
				"orgId":            "org_empty_recovery",
				"workspaceSlug":    "oclan-co",
				"userId":           "usr_owner",
				"deviceId":         "dev_empty_recovery",
				"accessToken":      "at_empty_recovery",
				"refreshToken":     "rt_empty_recovery",
				"expiresIn":        3600,
				"refreshExpiresAt": time.Now().UTC().Add(7 * 24 * time.Hour).Format(time.RFC3339),
			})
		case "/v1/secrets/encrypted":
			remoteSecretListSeen = true
			_ = json.NewEncoder(w).Encode(map[string]any{"secrets": []map[string]any{}})
		case "/v1/recovery-recipient":
			if r.Method == http.MethodGet {
				http.NotFound(w, r)
				return
			}
			if r.Method != http.MethodPost {
				http.NotFound(w, r)
				return
			}
			recoveryCreateSeen = true
			if r.Header.Get("authorization") != "Bearer at_empty_recovery" {
				t.Fatalf("unexpected recovery recipient auth header: %s", r.Header.Get("authorization"))
			}
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			replacements, ok := body["replacements"].([]any)
			if !ok || len(replacements) != 0 {
				t.Fatalf("fresh workspace should send empty recovery replacements array: %#v", body["replacements"])
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"recipientId":          body["recipientId"],
				"publicKeyFingerprint": body["publicKeyFingerprint"],
				"status":               "active",
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
	staleStore, err := store.Load(filepath.Join(tmp, "local-state.json"))
	if err != nil {
		t.Fatal(err)
	}
	staleSetup, err := staleStore.SetupRecovery(false)
	if err != nil {
		t.Fatal(err)
	}
	if err := staleStore.Save(); err != nil {
		t.Fatal(err)
	}
	recoveryKeyPath := filepath.Join(tmp, "recovery.key")
	out.Reset()
	errb.Reset()
	if code := app.Run([]string{"recovery", "setup", "--workspace", "oclan-co", "--output-file", recoveryKeyPath}); code != 0 {
		t.Fatalf("fresh workspace recovery setup failed: %s", errb.String())
	}
	if !recoveryCreateSeen {
		t.Fatal("expected recovery create endpoint")
	}
	if remoteSecretListSeen {
		t.Fatal("fresh workspace without a remote binding should not list remote secrets")
	}
	if keyBytes, err := os.ReadFile(recoveryKeyPath); err != nil {
		t.Fatal(err)
	} else if strings.TrimSpace(string(keyBytes)) == "" {
		t.Fatal("recovery setup should write the recovery key")
	}
	st, err := store.Load(filepath.Join(tmp, "local-state.json"))
	if err != nil {
		t.Fatal(err)
	}
	if recovery := st.ActiveRecovery(); recovery == nil {
		t.Fatal("fresh workspace recovery setup should commit local recovery metadata")
	} else if recovery.RecipientID == staleSetup.RecipientID {
		t.Fatal("fresh workspace recovery setup should replace stale local recovery metadata after server success")
	}
}

func TestRecoveryStatusPreservesSameRecipientLocalWrappingCounters(t *testing.T) {
	tmp := t.TempDir()
	old := os.Getenv("ASIRI_HOME")
	t.Cleanup(func() { _ = os.Setenv("ASIRI_HOME", old) })
	if err := os.Setenv("ASIRI_HOME", tmp); err != nil {
		t.Fatal(err)
	}
	var activeRecovery *asiri.RecoveryConfig
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		switch r.URL.Path {
		case "/v1/auth/device-code/start":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"deviceCode":              "dc_status_recovery",
				"userCode":                "RSTS-1234",
				"verificationUriComplete": serverURL(r) + "/auth/device?code=RSTS-1234",
				"expiresIn":               30,
				"interval":                0,
			})
		case "/v1/auth/device-code/token":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status":           "approved",
				"orgId":            "org_status_recovery",
				"workspaceSlug":    "oclan-co",
				"userId":           "usr_owner",
				"deviceId":         "dev_status_recovery",
				"accessToken":      "at_status_recovery",
				"refreshToken":     "rt_status_recovery",
				"expiresIn":        3600,
				"refreshExpiresAt": time.Now().UTC().Add(7 * 24 * time.Hour).Format(time.RFC3339),
			})
		case "/v1/orgs":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"activeOrgId": "org_status_recovery",
				"organizations": []map[string]any{
					{"id": "org_status_recovery", "name": "O Clan", "slug": "oclan-co", "ownerUserId": "usr_owner", "role": "owner", "canPull": true, "canWrite": true},
				},
			})
		case "/v1/recovery-recipient":
			if r.Method != http.MethodGet {
				http.NotFound(w, r)
				return
			}
			if r.Header.Get("authorization") != "Bearer at_status_recovery" {
				t.Fatalf("unexpected recovery status auth header: %s", r.Header.Get("authorization"))
			}
			if activeRecovery == nil {
				http.NotFound(w, r)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"recipientId":          activeRecovery.RecipientID,
				"publicKey":            activeRecovery.PublicKey,
				"publicKeyFingerprint": activeRecovery.PublicKeyFingerprint,
				"status":               "active",
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
	st, err := store.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.SetupRecovery(false); err != nil {
		t.Fatal(err)
	}
	if err := st.Save(); err != nil {
		t.Fatal(err)
	}
	if err := st.MarkRecoveryWrapped("oclan-co", 3); err != nil {
		t.Fatal(err)
	}
	recovery := st.ActiveRecovery()
	if recovery == nil {
		t.Fatal("expected local recovery metadata")
	}
	activeRecovery = recovery

	out.Reset()
	errb.Reset()
	if code := app.Run([]string{"recovery", "status"}); code != 0 {
		t.Fatalf("recovery status failed: %s", errb.String())
	}
	statusFields := strings.Fields(out.String())
	if !strings.Contains(out.String(), "oclan-co") || !strings.Contains(out.String(), "configured") || !containsString(statusFields, "3") {
		t.Fatalf("recovery status should preserve local wrapping count, got: %s", out.String())
	}
	reloaded, err := store.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	if count := reloaded.RecoveryWrappedCountForPrefix("oclan-co"); count != 3 {
		t.Fatalf("recovery status should persist local wrapping count, got %d", count)
	}
}

func TestTargetedPushPreservesRecoveryWrappedCount(t *testing.T) {
	tmp := t.TempDir()
	old := os.Getenv("ASIRI_HOME")
	t.Cleanup(func() { _ = os.Setenv("ASIRI_HOME", old) })
	if err := os.Setenv("ASIRI_HOME", tmp); err != nil {
		t.Fatal(err)
	}
	var activeRecovery *asiri.RecoveryConfig
	pushSeen := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		switch r.URL.Path {
		case "/v1/auth/device-code/start":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"deviceCode":              "dc_targeted_push",
				"userCode":                "TPUS-1234",
				"verificationUriComplete": serverURL(r) + "/auth/device?code=TPUS-1234",
				"expiresIn":               30,
				"interval":                0,
			})
		case "/v1/auth/device-code/token":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status":           "approved",
				"orgId":            "org_targeted_push",
				"workspaceSlug":    "oclan-co",
				"userId":           "usr_owner",
				"deviceId":         "dev_targeted_push",
				"accessToken":      "at_targeted_push",
				"refreshToken":     "rt_targeted_push",
				"expiresIn":        3600,
				"refreshExpiresAt": time.Now().UTC().Add(7 * 24 * time.Hour).Format(time.RFC3339),
			})
		case "/v1/orgs":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"activeOrgId": "org_targeted_push",
				"organizations": []map[string]any{
					{"id": "org_targeted_push", "name": "O Clan", "slug": "oclan-co", "ownerUserId": "usr_owner", "role": "owner", "canPull": true, "canWrite": true},
				},
			})
		case "/v1/sync/write-options":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"requestedWorkspaceSlug": "oclan-co",
				"activeWorkspace": map[string]any{
					"id":       "org_targeted_push",
					"slug":     "oclan-co",
					"canWrite": true,
					"paths": []map[string]any{{
						"fullPath": "oclan-co/local/asiri/API_KEY",
						"canWrite": true,
					}},
				},
			})
		case "/v1/recovery-recipient":
			if activeRecovery == nil {
				http.NotFound(w, r)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"recipientId":          activeRecovery.RecipientID,
				"publicKey":            activeRecovery.PublicKey,
				"publicKeyFingerprint": activeRecovery.PublicKeyFingerprint,
				"status":               "active",
			})
		case "/v1/devices":
			_ = json.NewEncoder(w).Encode(map[string]any{"devices": []map[string]any{}})
		case "/v1/secrets/encrypted":
			if activeRecovery == nil || r.URL.Query().Get("recoveryRecipientId") != activeRecovery.RecipientID {
				t.Fatalf("targeted push should request recovery-wrapped remote state, got query %s", r.URL.RawQuery)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"secrets": []map[string]any{}})
		case "/v1/secrets":
			if r.Method != http.MethodPost {
				http.NotFound(w, r)
				return
			}
			pushSeen++
			_ = json.NewEncoder(w).Encode(map[string]any{"id": "secv_targeted_push", "status": "active"})
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
		{"add", "--workspace", "oclan-co", "prod/asiri/OTHER_KEY", "--value-file", testSecretFile(t, "other_value")},
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
	if _, err := st.SetupRecovery(false); err != nil {
		t.Fatal(err)
	}
	if err := st.Save(); err != nil {
		t.Fatal(err)
	}
	if err := st.MarkRecoveryWrapped("oclan-co", 3); err != nil {
		t.Fatal(err)
	}
	activeRecovery = st.ActiveRecovery()
	out.Reset()
	errb.Reset()
	if code := app.Run([]string{"push", "--workspace", "oclan-co", "--secret", "local/asiri/API_KEY"}); code != 0 {
		t.Fatalf("targeted push failed: %s", errb.String())
	}
	if pushSeen == 0 {
		t.Fatal("expected targeted push to upload selected secret")
	}
	reloaded, err := store.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	if count := reloaded.RecoveryWrappedCountForPrefix("oclan-co"); count != 3 {
		t.Fatalf("targeted push should preserve existing recovery wrapped count, got %d", count)
	}
	resetRecovery := reloaded.State.Recoveries["org_targeted_push"]
	resetRecovery.WrappedSecretCount = 0
	resetRecovery.LastWrappedAt = time.Time{}
	reloaded.State.Recoveries["org_targeted_push"] = resetRecovery
	if err := reloaded.Save(); err != nil {
		t.Fatal(err)
	}
	activeRecovery = &resetRecovery
	out.Reset()
	errb.Reset()
	if code := app.Run([]string{"push", "--workspace", "oclan-co", "--secret", "prod/asiri/OTHER_KEY"}); code != 0 {
		t.Fatalf("first targeted push failed: %s", errb.String())
	}
	reloaded, err = store.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	if count := reloaded.RecoveryWrappedCountForPrefix("oclan-co"); count != 1 {
		t.Fatalf("first targeted push should record selected recovery wrapped count, got %d", count)
	}
}

func TestRecoverySetupSkipsWrappingWhenRemoteRegistrationFails(t *testing.T) {
	tmp := t.TempDir()
	old := os.Getenv("ASIRI_HOME")
	t.Cleanup(func() { _ = os.Setenv("ASIRI_HOME", old) })
	if err := os.Setenv("ASIRI_HOME", tmp); err != nil {
		t.Fatal(err)
	}
	recoveryCreateSeen := false
	var pushedSecret map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		switch r.URL.Path {
		case "/v1/auth/device-code/start":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"deviceCode":              "dc_recovery_registration_fail",
				"userCode":                "RFAIL-1234",
				"verificationUriComplete": serverURL(r) + "/auth/device?code=RFAIL-1234",
				"expiresIn":               30,
				"interval":                0,
			})
		case "/v1/auth/device-code/token":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status":           "approved",
				"orgId":            "org_recovery",
				"workspaceSlug":    "oclan-co",
				"userId":           "usr_owner",
				"deviceId":         "dev_recovery",
				"accessToken":      "at_recovery",
				"refreshToken":     "rt_recovery",
				"expiresIn":        3600,
				"refreshExpiresAt": time.Now().UTC().Add(7 * 24 * time.Hour).Format(time.RFC3339),
			})
		case "/v1/sync/write-options":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"requestedWorkspaceSlug": "oclan-co",
				"activeWorkspace": map[string]any{
					"id":       "org_recovery",
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
				if err := json.NewDecoder(r.Body).Decode(&pushedSecret); err != nil {
					t.Fatal(err)
				}
				pushedSecret["id"] = "secv_recovery"
				pushedSecret["status"] = "active"
				_ = json.NewEncoder(w).Encode(map[string]any{"id": "secv_recovery", "status": "active"})
				return
			}
			http.NotFound(w, r)
		case "/v1/secrets/encrypted":
			if pushedSecret == nil {
				_ = json.NewEncoder(w).Encode(map[string]any{"secrets": []map[string]any{}})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"secrets": []map[string]any{pushedSecret}})
		case "/v1/devices":
			_ = json.NewEncoder(w).Encode(map[string]any{"devices": []map[string]any{}})
		case "/v1/recovery-recipient":
			if r.Method == http.MethodGet {
				http.NotFound(w, r)
				return
			}
			if r.Method != http.MethodPost {
				http.NotFound(w, r)
				return
			}
			recoveryCreateSeen = true
			http.Error(w, `{"error":"owner required"}`, http.StatusForbidden)
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
	} {
		out.Reset()
		errb.Reset()
		if code := app.Run(step); code != 0 {
			t.Fatalf("%v failed with code %d stderr=%s", step, code, errb.String())
		}
	}
	out.Reset()
	errb.Reset()
	recoveryKeyPath := filepath.Join(tmp, "recovery.key")
	if code := app.Run([]string{"recovery", "setup", "--workspace", "oclan-co", "--output-file", recoveryKeyPath}); code == 0 {
		t.Fatal("recovery setup should fail when remote registration fails")
	}
	if !recoveryCreateSeen {
		t.Fatal("expected recovery registration endpoint")
	}
	if !strings.Contains(errb.String(), "recovery key delivered, but remote registration failed") {
		t.Fatalf("expected registration failure warning, got %s", errb.String())
	}
	if keyBytes, err := os.ReadFile(recoveryKeyPath); err != nil {
		t.Fatal(err)
	} else if strings.TrimSpace(string(keyBytes)) == "" {
		t.Fatal("recovery key should remain available after delivery")
	}
	st, err := store.Load(filepath.Join(tmp, "local-state.json"))
	if err != nil {
		t.Fatal(err)
	}
	if st.ActiveRecovery() != nil {
		t.Fatalf("local recovery config should not be active after remote registration failure: %#v", st.State.Recoveries)
	}
}

func TestRecoverySetupFailsWhenRemoteReplacementFails(t *testing.T) {
	tmp := t.TempDir()
	old := os.Getenv("ASIRI_HOME")
	t.Cleanup(func() { _ = os.Setenv("ASIRI_HOME", old) })
	if err := os.Setenv("ASIRI_HOME", tmp); err != nil {
		t.Fatal(err)
	}
	recoveryReplaceSeen := false
	remoteRecoveryActive := false
	var pushedSecret map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		switch r.URL.Path {
		case "/v1/auth/device-code/start":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"deviceCode":              "dc_recovery_wrap_fail",
				"userCode":                "RWFL-1234",
				"verificationUriComplete": serverURL(r) + "/auth/device?code=RWFL-1234",
				"expiresIn":               30,
				"interval":                0,
			})
		case "/v1/auth/device-code/token":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status":           "approved",
				"orgId":            "org_recovery",
				"workspaceSlug":    "oclan-co",
				"userId":           "usr_owner",
				"deviceId":         "dev_recovery",
				"accessToken":      "at_recovery",
				"refreshToken":     "rt_recovery",
				"expiresIn":        3600,
				"refreshExpiresAt": time.Now().UTC().Add(7 * 24 * time.Hour).Format(time.RFC3339),
			})
		case "/v1/sync/write-options":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"requestedWorkspaceSlug": "oclan-co",
				"activeWorkspace": map[string]any{
					"id":       "org_recovery",
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
				if err := json.NewDecoder(r.Body).Decode(&pushedSecret); err != nil {
					t.Fatal(err)
				}
				pushedSecret["id"] = "secv_recovery"
				pushedSecret["status"] = "active"
				_ = json.NewEncoder(w).Encode(map[string]any{"id": "secv_recovery", "status": "active"})
				return
			}
			http.NotFound(w, r)
		case "/v1/secrets/encrypted":
			if pushedSecret == nil {
				_ = json.NewEncoder(w).Encode(map[string]any{"secrets": []map[string]any{}})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"secrets": []map[string]any{pushedSecret}})
		case "/v1/devices":
			_ = json.NewEncoder(w).Encode(map[string]any{"devices": []map[string]any{}})
		case "/v1/recovery-recipient":
			if r.Method != http.MethodGet || !remoteRecoveryActive {
				http.NotFound(w, r)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"recipientId":          "rec_existing",
				"publicKey":            "remote-public-key",
				"publicKeyFingerprint": "remote-fingerprint",
				"status":               "active",
			})
		case "/v1/recovery-recipient/replace":
			recoveryReplaceSeen = true
			http.Error(w, `{"error":"replacement failed"}`, http.StatusInternalServerError)
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
	} {
		out.Reset()
		errb.Reset()
		if code := app.Run(step); code != 0 {
			t.Fatalf("%v failed with code %d stderr=%s", step, code, errb.String())
		}
	}
	remoteRecoveryActive = true
	out.Reset()
	errb.Reset()
	recoveryKeyPath := filepath.Join(tmp, "recovery.key")
	if code := app.Run([]string{"recovery", "setup", "--workspace", "oclan-co", "--force", "--output-file", recoveryKeyPath}); code == 0 {
		t.Fatal("recovery setup should fail when remote replacement fails")
	}
	if !recoveryReplaceSeen {
		t.Fatal("expected recovery replacement endpoint")
	}
	if !strings.Contains(errb.String(), "recovery key delivered, but remote replacement failed") {
		t.Fatalf("expected replacement failure, got %s", errb.String())
	}
	if keyBytes, err := os.ReadFile(recoveryKeyPath); err != nil {
		t.Fatal(err)
	} else if strings.TrimSpace(string(keyBytes)) == "" {
		t.Fatal("recovery key should remain available after delivery")
	}
	st, err := store.Load(filepath.Join(tmp, "local-state.json"))
	if err != nil {
		t.Fatal(err)
	}
	if st.ActiveRecovery() != nil {
		t.Fatalf("local recovery config should not be active after remote wrapping failure: %#v", st.State.Recoveries)
	}
}

func TestRecoverySetupForceCommitsWhenPreviousRecipientIsRetired(t *testing.T) {
	tmp := t.TempDir()
	old := os.Getenv("ASIRI_HOME")
	t.Cleanup(func() { _ = os.Setenv("ASIRI_HOME", old) })
	if err := os.Setenv("ASIRI_HOME", tmp); err != nil {
		t.Fatal(err)
	}
	var registeredRecipients []string
	replacementCount := 0
	staleRecoveryListRejected := false
	unscopedRecoveryListSeen := false
	var pushedSecret map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		switch r.URL.Path {
		case "/v1/auth/device-code/start":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"deviceCode":              "dc_recovery_force",
				"userCode":                "RFOR-1234",
				"verificationUriComplete": serverURL(r) + "/auth/device?code=RFOR-1234",
				"expiresIn":               30,
				"interval":                0,
			})
		case "/v1/auth/device-code/token":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status":           "approved",
				"orgId":            "org_recovery",
				"workspaceSlug":    "oclan-co",
				"userId":           "usr_owner",
				"deviceId":         "dev_recovery",
				"accessToken":      "at_recovery",
				"refreshToken":     "rt_recovery",
				"expiresIn":        3600,
				"refreshExpiresAt": time.Now().UTC().Add(7 * 24 * time.Hour).Format(time.RFC3339),
			})
		case "/v1/sync/write-options":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"requestedWorkspaceSlug": "oclan-co",
				"activeWorkspace": map[string]any{
					"id":       "org_recovery",
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
				if err := json.NewDecoder(r.Body).Decode(&pushedSecret); err != nil {
					t.Fatal(err)
				}
				pushedSecret["id"] = "secv_recovery"
				pushedSecret["status"] = "active"
				_ = json.NewEncoder(w).Encode(map[string]any{"id": "secv_recovery", "status": "active"})
				return
			}
			http.NotFound(w, r)
		case "/v1/recovery-recipient":
			if r.Method == http.MethodGet {
				if len(registeredRecipients) == 0 {
					http.NotFound(w, r)
					return
				}
				_ = json.NewEncoder(w).Encode(map[string]any{
					"recipientId":          registeredRecipients[len(registeredRecipients)-1],
					"publicKey":            "remote-public-key",
					"publicKeyFingerprint": "remote-fingerprint",
					"status":               "active",
				})
				return
			}
			if r.Method != http.MethodPost {
				http.NotFound(w, r)
				return
			}
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			recipientID, _ := body["recipientId"].(string)
			registeredRecipients = append(registeredRecipients, recipientID)
			replacements, ok := body["replacements"].([]any)
			if !ok || len(replacements) != 1 {
				t.Fatalf("expected one replacement in initial setup: %#v", body["replacements"])
			}
			replacementCount += 1
			_ = json.NewEncoder(w).Encode(map[string]any{
				"recipientId":          recipientID,
				"publicKeyFingerprint": body["publicKeyFingerprint"],
				"status":               "active",
			})
		case "/v1/recovery-recipient/replace":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			recipientID, _ := body["recipientId"].(string)
			registeredRecipients = append(registeredRecipients, recipientID)
			replacements, ok := body["replacements"].([]any)
			if !ok || len(replacements) != 1 {
				t.Fatalf("expected one replacement in forced setup: %#v", body["replacements"])
			}
			replacementCount += 1
			_ = json.NewEncoder(w).Encode(map[string]any{
				"recipientId":          recipientID,
				"publicKeyFingerprint": body["publicKeyFingerprint"],
				"status":               "active",
			})
		case "/v1/secrets/encrypted":
			if r.URL.Query().Get("orgId") != "org_recovery" {
				t.Fatalf("unexpected secrets query: %s", r.URL.RawQuery)
			}
			recoveryRecipientID := r.URL.Query().Get("recoveryRecipientId")
			if len(registeredRecipients) >= 1 && recoveryRecipientID == registeredRecipients[0] {
				staleRecoveryListRejected = true
				http.Error(w, `{"error":"recovery recipient is not registered for this workspace"}`, http.StatusForbidden)
				return
			}
			if len(registeredRecipients) >= 1 && recoveryRecipientID == "" {
				unscopedRecoveryListSeen = true
			}
			if pushedSecret == nil {
				_ = json.NewEncoder(w).Encode(map[string]any{"secrets": []map[string]any{}})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"secrets": []map[string]any{pushedSecret}})
		case "/v1/devices":
			_ = json.NewEncoder(w).Encode(map[string]any{"devices": []map[string]any{}})
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
	} {
		out.Reset()
		errb.Reset()
		if code := app.Run(step); code != 0 {
			t.Fatalf("%v failed with code %d stderr=%s", step, code, errb.String())
		}
	}
	for _, step := range [][]string{
		{"recovery", "setup", "--workspace", "oclan-co", "--output-file", filepath.Join(tmp, "recovery-1.key")},
		{"recovery", "setup", "--workspace", "oclan-co", "--force", "--output-file", filepath.Join(tmp, "recovery-2.key")},
	} {
		out.Reset()
		errb.Reset()
		if code := app.Run(step); code != 0 {
			t.Fatalf("%v failed with code %d stderr=%s", step, code, errb.String())
		}
	}
	if len(registeredRecipients) != 2 || registeredRecipients[0] == registeredRecipients[1] {
		t.Fatalf("expected two distinct recovery registrations: %#v", registeredRecipients)
	}
	if replacementCount != 2 {
		t.Fatalf("expected both setup runs to replace recovery wrapping, got %d", replacementCount)
	}
	if !staleRecoveryListRejected || !unscopedRecoveryListSeen {
		t.Fatalf("forced setup should fall back after stale recovery recipient rejection, rejected=%v unscoped=%v", staleRecoveryListRejected, unscopedRecoveryListSeen)
	}
	st, err := store.Load(filepath.Join(tmp, "local-state.json"))
	if err != nil {
		t.Fatal(err)
	}
	if recovery := st.ActiveRecovery(); recovery == nil || recovery.RecipientID != registeredRecipients[1] {
		t.Fatalf("forced replacement should commit the new local recovery config: %#v", st.State.Recoveries)
	}
}

func TestRecoveryRestoreUsesSuppliedKeyWhenLocalMetadataIsStale(t *testing.T) {
	tmp := t.TempDir()
	old := os.Getenv("ASIRI_HOME")
	t.Cleanup(func() { _ = os.Setenv("ASIRI_HOME", old) })
	if err := os.Setenv("ASIRI_HOME", tmp); err != nil {
		t.Fatal(err)
	}
	remoteListSeen := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		switch r.URL.Path {
		case "/v1/auth/device-code/start":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"deviceCode":              "dc_recovery_restore",
				"userCode":                "REST-1234",
				"verificationUriComplete": serverURL(r) + "/auth/device?code=REST-1234",
				"expiresIn":               30,
				"interval":                0,
			})
		case "/v1/auth/device-code/token":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status":           "approved",
				"orgId":            "org_recovery",
				"workspaceSlug":    "oclan-co",
				"userId":           "usr_owner",
				"deviceId":         "dev_recovery",
				"accessToken":      "at_recovery",
				"refreshToken":     "rt_recovery",
				"expiresIn":        3600,
				"refreshExpiresAt": time.Now().UTC().Add(7 * 24 * time.Hour).Format(time.RFC3339),
			})
		case "/v1/secrets/encrypted":
			remoteListSeen = true
			if got := r.URL.Query().Get("recoveryRecipientId"); !strings.HasPrefix(got, "rec_") {
				t.Fatalf("restore should list by supplied recovery key identity, got %q", got)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"secrets": []any{}})
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
	st, err := store.Load(filepath.Join(tmp, "local-state.json"))
	if err != nil {
		t.Fatal(err)
	}
	oldSetup, err := st.SetupRecovery(false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.SetupRecovery(true); err != nil {
		t.Fatal(err)
	}
	if err := st.Save(); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(tmp, "old-recovery.key")
	if err := os.WriteFile(keyPath, []byte(oldSetup.Key+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	errb.Reset()
	if code := app.Run([]string{"recovery", "restore", "--workspace", "oclan-co", "--key-file", keyPath}); code != 0 {
		t.Fatalf("restore should let the server decide whether the supplied key is active: %s", errb.String())
	}
	if !remoteListSeen {
		t.Fatal("restore should ask the server about the supplied recovery key")
	}
	if !strings.Contains(out.String(), "No remote active secrets to restore") {
		t.Fatalf("unexpected restore output: %s", out.String())
	}
	st, err = store.Load(filepath.Join(tmp, "local-state.json"))
	if err != nil {
		t.Fatal(err)
	}
	if recovery := st.ActiveRecovery(); recovery == nil || recovery.RecipientID != oldSetup.RecipientID {
		t.Fatalf("restore should refresh local recovery metadata from the supplied key: %#v", st.State.Recoveries)
	}
}

func TestRecoverySetupDoesNotPersistWhenKeyDeliveryFails(t *testing.T) {
	tmp := t.TempDir()
	old := os.Getenv("ASIRI_HOME")
	t.Cleanup(func() { _ = os.Setenv("ASIRI_HOME", old) })
	if err := os.Setenv("ASIRI_HOME", tmp); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	app := New(&out, &errb)
	remoteReplacementSeen := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		switch r.URL.Path {
		case "/v1/auth/device-code/start":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"deviceCode":              "dc_recovery_fail",
				"userCode":                "FAIL-1234",
				"verificationUriComplete": serverURL(r) + "/auth/device?code=FAIL-1234",
				"expiresIn":               30,
				"interval":                0,
			})
		case "/v1/auth/device-code/token":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status":           "approved",
				"orgId":            "org_recovery",
				"workspaceSlug":    "oclan-co",
				"userId":           "usr_owner",
				"deviceId":         "dev_recovery",
				"accessToken":      "at_recovery",
				"refreshToken":     "rt_recovery",
				"expiresIn":        3600,
				"refreshExpiresAt": time.Now().UTC().Add(7 * 24 * time.Hour).Format(time.RFC3339),
			})
		case "/v1/secrets/encrypted":
			_ = json.NewEncoder(w).Encode(map[string]any{"secrets": []map[string]any{}})
		case "/v1/recovery-recipient/replace":
			remoteReplacementSeen = true
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "active"})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	for _, step := range [][]string{
		{"init", "--device", "qa-laptop"},
		{"login", "--origin", server.URL},
	} {
		out.Reset()
		errb.Reset()
		if code := app.Run(step); code != 0 {
			t.Fatalf("%v failed: %s", step, errb.String())
		}
	}
	existingKeyPath := filepath.Join(tmp, "recovery.key")
	if err := os.WriteFile(existingKeyPath, []byte("existing\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	errb.Reset()
	if code := app.Run([]string{"recovery", "setup", "--workspace", "oclan-co", "--output-file", existingKeyPath}); code == 0 {
		t.Fatal("recovery setup should fail when key output cannot be created")
	}
	if remoteReplacementSeen {
		t.Fatal("remote recovery replacement should not run when key delivery fails")
	}
	st, err := store.Load(filepath.Join(tmp, "local-state.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(st.State.Recoveries) != 0 {
		t.Fatalf("workspace recovery config persisted after key delivery failure: %#v", st.State.Recoveries)
	}
}

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
				"activeWorkspace": map[string]any{
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

func TestPushListsWritableAlternativesWhenActiveWorkspaceCannotWrite(t *testing.T) {
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
		case "/v1/sync/write-options":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"requestedWorkspaceSlug": "oclan-co",
				"activeWorkspace": map[string]any{
					"id":       "org_oclan",
					"slug":     "oclan-co",
					"canWrite": false,
					"paths": []map[string]any{{
						"fullPath": "oclan-co/recipe-app/API_KEY",
						"canWrite": false,
					}},
				},
				"writableWorkspaces": []map[string]any{{
					"id":       "org_personal",
					"slug":     "peter-dev",
					"canWrite": true,
					"paths": []map[string]any{{
						"fullPath": "peter-dev/recipe-app/API_KEY",
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
				"activeWorkspace": map[string]any{
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

func TestListMergesActiveWorkspaceRemoteSecrets(t *testing.T) {
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
				"organizations": []map[string]any{{"id": "org_oclan", "slug": "oclan-co", "role": "owner", "canPull": true, "canWrite": true}},
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
	if code := app.Run([]string{"list"}); code != 0 {
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
	if code := app.Run([]string{"list", "--include-inactive"}); code != 0 {
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
	if code := app.Run([]string{"list", "--local"}); code != 0 {
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
	if code := app.Run([]string{"list", "--local"}); code != 0 {
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
			if r.URL.Query().Get("includeSecrets") != "1" {
				t.Fatalf("list actions should request remote secret metadata, got %s", r.URL.RawQuery)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"activeOrgId":   "org_oclan",
				"organizations": []map[string]any{{"id": "org_oclan", "slug": "oclan-co", "role": "owner", "canPull": true, "canWrite": true}},
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
	if code := app.Run([]string{"list"}); code != 0 {
		t.Fatalf("list failed: %s", errb.String())
	}
	all := out.String()
	for _, expected := range []string{
		"LOCAL_NEEDS_REWRAP", "synced,writable", "needs rewrap",
		"REMOTE_ONLY_UNWRAPPED", "remote-only,writable", "unwrapped",
		"REMOTE_NOT_TRUSTED", "remote-only,writable", "not trusted",
		"Next:",
		"run asiri rewrap --workspace oclan-co here",
		"run asiri rewrap --workspace oclan-co on a device where these secrets are wrapped, then run asiri pull --workspace oclan-co here",
		"run asiri device trust --workspace asiri-dev before pulling",
	} {
		if !strings.Contains(all, expected) {
			t.Fatalf("list output missing %q: %s", expected, all)
		}
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
			if r.Header.Get("authorization") != "Bearer at_delete" {
				t.Fatalf("unexpected workspace overview auth header: %s", r.Header.Get("authorization"))
			}
			if r.URL.Query().Get("includeSecrets") != "1" {
				_ = json.NewEncoder(w).Encode(map[string]any{
					"activeOrgId":   "org_oclan",
					"organizations": []map[string]any{{"id": "org_oclan", "slug": "oclan-co", "role": "owner", "canPull": true, "canWrite": true}},
				})
				return
			}
			workspaceOverviewSeen = true
			_ = json.NewEncoder(w).Encode(map[string]any{
				"activeOrgId":   "org_oclan",
				"organizations": []map[string]any{{"id": "org_oclan", "slug": "oclan-co", "role": "owner", "canPull": true, "canWrite": true}},
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
			if body["createdByDeviceId"] != "dev_oclan" || body["version"] != float64(2) {
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
			if body["createdByDeviceId"] != "dev_oclan" {
				t.Fatalf("delete request used wrong device id: %#v", body)
			}
			if body["version"] != float64(2) {
				t.Fatalf("delete request used wrong version: %#v", body)
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
		{"init", "--device", "qa-laptop"},
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
			if r.URL.Query().Get("includeSecrets") != "1" {
				_ = json.NewEncoder(w).Encode(map[string]any{
					"activeOrgId":   "org_oclan",
					"organizations": []map[string]any{{"id": "org_oclan", "slug": "oclan-co", "role": "owner", "canPull": true, "canWrite": true}},
				})
				return
			}
			overviewCount++
			_ = json.NewEncoder(w).Encode(map[string]any{
				"activeOrgId":   "org_oclan",
				"organizations": []map[string]any{{"id": "org_oclan", "slug": "oclan-co", "role": "owner", "canPull": true, "canWrite": true}},
				"secrets": []map[string]any{
					{"id": "sec_confirm", "orgId": "org_oclan", "workspaceSlug": "oclan-co", "scope": "oclan-co/local/asiri", "name": "PUSHED", "version": 1, "status": "active", "canWrite": true},
				},
			})
		case "/v1/secrets/sec_confirm/delete":
			deleteCount++
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
			if r.URL.Query().Get("includeSecrets") != "1" {
				_ = json.NewEncoder(w).Encode(map[string]any{
					"activeOrgId":   "org_oclan",
					"organizations": []map[string]any{{"id": "org_oclan", "slug": "oclan-co", "role": "owner", "canPull": true, "canWrite": true}},
				})
				return
			}
			if r.URL.Query().Get("includeInactive") != "1" {
				t.Fatalf("restore lookup should include inactive secrets: %s", r.URL.RawQuery)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"activeOrgId":   "org_oclan",
				"organizations": []map[string]any{{"id": "org_oclan", "slug": "oclan-co", "role": "owner", "canPull": true, "canWrite": true}},
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
			if body["createdByDeviceId"] != "dev_oclan" || body["version"] != float64(2) {
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
							"organizations": []map[string]any{{"id": "org_oclan", "slug": "oclan-co", "role": "owner", "canPull": true, "canWrite": true}},
						})
						return
					}
					_ = json.NewEncoder(w).Encode(map[string]any{
						"activeOrgId":   "org_oclan",
						"organizations": []map[string]any{{"id": "org_oclan", "slug": "oclan-co", "role": "owner", "canPull": true, "canWrite": true}},
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
			if r.URL.Query().Get("includeSecrets") != "1" {
				_ = json.NewEncoder(w).Encode(map[string]any{
					"activeOrgId":   "org_oclan",
					"organizations": []map[string]any{{"id": "org_oclan", "slug": "oclan-co", "role": "owner", "canPull": true, "canWrite": true}},
				})
				return
			}
			wrapped := true
			unwrapped := false
			_ = json.NewEncoder(w).Encode(map[string]any{
				"activeOrgId":   "org_oclan",
				"organizations": []map[string]any{{"id": "org_oclan", "slug": "oclan-co", "role": "owner", "canPull": true, "canWrite": true}},
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
			if body["createdByDeviceId"] != "dev_oclan" {
				t.Fatalf("bulk preflight used wrong device id: %#v", body)
			}
			if body["version"] != float64(1) {
				t.Fatalf("bulk preflight used wrong version: %#v", body)
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
			if body["createdByDeviceId"] != "dev_oclan" {
				t.Fatalf("bulk delete used wrong device id: %#v", body)
			}
			if body["version"] != float64(1) {
				t.Fatalf("bulk delete used wrong version: %#v", body)
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
		{"init", "--device", "qa-laptop"},
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
			if r.URL.Query().Get("includeSecrets") != "1" {
				_ = json.NewEncoder(w).Encode(map[string]any{
					"activeOrgId":   "org_oclan",
					"organizations": []map[string]any{{"id": "org_oclan", "slug": "oclan-co", "role": "owner", "canPull": true, "canWrite": true}},
				})
				return
			}
			wrapped := true
			_ = json.NewEncoder(w).Encode(map[string]any{
				"activeOrgId":   "org_oclan",
				"organizations": []map[string]any{{"id": "org_oclan", "slug": "oclan-co", "role": "owner", "canPull": true, "canWrite": true}},
				"secrets": []map[string]any{
					{"id": "sec_wrapped_remote_only", "orgId": "org_oclan", "workspaceSlug": "oclan-co", "scope": "oclan-co/prod", "name": "WRAPPED_ONLY", "version": 3, "status": "active", "canWrite": true, "wrappedToCurrentDevice": wrapped},
				},
			})
		case "/v1/secrets/sec_wrapped_remote_only/delete-preflight":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if body["createdByDeviceId"] != "dev_oclan" || body["version"] != float64(3) {
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
			if body["createdByDeviceId"] != "dev_oclan" || body["version"] != float64(3) {
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
			if r.URL.Query().Get("includeSecrets") != "1" {
				_ = json.NewEncoder(w).Encode(map[string]any{
					"activeOrgId":   "org_oclan",
					"organizations": []map[string]any{{"id": "org_oclan", "slug": "oclan-co", "role": "owner", "canPull": true, "canWrite": true}},
				})
				return
			}
			unwrapped := false
			_ = json.NewEncoder(w).Encode(map[string]any{
				"activeOrgId":   "org_oclan",
				"organizations": []map[string]any{{"id": "org_oclan", "slug": "oclan-co", "role": "owner", "canPull": true, "canWrite": true}},
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
			if r.URL.Query().Get("includeSecrets") != "1" {
				_ = json.NewEncoder(w).Encode(map[string]any{
					"activeOrgId":   "org_oclan",
					"organizations": []map[string]any{{"id": "org_oclan", "slug": "oclan-co", "role": "owner", "canPull": true, "canWrite": true}},
				})
				return
			}
			unwrapped := false
			_ = json.NewEncoder(w).Encode(map[string]any{
				"activeOrgId":   "org_oclan",
				"organizations": []map[string]any{{"id": "org_oclan", "slug": "oclan-co", "role": "owner", "canPull": true, "canWrite": true}},
				"secrets": []map[string]any{
					{"id": "sec_rollback_a", "orgId": "org_oclan", "workspaceSlug": "oclan-co", "scope": "oclan-co/prod", "name": "A", "version": 1, "status": "active", "canWrite": true, "wrappedToCurrentDevice": unwrapped},
					{"id": "sec_rollback_b", "orgId": "org_oclan", "workspaceSlug": "oclan-co", "scope": "oclan-co/prod", "name": "B", "version": 1, "status": "active", "canWrite": true, "wrappedToCurrentDevice": unwrapped},
				},
			})
		case "/v1/secrets/sec_rollback_a/delete-preflight", "/v1/secrets/sec_rollback_b/delete-preflight":
			id := strings.TrimPrefix(strings.TrimSuffix(r.URL.Path, "/delete-preflight"), "/v1/secrets/")
			_ = json.NewEncoder(w).Encode(map[string]any{"id": id, "orgId": "org_oclan", "scope": "oclan-co/prod", "name": strings.TrimPrefix(id, "sec_rollback_"), "version": 1, "status": "active"})
		case "/v1/secrets/sec_rollback_a/delete":
			deletedIDs = append(deletedIDs, "sec_rollback_a")
			_ = json.NewEncoder(w).Encode(map[string]any{"id": "sec_rollback_a", "orgId": "org_oclan", "scope": "oclan-co/prod", "name": "A", "version": 1, "status": "deleted"})
		case "/v1/secrets/sec_rollback_b/delete":
			deletedIDs = append(deletedIDs, "sec_rollback_b")
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": "delete_failed", "message": "delete failed after preflight"})
		case "/v1/secrets/sec_rollback_a/restore":
			restoredIDs = append(restoredIDs, "sec_rollback_a")
			_ = json.NewEncoder(w).Encode(map[string]any{"id": "sec_rollback_a", "orgId": "org_oclan", "scope": "oclan-co/prod", "name": "A", "version": 1, "status": "active"})
		case "/v1/secrets/sec_rollback_b/restore":
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
			if r.URL.Query().Get("includeSecrets") != "1" {
				_ = json.NewEncoder(w).Encode(map[string]any{
					"activeOrgId":   "org_oclan",
					"organizations": []map[string]any{{"id": "org_oclan", "slug": "oclan-co", "role": "owner", "canPull": true, "canWrite": true}},
				})
				return
			}
			unwrapped := false
			_ = json.NewEncoder(w).Encode(map[string]any{
				"activeOrgId":   "org_oclan",
				"organizations": []map[string]any{{"id": "org_oclan", "slug": "oclan-co", "role": "owner", "canPull": true, "canWrite": true}},
				"secrets": []map[string]any{
					{"id": "sec_confirm_bulk", "orgId": "org_oclan", "workspaceSlug": "oclan-co", "scope": "oclan-co/prod", "name": "GHOST", "version": 1, "status": "active", "canWrite": true, "wrappedToCurrentDevice": unwrapped},
				},
			})
		case "/v1/secrets/sec_confirm_bulk/delete-preflight":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if body["createdByDeviceId"] != "dev_oclan" || body["version"] != float64(1) {
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
		{"init", "--device", "qa-laptop"},
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
				"activeWorkspace": map[string]any{
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
	if code := app.Run([]string{"device", "status"}); code != 0 {
		t.Fatalf("device status failed: %s", errb.String())
	}
	status := out.String()
	for _, expected := range []string{"This device: qa-laptop", "WORKSPACE", "THIS DEVICE", "ACCOUNT WRITE", "KEYS", "NEXT", "oclan-co", "ready", "asiri-dev", "not trusted", "asiri device trust --workspace asiri-dev --origin " + server.URL, "recallstack-com", "unwrapped", "rewrap on a device with local keys"} {
		if !strings.Contains(status, expected) {
			t.Fatalf("device status output missing %q: %s", expected, status)
		}
	}
}

func TestDeviceTrustAllStartsTargetedApprovals(t *testing.T) {
	tmp := t.TempDir()
	old := os.Getenv("ASIRI_HOME")
	t.Cleanup(func() { _ = os.Setenv("ASIRI_HOME", old) })
	if err := os.Setenv("ASIRI_HOME", tmp); err != nil {
		t.Fatal(err)
	}
	targetedStarts := []string{}
	restoreSeen := false
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
			var body map[string]string
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if body["deviceCode"] == "dc_asiri" {
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
	out.Reset()
	errb.Reset()
	if code := app.Run([]string{"device", "trust", "--all"}); code != 0 {
		t.Fatalf("device trust --all failed: %s", errb.String())
	}
	if !reflect.DeepEqual(targetedStarts, []string{"", "asiri-dev"}) {
		t.Fatalf("unexpected device-code targets: %#v", targetedStarts)
	}
	if !restoreSeen {
		t.Fatal("expected original workspace session to be restored")
	}
	output := out.String()
	for _, expected := range []string{"oclan-co", "trusted", "asiri-dev", "eligible", "recallstack-com", "ask owner to approve", "Trust this device for workspace asiri-dev", "✓ This device is trusted for workspace asiri-dev"} {
		if !strings.Contains(output, expected) {
			t.Fatalf("device trust --all output missing %q: %s", expected, output)
		}
	}
}

func TestPullAllPrintsRowsSkipsIneligibleAndRestoresWorkspace(t *testing.T) {
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
					{"id": "org_oclan", "name": "O Clan", "slug": "oclan-co", "ownerUserId": "usr_owner", "role": "owner", "canPull": true, "canWrite": true},
					{"id": "org_asiri", "name": "Asiri Dev", "slug": "asiri-dev", "ownerUserId": "usr_owner", "role": "owner", "canPull": false, "canWrite": true},
					{"id": "org_recall", "name": "Recallstack", "slug": "recallstack-com", "ownerUserId": "usr_other", "role": "member", "canPull": true, "canWrite": false},
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
				if auth != "Bearer at_recall" || deviceID != "dev_recall" {
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
	if code := app.Run([]string{"pull"}); code != 0 {
		t.Fatalf("pull failed with code %d stderr=%s stdout=%s", code, errb.String(), out.String())
	}
	allOutput := out.String()
	for _, expected := range []string{"WORKSPACE", "oclan-co", "pulled", "asiri-dev", "skipped", "this device is not trusted for this workspace", "recallstack-com"} {
		if !strings.Contains(allOutput, expected) {
			t.Fatalf("pull output missing %q: %s", expected, allOutput)
		}
	}
	if !switchRecallSeen || switchAsiriSeen || restoreSeen {
		t.Fatalf("unexpected switch behavior: recall=%v asiri=%v restore=%v", switchRecallSeen, switchAsiriSeen, restoreSeen)
	}

	out.Reset()
	errb.Reset()
	if code := app.Run([]string{"pull", "--workspace", "asiri-dev"}); code != 0 {
		t.Fatalf("explicit ineligible pull should exit zero, stderr=%s stdout=%s", errb.String(), out.String())
	}
	if !strings.Contains(out.String(), "asiri-dev") || !strings.Contains(out.String(), "failed") {
		t.Fatalf("explicit ineligible pull output unexpected: %s", out.String())
	}
}

func TestRunDirectAsiriRefUsesCommandBasenamePolicy(t *testing.T) {
	tmp := t.TempDir()
	oldHome := os.Getenv("ASIRI_HOME")
	oldPath := os.Getenv("PATH")
	t.Cleanup(func() {
		_ = os.Setenv("ASIRI_HOME", oldHome)
		_ = os.Setenv("PATH", oldPath)
	})
	if err := os.Setenv("ASIRI_HOME", tmp); err != nil {
		t.Fatal(err)
	}
	binDir := t.TempDir()
	marker := filepath.Join(tmp, "ran")
	wranglerPath := binDir + "/wrangler"
	if err := os.WriteFile(wranglerPath, []byte("#!/bin/sh\nif [ \"$3\" != \"cf_prod_token\" ]; then echo bad-token >&2; exit 7; fi\ntouch \""+marker+"\"\necho unsafe-argv-ok\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	helpToolPath := binDir + "/help-tool"
	if err := os.WriteFile(helpToolPath, []byte("#!/bin/sh\nif [ \"$1\" = \"--help\" ]; then echo child-help-ok; exit 0; fi\necho missing-help >&2; exit 9\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Setenv("PATH", binDir+string(os.PathListSeparator)+oldPath); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	var errb bytes.Buffer
	app := New(&out, &errb)
	steps := [][]string{
		{"init", "--device", "qa-laptop"},
		{"add", "--workspace", "qa", "cloudflare/prod-token", "--value-file", testSecretFile(t, "cf_prod_token")},
		{"grant", "--workspace", "qa", "wrangler", "cloudflare/prod-token", "--inject-only"},
	}
	for _, step := range steps {
		out.Reset()
		errb.Reset()
		if code := app.Run(step); code != 0 {
			t.Fatalf("%v failed with code %d stderr=%s", step, code, errb.String())
		}
	}
	out.Reset()
	errb.Reset()
	if code := app.Run([]string{"run", "wrangler", "deploy", "--token", "asiri://cloudflare/prod-token"}); code == 0 {
		t.Fatalf("expected missing workspace denial, stdout=%s", out.String())
	}
	if !strings.Contains(errb.String(), "requires --workspace") {
		t.Fatalf("missing clear workspace denial stderr: %s", errb.String())
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("denied direct run executed child command; marker err=%v", err)
	}
	if strings.Contains(out.String(), "cf_prod_token") || strings.Contains(errb.String(), "cf_prod_token") {
		t.Fatalf("denial leaked secret stdout=%q stderr=%q", out.String(), errb.String())
	}
	out.Reset()
	errb.Reset()
	if code := app.Run([]string{"run", "--workspace", "qa", "wrangler", "deploy", "--token", "asiri://cloudflare/prod-token"}); code == 0 {
		t.Fatalf("expected explicit mode denial, stdout=%s", out.String())
	}
	if !strings.Contains(errb.String(), "argument substitution is disabled") {
		t.Fatalf("missing clear substitution denial stderr: %s", errb.String())
	}
	out.Reset()
	errb.Reset()
	if code := app.Run([]string{"run", "--workspace", "qa", "--unsafe-argv", "help-tool", "--help"}); code != 0 {
		t.Fatalf("expected unsafe argv child --help to pass through, stderr=%s", errb.String())
	}
	if !strings.Contains(out.String(), "child-help-ok") {
		t.Fatalf("unsafe argv child --help was not executed: stdout=%s stderr=%s", out.String(), errb.String())
	}
	out.Reset()
	errb.Reset()
	if code := app.Run([]string{"run", "--workspace", "qa", "--unsafe-argv", "asiri://cloudflare/prod-token"}); code == 0 {
		t.Fatalf("expected command-name substitution denial, stdout=%s", out.String())
	}
	if !strings.Contains(errb.String(), "not allowed in the command name") {
		t.Fatalf("missing command-name denial stderr: %s", errb.String())
	}
	if strings.Contains(out.String(), "cf_prod_token") || strings.Contains(errb.String(), "cf_prod_token") {
		t.Fatalf("command-name denial leaked secret stdout=%q stderr=%q", out.String(), errb.String())
	}
	out.Reset()
	errb.Reset()
	if code := app.Run([]string{"run", "--workspace", "qa", "--unsafe-argv", "wrangler", "deploy", "--token", "asiri://cloudflare/prod-token"}); code != 0 {
		t.Fatalf("expected unsafe argv substitution to run, stderr=%s", errb.String())
	}
	if !strings.Contains(out.String(), "unsafe-argv-ok") {
		t.Fatalf("unsafe argv command did not run: stdout=%s", out.String())
	}
	if strings.Contains(out.String(), "cf_prod_token") || strings.Contains(errb.String(), "cf_prod_token") {
		t.Fatalf("unsafe argv leaked secret through asiri output stdout=%q stderr=%q", out.String(), errb.String())
	}
	out.Reset()
	errb.Reset()
	if code := app.Run([]string{"audit", "tail", "--limit", "5"}); code != 0 {
		t.Fatalf("audit failed: %s", errb.String())
	}
	if !strings.Contains(out.String(), "secret_unsafe_argv_injected") || !strings.Contains(out.String(), "unsafe argv materialization") {
		t.Fatalf("audit missing unsafe argv event: %s", out.String())
	}
}

func TestRunExplicitEnvMappingUsesCommandBasenamePolicy(t *testing.T) {
	tmp := t.TempDir()
	oldHome := os.Getenv("ASIRI_HOME")
	oldPath := os.Getenv("PATH")
	t.Cleanup(func() {
		_ = os.Setenv("ASIRI_HOME", oldHome)
		_ = os.Setenv("PATH", oldPath)
	})
	if err := os.Setenv("ASIRI_HOME", tmp); err != nil {
		t.Fatal(err)
	}
	binDir := t.TempDir()
	wranglerPath := binDir + "/wrangler"
	if err := os.WriteFile(wranglerPath, []byte("#!/bin/sh\ntest \"$WRANGLER_SECRET\" = env_secret\necho explicit-env-ok\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Setenv("PATH", binDir+string(os.PathListSeparator)+oldPath); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	var errb bytes.Buffer
	app := New(&out, &errb)
	steps := [][]string{
		{"init", "--device", "qa-laptop"},
		{"add", "--workspace", "qa", "cloudflare/WRANGLER_SECRET", "--value-file", testSecretFile(t, "env_secret")},
		{"grant", "--workspace", "qa", "wrangler", "cloudflare/WRANGLER_SECRET", "--inject-only"},
		{"run", "--workspace", "qa", "--env", "WRANGLER_SECRET=cloudflare/WRANGLER_SECRET", "--", "wrangler", "deploy"},
	}
	for _, step := range steps {
		out.Reset()
		errb.Reset()
		if code := app.Run(step); code != 0 {
			t.Fatalf("%v failed with code %d stderr=%s", step, code, errb.String())
		}
	}
	if !strings.Contains(out.String(), "explicit-env-ok") {
		t.Fatalf("explicit env mapping did not execute fake wrangler: stdout=%s", out.String())
	}
	if strings.Contains(out.String(), "env_secret") || strings.Contains(errb.String(), "env_secret") {
		t.Fatalf("asiri output leaked injected secret stdout=%q stderr=%q", out.String(), errb.String())
	}
	out.Reset()
	errb.Reset()
	if code := app.Run([]string{"audit", "tail", "--limit", "5"}); code != 0 {
		t.Fatalf("audit failed: %s", errb.String())
	}
	if !strings.Contains(out.String(), "wrangler") || !strings.Contains(out.String(), "secret_injected") {
		t.Fatalf("audit missing explicit env mapping injection event: %s", out.String())
	}
}

func TestRuntimeAuditSyncReportsRuntimeLabelMetadata(t *testing.T) {
	tmp := t.TempDir()
	oldHome := os.Getenv("ASIRI_HOME")
	oldPath := os.Getenv("PATH")
	t.Cleanup(func() {
		_ = os.Setenv("ASIRI_HOME", oldHome)
		_ = os.Setenv("PATH", oldPath)
	})
	if err := os.Setenv("ASIRI_HOME", tmp); err != nil {
		t.Fatal(err)
	}
	binDir := t.TempDir()
	marker := filepath.Join(tmp, "ran")
	wranglerPath := filepath.Join(binDir, "wrangler")
	if err := os.WriteFile(wranglerPath, []byte(fmt.Sprintf("#!/bin/sh\ntest \"$WRANGLER_SECRET\" = env_secret\ntouch %q\necho runtime-sync-ok\n", marker)), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Setenv("PATH", binDir+string(os.PathListSeparator)+oldPath); err != nil {
		t.Fatal(err)
	}

	var uploaded []runtimeAuditBatchRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/session/refresh":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status":           "approved",
				"orgId":            "org_runtime",
				"workspaceSlug":    "runtime-ws",
				"userId":           "usr_owner",
				"deviceId":         "dev_remote",
				"accessToken":      "at_refreshed",
				"expiresIn":        3600,
				"refreshExpiresAt": time.Now().UTC().Add(7 * 24 * time.Hour).Format(time.RFC3339),
			})
		case "/v1/audit/batch":
			if r.Header.Get("authorization") != "Bearer at_runtime" {
				t.Fatalf("unexpected audit auth header: %s", r.Header.Get("authorization"))
			}
			var batch runtimeAuditBatchRequest
			if err := json.NewDecoder(r.Body).Decode(&batch); err != nil {
				t.Fatal(err)
			}
			uploaded = append(uploaded, batch)
			w.WriteHeader(http.StatusCreated)
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
		{"add", "--workspace", "qa", "cloudflare/WRANGLER_SECRET", "--value-file", testSecretFile(t, "env_secret")},
		{"grant", "--workspace", "qa", "wrangler", "cloudflare/WRANGLER_SECRET", "--inject-only"},
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
	if err := st.LinkControlPlaneForDevice(server.URL, "org_runtime", "runtime-ws", "usr_owner", "dev_remote", device.ID, "at_runtime", "rt_runtime", 3600, time.Now().UTC().Add(7*24*time.Hour).Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
	st.State.RemoteBindings["qa"] = asiri.RemoteWorkspaceBinding{WorkspaceID: "org_runtime", WorkspaceSlug: "runtime-ws", BoundAt: time.Now().UTC()}
	if err := st.Save(); err != nil {
		t.Fatal(err)
	}

	out.Reset()
	errb.Reset()
	if code := app.Run([]string{"run", "--workspace", "qa", "--env", "WRANGLER_SECRET=cloudflare/WRANGLER_SECRET", "--", "wrangler", "deploy"}); code != 0 {
		t.Fatalf("runtime command failed: %s", errb.String())
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("runtime command marker missing: %v", err)
	}
	if len(uploaded) != 1 || len(uploaded[0].Events) != 1 {
		t.Fatalf("expected one uploaded runtime audit event, got %#v", uploaded)
	}
	event := uploaded[0].Events[0]
	if event.OrgID != "org_runtime" || event.Action != "secret_injected" || event.Result != "allowed" {
		t.Fatalf("unexpected uploaded event: %#v", event)
	}
	if event.Metadata["runtimeLabel"] != "wrangler" || event.Metadata["runtimeLabelType"] != "process" || event.Metadata["workspaceId"] != "org_runtime" || event.Metadata["workspaceSlug"] != "runtime-ws" || event.Metadata["localAuditId"] == "" || event.Metadata["reportedCreatedAt"] == "" {
		t.Fatalf("runtime label metadata missing: %#v", event.Metadata)
	}
	raw, err := json.Marshal(uploaded)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "env_secret") {
		t.Fatalf("uploaded audit leaked secret value: %s", string(raw))
	}
	st, err = store.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	synced := false
	for _, item := range st.State.Audit {
		if item.Action == "secret_injected" && item.Metadata["runtimeLabel"] == "wrangler" {
			synced = item.RemoteSyncedAt != nil
			break
		}
	}
	if !synced {
		t.Fatalf("local runtime audit event was not marked synced")
	}
}

func TestRuntimeAuditSyncFailureDoesNotBlockLocalUse(t *testing.T) {
	tmp := t.TempDir()
	oldHome := os.Getenv("ASIRI_HOME")
	oldPath := os.Getenv("PATH")
	oldAuditSyncTimeout := runtimeAuditSyncTimeout
	t.Cleanup(func() {
		_ = os.Setenv("ASIRI_HOME", oldHome)
		_ = os.Setenv("PATH", oldPath)
		runtimeAuditSyncTimeout = oldAuditSyncTimeout
	})
	runtimeAuditSyncTimeout = 25 * time.Millisecond
	if err := os.Setenv("ASIRI_HOME", tmp); err != nil {
		t.Fatal(err)
	}
	binDir := t.TempDir()
	marker := filepath.Join(tmp, "ran")
	wranglerPath := filepath.Join(binDir, "wrangler")
	if err := os.WriteFile(wranglerPath, []byte(fmt.Sprintf("#!/bin/sh\ntest \"$WRANGLER_SECRET\" = env_secret\ntouch %q\necho runtime-offline-ok\n", marker)), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Setenv("PATH", binDir+string(os.PathListSeparator)+oldPath); err != nil {
		t.Fatal(err)
	}

	auditAttempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/session/refresh":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status":           "approved",
				"orgId":            "org_runtime",
				"workspaceSlug":    "runtime-ws",
				"userId":           "usr_owner",
				"deviceId":         "dev_remote",
				"accessToken":      "at_refreshed",
				"expiresIn":        3600,
				"refreshExpiresAt": time.Now().UTC().Add(7 * 24 * time.Hour).Format(time.RFC3339),
			})
		case "/v1/audit/batch":
			auditAttempts++
			time.Sleep(150 * time.Millisecond)
			http.Error(w, "offline", http.StatusServiceUnavailable)
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
		{"add", "--workspace", "qa", "cloudflare/WRANGLER_SECRET", "--value-file", testSecretFile(t, "env_secret")},
		{"grant", "--workspace", "qa", "wrangler", "cloudflare/WRANGLER_SECRET", "--inject-only"},
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
	if err := st.LinkControlPlaneForDevice(server.URL, "org_runtime", "runtime-ws", "usr_owner", "dev_remote", device.ID, "at_runtime", "rt_runtime", 3600, time.Now().UTC().Add(7*24*time.Hour).Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
	st.State.RemoteBindings["qa"] = asiri.RemoteWorkspaceBinding{WorkspaceID: "org_runtime", WorkspaceSlug: "runtime-ws", BoundAt: time.Now().UTC()}
	if err := st.Save(); err != nil {
		t.Fatal(err)
	}

	out.Reset()
	errb.Reset()
	if code := app.Run([]string{"run", "--workspace", "qa", "--env", "WRANGLER_SECRET=cloudflare/WRANGLER_SECRET", "--", "wrangler", "deploy"}); code != 0 {
		t.Fatalf("runtime command should ignore audit upload failure: %s", errb.String())
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("runtime command marker missing: %v", err)
	}
	if auditAttempts == 0 {
		t.Fatalf("expected an audit upload attempt")
	}
	st, err = store.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	startedAt := time.Now()
	app.syncRuntimeAuditBestEffort(st)
	if elapsed := time.Since(startedAt); elapsed > 250*time.Millisecond {
		t.Fatalf("audit sync timeout was not bounded: %s", elapsed)
	}
	foundPending := false
	for _, item := range st.State.Audit {
		if item.Action == "secret_injected" && item.Metadata["runtimeLabel"] == "wrangler" {
			foundPending = item.RemoteSyncedAt == nil
			break
		}
	}
	if !foundPending {
		t.Fatalf("failed upload should leave runtime audit event pending")
	}
}

func TestPendingRuntimeAuditEventsStayInOriginalWorkspace(t *testing.T) {
	createdAt := time.Now().UTC()
	st := &store.FileStore{State: asiri.State{
		ControlPlane: &asiri.ControlPlaneLink{
			WorkspaceID:   "org_two",
			WorkspaceSlug: "two",
		},
		RemoteBindings: map[string]asiri.RemoteWorkspaceBinding{
			"one": {WorkspaceID: "org_one", WorkspaceSlug: "one", BoundAt: createdAt},
		},
	}}
	metadata := runtimeAuditMetadata(st, "one/cloudflare", "wrangler", "process", nil)
	if metadata["workspaceId"] != "org_one" || metadata["workspaceSlug"] != "one" {
		t.Fatalf("runtime audit metadata should use bound scope workspace: %#v", metadata)
	}
	st.State.Audit = []asiri.AuditEvent{
		{
			ID:             "aud_one",
			Actor:          "wrangler",
			Action:         "secret_injected",
			Result:         "allowed",
			Scope:          "one/cloudflare",
			SecretNameHash: "hash_one",
			Reason:         "explicit env mapping",
			Metadata:       metadata,
			CreatedAt:      createdAt,
		},
		{
			ID:             "aud_legacy",
			Actor:          "wrangler",
			Action:         "secret_injected",
			Result:         "allowed",
			Scope:          "one/cloudflare",
			SecretNameHash: "hash_legacy",
			Reason:         "explicit env mapping",
			Metadata: map[string]string{
				"runtimeLabel":     "wrangler",
				"runtimeLabelType": "process",
			},
			CreatedAt: createdAt,
		},
	}

	ids, events := pendingRuntimeAuditEvents(st)
	if len(ids) != 0 || len(events) != 0 {
		t.Fatalf("event from original workspace should not upload while linked to another workspace: ids=%#v events=%#v", ids, events)
	}

	st.State.ControlPlane.WorkspaceID = "org_one"
	st.State.ControlPlane.WorkspaceSlug = "one"
	ids, events = pendingRuntimeAuditEvents(st)
	if len(ids) != 1 || ids[0] != "aud_one" || len(events) != 1 {
		t.Fatalf("expected only explicitly attributed original workspace event to become uploadable: ids=%#v events=%#v", ids, events)
	}
	if events[0].OrgID != "org_one" || events[0].Metadata["workspaceId"] != "org_one" || events[0].Metadata["workspaceSlug"] != "one" {
		t.Fatalf("uploaded event should keep original workspace attribution: %#v", events[0])
	}
}

func TestRunExplicitEnvMappingDeniesMissingDerivedCommandGrant(t *testing.T) {
	tmp := t.TempDir()
	oldHome := os.Getenv("ASIRI_HOME")
	oldPath := os.Getenv("PATH")
	t.Cleanup(func() {
		_ = os.Setenv("ASIRI_HOME", oldHome)
		_ = os.Setenv("PATH", oldPath)
	})
	if err := os.Setenv("ASIRI_HOME", tmp); err != nil {
		t.Fatal(err)
	}
	binDir := t.TempDir()
	marker := filepath.Join(tmp, "ran")
	wranglerPath := binDir + "/wrangler"
	if err := os.WriteFile(wranglerPath, []byte("#!/bin/sh\ntouch \""+marker+"\"\necho should-not-run\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Setenv("PATH", binDir+string(os.PathListSeparator)+oldPath); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	var errb bytes.Buffer
	app := New(&out, &errb)
	for _, step := range [][]string{
		{"init", "--device", "qa-laptop"},
		{"add", "--workspace", "qa", "cloudflare/WRANGLER_SECRET", "--value-file", testSecretFile(t, "env_secret")},
	} {
		out.Reset()
		errb.Reset()
		if code := app.Run(step); code != 0 {
			t.Fatalf("%v failed with code %d stderr=%s", step, code, errb.String())
		}
	}
	out.Reset()
	errb.Reset()
	if code := app.Run([]string{"run", "--workspace", "qa", "--env", "WRANGLER_SECRET=cloudflare/WRANGLER_SECRET", "--", "wrangler", "deploy"}); code == 0 {
		t.Fatalf("expected explicit env mapping denial, stdout=%s", out.String())
	}
	if !strings.Contains(errb.String(), "wrangler cannot inject qa/cloudflare/WRANGLER_SECRET") {
		t.Fatalf("missing clear denial stderr: %s", errb.String())
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("denied explicit env mapping executed child command; marker err=%v", err)
	}
	if strings.Contains(out.String(), "env_secret") || strings.Contains(errb.String(), "env_secret") {
		t.Fatalf("denial leaked secret stdout=%q stderr=%q", out.String(), errb.String())
	}
	out.Reset()
	errb.Reset()
	if code := app.Run([]string{"audit", "tail", "--limit", "5"}); code != 0 {
		t.Fatalf("audit failed: %s", errb.String())
	}
	if !strings.Contains(out.String(), "wrangler") || !strings.Contains(out.String(), "secret_injected") || !strings.Contains(out.String(), "denied") {
		t.Fatalf("audit missing explicit env mapping denial event: %s", out.String())
	}
}

func TestRunDirectAsiriRefSupportsExplicitAgentAndEmbeddedRefs(t *testing.T) {
	tmp := t.TempDir()
	oldHome := os.Getenv("ASIRI_HOME")
	oldPath := os.Getenv("PATH")
	t.Cleanup(func() {
		_ = os.Setenv("ASIRI_HOME", oldHome)
		_ = os.Setenv("PATH", oldPath)
	})
	if err := os.Setenv("ASIRI_HOME", tmp); err != nil {
		t.Fatal(err)
	}
	binDir := t.TempDir()
	marker := filepath.Join(tmp, "ran")
	toolPath := binDir + "/custom-tool"
	if err := os.WriteFile(toolPath, []byte("#!/bin/sh\nif [ \"$1\" != \"token=embedded_token\" ]; then echo bad-token >&2; exit 7; fi\ntouch \""+marker+"\"\necho embedded-unsafe-ok\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Setenv("PATH", binDir+string(os.PathListSeparator)+oldPath); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	var errb bytes.Buffer
	app := New(&out, &errb)
	steps := [][]string{
		{"init", "--device", "qa-laptop"},
		{"add", "--workspace", "org", "team/cloudflare/prod-token", "--value-file", testSecretFile(t, "embedded_token")},
		{"grant", "--workspace", "org", "release-bot", "team/cloudflare/prod-token", "--inject-only"},
	}
	for _, step := range steps {
		out.Reset()
		errb.Reset()
		if code := app.Run(step); code != 0 {
			t.Fatalf("%v failed with code %d stderr=%s", step, code, errb.String())
		}
	}
	out.Reset()
	errb.Reset()
	if code := app.Run([]string{"run", "--agent", "release-bot", "custom-tool", "token=asiri://team/cloudflare/prod-token"}); code == 0 {
		t.Fatalf("expected missing workspace denial, stdout=%s", out.String())
	}
	if !strings.Contains(errb.String(), "requires --workspace") {
		t.Fatalf("missing clear workspace denial stderr: %s", errb.String())
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("denied direct run executed child command; marker err=%v", err)
	}
	out.Reset()
	errb.Reset()
	if code := app.Run([]string{"run", "--workspace", "org", "--agent", "release-bot", "custom-tool", "token=asiri://team/cloudflare/prod-token"}); code == 0 {
		t.Fatalf("expected explicit mode denial, stdout=%s", out.String())
	}
	if !strings.Contains(errb.String(), "argument substitution is disabled") {
		t.Fatalf("missing clear substitution denial stderr: %s", errb.String())
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("denied direct run executed child command; marker err=%v", err)
	}
	if strings.Contains(out.String(), "embedded_token") || strings.Contains(errb.String(), "embedded_token") {
		t.Fatalf("denial leaked secret stdout=%q stderr=%q", out.String(), errb.String())
	}
	out.Reset()
	errb.Reset()
	if code := app.Run([]string{"run", "--workspace", "org", "--agent", "release-bot", "--unsafe-argv", "custom-tool", "token=asiri://team/cloudflare/prod-token"}); code != 0 {
		t.Fatalf("expected unsafe argv substitution to run, stderr=%s", errb.String())
	}
	if !strings.Contains(out.String(), "embedded-unsafe-ok") {
		t.Fatalf("unsafe argv command did not run: stdout=%s", out.String())
	}
	if strings.Contains(out.String(), "embedded_token") || strings.Contains(errb.String(), "embedded_token") {
		t.Fatalf("unsafe argv leaked secret through asiri output stdout=%q stderr=%q", out.String(), errb.String())
	}
}

func TestRunDirectAsiriRefDeniesMissingGrantBeforeExecuting(t *testing.T) {
	tmp := t.TempDir()
	oldHome := os.Getenv("ASIRI_HOME")
	oldPath := os.Getenv("PATH")
	t.Cleanup(func() {
		_ = os.Setenv("ASIRI_HOME", oldHome)
		_ = os.Setenv("PATH", oldPath)
	})
	if err := os.Setenv("ASIRI_HOME", tmp); err != nil {
		t.Fatal(err)
	}
	binDir := t.TempDir()
	marker := tmp + "/ran"
	wranglerPath := binDir + "/wrangler"
	if err := os.WriteFile(wranglerPath, []byte("#!/bin/sh\ntouch \""+marker+"\"\necho should-not-run\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Setenv("PATH", binDir+string(os.PathListSeparator)+oldPath); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	var errb bytes.Buffer
	app := New(&out, &errb)
	for _, step := range [][]string{
		{"init", "--device", "qa-laptop"},
		{"add", "--workspace", "qa", "cloudflare/prod-token", "--value-file", testSecretFile(t, "cf_prod_token")},
	} {
		out.Reset()
		errb.Reset()
		if code := app.Run(step); code != 0 {
			t.Fatalf("%v failed with code %d stderr=%s", step, code, errb.String())
		}
	}
	out.Reset()
	errb.Reset()
	if code := app.Run([]string{"run", "--workspace", "qa", "--unsafe-argv", "wrangler", "deploy", "--token", "asiri://cloudflare/prod-token"}); code == 0 {
		t.Fatalf("expected direct run denial, stdout=%s", out.String())
	}
	if !strings.Contains(errb.String(), "wrangler cannot inject qa/cloudflare/prod-token") {
		t.Fatalf("missing clear denial stderr: %s", errb.String())
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("denied direct run executed child command; marker err=%v", err)
	}
	if strings.Contains(out.String(), "cf_prod_token") || strings.Contains(errb.String(), "cf_prod_token") {
		t.Fatalf("denial leaked secret stdout=%q stderr=%q", out.String(), errb.String())
	}
}

func TestEnvSingleSecretExport(t *testing.T) {
	tmp := t.TempDir()
	oldHome := os.Getenv("ASIRI_HOME")
	t.Cleanup(func() { _ = os.Setenv("ASIRI_HOME", oldHome) })
	_ = os.Setenv("ASIRI_HOME", tmp)
	var out, errb bytes.Buffer
	app := New(&out, &errb)
	for _, step := range [][]string{
		{"init", "--device", "qa-laptop"},
		{"add", "--workspace", "qa", "cloudflare/WRANGLER_SECRET", "--value-file", testSecretFile(t, "env_secret")},
		{"grant", "--workspace", "qa", "sh", "cloudflare/WRANGLER_SECRET", "--inject-only"},
		{"env", "--workspace", "qa", "cloudflare/WRANGLER_SECRET", "--", "sh", "-c", "test \"$WRANGLER_SECRET\" = env_secret"},
	} {
		out.Reset()
		errb.Reset()
		if code := app.Run(step); code != 0 {
			t.Fatalf("%v failed code=%d stderr=%s", step, code, errb.String())
		}
	}
	if strings.Contains(out.String(), "env_secret") || strings.Contains(errb.String(), "env_secret") {
		t.Fatalf("env leaked secret stdout=%q stderr=%q", out.String(), errb.String())
	}
}

func TestEnvDirectScopeExport(t *testing.T) {
	tmp := t.TempDir()
	oldHome := os.Getenv("ASIRI_HOME")
	t.Cleanup(func() { _ = os.Setenv("ASIRI_HOME", oldHome) })
	_ = os.Setenv("ASIRI_HOME", tmp)
	var out, errb bytes.Buffer
	app := New(&out, &errb)
	steps := [][]string{
		{"init", "--device", "qa-laptop"},
		{"add", "--workspace", "qa", "cloudflare/WRANGLER_SECRET", "--value-file", testSecretFile(t, "env_secret")},
		{"add", "--workspace", "qa", "cloudflare/CLOUDFLARE_ACCOUNT_ID", "--value-file", testSecretFile(t, "acct_123")},
		{"add", "--workspace", "qa", "cloudflare/nested/IGNORED", "--value-file", testSecretFile(t, "ignored")},
		{"grant", "--workspace", "qa", "sh", "cloudflare/WRANGLER_SECRET", "--inject-only"},
		{"grant", "--workspace", "qa", "sh", "cloudflare/CLOUDFLARE_ACCOUNT_ID", "--inject-only"},
		{"env", "--workspace", "qa", "cloudflare", "--", "sh", "-c", "test \"$WRANGLER_SECRET\" = env_secret && test \"$CLOUDFLARE_ACCOUNT_ID\" = acct_123 && test -z \"${IGNORED:-}\""},
	}
	for _, step := range steps {
		out.Reset()
		errb.Reset()
		if code := app.Run(step); code != 0 {
			t.Fatalf("%v failed code=%d stderr=%s", step, code, errb.String())
		}
	}
}

func TestEnvRemoteHintFallsBackToSlashyScopeSelection(t *testing.T) {
	tmp := t.TempDir()
	oldHome := os.Getenv("ASIRI_HOME")
	t.Cleanup(func() { _ = os.Setenv("ASIRI_HOME", oldHome) })
	_ = os.Setenv("ASIRI_HOME", tmp)

	overviewSeen := false
	remoteVisibleSecrets := []map[string]any{{
		"id":                     "sec_remote_child",
		"orgId":                  "org_runtime",
		"workspaceSlug":          "oclan-co",
		"scope":                  "oclan-co/prod/github",
		"name":                   "SYNC_KEY",
		"version":                1,
		"status":                 "active",
		"canWrite":               true,
		"wrappedToCurrentDevice": false,
	}, {
		"id":                     "sec_denied_child",
		"orgId":                  "org_runtime",
		"workspaceSlug":          "oclan-co",
		"scope":                  "oclan-co/prod/github",
		"name":                   "DENIED_KEY",
		"version":                1,
		"status":                 "active",
		"canWrite":               true,
		"wrappedToCurrentDevice": false,
	}}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		switch r.URL.Path {
		case "/v1/orgs":
			if r.Header.Get("authorization") != "Bearer at_runtime" {
				t.Fatalf("unexpected workspace overview auth header: %s", r.Header.Get("authorization"))
			}
			if r.URL.Query().Get("includeSecrets") != "1" {
				_ = json.NewEncoder(w).Encode(map[string]any{
					"activeOrgId":   "org_runtime",
					"organizations": []map[string]any{{"id": "org_runtime", "slug": "oclan-co", "role": "owner", "canPull": true, "canWrite": true}},
				})
				return
			}
			overviewSeen = true
			_ = json.NewEncoder(w).Encode(map[string]any{
				"activeOrgId":   "org_runtime",
				"organizations": []map[string]any{{"id": "org_runtime", "slug": "oclan-co", "role": "owner", "canPull": true, "canWrite": true}},
				"secrets":       remoteVisibleSecrets,
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	var out, errb bytes.Buffer
	app := New(&out, &errb)
	for _, step := range [][]string{
		{"init", "--device", "qa-laptop"},
	} {
		out.Reset()
		errb.Reset()
		if code := app.Run(step); code != 0 {
			t.Fatalf("%v failed code=%d stderr=%s", step, code, errb.String())
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
	if err := st.LinkControlPlaneForDevice(server.URL, "org_runtime", "oclan-co", "usr_owner", "dev_remote", device.ID, "at_runtime", "rt_runtime", 3600, time.Now().UTC().Add(7*24*time.Hour).Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
	if err := st.Save(); err != nil {
		t.Fatal(err)
	}

	out.Reset()
	errb.Reset()
	if code := app.Run([]string{"env", "--workspace", "oclan-co", "prod/github", "--", "sh", "-c", "true"}); code == 0 {
		t.Fatal("expected remote-only scope selection to fail before execution")
	}
	if overviewSeen {
		t.Fatal("remote lookup should not run without an inject grant")
	}
	if !strings.Contains(errb.String(), "no exact secret or direct child secrets found") {
		t.Fatalf("unexpected ungranted stderr: %s", errb.String())
	}

	st, err = store.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	st.State.Policies = append(st.State.Policies, asiri.Policy{
		ID:            "pol_remote_scope_hint",
		Subject:       "sh",
		ScopePattern:  "oclan-co/prod/github",
		SecretPattern: "*",
		Actions:       []string{"inject"},
		ApprovalMode:  "none",
		CreatedAt:     time.Now().UTC(),
	}, asiri.Policy{
		ID:            "pol_remote_scope_hint_denied",
		Subject:       "sh",
		ScopePattern:  "oclan-co/prod/github",
		SecretPattern: "DENIED_KEY",
		Actions:       []string{"deny"},
		ApprovalMode:  "require-owner",
		CreatedAt:     time.Now().UTC(),
	})
	if err := st.Save(); err != nil {
		t.Fatal(err)
	}

	overviewSeen = false
	out.Reset()
	errb.Reset()
	if code := app.Run([]string{"env", "--workspace", "oclan-co", "prod/github", "--", "sh", "-c", "true"}); code == 0 {
		t.Fatal("expected remote-only scope selection to fail before execution")
	}
	if !overviewSeen {
		t.Fatal("expected remote metadata lookup")
	}
	for _, expected := range []string{
		"1 direct child secret(s) exist remotely under oclan-co/prod/github",
		"not locally usable on this device",
		"asiri rewrap --workspace oclan-co",
		"asiri pull --workspace oclan-co",
	} {
		if !strings.Contains(errb.String(), expected) {
			t.Fatalf("missing %q in stderr: %s", expected, errb.String())
		}
	}
	if strings.Contains(errb.String(), "2 direct child") {
		t.Fatalf("denied remote child should not be counted in hint: %s", errb.String())
	}

	remoteVisibleSecrets = []map[string]any{{
		"id":                     "sec_denied_child",
		"orgId":                  "org_runtime",
		"workspaceSlug":          "oclan-co",
		"scope":                  "oclan-co/prod/github",
		"name":                   "DENIED_KEY",
		"version":                1,
		"status":                 "active",
		"canWrite":               true,
		"wrappedToCurrentDevice": false,
	}}
	overviewSeen = false
	out.Reset()
	errb.Reset()
	if code := app.Run([]string{"env", "--workspace", "oclan-co", "prod/github", "--", "sh", "-c", "true"}); code == 0 {
		t.Fatal("expected denied-only remote scope selection to fail before execution")
	}
	if !overviewSeen {
		t.Fatal("expected remote metadata lookup for denied-only scope")
	}
	if !strings.Contains(errb.String(), "no exact secret or direct child secrets found") || strings.Contains(errb.String(), "direct child secret(s) exist remotely") {
		t.Fatalf("denied-only remote children should not produce inventory hint: %s", errb.String())
	}
}

func TestEnvInvalidNameAndMissingGrantDoNotExecute(t *testing.T) {
	tmp := t.TempDir()
	oldHome := os.Getenv("ASIRI_HOME")
	oldPath := os.Getenv("PATH")
	t.Cleanup(func() { _ = os.Setenv("ASIRI_HOME", oldHome); _ = os.Setenv("PATH", oldPath) })
	_ = os.Setenv("ASIRI_HOME", tmp)
	binDir := t.TempDir()
	marker := filepath.Join(tmp, "ran")
	tool := filepath.Join(binDir, "tool")
	if err := os.WriteFile(tool, []byte("#!/bin/sh\ntouch '"+marker+"'\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	_ = os.Setenv("PATH", binDir+string(os.PathListSeparator)+oldPath)
	var out, errb bytes.Buffer
	app := New(&out, &errb)
	setup := [][]string{{"init", "--device", "qa-laptop"}, {"add", "--workspace", "qa", "cloudflare/BAD-NAME", "--value-file", testSecretFile(t, "bad_secret")}, {"grant", "--workspace", "qa", "tool", "cloudflare/BAD-NAME", "--inject-only"}, {"add", "--workspace", "qa", "cloudflare/WRANGLER_SECRET", "--value-file", testSecretFile(t, "env_secret")}}
	for _, step := range setup {
		out.Reset()
		errb.Reset()
		if code := app.Run(step); code != 0 {
			t.Fatalf("%v failed code=%d stderr=%s", step, code, errb.String())
		}
	}
	out.Reset()
	errb.Reset()
	if code := app.Run([]string{"env", "--workspace", "qa", "cloudflare/BAD-NAME", "--", "tool"}); code == 0 {
		t.Fatal("expected invalid env name failure")
	}
	if !strings.Contains(errb.String(), "not a valid environment variable") {
		t.Fatalf("unexpected invalid-name stderr=%s", errb.String())
	}
	out.Reset()
	errb.Reset()
	if code := app.Run([]string{"env", "--workspace", "qa", "cloudflare/WRANGLER_SECRET", "--", "tool"}); code == 0 {
		t.Fatal("expected missing grant failure")
	}
	if !strings.Contains(errb.String(), "tool cannot inject qa/cloudflare/WRANGLER_SECRET") {
		t.Fatalf("unexpected missing-grant stderr=%s", errb.String())
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("child executed despite env preflight failure: %v", err)
	}
	if strings.Contains(out.String(), "env_secret") || strings.Contains(errb.String(), "env_secret") {
		t.Fatalf("env failure leaked secret stdout=%q stderr=%q", out.String(), errb.String())
	}
}

func TestMountSingleSecretFileAndCleanup(t *testing.T) {
	tmp := t.TempDir()
	oldHome := os.Getenv("ASIRI_HOME")
	t.Cleanup(func() { _ = os.Setenv("ASIRI_HOME", oldHome) })
	_ = os.Setenv("ASIRI_HOME", tmp)
	mountDir := filepath.Join(tmp, "secrets")
	modeFile := filepath.Join(tmp, "mode")
	var out, errb bytes.Buffer
	app := New(&out, &errb)
	steps := [][]string{
		{"init", "--device", "qa-laptop"},
		{"add", "--workspace", "qa", "cloudflare/WRANGLER_SECRET", "--value-file", testSecretFile(t, "mounted_secret")},
		{"grant", "--workspace", "qa", "sh", "cloudflare/WRANGLER_SECRET", "--mount"},
		{"mount", "--workspace", "qa", "--dir", mountDir, "cloudflare/WRANGLER_SECRET", "--", "sh", "-c", "test \"$(cat \"$ASIRI_SECRETS_DIR/WRANGLER_SECRET\")\" = mounted_secret && (stat -c %a \"$ASIRI_SECRETS_DIR/WRANGLER_SECRET\" 2>/dev/null || stat -f %Lp \"$ASIRI_SECRETS_DIR/WRANGLER_SECRET\") > '" + modeFile + "'"},
	}
	for _, step := range steps {
		out.Reset()
		errb.Reset()
		if code := app.Run(step); code != 0 {
			t.Fatalf("%v failed code=%d stderr=%s", step, code, errb.String())
		}
	}
	if b, err := os.ReadFile(modeFile); err != nil || strings.TrimSpace(string(b)) != "600" {
		t.Fatalf("expected mode 600, got %q err=%v", string(b), err)
	}
	if _, err := os.Stat(filepath.Join(mountDir, "WRANGLER_SECRET")); !os.IsNotExist(err) {
		t.Fatalf("mount file not cleaned up: %v", err)
	}
	if strings.Contains(out.String(), "mounted_secret") || strings.Contains(errb.String(), "mounted_secret") {
		t.Fatalf("mount leaked secret stdout=%q stderr=%q", out.String(), errb.String())
	}
}

func TestMountChildDirArgumentDoesNotChangeMountDirectory(t *testing.T) {
	tmp := t.TempDir()
	oldHome := os.Getenv("ASIRI_HOME")
	t.Cleanup(func() { _ = os.Setenv("ASIRI_HOME", oldHome) })
	_ = os.Setenv("ASIRI_HOME", tmp)
	childDir := filepath.Join(tmp, "child-dir")
	var out, errb bytes.Buffer
	app := New(&out, &errb)
	steps := [][]string{
		{"init", "--device", "qa-laptop"},
		{"add", "--workspace", "qa", "cloudflare/WRANGLER_SECRET", "--value-file", testSecretFile(t, "mounted_secret")},
		{"grant", "--workspace", "qa", "sh", "cloudflare/WRANGLER_SECRET", "--mount"},
		{"mount", "--workspace", "qa", "cloudflare/WRANGLER_SECRET", "--", "sh", "-c", "test \"$ASIRI_SECRETS_DIR\" != \"$1\" && test \"$(cat \"$ASIRI_SECRETS_DIR/WRANGLER_SECRET\")\" = mounted_secret", "sh", childDir, "--dir", childDir},
	}
	for _, step := range steps {
		out.Reset()
		errb.Reset()
		if code := app.Run(step); code != 0 {
			t.Fatalf("%v failed code=%d stderr=%s", step, code, errb.String())
		}
	}
	if _, err := os.Stat(filepath.Join(childDir, "WRANGLER_SECRET")); !os.IsNotExist(err) {
		t.Fatalf("child --dir argument was used as mount directory: %v", err)
	}
}

func TestMountDirectScopeFiles(t *testing.T) {
	tmp := t.TempDir()
	oldHome := os.Getenv("ASIRI_HOME")
	t.Cleanup(func() { _ = os.Setenv("ASIRI_HOME", oldHome) })
	_ = os.Setenv("ASIRI_HOME", tmp)
	var out, errb bytes.Buffer
	app := New(&out, &errb)
	steps := [][]string{
		{"init", "--device", "qa-laptop"},
		{"add", "--workspace", "qa", "cloudflare/WRANGLER_SECRET", "--value-file", testSecretFile(t, "mounted_secret")},
		{"add", "--workspace", "qa", "cloudflare/CLOUDFLARE_ACCOUNT_ID", "--value-file", testSecretFile(t, "acct_123")},
		{"grant", "--workspace", "qa", "sh", "cloudflare/WRANGLER_SECRET", "--mount"},
		{"grant", "--workspace", "qa", "sh", "cloudflare/CLOUDFLARE_ACCOUNT_ID", "--mount"},
		{"mount", "--workspace", "qa", "cloudflare", "--", "sh", "-c", "test \"$(cat \"$ASIRI_SECRETS_DIR/WRANGLER_SECRET\")\" = mounted_secret && test \"$(cat \"$ASIRI_SECRETS_DIR/CLOUDFLARE_ACCOUNT_ID\")\" = acct_123"},
	}
	for _, step := range steps {
		out.Reset()
		errb.Reset()
		if code := app.Run(step); code != 0 {
			t.Fatalf("%v failed code=%d stderr=%s", step, code, errb.String())
		}
	}
}

func TestMountMissingGrantAndUnsafeDestinationDoNotExecute(t *testing.T) {
	tmp := t.TempDir()
	oldHome := os.Getenv("ASIRI_HOME")
	oldPath := os.Getenv("PATH")
	t.Cleanup(func() { _ = os.Setenv("ASIRI_HOME", oldHome); _ = os.Setenv("PATH", oldPath) })
	_ = os.Setenv("ASIRI_HOME", tmp)
	binDir := t.TempDir()
	marker := filepath.Join(tmp, "ran")
	tool := filepath.Join(binDir, "tool")
	if err := os.WriteFile(tool, []byte("#!/bin/sh\ntouch '"+marker+"'\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	_ = os.Setenv("PATH", binDir+string(os.PathListSeparator)+oldPath)
	var out, errb bytes.Buffer
	app := New(&out, &errb)
	for _, step := range [][]string{{"init", "--device", "qa-laptop"}, {"add", "--workspace", "qa", "cloudflare/WRANGLER_SECRET", "--value-file", testSecretFile(t, "mounted_secret")}} {
		out.Reset()
		errb.Reset()
		if code := app.Run(step); code != 0 {
			t.Fatalf("%v failed code=%d stderr=%s", step, code, errb.String())
		}
	}
	out.Reset()
	errb.Reset()
	if code := app.Run([]string{"mount", "--workspace", "qa", "cloudflare/WRANGLER_SECRET", "--", "tool"}); code == 0 {
		t.Fatal("expected missing mount grant failure")
	}
	if !strings.Contains(errb.String(), "tool cannot mount qa/cloudflare/WRANGLER_SECRET") {
		t.Fatalf("unexpected missing-grant stderr=%s", errb.String())
	}
	out.Reset()
	errb.Reset()
	if code := app.Run([]string{"grant", "--workspace", "qa", "tool", "cloudflare/WRANGLER_SECRET", "--mount"}); code != 0 {
		t.Fatalf("grant failed: %s", errb.String())
	}
	out.Reset()
	errb.Reset()
	if code := app.Run([]string{"mount", "--workspace", "qa", "cloudflare/WRANGLER_SECRET:../bad", "--", "tool"}); code == 0 {
		t.Fatal("expected unsafe destination failure")
	}
	if !strings.Contains(errb.String(), "path traversal") {
		t.Fatalf("unexpected unsafe-dest stderr=%s", errb.String())
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("child executed despite mount preflight failure: %v", err)
	}
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
