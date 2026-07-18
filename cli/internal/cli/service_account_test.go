package cli

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/o-clan/asiri/cli/internal/asiri"
	"github.com/o-clan/asiri/cli/internal/store"
)

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

func TestServiceAccountSessionRejectsOtherExplicitWorkspaces(t *testing.T) {
	tmp := t.TempDir()
	old := os.Getenv("ASIRI_HOME")
	t.Cleanup(func() { _ = os.Setenv("ASIRI_HOME", old) })
	if err := os.Setenv("ASIRI_HOME", tmp); err != nil {
		t.Fatal(err)
	}
	remoteHit := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		remoteHit = true
		http.Error(w, "unexpected", http.StatusInternalServerError)
	}))
	defer server.Close()

	var out, errb bytes.Buffer
	app := New(&out, &errb)
	if code := app.Run([]string{"init", "--device", "service-host", "--workspace", "other"}); code != 0 {
		t.Fatalf("init failed: %s", errb.String())
	}
	if code := app.Run([]string{"add", "--workspace", "other", "app/KEY", "--value-file", testSecretFile(t, "must_not_release")}); code != 0 {
		t.Fatalf("add failed: %s", errb.String())
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

	commands := [][]string{
		{"setup", "doctor", "--workspace", "other"},
		{"get", "--workspace", "other", "app/KEY"},
		{"list", "--local", "--workspace", "other"},
		{"run", "--workspace", "other", "--env", "KEY=app/KEY", "--", "sh", "-c", "true"},
		{"broker", "start", "--workspace", "other", "--agent", "app"},
		{"device", "status", "--workspace", "other"},
		{"pull", "--workspace", "other"},
	}
	for _, command := range commands {
		out.Reset()
		errb.Reset()
		if code := app.Run(command); code == 0 {
			t.Fatalf("%v should reject the other workspace", command)
		}
		if !strings.Contains(errb.String(), "service account session is scoped to workspace prod") {
			t.Fatalf("%v returned the wrong error: %s", command, errb.String())
		}
		if strings.Contains(out.String(), "must_not_release") {
			t.Fatalf("%v released a secret", command)
		}
	}
	if remoteHit {
		t.Fatal("other-workspace rejection should happen before remote calls")
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

func TestServiceAccountLoginRejectsExistingControlPlaneSession(t *testing.T) {
	tmp := t.TempDir()
	old := os.Getenv("ASIRI_HOME")
	t.Cleanup(func() { _ = os.Setenv("ASIRI_HOME", old) })
	if err := os.Setenv("ASIRI_HOME", tmp); err != nil {
		t.Fatal(err)
	}

	var out, errb bytes.Buffer
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
	if err := st.LinkControlPlaneForDevice("http://control.test", "org_prod", "prod", "usr_owner", "dev_prod", device.ID, "at", "rt", 3600, time.Now().UTC().Add(24*time.Hour).Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}

	out.Reset()
	errb.Reset()
	if code := app.Run([]string{"service-account", "login", "--workspace", "prod", "--service-account", "prod-api"}); code == 0 {
		t.Fatal("service-account login should reject an existing control-plane session")
	}
	if !strings.Contains(errb.String(), "requires no existing control-plane session") {
		t.Fatalf("unexpected error: %s", errb.String())
	}
}

func TestServiceAccountLoginRejectsMismatchedApproval(t *testing.T) {
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
			var body map[string]string
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if body["workspaceSlug"] != "prod" || body["serviceAccountSlug"] != "prod-api" {
				t.Fatalf("unexpected service-account login request: %#v", body)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"deviceCode":              "dc_service_mismatch",
				"userCode":                "SVCM-1234",
				"verificationUriComplete": serverURL(r) + "/auth/device?code=SVCM-1234",
				"expiresIn":               30,
				"interval":                0,
			})
		case "/v1/auth/device-code/token":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status":             "approved",
				"orgId":              "org_other",
				"workspaceSlug":      "other",
				"userId":             "usr_owner",
				"deviceId":           "dev_other",
				"serviceAccountId":   "svc_prod",
				"serviceAccountSlug": "prod-api",
				"accessToken":        "at_service",
				"refreshToken":       "rt_service",
				"expiresIn":          3600,
				"refreshExpiresAt":   time.Now().UTC().Add(7 * 24 * time.Hour).Format(time.RFC3339),
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	var out, errb bytes.Buffer
	app := New(&out, &errb)
	if code := app.Run([]string{"init", "--device", "service-host"}); code != 0 {
		t.Fatalf("init failed: %s", errb.String())
	}
	out.Reset()
	errb.Reset()
	if code := app.Run([]string{"service-account", "login", "--origin", server.URL, "--workspace", "prod", "--service-account", "prod-api"}); code == 0 {
		t.Fatal("mismatched service-account approval should fail")
	}
	if !strings.Contains(errb.String(), "approved a different workspace or service account") {
		t.Fatalf("unexpected mismatch error: %s", errb.String())
	}
	st, err := store.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	if st.State.ControlPlane != nil {
		t.Fatalf("mismatched approval should not persist a session: %#v", st.State.ControlPlane)
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
		case "/v1/orgs":
			assertWorkspaceOverviewTarget(t, r, "prod")
			_ = json.NewEncoder(w).Encode(map[string]any{"organizations": []map[string]any{{
				"id": "org_setup", "slug": "prod", "role": "owner", "canPull": true, "canWrite": true, "currentDeviceTrusted": true, "currentDeviceId": "dev_remote",
			}}})
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
			assertRequestWorkspace(t, r, "org_setup")
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

func TestServiceAccountRuntimeUsesSyncedServicePolicies(t *testing.T) {
	expiredAt := time.Now().UTC().Add(-time.Minute)
	validUntil := time.Now().UTC().Add(time.Hour)
	st := &store.FileStore{State: asiri.State{
		ControlPlane: &asiri.ControlPlaneLink{Source: "service-account", ServiceAccountID: "svc_prod", ServiceAccountSlug: "prod-api"},
		Policies: []asiri.Policy{{
			ID:            "pol_stale",
			Subject:       "prod-api",
			ScopePattern:  "prod/*",
			SecretPattern: "*",
			Actions:       []string{"read"},
			ApprovalMode:  "none",
			CreatedAt:     time.Now().UTC(),
		}, {
			ID:            "pol_previous_sync",
			Subject:       store.ServiceAccountRuntimeSubject("svc_prod"),
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
	if subject != store.ServiceAccountRuntimeSubject("svc_prod") || labelType != "service" {
		t.Fatalf("service account runtime subject mismatch: subject=%s type=%s", subject, labelType)
	}
	if allowed, _ := st.CheckPolicy(subject, "prod/api/DATABASE_URL", "read"); allowed {
		t.Fatal("synced inject-only service account policy should not allow raw read")
	}
	if allowed, reason := st.CheckPolicy(subject, "prod/api/DATABASE_URL", "inject"); !allowed {
		t.Fatalf("synced service account policy should allow inject: %s", reason)
	}
	var syncedInject *asiri.Policy
	for i := range st.State.Policies {
		if st.State.Policies[i].ID == "pol_inject" {
			syncedInject = &st.State.Policies[i]
			break
		}
	}
	if syncedInject == nil || syncedInject.ExpiresAt == nil || !syncedInject.ExpiresAt.Equal(validUntil) {
		t.Fatalf("synced service account policy should preserve expiry: %#v", syncedInject)
	}
}
