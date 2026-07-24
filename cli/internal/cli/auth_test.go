package cli

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/o-clan/asiri/cli/internal/asiri"
	"github.com/o-clan/asiri/cli/internal/keystore"
	"github.com/o-clan/asiri/cli/internal/store"
)

func TestDetectedDeviceKindUsesReliableRuntimeSignals(t *testing.T) {
	tests := []struct {
		name      string
		goos      string
		container bool
		env       map[string]string
		want      string
	}{
		{name: "mac laptop", goos: "darwin", want: "laptop"},
		{name: "windows laptop", goos: "windows", want: "laptop"},
		{name: "github actions", goos: "linux", env: map[string]string{"GITHUB_ACTIONS": "true"}, want: "ci"},
		{name: "generic ci", goos: "linux", env: map[string]string{"CI": "1"}, want: "ci"},
		{name: "linux container", goos: "linux", container: true, want: "server"},
		{name: "linux ssh", goos: "linux", env: map[string]string{"SSH_CONNECTION": "client server"}, want: "server"},
		{name: "headless linux", goos: "linux", want: "server"},
		{name: "desktop linux", goos: "linux", env: map[string]string{"DISPLAY": ":0"}, want: "laptop"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			getenv := func(key string) string { return test.env[key] }
			if got := detectedDeviceKind(test.goos, getenv, test.container); got != test.want {
				t.Fatalf("detected kind %q, want %q", got, test.want)
			}
		})
	}
}

func TestParseInitArgsAcceptsExplicitDeviceKind(t *testing.T) {
	name, kind, workspace, err := parseInitArgs([]string{"--device", "octo-staging-host", "--kind", "server"})
	if err != nil {
		t.Fatal(err)
	}
	if name != "octo-staging-host" || kind != "server" || workspace != "" {
		t.Fatalf("unexpected init options: name=%q kind=%q workspace=%q", name, kind, workspace)
	}
	if _, _, _, err := parseInitArgs([]string{"--kind", "hostname-guess"}); err == nil {
		t.Fatal("invalid device kind accepted")
	}
}

func TestInitFallsBackToLocalFileKeyStoreWhenPlatformKeyringUnavailable(t *testing.T) {
	tmp := t.TempDir()
	oldHome := os.Getenv("ASIRI_HOME")
	t.Cleanup(func() {
		_ = os.Setenv("ASIRI_HOME", oldHome)
		keystore.ClearConfiguredFileKeyStoreDir()
	})
	_ = os.Setenv("ASIRI_HOME", tmp)
	keystore.ClearConfiguredFileKeyStoreDir()
	restoreFailure := keystore.FailPlatformOperationsForTesting(keystore.ErrPlatformUnavailable, nil, nil)
	t.Cleanup(restoreFailure)

	var out, errb bytes.Buffer
	app := New(&out, &errb)
	if code := app.Run([]string{"init", "--device", "headless-box", "--kind", "server", "--workspace", "personal"}); code != 0 {
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
	device, err := st.ActiveDevice()
	if err != nil {
		t.Fatal(err)
	}
	if device.Kind != "server" {
		t.Fatalf("explicit device kind was not persisted: %q", device.Kind)
	}
	keyStoreDir := store.DefaultFileKeyStoreDir(statePath)
	entries, err := os.ReadDir(keyStoreDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 3 {
		t.Fatalf("expected device private keys and audit ledger key in file keystore, got %d entries", len(entries))
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

func TestInitDoesNotFallbackOnTemporaryKeychainFailures(t *testing.T) {
	for _, test := range []struct {
		name string
		err  error
	}{
		{name: "authentication", err: keystore.ErrPlatformAuthentication},
		{name: "timeout", err: keystore.ErrPlatformTimeout},
	} {
		t.Run(test.name, func(t *testing.T) {
			tmp := t.TempDir()
			oldHome := os.Getenv("ASIRI_HOME")
			t.Cleanup(func() {
				_ = os.Setenv("ASIRI_HOME", oldHome)
				keystore.ClearConfiguredFileKeyStoreDir()
			})
			_ = os.Setenv("ASIRI_HOME", tmp)
			keystore.ClearConfiguredFileKeyStoreDir()
			restoreFailure := keystore.FailPlatformOperationsForTesting(test.err, nil, nil)
			t.Cleanup(restoreFailure)

			var out, errb bytes.Buffer
			app := New(&out, &errb)
			if code := app.Run([]string{"init", "--device", "mac", "--kind", "laptop"}); code == 0 {
				t.Fatal("init unexpectedly succeeded")
			}
			if strings.Contains(out.String(), "file key store") || keystore.FileKeyStoreDir() != "" {
				t.Fatalf("temporary failure triggered file-store fallback: %s", out.String())
			}
			if _, err := os.Stat(filepath.Join(tmp, "local-state.json")); !os.IsNotExist(err) {
				t.Fatalf("temporary failure persisted local state: %v", err)
			}
			if !strings.Contains(errb.String(), "Refresh the Keychain") {
				t.Fatalf("missing friendly recovery guidance: %s", errb.String())
			}
		})
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

func TestLoginRejectsWorkspaceSelection(t *testing.T) {
	if err := validateLoginArgs([]string{"--workspace", "prod"}); err == nil || !strings.Contains(err.Error(), "does not accept --workspace") {
		t.Fatalf("expected account login to reject workspace selection, got %v", err)
	}
	if err := validateLoginArgs([]string{"--origin", "http://127.0.0.1:4173", "unexpected"}); err == nil || !strings.Contains(err.Error(), "unknown login argument") {
		t.Fatalf("expected unknown login argument rejection, got %v", err)
	}
}

func TestLoginForceRevokesDisplacedServerSession(t *testing.T) {
	tmp := t.TempDir()
	old := os.Getenv("ASIRI_HOME")
	t.Cleanup(func() { _ = os.Setenv("ASIRI_HOME", old) })
	if err := os.Setenv("ASIRI_HOME", tmp); err != nil {
		t.Fatal(err)
	}

	logoutSeen := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		switch r.URL.Path {
		case "/v1/auth/session/logout":
			var body map[string]string
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if body["refreshToken"] != "rt_old" || r.Header.Get("x-asiri-device") != "dev_old" {
				t.Fatalf("forced login revoked the wrong session: body=%#v device=%s", body, r.Header.Get("x-asiri-device"))
			}
			logoutSeen = true
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "logged_out"})
		case "/v1/auth/device-code/start":
			if !logoutSeen {
				t.Fatal("forced login started replacement before revoking the existing session")
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"deviceCode": "dc_new", "userCode": "NEW1-2345",
				"verificationUriComplete": serverURL(r) + "/auth/device?code=NEW1-2345",
				"expiresIn":               30, "interval": 0,
			})
		case "/v1/auth/device-code/token":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status": "approved", "orgId": "org_new", "workspaceSlug": "new",
				"userId": "usr_new", "deviceId": "dev_new",
				"accessToken": "at_new", "refreshToken": "rt_new", "expiresIn": 3600,
				"refreshExpiresAt": time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339),
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
	if err := st.LinkControlPlaneForDevice(server.URL, "org_old", "old", "usr_old", "dev_old", device.ID, "at_old", "rt_old", 3600, time.Now().UTC().Add(24*time.Hour).Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}

	out.Reset()
	errb.Reset()
	if code := app.Run([]string{"login", "--force", "--origin", server.URL}); code != 0 {
		t.Fatalf("forced login failed: %s", errb.String())
	}
	if !logoutSeen {
		t.Fatal("forced login did not revoke the displaced server session")
	}
	reloaded, err := store.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	refreshToken, err := reloaded.ControlPlaneRefreshToken()
	if err != nil {
		t.Fatal(err)
	}
	if refreshToken != "rt_new" || reloaded.State.ControlPlane == nil || reloaded.State.ControlPlane.DeviceID != "dev_new" {
		t.Fatalf("forced login did not persist only the replacement session: %#v token=%s", reloaded.State.ControlPlane, refreshToken)
	}
}

func TestLoginForceFailsBeforeReplacementWhenServerLogoutFails(t *testing.T) {
	tmp := t.TempDir()
	old := os.Getenv("ASIRI_HOME")
	t.Cleanup(func() { _ = os.Setenv("ASIRI_HOME", old) })
	if err := os.Setenv("ASIRI_HOME", tmp); err != nil {
		t.Fatal(err)
	}
	startSeen := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		switch r.URL.Path {
		case "/v1/auth/session/logout":
			w.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": "temporarily_unavailable"})
		case "/v1/auth/device-code/start":
			startSeen = true
			http.Error(w, "unexpected replacement", http.StatusInternalServerError)
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
	if err := st.LinkControlPlaneForDevice(server.URL, "org_old", "old", "usr_old", "dev_old", device.ID, "at_old", "rt_old", 3600, time.Now().UTC().Add(24*time.Hour).Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}

	out.Reset()
	errb.Reset()
	if code := app.Run([]string{"login", "--force", "--origin", server.URL}); code == 0 {
		t.Fatal("forced login should fail when the displaced session cannot be revoked")
	}
	if startSeen || !strings.Contains(errb.String(), "cannot replace the existing control-plane session safely") {
		t.Fatalf("forced login did not fail safely: start=%v stderr=%s", startSeen, errb.String())
	}
	reloaded, err := store.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	refreshToken, err := reloaded.ControlPlaneRefreshToken()
	if err != nil {
		t.Fatal(err)
	}
	if refreshToken != "rt_old" || reloaded.State.ControlPlane == nil || reloaded.State.ControlPlane.DeviceID != "dev_old" {
		t.Fatalf("failed forced login changed the existing session: %#v token=%s", reloaded.State.ControlPlane, refreshToken)
	}
}

func TestLoginRequiresForceToChangeControlPlaneOrigin(t *testing.T) {
	tmp := t.TempDir()
	old := os.Getenv("ASIRI_HOME")
	t.Cleanup(func() { _ = os.Setenv("ASIRI_HOME", old) })
	if err := os.Setenv("ASIRI_HOME", tmp); err != nil {
		t.Fatal(err)
	}
	requestSeen := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestSeen = true
		http.Error(w, "unexpected request", http.StatusInternalServerError)
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
	if err := st.LinkControlPlaneForDevice("http://old-control.test", "org_old", "old", "usr_old", "dev_old", device.ID, "at_old", "rt_old", 3600, time.Now().UTC().Add(24*time.Hour).Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}

	out.Reset()
	errb.Reset()
	if code := app.Run([]string{"login", "--origin", server.URL}); code == 0 {
		t.Fatal("login should require --force before changing control-plane origin")
	}
	if requestSeen || !strings.Contains(errb.String(), "linked to a different origin") {
		t.Fatalf("origin replacement did not fail safely: request=%v stderr=%s", requestSeen, errb.String())
	}
}

func TestLoginRecoversExpiredSessionWithoutForce(t *testing.T) {
	tmp := t.TempDir()
	old := os.Getenv("ASIRI_HOME")
	t.Cleanup(func() { _ = os.Setenv("ASIRI_HOME", old) })
	if err := os.Setenv("ASIRI_HOME", tmp); err != nil {
		t.Fatal(err)
	}
	refreshSeen := false
	startSeen := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		switch r.URL.Path {
		case "/v1/auth/session/refresh":
			refreshSeen = true
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": "invalid_refresh_token"})
		case "/v1/auth/device-code/start":
			if !refreshSeen {
				t.Fatal("login started replacement before checking the existing session")
			}
			startSeen = true
			_ = json.NewEncoder(w).Encode(map[string]any{
				"deviceCode": "dc_recovery", "userCode": "RCVR-1234",
				"verificationUriComplete": serverURL(r) + "/auth/device?code=RCVR-1234",
				"expiresIn":               30, "interval": 0,
			})
		case "/v1/auth/device-code/token":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status": "approved", "orgId": "org_new", "workspaceSlug": "new",
				"userId": "usr_new", "deviceId": "dev_new",
				"accessToken": "at_new", "refreshToken": "rt_new", "expiresIn": 3600,
				"refreshExpiresAt": time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339),
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
	secret, err := st.AddSecret("old/local/API_KEY", "preserved-secret")
	if err != nil {
		t.Fatal(err)
	}
	dataKeyAccount := secret.Versions[0].DataKeyAccount
	if err := st.LinkControlPlaneForDevice(server.URL, "org_old", "old", "usr_old", "dev_old", device.ID, "at_old", "rt_old", 3600, time.Now().UTC().Add(24*time.Hour).Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}

	out.Reset()
	errb.Reset()
	if code := app.Run([]string{"login", "--origin", server.URL}); code != 0 {
		t.Fatalf("expired-session recovery failed: %s", errb.String())
	}
	if !refreshSeen || !startSeen {
		t.Fatalf("expired-session recovery did not complete: refresh=%v start=%v", refreshSeen, startSeen)
	}
	reloaded, err := store.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	refreshToken, err := reloaded.ControlPlaneRefreshToken()
	if err != nil {
		t.Fatal(err)
	}
	if refreshToken != "rt_new" {
		t.Fatalf("expired-session recovery did not persist replacement credentials: %s", refreshToken)
	}
	if value, _, err := reloaded.GetSecret("old/local/API_KEY"); err != nil || value != "preserved-secret" {
		t.Fatalf("expired-session recovery changed the local secret: value=%q err=%v", value, err)
	}
	if got := reloaded.State.Secrets[store.SecretKey("old/local", "API_KEY")].Versions[0].DataKeyAccount; got != dataKeyAccount {
		t.Fatalf("expired-session recovery changed the data-key account: got=%q want=%q", got, dataKeyAccount)
	}
}

func TestLoginTrustFailuresPreserveLocalVaultAndGiveSafeRecovery(t *testing.T) {
	for _, tc := range []struct {
		name          string
		errorCode     string
		message       string
		expectsEnroll bool
	}{
		{name: "revoked keys", errorCode: "device_revoked", message: "device has been revoked", expectsEnroll: true},
		{name: "untrusted session", errorCode: "device_not_trusted", expectsEnroll: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
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
				case "/v1/auth/session/refresh":
					w.WriteHeader(http.StatusForbidden)
					_ = json.NewEncoder(w).Encode(map[string]any{"error": tc.errorCode, "message": tc.message})
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
			secret, err := st.AddSecret("prod/local/API_KEY", "preserved-secret")
			if err != nil {
				t.Fatal(err)
			}
			dataKeyAccount := secret.Versions[0].DataKeyAccount
			if err := st.LinkControlPlaneForDevice(server.URL, "org_prod", "prod", "usr_owner", "dev_remote", device.ID, "at_old", "rt_old", 3600, time.Now().UTC().Add(24*time.Hour).Format(time.RFC3339)); err != nil {
				t.Fatal(err)
			}
			keyRefsBefore := append([]asiri.KeyRef(nil), st.State.KeyRefs...)

			out.Reset()
			errb.Reset()
			if code := app.Run([]string{"login", "--origin", server.URL}); code == 0 {
				t.Fatal("login should fail until the linked device state is recovered")
			}
			if deviceCodeStarted {
				t.Fatal("login should not start another device code with the rejected linked session")
			}
			guidance := errb.String()
			if tc.expectsEnroll {
				requireOrderedText(t, guidance, "asiri logout", "asiri device enroll --name <new-name>", "asiri login --origin "+server.URL)
			} else {
				requireOrderedText(t, guidance, "asiri logout", "asiri login --origin "+server.URL)
				if strings.Contains(guidance, "device enroll") {
					t.Fatalf("generic untrusted-session recovery should keep existing device keys: %s", guidance)
				}
			}
			if !strings.Contains(guidance, "local vault") || !strings.Contains(guidance, "preserved") {
				t.Fatalf("recovery guidance should confirm local vault preservation: %s", guidance)
			}

			reloaded, err := store.LoadDefault()
			if err != nil {
				t.Fatal(err)
			}
			if reloaded.State.ControlPlane == nil || reloaded.State.LocalDeviceID != device.ID {
				t.Fatalf("trust failure changed the linked session or local device: %#v", reloaded.State.ControlPlane)
			}
			if !reflect.DeepEqual(reloaded.State.KeyRefs, keyRefsBefore) {
				t.Fatalf("trust failure changed local key refs: got=%#v want=%#v", reloaded.State.KeyRefs, keyRefsBefore)
			}
			if got := reloaded.State.Secrets[store.SecretKey("prod/local", "API_KEY")].Versions[0].DataKeyAccount; got != dataKeyAccount {
				t.Fatalf("trust failure changed the data-key account: got=%q want=%q", got, dataKeyAccount)
			}
			if value, _, err := reloaded.GetSecret("prod/local/API_KEY"); err != nil || value != "preserved-secret" {
				t.Fatalf("trust failure made the local secret unusable: value=%q err=%v", value, err)
			}
		})
	}
}

func TestRefreshAccessTrustFailurePreservesLocalVault(t *testing.T) {
	tmp := t.TempDir()
	old := os.Getenv("ASIRI_HOME")
	t.Cleanup(func() { _ = os.Setenv("ASIRI_HOME", old) })
	if err := os.Setenv("ASIRI_HOME", tmp); err != nil {
		t.Fatal(err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		if r.URL.Path != "/v1/auth/session/refresh" {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]any{"error": "device_not_trusted"})
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
	secret, err := st.AddSecret("prod/local/API_KEY", "preserved-secret")
	if err != nil {
		t.Fatal(err)
	}
	dataKeyAccount := secret.Versions[0].DataKeyAccount
	if err := st.LinkControlPlaneForDevice(server.URL, "org_prod", "prod", "usr_owner", "dev_remote", device.ID, "at_old", "rt_old", 3600, time.Now().UTC().Add(24*time.Hour).Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
	keyRefsBefore := append([]asiri.KeyRef(nil), st.State.KeyRefs...)

	if _, err := refreshControlPlaneAccess(server.URL, st); err == nil {
		t.Fatal("refresh should fail for an untrusted linked session")
	} else {
		guidance := err.Error()
		requireOrderedText(t, guidance, "asiri logout", "asiri login --origin "+server.URL)
		if strings.Contains(guidance, "device enroll") {
			t.Fatalf("generic untrusted-session refresh should keep existing device keys: %s", guidance)
		}
	}

	reloaded, err := store.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(reloaded.State.KeyRefs, keyRefsBefore) {
		t.Fatalf("refresh trust failure changed local key refs: got=%#v want=%#v", reloaded.State.KeyRefs, keyRefsBefore)
	}
	if got := reloaded.State.Secrets[store.SecretKey("prod/local", "API_KEY")].Versions[0].DataKeyAccount; got != dataKeyAccount {
		t.Fatalf("refresh trust failure changed the data-key account: got=%q want=%q", got, dataKeyAccount)
	}
	if value, _, err := reloaded.GetSecret("prod/local/API_KEY"); err != nil || value != "preserved-secret" {
		t.Fatalf("refresh trust failure made the local secret unusable: value=%q err=%v", value, err)
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
	for _, expected := range []string{"peter@example.com", "Peter Owner", "LOCAL DEVICE", "qa-laptop", "AUTH DEVICE", "dev_remote"} {
		if !strings.Contains(got, expected) {
			t.Fatalf("whoami output missing %q: %s", expected, got)
		}
	}
	if strings.Contains(got, "WORKSPACE") || strings.Contains(got, "oclan-co") {
		t.Fatalf("user whoami should not report workspace selection: %s", got)
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

func TestInitAcceptsWorkspaceSlug(t *testing.T) {
	tmp := t.TempDir()
	old := os.Getenv("ASIRI_HOME")
	t.Cleanup(func() { _ = os.Setenv("ASIRI_HOME", old) })
	if err := os.Setenv("ASIRI_HOME", tmp); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	var errb bytes.Buffer
	app := New(&out, &errb)
	if code := app.Run([]string{"init", "--workspace", "xai-dev", "--device", "qa-laptop"}); code != 0 {
		t.Fatalf("init should accept a local workspace slug: %s", errb.String())
	}
	st, err := store.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	workspace, ok := st.LocalWorkspace("xai-dev")
	if !ok || workspace.CanonicalSlug != "xai-dev" {
		t.Fatalf("expected xai-dev local workspace, got %#v", st.State.Workspaces)
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
	expectedKind := detectedDeviceKind(runtime.GOOS, os.Getenv, runningInContainer())
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		switch r.URL.Path {
		case "/v1/auth/device-code/start":
			startSeen = true
			var body map[string]string
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if body["localWorkspaceSlug"] != "" || body["workspaceSlug"] != "" || body["deviceName"] != "qa-laptop" || body["kind"] != expectedKind || body["encryptionPublicKey"] == "" || body["signingPublicKey"] == "" {
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
		case "/v1/orgs":
			assertWorkspaceOverviewTarget(t, r, "oclan-co")
			_ = json.NewEncoder(w).Encode(map[string]any{"organizations": []map[string]any{{
				"id": "org_remote", "slug": "oclan-co", "role": "owner", "canPull": true, "canWrite": true, "currentDeviceTrusted": true, "currentDeviceId": "dev_remote",
			}}})
		case "/v1/devices":
			if r.URL.Query().Get("orgId") != "org_remote" {
				t.Fatalf("unexpected remote device query: %s", r.URL.RawQuery)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"devices": []map[string]any{{"id": "dev_other", "name": "ci-runner", "status": "trusted"}}})
		case "/v1/devices/dev_other/revoke":
			remoteRevokeSeen = true
			if r.Header.Get("authorization") != "Bearer at_refreshed" {
				t.Fatalf("unexpected remote revoke auth header: %s", r.Header.Get("authorization"))
			}
			assertRequestWorkspace(t, r, "org_remote")
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
	if !strings.Contains(out.String(), "ABCD-2345") || !strings.Contains(out.String(), "control-plane account") {
		t.Fatalf("login output missing code or account confirmation: %s", out.String())
	}
	st, err := store.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	if st.State.ControlPlane == nil || st.State.ControlPlane.DeviceID != "dev_remote" || st.State.ControlPlane.WorkspaceSlug != "oclan-co" {
		t.Fatalf("control-plane link not persisted: %#v", st.State.ControlPlane)
	}
	if len(st.State.Workspaces) != 0 {
		t.Fatalf("control-plane-first login created local workspaces: %#v", st.State.Workspaces)
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
