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
		case "/v1/orgs":
			assertWorkspaceOverviewTarget(t, r, "oclan-co")
			_ = json.NewEncoder(w).Encode(map[string]any{"organizations": []map[string]any{{
				"id": "org_remote", "slug": "oclan-co", "role": "owner", "canPull": true, "canWrite": true, "currentDeviceTrusted": true, "currentDeviceId": "dev_remote",
			}}})
		case "/v1/devices":
			if r.URL.Query().Get("scope") != "oclan-co/local/asiri" || r.URL.Query().Get("secretName") != "API_KEY" {
				t.Fatalf("rewrap targets must be requested for one secret: %s", r.URL.RawQuery)
			}
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
		case "/v1/orgs":
			assertWorkspaceOverviewTarget(t, r, "oclan-co")
			_ = json.NewEncoder(w).Encode(map[string]any{"organizations": []map[string]any{{
				"id": "org_remote", "slug": "oclan-co", "role": "owner", "canPull": true, "canWrite": true, "currentDeviceTrusted": true, "currentDeviceId": "dev_remote",
			}}})
		case "/v1/devices":
			if r.URL.Query().Get("scope") != "oclan-co/local/asiri" || r.URL.Query().Get("secretName") != "API_KEY" {
				t.Fatalf("rewrap targets must be requested for one secret: %s", r.URL.RawQuery)
			}
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
