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
		{"init", "--device", "qa-laptop", "--workspace", "oclan-co"},
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
	if !strings.Contains(out.String(), "cannot be decrypted by this device") {
		t.Fatalf("rewrap output missing skip result: %s", out.String())
	}
}

func TestRewrapUsesAccessibleRemoteVersionWhenLocalVersionIsOlder(t *testing.T) {
	tmp := t.TempDir()
	old := os.Getenv("ASIRI_HOME")
	t.Cleanup(func() { _ = os.Setenv("ASIRI_HOME", old) })
	if err := os.Setenv("ASIRI_HOME", tmp); err != nil {
		t.Fatal(err)
	}
	devicePublicKey := ""
	var remoteSourceWrapped store.RemoteWrappedKey
	var writtenKeys []store.RemoteWrappedKey
	malformedRemote := false
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
				"deviceCode":              "dc_rewrap_remote",
				"userCode":                "REMOTE-1234",
				"verificationUriComplete": serverURL(r) + "/auth/device?code=REMOTE-1234",
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
				"accessToken":      "at_rewrap_remote",
				"refreshToken":     "rt_rewrap_remote",
				"expiresIn":        3600,
				"refreshExpiresAt": time.Now().UTC().Add(7 * 24 * time.Hour).Format(time.RFC3339),
			})
		case "/v1/orgs":
			_ = json.NewEncoder(w).Encode(map[string]any{"organizations": []map[string]any{{
				"id": "org_remote", "slug": "oclan-co", "role": "owner", "canPull": true, "canWrite": true,
				"currentDeviceTrusted": true, "currentDeviceId": "dev_remote",
			}}})
		case "/v1/secrets":
			_ = json.NewEncoder(w).Encode(map[string]any{"secrets": []map[string]any{{
				"id": "secv_remote_newer", "orgId": "org_remote", "scope": "oclan-co/local/asiri", "name": "API_KEY",
				"version": 2, "status": "active", "wrappedRecipients": []map[string]any{{
					"recipientType": "device", "recipientId": "dev_remote", "wrapAlgorithm": "p256-hkdf-aes256gcm",
				}},
			}}})
		case "/v1/secrets/encrypted":
			wrappedKeys := []store.RemoteWrappedKey{remoteSourceWrapped}
			if malformedRemote {
				wrappedKeys = []store.RemoteWrappedKey{{RecipientType: "device", RecipientID: "dev_remote", WrapAlgorithm: "p256-hkdf-aes256gcm", WrappedKey: "malformed"}}
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"secrets": []map[string]any{{
				"id": "secv_remote_newer", "orgId": "org_remote", "scope": "oclan-co/local/asiri", "name": "API_KEY",
				"version": 2, "status": "active", "wrappedKeys": wrappedKeys,
			}}})
		case "/v1/devices/wrapping-targets":
			_ = json.NewEncoder(w).Encode(map[string]any{"targets": []map[string]any{{
				"secretId": "secv_remote_newer", "devices": []map[string]any{{
					"id": "dev_other", "name": "server", "status": "trusted", "kind": "server", "encryptionPublicKey": devicePublicKey,
				}},
			}}})
		case "/v1/secrets/wrapped-keys/batch":
			var body struct {
				Entries []remoteWrappedKeyBatchEntry `json:"entries"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if len(body.Entries) != 1 || body.Entries[0].SecretID != "secv_remote_newer" {
				t.Fatalf("unexpected batch body: %#v", body)
			}
			writtenKeys = body.Entries[0].WrappedKeys
			_ = json.NewEncoder(w).Encode(map[string]any{"updated": 1, "added": 1})
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
	secretKey := store.SecretKey("oclan-co/local/asiri", "API_KEY")
	originalSecret := st.State.Secrets[secretKey]
	originalSecret.Versions = append(originalSecret.Versions[:0:0], originalSecret.Versions...)
	if _, err := st.AddSecret("oclan-co/local/asiri/API_KEY", "remote_newer_value"); err != nil {
		t.Fatal(err)
	}
	remoteSourceWrapped, err = st.RemoteWrappedKeyForSecretVersionPublicKey("org_remote", "oclan-co/local/asiri", "API_KEY", 2, "dev_remote", devicePublicKey)
	if err != nil {
		t.Fatal(err)
	}
	expectedKey, err := st.UnwrapDeviceDataKey("dev_remote", []store.RemoteWrappedKey{remoteSourceWrapped})
	if err != nil {
		t.Fatal(err)
	}
	st.State.Secrets[secretKey] = originalSecret
	if err := st.Save(); err != nil {
		t.Fatal(err)
	}

	out.Reset()
	errb.Reset()
	if code := app.Run([]string{"rewrap", "--workspace", "oclan-co"}); code != 0 {
		t.Fatalf("rewrap failed with code %d stderr=%s", code, errb.String())
	}
	if len(writtenKeys) != 1 || writtenKeys[0].RecipientID != "dev_other" {
		t.Fatalf("expected one wrapped key for remote target, got %#v", writtenKeys)
	}
	actualKey, err := st.UnwrapDeviceDataKey("dev_other", writtenKeys)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(actualKey, expectedKey) {
		t.Fatal("rewrap did not preserve the remote version data key")
	}
	reloaded, err := store.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	if !localSecretVersionExists(reloaded, "oclan-co/local/asiri", "API_KEY", 1) || localSecretVersionExists(reloaded, "oclan-co/local/asiri", "API_KEY", 2) {
		t.Fatal("rewrap changed the local secret versions")
	}
	if _, err := reloaded.AddSecret("oclan-co/local/asiri/API_KEY", "conflicting_local_value"); err != nil {
		t.Fatal(err)
	}
	localWrapped, err := reloaded.RemoteWrappedKeyForSecretVersionPublicKey("org_remote", "oclan-co/local/asiri", "API_KEY", 2, "dev_remote", devicePublicKey)
	if err != nil {
		t.Fatal(err)
	}
	localKey, err := reloaded.UnwrapDeviceDataKey("dev_remote", []store.RemoteWrappedKey{localWrapped})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(localKey, expectedKey) {
		t.Fatal("test requires distinct local and remote version keys")
	}
	writtenKeys = nil
	out.Reset()
	errb.Reset()
	if code := app.Run([]string{"rewrap", "--workspace", "oclan-co"}); code != 0 {
		t.Fatalf("rewrap with conflicting local version failed with code %d stderr=%s", code, errb.String())
	}
	actualKey, err = reloaded.UnwrapDeviceDataKey("dev_other", writtenKeys)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(actualKey, expectedKey) || bytes.Equal(actualKey, localKey) {
		t.Fatal("rewrap did not prefer the authoritative remote version key")
	}
	if !strings.Contains(out.String(), "Rewrapped 1 key(s) across 1 secret version(s)") {
		t.Fatalf("rewrap output missing success count: %s", out.String())
	}
	withoutLocalVersion, err := store.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	withoutLocalVersion.State.Secrets[secretKey] = originalSecret
	if err := withoutLocalVersion.Save(); err != nil {
		t.Fatal(err)
	}
	malformedRemote = true
	writtenKeys = nil
	out.Reset()
	errb.Reset()
	if code := app.Run([]string{"rewrap", "--workspace", "oclan-co"}); code == 0 {
		t.Fatalf("rewrap should reject a malformed remote-only wrapped key: %s", out.String())
	}
	if len(writtenKeys) != 0 {
		t.Fatal("rewrap wrote keys after the remote-only source failed to decrypt")
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
	batchTargetsSeen := false
	batchWriteSeen := false
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
		case "/v1/devices/wrapping-targets":
			batchTargetsSeen = true
			http.NotFound(w, r)
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
			_ = json.NewEncoder(w).Encode(map[string]any{"secrets": []map[string]any{{
				"id": "secv_current_missing", "orgId": "org_remote", "scope": "oclan-co/local/asiri", "name": "API_KEY",
				"version": 1, "status": "active", "wrappedKeys": []map[string]any{{
					"recipientType": "device", "recipientId": "dev_remote", "wrapAlgorithm": "p256-hkdf-aes256gcm", "wrappedKey": "malformed",
				}},
			}}})
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
		case "/v1/secrets/wrapped-keys/batch":
			batchWriteSeen = true
			http.NotFound(w, r)
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
		{"init", "--device", "qa-laptop", "--workspace", "oclan-co"},
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
	if !batchTargetsSeen || !batchWriteSeen {
		t.Fatalf("expected batch endpoint compatibility probes, got targets=%t writes=%t", batchTargetsSeen, batchWriteSeen)
	}
	if !strings.Contains(out.String(), "Rewrapped 1") {
		t.Fatalf("rewrap output missing success count: %s", out.String())
	}
}

func TestRewrapUsesBatchTargetsAndWrites(t *testing.T) {
	tmp := t.TempDir()
	old := os.Getenv("ASIRI_HOME")
	t.Cleanup(func() { _ = os.Setenv("ASIRI_HOME", old) })
	if err := os.Setenv("ASIRI_HOME", tmp); err != nil {
		t.Fatal(err)
	}
	devicePublicKey := ""
	targetRequests := 0
	batchWriteRequests := 0
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
				"deviceCode": "dc_rewrap_batch", "userCode": "BATCH-1234",
				"verificationUriComplete": serverURL(r) + "/auth/device?code=BATCH-1234", "expiresIn": 30, "interval": 0,
			})
		case "/v1/auth/device-code/token":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status": "approved", "orgId": "org_remote", "workspaceSlug": "oclan-co", "userId": "usr_owner",
				"deviceId": "dev_remote", "accessToken": "at_rewrap_batch", "refreshToken": "rt_rewrap_batch",
				"expiresIn": 3600, "refreshExpiresAt": time.Now().UTC().Add(7 * 24 * time.Hour).Format(time.RFC3339),
			})
		case "/v1/orgs":
			_ = json.NewEncoder(w).Encode(map[string]any{"organizations": []map[string]any{{
				"id": "org_remote", "slug": "oclan-co", "role": "owner", "canPull": true, "canWrite": true,
				"currentDeviceTrusted": true, "currentDeviceId": "dev_remote",
			}}})
		case "/v1/secrets":
			_ = json.NewEncoder(w).Encode(map[string]any{"secrets": []map[string]any{
				{"id": "sec_batch_one", "orgId": "org_remote", "scope": "oclan-co/local/asiri", "name": "API_KEY", "version": 1, "status": "active", "wrappedRecipients": []map[string]any{{"recipientType": "device", "recipientId": "dev_old", "wrapAlgorithm": "p256-hkdf-aes256gcm"}}},
				{"id": "sec_batch_two", "orgId": "org_remote", "scope": "oclan-co/prod/api", "name": "OTHER_KEY", "version": 1, "status": "active", "wrappedRecipients": []map[string]any{{"recipientType": "device", "recipientId": "dev_old", "wrapAlgorithm": "p256-hkdf-aes256gcm"}}},
			}})
		case "/v1/devices/wrapping-targets":
			targetRequests++
			device := map[string]any{"id": "dev_remote", "name": "qa-laptop", "status": "trusted", "kind": "laptop", "encryptionPublicKey": devicePublicKey}
			_ = json.NewEncoder(w).Encode(map[string]any{"targets": []map[string]any{
				{"secretId": "sec_batch_one", "devices": []map[string]any{device}},
				{"secretId": "sec_batch_two", "devices": []map[string]any{device}},
			}})
		case "/v1/secrets/wrapped-keys/batch":
			batchWriteRequests++
			var body struct {
				Entries []remoteWrappedKeyBatchEntry `json:"entries"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if len(body.Entries) != 2 || len(body.Entries[0].WrappedKeys) != 1 || len(body.Entries[1].WrappedKeys) != 1 {
				t.Fatalf("unexpected batch body: %#v", body)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"updated": 2, "added": 2})
		case "/v1/secrets/encrypted":
			_ = json.NewEncoder(w).Encode(map[string]any{"secrets": []map[string]any{}})
		case "/v1/devices", "/v1/secrets/sec_batch_one/wrapped-keys", "/v1/secrets/sec_batch_two/wrapped-keys":
			t.Fatalf("rewrap used legacy endpoint %s", r.URL.Path)
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
		{"add", "--workspace", "oclan-co", "local/asiri/API_KEY", "--value-file", testSecretFile(t, "secret_value")},
		{"add", "--workspace", "oclan-co", "prod/api/OTHER_KEY", "--value-file", testSecretFile(t, "other_value")},
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
	if targetRequests != 1 || batchWriteRequests != 1 {
		t.Fatalf("expected one target and one write request, got targets=%d writes=%d", targetRequests, batchWriteRequests)
	}
	if !strings.Contains(out.String(), "Rewrapped 2 key(s) across 2 secret version(s)") {
		t.Fatalf("rewrap output missing batch counts: %s", out.String())
	}
}
