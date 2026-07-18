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

func TestFreshLocalUserIsPromptedToCreateWorkspace(t *testing.T) {
	tmp := t.TempDir()
	old := os.Getenv("ASIRI_HOME")
	t.Cleanup(func() { _ = os.Setenv("ASIRI_HOME", old) })
	if err := os.Setenv("ASIRI_HOME", tmp); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	app := New(&out, &errb)
	if code := app.Run([]string{"init", "--device", "offline-laptop"}); code != 0 {
		t.Fatalf("init failed: %s", errb.String())
	}
	if !strings.Contains(out.String(), "asiri login") || !strings.Contains(out.String(), "asiri workspace create <slug>") {
		t.Fatalf("init did not explain hosted and offline onboarding: %s", out.String())
	}
	out.Reset()
	errb.Reset()
	if code := app.Run([]string{"workspace", "list"}); code != 0 {
		t.Fatalf("workspace list failed: %s", errb.String())
	}
	if !strings.Contains(out.String(), "asiri workspace create <slug>") {
		t.Fatalf("empty workspace list did not suggest workspace creation: %s", out.String())
	}
	if strings.Contains(out.String(), "DEFAULT") {
		t.Fatalf("workspace list still exposes removed default state: %s", out.String())
	}
	out.Reset()
	errb.Reset()
	if code := app.Run([]string{"list"}); code == 0 {
		t.Fatal("list without a workspace succeeded")
	}
	if !strings.Contains(errb.String(), "list requires --workspace <slug>") || !strings.Contains(errb.String(), "asiri workspace create <slug>") {
		t.Fatalf("list did not explain how to create a workspace: %s", errb.String())
	}
	for _, command := range [][]string{{"audit", "tail", "--workspace", "offline-dev"}, {"policy", "list", "--workspace", "offline-dev"}} {
		out.Reset()
		errb.Reset()
		if code := app.Run(command); code == 0 {
			t.Fatalf("%v accepted an uncreated offline workspace", command)
		}
		if !strings.Contains(errb.String(), "asiri workspace create offline-dev") {
			t.Fatalf("%v did not guide offline workspace creation: %s", command, errb.String())
		}
	}
}

func TestOfflineWorkspaceCreateAliasAndExplicitList(t *testing.T) {
	tmp := t.TempDir()
	old := os.Getenv("ASIRI_HOME")
	t.Cleanup(func() { _ = os.Setenv("ASIRI_HOME", old) })
	if err := os.Setenv("ASIRI_HOME", tmp); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	app := New(&out, &errb)
	steps := [][]string{
		{"init", "--device", "offline-laptop", "--workspace", "xai-dev"},
		{"workspace", "create", "another-dev"},
		{"workspace", "alias", "set", "--workspace", "xai-dev", "xai"},
		{"add", "--workspace", "xai", "app/API_KEY", "--value-file", testSecretFile(t, "offline-secret")},
	}
	for _, step := range steps {
		out.Reset()
		errb.Reset()
		if code := app.Run(step); code != 0 {
			t.Fatalf("%v failed: %s", step, errb.String())
		}
	}
	out.Reset()
	errb.Reset()
	if code := app.Run([]string{"list"}); code == 0 {
		t.Fatal("list without a workspace succeeded after local workspaces existed")
	}
	if !strings.Contains(errb.String(), "list requires --workspace <slug>") {
		t.Fatalf("bare list did not retain the explicit workspace requirement: %s", errb.String())
	}
	out.Reset()
	errb.Reset()
	if code := app.Run([]string{"workspace", "default", "xai-dev"}); code == 0 {
		t.Fatal("removed workspace default command succeeded")
	}
	if !strings.Contains(errb.String(), "unknown workspace command") {
		t.Fatalf("removed workspace default command returned an unexpected error: %s", errb.String())
	}
	out.Reset()
	errb.Reset()
	if code := app.Run([]string{"list", "--workspace", "xai"}); code != 0 {
		t.Fatalf("offline list failed: %s", errb.String())
	}
	if !strings.Contains(out.String(), "xai-dev") || !strings.Contains(out.String(), "app/API_KEY") {
		t.Fatalf("explicit offline list missed local workspace secret: %s", out.String())
	}
	out.Reset()
	errb.Reset()
	if code := app.Run([]string{"workspace", "alias", "set", "--workspace", "another-dev", "xai"}); code == 0 {
		t.Fatal("duplicate local alias accepted")
	}
	if !strings.Contains(errb.String(), "already in use") {
		t.Fatalf("unexpected alias collision error: %s", errb.String())
	}
}

func TestFirstSyncCanonicalizesLocalWorkspaceAndKeepsAlias(t *testing.T) {
	tmp := t.TempDir()
	old := os.Getenv("ASIRI_HOME")
	t.Cleanup(func() { _ = os.Setenv("ASIRI_HOME", old) })
	if err := os.Setenv("ASIRI_HOME", tmp); err != nil {
		t.Fatal(err)
	}
	aliasPutCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		switch r.URL.Path {
		case "/v1/auth/device-code/start":
			_ = json.NewEncoder(w).Encode(map[string]any{"deviceCode": "dc_sync", "userCode": "SYNC-123", "verificationUriComplete": serverURL(r) + "/auth/device?code=SYNC-123", "expiresIn": 30, "interval": 0})
		case "/v1/auth/device-code/token":
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "approved", "orgId": "org_personal", "workspaceSlug": "person-example-com", "userId": "usr_owner", "deviceId": "dev_personal", "accessToken": "at_sync", "refreshToken": "rt_sync", "expiresIn": 3600, "refreshExpiresAt": time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339)})
		case "/v1/workspaces/sync":
			var body map[string]string
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if body["localWorkspaceId"] == "" || body["localSlug"] != "xai-dev" || body["alias"] != "xai" {
				t.Fatalf("unexpected sync body: %#v", body)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"id": "org_synced", "slug": "xai-dev-8dhc3udj", "canonicalSlug": "xai-dev-8dhc3udj", "alias": "xai", "kind": "custom", "ownerUserId": "usr_owner", "role": "owner", "canWrite": true, "currentDeviceTrusted": true, "currentDeviceId": "dev_synced"})
		case "/v1/orgs":
			if r.URL.Query().Get("workspace") != "org_synced" {
				t.Fatalf("unexpected workspace target: %s", r.URL.RawQuery)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"organizations": []map[string]any{{"id": "org_synced", "slug": "xai-dev-8dhc3udj", "canonicalSlug": "xai-dev-8dhc3udj", "alias": "xai", "kind": "custom", "role": "owner", "canWrite": true, "currentDeviceTrusted": true, "currentDeviceId": "dev_synced"}}})
		case "/v1/workspaces/org_synced/alias":
			aliasPutCount++
			_ = json.NewEncoder(w).Encode(map[string]any{"id": "org_synced", "slug": "xai-dev-8dhc3udj", "canonicalSlug": "xai-dev-8dhc3udj", "alias": "xai-renamed", "kind": "custom", "role": "owner", "canWrite": true, "currentDeviceTrusted": true, "currentDeviceId": "dev_synced"})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	var out, errb bytes.Buffer
	app := New(&out, &errb)
	for _, step := range [][]string{
		{"init", "--device", "offline-laptop", "--workspace", "xai-dev"},
		{"workspace", "alias", "set", "--workspace", "xai-dev", "xai"},
		{"add", "--workspace", "xai-dev", "app/API_KEY", "--value-file", testSecretFile(t, "offline-secret")},
		{"login", "--origin", server.URL},
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
	out.Reset()
	_, _, dryRunStop, err := app.prepareLocalWorkspacePush(st, pushOptions{Workspace: "xai-dev", DryRun: true}, "at_sync")
	if err != nil || !dryRunStop || !strings.Contains(out.String(), "alias xai would be retained") {
		t.Fatalf("dry-run did not report the selected alias: stop=%v err=%v out=%s", dryRunStop, err, out.String())
	}
	out.Reset()
	options, _, stop, err := app.prepareLocalWorkspacePush(st, pushOptions{Workspace: "xai-dev"}, "at_sync")
	if err != nil {
		t.Fatal(err)
	}
	if stop || options.Workspace != "xai-dev-8dhc3udj" {
		t.Fatalf("unexpected canonicalization result: options=%#v stop=%v", options, stop)
	}
	workspace, ok := st.LocalWorkspace("xai")
	if !ok || workspace.CanonicalSlug != "xai-dev-8dhc3udj" || workspace.Alias != "xai" || workspace.RemoteWorkspaceID != "org_synced" {
		t.Fatalf("unexpected local workspace after sync: %#v", workspace)
	}
	if _, _, err := st.GetSecret("xai-dev-8dhc3udj/app/API_KEY"); err != nil {
		t.Fatalf("canonical secret unavailable after sync: %v", err)
	}
	out.Reset()
	errb.Reset()
	if code := app.Run([]string{"workspace", "create", "taken-alias"}); code != 0 {
		t.Fatalf("local collision workspace setup failed: %s", errb.String())
	}
	out.Reset()
	errb.Reset()
	if code := app.Run([]string{"workspace", "alias", "set", "--workspace", "xai", "taken-alias"}); code == 0 {
		t.Fatal("hosted alias update accepted a local identity collision")
	}
	if aliasPutCount != 0 {
		t.Fatal("hosted alias collision was detected after mutating the control plane")
	}
	out.Reset()
	errb.Reset()
	if code := app.Run([]string{"workspace", "alias", "set", "--workspace", "xai", "xai-renamed"}); code != 0 {
		t.Fatalf("hosted alias update failed: %s", errb.String())
	}
	if aliasPutCount != 1 {
		t.Fatal("hosted alias update did not reach the control plane")
	}
	reloaded, err := store.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	updated, ok := reloaded.LocalWorkspace("xai-renamed")
	if !ok || updated.RemoteWorkspaceID != "org_synced" {
		t.Fatalf("updated hosted alias did not resolve locally: %#v", updated)
	}
}
