package cli

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/o-clan/asiri/cli/internal/asiri"
	"github.com/o-clan/asiri/cli/internal/store"
)

func TestEnvSingleSecretExport(t *testing.T) {
	tmp := t.TempDir()
	oldHome := os.Getenv("ASIRI_HOME")
	t.Cleanup(func() { _ = os.Setenv("ASIRI_HOME", oldHome) })
	_ = os.Setenv("ASIRI_HOME", tmp)
	var out, errb bytes.Buffer
	app := New(&out, &errb)
	for _, step := range [][]string{
		{"init", "--device", "qa-laptop", "--workspace", "qa"},
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
		{"init", "--device", "qa-laptop", "--workspace", "qa"},
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
		{"init", "--device", "qa-laptop", "--workspace", "qa"},
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
	setup := [][]string{{"init", "--device", "qa-laptop", "--workspace", "qa"}, {"add", "--workspace", "qa", "cloudflare/BAD-NAME", "--value-file", testSecretFile(t, "bad_secret")}, {"grant", "--workspace", "qa", "tool", "cloudflare/BAD-NAME", "--inject-only"}, {"add", "--workspace", "qa", "cloudflare/WRANGLER_SECRET", "--value-file", testSecretFile(t, "env_secret")}}
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
		{"init", "--device", "qa-laptop", "--workspace", "qa"},
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
		{"init", "--device", "qa-laptop", "--workspace", "qa"},
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
		{"init", "--device", "qa-laptop", "--workspace", "qa"},
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
	for _, step := range [][]string{{"init", "--device", "qa-laptop", "--workspace", "qa"}, {"add", "--workspace", "qa", "cloudflare/WRANGLER_SECRET", "--value-file", testSecretFile(t, "mounted_secret")}} {
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
