package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/o-clan/asiri/cli/internal/keystore"
	"github.com/o-clan/asiri/cli/internal/store"
)

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
		{"grant", "--workspace", "qa", "codex", "openai/api_key", "--broker"},
		{"run", "--workspace", "qa", "--agent", "codex", "--env", "OPENAI_API_KEY=openai/api_key", "--", "sh", "-c", "test \"$OPENAI_API_KEY\" = qa_secret_value"},
	}
	for _, step := range steps {
		if code := app.Run(step); code != 0 {
			t.Fatalf("%v failed with code %d stderr=%s", step, code, errb.String())
		}
	}
	brokerApp := New(io.Discard, io.Discard)
	resp, payload := runBrokerValueRequest(t, brokerApp, map[string]string{
		"requestId": "req_allowed",
		"workspace": "qa",
		"subject":   "codex",
		"path":      "openai/api_key",
	}, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("broker request failed status=%d body=%s", resp.StatusCode, payload)
	}
	var brokerResponse map[string]string
	if err := json.Unmarshal([]byte(payload), &brokerResponse); err != nil {
		t.Fatal(err)
	}
	if brokerResponse["value"] != "qa_secret_value" {
		t.Fatalf("broker returned wrong value")
	}
	resp, payload = runBrokerValueRequest(t, brokerApp, map[string]string{
		"requestId": "req_bad_token",
		"workspace": "qa",
		"subject":   "codex",
		"path":      "openai/api_key",
	}, "bad-token")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("broker bad token returned status=%d body=%s", resp.StatusCode, payload)
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

func TestEnvExportInvalidNameDoesNotAuditMaterialization(t *testing.T) {
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
		{"add", "--workspace", "qa", "app/api-key", "--value-file", testSecretFile(t, "env_secret")},
		{"grant", "--workspace", "qa", "sh", "app/api-key", "--inject-only"},
	} {
		out.Reset()
		errb.Reset()
		if code := app.Run(step); code != 0 {
			t.Fatalf("%v failed with code %d stderr=%s", step, code, errb.String())
		}
	}

	out.Reset()
	errb.Reset()
	if code := app.Run([]string{"env", "--workspace", "qa", "app", "--", "sh", "-c", "true"}); code == 0 {
		t.Fatal("env export should fail for invalid environment variable name")
	}
	st, err := store.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	for _, event := range st.State.Audit {
		if event.Action == "secret_env_exported" && event.Result == "allowed" {
			t.Fatalf("invalid env export must not audit allowed materialization: %#v", event)
		}
	}
}

func TestMountExplicitDestinationScopeDoesNotAuditMaterialization(t *testing.T) {
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
		{"add", "--workspace", "qa", "app/ONE", "--value-file", testSecretFile(t, "one")},
		{"add", "--workspace", "qa", "app/TWO", "--value-file", testSecretFile(t, "two")},
		{"grant", "--workspace", "qa", "sh", "app/ONE", "--mount"},
		{"grant", "--workspace", "qa", "sh", "app/TWO", "--mount"},
	} {
		out.Reset()
		errb.Reset()
		if code := app.Run(step); code != 0 {
			t.Fatalf("%v failed with code %d stderr=%s", step, code, errb.String())
		}
	}

	out.Reset()
	errb.Reset()
	dest := filepath.Join(tmp, "mounted-secret")
	if code := app.Run([]string{"mount", "--workspace", "qa", "app:" + dest, "--", "sh", "-c", "true"}); code == 0 {
		t.Fatal("scope mount with explicit destination should fail")
	}
	st, err := store.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	for _, event := range st.State.Audit {
		if event.Action == "secret_mounted" && event.Result == "allowed" {
			t.Fatalf("invalid mount must not audit allowed materialization: %#v", event)
		}
	}
}

func TestRuntimePreflightBlocksPartialMaterialization(t *testing.T) {
	for _, tc := range []struct {
		name        string
		grant       []string
		run         func(marker string) []string
		auditAction string
	}{
		{
			name:  "explicit env mapping",
			grant: []string{"grant", "--workspace", "qa", "sh", "app/ONE", "--inject-only"},
			run: func(marker string) []string {
				return []string{"run", "--workspace", "qa", "--env", "ONE=app/ONE", "--env", "TWO=app/TWO", "--", "sh", "-c", "touch " + marker}
			},
			auditAction: "secret_injected",
		},
		{
			name:  "env export",
			grant: []string{"grant", "--workspace", "qa", "sh", "app/ONE", "--inject-only"},
			run: func(marker string) []string {
				return []string{"env", "--workspace", "qa", "app", "--", "sh", "-c", "touch " + marker}
			},
			auditAction: "secret_env_exported",
		},
		{
			name:  "unsafe argv",
			grant: []string{"grant", "--workspace", "qa", "sh", "app/ONE", "--inject-only"},
			run: func(marker string) []string {
				return []string{"run", "--workspace", "qa", "--unsafe-argv", "--", "sh", "-c", "test asiri://app/ONE = one && test asiri://app/TWO = two && touch " + marker}
			},
			auditAction: "secret_unsafe_argv_injected",
		},
		{
			name:  "mount scope",
			grant: []string{"grant", "--workspace", "qa", "sh", "app/ONE", "--mount"},
			run: func(marker string) []string {
				return []string{"mount", "--workspace", "qa", "--dir", filepath.Join(filepath.Dir(marker), "mount-dir"), "app", "--", "sh", "-c", "touch " + marker}
			},
			auditAction: "secret_mounted",
		},
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
			for _, step := range [][]string{
				{"init", "--device", "qa-laptop"},
				{"add", "--workspace", "qa", "app/ONE", "--value-file", testSecretFile(t, "one")},
				{"add", "--workspace", "qa", "app/TWO", "--value-file", testSecretFile(t, "two")},
				tc.grant,
			} {
				out.Reset()
				errb.Reset()
				if code := app.Run(step); code != 0 {
					t.Fatalf("%v failed with code %d stderr=%s", step, code, errb.String())
				}
			}

			marker := filepath.Join(tmp, "ran")
			out.Reset()
			errb.Reset()
			if code := app.Run(tc.run(marker)); code == 0 {
				t.Fatal("partial materialization should fail before executing child command")
			}
			if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("child command executed after failed preflight: %v", err)
			}
			st, err := store.LoadDefault()
			if err != nil {
				t.Fatal(err)
			}
			for _, event := range st.State.Audit {
				if event.Action == tc.auditAction && event.Result == "allowed" {
					t.Fatalf("failed preflight must not audit allowed materialization: %#v", event)
				}
			}
		})
	}
}

func TestUnusableSecretDoesNotAuditAllowedMaterialization(t *testing.T) {
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
		{"add", "--workspace", "qa", "app/ONE", "--value-file", testSecretFile(t, "one")},
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
	secret := st.State.Secrets[store.SecretKey("qa/app", "ONE")]
	if len(secret.Versions) == 0 || secret.Versions[0].DataKeyAccount == "" {
		t.Fatalf("test secret missing data key account: %#v", secret)
	}
	if err := keystore.Delete(secret.Versions[0].DataKeyAccount); err != nil {
		t.Fatal(err)
	}

	out.Reset()
	errb.Reset()
	if code := app.Run([]string{"get", "--workspace", "qa", "app/ONE"}); code == 0 {
		t.Fatal("get should fail when local key material is missing")
	}
	st, err = store.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	foundFailed := false
	for _, event := range st.State.Audit {
		if event.Action != "secret_read" {
			continue
		}
		if event.Result == "allowed" {
			t.Fatalf("unusable secret must not audit allowed release: %#v", event)
		}
		if event.Result == "failed" {
			foundFailed = true
		}
	}
	if !foundFailed {
		t.Fatal("expected failed audit for unusable secret")
	}
}

func TestAuditTailShowsLocalStatusForLocalOnlyEvents(t *testing.T) {
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
		t.Fatalf("init failed with code %d stderr=%s", code, errb.String())
	}
	if code := app.Run([]string{"add", "--workspace", "qa", "local/TEST", "--value-file", testSecretFile(t, "test")}); code != 0 {
		t.Fatalf("add failed with code %d stderr=%s", code, errb.String())
	}
	out.Reset()
	errb.Reset()
	if code := app.Run([]string{"audit", "tail", "--workspace", "qa", "--limit", "5"}); code != 0 {
		t.Fatalf("audit tail failed with code %d stderr=%s", code, errb.String())
	}
	if strings.Contains(out.String(), "\tpending\t") {
		t.Fatalf("local-only audit rows should not be shown as pending: %s", out.String())
	}
	if !strings.Contains(out.String(), "\tsecret_created\tallowed\tlocal\t") {
		t.Fatalf("expected local audit status, got: %s", out.String())
	}
}

func TestBrokerReloadsLocalStateBetweenRequests(t *testing.T) {
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
		{"add", "--workspace", "qa", "openai/api_key", "--value-file", testSecretFile(t, "old_secret")},
		{"grant", "--workspace", "qa", "codex", "openai/api_key", "--broker"},
	} {
		if code := app.Run(step); code != 0 {
			t.Fatalf("%v failed with code %d stderr=%s", step, code, errb.String())
		}
	}
	clientFile := filepath.Join(t.TempDir(), "broker-client.json")
	done := make(chan int, 1)
	go func() {
		done <- New(io.Discard, io.Discard).Run([]string{"broker", "start", "--workspace", "qa", "--agent", "codex", "--listen", "127.0.0.1:0", "--client-file", clientFile, "--idle-timeout", "1s", "--token-ttl", "30s"})
	}()
	cfg := waitForBrokerClientConfig(t, clientFile)
	resp, payload := postBrokerValueRequest(t, cfg, map[string]string{
		"requestId": "req_old",
		"workspace": "qa",
		"subject":   "codex",
		"path":      "openai/api_key",
	}, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("broker old request failed status=%d body=%s", resp.StatusCode, payload)
	}
	var body map[string]string
	if err := json.Unmarshal([]byte(payload), &body); err != nil {
		t.Fatal(err)
	}
	if body["value"] != "old_secret" {
		t.Fatalf("broker returned old request value %q", body["value"])
	}
	if code := app.Run([]string{"rotate", "--workspace", "qa", "openai/api_key", "--value-file", testSecretFile(t, "new_secret")}); code != 0 {
		t.Fatalf("rotate failed with code %d stderr=%s", code, errb.String())
	}
	resp, payload = postBrokerValueRequest(t, cfg, map[string]string{
		"requestId": "req_new",
		"workspace": "qa",
		"subject":   "codex",
		"path":      "openai/api_key",
	}, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("broker new request failed status=%d body=%s", resp.StatusCode, payload)
	}
	body = map[string]string{}
	if err := json.Unmarshal([]byte(payload), &body); err != nil {
		t.Fatal(err)
	}
	if body["value"] != "new_secret" {
		t.Fatalf("broker did not reload rotated value: %q", body["value"])
	}
	select {
	case code := <-done:
		if code != 0 {
			t.Fatalf("broker exited with code %d", code)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("broker did not stop after idle timeout")
	}
	out.Reset()
	errb.Reset()
	if code := app.Run([]string{"get", "--workspace", "qa", "openai/api_key"}); code != 0 {
		t.Fatalf("get after broker stop failed with code %d stderr=%s", code, errb.String())
	}
	if strings.TrimSpace(out.String()) != "new_secret" {
		t.Fatalf("broker stop overwrote rotated value: %q", out.String())
	}
}

func TestBrokerRequiresExplicitBrokerGrant(t *testing.T) {
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
		{"add", "--workspace", "qa", "openai/api_key", "--value-file", testSecretFile(t, "qa_secret_value")},
		{"grant", "--workspace", "qa", "codex", "openai/api_key", "--inject-only"},
	} {
		if code := app.Run(step); code != 0 {
			t.Fatalf("%v failed with code %d stderr=%s", step, code, errb.String())
		}
	}
	resp, payload := runBrokerValueRequest(t, New(io.Discard, io.Discard), map[string]string{
		"requestId": "req_no_broker_grant",
		"workspace": "qa",
		"subject":   "codex",
		"path":      "openai/api_key",
	}, "")
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("broker without grant returned status=%d body=%s", resp.StatusCode, payload)
	}
	if strings.Contains(payload, "qa_secret_value") {
		t.Fatalf("broker denial leaked secret: %s", payload)
	}
	out.Reset()
	if audit := app.Run([]string{"audit", "tail", "--workspace", "qa", "--limit", "10"}); audit != 0 {
		t.Fatalf("audit tail failed")
	}
	if !strings.Contains(out.String(), "secret_brokered") {
		t.Fatalf("audit tail missing broker denial: %s", out.String())
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
