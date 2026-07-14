package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

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
	if code := app.Run([]string{"audit", "tail", "--workspace", "qa", "--limit", "5"}); code != 0 {
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
	if code := app.Run([]string{"audit", "tail", "--workspace", "qa", "--limit", "5"}); code != 0 {
		t.Fatalf("audit failed: %s", errb.String())
	}
	if !strings.Contains(out.String(), "wrangler") || !strings.Contains(out.String(), "secret_injected") {
		t.Fatalf("audit missing explicit env mapping injection event: %s", out.String())
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
	if code := app.Run([]string{"audit", "tail", "--workspace", "qa", "--limit", "5"}); code != 0 {
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
