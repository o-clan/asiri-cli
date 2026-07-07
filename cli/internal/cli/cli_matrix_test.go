package cli

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

func TestCLICommandMatrix(t *testing.T) {
	tmp := t.TempDir()
	old := os.Getenv("ASIRI_HOME")
	t.Cleanup(func() { _ = os.Setenv("ASIRI_HOME", old) })
	if err := os.Setenv("ASIRI_HOME", tmp); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	var errb bytes.Buffer
	app := New(&out, &errb)

	expectOK := func(args ...string) string {
		out.Reset()
		errb.Reset()
		if code := app.Run(args); code != 0 {
			t.Fatalf("expected OK for %v, code=%d stderr=%s", args, code, errb.String())
		}
		return out.String()
	}
	expectFail := func(want string, args ...string) {
		out.Reset()
		errb.Reset()
		if code := app.Run(args); code == 0 {
			t.Fatalf("expected failure for %v, stdout=%s", args, out.String())
		}
		if !strings.Contains(errb.String(), want) {
			t.Fatalf("expected stderr to contain %q for %v, got %s", want, args, errb.String())
		}
	}

	if help := expectOK("--help"); !strings.Contains(help, "asiri broker start") || !strings.Contains(help, "pull") || strings.Contains(help, "  sync") {
		t.Fatalf("help missing broker command: %s", help)
	}
	if pullHelp := expectOK("pull", "--help"); !strings.Contains(pullHelp, "Usage: asiri pull") || strings.Contains(pullHelp, "Usage: asiri sync") {
		t.Fatalf("pull help output mismatch: %s", pullHelp)
	}
	for _, check := range []struct {
		args []string
		want []string
	}{
		{[]string{"push", "--help"}, []string{"--workspace <slug>", "specified workspace"}},
		{[]string{"rekey", "--help"}, []string{"--workspace <slug>"}},
		{[]string{"rewrap", "--help"}, []string{"--workspace <slug>"}},
		{[]string{"recovery", "setup", "--help"}, []string{"--workspace <slug>"}},
		{[]string{"recovery", "restore", "--help"}, []string{"--workspace <slug>"}},
		{[]string{"device", "revoke", "--help"}, []string{"--workspace <slug>"}},
		{[]string{"secret", "--help"}, []string{"delete", "restore"}},
		{[]string{"secret", "delete", "--help"}, []string{"--workspace <slug>", "short paths", "--where remote-only", "--confirm-token"}},
		{[]string{"secret", "restore", "--help"}, []string{"--workspace <slug>", "short paths", "--yes"}},
		{[]string{"local", "wipe", "--help"}, []string{"--yes", "never calls remote APIs"}},
		{[]string{"add", "--help"}, []string{"--workspace <slug>", "short paths"}},
		{[]string{"rotate", "--help"}, []string{"--workspace <slug>", "short paths"}},
		{[]string{"rm", "--help"}, []string{"--workspace <slug>", "short paths", "--remote"}},
		{[]string{"grant", "--help"}, []string{"--workspace <slug>", "short paths"}},
		{[]string{"deny", "--help"}, []string{"--workspace <slug>", "short paths"}},
		{[]string{"run", "--help"}, []string{"--workspace <slug>", "short paths"}},
		{[]string{"env", "--help"}, []string{"--workspace <slug>", "short paths"}},
		{[]string{"mount", "--help"}, []string{"--workspace <slug>", "short paths"}},
	} {
		help := expectOK(check.args...)
		for _, want := range check.want {
			if !strings.Contains(help, want) {
				t.Fatalf("help for %v missing %q: %s", check.args, want, help)
			}
		}
	}
	expectFail("unknown help topic", "sync", "--help")
	if version := expectOK("--version"); !strings.Contains(version, "asiri "+Version) {
		t.Fatalf("version output mismatch: %s", version)
	}
	expectOK("init", "--device", "qa-laptop")
	expectFail("unknown command", "sync")
	for _, step := range [][]string{
		{"add", "openai/missing", "--value-file", testSecretFile(t, "value")},
		{"rotate", "openai/missing", "--value-file", testSecretFile(t, "value")},
		{"rm", "openai/missing"},
		{"secret", "delete", "openai/missing"},
		{"grant", "codex", "openai/missing", "--inject-only"},
		{"deny", "codex", "openai/*"},
		{"run", "--env", "API_KEY=openai/missing", "--", "sh", "-c", "true"},
		{"env", "openai/missing", "--", "sh", "-c", "true"},
		{"mount", "openai/missing", "--", "sh", "-c", "true"},
		{"device", "revoke", "dev_remote", "--remote"},
	} {
		expectFail("requires --workspace", step...)
	}
	if devices := expectOK("device", "list"); !strings.Contains(devices, "qa-laptop") || !strings.Contains(devices, "trusted") {
		t.Fatalf("device list missing enrolled trusted device: %s", devices)
	}
	expectFail("--value is unsafe", "add", "--workspace", "qa", "openai/leaky", "--value", "qa_secret_value")
	expectFail("unknown option", "secret", "delete", "--workspace", "qa", "openai/api_key", "--force")
	expectFail("does not accept scope/name", "secret", "delete", "--workspace", "qa", "--remote-only-unwrapped", "openai/api_key")
	expectFail("add accepts short paths", "add", "--workspace", "qa", "qa/openai/full_path", "--value-file", testSecretFile(t, "qa_nested_scope_value"))
	app.In = strings.NewReader("stdin_secret_value\n")
	expectOK("add", "--workspace", "qa", "openai/stdin_key", "--stdin")
	app.In = os.Stdin
	if value := expectOK("get", "--workspace", "qa", "openai/stdin_key"); strings.TrimSpace(value) != "stdin_secret_value" {
		t.Fatalf("stdin secret get returned %q", value)
	}
	expectOK("add", "--workspace", "qa", "openai/api_key", "--value-file", testSecretFile(t, "qa_secret_value"))
	if listing := expectOK("list", "openai", "--workspace", "qa"); !strings.Contains(listing, "openai/api_key") || !strings.Contains(listing, "sn_") {
		t.Fatalf("list missing secret metadata: %s", listing)
	}
	if listing := expectOK("list", "--status", "local-only", "--workspace", "qa"); !strings.Contains(listing, "openai/api_key") {
		t.Fatalf("status-only list missing local secret metadata: %s", listing)
	}
	expectFail("list accepts short paths", "list", "qa/openai", "--workspace", "qa")
	expectFail("must be a workspace slug", "add", "--workspace", "org_qa", "openai/not_a_slug", "--value-file", testSecretFile(t, "qa_secret_value"))
	if value := expectOK("get", "--workspace", "qa", "openai/api_key"); strings.TrimSpace(value) != "qa_secret_value" {
		t.Fatalf("human get returned %q", value)
	}
	expectFail("reserved for human identity", "get", "--workspace", "qa", "openai/api_key", "--agent", "local-human")
	expectFail("reserved for human identity", "grant", "--workspace", "qa", "local-human", "openai/api_key", "--read")
	expectOK("grant", "--workspace", "qa", "codex", "openai/api_key", "--inject-only")
	expectFail("raw read requires", "get", "--workspace", "qa", "openai/api_key", "--agent", "codex")
	expectOK("grant", "--workspace", "qa", "analyst", "openai/api_key", "--read")
	if value := expectOK("get", "--workspace", "qa", "openai/api_key", "--agent", "analyst"); strings.TrimSpace(value) != "qa_secret_value" {
		t.Fatalf("explicit agent read grant failed: %q", value)
	}
	expectOK("deny", "--workspace", "qa", "prod-bot", "prod/*")
	expectOK("grant", "--workspace", "qa", "prod-bot", "openai/api_key", "--inject-only")
	expectOK("deny", "--workspace", "qa", "blocked-bot", "openai/*")
	expectOK("grant", "--workspace", "qa", "blocked-bot", "openai/api_key", "--inject-only")
	expectFail("access denied by owner policy", "run", "--workspace", "qa", "--agent", "blocked-bot", "--env", "OPENAI_API_KEY=openai/api_key", "--", "sh", "-c", "true")
	expectFail("requires --workspace", "run", "--agent", "codex", "sh", "-c", "test asiri://openai/api_key = qa_secret_value")
	expectFail("argument substitution is disabled", "run", "--workspace", "qa", "--agent", "codex", "sh", "-c", "test asiri://openai/api_key = qa_secret_value")
	expectOK("run", "--workspace", "qa", "--agent", "codex", "--unsafe-argv", "sh", "-c", "test $1 = qa_secret_value", "sh", "asiri://openai/api_key")
	if policies := expectOK("policy", "list"); !strings.Contains(policies, "codex") || !strings.Contains(policies, "analyst") || !strings.Contains(policies, "prod-bot") {
		t.Fatalf("policy list missing grants/denies: %s", policies)
	}
	expectOK("run", "--workspace", "qa", "--agent", "codex", "--env", "OPENAI_API_KEY=openai/api_key", "--", "sh", "-c", "test \"$OPENAI_API_KEY\" = qa_secret_value")
	expectFail("requires --workspace", "broker", "start", "--once")
	expectOK("rotate", "--workspace", "qa", "openai/api_key", "--value-file", testSecretFile(t, "qa_rotated_value"))
	if value := expectOK("get", "--workspace", "qa", "openai/api_key"); strings.TrimSpace(value) != "qa_rotated_value" {
		t.Fatalf("rotated get returned %q", value)
	}
	if audit := expectOK("audit", "tail", "--limit", "20"); !strings.Contains(audit, "secret_rotated") || !strings.Contains(audit, "secret_injected") || !strings.Contains(audit, "secret_read") {
		t.Fatalf("audit tail missing expected events: %s", audit)
	}
	expectFail("last trusted local device", "device", "revoke", "qa-laptop")
	expectOK("rm", "--workspace", "qa", "openai/api_key")
	expectOK("rm", "--workspace", "qa", "openai/stdin_key")
	if listing := expectOK("list", "openai", "--workspace", "qa"); strings.Contains(listing, "openai/api_key") {
		t.Fatalf("removed secret still listed: %s", listing)
	}
	expectOK("device", "revoke", "qa-laptop")
	if devices := expectOK("device", "list", "--include-revoked"); !strings.Contains(devices, "revoked") {
		t.Fatalf("device revoke not reflected in list: %s", devices)
	}
	expectOK("cache", "wipe")
	expectFail("asiri is not initialized", "audit", "tail")
	expectOK("init", "--device", "qa-laptop")
	expectOK("local", "wipe", "--yes")
	expectFail("asiri is not initialized", "audit", "tail")
}
