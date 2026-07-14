package cli

import (
	"bytes"
	"strings"
	"testing"
)

func TestParseBrokerStartArgsRejectsInvalidDurations(t *testing.T) {
	for _, flag := range []string{"--token-ttl", "--idle-timeout", "--max-runtime"} {
		if _, err := parseBrokerStartArgs([]string{"--workspace", "qa", "--agent", "codex", flag, "0s"}); err == nil {
			t.Fatalf("%s accepted zero duration", flag)
		}
		if _, err := parseBrokerStartArgs([]string{"--workspace", "qa", "--agent", "codex", flag, "-1s"}); err == nil {
			t.Fatalf("%s accepted negative duration", flag)
		}
	}
}

func TestWorkspaceParsersRejectDuplicateWorkspaceFlags(t *testing.T) {
	tests := []struct {
		name  string
		parse func() error
	}{
		{name: "service account create", parse: func() error {
			_, err := parseServiceAccountCreateArgs([]string{"--workspace", "prod", "--workspace", "other"})
			return err
		}},
		{name: "service account list", parse: func() error {
			_, err := parseServiceAccountSelectArgs([]string{"--workspace", "prod", "--workspace", "other"}, "list")
			return err
		}},
		{name: "service account grant", parse: func() error {
			_, err := parseServiceAccountGrantArgs([]string{"--workspace", "prod", "--workspace", "other"})
			return err
		}},
		{name: "device trust", parse: func() error {
			_, err := parseDeviceTrustArgs([]string{"--workspace", "prod", "--workspace", "other"})
			return err
		}},
		{name: "broker start aliases", parse: func() error {
			_, err := parseBrokerStartArgs([]string{"--workspace", "prod", "-w", "other"})
			return err
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := test.parse(); err == nil || !strings.Contains(err.Error(), "accepts one --workspace") {
				t.Fatalf("expected duplicate workspace rejection, got %v", err)
			}
		})
	}
}

func TestDefaultControlPlaneOriginMatchesLocalDev(t *testing.T) {
	if defaultControlPlaneOrigin != "http://127.0.0.1:4173" {
		t.Fatalf("source default control-plane origin must match local dev, got %s", defaultControlPlaneOrigin)
	}
}

func TestLoginHelpDistinguishesSessionReplacementFromKeyRecovery(t *testing.T) {
	var out, errb bytes.Buffer
	app := New(&out, &errb)
	if code := app.Run([]string{"help", "login"}); code != 0 {
		t.Fatalf("login help failed: %s", errb.String())
	}
	help := out.String()
	for _, expected := range []string{"expired session", "--force", "does not create new device keys"} {
		if !strings.Contains(help, expected) {
			t.Fatalf("login help missing %q: %s", expected, help)
		}
	}
	requireOrderedText(t, help, "asiri logout", "asiri device enroll --name <new-name>", "asiri login")

	out.Reset()
	errb.Reset()
	if code := app.Run([]string{"help", "logout"}); code != 0 {
		t.Fatalf("logout help failed: %s", errb.String())
	}
	for _, expected := range []string{"local vault", "secrets", "device keys", "preserved"} {
		if !strings.Contains(out.String(), expected) {
			t.Fatalf("logout help missing %q: %s", expected, out.String())
		}
	}
}
