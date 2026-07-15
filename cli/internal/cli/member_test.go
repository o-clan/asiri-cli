package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/o-clan/asiri/cli/internal/store"
)

func TestMemberCommandArgumentValidation(t *testing.T) {
	t.Run("member list", func(t *testing.T) {
		for _, args := range [][]string{
			{},
			{"--workspace"},
			{"--workspace", "prod", "--workspace", "other"},
			{"--workspace", "prod", "--unexpected"},
		} {
			if _, err := parseMemberListArgs(args); err == nil {
				t.Fatalf("member list should reject %#v", args)
			}
		}
		options, err := parseMemberListArgs([]string{"--workspace", "prod", "--all", "--origin", "https://control.test"})
		if err != nil || options.Workspace != "prod" || !options.All {
			t.Fatalf("valid member list arguments did not parse: options=%#v err=%v", options, err)
		}
	})

	t.Run("access list", func(t *testing.T) {
		for _, args := range [][]string{
			{},
			{"--workspace", "prod", "--member"},
			{"--workspace", "prod", "--member", "one@example.test", "--member", "usr_one"},
			{"--workspace", "prod", "--unexpected"},
		} {
			if _, err := parseMemberAccessListArgs(args); err == nil {
				t.Fatalf("member access list should reject %#v", args)
			}
		}
		options, err := parseMemberAccessListArgs([]string{"--workspace", "prod", "--member", "one@example.test", "--all"})
		if err != nil || options.Workspace != "prod" || options.Member != "one@example.test" || !options.All {
			t.Fatalf("valid member access list arguments did not parse: options=%#v err=%v", options, err)
		}
	})

	t.Run("access grant", func(t *testing.T) {
		for _, args := range [][]string{
			{},
			{"--workspace", "prod", "--envelope", "api"},
			{"--workspace", "prod", "--member", "one@example.test"},
			{"--workspace", "prod", "--member", "one@example.test", "--envelope", "api", "--secret", "api/KEY"},
			{"--workspace", "prod", "--member", "one@example.test", "--secret", "api/KEY", "--include-descendants"},
			{"--workspace", "prod", "--member", "one@example.test", "--envelope"},
			{"--workspace", "prod", "--member", "one@example.test", "--envelope", "api", "--unexpected"},
		} {
			if _, err := parseMemberAccessGrantArgs(args); err == nil {
				t.Fatalf("member access grant should reject %#v", args)
			}
		}
		options, err := parseMemberAccessGrantArgs([]string{"--workspace", "prod", "--member", "one@example.test", "--envelope", "api", "--include-descendants"})
		if err != nil || options.Envelope != "api" || !options.IncludeDescendants {
			t.Fatalf("valid envelope grant arguments did not parse: options=%#v err=%v", options, err)
		}
		options, err = parseMemberAccessGrantArgs([]string{"--workspace", "prod", "--member", "usr_one", "--secret", "api/KEY"})
		if err != nil || options.Secret != "api/KEY" || options.IncludeDescendants {
			t.Fatalf("valid secret grant arguments did not parse: options=%#v err=%v", options, err)
		}
	})

	t.Run("access revoke", func(t *testing.T) {
		for _, args := range [][]string{
			{},
			{"--workspace", "prod"},
			{"--workspace", "prod", "--grant"},
			{"--workspace", "prod", "--grant", "grant_one", "--grant", "grant_two"},
			{"--workspace", "prod", "--grant", "grant_one", "--unexpected"},
		} {
			if _, err := parseMemberAccessRevokeArgs(args); err == nil {
				t.Fatalf("member access revoke should reject %#v", args)
			}
		}
		options, err := parseMemberAccessRevokeArgs([]string{"--workspace", "prod", "--grant", "grant_one"})
		if err != nil || options.Workspace != "prod" || options.GrantID != "grant_one" {
			t.Fatalf("valid revoke arguments did not parse: options=%#v err=%v", options, err)
		}
	})
}

func TestMemberAccessCommandHelpUsesFullPath(t *testing.T) {
	var out bytes.Buffer
	var errb bytes.Buffer
	app := New(&out, &errb)
	if code := app.Run([]string{"member", "access", "grant", "--help"}); code != 0 {
		t.Fatalf("member access grant help failed: %s", errb.String())
	}
	if !strings.Contains(out.String(), "asiri member access grant") || !strings.Contains(out.String(), "--include-descendants") {
		t.Fatalf("member access grant help returned the wrong topic: %s", out.String())
	}
}

func TestSafeMemberOutputSanitizesTerminalControlCharacters(t *testing.T) {
	hostile := "Mallory\x1b]8;;https://evil.test\a\nOWNER\t\u202espoof"
	safe := safeMemberOutput(hostile)
	for _, forbidden := range []string{"\x1b", "\a", "\n", "\t", "\u202e"} {
		if strings.Contains(safe, forbidden) {
			t.Fatalf("member output retained terminal control %q: %q", forbidden, safe)
		}
	}
	if !strings.Contains(safe, "Mallory") || !strings.Contains(safe, "OWNER") {
		t.Fatalf("member output lost readable identity text: %q", safe)
	}
}

type memberCommandTestGrant struct {
	ID                 string `json:"id"`
	OrgID              string `json:"orgId"`
	UserID             string `json:"userId"`
	TargetType         string `json:"targetType"`
	Scope              string `json:"scope"`
	SecretName         string `json:"secretName,omitempty"`
	IncludeDescendants bool   `json:"includeDescendants"`
	Status             string `json:"status"`
	GrantedByUserID    string `json:"grantedByUserId"`
	CreatedAt          string `json:"createdAt"`
	RevokedAt          string `json:"revokedAt,omitempty"`
}

func TestTrustedHumanCLIManagesMemberAccess(t *testing.T) {
	tmp := t.TempDir()
	old := os.Getenv("ASIRI_HOME")
	t.Cleanup(func() { _ = os.Setenv("ASIRI_HOME", old) })
	if err := os.Setenv("ASIRI_HOME", tmp); err != nil {
		t.Fatal(err)
	}

	members := []map[string]any{
		{
			"id": "membership_owner", "orgId": "org_prod", "userId": "usr_owner", "role": "owner", "status": "active",
			"userEmail": "owner@example.test", "userDisplayName": "Peter Owner", "accessToken": "member_response_token_sentinel",
		},
		{
			"id": "membership_alex", "orgId": "org_prod", "userId": "usr_alex", "role": "member", "status": "active",
			"userEmail": "alex@example.test", "userDisplayName": "Alex Morgan", "wrappedDek": "wrapped_dek_sentinel",
		},
	}
	grants := []memberCommandTestGrant{}
	grantPostCalls := 0
	grantCreateCount := 0
	revokePostCalls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		if !assertMemberCommandSignedRequest(t, r) {
			http.Error(w, "unsigned request", http.StatusUnauthorized)
			return
		}
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/orgs":
			if r.URL.Query().Get("workspace") != "prod" {
				t.Errorf("workspace lookup used the wrong target: %s", r.URL.RawQuery)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"organizations": []map[string]any{{
				"id": "org_prod", "slug": "prod", "role": "owner", "canPull": true, "canWrite": true,
				"currentDeviceTrusted": true, "currentDeviceId": "dev_remote",
			}}})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/members":
			if r.URL.Query().Get("orgId") != "org_prod" {
				t.Errorf("member list used the wrong workspace: %s", r.URL.RawQuery)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"members": members, "value": "plaintext_value_sentinel"})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/secret-access-grants":
			if r.URL.Query().Get("orgId") != "org_prod" {
				t.Errorf("access list used the wrong workspace: %s", r.URL.RawQuery)
			}
			visible := grants
			if r.URL.Query().Get("includeInactive") != "1" {
				visible = make([]memberCommandTestGrant, 0, len(grants))
				for _, grant := range grants {
					if grant.Status == "active" {
						visible = append(visible, grant)
					}
				}
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"secretAccessGrants": visible,
				"ciphertext":         "ciphertext_sentinel",
			})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/secret-access-grants":
			grantPostCalls++
			var body struct {
				OrgID              string `json:"orgId"`
				UserID             string `json:"userId"`
				TargetType         string `json:"targetType"`
				Scope              string `json:"scope"`
				SecretName         string `json:"secretName"`
				IncludeDescendants bool   `json:"includeDescendants"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Errorf("decode grant request: %v", err)
				http.Error(w, "invalid json", http.StatusBadRequest)
				return
			}
			if body.OrgID != "org_prod" || body.UserID != "usr_alex" {
				t.Errorf("grant request targeted the wrong member or workspace: %#v", body)
			}
			for _, grant := range grants {
				if grant.Status == "active" && grant.UserID == body.UserID && grant.TargetType == body.TargetType && grant.Scope == body.Scope && grant.SecretName == body.SecretName && grant.IncludeDescendants == body.IncludeDescendants {
					_ = json.NewEncoder(w).Encode(map[string]any{
						"id": grant.ID, "orgId": grant.OrgID, "userId": grant.UserID, "targetType": grant.TargetType,
						"scope": grant.Scope, "secretName": grant.SecretName, "includeDescendants": grant.IncludeDescendants,
						"status": grant.Status, "grantedByUserId": grant.GrantedByUserID, "value": "plaintext_value_sentinel",
					})
					return
				}
			}
			grantCreateCount++
			grant := memberCommandTestGrant{
				ID: fmt.Sprintf("grant_%d", grantCreateCount), OrgID: body.OrgID, UserID: body.UserID,
				TargetType: body.TargetType, Scope: body.Scope, SecretName: body.SecretName,
				IncludeDescendants: body.IncludeDescendants, Status: "active", GrantedByUserID: "usr_owner",
				CreatedAt: time.Now().UTC().Format(time.RFC3339),
			}
			grants = append(grants, grant)
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(grant)
		case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/v1/secret-access-grants/") && strings.HasSuffix(r.URL.Path, "/revoke"):
			revokePostCalls++
			grantID := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/v1/secret-access-grants/"), "/revoke")
			for index := range grants {
				if grants[index].ID == grantID {
					grants[index].Status = "revoked"
					grants[index].RevokedAt = time.Now().UTC().Format(time.RFC3339)
					_ = json.NewEncoder(w).Encode(grants[index])
					return
				}
			}
			http.NotFound(w, r)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	var out bytes.Buffer
	var errb bytes.Buffer
	app := New(&out, &errb)
	if code := app.Run([]string{"init", "--device", "trusted-member-cli"}); code != 0 {
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
	if err := st.LinkControlPlaneForDevice(server.URL, "org_prod", "prod", "usr_owner", "dev_remote", device.ID, "at_member", "rt_member", 3600, time.Now().UTC().Add(7*24*time.Hour).Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}

	var observedOutput strings.Builder
	run := func(args ...string) string {
		t.Helper()
		out.Reset()
		errb.Reset()
		if code := app.Run(args); code != 0 {
			t.Fatalf("%v failed: %s", args, errb.String())
		}
		result := out.String()
		observedOutput.WriteString(result)
		observedOutput.WriteString(errb.String())
		return result
	}

	output := run("member", "list", "--workspace", "prod")
	for _, expected := range []string{"Alex Morgan", "alex@example.test", "usr_alex", "Peter Owner", "owner@example.test", "usr_owner"} {
		if !strings.Contains(output, expected) {
			t.Fatalf("member list omitted %q: %s", expected, output)
		}
	}

	output = run("member", "access", "list", "--workspace", "prod")
	if !strings.Contains(output, "GRANT ID") {
		t.Fatalf("empty access list should still print its header: %s", output)
	}

	output = run("member", "access", "grant", "--workspace", "prod", "--member", "ALEX@EXAMPLE.TEST", "--envelope", "/")
	if grantCreateCount != 1 || grants[0].TargetType != "envelope" || grants[0].Scope != "prod" || grants[0].IncludeDescendants {
		t.Fatalf("root envelope grant was normalized incorrectly: creates=%d grants=%#v", grantCreateCount, grants)
	}
	if !strings.Contains(output, "envelope:/") || !strings.Contains(output, "asiri rewrap --workspace prod") {
		t.Fatalf("root grant output omitted its target or rewrap step: %s", output)
	}

	output = run("member", "access", "grant", "--workspace", "prod", "--member", "alex@example.test", "--envelope", "/")
	if grantPostCalls != 2 || grantCreateCount != 1 || !strings.Contains(output, "already exists") {
		t.Fatalf("duplicate grant should be idempotent: posts=%d creates=%d output=%s", grantPostCalls, grantCreateCount, output)
	}

	run("member", "access", "grant", "--workspace", "prod", "--member", "usr_alex", "--secret", "payments/STRIPE_KEY")
	if grantCreateCount != 2 || grants[1].TargetType != "secret" || grants[1].Scope != "prod/payments" || grants[1].SecretName != "STRIPE_KEY" || grants[1].IncludeDescendants {
		t.Fatalf("secret grant was normalized incorrectly: %#v", grants)
	}

	run("member", "access", "grant", "--workspace", "prod", "--member", "alex@example.test", "--envelope", "apps", "--include-descendants")
	if grantCreateCount != 3 || grants[2].TargetType != "envelope" || grants[2].Scope != "prod/apps" || !grants[2].IncludeDescendants {
		t.Fatalf("descendant envelope grant was normalized incorrectly: %#v", grants)
	}

	out.Reset()
	errb.Reset()
	postsBeforeDisplayName := grantPostCalls
	if code := app.Run([]string{"member", "access", "grant", "--workspace", "prod", "--member", "Alex Morgan", "--envelope", "apps"}); code == 0 {
		t.Fatal("display-name member selection should fail")
	}
	if grantPostCalls != postsBeforeDisplayName || !strings.Contains(errb.String(), "exact email or user id") {
		t.Fatalf("display-name selection should fail before grant creation: posts=%d error=%s", grantPostCalls, errb.String())
	}
	observedOutput.WriteString(errb.String())

	output = run("member", "access", "list", "--workspace", "prod", "--member", "usr_alex")
	for _, expected := range []string{"envelope:/", "secret:payments/STRIPE_KEY", "envelope:apps", "grant_1", "grant_2", "grant_3"} {
		if !strings.Contains(output, expected) {
			t.Fatalf("filtered access list omitted %q: %s", expected, output)
		}
	}

	output = run("member", "access", "revoke", "--workspace", "prod", "--grant", "grant_1")
	if revokePostCalls != 1 || grants[0].Status != "revoked" || !strings.Contains(output, "cached copies are not erased") {
		t.Fatalf("revoke did not update the grant or warn about cached copies: posts=%d grants=%#v output=%s", revokePostCalls, grants, output)
	}
	output = run("member", "access", "revoke", "--workspace", "prod", "--grant", "grant_1")
	if revokePostCalls != 1 || !strings.Contains(output, "already revoked") {
		t.Fatalf("repeat revoke should be idempotent without another mutation: posts=%d output=%s", revokePostCalls, output)
	}

	output = run("member", "access", "list", "--workspace", "prod", "--member", "alex@example.test", "--all")
	if !strings.Contains(output, "revoked") || !strings.Contains(output, "grant_1") {
		t.Fatalf("--all access list omitted the revoked grant: %s", output)
	}

	for _, sentinel := range []string{"plaintext_value_sentinel", "ciphertext_sentinel", "wrapped_dek_sentinel", "member_response_token_sentinel", "at_member", "rt_member"} {
		if strings.Contains(observedOutput.String(), sentinel) {
			t.Fatalf("member commands leaked %q in output: %s", sentinel, observedOutput.String())
		}
	}
}

func TestServiceAccountSessionRejectsMemberCommandsBeforeNetwork(t *testing.T) {
	tmp := t.TempDir()
	old := os.Getenv("ASIRI_HOME")
	t.Cleanup(func() { _ = os.Setenv("ASIRI_HOME", old) })
	if err := os.Setenv("ASIRI_HOME", tmp); err != nil {
		t.Fatal(err)
	}

	remoteHits := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		remoteHits++
		http.Error(w, "unexpected", http.StatusInternalServerError)
	}))
	defer server.Close()

	var out bytes.Buffer
	var errb bytes.Buffer
	app := New(&out, &errb)
	if code := app.Run([]string{"init", "--device", "service-member-cli"}); code != 0 {
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
	if err := st.LinkServiceAccountControlPlane(server.URL, "org_prod", "prod", "usr_owner", "svc_prod", "prod-api", "Production API", "dev_remote", device.ID, "at_service", "rt_service", 3600, time.Now().UTC().Add(7*24*time.Hour).Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}

	commands := [][]string{
		{"member", "list", "--workspace", "prod"},
		{"member", "access", "list", "--workspace", "prod"},
		{"member", "access", "grant", "--workspace", "prod", "--member", "member@example.test", "--envelope", "/"},
		{"member", "access", "revoke", "--workspace", "prod", "--grant", "grant_1"},
	}
	for _, command := range commands {
		out.Reset()
		errb.Reset()
		if code := app.Run(command); code == 0 {
			t.Fatalf("%v should reject a service-account session", command)
		}
		if !strings.Contains(errb.String(), "requires a human session") {
			t.Fatalf("%v returned the wrong error: %s", command, errb.String())
		}
	}
	if remoteHits != 0 {
		t.Fatalf("service-account rejection should happen before network access, hits=%d", remoteHits)
	}
}

func assertMemberCommandSignedRequest(t *testing.T, r *http.Request) bool {
	t.Helper()
	valid := true
	if got := r.Header.Get("authorization"); got != "Bearer at_member" {
		t.Errorf("member request used the wrong authorization header: %q", got)
		valid = false
	}
	if got := r.Header.Get("x-asiri-device"); got != "dev_remote" {
		t.Errorf("member request used the wrong trusted device: %q", got)
		valid = false
	}
	for _, header := range []string{"x-asiri-signature", "x-asiri-timestamp"} {
		if r.Header.Get(header) == "" {
			t.Errorf("member request omitted %s", header)
			valid = false
		}
	}
	return valid
}
