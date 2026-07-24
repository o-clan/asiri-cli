package cli

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/o-clan/asiri/cli/internal/keystore"
	"github.com/o-clan/asiri/cli/internal/store"
	"github.com/zalando/go-keyring"
)

func TestMain(m *testing.M) {
	keyring.MockInit()
	restore := keystore.UseGoKeyringForTesting()
	code := m.Run()
	restore()
	os.Exit(code)
}

func testSecretFile(t *testing.T, value string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "secret.txt")
	if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func testSecretBytesFile(t *testing.T, value []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "secret.bin")
	if err := os.WriteFile(path, value, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func linkLocalWorkspaceForTest(t *testing.T, workspace string, remoteWorkspaceID ...string) {
	t.Helper()
	st, err := store.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	remoteID := ""
	if len(remoteWorkspaceID) > 0 {
		remoteID = remoteWorkspaceID[0]
	} else if st.State.ControlPlane != nil {
		remoteID = st.State.ControlPlane.WorkspaceID
	}
	if remoteID == "" {
		t.Fatalf("remote workspace id is required for test workspace %s", workspace)
	}
	if err := st.BindWorkspacePrefix(workspace, remoteID, workspace); err != nil {
		t.Fatal(err)
	}
}

func requireOrderedText(t *testing.T, value string, expected ...string) {
	t.Helper()
	position := -1
	for _, item := range expected {
		next := strings.Index(value[position+1:], item)
		if next < 0 {
			t.Fatalf("output missing %q after position %d: %s", item, position, value)
		}
		position += next + len(item) + 1
	}
}

type brokerClientTestConfig struct {
	URL       string    `json:"url"`
	Token     string    `json:"token"`
	Workspace string    `json:"workspace"`
	Subject   string    `json:"subject"`
	ExpiresAt time.Time `json:"expiresAt"`
}

func runBrokerValueRequest(t *testing.T, app App, request map[string]string, tokenOverride string, extraArgs ...string) (*http.Response, string) {
	t.Helper()
	clientFile := filepath.Join(t.TempDir(), "broker-client.json")
	args := []string{"broker", "start", "--workspace", "qa", "--agent", "codex", "--listen", "127.0.0.1:0", "--client-file", clientFile, "--idle-timeout", "5s", "--token-ttl", "30s", "--once"}
	args = append(args, extraArgs...)
	done := make(chan int, 1)
	go func() {
		done <- app.Run(args)
	}()
	cfg := waitForBrokerClientConfig(t, clientFile)
	if tokenOverride == "" {
		tokenOverride = cfg.Token
	}
	resp, payload := postBrokerValueRequest(t, cfg, request, tokenOverride)
	if tokenOverride != cfg.Token {
		// Invalid authentication intentionally does not consume --once. Send one
		// authenticated request so the helper can shut the broker down promptly.
		cleanupResp, cleanupPayload := postBrokerValueRequest(t, cfg, request, cfg.Token)
		if cleanupResp.StatusCode != http.StatusOK {
			t.Fatalf("broker cleanup request failed status=%d body=%s", cleanupResp.StatusCode, cleanupPayload)
		}
	}
	select {
	case code := <-done:
		if code != 0 {
			t.Fatalf("broker exited with code %d", code)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("broker did not exit after one request")
	}
	return resp, payload
}

func postBrokerValueRequest(t *testing.T, cfg brokerClientTestConfig, request map[string]string, tokenOverride string) (*http.Response, string) {
	t.Helper()
	if tokenOverride == "" {
		tokenOverride = cfg.Token
	}
	body, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	httpReq, err := http.NewRequest(http.MethodPost, cfg.URL, strings.NewReader(string(body)))
	if err != nil {
		t.Fatal(err)
	}
	httpReq.Header.Set("authorization", "Bearer "+tokenOverride)
	httpReq.Header.Set("content-type", "application/json")
	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	return resp, string(payload)
}

func waitForBrokerClientConfig(t *testing.T, path string) brokerClientTestConfig {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		data, err := os.ReadFile(path)
		if err == nil {
			var cfg brokerClientTestConfig
			if err := json.Unmarshal(data, &cfg); err != nil {
				t.Fatal(err)
			}
			if cfg.URL == "" || cfg.Token == "" {
				t.Fatalf("broker client config missing URL or token: %s", string(data))
			}
			return cfg
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("broker client config was not written")
	return brokerClientTestConfig{}
}

func serverURL(r *http.Request) string {
	return "http://" + r.Host
}

func remoteDeleteTokenFromOutput(t *testing.T, output string) string {
	t.Helper()
	for _, line := range strings.Split(output, "\n") {
		token, ok := strings.CutPrefix(line, "Confirmation token: ")
		if ok && strings.HasPrefix(token, "del_") {
			return token
		}
	}
	t.Fatalf("missing confirmation token in output: %s", output)
	return ""
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func assertSecretMutationBody(t testing.TB, r *http.Request, orgID, deviceID string, version int) {
	t.Helper()
	var body map[string]any
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body["orgId"] != orgID || body["createdByDeviceId"] != deviceID || body["version"] != float64(version) {
		t.Fatalf("secret mutation request used wrong body: %#v", body)
	}
}

func assertWorkspaceOverviewTarget(t testing.TB, r *http.Request, workspace string) {
	t.Helper()
	if got := r.URL.Query().Get("workspace"); got != workspace {
		t.Fatalf("workspace overview used wrong target: got %q want %q; query=%s", got, workspace, r.URL.RawQuery)
	}
}

func assertAuditBatchWorkspace(t testing.TB, batch runtimeAuditBatchRequest, orgID string) {
	t.Helper()
	if batch.OrgID != orgID {
		t.Fatalf("audit batch used wrong workspace: got %q want %q", batch.OrgID, orgID)
	}
	for _, event := range batch.Events {
		if event.OrgID != orgID {
			t.Fatalf("audit batch mixed workspaces: batch=%q event=%q", batch.OrgID, event.OrgID)
		}
	}
}

func assertRequestWorkspace(t testing.TB, r *http.Request, orgID string) {
	t.Helper()
	var body map[string]any
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body["orgId"] != orgID {
		t.Fatalf("request used wrong workspace: got %#v want %q", body["orgId"], orgID)
	}
}
