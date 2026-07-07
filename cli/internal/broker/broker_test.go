package broker

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestRunDefaultsToUnixSocket(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix sockets are not the default on windows")
	}
	clientFile := filepath.Join(t.TempDir(), "client.json")
	done := make(chan error, 1)
	go func() {
		_, err := Run(context.Background(), Options{
			Workspace:   "qa",
			Subject:     "codex",
			ClientFile:  clientFile,
			TokenTTL:    30 * time.Second,
			IdleTimeout: 5 * time.Second,
			Once:        true,
		}, func(_ context.Context, request ValueRequest) (ValueResponse, error) {
			if request.RequestID != "req_unix" {
				t.Errorf("unexpected request id %q", request.RequestID)
			}
			return ValueResponse{RequestID: request.RequestID, Value: "ok"}, nil
		})
		done <- err
	}()
	cfg := waitForClientConfig(t, clientFile)
	if cfg.Mode != "unix" {
		t.Fatalf("expected unix mode, got %q", cfg.Mode)
	}
	client := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", cfg.Address)
		},
	}}
	body := `{"requestId":"req_unix","workspace":"qa","subject":"codex","path":"openai/api_key"}`
	req, err := http.NewRequest(http.MethodPost, "http://asiri/v1/secrets/value", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("authorization", "Bearer "+cfg.Token)
	req.Header.Set("content-type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unexpected status %d", resp.StatusCode)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("broker did not exit")
	}
	if _, err := os.Stat(clientFile); !os.IsNotExist(err) {
		t.Fatalf("client config was not cleaned up: %v", err)
	}
}

func TestRunCleansGeneratedClientFileForExplicitUnixSocket(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix sockets are not supported on windows")
	}
	dir, err := os.MkdirTemp("", "ab-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	socketPath := filepath.Join(dir, "broker.sock")
	clientFile := filepath.Join(dir, "client.json")
	ready := make(chan Summary, 1)
	done := make(chan error, 1)
	go func() {
		_, err := Run(context.Background(), Options{
			Workspace:   "qa",
			Subject:     "codex",
			SocketPath:  socketPath,
			TokenTTL:    30 * time.Second,
			IdleTimeout: 30 * time.Second,
			Once:        true,
			OnReady: func(summary Summary) {
				ready <- summary
			},
		}, func(_ context.Context, request ValueRequest) (ValueResponse, error) {
			return ValueResponse{RequestID: request.RequestID, Value: "ok"}, nil
		})
		done <- err
	}()
	var summary Summary
	select {
	case summary = <-ready:
	case err := <-done:
		t.Fatalf("broker exited before ready: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("broker did not become ready")
	}
	if summary.ClientFile != clientFile {
		t.Fatalf("unexpected generated client file %q", summary.ClientFile)
	}
	cfg := waitForClientConfig(t, clientFile)
	client := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", cfg.Address)
		},
	}}
	req, err := http.NewRequest(http.MethodPost, "http://asiri/v1/secrets/value", strings.NewReader(`{"requestId":"req_cleanup","workspace":"qa","subject":"codex","path":"openai/api_key"}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("authorization", "Bearer "+cfg.Token)
	req.Header.Set("content-type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unexpected status %d", resp.StatusCode)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("broker did not exit")
	}
	for _, path := range []string{socketPath, clientFile} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("runtime file was not cleaned up: %s: %v", path, err)
		}
	}
}

func TestRunRejectsNonLoopbackHTTP(t *testing.T) {
	_, err := Run(context.Background(), Options{
		Workspace:   "qa",
		Subject:     "codex",
		ListenAddr:  "0.0.0.0:0",
		TokenTTL:    30 * time.Second,
		IdleTimeout: 5 * time.Second,
		Once:        true,
	}, func(_ context.Context, request ValueRequest) (ValueResponse, error) {
		return ValueResponse{RequestID: request.RequestID, Value: "ok"}, nil
	})
	if err == nil || !strings.Contains(err.Error(), "loopback") {
		t.Fatalf("expected loopback error, got %v", err)
	}
}

func TestRunRejectsExistingClientFile(t *testing.T) {
	clientFile := filepath.Join(t.TempDir(), "client.json")
	if err := os.WriteFile(clientFile, []byte("do not overwrite"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Run(context.Background(), Options{
		Workspace:   "qa",
		Subject:     "codex",
		ListenAddr:  "127.0.0.1:0",
		ClientFile:  clientFile,
		TokenTTL:    30 * time.Second,
		IdleTimeout: 5 * time.Second,
		Once:        true,
	}, func(_ context.Context, request ValueRequest) (ValueResponse, error) {
		return ValueResponse{RequestID: request.RequestID, Value: "ok"}, nil
	})
	if err == nil || !strings.Contains(err.Error(), "client file already exists") {
		t.Fatalf("expected existing client file error, got %v", err)
	}
	data, err := os.ReadFile(clientFile)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "do not overwrite" {
		t.Fatalf("client file was overwritten: %q", string(data))
	}
}

func TestWriteClientConfigPublishesAtomically(t *testing.T) {
	clientFile := filepath.Join(t.TempDir(), "client.json")
	seen := make(chan []byte, 1)
	watchErr := make(chan error, 1)
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
			}
			data, err := os.ReadFile(clientFile)
			if err == nil {
				seen <- data
				return
			}
			if !os.IsNotExist(err) {
				watchErr <- err
				return
			}
		}
	}()
	address := strings.Repeat("x", 1<<20)
	if err := writeClientConfig(Summary{
		Mode:       "unix",
		Address:    address,
		ClientFile: clientFile,
		Workspace:  "qa",
		Subject:    "codex",
		ExpiresAt:  time.Now().UTC().Add(time.Minute),
	}, "token"); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-watchErr:
		t.Fatal(err)
	case data := <-seen:
		var cfg clientConfig
		if err := json.Unmarshal(data, &cfg); err != nil {
			t.Fatalf("client config was published before valid JSON was complete: %v", err)
		}
		if cfg.Address != address {
			t.Fatal("client config was published before the full address was written")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("client config was not observed")
	}
}

func TestRunDoesNotConsumeOnceForInvalidToken(t *testing.T) {
	clientFile := filepath.Join(t.TempDir(), "client.json")
	done := make(chan error, 1)
	go func() {
		_, err := Run(context.Background(), Options{
			Workspace:   "qa",
			Subject:     "codex",
			ListenAddr:  "127.0.0.1:0",
			ClientFile:  clientFile,
			TokenTTL:    30 * time.Second,
			IdleTimeout: 5 * time.Second,
			Once:        true,
		}, func(_ context.Context, request ValueRequest) (ValueResponse, error) {
			return ValueResponse{RequestID: request.RequestID, Value: "ok"}, nil
		})
		done <- err
	}()
	cfg := waitForClientConfig(t, clientFile)
	resp := postTestBrokerRequest(t, cfg, "bad-token", strings.NewReader(`{"requestId":"req_bad","workspace":"qa","subject":"codex","path":"openai/api_key"}`))
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("invalid token status=%d", resp.StatusCode)
	}
	select {
	case err := <-done:
		t.Fatalf("broker exited after invalid token: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	resp = postTestBrokerRequest(t, cfg, cfg.Token, strings.NewReader(`{"requestId":"req_ok","workspace":"qa","subject":"codex","path":"openai/api_key"}`))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("valid request status=%d", resp.StatusCode)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("broker did not exit after valid once request")
	}
}

func TestRunOnceRejectsConcurrentAuthenticatedRequests(t *testing.T) {
	clientFile := filepath.Join(t.TempDir(), "client.json")
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		_, err := Run(context.Background(), Options{
			Workspace:   "qa",
			Subject:     "codex",
			ListenAddr:  "127.0.0.1:0",
			ClientFile:  clientFile,
			TokenTTL:    30 * time.Second,
			IdleTimeout: 5 * time.Second,
			Once:        true,
		}, func(_ context.Context, request ValueRequest) (ValueResponse, error) {
			entered <- struct{}{}
			if request.RequestID == "req_first" {
				<-release
			}
			return ValueResponse{RequestID: request.RequestID, Value: "ok"}, nil
		})
		done <- err
	}()
	cfg := waitForClientConfig(t, clientFile)
	first := make(chan int, 1)
	go func() {
		resp := postTestBrokerRequest(t, cfg, cfg.Token, strings.NewReader(`{"requestId":"req_first","workspace":"qa","subject":"codex","path":"openai/api_key"}`))
		first <- resp.StatusCode
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("first request did not reach handler")
	}
	resp := postTestBrokerRequest(t, cfg, cfg.Token, strings.NewReader(`{"requestId":"req_second","workspace":"qa","subject":"codex","path":"openai/api_key"}`))
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("second once request status=%d", resp.StatusCode)
	}
	close(release)
	if status := <-first; status != http.StatusOK {
		t.Fatalf("first once request status=%d", status)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("broker did not exit after claimed once request")
	}
}

func TestRunRejectsTokenExpiredBeforeBodyCompletes(t *testing.T) {
	clientFile := filepath.Join(t.TempDir(), "client.json")
	handled := make(chan struct{}, 1)
	done := make(chan error, 1)
	go func() {
		_, err := Run(context.Background(), Options{
			Workspace:   "qa",
			Subject:     "codex",
			ListenAddr:  "127.0.0.1:0",
			ClientFile:  clientFile,
			TokenTTL:    time.Second,
			IdleTimeout: 5 * time.Second,
			Once:        true,
		}, func(_ context.Context, request ValueRequest) (ValueResponse, error) {
			handled <- struct{}{}
			return ValueResponse{RequestID: request.RequestID, Value: "ok"}, nil
		})
		done <- err
	}()
	cfg := waitForClientConfig(t, clientFile)
	resp := postTestBrokerRequest(t, cfg, cfg.Token, &delayedReader{
		delay: 1200 * time.Millisecond,
		body:  `{"requestId":"req_expired","workspace":"qa","subject":"codex","path":"openai/api_key"}`,
	})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expired slow request status=%d", resp.StatusCode)
	}
	select {
	case <-handled:
		t.Fatal("handler was called after token expiry")
	default:
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("broker did not exit after expired once request")
	}
}

func waitForClientConfig(t *testing.T, path string) clientConfig {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		data, err := os.ReadFile(path)
		if err == nil {
			var cfg clientConfig
			if err := json.Unmarshal(data, &cfg); err != nil {
				t.Fatal(err)
			}
			return cfg
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatal("client config was not written")
	return clientConfig{}
}

func postTestBrokerRequest(t *testing.T, cfg clientConfig, token string, body io.Reader) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, cfg.URL, body)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("authorization", "Bearer "+token)
	req.Header.Set("content-type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

type delayedReader struct {
	delay time.Duration
	body  string
	sent  bool
}

func (reader *delayedReader) Read(p []byte) (int, error) {
	if reader.sent {
		return 0, io.EOF
	}
	time.Sleep(reader.delay)
	reader.sent = true
	return copy(p, reader.body), nil
}
