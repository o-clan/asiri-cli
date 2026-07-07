package broker

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

const (
	defaultTokenTTL     = 15 * time.Minute
	defaultIdleTimeout  = 15 * time.Minute
	defaultMaxRuntime   = 8 * time.Hour
	defaultRequestLimit = 32 * 1024
)

type Options struct {
	Workspace    string
	Subject      string
	SocketPath   string
	ListenAddr   string
	ClientFile   string
	TokenTTL     time.Duration
	IdleTimeout  time.Duration
	MaxRuntime   time.Duration
	Once         bool
	OnReady      func(Summary)
	OnEvent      func(Event)
	RequestLimit int64
}

type Summary struct {
	Mode       string
	Address    string
	ClientFile string
	Workspace  string
	Subject    string
	ExpiresAt  time.Time
}

type Event struct {
	Action    string
	Result    string
	Reason    string
	RequestID string
}

type ValueRequest struct {
	RequestID string `json:"requestId,omitempty"`
	Workspace string `json:"workspace,omitempty"`
	Subject   string `json:"subject,omitempty"`
	Path      string `json:"path"`
}

type ValueResponse struct {
	RequestID string `json:"requestId,omitempty"`
	Value     string `json:"value"`
}

type Error struct {
	Status  int
	Code    string
	Message string
}

func (e *Error) Error() string {
	if e == nil {
		return ""
	}
	return e.Message
}

type Handler func(context.Context, ValueRequest) (ValueResponse, error)

type clientConfig struct {
	Version   int       `json:"version"`
	Mode      string    `json:"mode"`
	Address   string    `json:"address"`
	URL       string    `json:"url,omitempty"`
	Token     string    `json:"token"`
	Workspace string    `json:"workspace"`
	Subject   string    `json:"subject"`
	ExpiresAt time.Time `json:"expiresAt"`
}

type errorResponse struct {
	RequestID string `json:"requestId,omitempty"`
	Error     string `json:"error"`
	Code      string `json:"code,omitempty"`
}

func Run(ctx context.Context, options Options, handler Handler) (Summary, error) {
	if handler == nil {
		return Summary{}, errors.New("broker handler is required")
	}
	if err := options.validate(); err != nil {
		return Summary{}, err
	}
	options = options.withDefaults()
	token, err := randomToken()
	if err != nil {
		return Summary{}, err
	}
	listener, mode, address, clientFile, cleanup, err := listen(options)
	if err != nil {
		return Summary{}, err
	}
	defer cleanup()

	expiresAt := time.Now().UTC().Add(options.TokenTTL)
	summary := Summary{
		Mode:       mode,
		Address:    address,
		ClientFile: clientFile,
		Workspace:  options.Workspace,
		Subject:    options.Subject,
		ExpiresAt:  expiresAt,
	}
	if err := writeClientConfig(summary, token); err != nil {
		_ = listener.Close()
		return Summary{}, err
	}

	serverCtx, cancel := context.WithCancel(ctx)
	if options.MaxRuntime > 0 {
		serverCtx, cancel = context.WithTimeout(ctx, options.MaxRuntime)
	}
	defer cancel()

	server := &http.Server{
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       readTimeout(options.TokenTTL),
	}
	var stopOnce sync.Once
	stop := func() {
		stopOnce.Do(func() {
			cancel()
			shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer shutdownCancel()
			_ = server.Shutdown(shutdownCtx)
		})
	}
	idle := time.NewTimer(options.IdleTimeout)
	defer idle.Stop()
	resetIdle := func() {
		if options.IdleTimeout <= 0 {
			return
		}
		if !idle.Stop() {
			select {
			case <-idle.C:
			default:
			}
		}
		idle.Reset(options.IdleTimeout)
	}

	mux := http.NewServeMux()
	onceClaimed := false
	var onceMu sync.Mutex
	claimOnce := func() bool {
		if !options.Once {
			return true
		}
		onceMu.Lock()
		defer onceMu.Unlock()
		if onceClaimed {
			return false
		}
		onceClaimed = true
		return true
	}
	mux.HandleFunc("/v1/secrets/value", func(w http.ResponseWriter, r *http.Request) {
		requestID := ""
		onceEligible := false
		defer func() {
			if options.Once && onceEligible {
				go stop()
			}
		}()
		if r.Method != http.MethodPost {
			options.emit(Event{Action: "broker_request", Result: "denied", Reason: "method not allowed"})
			writeError(w, requestID, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
			return
		}
		if tokenExpired(expiresAt) {
			options.emit(Event{Action: "broker_request", Result: "denied", Reason: "broker token expired"})
			writeError(w, requestID, http.StatusUnauthorized, "token_expired", "broker token expired")
			return
		}
		if !authorized(r.Header.Get("Authorization"), token) {
			options.emit(Event{Action: "broker_request", Result: "denied", Reason: "invalid broker token"})
			writeError(w, requestID, http.StatusUnauthorized, "invalid_token", "invalid broker token")
			return
		}
		if !claimOnce() {
			options.emit(Event{Action: "broker_request", Result: "denied", Reason: "broker once request already handled"})
			writeError(w, requestID, http.StatusConflict, "once_used", "broker already handled one request")
			return
		}
		onceEligible = true
		resetIdle()
		r.Body = http.MaxBytesReader(w, r.Body, options.RequestLimit)
		var request ValueRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			options.emit(Event{Action: "broker_request", Result: "denied", Reason: "invalid broker request"})
			writeError(w, requestID, http.StatusBadRequest, "invalid_request", "invalid broker request")
			return
		}
		requestID = strings.TrimSpace(request.RequestID)
		if tokenExpired(expiresAt) {
			options.emit(Event{Action: "broker_request", Result: "denied", Reason: "broker token expired"})
			writeError(w, requestID, http.StatusUnauthorized, "token_expired", "broker token expired")
			return
		}
		requestCtx, requestCancel := context.WithDeadline(serverCtx, expiresAt)
		defer requestCancel()
		response, err := handler(requestCtx, request)
		if err != nil {
			status, code, message := errorDetails(err)
			writeError(w, requestID, status, code, message)
			return
		}
		if tokenExpired(expiresAt) {
			options.emit(Event{Action: "broker_request", Result: "denied", Reason: "broker token expired"})
			writeError(w, requestID, http.StatusUnauthorized, "token_expired", "broker token expired")
			return
		}
		w.Header().Set("content-type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	})
	server.Handler = mux

	go func() {
		select {
		case <-serverCtx.Done():
			stop()
		case <-idle.C:
			options.emit(Event{Action: "broker_request", Result: "failed", Reason: "broker idle timeout"})
			stop()
		}
	}()

	if options.OnReady != nil {
		options.OnReady(summary)
	}
	err = server.Serve(listener)
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		return summary, err
	}
	return summary, nil
}

func (options Options) withDefaults() Options {
	if options.TokenTTL == 0 {
		options.TokenTTL = defaultTokenTTL
	}
	if options.IdleTimeout == 0 {
		options.IdleTimeout = defaultIdleTimeout
	}
	if options.MaxRuntime == 0 {
		options.MaxRuntime = defaultMaxRuntime
	}
	if options.RequestLimit <= 0 {
		options.RequestLimit = defaultRequestLimit
	}
	return options
}

func (options Options) validate() error {
	if strings.TrimSpace(options.Workspace) == "" {
		return errors.New("broker requires a workspace")
	}
	if strings.TrimSpace(options.Subject) == "" {
		return errors.New("broker requires a subject")
	}
	if options.SocketPath != "" && options.ListenAddr != "" {
		return errors.New("broker accepts either --socket or --listen, not both")
	}
	if options.TokenTTL != 0 && options.TokenTTL < time.Second {
		return errors.New("broker token ttl must be at least 1s")
	}
	if options.IdleTimeout != 0 && options.IdleTimeout < time.Second {
		return errors.New("broker idle timeout must be at least 1s")
	}
	if options.MaxRuntime != 0 && options.MaxRuntime < time.Second {
		return errors.New("broker max runtime must be at least 1s")
	}
	return nil
}

func listen(options Options) (net.Listener, string, string, string, func(), error) {
	cleanupFiles := []string{}
	cleanupDirs := []string{}
	cleanup := func() {
		for _, path := range cleanupFiles {
			_ = os.Remove(path)
		}
		for _, path := range cleanupDirs {
			_ = os.RemoveAll(path)
		}
	}
	if options.SocketPath != "" || (options.ListenAddr == "" && runtime.GOOS != "windows") {
		socketPath := options.SocketPath
		runtimeDir := ""
		if socketPath == "" {
			var err error
			runtimeDir, err = os.MkdirTemp("", "asiri-broker-*")
			if err != nil {
				return nil, "", "", "", cleanup, err
			}
			_ = os.Chmod(runtimeDir, 0o700)
			cleanupDirs = append(cleanupDirs, runtimeDir)
			socketPath = filepath.Join(runtimeDir, "broker.sock")
		}
		if _, err := os.Stat(socketPath); err == nil {
			cleanup()
			return nil, "", "", "", cleanup, fmt.Errorf("broker socket already exists: %s", socketPath)
		}
		if err := os.MkdirAll(filepath.Dir(socketPath), 0o700); err != nil {
			cleanup()
			return nil, "", "", "", cleanup, err
		}
		listener, err := net.Listen("unix", socketPath)
		if err != nil {
			cleanup()
			return nil, "", "", "", cleanup, err
		}
		_ = os.Chmod(socketPath, 0o600)
		if runtimeDir == "" {
			cleanupFiles = append(cleanupFiles, socketPath)
		}
		clientFile := options.ClientFile
		if clientFile == "" {
			clientFile = filepath.Join(filepath.Dir(socketPath), "client.json")
		}
		if err := requireNewFile(clientFile); err != nil {
			_ = listener.Close()
			cleanup()
			return nil, "", "", "", cleanup, err
		}
		if runtimeDir == "" || options.ClientFile != "" {
			cleanupFiles = append(cleanupFiles, clientFile)
		}
		return listener, "unix", socketPath, clientFile, cleanup, nil
	}
	addr := options.ListenAddr
	if addr == "" {
		addr = "127.0.0.1:0"
	}
	if err := requireLoopback(addr); err != nil {
		return nil, "", "", "", cleanup, err
	}
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, "", "", "", cleanup, err
	}
	clientFile := options.ClientFile
	if clientFile == "" {
		runtimeDir, err := os.MkdirTemp("", "asiri-broker-*")
		if err != nil {
			_ = listener.Close()
			return nil, "", "", "", cleanup, err
		}
		_ = os.Chmod(runtimeDir, 0o700)
		cleanupDirs = append(cleanupDirs, runtimeDir)
		clientFile = filepath.Join(runtimeDir, "client.json")
	}
	if err := requireNewFile(clientFile); err != nil {
		_ = listener.Close()
		cleanup()
		return nil, "", "", "", cleanup, err
	}
	if options.ClientFile != "" {
		cleanupFiles = append(cleanupFiles, clientFile)
	}
	return listener, "http", listener.Addr().String(), clientFile, cleanup, nil
}

func writeClientConfig(summary Summary, token string) error {
	clientFile := summary.ClientFile
	if clientFile == "" {
		runtimeDir, err := os.MkdirTemp("", "asiri-broker-*")
		if err != nil {
			return err
		}
		_ = os.Chmod(runtimeDir, 0o700)
		clientFile = filepath.Join(runtimeDir, "client.json")
		summary.ClientFile = clientFile
	}
	if err := os.MkdirAll(filepath.Dir(clientFile), 0o700); err != nil {
		return err
	}
	url := ""
	if summary.Mode == "http" {
		url = "http://" + summary.Address + "/v1/secrets/value"
	}
	data, err := json.MarshalIndent(clientConfig{
		Version:   1,
		Mode:      summary.Mode,
		Address:   summary.Address,
		URL:       url,
		Token:     token,
		Workspace: summary.Workspace,
		Subject:   summary.Subject,
		ExpiresAt: summary.ExpiresAt,
	}, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return publishNewFileAtomic(clientFile, data)
}

func publishNewFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	file, err := os.CreateTemp(dir, ".client-*.tmp")
	if err != nil {
		return err
	}
	tempPath := file.Name()
	defer func() { _ = os.Remove(tempPath) }()
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return err
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Link(tempPath, path); err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("client file already exists: %s", path)
		}
		return err
	}
	return nil
}

func randomToken() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func authorized(header, token string) bool {
	prefix := "Bearer "
	if !strings.HasPrefix(header, prefix) {
		return false
	}
	got := strings.TrimSpace(strings.TrimPrefix(header, prefix))
	return subtle.ConstantTimeCompare([]byte(got), []byte(token)) == 1
}

func requireLoopback(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("invalid broker listen address: %w", err)
	}
	if host == "localhost" {
		return nil
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	if ip == nil || !ip.IsLoopback() {
		return errors.New("broker listen address must be loopback")
	}
	return nil
}

func writeError(w http.ResponseWriter, requestID string, status int, code, message string) {
	w.Header().Set("content-type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(errorResponse{RequestID: requestID, Error: message, Code: code})
}

func errorDetails(err error) (int, string, string) {
	var brokerErr *Error
	if errors.As(err, &brokerErr) {
		status := brokerErr.Status
		if status == 0 {
			status = http.StatusBadRequest
		}
		code := brokerErr.Code
		if code == "" {
			code = "broker_error"
		}
		return status, code, brokerErr.Message
	}
	return http.StatusInternalServerError, "broker_error", "broker request failed"
}

func (options Options) emit(event Event) {
	if options.OnEvent != nil {
		options.OnEvent(event)
	}
}

func readTimeout(tokenTTL time.Duration) time.Duration {
	return 30 * time.Second
}

func tokenExpired(expiresAt time.Time) bool {
	return !time.Now().UTC().Before(expiresAt)
}

func requireNewFile(path string) error {
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("broker client file already exists: %s", path)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}
