package cli

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/o-clan/asiri/cli/internal/broker"
	"github.com/o-clan/asiri/cli/internal/store"
)

func (a App) broker(st *store.FileStore, args []string) int {
	if len(args) == 0 || args[0] != "start" {
		return a.fail(errors.New("broker start is required"))
	}
	if err := st.RequireInitialized(); err != nil {
		return a.fail(err)
	}
	options, err := parseBrokerStartArgs(args[1:])
	if err != nil {
		return a.fail(err)
	}
	target, err := a.workspacePathTarget(st, options.Workspace, "broker start")
	if err != nil {
		return a.fail(err)
	}
	if options.Agent == "" && (st.State.ControlPlane == nil || st.State.ControlPlane.Source != "service-account") {
		return a.fail(errors.New("broker start requires --agent"))
	}
	subject, runtimeType, err := runtimeSubject(st, options.Agent, "", options.Agent != "")
	if err != nil {
		return a.fail(err)
	}
	if subject == "" {
		return a.fail(errors.New("broker start requires a subject"))
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	var mu sync.Mutex
	runtimeStore := brokerRuntimeStore{path: st.Path, current: st}
	requestAuditSync, waitAuditSync := a.startRuntimeAuditSyncWorker(ctx, st.Path, &mu)
	defer func() {
		stop()
		waitAuditSync()
	}()
	brokerOptions := broker.Options{
		Workspace:   target.Slug,
		Subject:     subject,
		SocketPath:  options.SocketPath,
		ListenAddr:  options.ListenAddr,
		ClientFile:  options.ClientFile,
		TokenTTL:    options.TokenTTL,
		IdleTimeout: options.IdleTimeout,
		MaxRuntime:  options.MaxRuntime,
		Once:        options.Once,
		OnReady: func(summary broker.Summary) {
			mu.Lock()
			_ = runtimeStore.audit(subject, "broker_started", "allowed", "", "", "local broker started", target.Slug, subject, runtimeType, "", map[string]string{"mode": summary.Mode})
			requestAuditSync()
			mu.Unlock()
			fmt.Fprintf(a.Out, "asiri broker ready\nmode\t%s\naddress\t%s\nclient\t%s\nworkspace\t%s\nsubject\t%s\nexpires\t%s\n", summary.Mode, summary.Address, summary.ClientFile, summary.Workspace, summary.Subject, summary.ExpiresAt.Format(time.RFC3339))
		},
		OnEvent: func(event broker.Event) {
			mu.Lock()
			_ = runtimeStore.audit(subject, event.Action, event.Result, "", "", event.Reason, target.Slug, subject, runtimeType, event.RequestID, nil)
			requestAuditSync()
			mu.Unlock()
		},
	}
	_, runErr := broker.Run(ctx, brokerOptions, func(requestCtx context.Context, request broker.ValueRequest) (broker.ValueResponse, error) {
		mu.Lock()
		defer mu.Unlock()
		return a.handleBrokerValueRequest(requestCtx, &runtimeStore, target, subject, runtimeType, request, requestAuditSync)
	})
	mu.Lock()
	result := "allowed"
	reason := "local broker stopped"
	if runErr != nil {
		result = "failed"
		reason = runErr.Error()
	}
	_ = runtimeStore.audit(subject, "broker_stopped", result, "", "", reason, target.Slug, subject, runtimeType, "", nil)
	a.syncRuntimeAuditBestEffort(runtimeStore.currentStore())
	mu.Unlock()
	if runErr != nil {
		return a.fail(runErr)
	}
	return 0
}

type brokerRuntimeStore struct {
	path    string
	current *store.FileStore
}

func (runtime *brokerRuntimeStore) currentStore() *store.FileStore {
	return runtime.current
}

func (runtime *brokerRuntimeStore) load() (*store.FileStore, error) {
	latest, err := store.Load(runtime.path)
	if err != nil {
		return nil, err
	}
	runtime.current = latest
	return latest, nil
}

func (runtime *brokerRuntimeStore) audit(actor, action, result, scope, nameHash, reason, workspaceSlug, label, labelType, requestID string, extra map[string]string) error {
	latest, err := runtime.load()
	if err != nil {
		return err
	}
	latest.Audit(actor, action, result, scope, nameHash, reason, brokerRuntimeAuditMetadata(latest, workspaceSlug, label, labelType, requestID, extra))
	if err := latest.Save(); err != nil {
		return err
	}
	runtime.current = latest
	return nil
}

func (a App) startRuntimeAuditSyncWorker(ctx context.Context, path string, mu *sync.Mutex) (func(), func()) {
	requested := make(chan struct{}, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-ctx.Done():
				return
			case <-requested:
				a.syncRuntimeAuditBestEffortFromPath(path, mu)
			}
		}
	}()
	requestSync := func() {
		select {
		case requested <- struct{}{}:
		default:
		}
	}
	wait := func() {
		<-done
	}
	return requestSync, wait
}

func (a App) syncRuntimeAuditBestEffortFromPath(path string, mu *sync.Mutex) {
	mu.Lock()
	st, err := store.Load(path)
	if err != nil || st.State.ControlPlane == nil {
		mu.Unlock()
		return
	}
	_, events := pendingRuntimeAuditEvents(st)
	if len(events) == 0 {
		mu.Unlock()
		return
	}
	accessToken, ok := runtimeAuditAccessToken(st)
	if !ok {
		mu.Unlock()
		return
	}
	endpoint := strings.TrimRight(st.State.ControlPlane.Origin, "/") + "/v1/audit/batch"
	batches := runtimeAuditBatchesByWorkspace(events)
	mu.Unlock()
	acks := []store.RemoteAuditAck{}
	for _, batch := range batches {
		var response runtimeAuditBatchResponse
		if err := postJSONBearerTimeout(st, endpoint, accessToken, runtimeAuditBatchRequest{OrgID: batch[0].OrgID, Events: batch}, &response, runtimeAuditSyncTimeout); err != nil {
			continue
		}
		acks = append(acks, runtimeAuditRemoteAcks(batch, response.Acks)...)
	}
	if len(acks) == 0 {
		return
	}
	mu.Lock()
	defer mu.Unlock()
	latest, err := store.Load(path)
	if err != nil {
		return
	}
	// A 2xx without matching acks stays pending; the ack is the durable sync boundary.
	latest.MarkAuditEventsRemoteAcked(acks)
	_ = latest.Save()
}

type brokerStartOptions struct {
	Workspace   string
	Agent       string
	SocketPath  string
	ListenAddr  string
	ClientFile  string
	TokenTTL    time.Duration
	IdleTimeout time.Duration
	MaxRuntime  time.Duration
	Once        bool
}

func parseBrokerStartArgs(args []string) (brokerStartOptions, error) {
	options := brokerStartOptions{}
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--workspace", "-w":
			if options.Workspace != "" {
				return options, errors.New("broker start accepts one --workspace value")
			}
			if i+1 >= len(args) || strings.HasPrefix(args[i+1], "--") {
				return options, errors.New("--workspace requires a slug")
			}
			options.Workspace = args[i+1]
			i++
		case "--agent":
			if i+1 >= len(args) || strings.HasPrefix(args[i+1], "--") {
				return options, errors.New("--agent requires a subject")
			}
			options.Agent = store.NormalizeSubjectLabel(args[i+1])
			i++
		case "--socket":
			if i+1 >= len(args) || strings.HasPrefix(args[i+1], "--") {
				return options, errors.New("--socket requires a path")
			}
			options.SocketPath = args[i+1]
			i++
		case "--listen":
			if i+1 >= len(args) || strings.HasPrefix(args[i+1], "--") {
				return options, errors.New("--listen requires an address")
			}
			options.ListenAddr = args[i+1]
			i++
		case "--client-file":
			if i+1 >= len(args) || strings.HasPrefix(args[i+1], "--") {
				return options, errors.New("--client-file requires a path")
			}
			options.ClientFile = args[i+1]
			i++
		case "--token-ttl":
			value, err := parseBrokerDurationFlag(args, &i, "--token-ttl")
			if err != nil {
				return options, err
			}
			options.TokenTTL = value
		case "--idle-timeout":
			value, err := parseBrokerDurationFlag(args, &i, "--idle-timeout")
			if err != nil {
				return options, err
			}
			options.IdleTimeout = value
		case "--max-runtime":
			value, err := parseBrokerDurationFlag(args, &i, "--max-runtime")
			if err != nil {
				return options, err
			}
			options.MaxRuntime = value
		case "--once":
			options.Once = true
		default:
			return options, fmt.Errorf("unknown broker start argument %q", args[i])
		}
	}
	if options.Workspace == "" {
		return options, errors.New("broker start requires --workspace")
	}
	return options, nil
}

func parseBrokerDurationFlag(args []string, index *int, flag string) (time.Duration, error) {
	if *index+1 >= len(args) || strings.HasPrefix(args[*index+1], "--") {
		return 0, fmt.Errorf("%s requires a duration", flag)
	}
	value, err := time.ParseDuration(args[*index+1])
	if err != nil {
		return 0, fmt.Errorf("%s must be a duration like 15m or 1h: %w", flag, err)
	}
	if value < time.Second {
		return 0, fmt.Errorf("%s must be at least 1s", flag)
	}
	*index = *index + 1
	return value, nil
}

func (a App) handleBrokerValueRequest(requestCtx context.Context, runtimeStore *brokerRuntimeStore, target workspacePathTarget, subject, runtimeType string, request broker.ValueRequest, requestAuditSync func()) (broker.ValueResponse, error) {
	if err := requestCtx.Err(); err != nil {
		return broker.ValueResponse{}, &broker.Error{Status: http.StatusUnauthorized, Code: "token_expired", Message: "broker token expired"}
	}
	st, err := runtimeStore.load()
	if err != nil {
		return broker.ValueResponse{}, err
	}
	requestID := strings.TrimSpace(request.RequestID)
	if requestID == "" || len(requestID) > 128 {
		_ = runtimeStore.audit(subject, "broker_request", "denied", "", "", "invalid broker request id", target.Slug, subject, runtimeType, "", nil)
		requestAuditSync()
		return broker.ValueResponse{}, &broker.Error{Status: http.StatusBadRequest, Code: "invalid_request_id", Message: "broker request requires a short requestId"}
	}
	if strings.TrimSpace(request.Workspace) != target.Slug {
		_ = runtimeStore.audit(subject, "broker_request", "denied", "", "", "broker workspace mismatch", target.Slug, subject, runtimeType, requestID, nil)
		requestAuditSync()
		return broker.ValueResponse{}, &broker.Error{Status: http.StatusForbidden, Code: "workspace_mismatch", Message: "broker workspace mismatch"}
	}
	if store.NormalizeSubjectLabel(request.Subject) != subject {
		_ = runtimeStore.audit(subject, "broker_request", "denied", "", "", "broker subject mismatch", target.Slug, subject, runtimeType, requestID, nil)
		requestAuditSync()
		return broker.ValueResponse{}, &broker.Error{Status: http.StatusForbidden, Code: "subject_mismatch", Message: "broker subject mismatch"}
	}
	shortPath := strings.TrimSpace(request.Path)
	if shortPath == "" {
		_ = runtimeStore.audit(subject, "broker_request", "denied", "", "", "missing broker secret path", target.Slug, subject, runtimeType, requestID, nil)
		requestAuditSync()
		return broker.ValueResponse{}, &broker.Error{Status: http.StatusBadRequest, Code: "missing_path", Message: "broker request requires a secret path"}
	}
	fullPath, err := workspacePrefixedPath(target, shortPath, "broker")
	if err != nil {
		_ = runtimeStore.audit(subject, "broker_request", "denied", "", "", "invalid broker secret path", target.Slug, subject, runtimeType, requestID, nil)
		requestAuditSync()
		return broker.ValueResponse{}, &broker.Error{Status: http.StatusBadRequest, Code: "invalid_path", Message: err.Error()}
	}
	allowed, reason := st.CheckPolicy(subject, fullPath, "broker")
	scope, name, parseErr := store.ParseSecretPath(fullPath)
	hash := ""
	if parseErr == nil {
		hash = store.HashSecretName(scope, name)
	}
	if !allowed {
		_ = runtimeStore.audit(subject, "secret_brokered", "denied", scope, hash, reason, target.Slug, subject, runtimeType, requestID, map[string]string{"mode": "broker"})
		requestAuditSync()
		return broker.ValueResponse{}, &broker.Error{Status: http.StatusForbidden, Code: "policy_denied", Message: reason}
	}
	secretMetadata, err := st.SecretMetadata(fullPath)
	if err != nil {
		message := err.Error()
		if hint := a.remoteSelectionHint(st, fullPath, subject, "broker", false); hint != "" {
			message = hint
		}
		_ = runtimeStore.audit(subject, "secret_brokered", "failed", scope, hash, "secret not locally usable", target.Slug, subject, runtimeType, requestID, map[string]string{"mode": "broker"})
		requestAuditSync()
		return broker.ValueResponse{}, &broker.Error{Status: http.StatusNotFound, Code: "secret_not_local", Message: message}
	}
	if err := st.CheckSecretReadable(fullPath); err != nil {
		_ = runtimeStore.audit(subject, "secret_brokered", "failed", scope, hash, "secret not locally usable", target.Slug, subject, runtimeType, requestID, map[string]string{"mode": "broker"})
		requestAuditSync()
		return broker.ValueResponse{}, &broker.Error{Status: http.StatusNotFound, Code: "secret_not_local", Message: err.Error()}
	}
	if err := a.gateSecretRelease(st, subject, "secret_brokered", secretMetadata.Scope, secretMetadata.NameHash, "broker value request", brokerRuntimeAuditMetadata(st, target.Slug, subject, runtimeType, requestID, map[string]string{"mode": "broker"})); err != nil {
		runtimeStore.current = st
		return broker.ValueResponse{}, err
	}
	runtimeStore.current = st
	value, _, err := st.GetSecret(fullPath)
	if err != nil {
		message := err.Error()
		if hint := a.remoteSelectionHint(st, fullPath, subject, "broker", false); hint != "" {
			message = hint
		}
		_ = runtimeStore.audit(subject, "secret_brokered", "failed", scope, hash, "secret not locally usable", target.Slug, subject, runtimeType, requestID, map[string]string{"mode": "broker"})
		requestAuditSync()
		return broker.ValueResponse{}, &broker.Error{Status: http.StatusNotFound, Code: "secret_not_local", Message: message}
	}
	if err := requestCtx.Err(); err != nil {
		return broker.ValueResponse{}, &broker.Error{Status: http.StatusUnauthorized, Code: "token_expired", Message: "broker token expired"}
	}
	requestAuditSync()
	return broker.ValueResponse{RequestID: requestID, Value: value}, nil
}

func brokerRuntimeAuditMetadata(st *store.FileStore, workspaceSlug, label, labelType, requestID string, extra map[string]string) map[string]string {
	metadata := runtimeAuditMetadata(st, "", label, labelType, extra)
	if metadata == nil {
		metadata = map[string]string{}
	}
	if workspaceSlug != "" {
		metadata["workspaceSlug"] = workspaceSlug
		if st != nil {
			if binding, ok := st.RemoteBindingForPrefix(workspaceSlug); ok && binding.WorkspaceID != "" {
				metadata["workspaceId"] = binding.WorkspaceID
			}
		}
	}
	if requestID != "" {
		metadata["requestId"] = requestID
	}
	return metadata
}
