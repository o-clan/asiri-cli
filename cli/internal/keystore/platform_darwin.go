//go:build darwin

package keystore

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/zalando/go-keyring"
)

const (
	securityCommandPath    = "/usr/bin/security"
	legacyEncodingPrefix   = "go-keyring-encoded:"
	base64EncodingPrefix   = "go-keyring-base64:"
	keychainCommandLimit   = 4096
	keychainCommandTimeout = 30 * time.Second
)

type securityCommandRunner func(ctx context.Context, stdin string, args ...string) ([]byte, error)

type darwinKeyStore struct {
	run     securityCommandRunner
	timeout time.Duration
	gate    chan struct{}
}

type securityExitError struct {
	code int
}

func (e securityExitError) Error() string {
	return fmt.Sprintf("security command exited with status %d", e.code)
}

func newPlatformKeyStore() platformKeyStore {
	return &darwinKeyStore{
		run:     runSecurityCommand,
		timeout: keychainCommandTimeout,
		gate:    make(chan struct{}, 1),
	}
}

func (k *darwinKeyStore) Store(service, account, value string) error {
	encoded := base64EncodingPrefix + base64.StdEncoding.EncodeToString([]byte(value))
	command := fmt.Sprintf("add-generic-password -U -s %s -a %s -w %s\n", shellQuote(service), shellQuote(account), shellQuote(encoded))
	if len(command) > keychainCommandLimit {
		return keyring.ErrSetDataTooBig
	}
	_, err := k.execute(command, "-i")
	return classifySecurityError(err, nil)
}

func (k *darwinKeyStore) Load(service, account string) (string, error) {
	output, err := k.execute("", "find-generic-password", "-s", service, "-wa", account)
	if err != nil {
		return "", classifySecurityError(err, output)
	}
	value := strings.TrimSpace(string(output))
	switch {
	case strings.HasPrefix(value, legacyEncodingPrefix):
		decoded, decodeErr := hex.DecodeString(value[len(legacyEncodingPrefix):])
		if decodeErr != nil {
			return "", errors.New("invalid macOS Keychain value encoding")
		}
		return string(decoded), nil
	case strings.HasPrefix(value, base64EncodingPrefix):
		decoded, decodeErr := base64.StdEncoding.DecodeString(value[len(base64EncodingPrefix):])
		if decodeErr != nil {
			return "", errors.New("invalid macOS Keychain value encoding")
		}
		return string(decoded), nil
	default:
		return value, nil
	}
}

func (k *darwinKeyStore) Delete(service, account string) error {
	output, err := k.execute("", "delete-generic-password", "-s", service, "-a", account)
	return classifySecurityError(err, output)
}

func (k *darwinKeyStore) execute(stdin string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), k.timeout)
	defer cancel()
	if k.gate != nil {
		select {
		case k.gate <- struct{}{}:
			defer func() { <-k.gate }()
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return k.run(ctx, stdin, args...)
}

func runSecurityCommand(ctx context.Context, stdin string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, securityCommandPath, args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	output, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return output, securityExitError{code: exitErr.ExitCode()}
	}
	return output, err
}

func classifySecurityError(err error, output []byte) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return ErrPlatformTimeout
	}
	if strings.Contains(string(output), "could not be found") {
		return ErrKeyNotFound
	}
	var exitErr securityExitError
	if errors.As(err, &exitErr) {
		if exitErr.code == 44 {
			return ErrKeyNotFound
		}
		if exitErr.code == 51 {
			return ErrPlatformAuthentication
		}
		return exitErr
	}
	var execErr *exec.Error
	var pathErr *os.PathError
	if errors.As(err, &execErr) || errors.As(err, &pathErr) || errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("%w: macOS Keychain command is unavailable", ErrPlatformUnavailable)
	}
	return errors.New("macOS Keychain command failed")
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}
