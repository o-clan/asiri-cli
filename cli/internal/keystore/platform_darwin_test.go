//go:build darwin

package keystore

import (
	"context"
	"encoding/base64"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

func TestDarwinAuthenticationFailureIsTypedAndSanitized(t *testing.T) {
	secret := "must-not-appear-in-errors"
	usePlatformKeyStoreForTest(t, &darwinKeyStore{
		timeout: time.Second,
		run: func(context.Context, string, ...string) ([]byte, error) {
			return []byte("sensitive diagnostic output"), securityExitError{code: 51}
		},
	})

	err := Store("account", secret)
	if !errors.Is(err, ErrPlatformAuthentication) {
		t.Fatalf("expected authentication error, got %v", err)
	}
	if errors.Is(err, ErrPlatformUnavailable) {
		t.Fatalf("authentication failure must not trigger file-store fallback: %v", err)
	}
	if strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), "sensitive diagnostic") {
		t.Fatal("error exposed secret material or Keychain diagnostics")
	}
}

func TestDarwinTimeoutHasRecoveryGuidance(t *testing.T) {
	timeout := 20 * time.Millisecond
	usePlatformKeyStoreForTest(t, &darwinKeyStore{
		timeout: timeout,
		run: func(ctx context.Context, _ string, _ ...string) ([]byte, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		},
	})

	started := time.Now()
	_, err := Load("account")
	elapsed := time.Since(started)
	if !errors.Is(err, ErrPlatformTimeout) {
		t.Fatalf("expected timeout error, got %v", err)
	}
	if elapsed < timeout || elapsed > 500*time.Millisecond {
		t.Fatalf("Keychain timeout took %s, expected a bounded wait", elapsed)
	}
	if !strings.Contains(err.Error(), "macOS Keychain did not respond in time.") {
		t.Fatalf("unexpected timeout message: %v", err)
	}
}

func TestDarwinLoadDecodesGoKeyringValues(t *testing.T) {
	value := "line one\nline two"
	encoded := base64EncodingPrefix + base64.StdEncoding.EncodeToString([]byte(value)) + "\n"
	store := &darwinKeyStore{
		timeout: time.Second,
		run: func(context.Context, string, ...string) ([]byte, error) {
			return []byte(encoded), nil
		},
	}

	got, err := store.Load(Service, "account")
	if err != nil {
		t.Fatal(err)
	}
	if got != value {
		t.Fatalf("decoded value mismatch: got %q", got)
	}
}

func TestDarwinNotFoundAndUnavailableRemainDistinct(t *testing.T) {
	notFound := &darwinKeyStore{
		timeout: time.Second,
		run: func(context.Context, string, ...string) ([]byte, error) {
			return []byte("The specified item could not be found in the keychain."), securityExitError{code: 44}
		},
	}
	if err := notFound.Delete(Service, "account"); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("expected not-found error, got %v", err)
	}

	unavailable := &darwinKeyStore{
		timeout: time.Second,
		run: func(context.Context, string, ...string) ([]byte, error) {
			return nil, &os.PathError{Op: "fork/exec", Path: securityCommandPath, Err: os.ErrNotExist}
		},
	}
	if err := unavailable.Store(Service, "account", "value"); !errors.Is(err, ErrPlatformUnavailable) {
		t.Fatalf("expected unavailable error, got %v", err)
	}
}

func usePlatformKeyStoreForTest(t *testing.T, store platformKeyStore) {
	t.Helper()
	configuredPlatformKeyStore.Lock()
	previous := configuredPlatformKeyStore.store
	configuredPlatformKeyStore.store = store
	configuredPlatformKeyStore.Unlock()
	t.Cleanup(func() {
		configuredPlatformKeyStore.Lock()
		configuredPlatformKeyStore.store = previous
		configuredPlatformKeyStore.Unlock()
	})
}
