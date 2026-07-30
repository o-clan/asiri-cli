package keystore

import (
	"errors"
	"testing"

	"github.com/zalando/go-keyring"
)

func TestGoKeyringOperationFailuresAreTypedAsUnavailable(t *testing.T) {
	providerErr := errors.New("platform keyring service is unavailable")
	keyring.MockInitWithError(providerErr)
	t.Cleanup(keyring.MockInit)
	store := goKeyringStore{operationErrorsUnavailable: true}

	if err := store.Store(Service, "account", "value"); !errors.Is(err, ErrPlatformUnavailable) {
		t.Fatalf("expected unavailable store error, got %v", err)
	}
	if _, err := store.Load(Service, "account"); !errors.Is(err, ErrPlatformUnavailable) {
		t.Fatalf("expected unavailable load error, got %v", err)
	}
	if err := store.Delete(Service, "account"); !errors.Is(err, ErrPlatformUnavailable) {
		t.Fatalf("expected unavailable delete error, got %v", err)
	}
}

func TestGoKeyringNotFoundRemainsDistinctFromUnavailable(t *testing.T) {
	keyring.MockInit()
	t.Cleanup(keyring.MockInit)
	store := goKeyringStore{operationErrorsUnavailable: true}

	if _, err := store.Load(Service, "missing"); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("expected not-found load error, got %v", err)
	} else if errors.Is(err, ErrPlatformUnavailable) {
		t.Fatalf("not-found load error was classified as unavailable: %v", err)
	}
	if err := store.Delete(Service, "missing"); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("expected not-found delete error, got %v", err)
	} else if errors.Is(err, ErrPlatformUnavailable) {
		t.Fatalf("not-found delete error was classified as unavailable: %v", err)
	}
}
