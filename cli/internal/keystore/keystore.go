package keystore

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	"github.com/zalando/go-keyring"
)

const Service = "asiri"

var (
	ErrPlatformUnavailable    = errors.New("platform key storage unavailable")
	ErrPlatformAuthentication = errors.New("macOS denied access to the login Keychain.")
	ErrPlatformTimeout        = errors.New("macOS Keychain did not respond in time.")
	ErrKeyNotFound            = errors.New("key material not found")
)

type platformKeyStore interface {
	Store(service, account, value string) error
	Load(service, account string) (string, error)
	Delete(service, account string) error
}

type goKeyringStore struct {
	storeErrorsUnavailable bool
}

type failingPlatformKeyStore struct {
	base      platformKeyStore
	storeErr  error
	loadErr   error
	deleteErr error
}

func (k goKeyringStore) Store(service, account, value string) error {
	if err := keyring.Set(service, account, value); err != nil {
		if k.storeErrorsUnavailable || errors.Is(err, ErrPlatformUnavailable) {
			return fmt.Errorf("%w: %v", ErrPlatformUnavailable, err)
		}
		return err
	}
	return nil
}

func (goKeyringStore) Load(service, account string) (string, error) {
	value, err := keyring.Get(service, account)
	if errors.Is(err, keyring.ErrNotFound) {
		return "", ErrKeyNotFound
	}
	return value, err
}

func (goKeyringStore) Delete(service, account string) error {
	err := keyring.Delete(service, account)
	if errors.Is(err, keyring.ErrNotFound) {
		return ErrKeyNotFound
	}
	return err
}

func (k failingPlatformKeyStore) Store(service, account, value string) error {
	if k.storeErr != nil {
		return k.storeErr
	}
	return k.base.Store(service, account, value)
}

func (k failingPlatformKeyStore) Load(service, account string) (string, error) {
	if k.loadErr != nil {
		return "", k.loadErr
	}
	return k.base.Load(service, account)
}

func (k failingPlatformKeyStore) Delete(service, account string) error {
	if k.deleteErr != nil {
		return k.deleteErr
	}
	return k.base.Delete(service, account)
}

var configuredPlatformKeyStore struct {
	sync.RWMutex
	store platformKeyStore
}

func init() {
	configuredPlatformKeyStore.store = newPlatformKeyStore()
}

var configuredFileKeyStore struct {
	sync.RWMutex
	dir string
}

func DataKeyAccount(workspaceID, keyID string) string {
	return fmt.Sprintf("workspace:%s:data:%s", workspaceID, keyID)
}

func DeviceKeyAccount(deviceID, purpose string) string {
	return fmt.Sprintf("device:%s:%s", deviceID, purpose)
}

func SessionAccessAccount(workspaceID, deviceID string) string {
	return fmt.Sprintf("session:%s:%s:access", workspaceID, deviceID)
}

func SessionRefreshAccount(workspaceID, deviceID string) string {
	return fmt.Sprintf("session:%s:%s:refresh", workspaceID, deviceID)
}

func NewDataKey() (string, error) {
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(key), nil
}

func Store(account, value string) error {
	if dir := fileKeyStoreDir(); dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("file key storage unavailable: %w", err)
		}
		if err := os.WriteFile(fileKeyStorePath(dir, account), []byte(value), 0o600); err != nil {
			return fmt.Errorf("file key storage unavailable: %w", err)
		}
		return nil
	}
	if err := currentPlatformKeyStore().Store(Service, account, value); err != nil {
		if errors.Is(err, ErrPlatformUnavailable) {
			return err
		}
		return fmt.Errorf("platform key storage failed: %w", err)
	}
	return nil
}

func Load(account string) (string, error) {
	if dir := fileKeyStoreDir(); dir != "" {
		value, err := os.ReadFile(fileKeyStorePath(dir, account))
		if err != nil {
			if os.IsNotExist(err) {
				return "", ErrKeyNotFound
			}
			return "", fmt.Errorf("file key material unavailable: %w", err)
		}
		return string(value), nil
	}
	value, err := currentPlatformKeyStore().Load(Service, account)
	if err != nil {
		return "", fmt.Errorf("platform key material unavailable: %w", err)
	}
	return value, nil
}

func Delete(account string) error {
	if dir := fileKeyStoreDir(); dir != "" {
		if err := os.Remove(fileKeyStorePath(dir, account)); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("file key deletion failed: %w", err)
		}
		return nil
	}
	if err := currentPlatformKeyStore().Delete(Service, account); err != nil && !errors.Is(err, ErrKeyNotFound) {
		return fmt.Errorf("platform key deletion failed: %w", err)
	}
	return nil
}

func currentPlatformKeyStore() platformKeyStore {
	configuredPlatformKeyStore.RLock()
	defer configuredPlatformKeyStore.RUnlock()
	return configuredPlatformKeyStore.store
}

// UseGoKeyringForTesting preserves the dependency's in-memory mock behavior in
// packages that exercise keystore consumers. Production code must not call it.
func UseGoKeyringForTesting() func() {
	configuredPlatformKeyStore.Lock()
	previous := configuredPlatformKeyStore.store
	configuredPlatformKeyStore.store = goKeyringStore{}
	configuredPlatformKeyStore.Unlock()
	return func() {
		configuredPlatformKeyStore.Lock()
		configuredPlatformKeyStore.store = previous
		configuredPlatformKeyStore.Unlock()
	}
}

// FailPlatformOperationsForTesting injects operation-specific failures while
// preserving the configured test store and its contents.
func FailPlatformOperationsForTesting(storeErr, loadErr, deleteErr error) func() {
	configuredPlatformKeyStore.Lock()
	previous := configuredPlatformKeyStore.store
	configuredPlatformKeyStore.store = failingPlatformKeyStore{
		base:      previous,
		storeErr:  storeErr,
		loadErr:   loadErr,
		deleteErr: deleteErr,
	}
	configuredPlatformKeyStore.Unlock()
	return func() {
		configuredPlatformKeyStore.Lock()
		configuredPlatformKeyStore.store = previous
		configuredPlatformKeyStore.Unlock()
	}
}

func ConfigureFileKeyStoreDir(dir string) {
	configuredFileKeyStore.Lock()
	defer configuredFileKeyStore.Unlock()
	configuredFileKeyStore.dir = dir
}

func ClearConfiguredFileKeyStoreDir() {
	ConfigureFileKeyStoreDir("")
}

func FileKeyStoreDir() string {
	return fileKeyStoreDir()
}

func fileKeyStoreDir() string {
	configuredFileKeyStore.RLock()
	defer configuredFileKeyStore.RUnlock()
	return configuredFileKeyStore.dir
}

func fileKeyStorePath(dir, account string) string {
	sum := sha256.Sum256([]byte(Service + "\x00" + account))
	return filepath.Join(dir, hex.EncodeToString(sum[:])+".key")
}
