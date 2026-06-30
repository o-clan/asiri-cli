package keystore

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/zalando/go-keyring"
)

const Service = "asiri"

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
	if err := keyring.Set(Service, account, value); err != nil {
		return fmt.Errorf("platform key storage unavailable: %w", err)
	}
	return nil
}

func Load(account string) (string, error) {
	if dir := fileKeyStoreDir(); dir != "" {
		value, err := os.ReadFile(fileKeyStorePath(dir, account))
		if err != nil {
			return "", fmt.Errorf("file key material unavailable: %w", err)
		}
		return string(value), nil
	}
	value, err := keyring.Get(Service, account)
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
	if err := keyring.Delete(Service, account); err != nil && err != keyring.ErrNotFound {
		return fmt.Errorf("platform key deletion failed: %w", err)
	}
	return nil
}

func fileKeyStoreDir() string {
	return os.Getenv("ASIRI_FILE_KEYSTORE_DIR")
}

func fileKeyStorePath(dir, account string) string {
	sum := sha256.Sum256([]byte(Service + "\x00" + account))
	return filepath.Join(dir, hex.EncodeToString(sum[:])+".key")
}
