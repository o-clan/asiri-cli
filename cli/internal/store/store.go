package store

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/o-clan/asiri/cli/internal/asiri"
	"github.com/o-clan/asiri/cli/internal/keystore"
)

var workspaceSlugPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,62}$`)
var scopePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9/_-]{1,96}$`)
var namePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{1,96}$`)

type FileStore struct {
	Path  string
	State asiri.State
}

type previousStateFields struct {
	WorkspaceID         string    `json:"workspaceId"`
	WorkspaceSlug       string    `json:"workspaceSlug"`
	RemoteWorkspaceID   string    `json:"remoteWorkspaceId"`
	RemoteWorkspaceSlug string    `json:"remoteWorkspaceSlug"`
	UpdatedAt           time.Time `json:"updatedAt"`
}

type RemoteWrappedKey struct {
	RecipientType string `json:"recipientType"`
	RecipientID   string `json:"recipientId"`
	WrapAlgorithm string `json:"wrapAlgorithm"`
	WrappedKey    string `json:"wrappedKey"`
}

type RemoteSecretVersion struct {
	ID                string             `json:"id,omitempty"`
	OrgID             string             `json:"orgId"`
	Scope             string             `json:"scope"`
	Name              string             `json:"name"`
	Version           int                `json:"version"`
	Algorithm         string             `json:"algorithm"`
	Nonce             string             `json:"nonce"`
	Ciphertext        string             `json:"ciphertext"`
	AAD               string             `json:"aad"`
	WrappedKeys       []RemoteWrappedKey `json:"wrappedKeys"`
	Status            string             `json:"status,omitempty"`
	CreatedByDeviceID string             `json:"createdByDeviceId"`
	CreatedAt         time.Time          `json:"createdAt,omitempty"`
}

type RemoteImportSkipped struct {
	Scope  string
	Name   string
	Reason string
}

type RemoteImportPartialError struct {
	Skipped []RemoteImportSkipped
}

func (e *RemoteImportPartialError) Error() string {
	if e == nil || len(e.Skipped) == 0 {
		return ""
	}
	suffix := ""
	if len(e.Skipped) != 1 {
		suffix = "s"
	}
	first := e.Skipped[0]
	return fmt.Sprintf("skipped %d malformed remote secret version%s: %s: %s", len(e.Skipped), suffix, remoteImportSkippedLabel(first), first.Reason)
}

func (e *RemoteImportPartialError) add(remote RemoteSecretVersion, err error) {
	if err == nil {
		return
	}
	e.Skipped = append(e.Skipped, RemoteImportSkipped{Scope: remote.Scope, Name: remote.Name, Reason: err.Error()})
}

func remoteImportSkippedLabel(skipped RemoteImportSkipped) string {
	if skipped.Scope == "" && skipped.Name == "" {
		return "(missing path)"
	}
	if skipped.Scope == "" {
		return skipped.Name
	}
	if skipped.Name == "" {
		return skipped.Scope
	}
	return SecretKey(skipped.Scope, skipped.Name)
}

type preparedRemoteSecretVersion struct {
	remote  RemoteSecretVersion
	dataKey []byte
	account string
}

type LocalSecretRef struct {
	Scope   string
	Name    string
	Version int
}

type RecoverySetup struct {
	Key         string
	RecipientID string
	PublicKey   string
	Fingerprint string
	Config      asiri.RecoveryConfig
}

type RecoveryKeyIdentity struct {
	RecipientID string
	Fingerprint string
	PublicKey   string
}

type wrappedKeyPayload struct {
	EphemeralPublicKey string `json:"ephemeralPublicKey"`
	Nonce              string `json:"nonce"`
	Ciphertext         string `json:"ciphertext"`
	AAD                string `json:"aad"`
}

func DefaultPath() (string, error) {
	if home := os.Getenv("ASIRI_HOME"); home != "" {
		return filepath.Join(home, "local-state.json"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".asiri", "local-state.json"), nil
}

func LoadDefault() (*FileStore, error) {
	path, err := DefaultPath()
	if err != nil {
		return nil, err
	}
	return Load(path)
}

func Load(path string) (*FileStore, error) {
	store := &FileStore{Path: path}
	bytes, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		store.State = asiri.State{Version: 1, Secrets: map[string]asiri.Secret{}, Policies: []asiri.Policy{}, Audit: []asiri.AuditEvent{}, RemoteBindings: map[string]asiri.RemoteWorkspaceBinding{}}
		return store, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(bytes, &store.State); err != nil {
		return nil, err
	}
	store.migratePreviousState(bytes)
	if store.State.Secrets == nil {
		store.State.Secrets = map[string]asiri.Secret{}
	}
	if store.State.KeyRefs == nil {
		store.State.KeyRefs = []asiri.KeyRef{}
	}
	if store.State.RemoteBindings == nil {
		store.State.RemoteBindings = map[string]asiri.RemoteWorkspaceBinding{}
	}
	return store, nil
}

func (s *FileStore) migratePreviousState(bytes []byte) {
	var previous previousStateFields
	if err := json.Unmarshal(bytes, &previous); err != nil {
		return
	}
	if s.State.VaultID == "" && previous.WorkspaceID != "" && previous.WorkspaceID != previous.RemoteWorkspaceID {
		s.State.VaultID = previous.WorkspaceID
	}
	if s.State.VaultID == "" && previous.RemoteWorkspaceID != "" {
		s.State.VaultID = NewID("vault")
	}
	if previous.RemoteWorkspaceID == "" {
		return
	}
	prefix := previous.RemoteWorkspaceSlug
	if prefix == "" {
		prefix = previous.WorkspaceSlug
	}
	if prefix == "" {
		return
	}
	if s.State.RemoteBindings == nil {
		s.State.RemoteBindings = map[string]asiri.RemoteWorkspaceBinding{}
	}
	if existing := s.State.RemoteBindings[prefix]; existing.WorkspaceID != "" {
		return
	}
	boundAt := previous.UpdatedAt
	if boundAt.IsZero() {
		boundAt = time.Now().UTC()
	}
	s.State.RemoteBindings[prefix] = asiri.RemoteWorkspaceBinding{
		WorkspaceID:   previous.RemoteWorkspaceID,
		WorkspaceSlug: previous.RemoteWorkspaceSlug,
		BoundAt:       boundAt,
	}
}

func (s *FileStore) Save() error {
	if s.State.CreatedAt.IsZero() {
		s.State.CreatedAt = time.Now().UTC()
	}
	s.State.UpdatedAt = time.Now().UTC()
	if err := os.MkdirAll(filepath.Dir(s.Path), 0o700); err != nil {
		return err
	}
	bytes, err := json.MarshalIndent(s.State, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.Path, bytes, 0o600)
}

func (s *FileStore) InitializeLocal() error {
	if s.State.VaultID != "" {
		return errors.New("asiri is already initialized")
	}
	s.State.Version = 1
	s.State.VaultID = NewID("vault")
	s.State.UserID = "local-human"
	s.State.KeyStore = "platform"
	if s.State.Secrets == nil {
		s.State.Secrets = map[string]asiri.Secret{}
	}
	if s.State.RemoteBindings == nil {
		s.State.RemoteBindings = map[string]asiri.RemoteWorkspaceBinding{}
	}
	s.Audit(s.State.UserID, "local_vault_initialized", "allowed", "", "", "offline local vault initialized", nil)
	return s.Save()
}

func (s *FileStore) RequireInitialized() error {
	if s.State.VaultID == "" || s.State.UserID == "" || s.State.KeyStore != "platform" {
		return errors.New("asiri is not initialized; run `asiri init` first")
	}
	return nil
}

func (s *FileStore) ActiveDevice() (*asiri.Device, error) {
	if currentID := s.currentLocalDeviceID(); currentID != "" {
		return s.localTrustedDevice(currentID)
	}
	if len(s.State.Devices) == 1 {
		if s.State.Devices[0].Status == asiri.DeviceTrusted {
			return &s.State.Devices[0], nil
		}
		return nil, errors.New("no trusted device found; run `asiri device enroll --name <name>`")
	}
	if len(s.State.Devices) == 0 {
		return nil, errors.New("no trusted device found; run `asiri device enroll --name <name>`")
	}
	return nil, errors.New("local device binding is missing; run `asiri login --force` or re-enroll this device")
}

func (s *FileStore) currentLocalDeviceID() string {
	if s.State.ControlPlane != nil && s.State.ControlPlane.LocalDeviceID != "" {
		return s.State.ControlPlane.LocalDeviceID
	}
	if s.State.LocalDeviceID != "" {
		return s.State.LocalDeviceID
	}
	return ""
}

func (s *FileStore) localTrustedDevice(deviceID string) (*asiri.Device, error) {
	if deviceID == "" {
		return nil, errors.New("local device id is required")
	}
	for i := range s.State.Devices {
		if s.State.Devices[i].ID == deviceID && s.State.Devices[i].Status == asiri.DeviceTrusted {
			return &s.State.Devices[i], nil
		}
	}
	return nil, fmt.Errorf("trusted local device %s not found", deviceID)
}

func (s *FileStore) DeviceSigningPrivateKey() (*ecdsa.PrivateKey, error) {
	if s.State.ControlPlane == nil || s.State.ControlPlane.LocalDeviceID == "" {
		return nil, errors.New("control plane local device binding is missing; run `asiri login --force`")
	}
	if _, err := s.localTrustedDevice(s.State.ControlPlane.LocalDeviceID); err != nil {
		return nil, err
	}
	return s.deviceSigningPrivateKey(s.State.ControlPlane.LocalDeviceID)
}

func (s *FileStore) LocalDeviceSigningPrivateKey() (*ecdsa.PrivateKey, error) {
	device, err := s.ActiveDevice()
	if err != nil {
		return nil, err
	}
	return s.deviceSigningPrivateKey(device.ID)
}

func (s *FileStore) deviceSigningPrivateKey(deviceID string) (*ecdsa.PrivateKey, error) {
	account := keystore.DeviceKeyAccount(deviceID, "signing-private")
	hasRef := false
	for _, ref := range s.State.KeyRefs {
		if ref.Purpose == "device-signing-private-key" && ref.Account == account {
			hasRef = true
			break
		}
	}
	if !hasRef {
		return nil, fmt.Errorf("device signing key ref not found for %s", deviceID)
	}
	encoded, err := keystore.Load(account)
	if err != nil {
		return nil, err
	}
	privateBytes, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, err
	}
	privateKey, err := x509.ParseECPrivateKey(privateBytes)
	if err != nil {
		return nil, err
	}
	if privateKey.Curve != elliptic.P256() {
		return nil, errors.New("device signing key must be P-256")
	}
	return privateKey, nil
}

func (s *FileStore) AddSecret(fullPath, value string) (asiri.Secret, error) {
	if err := s.RequireInitialized(); err != nil {
		return asiri.Secret{}, err
	}
	device, err := s.ActiveDevice()
	if err != nil {
		return asiri.Secret{}, err
	}
	scope, name, err := ParseSecretPath(fullPath)
	if err != nil {
		return asiri.Secret{}, err
	}
	now := time.Now().UTC()
	key := SecretKey(scope, name)
	secret := s.State.Secrets[key]
	if secret.Scope == "" {
		secret = asiri.Secret{Scope: scope, Name: name, NameHash: HashSecretName(scope, name), Versions: []asiri.SecretVersion{}, CreatedAt: now}
	}
	for i := range secret.Versions {
		if secret.Versions[i].Status == "active" {
			secret.Versions[i].Status = "stale"
		}
	}
	version := len(secret.Versions) + 1
	workspaceID := s.encryptionWorkspaceIDForScope(scope)
	aad := fmt.Sprintf("%s:%s:%s:%d:%s", workspaceID, scope, name, version, device.ID)
	dataKey, dataKeyAccount, err := s.newSecretDataKey(scope, name, version)
	if err != nil {
		return asiri.Secret{}, err
	}
	nonce, ciphertext, err := encryptWithKey(dataKey, []byte(value), []byte(aad))
	if err != nil {
		s.deleteDataKeyAccounts(dataKeyAccount)
		return asiri.Secret{}, err
	}
	secret.Versions = append(secret.Versions, asiri.SecretVersion{
		Version: version, Algorithm: "aes-256-gcm", Nonce: nonce, AAD: aad, Ciphertext: ciphertext, DataKeyAccount: dataKeyAccount, Status: "active", CreatedAt: now,
	})
	secret.ActiveVersion = version
	secret.UpdatedAt = now
	s.State.Secrets[key] = secret
	action := "secret_created"
	if version > 1 {
		action = "secret_rotated"
	}
	s.Audit(device.ID, action, "allowed", scope, secret.NameHash, "encrypted locally", map[string]string{"version": fmt.Sprintf("%d", version)})
	if err := s.Save(); err != nil {
		s.deleteDataKeyAccounts(dataKeyAccount)
		return asiri.Secret{}, err
	}
	return secret, nil
}

func (s *FileStore) GetSecret(fullPath string) (string, asiri.Secret, error) {
	if err := s.RequireInitialized(); err != nil {
		return "", asiri.Secret{}, err
	}
	secret, err := s.SecretMetadata(fullPath)
	if err != nil {
		return "", asiri.Secret{}, err
	}
	for _, version := range secret.Versions {
		if version.Version == secret.ActiveVersion && version.Status == "active" {
			plaintext, err := s.decryptSecretVersion(version)
			if err != nil {
				return "", asiri.Secret{}, err
			}
			return string(plaintext), secret, nil
		}
	}
	return "", asiri.Secret{}, fmt.Errorf("secret %s has no active version", fullPath)
}

func (s *FileStore) SecretMetadata(fullPath string) (asiri.Secret, error) {
	scope, name, err := ParseSecretPath(fullPath)
	if err != nil {
		return asiri.Secret{}, err
	}
	secret, ok := s.State.Secrets[SecretKey(scope, name)]
	if !ok {
		return asiri.Secret{}, fmt.Errorf("secret %s not found", fullPath)
	}
	return secret, nil
}

func (s *FileStore) RemoveSecret(fullPath string) error {
	scope, name, err := ParseSecretPath(fullPath)
	if err != nil {
		return err
	}
	key := SecretKey(scope, name)
	secret, ok := s.State.Secrets[key]
	if !ok {
		return fmt.Errorf("secret %s not found", fullPath)
	}
	accounts := make([]string, 0, len(secret.Versions))
	for _, version := range secret.Versions {
		if version.DataKeyAccount != "" {
			accounts = append(accounts, version.DataKeyAccount)
		}
	}
	delete(s.State.Secrets, key)
	s.removeKeyRefs(accounts...)
	s.Audit(s.State.UserID, "secret_deleted", "allowed", scope, secret.NameHash, "deleted by local runtime", nil)
	if err := s.Save(); err != nil {
		return err
	}
	for _, account := range accounts {
		_ = keystore.Delete(account)
	}
	return nil
}

func (s *FileStore) Grant(subject, fullPath string, actions []string) (asiri.Policy, error) {
	if err := s.RequireInitialized(); err != nil {
		return asiri.Policy{}, err
	}
	subject = NormalizeSubjectLabel(subject)
	if err := s.ValidateSubjectLabel(subject); err != nil {
		return asiri.Policy{}, err
	}
	scope, name, err := ParseSecretPath(fullPath)
	if err != nil {
		return asiri.Policy{}, err
	}
	policy := asiri.Policy{ID: NewID("pol"), Subject: subject, ScopePattern: scope, SecretPattern: name, Actions: actions, ApprovalMode: "none", CreatedAt: time.Now().UTC()}
	s.State.Policies = append(s.State.Policies, policy)
	s.Audit(s.State.UserID, "policy_changed", "allowed", scope, HashSecretName(scope, name), "grant created", map[string]string{"subject": subject, "actions": strings.Join(actions, ",")})
	return policy, s.Save()
}

func (s *FileStore) Deny(subject, pattern string) (asiri.Policy, error) {
	if err := s.RequireInitialized(); err != nil {
		return asiri.Policy{}, err
	}
	subject = NormalizeSubjectLabel(subject)
	if err := s.ValidateSubjectLabel(subject); err != nil {
		return asiri.Policy{}, err
	}
	scope := pattern
	name := "*"
	if strings.Contains(pattern, "/") {
		parts := strings.Split(pattern, "/")
		if len(parts) > 1 {
			name = parts[len(parts)-1]
			scope = strings.Join(parts[:len(parts)-1], "/")
		}
	}
	policy := asiri.Policy{ID: NewID("pol"), Subject: subject, ScopePattern: scope, SecretPattern: name, Actions: []string{"deny"}, ApprovalMode: "require-owner", CreatedAt: time.Now().UTC()}
	s.State.Policies = append(s.State.Policies, policy)
	s.Audit(s.State.UserID, "policy_changed", "allowed", scope, "", "deny policy created", map[string]string{"subject": subject})
	return policy, s.Save()
}

func (s *FileStore) CheckPolicy(subject, fullPath, action string) (bool, string) {
	subject = NormalizeSubjectLabel(subject)
	scope, name, err := ParseSecretPath(fullPath)
	if err != nil {
		return false, err.Error()
	}
	now := time.Now().UTC()
	if subject != "" && s.isReservedSubjectLabel(subject) {
		return false, "subject label is reserved for human identity"
	}
	if subject != "" {
		for _, policy := range s.State.Policies {
			if policyExpired(policy, now) {
				continue
			}
			if policy.Subject == subject && MatchPattern(policy.ScopePattern, scope) && MatchPattern(policy.SecretPattern, name) && contains(policy.Actions, "deny") {
				return false, "access denied by owner policy"
			}
		}
	}
	if action == "read" && subject != "" {
		for _, policy := range s.State.Policies {
			if policyExpired(policy, now) {
				continue
			}
			if policy.Subject == subject && policy.ApprovalMode == "none" && MatchPattern(policy.ScopePattern, scope) && MatchPattern(policy.SecretPattern, name) && contains(policy.Actions, "read") {
				return true, "explicit raw read grant"
			}
		}
		return false, "agent raw read requires explicit policy"
	}
	if subject == "" {
		return true, "human local runtime access"
	}
	for _, policy := range s.State.Policies {
		if policyExpired(policy, now) {
			continue
		}
		if policy.Subject == subject && policy.ApprovalMode == "none" && MatchPattern(policy.ScopePattern, scope) && MatchPattern(policy.SecretPattern, name) && contains(policy.Actions, action) {
			return true, "policy allowed"
		}
	}
	return false, "no matching policy"
}

func policyExpired(policy asiri.Policy, now time.Time) bool {
	return policy.ExpiresAt != nil && !policy.ExpiresAt.After(now)
}

func (s *FileStore) ValidateSubjectLabel(subject string) error {
	subject = NormalizeSubjectLabel(subject)
	if subject == "" {
		return errors.New("subject label is required")
	}
	if s.isReservedSubjectLabel(subject) {
		return errors.New("subject label is reserved for human identity")
	}
	return nil
}

func (s *FileStore) isReservedSubjectLabel(subject string) bool {
	subject = NormalizeSubjectLabel(subject)
	if subject == "" {
		return false
	}
	if s.State.UserID != "" && subject == s.State.UserID {
		return true
	}
	return s.State.ControlPlane != nil && s.State.ControlPlane.UserID != "" && subject == s.State.ControlPlane.UserID
}

func NormalizeSubjectLabel(subject string) string {
	return strings.TrimSpace(subject)
}

func (s *FileStore) RevokeDevice(nameOrID string) error {
	for i := range s.State.Devices {
		if s.State.Devices[i].ID == nameOrID || s.State.Devices[i].Name == nameOrID {
			if s.State.Devices[i].Status == asiri.DeviceTrusted && s.trustedDeviceCount() == 1 && len(s.ActiveSecretRefs()) > 0 {
				return errors.New("cannot revoke the last trusted local device while active local secrets exist; configure recovery or rewrap another trusted device first")
			}
			now := time.Now().UTC()
			deviceID := s.State.Devices[i].ID
			currentID := s.currentLocalDeviceID()
			revokedCurrent := deviceID == currentID || currentID == ""
			accounts := s.deviceKeyAccounts(deviceID)
			if revokedCurrent {
				accounts = s.allKeyRefAccounts()
			}
			deleteErr := deleteKeyAccounts(accounts)
			s.removeKeyRefs(accounts...)
			s.State.Devices[i].Status = asiri.DeviceRevoked
			s.State.Devices[i].RevokedAt = &now
			reason := "future sync blocked"
			if revokedCurrent {
				reason = "local device revoked; local key material cleared"
				s.Audit(s.State.UserID, "local_key_material_cleared", "allowed", "", "", reason, nil)
			}
			s.Audit(s.State.UserID, "device_revoked", "allowed", "", "", reason, map[string]string{"device": s.State.Devices[i].Name})
			if err := s.Save(); err != nil {
				return err
			}
			return deleteErr
		}
	}
	return fmt.Errorf("device %s not found", nameOrID)
}

func (s *FileStore) trustedDeviceCount() int {
	count := 0
	for _, device := range s.State.Devices {
		if device.Status == asiri.DeviceTrusted {
			count += 1
		}
	}
	return count
}

func (s *FileStore) deviceKeyAccounts(deviceID string) []string {
	accounts := []string{}
	for _, ref := range s.State.KeyRefs {
		if ref.Account == keystore.DeviceKeyAccount(deviceID, "encryption-private") || ref.Account == keystore.DeviceKeyAccount(deviceID, "signing-private") {
			accounts = append(accounts, ref.Account)
		}
	}
	return accounts
}

func (s *FileStore) allKeyRefAccounts() []string {
	accounts := make([]string, 0, len(s.State.KeyRefs))
	for _, ref := range s.State.KeyRefs {
		if ref.Account != "" {
			accounts = append(accounts, ref.Account)
		}
	}
	return accounts
}

func (s *FileStore) AddKeyRef(purpose, account string) {
	s.addKeyRef(purpose, account)
}

func (s *FileStore) LinkControlPlane(origin, workspaceID, workspaceSlug, userID, deviceID, accessToken, refreshToken string, expiresIn int, refreshExpiresAt string) error {
	device, err := s.ActiveDevice()
	if err != nil {
		return err
	}
	return s.LinkControlPlaneForDevice(origin, workspaceID, workspaceSlug, userID, deviceID, device.ID, accessToken, refreshToken, expiresIn, refreshExpiresAt)
}

func (s *FileStore) LinkControlPlaneForDevice(origin, workspaceID, workspaceSlug, userID, deviceID, localDeviceID, accessToken, refreshToken string, expiresIn int, refreshExpiresAt string) error {
	if err := s.RequireInitialized(); err != nil {
		return err
	}
	if _, err := s.localTrustedDevice(localDeviceID); err != nil {
		return err
	}
	if accessToken == "" || refreshToken == "" {
		return errors.New("control plane did not return session tokens")
	}
	if workspaceID == "" || workspaceSlug == "" {
		return errors.New("control plane did not return workspace metadata")
	}
	accessAccount := keystore.SessionAccessAccount(workspaceID, deviceID)
	refreshAccount := keystore.SessionRefreshAccount(workspaceID, deviceID)
	refreshExpiry, err := parseControlPlaneExpiry(refreshExpiresAt, 7*24*time.Hour)
	if err != nil {
		return err
	}
	accessExpiry := time.Now().UTC().Add(time.Duration(expiresIn) * time.Second)
	if expiresIn <= 0 {
		accessExpiry = time.Now().UTC().Add(time.Hour)
	}
	if s.State.ControlPlane != nil {
		s.deleteControlPlaneTokens(s.State.ControlPlane)
	}
	if err := keystore.Store(accessAccount, accessToken); err != nil {
		return err
	}
	if err := keystore.Store(refreshAccount, refreshToken); err != nil {
		_ = keystore.Delete(accessAccount)
		return err
	}
	s.addKeyRef("control-plane-access-token", accessAccount)
	s.addKeyRef("control-plane-refresh-token", refreshAccount)
	s.State.ControlPlane = &asiri.ControlPlaneLink{
		Origin:               origin,
		WorkspaceID:          workspaceID,
		WorkspaceSlug:        workspaceSlug,
		UserID:               userID,
		DeviceID:             deviceID,
		LocalDeviceID:        localDeviceID,
		Source:               "device-code",
		AccessTokenAccount:   accessAccount,
		RefreshTokenAccount:  refreshAccount,
		AccessTokenExpiresAt: accessExpiry,
		RefreshExpiresAt:     refreshExpiry,
		LinkedAt:             time.Now().UTC(),
	}
	s.State.LocalDeviceID = localDeviceID
	s.Audit(s.State.UserID, "control_plane_linked", "allowed", "", "", "device-code login approved", map[string]string{"origin": origin, "workspace": workspaceSlug, "remoteDevice": deviceID})
	return s.Save()
}

func (s *FileStore) LinkWorkloadControlPlane(origin, workspaceID, workspaceSlug, userID, workloadID, workloadSlug, deviceID, localDeviceID, accessToken string, expiresIn int) error {
	if err := s.RequireInitialized(); err != nil {
		return err
	}
	if _, err := s.localTrustedDevice(localDeviceID); err != nil {
		return err
	}
	if accessToken == "" {
		return errors.New("control plane did not return an access token")
	}
	if workspaceID == "" || workspaceSlug == "" || workloadID == "" || workloadSlug == "" {
		return errors.New("control plane did not return workload session metadata")
	}
	accessAccount := keystore.SessionAccessAccount(workspaceID, deviceID)
	if s.State.ControlPlane != nil {
		s.deleteControlPlaneTokens(s.State.ControlPlane)
	}
	if err := keystore.Store(accessAccount, accessToken); err != nil {
		return err
	}
	s.addKeyRef("control-plane-access-token", accessAccount)
	expiresAt := time.Now().UTC().Add(time.Duration(expiresIn) * time.Second)
	if expiresIn <= 0 {
		expiresAt = time.Now().UTC().Add(15 * time.Minute)
	}
	s.State.ControlPlane = &asiri.ControlPlaneLink{
		Origin:               origin,
		WorkspaceID:          workspaceID,
		WorkspaceSlug:        workspaceSlug,
		UserID:               userID,
		WorkloadID:           workloadID,
		WorkloadSlug:         workloadSlug,
		DeviceID:             deviceID,
		LocalDeviceID:        localDeviceID,
		Source:               "oidc",
		AccessTokenAccount:   accessAccount,
		AccessTokenExpiresAt: expiresAt,
		RefreshExpiresAt:     expiresAt,
		LinkedAt:             time.Now().UTC(),
	}
	s.State.LocalDeviceID = localDeviceID
	s.Audit(workloadSlug, "control_plane_linked", "allowed", "", "", "OIDC workload session approved", map[string]string{"origin": origin, "workspace": workspaceSlug, "remoteDevice": deviceID})
	return s.Save()
}

func (s *FileStore) ControlPlaneRefreshToken() (string, error) {
	if s.State.ControlPlane == nil || s.State.ControlPlane.RefreshTokenAccount == "" {
		return "", errors.New("asiri is not linked to a control plane")
	}
	return keystore.Load(s.State.ControlPlane.RefreshTokenAccount)
}

func (s *FileStore) ControlPlaneAccessToken() (string, error) {
	if s.State.ControlPlane == nil || s.State.ControlPlane.AccessTokenAccount == "" {
		return "", errors.New("asiri is not linked to a control plane")
	}
	return keystore.Load(s.State.ControlPlane.AccessTokenAccount)
}

func (s *FileStore) RemoteSecretVersionsForPrefix(prefix string) ([]RemoteSecretVersion, error) {
	recovery := s.ActiveRecovery()
	return s.RemoteSecretVersionsForPrefixWithRecovery(prefix, recovery)
}

func (s *FileStore) RemoteSecretVersionsForPrefixWithRecovery(prefix string, recovery *asiri.RecoveryConfig) ([]RemoteSecretVersion, error) {
	refs := []LocalSecretRef{}
	for _, ref := range s.ActiveSecretRefs() {
		if WorkspacePrefix(ref.Scope) == prefix {
			refs = append(refs, ref)
		}
	}
	return s.RemoteSecretVersionsForRefsWithRecovery(prefix, refs, recovery)
}

func (s *FileStore) RemoteSecretVersionsForRefsWithRecovery(prefix string, refs []LocalSecretRef, recovery *asiri.RecoveryConfig) ([]RemoteSecretVersion, error) {
	if err := s.RequireInitialized(); err != nil {
		return nil, err
	}
	if s.State.ControlPlane == nil {
		return nil, errors.New("asiri is not linked to a control plane")
	}
	if binding, ok := s.RemoteBindingForPrefix(prefix); !ok || binding.WorkspaceID != s.State.ControlPlane.WorkspaceID {
		return nil, fmt.Errorf("workspace prefix %s is not bound to the current control-plane session for %s", prefix, s.State.ControlPlane.WorkspaceSlug)
	}
	device, err := s.ActiveDevice()
	if err != nil {
		return nil, err
	}
	selected := map[string]LocalSecretRef{}
	keys := make([]string, 0, len(refs))
	for _, ref := range refs {
		if WorkspacePrefix(ref.Scope) != prefix {
			return nil, fmt.Errorf("secret %s is not under workspace prefix %s", SecretKey(ref.Scope, ref.Name), prefix)
		}
		key := SecretKey(ref.Scope, ref.Name)
		if _, ok := selected[key]; ok {
			continue
		}
		selected[key] = ref
		keys = append(keys, key)
	}
	sort.Strings(keys)
	versions := make([]RemoteSecretVersion, 0, len(keys))
	for _, key := range keys {
		secret := s.State.Secrets[key]
		if secret.Scope == "" {
			return nil, fmt.Errorf("local secret %s not found", key)
		}
		ref := selected[key]
		targetVersion := ref.Version
		if targetVersion == 0 {
			targetVersion = secret.ActiveVersion
		}
		found := false
		for i := range secret.Versions {
			version := secret.Versions[i]
			if version.Version != targetVersion {
				continue
			}
			found = true
			if version.Status == "deleted" {
				return nil, fmt.Errorf("local secret %s version %d is deleted", key, targetVersion)
			}
			if version.Status != "active" {
				return nil, fmt.Errorf("local secret %s version %d is %s; push only supports active versions", key, targetVersion, version.Status)
			}
			dataKey, err := s.dataKeyForVersion(version)
			if err != nil {
				return nil, err
			}
			wrapped, err := wrapKeyToDevice(dataKey, *device, s.State.ControlPlane.DeviceID)
			if err != nil {
				return nil, err
			}
			wrappedKeys := []RemoteWrappedKey{wrapped}
			if recovery != nil {
				recoveryWrapped, err := recoveryWrappedDataKey(dataKey, *recovery)
				if err != nil {
					return nil, err
				}
				wrappedKeys = append(wrappedKeys, recoveryWrapped)
			}
			versions = append(versions, RemoteSecretVersion{
				OrgID:             s.State.ControlPlane.WorkspaceID,
				Scope:             secret.Scope,
				Name:              secret.Name,
				Version:           version.Version,
				Algorithm:         version.Algorithm,
				Nonce:             version.Nonce,
				Ciphertext:        version.Ciphertext,
				AAD:               version.AAD,
				WrappedKeys:       wrappedKeys,
				CreatedByDeviceID: s.State.ControlPlane.DeviceID,
			})
			break
		}
		if !found {
			return nil, fmt.Errorf("local secret %s version %d not found", key, targetVersion)
		}
	}
	return versions, nil
}

func (s *FileStore) ImportRemoteSecretVersions(versions []RemoteSecretVersion, force bool) (int, error) {
	return s.importRemoteSecretVersions(versions, force, func(remote RemoteSecretVersion) ([]byte, bool, error) {
		dataKey, err := s.UnwrapDeviceDataKey(remote.WrappedKeys)
		if err != nil {
			return nil, false, fmt.Errorf("is not wrapped to this device: %w", err)
		}
		return dataKey, true, nil
	})
}

func (s *FileStore) ImportRecoveryRemoteSecretVersions(versions []RemoteSecretVersion, recoveryKey string, force bool) (int, RecoveryKeyIdentity, error) {
	if err := s.RequireInitialized(); err != nil {
		return 0, RecoveryKeyIdentity{}, err
	}
	privateKey, identity, err := parseRecoveryKey(recoveryKey)
	if err != nil {
		return 0, RecoveryKeyIdentity{}, err
	}
	imported, err := s.importRemoteSecretVersions(versions, force, func(remote RemoteSecretVersion) ([]byte, bool, error) {
		return unwrapRecoveryDataKeyWithIdentity(privateKey, identity, remote.WrappedKeys)
	})
	if err != nil {
		return imported, identity, err
	}
	if imported == 0 {
		return 0, identity, errors.New("remote secrets are not wrapped to this recovery key")
	}
	return imported, identity, nil
}

func RecoveryKeyIdentityForKey(recoveryKey string) (RecoveryKeyIdentity, error) {
	_, identity, err := parseRecoveryKey(recoveryKey)
	return identity, err
}

func (s *FileStore) importRemoteSecretVersions(versions []RemoteSecretVersion, force bool, dataKeyForRemote func(RemoteSecretVersion) ([]byte, bool, error)) (int, error) {
	if err := s.RequireInitialized(); err != nil {
		return 0, err
	}
	if s.State.Secrets == nil {
		s.State.Secrets = map[string]asiri.Secret{}
	}
	if s.State.RemoteBindings == nil {
		s.State.RemoteBindings = map[string]asiri.RemoteWorkspaceBinding{}
	}
	prepared := []preparedRemoteSecretVersion{}
	partial := &RemoteImportPartialError{}
	for _, remote := range versions {
		if remote.Status != "" && remote.Status != "active" {
			continue
		}
		if remote.Scope == "" || remote.Name == "" {
			partial.add(remote, errors.New("remote secret record is missing scope or name"))
			continue
		}
		if s.State.ControlPlane != nil && remote.OrgID != "" && remote.OrgID != s.State.ControlPlane.WorkspaceID {
			partial.add(remote, fmt.Errorf("belongs to workspace %s, not %s", remote.OrgID, s.State.ControlPlane.WorkspaceID))
			continue
		}
		if !remoteAADMatches(remote) {
			partial.add(remote, errors.New("encryption metadata does not match its path"))
			continue
		}
		if s.State.ControlPlane != nil && remote.OrgID == s.State.ControlPlane.WorkspaceID && WorkspacePrefix(remote.Scope) != s.State.ControlPlane.WorkspaceSlug {
			partial.add(remote, fmt.Errorf("belongs to workspace %s, but its path prefix is %s", s.State.ControlPlane.WorkspaceSlug, WorkspacePrefix(remote.Scope)))
			continue
		}
		if remote.Algorithm != "aes-256-gcm" {
			partial.add(remote, fmt.Errorf("unsupported remote secret algorithm %s", remote.Algorithm))
			continue
		}
		dataKey, include, err := dataKeyForRemote(remote)
		if err != nil {
			partial.add(remote, err)
			continue
		}
		if !include {
			continue
		}
		if _, err := decryptWithKey(dataKey, remote.Nonce, remote.Ciphertext, []byte(remote.AAD)); err != nil {
			partial.add(remote, fmt.Errorf("cannot be decrypted by this data key: %w", err))
			continue
		}
		key := SecretKey(remote.Scope, remote.Name)
		if secret := s.State.Secrets[key]; secret.Scope != "" && !force {
			if active := activeSecretVersion(secret); active == nil || active.Version != remote.Version || active.AAD != remote.AAD || active.Ciphertext != remote.Ciphertext {
				return 0, fmt.Errorf("remote secret %s/%s conflicts with a local active version; rerun with --force only if you intend to replace it", remote.Scope, remote.Name)
			}
		}
		accountWorkspaceID := s.State.VaultID
		if remote.OrgID != "" {
			prefix := WorkspacePrefix(remote.Scope)
			if existing := s.State.RemoteBindings[prefix]; existing.WorkspaceID != "" && existing.WorkspaceID != remote.OrgID {
				return 0, fmt.Errorf("remote secret %s/%s belongs to workspace %s, but prefix %s is already bound to workspace %s", remote.Scope, remote.Name, remote.OrgID, prefix, existing.WorkspaceID)
			}
			accountWorkspaceID = remote.OrgID
		}
		prepared = append(prepared, preparedRemoteSecretVersion{
			remote:  remote,
			dataKey: dataKey,
			account: secretDataKeyAccount(accountWorkspaceID, remote.Scope, remote.Name, remote.Version),
		})
	}
	imported := 0
	now := time.Now().UTC()
	type storedDataKeyAccount struct {
		account  string
		previous string
		existed  bool
	}
	storedAccounts := []storedDataKeyAccount{}
	restoreStoredAccounts := func() {
		for _, stored := range storedAccounts {
			if stored.existed {
				_ = keystore.Store(stored.account, stored.previous)
				s.addKeyRef("secret-data-key", stored.account)
				continue
			}
			s.deleteDataKeyAccounts(stored.account)
		}
	}
	for _, item := range prepared {
		remote := item.remote
		previous, loadErr := keystore.Load(item.account)
		accountExisted := loadErr == nil
		if err := s.storeDataKey(item.account, item.dataKey); err != nil {
			restoreStoredAccounts()
			return imported, err
		}
		storedAccounts = append(storedAccounts, storedDataKeyAccount{account: item.account, previous: previous, existed: accountExisted})
		key := SecretKey(remote.Scope, remote.Name)
		secret := s.State.Secrets[key]
		if secret.Scope == "" {
			secret = asiri.Secret{
				Scope:     remote.Scope,
				Name:      remote.Name,
				NameHash:  HashSecretName(remote.Scope, remote.Name),
				Versions:  []asiri.SecretVersion{},
				CreatedAt: remote.CreatedAt,
			}
			if secret.CreatedAt.IsZero() {
				secret.CreatedAt = now
			}
		}
		for i := range secret.Versions {
			if secret.Versions[i].Status == "active" {
				secret.Versions[i].Status = "stale"
			}
		}
		createdAt := remote.CreatedAt
		if createdAt.IsZero() {
			createdAt = now
		}
		nextVersion := asiri.SecretVersion{
			Version:        remote.Version,
			Algorithm:      remote.Algorithm,
			Nonce:          remote.Nonce,
			AAD:            remote.AAD,
			Ciphertext:     remote.Ciphertext,
			DataKeyAccount: item.account,
			Status:         "active",
			CreatedAt:      createdAt,
		}
		replaced := false
		for i := range secret.Versions {
			if secret.Versions[i].Version == remote.Version {
				secret.Versions[i] = nextVersion
				replaced = true
				break
			}
		}
		if !replaced {
			secret.Versions = append(secret.Versions, nextVersion)
		}
		secret.ActiveVersion = remote.Version
		secret.UpdatedAt = now
		s.State.Secrets[key] = secret
		if remote.OrgID != "" {
			prefix := WorkspacePrefix(remote.Scope)
			if existing := s.State.RemoteBindings[prefix]; existing.WorkspaceID == "" {
				workspaceSlug := ""
				if s.State.ControlPlane != nil && s.State.ControlPlane.WorkspaceID == remote.OrgID {
					workspaceSlug = s.State.ControlPlane.WorkspaceSlug
				}
				s.State.RemoteBindings[prefix] = asiri.RemoteWorkspaceBinding{WorkspaceID: remote.OrgID, WorkspaceSlug: workspaceSlug, BoundAt: now}
			}
		}
		imported += 1
	}
	if len(partial.Skipped) > 0 {
		s.Audit(s.State.UserID, "control_plane_import_quarantine", "failed", "", "", "skipped malformed remote secret versions", map[string]string{"count": fmt.Sprintf("%d", len(partial.Skipped)), "first": remoteImportSkippedLabel(partial.Skipped[0])})
	}
	if imported > 0 {
		metadata := map[string]string{"count": fmt.Sprintf("%d", imported)}
		if len(partial.Skipped) > 0 {
			metadata["skipped"] = fmt.Sprintf("%d", len(partial.Skipped))
		}
		s.Audit(s.State.UserID, "control_plane_import", "allowed", "", "", "imported encrypted remote secret versions", metadata)
	}
	if imported > 0 || len(partial.Skipped) > 0 {
		if err := s.Save(); err != nil {
			restoreStoredAccounts()
			return imported, err
		}
		if len(partial.Skipped) > 0 {
			return imported, partial
		}
		return imported, nil
	}
	return imported, nil
}

func activeSecretVersion(secret asiri.Secret) *asiri.SecretVersion {
	for i := range secret.Versions {
		if secret.Versions[i].Version == secret.ActiveVersion && secret.Versions[i].Status == "active" {
			return &secret.Versions[i]
		}
	}
	return nil
}

func remoteAADMatches(remote RemoteSecretVersion) bool {
	parts := strings.Split(remote.AAD, ":")
	if len(parts) != 5 {
		return false
	}
	version, err := strconv.Atoi(parts[3])
	if err != nil {
		return false
	}
	if remote.OrgID != "" && parts[0] != remote.OrgID {
		return false
	}
	return parts[1] == remote.Scope && parts[2] == remote.Name && version == remote.Version
}

func (s *FileStore) RotateDataKeys() (int, error) {
	return s.rotateDataKeys("")
}

func (s *FileStore) RotateDataKeysForPrefix(prefix string) (int, error) {
	if prefix == "" {
		return 0, errors.New("workspace prefix is required")
	}
	return s.rotateDataKeys(prefix)
}

func (s *FileStore) rotateDataKeys(prefix string) (int, error) {
	if err := s.RequireInitialized(); err != nil {
		return 0, err
	}
	device, err := s.ActiveDevice()
	if err != nil {
		return 0, err
	}
	type plainSecret struct {
		key    string
		value  []byte
		secret asiri.Secret
	}
	items := []plainSecret{}
	keys := make([]string, 0, len(s.State.Secrets))
	for key := range s.State.Secrets {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		secret := s.State.Secrets[key]
		if prefix != "" && WorkspacePrefix(secret.Scope) != prefix {
			continue
		}
		for _, version := range secret.Versions {
			if version.Version == secret.ActiveVersion && version.Status == "active" {
				plaintext, err := s.decryptSecretVersion(version)
				if err != nil {
					return 0, err
				}
				items = append(items, plainSecret{key: key, value: plaintext, secret: secret})
				break
			}
		}
	}
	if len(items) == 0 {
		return 0, nil
	}
	newAccounts := []string{}
	nextSecrets := make(map[string]asiri.Secret, len(s.State.Secrets))
	for key, secret := range s.State.Secrets {
		nextSecrets[key] = secret
	}
	now := time.Now().UTC()
	for _, item := range items {
		secret := item.secret
		for i := range secret.Versions {
			if secret.Versions[i].Status == "active" {
				secret.Versions[i].Status = "stale"
			}
		}
		nextVersion := len(secret.Versions) + 1
		workspaceID := s.encryptionWorkspaceIDForScope(secret.Scope)
		aad := fmt.Sprintf("%s:%s:%s:%d:%s", workspaceID, secret.Scope, secret.Name, nextVersion, device.ID)
		dataKey, dataKeyAccount, err := s.newSecretDataKey(secret.Scope, secret.Name, nextVersion)
		if err != nil {
			s.deleteDataKeyAccounts(newAccounts...)
			return 0, err
		}
		newAccounts = append(newAccounts, dataKeyAccount)
		nonce, ciphertext, err := encryptWithKey(dataKey, item.value, []byte(aad))
		if err != nil {
			s.deleteDataKeyAccounts(newAccounts...)
			return 0, err
		}
		secret.Versions = append(secret.Versions, asiri.SecretVersion{
			Version: nextVersion, Algorithm: "aes-256-gcm", Nonce: nonce, AAD: aad, Ciphertext: ciphertext, DataKeyAccount: dataKeyAccount, Status: "active", CreatedAt: now,
		})
		secret.ActiveVersion = nextVersion
		secret.UpdatedAt = now
		nextSecrets[item.key] = secret
	}
	s.State.Secrets = nextSecrets
	s.Audit(device.ID, "data_keys_rotated", "allowed", "", "", "local secrets re-encrypted with new scoped data keys", map[string]string{"secrets": fmt.Sprintf("%d", len(items))})
	if err := s.Save(); err != nil {
		s.deleteDataKeyAccounts(newAccounts...)
		return 0, err
	}
	return len(items), nil
}

func (s *FileStore) ActiveRecovery() *asiri.RecoveryConfig {
	if s.State.ControlPlane == nil || s.State.ControlPlane.WorkspaceID == "" {
		return nil
	}
	recovery, ok := s.State.Recoveries[s.State.ControlPlane.WorkspaceID]
	if !ok {
		return nil
	}
	return &recovery
}

func (s *FileStore) SetupRecovery(force bool) (RecoverySetup, error) {
	if err := s.RequireInitialized(); err != nil {
		return RecoverySetup{}, err
	}
	if s.State.ControlPlane == nil || s.State.ControlPlane.WorkspaceID == "" {
		return RecoverySetup{}, errors.New("asiri is not linked to a control plane")
	}
	if s.ActiveRecovery() != nil && !force {
		return RecoverySetup{}, fmt.Errorf("recovery is already configured for workspace %s; use --force to replace it", s.State.ControlPlane.WorkspaceSlug)
	}
	setup, err := s.GenerateRecoverySetup()
	if err != nil {
		return RecoverySetup{}, err
	}
	s.CommitRecoverySetup(setup)
	return setup, nil
}

func (s *FileStore) GenerateRecoverySetup() (RecoverySetup, error) {
	if err := s.RequireInitialized(); err != nil {
		return RecoverySetup{}, err
	}
	if s.State.ControlPlane == nil || s.State.ControlPlane.WorkspaceID == "" {
		return RecoverySetup{}, errors.New("asiri is not linked to a control plane")
	}
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return RecoverySetup{}, err
	}
	privateBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return RecoverySetup{}, err
	}
	publicBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return RecoverySetup{}, err
	}
	publicKey := base64.StdEncoding.EncodeToString(publicBytes)
	fingerprint := PublicKeyFingerprint(publicKey)
	recipientID := "rec_" + fingerprint
	now := time.Now().UTC()
	config := asiri.RecoveryConfig{
		RecipientID:          recipientID,
		PublicKey:            publicKey,
		PublicKeyFingerprint: fingerprint,
		CreatedAt:            now,
	}
	return RecoverySetup{
		Key:         "asiri_recovery_" + base64.RawURLEncoding.EncodeToString(privateBytes),
		RecipientID: recipientID,
		PublicKey:   publicKey,
		Fingerprint: fingerprint,
		Config:      config,
	}, nil
}

func (s *FileStore) CommitRecoverySetup(setup RecoverySetup) {
	if s.State.Recoveries == nil {
		s.State.Recoveries = map[string]asiri.RecoveryConfig{}
	}
	s.State.Recoveries[s.State.ControlPlane.WorkspaceID] = setup.Config
	s.Audit(s.State.UserID, "recovery_configured", "allowed", s.State.ControlPlane.WorkspaceSlug, "", "workspace recovery public key stored locally", map[string]string{"recipient": setup.RecipientID, "fingerprint": setup.Fingerprint, "workspace": s.State.ControlPlane.WorkspaceSlug})
}

func (s *FileStore) SetActiveRecovery(recovery *asiri.RecoveryConfig) error {
	if s.State.ControlPlane == nil || s.State.ControlPlane.WorkspaceID == "" {
		return errors.New("asiri is not linked to a control plane")
	}
	if s.State.Recoveries == nil {
		s.State.Recoveries = map[string]asiri.RecoveryConfig{}
	}
	if recovery == nil {
		delete(s.State.Recoveries, s.State.ControlPlane.WorkspaceID)
		return s.Save()
	}
	s.State.Recoveries[s.State.ControlPlane.WorkspaceID] = *recovery
	return s.Save()
}

func (s *FileStore) RecoveryWrappedKeyForSecretVersion(scope, name string, version int) (RemoteWrappedKey, error) {
	if err := s.RequireInitialized(); err != nil {
		return RemoteWrappedKey{}, err
	}
	recovery := s.ActiveRecovery()
	if recovery == nil {
		return RemoteWrappedKey{}, errors.New("recovery is not configured for the current control-plane workspace")
	}
	return s.RecoveryWrappedKeyForSecretVersionWithConfig(scope, name, version, *recovery)
}

func (s *FileStore) RecoveryWrappedKeyForSecretVersionWithConfig(scope, name string, version int, recovery asiri.RecoveryConfig) (RemoteWrappedKey, error) {
	if err := s.RequireInitialized(); err != nil {
		return RemoteWrappedKey{}, err
	}
	if WorkspacePrefix(scope) != s.State.ControlPlane.WorkspaceSlug {
		return RemoteWrappedKey{}, fmt.Errorf("secret scope %s is not in the current control-plane workspace %s", scope, s.State.ControlPlane.WorkspaceSlug)
	}
	dataKey, err := s.dataKeyForSecretVersion(scope, name, version)
	if err != nil {
		return RemoteWrappedKey{}, err
	}
	return recoveryWrappedDataKey(dataKey, recovery)
}

func recoveryWrappedDataKey(dataKey []byte, recovery asiri.RecoveryConfig) (RemoteWrappedKey, error) {
	return wrapKeyToPublicKeyWithOptions(dataKey, recovery.PublicKey, recovery.RecipientID, "recovery", "recovery-hkdf-aes256gcm", "asiri recovery wrap", "asiri-recovery-wrap:")
}

func (s *FileStore) UnwrapDeviceDataKey(wrappedKeys []RemoteWrappedKey) ([]byte, error) {
	if err := s.RequireInitialized(); err != nil {
		return nil, err
	}
	if s.State.ControlPlane == nil || s.State.ControlPlane.DeviceID == "" {
		return nil, errors.New("asiri is not linked to a control plane")
	}
	device, err := s.ActiveDevice()
	if err != nil {
		return nil, err
	}
	privateKey, err := s.deviceEncryptionPrivateKey(device.ID)
	if err != nil {
		return nil, err
	}
	for _, key := range wrappedKeys {
		if key.RecipientType == "device" && key.RecipientID == s.State.ControlPlane.DeviceID && key.WrapAlgorithm == "p256-hkdf-aes256gcm" {
			return unwrapKeyWithPrivate(privateKey, key, s.State.ControlPlane.DeviceID, "asiri p256 wrap", "asiri-wrap:")
		}
	}
	return nil, errors.New("remote secrets are not wrapped to this device")
}

func UnwrapRecoveryDataKey(wrappedKeys []RemoteWrappedKey, recoveryKey string) ([]byte, RecoveryKeyIdentity, error) {
	privateKey, identity, err := parseRecoveryKey(recoveryKey)
	if err != nil {
		return nil, RecoveryKeyIdentity{}, err
	}
	dataKey, ok, err := unwrapRecoveryDataKeyWithIdentity(privateKey, identity, wrappedKeys)
	if err != nil {
		return nil, identity, err
	}
	if ok {
		return dataKey, identity, nil
	}
	return nil, identity, errors.New("remote secrets are not wrapped to this recovery key")
}

func unwrapRecoveryDataKeyWithIdentity(privateKey *ecdsa.PrivateKey, identity RecoveryKeyIdentity, wrappedKeys []RemoteWrappedKey) ([]byte, bool, error) {
	for _, key := range wrappedKeys {
		if key.RecipientType == "recovery" && key.RecipientID == identity.RecipientID && key.WrapAlgorithm == "recovery-hkdf-aes256gcm" {
			dataKey, err := unwrapKeyWithPrivate(privateKey, key, identity.RecipientID, "asiri recovery wrap", "asiri-recovery-wrap:")
			return dataKey, true, err
		}
	}
	return nil, false, nil
}

func (s *FileStore) MarkRecoveryWrapped(prefix string, count int) error {
	if s.State.ControlPlane == nil || s.State.ControlPlane.WorkspaceID == "" {
		return errors.New("asiri is not linked to a control plane")
	}
	if prefix != "" && prefix != s.State.ControlPlane.WorkspaceSlug {
		return fmt.Errorf("workspace prefix %s does not match the current control-plane workspace %s", prefix, s.State.ControlPlane.WorkspaceSlug)
	}
	recovery := s.ActiveRecovery()
	if recovery == nil {
		return nil
	}
	recovery.WrappedSecretCount = count
	recovery.LastWrappedAt = time.Now().UTC()
	s.State.Recoveries[s.State.ControlPlane.WorkspaceID] = *recovery
	metadata := map[string]string{"count": fmt.Sprintf("%d", count), "recipient": recovery.RecipientID, "workspace": s.State.ControlPlane.WorkspaceSlug}
	s.Audit(s.State.UserID, "recovery_wrapped", "allowed", prefix, "", "recovery-wrapped active remote secrets", metadata)
	return s.Save()
}

func (s *FileStore) RecoveryWrappedCountForPrefix(prefix string) int {
	if s.State.ControlPlane == nil || prefix != s.State.ControlPlane.WorkspaceSlug {
		return 0
	}
	recovery := s.ActiveRecovery()
	if recovery == nil {
		return 0
	}
	return recovery.WrappedSecretCount
}

func (s *FileStore) ActiveSecretRefs() []LocalSecretRef {
	keys := make([]string, 0, len(s.State.Secrets))
	for key := range s.State.Secrets {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	refs := make([]LocalSecretRef, 0, len(keys))
	for _, key := range keys {
		secret := s.State.Secrets[key]
		for _, version := range secret.Versions {
			if version.Version == secret.ActiveVersion && version.Status == "active" {
				refs = append(refs, LocalSecretRef{Scope: secret.Scope, Name: secret.Name, Version: version.Version})
				break
			}
		}
	}
	return refs
}

func WorkspacePrefix(scope string) string {
	trimmed := strings.Trim(scope, "/")
	if trimmed == "" {
		return ""
	}
	if index := strings.Index(trimmed, "/"); index >= 0 {
		return trimmed[:index]
	}
	return trimmed
}

func ReplaceWorkspacePrefix(scope, oldSlug, newSlug string) (string, bool) {
	trimmed := strings.Trim(scope, "/")
	if trimmed == oldSlug {
		return newSlug, true
	}
	prefix := oldSlug + "/"
	if strings.HasPrefix(trimmed, prefix) {
		return newSlug + "/" + strings.TrimPrefix(trimmed, prefix), true
	}
	return scope, false
}

func (s *FileStore) BindWorkspacePrefix(prefix, remoteWorkspaceID, remoteWorkspaceSlug string) error {
	if err := s.RequireInitialized(); err != nil {
		return err
	}
	if prefix == "" {
		return errors.New("workspace prefix is required")
	}
	if err := ValidateWorkspaceSlug(prefix); err != nil {
		return err
	}
	if remoteWorkspaceID == "" {
		return errors.New("remote workspace id is required")
	}
	if s.State.RemoteBindings == nil {
		s.State.RemoteBindings = map[string]asiri.RemoteWorkspaceBinding{}
	}
	if existing := s.State.RemoteBindings[prefix]; existing.WorkspaceID != "" && existing.WorkspaceID != remoteWorkspaceID {
		return fmt.Errorf("workspace prefix %s is already bound to workspace id %s; refusing to bind it to workspace id %s", prefix, existing.WorkspaceID, remoteWorkspaceID)
	}
	device, err := s.ActiveDevice()
	if err != nil {
		return err
	}
	newAccounts := []string{}
	oldAccounts := []string{}
	nextSecrets := make(map[string]asiri.Secret, len(s.State.Secrets))
	changed := 0
	for key, secret := range s.State.Secrets {
		if WorkspacePrefix(secret.Scope) != prefix {
			nextSecrets[key] = secret
			continue
		}
		for i := range secret.Versions {
			parts := strings.Split(secret.Versions[i].AAD, ":")
			if len(parts) == 5 && parts[0] == remoteWorkspaceID {
				continue
			}
			plaintext, err := s.decryptSecretVersion(secret.Versions[i])
			if err != nil {
				s.deleteDataKeyAccounts(newAccounts...)
				return err
			}
			aad := fmt.Sprintf("%s:%s:%s:%d:%s", remoteWorkspaceID, secret.Scope, secret.Name, secret.Versions[i].Version, device.ID)
			oldAccount := secret.Versions[i].DataKeyAccount
			dataKey, dataKeyAccount, err := s.newSecretDataKeyForWorkspace(remoteWorkspaceID, secret.Scope, secret.Name, secret.Versions[i].Version)
			if err != nil {
				s.deleteDataKeyAccounts(newAccounts...)
				return err
			}
			newAccounts = append(newAccounts, dataKeyAccount)
			nonce, ciphertext, err := encryptWithKey(dataKey, plaintext, []byte(aad))
			if err != nil {
				s.deleteDataKeyAccounts(newAccounts...)
				return err
			}
			secret.Versions[i].AAD = aad
			secret.Versions[i].Nonce = nonce
			secret.Versions[i].Ciphertext = ciphertext
			secret.Versions[i].DataKeyAccount = dataKeyAccount
			if oldAccount != "" && oldAccount != dataKeyAccount {
				oldAccounts = append(oldAccounts, oldAccount)
			}
			changed += 1
		}
		secret.UpdatedAt = time.Now().UTC()
		nextSecrets[key] = secret
	}
	s.State.Secrets = nextSecrets
	s.State.RemoteBindings[prefix] = asiri.RemoteWorkspaceBinding{WorkspaceID: remoteWorkspaceID, WorkspaceSlug: remoteWorkspaceSlug, BoundAt: time.Now().UTC()}
	s.removeKeyRefs(oldAccounts...)
	s.Audit(s.State.UserID, "workspace_prefix_bound", "allowed", prefix, "", "local prefix bound to control-plane workspace id", map[string]string{"workspace": remoteWorkspaceID, "versions": fmt.Sprintf("%d", changed)})
	if err := s.Save(); err != nil {
		s.deleteDataKeyAccounts(newAccounts...)
		return err
	}
	for _, account := range oldAccounts {
		_ = keystore.Delete(account)
	}
	return nil
}

func (s *FileStore) RenameWorkspacePrefix(oldSlug, newSlug, remoteWorkspaceID string) error {
	if err := s.RequireInitialized(); err != nil {
		return err
	}
	if oldSlug == "" || newSlug == "" {
		return errors.New("path prefix rename requires old and new workspace slugs")
	}
	if oldSlug == newSlug {
		return nil
	}
	if err := ValidateWorkspaceSlug(newSlug); err != nil {
		return err
	}
	if remoteWorkspaceID == "" {
		return errors.New("remote workspace id is required")
	}
	if s.State.RemoteBindings == nil {
		s.State.RemoteBindings = map[string]asiri.RemoteWorkspaceBinding{}
	}
	device, err := s.ActiveDevice()
	if err != nil {
		return err
	}
	type renamePlan struct {
		key      string
		newKey   string
		newScope string
		secret   asiri.Secret
		renamed  bool
	}
	plans := make([]renamePlan, 0, len(s.State.Secrets))
	targetKeys := make(map[string]struct{}, len(s.State.Secrets))
	renamed := 0
	for key, secret := range s.State.Secrets {
		newScope, ok := ReplaceWorkspacePrefix(secret.Scope, oldSlug, newSlug)
		newKey := key
		if ok {
			newKey = SecretKey(newScope, secret.Name)
			renamed += 1
		}
		if _, exists := targetKeys[newKey]; exists {
			return fmt.Errorf("cannot rename workspace prefix because secret %s already exists", newKey)
		}
		targetKeys[newKey] = struct{}{}
		plans = append(plans, renamePlan{key: key, newKey: newKey, newScope: newScope, secret: secret, renamed: ok})
	}
	nextSecrets := make(map[string]asiri.Secret, len(s.State.Secrets))
	newAccounts := []string{}
	oldAccounts := []string{}
	for _, plan := range plans {
		if !plan.renamed {
			nextSecrets[plan.key] = plan.secret
			continue
		}
		secret := plan.secret
		newScope := plan.newScope
		secret.Scope = newScope
		secret.NameHash = HashSecretName(newScope, secret.Name)
		for i := range secret.Versions {
			plaintext, err := s.decryptSecretVersion(secret.Versions[i])
			if err != nil {
				s.deleteDataKeyAccounts(newAccounts...)
				return err
			}
			aad := fmt.Sprintf("%s:%s:%s:%d:%s", remoteWorkspaceID, newScope, secret.Name, secret.Versions[i].Version, device.ID)
			oldAccount := secret.Versions[i].DataKeyAccount
			dataKey, dataKeyAccount, err := s.newSecretDataKeyForWorkspace(remoteWorkspaceID, newScope, secret.Name, secret.Versions[i].Version)
			if err != nil {
				s.deleteDataKeyAccounts(newAccounts...)
				return err
			}
			newAccounts = append(newAccounts, dataKeyAccount)
			nonce, ciphertext, err := encryptWithKey(dataKey, plaintext, []byte(aad))
			if err != nil {
				s.deleteDataKeyAccounts(newAccounts...)
				return err
			}
			secret.Versions[i].AAD = aad
			secret.Versions[i].Nonce = nonce
			secret.Versions[i].Ciphertext = ciphertext
			secret.Versions[i].DataKeyAccount = dataKeyAccount
			if oldAccount != "" && oldAccount != dataKeyAccount {
				oldAccounts = append(oldAccounts, oldAccount)
			}
		}
		secret.UpdatedAt = time.Now().UTC()
		nextSecrets[plan.newKey] = secret
	}
	for i := range s.State.Policies {
		if newScope, ok := ReplaceWorkspacePrefix(s.State.Policies[i].ScopePattern, oldSlug, newSlug); ok {
			s.State.Policies[i].ScopePattern = newScope
		}
	}
	s.State.Secrets = nextSecrets
	delete(s.State.RemoteBindings, oldSlug)
	s.State.RemoteBindings[newSlug] = asiri.RemoteWorkspaceBinding{WorkspaceID: remoteWorkspaceID, WorkspaceSlug: newSlug, BoundAt: time.Now().UTC()}
	s.removeKeyRefs(oldAccounts...)
	s.Audit(s.State.UserID, "local_workspace_prefix_renamed", "allowed", "", "", "local path prefix updated before push", map[string]string{"from": oldSlug, "to": newSlug, "secrets": fmt.Sprintf("%d", renamed), "workspace": remoteWorkspaceID})
	if err := s.Save(); err != nil {
		s.deleteDataKeyAccounts(newAccounts...)
		return err
	}
	for _, account := range oldAccounts {
		_ = keystore.Delete(account)
	}
	return nil
}

func (s *FileStore) RemoteWrappedKeyForSecretVersionPublicKey(scope, name string, version int, remoteDeviceID, encryptionPublicKey string) (RemoteWrappedKey, error) {
	if err := s.RequireInitialized(); err != nil {
		return RemoteWrappedKey{}, err
	}
	if s.State.ControlPlane == nil {
		return RemoteWrappedKey{}, errors.New("asiri is not linked to a control plane")
	}
	if err := s.requirePrefixBoundToActiveWorkspace(scope, "rewrap secrets"); err != nil {
		return RemoteWrappedKey{}, err
	}
	dataKey, err := s.dataKeyForSecretVersion(scope, name, version)
	if err != nil {
		return RemoteWrappedKey{}, err
	}
	return wrapKeyToPublicKey(dataKey, encryptionPublicKey, remoteDeviceID)
}

func (s *FileStore) RefreshControlPlane(accessToken string, expiresIn int, refreshExpiresAt string) error {
	if s.State.ControlPlane == nil {
		return errors.New("asiri is not linked to a control plane")
	}
	if accessToken == "" {
		return errors.New("control plane did not return an access token")
	}
	refreshExpiry, err := parseControlPlaneExpiry(refreshExpiresAt, 7*24*time.Hour)
	if err != nil {
		return err
	}
	if err := keystore.Store(s.State.ControlPlane.AccessTokenAccount, accessToken); err != nil {
		return err
	}
	expiresAt := time.Now().UTC().Add(time.Duration(expiresIn) * time.Second)
	if expiresIn <= 0 {
		expiresAt = time.Now().UTC().Add(time.Hour)
	}
	s.State.ControlPlane.AccessTokenExpiresAt = expiresAt
	s.State.ControlPlane.RefreshExpiresAt = refreshExpiry
	s.Audit(s.State.UserID, "control_plane_session_refreshed", "allowed", "", "", "session refreshed", map[string]string{"origin": s.State.ControlPlane.Origin, "workspace": s.State.ControlPlane.WorkspaceSlug})
	return s.Save()
}

func (s *FileStore) ClearControlPlane() error {
	if s.State.ControlPlane == nil {
		return nil
	}
	link := s.State.ControlPlane
	s.deleteControlPlaneTokens(link)
	s.State.ControlPlane = nil
	s.Audit(s.State.UserID, "control_plane_logged_out", "allowed", "", "", "local session cleared", map[string]string{"origin": link.Origin, "workspace": link.WorkspaceSlug})
	return s.Save()
}

func (s *FileStore) QuarantineLocalKeys(reason string) error {
	accounts := s.allKeyRefAccounts()
	deleteErr := deleteKeyAccounts(accounts)
	s.State.KeyRefs = []asiri.KeyRef{}
	s.State.ControlPlane = nil
	now := time.Now().UTC()
	for i := range s.State.Devices {
		if s.State.Devices[i].Status == asiri.DeviceTrusted {
			s.State.Devices[i].Status = asiri.DeviceRevoked
			s.State.Devices[i].RevokedAt = &now
		}
	}
	if reason == "" {
		reason = "local key material cleared"
	}
	s.Audit(s.State.UserID, "local_key_material_cleared", "allowed", "", "", reason, nil)
	if err := s.Save(); err != nil {
		return err
	}
	return deleteErr
}

func deleteKeyAccounts(accounts []string) error {
	var firstErr error
	seen := map[string]bool{}
	for _, account := range accounts {
		if account == "" || seen[account] {
			continue
		}
		seen[account] = true
		if err := keystore.Delete(account); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func (s *FileStore) DeletePlatformKeys() error {
	for _, ref := range s.State.KeyRefs {
		if ref.Account == "" {
			continue
		}
		if err := keystore.Delete(ref.Account); err != nil {
			return err
		}
	}
	return nil
}

func (s *FileStore) addKeyRef(purpose, account string) {
	for _, ref := range s.State.KeyRefs {
		if ref.Account == account {
			return
		}
	}
	s.State.KeyRefs = append(s.State.KeyRefs, asiri.KeyRef{Purpose: purpose, Account: account})
}

func (s *FileStore) deleteControlPlaneTokens(link *asiri.ControlPlaneLink) {
	accounts := []string{link.AccessTokenAccount, link.RefreshTokenAccount}
	for _, account := range accounts {
		if account != "" {
			_ = keystore.Delete(account)
		}
	}
	s.removeKeyRefs(accounts...)
}

func (s *FileStore) encryptionWorkspaceIDForScope(scope string) string {
	prefix := WorkspacePrefix(scope)
	if s.State.RemoteBindings != nil {
		if binding := s.State.RemoteBindings[prefix]; binding.WorkspaceID != "" {
			return binding.WorkspaceID
		}
	}
	return s.State.VaultID
}

func (s *FileStore) RemoteBindingForPrefix(prefix string) (asiri.RemoteWorkspaceBinding, bool) {
	if s.State.RemoteBindings == nil {
		return asiri.RemoteWorkspaceBinding{}, false
	}
	binding := s.State.RemoteBindings[prefix]
	return binding, binding.WorkspaceID != ""
}

func (s *FileStore) requirePrefixBoundToActiveWorkspace(scope, action string) error {
	if s.State.ControlPlane == nil {
		return errors.New("asiri is not linked to a control plane")
	}
	prefix := WorkspacePrefix(scope)
	binding, ok := s.RemoteBindingForPrefix(prefix)
	if !ok {
		return fmt.Errorf("workspace prefix %s is not bound to a control-plane workspace; push or pull it before trying to %s", prefix, action)
	}
	if binding.WorkspaceID != s.State.ControlPlane.WorkspaceID {
		return fmt.Errorf("workspace prefix %s is bound to workspace id %s, but the current control-plane session is workspace id %s; refusing to %s", prefix, binding.WorkspaceID, s.State.ControlPlane.WorkspaceID, action)
	}
	return nil
}

func (s *FileStore) removeKeyRefs(accounts ...string) {
	remove := map[string]bool{}
	for _, account := range accounts {
		if account != "" {
			remove[account] = true
		}
	}
	if len(remove) == 0 {
		return
	}
	refs := s.State.KeyRefs[:0]
	for _, ref := range s.State.KeyRefs {
		if !remove[ref.Account] {
			refs = append(refs, ref)
		}
	}
	s.State.KeyRefs = refs
}

func parseControlPlaneExpiry(value string, fallback time.Duration) (time.Time, error) {
	if value == "" {
		return time.Now().UTC().Add(fallback), nil
	}
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid control plane session expiry: %w", err)
	}
	return parsed.UTC(), nil
}

func (s *FileStore) Audit(actor, action, result, scope, secretNameHash, reason string, metadata map[string]string) {
	s.State.Audit = append([]asiri.AuditEvent{{ID: NewID("aud"), Actor: actor, Action: action, Scope: scope, SecretNameHash: secretNameHash, Result: result, Reason: reason, Metadata: metadata, CreatedAt: time.Now().UTC()}}, s.State.Audit...)
}

func (s *FileStore) MarkAuditEventsRemoteSynced(ids []string, syncedAt time.Time) {
	if len(ids) == 0 {
		return
	}
	selected := map[string]bool{}
	for _, id := range ids {
		selected[id] = true
	}
	for index := range s.State.Audit {
		if selected[s.State.Audit[index].ID] {
			value := syncedAt
			s.State.Audit[index].RemoteSyncedAt = &value
		}
	}
}

func ParseSecretPath(fullPath string) (string, string, error) {
	trimmed := strings.Trim(fullPath, "/")
	index := strings.LastIndex(trimmed, "/")
	if index <= 0 || index == len(trimmed)-1 {
		return "", "", fmt.Errorf("secret path must look like scope/name, got %q", fullPath)
	}
	scope := trimmed[:index]
	name := trimmed[index+1:]
	if !scopePattern.MatchString(scope) {
		return "", "", fmt.Errorf("invalid scope %q", scope)
	}
	if !namePattern.MatchString(name) {
		return "", "", fmt.Errorf("invalid secret name %q", name)
	}
	return scope, name, nil
}

func ValidateWorkspaceSlug(slug string) error {
	if !workspaceSlugPattern.MatchString(slug) {
		return fmt.Errorf("invalid workspace slug %q; use lower-case letters, numbers, and hyphens", slug)
	}
	return nil
}

func SecretKey(scope, name string) string { return scope + "/" + name }

func HashSecretName(scope, name string) string {
	digest := sha256.Sum256([]byte(scope + "/" + name))
	return "sn_" + hex.EncodeToString(digest[:8])
}

func PublicKeyFingerprint(publicKey string) string {
	digest := sha256.Sum256([]byte(publicKey))
	return hex.EncodeToString(digest[:8])
}

func NewID(prefix string) string {
	bytes := make([]byte, 9)
	_, _ = io.ReadFull(rand.Reader, bytes)
	return prefix + "_" + hex.EncodeToString(bytes)
}

func Mask(value string) string {
	return "redacted"
}

func MatchPattern(pattern, value string) bool {
	if pattern == "*" || pattern == value {
		return true
	}
	if strings.HasSuffix(pattern, "*") {
		return strings.HasPrefix(value, strings.TrimSuffix(pattern, "*"))
	}
	return false
}

func encryptWithKey(key, plaintext, aad []byte) (string, string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", "", err
	}
	ciphertext := gcm.Seal(nil, nonce, plaintext, aad)
	return base64.StdEncoding.EncodeToString(nonce), base64.StdEncoding.EncodeToString(ciphertext), nil
}

func (s *FileStore) newSecretDataKey(scope, name string, version int) ([]byte, string, error) {
	return s.newSecretDataKeyForWorkspace(s.encryptionWorkspaceIDForScope(scope), scope, name, version)
}

func (s *FileStore) newSecretDataKeyForWorkspace(workspaceID, scope, name string, version int) ([]byte, string, error) {
	encoded, err := keystore.NewDataKey()
	if err != nil {
		return nil, "", err
	}
	key, err := decodeDataKey(encoded)
	if err != nil {
		return nil, "", err
	}
	account := secretDataKeyAccount(workspaceID, scope, name, version)
	if err := s.storeDataKey(account, key); err != nil {
		return nil, "", err
	}
	return key, account, nil
}

func (s *FileStore) storeDataKey(account string, key []byte) error {
	if len(key) != 32 {
		return errors.New("invalid data key length")
	}
	if err := keystore.Store(account, base64.StdEncoding.EncodeToString(key)); err != nil {
		return err
	}
	s.addKeyRef("secret-data-key", account)
	return nil
}

func (s *FileStore) deleteDataKeyAccounts(accounts ...string) {
	for _, account := range accounts {
		if account != "" {
			_ = keystore.Delete(account)
		}
	}
	s.removeKeyRefs(accounts...)
}

func (s *FileStore) dataKeyForVersion(version asiri.SecretVersion) ([]byte, error) {
	if _, err := s.ActiveDevice(); err != nil {
		return nil, err
	}
	if version.DataKeyAccount == "" {
		return nil, errors.New("secret version is missing a scoped data key")
	}
	return loadDataKey(version.DataKeyAccount)
}

func (s *FileStore) dataKeyForSecretVersion(scope, name string, versionNumber int) ([]byte, error) {
	secret, ok := s.State.Secrets[SecretKey(scope, name)]
	if !ok {
		return nil, fmt.Errorf("secret %s/%s not found", scope, name)
	}
	for _, version := range secret.Versions {
		if version.Version == versionNumber {
			return s.dataKeyForVersion(version)
		}
	}
	return nil, fmt.Errorf("secret %s/%s version %d is not stored locally", scope, name, versionNumber)
}

func (s *FileStore) decryptSecretVersion(version asiri.SecretVersion) ([]byte, error) {
	key, err := s.dataKeyForVersion(version)
	if err != nil {
		return nil, err
	}
	return decryptWithKey(key, version.Nonce, version.Ciphertext, []byte(version.AAD))
}

func loadDataKey(account string) ([]byte, error) {
	encoded, err := keystore.Load(account)
	if err != nil {
		return nil, err
	}
	return decodeDataKey(encoded)
}

func decodeDataKey(encoded string) ([]byte, error) {
	key, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, err
	}
	if len(key) != 32 {
		return nil, errors.New("invalid data key length")
	}
	return key, nil
}

func secretDataKeyAccount(workspaceID, scope, name string, version int) string {
	digest := sha256.Sum256([]byte(workspaceID + "\x00" + scope + "\x00" + name + "\x00" + strconv.Itoa(version)))
	return keystore.DataKeyAccount(workspaceID, hex.EncodeToString(digest[:16]))
}

func decryptWithKey(key []byte, nonceB64, ciphertextB64 string, aad []byte) ([]byte, error) {
	nonce, err := base64.StdEncoding.DecodeString(nonceB64)
	if err != nil {
		return nil, err
	}
	ciphertext, err := base64.StdEncoding.DecodeString(ciphertextB64)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, nonce, ciphertext, aad)
}

func (s *FileStore) deviceEncryptionPrivateKey(deviceID string) (*ecdsa.PrivateKey, error) {
	encoded, err := keystore.Load(keystore.DeviceKeyAccount(deviceID, "encryption-private"))
	if err != nil {
		return nil, err
	}
	privateBytes, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, err
	}
	privateKey, err := x509.ParseECPrivateKey(privateBytes)
	if err != nil {
		return nil, err
	}
	if privateKey.Curve != elliptic.P256() {
		return nil, errors.New("device encryption key must be P-256")
	}
	return privateKey, nil
}

func parseRecoveryKey(recoveryKey string) (*ecdsa.PrivateKey, RecoveryKeyIdentity, error) {
	const prefix = "asiri_recovery_"
	if !strings.HasPrefix(strings.TrimSpace(recoveryKey), prefix) {
		return nil, RecoveryKeyIdentity{}, errors.New("invalid recovery key")
	}
	privateBytes, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(strings.TrimSpace(recoveryKey), prefix))
	if err != nil {
		return nil, RecoveryKeyIdentity{}, err
	}
	privateKey, err := x509.ParseECPrivateKey(privateBytes)
	if err != nil {
		return nil, RecoveryKeyIdentity{}, err
	}
	if privateKey.Curve != elliptic.P256() {
		return nil, RecoveryKeyIdentity{}, errors.New("recovery key must be P-256")
	}
	publicBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, RecoveryKeyIdentity{}, err
	}
	publicKey := base64.StdEncoding.EncodeToString(publicBytes)
	fingerprint := PublicKeyFingerprint(publicKey)
	return privateKey, RecoveryKeyIdentity{RecipientID: "rec_" + fingerprint, Fingerprint: fingerprint, PublicKey: publicKey}, nil
}

func unwrapKeyWithPrivate(privateKey *ecdsa.PrivateKey, wrapped RemoteWrappedKey, recipientID, hkdfLabel, aadPrefix string) ([]byte, error) {
	payloadBytes, err := base64.StdEncoding.DecodeString(wrapped.WrappedKey)
	if err != nil {
		return nil, err
	}
	var payload wrappedKeyPayload
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return nil, err
	}
	ephemeralBytes, err := base64.StdEncoding.DecodeString(payload.EphemeralPublicKey)
	if err != nil {
		return nil, err
	}
	x, y := elliptic.Unmarshal(elliptic.P256(), ephemeralBytes)
	if x == nil || y == nil {
		return nil, errors.New("invalid wrapped key public material")
	}
	nonce, err := base64.StdEncoding.DecodeString(payload.Nonce)
	if err != nil {
		return nil, err
	}
	ciphertext, err := base64.StdEncoding.DecodeString(payload.Ciphertext)
	if err != nil {
		return nil, err
	}
	aad, err := base64.StdEncoding.DecodeString(payload.AAD)
	if err != nil {
		return nil, err
	}
	expectedAAD := []byte(aadPrefix + recipientID)
	if string(aad) != string(expectedAAD) {
		return nil, errors.New("wrapped key AAD does not match recipient")
	}
	sharedX, _ := privateKey.Curve.ScalarMult(x, y, privateKey.D.Bytes())
	if sharedX == nil {
		return nil, errors.New("failed to derive wrapping key")
	}
	wrapKey := hkdfSHA256(sharedX.Bytes(), []byte(hkdfLabel), []byte(recipientID), 32)
	block, err := aes.NewCipher(wrapKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	key, err := gcm.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, err
	}
	if len(key) != 32 {
		return nil, errors.New("invalid unwrapped data key length")
	}
	return key, nil
}

func wrapKeyToDevice(key []byte, device asiri.Device, remoteDeviceID string) (RemoteWrappedKey, error) {
	return wrapKeyToPublicKey(key, device.EncryptionPublicKey, remoteDeviceID)
}

func wrapKeyToPublicKey(key []byte, encryptionPublicKey string, remoteDeviceID string) (RemoteWrappedKey, error) {
	return wrapKeyToPublicKeyWithOptions(key, encryptionPublicKey, remoteDeviceID, "device", "p256-hkdf-aes256gcm", "asiri p256 wrap", "asiri-wrap:")
}

func wrapKeyToPublicKeyWithOptions(key []byte, encryptionPublicKey string, recipientID string, recipientType string, wrapAlgorithm string, hkdfLabel string, aadPrefix string) (RemoteWrappedKey, error) {
	publicBytes, err := base64.StdEncoding.DecodeString(encryptionPublicKey)
	if err != nil {
		return RemoteWrappedKey{}, err
	}
	parsed, err := x509.ParsePKIXPublicKey(publicBytes)
	if err != nil {
		return RemoteWrappedKey{}, err
	}
	publicKey, ok := parsed.(*ecdsa.PublicKey)
	if !ok || publicKey.Curve != elliptic.P256() {
		return RemoteWrappedKey{}, errors.New("device encryption key must be P-256")
	}
	ephemeral, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return RemoteWrappedKey{}, err
	}
	sharedX, _ := publicKey.Curve.ScalarMult(publicKey.X, publicKey.Y, ephemeral.D.Bytes())
	if sharedX == nil {
		return RemoteWrappedKey{}, errors.New("failed to derive device wrapping key")
	}
	wrapKey := hkdfSHA256(sharedX.Bytes(), []byte(hkdfLabel), []byte(recipientID), 32)
	block, err := aes.NewCipher(wrapKey)
	if err != nil {
		return RemoteWrappedKey{}, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return RemoteWrappedKey{}, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return RemoteWrappedKey{}, err
	}
	ephemeralPublic := elliptic.Marshal(elliptic.P256(), ephemeral.PublicKey.X, ephemeral.PublicKey.Y)
	aad := []byte(aadPrefix + recipientID)
	payload := map[string]string{
		"ephemeralPublicKey": base64.StdEncoding.EncodeToString(ephemeralPublic),
		"nonce":              base64.StdEncoding.EncodeToString(nonce),
		"ciphertext":         base64.StdEncoding.EncodeToString(gcm.Seal(nil, nonce, key, aad)),
		"aad":                base64.StdEncoding.EncodeToString(aad),
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return RemoteWrappedKey{}, err
	}
	return RemoteWrappedKey{
		RecipientType: recipientType,
		RecipientID:   recipientID,
		WrapAlgorithm: wrapAlgorithm,
		WrappedKey:    base64.StdEncoding.EncodeToString(encoded),
	}, nil
}

func hkdfSHA256(secret, salt, info []byte, length int) []byte {
	if salt == nil {
		salt = make([]byte, sha256.Size)
	}
	extract := hmac.New(sha256.New, salt)
	extract.Write(secret)
	prk := extract.Sum(nil)
	out := make([]byte, 0, length)
	previous := []byte{}
	counter := byte(1)
	for len(out) < length {
		expand := hmac.New(sha256.New, prk)
		expand.Write(previous)
		expand.Write(info)
		expand.Write([]byte{counter})
		previous = expand.Sum(nil)
		out = append(out, previous...)
		counter++
	}
	return out[:length]
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
