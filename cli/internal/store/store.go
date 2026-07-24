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

const (
	KeyStorePlatform = "platform"
	KeyStoreFile     = "file"
)

type FileStore struct {
	Path                   string
	State                  asiri.State
	auditLedgerUnavailable bool
	loadedStateDigest      [sha256.Size]byte
	loadedStateExists      bool
	loadedStateKnown       bool
	stateLockHeld          bool
}

var ErrAuditLedgerKeyUnavailable = errors.New("local audit ledger key unavailable")
var ErrConcurrentStateChange = errors.New("local Asiri state changed in another process; retry the command")

type persistedAuditFields struct {
	Audit       []asiri.AuditEvent        `json:"audit"`
	AuditLedger []asiri.AuditLedgerRecord `json:"auditLedger"`
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

func LoadDefaultLocked() (*FileStore, func() error, error) {
	path, err := DefaultPath()
	if err != nil {
		return nil, nil, err
	}
	lock, err := acquireStateFileLock(path)
	if err != nil {
		return nil, nil, err
	}
	store, err := Load(path)
	if err != nil {
		_ = lock.Close()
		return nil, nil, err
	}
	store.stateLockHeld = true
	release := func() error {
		store.stateLockHeld = false
		return lock.Close()
	}
	return store, release, nil
}

func Load(path string) (*FileStore, error) {
	store := &FileStore{Path: path}
	bytes, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		store.State = asiri.State{Version: 1, Secrets: map[string]asiri.Secret{}, Policies: []asiri.Policy{}, Audit: []asiri.AuditEvent{}, Workspaces: map[string]asiri.LocalWorkspace{}, RemoteBindings: map[string]asiri.RemoteWorkspaceBinding{}}
		store.loadedStateKnown = true
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
	if store.State.Workspaces == nil {
		store.State.Workspaces = map[string]asiri.LocalWorkspace{}
	}
	store.migrateLocalWorkspaces()
	if store.State.EnvelopeAuditModes == nil {
		store.State.EnvelopeAuditModes = map[string]asiri.AuditMode{}
	}
	store.configureKeyStore()
	if err := store.loadAuditFromLedger(bytes); err != nil {
		return nil, err
	}
	store.removeLegacyOidcControlPlaneSession()
	store.loadedStateDigest = sha256.Sum256(bytes)
	store.loadedStateExists = true
	store.loadedStateKnown = true
	return store, nil
}

func (s *FileStore) removeLegacyOidcControlPlaneSession() {
	if s.State.ControlPlane == nil || s.State.ControlPlane.Source != "oidc" {
		return
	}
	s.deleteControlPlaneTokens(s.State.ControlPlane)
	s.State.ControlPlane = nil
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

func (s *FileStore) migrateLocalWorkspaces() {
	if s.State.VaultID == "" {
		return
	}
	prefixes := map[string]bool{}
	for _, secret := range s.State.Secrets {
		if prefix := WorkspacePrefix(secret.Scope); prefix != "" {
			prefixes[prefix] = true
		}
	}
	for _, policy := range s.State.Policies {
		if prefix := WorkspacePrefix(policy.ScopePattern); prefix != "" {
			prefixes[prefix] = true
		}
	}
	for prefix := range s.State.RemoteBindings {
		if prefix != "" {
			prefixes[prefix] = true
		}
	}
	for prefix := range prefixes {
		if _, ok := s.LocalWorkspace(prefix); ok {
			continue
		}
		binding := s.State.RemoteBindings[prefix]
		kind := "local"
		if binding.WorkspaceID != "" {
			kind = "legacy"
		}
		workspaceID := deterministicLocalWorkspaceID(s.State.VaultID, prefix)
		now := s.State.CreatedAt
		if now.IsZero() {
			now = time.Now().UTC()
		}
		s.State.Workspaces[workspaceID] = asiri.LocalWorkspace{
			ID:                workspaceID,
			CanonicalSlug:     prefix,
			Kind:              kind,
			RemoteWorkspaceID: binding.WorkspaceID,
			CreatedAt:         now,
			UpdatedAt:         now,
		}
	}
}

func (s *FileStore) Save() error {
	return s.save()
}

func (s *FileStore) SaveWithAuditLedger() error {
	return s.save()
}

func (s *FileStore) save() error {
	if err := os.MkdirAll(filepath.Dir(s.Path), 0o700); err != nil {
		return err
	}
	var lock *stateFileLock
	var err error
	if !s.stateLockHeld {
		lock, err = acquireStateFileLock(s.Path)
		if err != nil {
			return err
		}
		defer lock.Close()
	}
	if err := s.requireCurrentStateSnapshot(); err != nil {
		return err
	}
	if s.State.CreatedAt.IsZero() {
		s.State.CreatedAt = time.Now().UTC()
	}
	s.State.UpdatedAt = time.Now().UTC()
	newAuditLedgerKeyAccount := ""
	if err := s.rebuildAuditLedger(&newAuditLedgerKeyAccount); err != nil {
		if newAuditLedgerKeyAccount != "" {
			_ = keystore.Delete(newAuditLedgerKeyAccount)
		}
		return err
	}
	bytes, err := s.writeStateFile()
	if err != nil {
		if newAuditLedgerKeyAccount != "" {
			_ = keystore.Delete(newAuditLedgerKeyAccount)
		}
		return err
	}
	s.loadedStateDigest = sha256.Sum256(bytes)
	s.loadedStateExists = true
	s.loadedStateKnown = true
	return nil
}

func (s *FileStore) requireCurrentStateSnapshot() error {
	if !s.loadedStateKnown {
		return ErrConcurrentStateChange
	}
	bytes, err := os.ReadFile(s.Path)
	if errors.Is(err, os.ErrNotExist) {
		if s.loadedStateExists {
			return ErrConcurrentStateChange
		}
		return nil
	}
	if err != nil {
		return err
	}
	if !s.loadedStateExists || sha256.Sum256(bytes) != s.loadedStateDigest {
		return ErrConcurrentStateChange
	}
	return nil
}

func (s *FileStore) writeStateFile() ([]byte, error) {
	bytes, err := json.MarshalIndent(s.State, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := writeFileAtomically(s.Path, bytes); err != nil {
		return nil, err
	}
	return bytes, nil
}

func writeFileAtomically(path string, bytes []byte) (resultErr error) {
	dir := filepath.Dir(path)
	if info, err := os.Stat(path); err == nil && info.Mode().Perm()&0o200 == 0 {
		return os.ErrPermission
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	temp, err := os.CreateTemp(dir, ".asiri-state-*")
	if err != nil {
		return err
	}
	tempPath := temp.Name()
	defer func() {
		_ = temp.Close()
		_ = os.Remove(tempPath)
	}()
	if err := temp.Chmod(0o600); err != nil {
		return err
	}
	if _, err := temp.Write(bytes); err != nil {
		return err
	}
	if err := temp.Sync(); err != nil {
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := replaceStateFile(tempPath, path); err != nil {
		return err
	}
	if dirHandle, err := os.Open(dir); err == nil {
		_ = dirHandle.Sync()
		_ = dirHandle.Close()
	}
	return nil
}

func (s *FileStore) loadAuditFromLedger(bytes []byte) error {
	var persisted persistedAuditFields
	if err := json.Unmarshal(bytes, &persisted); err != nil {
		return err
	}
	if len(persisted.AuditLedger) > 0 {
		events, err := s.decryptAuditLedger(persisted.AuditLedger)
		if err != nil {
			if errors.Is(err, ErrAuditLedgerKeyUnavailable) {
				s.auditLedgerUnavailable = true
				s.State.Audit = []asiri.AuditEvent{}
				return nil
			}
			return err
		}
		s.State.Audit = events
		return nil
	}
	if s.State.AuditLedgerHead != nil {
		return errors.New("local audit ledger is missing")
	}
	if s.State.VaultID != "" {
		if _, err := loadDataKey(auditLedgerDataKeyAccount(s.State.VaultID)); err == nil {
			return errors.New("local audit ledger is missing")
		} else if !errors.Is(err, keystore.ErrKeyNotFound) {
			return err
		}
	}
	s.State.Audit = persisted.Audit
	for index := range s.State.Audit {
		s.ensureAuditDigest(&s.State.Audit[index])
	}
	if s.State.Audit == nil {
		s.State.Audit = []asiri.AuditEvent{}
	}
	return nil
}

func (s *FileStore) rebuildAuditLedger(newAuditLedgerKeyAccount *string) error {
	if s.auditLedgerUnavailable {
		return ErrAuditLedgerKeyUnavailable
	}
	if len(s.State.Audit) == 0 {
		s.State.AuditLedger = nil
		s.State.AuditLedgerHead = nil
		return nil
	}
	if s.State.VaultID == "" {
		return errors.New("audit ledger requires an initialized vault")
	}
	key, createdAccount, err := s.auditLedgerKey()
	if err != nil {
		return err
	}
	if newAuditLedgerKeyAccount != nil && createdAccount != "" {
		*newAuditLedgerKeyAccount = createdAccount
	}
	records := make([]asiri.AuditLedgerRecord, 0, len(s.State.Audit))
	previousHash := ""
	sequence := 1
	for index := len(s.State.Audit) - 1; index >= 0; index-- {
		event := s.State.Audit[index]
		if event.ID == "" {
			event.ID = NewID("aud")
		}
		if event.CreatedAt.IsZero() {
			event.CreatedAt = time.Now().UTC()
		}
		s.ensureAuditDigest(&event)
		plaintext, err := json.Marshal(event)
		if err != nil {
			return err
		}
		aad := fmt.Sprintf("asiri-audit-ledger:v1:%s:%d:%s", s.State.VaultID, sequence, previousHash)
		nonce, ciphertext, err := encryptWithKey(key, plaintext, []byte(aad))
		if err != nil {
			return err
		}
		record := asiri.AuditLedgerRecord{
			Sequence:     sequence,
			EventID:      event.ID,
			PreviousHash: previousHash,
			Algorithm:    "aes-256-gcm",
			Nonce:        nonce,
			AAD:          aad,
			Ciphertext:   ciphertext,
			CreatedAt:    event.CreatedAt,
		}
		record.Hash = auditLedgerRecordHash(record)
		signature, signatureAlg, signerDeviceID, err := s.signAuditLedgerRecord(key, record.Hash)
		if err != nil {
			return err
		}
		record.Signature = signature
		record.SignatureAlg = signatureAlg
		record.SignerDeviceID = signerDeviceID
		records = append(records, record)
		previousHash = record.Hash
		s.State.Audit[index] = event
		sequence++
	}
	s.State.AuditLedger = records
	headHash := auditLedgerHeadHash(len(records), previousHash)
	signature, signatureAlg, signerDeviceID, err := s.signAuditLedgerRecord(key, headHash)
	if err != nil {
		return err
	}
	s.State.AuditLedgerHead = &asiri.AuditLedgerHead{
		Count:          len(records),
		Hash:           headHash,
		Signature:      signature,
		SignatureAlg:   signatureAlg,
		SignerDeviceID: signerDeviceID,
		UpdatedAt:      time.Now().UTC(),
	}
	return nil
}

func (s *FileStore) decryptAuditLedger(records []asiri.AuditLedgerRecord) ([]asiri.AuditEvent, error) {
	key, err := loadDataKey(auditLedgerDataKeyAccount(s.State.VaultID))
	if err != nil {
		if errors.Is(err, keystore.ErrKeyNotFound) {
			return nil, ErrAuditLedgerKeyUnavailable
		}
		return nil, err
	}
	events := make([]asiri.AuditEvent, 0, len(records))
	previousHash := ""
	for index, record := range records {
		if record.Sequence != index+1 {
			return nil, errors.New("local audit ledger sequence is invalid")
		}
		if record.PreviousHash != previousHash {
			return nil, errors.New("local audit ledger hash chain is invalid")
		}
		if record.Algorithm != "aes-256-gcm" {
			return nil, fmt.Errorf("unsupported local audit ledger algorithm %s", record.Algorithm)
		}
		hash := auditLedgerRecordHash(record)
		if hash != record.Hash {
			return nil, errors.New("local audit ledger record hash mismatch")
		}
		if err := s.verifyAuditLedgerRecord(key, record); err != nil {
			return nil, err
		}
		plaintext, err := decryptWithKey(key, record.Nonce, record.Ciphertext, []byte(record.AAD))
		if err != nil {
			return nil, fmt.Errorf("local audit ledger decrypt failed: %w", err)
		}
		var event asiri.AuditEvent
		if err := json.Unmarshal(plaintext, &event); err != nil {
			return nil, fmt.Errorf("local audit ledger record is invalid: %w", err)
		}
		if event.ID != record.EventID {
			return nil, errors.New("local audit ledger event id mismatch")
		}
		if digest := AuditEventDigest(event); event.Digest != "" && event.Digest != digest {
			return nil, errors.New("local audit ledger event digest mismatch")
		}
		event.Digest = AuditEventDigest(event)
		events = append(events, event)
		previousHash = record.Hash
	}
	if err := s.verifyAuditLedgerHead(key, len(records), previousHash); err != nil {
		return nil, err
	}
	for left, right := 0, len(events)-1; left < right; left, right = left+1, right-1 {
		events[left], events[right] = events[right], events[left]
	}
	return events, nil
}

func (s *FileStore) auditLedgerKey() ([]byte, string, error) {
	account := auditLedgerDataKeyAccount(s.State.VaultID)
	key, err := loadDataKey(account)
	if err == nil {
		return key, "", nil
	}
	if !errors.Is(err, keystore.ErrKeyNotFound) {
		return nil, "", err
	}
	encoded, err := keystore.NewDataKey()
	if err != nil {
		return nil, "", err
	}
	key, err = decodeDataKey(encoded)
	if err != nil {
		return nil, "", err
	}
	if err := keystore.Store(account, encoded); err != nil {
		return nil, "", err
	}
	return key, account, nil
}

func auditLedgerDataKeyAccount(vaultID string) string {
	return keystore.DataKeyAccount(vaultID, "audit-ledger-v1")
}

func (s *FileStore) ensureAuditDigest(event *asiri.AuditEvent) {
	event.Digest = AuditEventDigest(*event)
}

func AuditEventDigest(event asiri.AuditEvent) string {
	payload := struct {
		ID             string            `json:"id"`
		Actor          string            `json:"actor"`
		Action         string            `json:"action"`
		Scope          string            `json:"scope,omitempty"`
		SecretNameHash string            `json:"secretNameHash,omitempty"`
		Result         string            `json:"result"`
		Reason         string            `json:"reason,omitempty"`
		Metadata       map[string]string `json:"metadata,omitempty"`
		CreatedAt      string            `json:"createdAt"`
	}{
		ID:             event.ID,
		Actor:          event.Actor,
		Action:         event.Action,
		Scope:          event.Scope,
		SecretNameHash: event.SecretNameHash,
		Result:         event.Result,
		Reason:         event.Reason,
		Metadata:       event.Metadata,
		CreatedAt:      event.CreatedAt.UTC().Format(time.RFC3339Nano),
	}
	encoded, _ := json.Marshal(payload)
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

func auditLedgerRecordHash(record asiri.AuditLedgerRecord) string {
	payload := struct {
		Sequence     int       `json:"sequence"`
		EventID      string    `json:"eventId"`
		PreviousHash string    `json:"previousHash"`
		Algorithm    string    `json:"algorithm"`
		Nonce        string    `json:"nonce"`
		AAD          string    `json:"aad"`
		Ciphertext   string    `json:"ciphertext"`
		CreatedAt    time.Time `json:"createdAt"`
	}{
		Sequence:     record.Sequence,
		EventID:      record.EventID,
		PreviousHash: record.PreviousHash,
		Algorithm:    record.Algorithm,
		Nonce:        record.Nonce,
		AAD:          record.AAD,
		Ciphertext:   record.Ciphertext,
		CreatedAt:    record.CreatedAt,
	}
	encoded, _ := json.Marshal(payload)
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

func auditLedgerHeadHash(count int, lastHash string) string {
	payload := struct {
		Count    int    `json:"count"`
		LastHash string `json:"lastHash"`
	}{
		Count:    count,
		LastHash: lastHash,
	}
	encoded, _ := json.Marshal(payload)
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

func (s *FileStore) signAuditLedgerRecord(key []byte, recordHash string) (string, string, string, error) {
	// Keep ledger authenticity anchored in key storage. Device public keys live
	// in the editable state file, so they cannot validate state-file integrity.
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(recordHash))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil)), "hmac-sha256", "", nil
}

func (s *FileStore) verifyAuditLedgerHead(key []byte, count int, lastHash string) error {
	head := s.State.AuditLedgerHead
	if head == nil {
		if count > 0 {
			return errors.New("local audit ledger head is missing")
		}
		return nil
	}
	expected := auditLedgerHeadHash(count, lastHash)
	if head.Count != count || head.Hash != expected {
		return errors.New("local audit ledger head mismatch")
	}
	record := asiri.AuditLedgerRecord{
		Hash:           head.Hash,
		Signature:      head.Signature,
		SignatureAlg:   head.SignatureAlg,
		SignerDeviceID: head.SignerDeviceID,
	}
	return s.verifyAuditLedgerRecord(key, record)
}

func (s *FileStore) verifyAuditLedgerRecord(key []byte, record asiri.AuditLedgerRecord) error {
	if record.SignatureAlg != "hmac-sha256" {
		return fmt.Errorf("unsupported local audit ledger signature %s", record.SignatureAlg)
	}
	signature, err := base64.StdEncoding.DecodeString(record.Signature)
	if err != nil {
		return err
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(record.Hash))
	if !hmac.Equal(signature, mac.Sum(nil)) {
		return errors.New("local audit ledger signature is invalid")
	}
	return nil
}

func (s *FileStore) deviceByID(id string) *asiri.Device {
	for index := range s.State.Devices {
		if s.State.Devices[index].ID == id {
			return &s.State.Devices[index]
		}
	}
	return nil
}

func (s *FileStore) InitializeLocal() error {
	if s.State.VaultID != "" {
		return errors.New("asiri is already initialized")
	}
	s.State.Version = 1
	s.State.VaultID = NewID("vault")
	s.State.UserID = "local-human"
	s.State.Workspaces = map[string]asiri.LocalWorkspace{}
	s.State.KeyStore = KeyStorePlatform
	if keystore.FileKeyStoreDir() != "" {
		s.State.KeyStore = KeyStoreFile
	}
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
	if s.State.VaultID == "" || s.State.UserID == "" || !validKeyStore(s.State.KeyStore) {
		return errors.New("asiri is not initialized; run `asiri init` first")
	}
	return nil
}

func (s *FileStore) UseDefaultFileKeyStore() {
	keystore.ConfigureFileKeyStoreDir(DefaultFileKeyStoreDir(s.Path))
	s.State.KeyStore = KeyStoreFile
}

func DefaultFileKeyStoreDir(statePath string) string {
	return filepath.Join(filepath.Dir(statePath), "key-store")
}

func (s *FileStore) configureKeyStore() {
	if s.State.KeyStore == KeyStoreFile {
		keystore.ConfigureFileKeyStoreDir(DefaultFileKeyStoreDir(s.Path))
	}
}

func validKeyStore(keyStore string) bool {
	return keyStore == KeyStorePlatform || keyStore == KeyStoreFile
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
	return s.AddSecretBytes(fullPath, []byte(value))
}

func (s *FileStore) AddSecretBytes(fullPath string, value []byte) (asiri.Secret, error) {
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
	version := nextSecretVersion(secret.Versions)
	workspaceID := s.encryptionWorkspaceIDForScope(scope)
	aad := fmt.Sprintf("%s:%s:%s:%d:%s", workspaceID, scope, name, version, device.ID)
	dataKey, dataKeyAccount, err := s.newSecretDataKey(scope, name, version)
	if err != nil {
		return asiri.Secret{}, err
	}
	nonce, ciphertext, err := encryptWithKey(dataKey, value, []byte(aad))
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
	value, secret, err := s.GetSecretBytes(fullPath)
	return string(value), secret, err
}

func (s *FileStore) GetSecretBytes(fullPath string) ([]byte, asiri.Secret, error) {
	if err := s.RequireInitialized(); err != nil {
		return nil, asiri.Secret{}, err
	}
	secret, err := s.SecretMetadata(fullPath)
	if err != nil {
		return nil, asiri.Secret{}, err
	}
	for _, version := range secret.Versions {
		if version.Version == secret.ActiveVersion && version.Status == "active" {
			plaintext, err := s.decryptSecretVersion(version)
			if err != nil {
				return nil, asiri.Secret{}, err
			}
			return plaintext, secret, nil
		}
	}
	return nil, asiri.Secret{}, fmt.Errorf("secret %s has no active version", fullPath)
}

func (s *FileStore) CheckSecretReadable(fullPath string) error {
	if err := s.RequireInitialized(); err != nil {
		return err
	}
	secret, err := s.SecretMetadata(fullPath)
	if err != nil {
		return err
	}
	for _, version := range secret.Versions {
		if version.Version == secret.ActiveVersion && version.Status == "active" {
			// Verify local usability without returning plaintext. Strict audit
			// still gates external release before the value reaches a caller.
			_, err := s.decryptSecretVersion(version)
			return err
		}
	}
	return fmt.Errorf("secret %s has no active version", fullPath)
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

func ServiceAccountRuntimeSubject(serviceAccountID string) string {
	serviceAccountID = strings.TrimSpace(serviceAccountID)
	if serviceAccountID == "" {
		return ""
	}
	return "service-account:" + serviceAccountID
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

func (s *FileStore) LinkServiceAccountControlPlane(origin, workspaceID, workspaceSlug, approvedByUserID, serviceAccountID, serviceAccountSlug, serviceAccountName, deviceID, localDeviceID, accessToken, refreshToken string, expiresIn int, refreshExpiresAt string) error {
	if err := s.RequireInitialized(); err != nil {
		return err
	}
	if _, err := s.localTrustedDevice(localDeviceID); err != nil {
		return err
	}
	if accessToken == "" {
		return errors.New("control plane did not return an access token")
	}
	if refreshToken == "" {
		return errors.New("control plane did not return a refresh token")
	}
	if workspaceID == "" || workspaceSlug == "" || serviceAccountID == "" || serviceAccountSlug == "" {
		return errors.New("control plane did not return service account session metadata")
	}
	accessAccount := keystore.SessionAccessAccount(workspaceID, deviceID)
	refreshAccount := keystore.SessionRefreshAccount(workspaceID, deviceID)
	refreshExpiry, err := parseControlPlaneExpiry(refreshExpiresAt, 7*24*time.Hour)
	if err != nil {
		return err
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
	runtimeSubject := ServiceAccountRuntimeSubject(serviceAccountID)
	keptPolicies := s.State.Policies[:0]
	for _, policy := range s.State.Policies {
		if NormalizeSubjectLabel(policy.Subject) != runtimeSubject {
			keptPolicies = append(keptPolicies, policy)
		}
	}
	s.State.Policies = keptPolicies
	expiresAt := time.Now().UTC().Add(time.Duration(expiresIn) * time.Second)
	if expiresIn <= 0 {
		expiresAt = time.Now().UTC().Add(time.Hour)
	}
	s.State.ControlPlane = &asiri.ControlPlaneLink{
		Origin:               origin,
		WorkspaceID:          workspaceID,
		WorkspaceSlug:        workspaceSlug,
		UserID:               approvedByUserID,
		ServiceAccountID:     serviceAccountID,
		ServiceAccountSlug:   serviceAccountSlug,
		ServiceAccountName:   serviceAccountName,
		ApprovedByUserID:     approvedByUserID,
		DeviceID:             deviceID,
		LocalDeviceID:        localDeviceID,
		Source:               "service-account",
		AccessTokenAccount:   accessAccount,
		RefreshTokenAccount:  refreshAccount,
		AccessTokenExpiresAt: expiresAt,
		RefreshExpiresAt:     refreshExpiry,
		LinkedAt:             time.Now().UTC(),
	}
	s.State.LocalDeviceID = localDeviceID
	s.Audit(serviceAccountSlug, "control_plane_linked", "allowed", "", "", "service account session approved", map[string]string{"origin": origin, "workspace": workspaceSlug, "remoteDevice": deviceID, "approvedByUserId": approvedByUserID})
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

func (s *FileStore) RemoteSecretVersionsForPrefix(workspaceID, workspaceSlug, remoteDeviceID, prefix string) ([]RemoteSecretVersion, error) {
	recovery := s.RecoveryForWorkspace(workspaceID)
	return s.RemoteSecretVersionsForPrefixWithRecovery(workspaceID, workspaceSlug, remoteDeviceID, prefix, recovery)
}

func (s *FileStore) RemoteSecretVersionsForPrefixWithRecovery(workspaceID, workspaceSlug, remoteDeviceID, prefix string, recovery *asiri.RecoveryConfig) ([]RemoteSecretVersion, error) {
	refs := []LocalSecretRef{}
	for _, ref := range s.ActiveSecretRefs() {
		if WorkspacePrefix(ref.Scope) == prefix {
			refs = append(refs, ref)
		}
	}
	return s.RemoteSecretVersionsForRefsWithRecovery(workspaceID, workspaceSlug, remoteDeviceID, refs, recovery)
}

func (s *FileStore) RemoteSecretVersionsForRefsWithRecovery(workspaceID, workspaceSlug, remoteDeviceID string, refs []LocalSecretRef, recovery *asiri.RecoveryConfig) ([]RemoteSecretVersion, error) {
	if err := s.RequireInitialized(); err != nil {
		return nil, err
	}
	if s.State.ControlPlane == nil {
		return nil, errors.New("asiri is not linked to a control plane")
	}
	if workspaceID == "" || workspaceSlug == "" || remoteDeviceID == "" {
		return nil, errors.New("remote workspace and trusted device are required")
	}
	prefix := workspaceSlug
	if binding, ok := s.RemoteBindingForPrefix(prefix); !ok || binding.WorkspaceID != workspaceID {
		return nil, fmt.Errorf("workspace prefix %s is not bound to workspace %s", prefix, workspaceSlug)
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
			wrapped, err := wrapKeyToDevice(dataKey, *device, remoteDeviceID)
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
				OrgID:             workspaceID,
				Scope:             secret.Scope,
				Name:              secret.Name,
				Version:           version.Version,
				Algorithm:         version.Algorithm,
				Nonce:             version.Nonce,
				Ciphertext:        version.Ciphertext,
				AAD:               version.AAD,
				WrappedKeys:       wrappedKeys,
				CreatedByDeviceID: remoteDeviceID,
			})
			break
		}
		if !found {
			return nil, fmt.Errorf("local secret %s version %d not found", key, targetVersion)
		}
	}
	return versions, nil
}

func (s *FileStore) ImportRemoteSecretVersions(workspaceID, workspaceSlug, remoteDeviceID string, versions []RemoteSecretVersion, force bool) (int, error) {
	return s.importRemoteSecretVersions(workspaceID, workspaceSlug, versions, force, func(remote RemoteSecretVersion) ([]byte, bool, error) {
		dataKey, err := s.UnwrapDeviceDataKey(remoteDeviceID, remote.WrappedKeys)
		if err != nil {
			return nil, false, fmt.Errorf("is not wrapped to this device: %w", err)
		}
		return dataKey, true, nil
	})
}

func (s *FileStore) ImportRecoveryRemoteSecretVersions(workspaceID, workspaceSlug string, versions []RemoteSecretVersion, recoveryKey string, force bool) (int, RecoveryKeyIdentity, error) {
	if err := s.RequireInitialized(); err != nil {
		return 0, RecoveryKeyIdentity{}, err
	}
	privateKey, identity, err := parseRecoveryKey(recoveryKey)
	if err != nil {
		return 0, RecoveryKeyIdentity{}, err
	}
	imported, err := s.importRemoteSecretVersions(workspaceID, workspaceSlug, versions, force, func(remote RemoteSecretVersion) ([]byte, bool, error) {
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

func (s *FileStore) importRemoteSecretVersions(workspaceID, workspaceSlug string, versions []RemoteSecretVersion, force bool, dataKeyForRemote func(RemoteSecretVersion) ([]byte, bool, error)) (int, error) {
	if err := s.RequireInitialized(); err != nil {
		return 0, err
	}
	if workspaceID == "" || workspaceSlug == "" {
		return 0, errors.New("remote workspace is required")
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
		if remote.OrgID == "" {
			partial.add(remote, errors.New("remote secret record is missing workspace id"))
			continue
		}
		if remote.OrgID != workspaceID {
			partial.add(remote, fmt.Errorf("belongs to workspace %s, not %s", remote.OrgID, workspaceID))
			continue
		}
		if !remoteAADMatches(remote) {
			partial.add(remote, errors.New("encryption metadata does not match its path"))
			continue
		}
		if WorkspacePrefix(remote.Scope) != workspaceSlug {
			partial.add(remote, fmt.Errorf("belongs to workspace %s, but its path prefix is %s", workspaceSlug, WorkspacePrefix(remote.Scope)))
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
		account, err := newSecretDataKeyAccount(accountWorkspaceID)
		if err != nil {
			return 0, err
		}
		prepared = append(prepared, preparedRemoteSecretVersion{
			remote:  remote,
			dataKey: dataKey,
			account: account,
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
		nextVersion := nextSecretVersion(secret.Versions)
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

func (s *FileStore) RecoveryForWorkspace(workspaceID string) *asiri.RecoveryConfig {
	if workspaceID == "" {
		return nil
	}
	recovery, ok := s.State.Recoveries[workspaceID]
	if !ok {
		return nil
	}
	return &recovery
}

func (s *FileStore) SetupRecovery(workspaceID, workspaceSlug string, force bool) (RecoverySetup, error) {
	if err := s.RequireInitialized(); err != nil {
		return RecoverySetup{}, err
	}
	if workspaceID == "" || workspaceSlug == "" {
		return RecoverySetup{}, errors.New("workspace is required")
	}
	if s.RecoveryForWorkspace(workspaceID) != nil && !force {
		return RecoverySetup{}, fmt.Errorf("recovery is already configured for workspace %s; use --force to replace it", workspaceSlug)
	}
	setup, err := s.GenerateRecoverySetup()
	if err != nil {
		return RecoverySetup{}, err
	}
	s.CommitRecoverySetup(workspaceID, workspaceSlug, setup)
	return setup, nil
}

func (s *FileStore) GenerateRecoverySetup() (RecoverySetup, error) {
	if err := s.RequireInitialized(); err != nil {
		return RecoverySetup{}, err
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

func (s *FileStore) CommitRecoverySetup(workspaceID, workspaceSlug string, setup RecoverySetup) {
	if s.State.Recoveries == nil {
		s.State.Recoveries = map[string]asiri.RecoveryConfig{}
	}
	s.State.Recoveries[workspaceID] = setup.Config
	s.Audit(s.State.UserID, "recovery_configured", "allowed", workspaceSlug, "", "workspace recovery public key stored locally", map[string]string{"recipient": setup.RecipientID, "fingerprint": setup.Fingerprint, "workspace": workspaceSlug})
}

func (s *FileStore) SetRecoveryForWorkspace(workspaceID string, recovery *asiri.RecoveryConfig) error {
	if workspaceID == "" {
		return errors.New("workspace is required")
	}
	if s.State.Recoveries == nil {
		s.State.Recoveries = map[string]asiri.RecoveryConfig{}
	}
	if recovery == nil {
		delete(s.State.Recoveries, workspaceID)
		return s.Save()
	}
	s.State.Recoveries[workspaceID] = *recovery
	return s.Save()
}

func (s *FileStore) RecoveryWrappedKeyForSecretVersion(workspaceID, workspaceSlug, scope, name string, version int) (RemoteWrappedKey, error) {
	if err := s.RequireInitialized(); err != nil {
		return RemoteWrappedKey{}, err
	}
	recovery := s.RecoveryForWorkspace(workspaceID)
	if recovery == nil {
		return RemoteWrappedKey{}, fmt.Errorf("recovery is not configured for workspace %s", workspaceSlug)
	}
	return s.RecoveryWrappedKeyForSecretVersionWithConfig(workspaceSlug, scope, name, version, *recovery)
}

func (s *FileStore) RecoveryWrappedKeyForSecretVersionWithConfig(workspaceSlug, scope, name string, version int, recovery asiri.RecoveryConfig) (RemoteWrappedKey, error) {
	if err := s.RequireInitialized(); err != nil {
		return RemoteWrappedKey{}, err
	}
	if WorkspacePrefix(scope) != workspaceSlug {
		return RemoteWrappedKey{}, fmt.Errorf("secret scope %s is not in workspace %s", scope, workspaceSlug)
	}
	dataKey, err := s.dataKeyForSecretVersion(scope, name, version)
	if err != nil {
		return RemoteWrappedKey{}, err
	}
	return recoveryWrappedDataKey(dataKey, recovery)
}

func (s *FileStore) RecoveryWrappedKeyForRemoteVersion(remoteDeviceID string, wrappedKeys []RemoteWrappedKey, recovery asiri.RecoveryConfig) (RemoteWrappedKey, error) {
	dataKey, err := s.UnwrapDeviceDataKey(remoteDeviceID, wrappedKeys)
	if err != nil {
		return RemoteWrappedKey{}, err
	}
	return recoveryWrappedDataKey(dataKey, recovery)
}

func (s *FileStore) RemoteWrappedKeyForRemoteVersionPublicKey(remoteDeviceID string, wrappedKeys []RemoteWrappedKey, targetRemoteDeviceID, encryptionPublicKey string) (RemoteWrappedKey, error) {
	dataKey, err := s.UnwrapDeviceDataKey(remoteDeviceID, wrappedKeys)
	if err != nil {
		return RemoteWrappedKey{}, err
	}
	return wrapKeyToPublicKey(dataKey, encryptionPublicKey, targetRemoteDeviceID)
}

func recoveryWrappedDataKey(dataKey []byte, recovery asiri.RecoveryConfig) (RemoteWrappedKey, error) {
	return wrapKeyToPublicKeyWithOptions(dataKey, recovery.PublicKey, recovery.RecipientID, "recovery", "recovery-hkdf-aes256gcm", "asiri recovery wrap", "asiri-recovery-wrap:")
}

func (s *FileStore) UnwrapDeviceDataKey(remoteDeviceID string, wrappedKeys []RemoteWrappedKey) ([]byte, error) {
	if err := s.RequireInitialized(); err != nil {
		return nil, err
	}
	if remoteDeviceID == "" {
		return nil, errors.New("remote device is required")
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
		if key.RecipientType == "device" && key.RecipientID == remoteDeviceID && key.WrapAlgorithm == "p256-hkdf-aes256gcm" {
			return unwrapKeyWithPrivate(privateKey, key, remoteDeviceID, "asiri p256 wrap", "asiri-wrap:")
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

func (s *FileStore) MarkRecoveryWrapped(workspaceID, workspaceSlug string, count int) error {
	if workspaceID == "" || workspaceSlug == "" {
		return errors.New("workspace is required")
	}
	recovery := s.RecoveryForWorkspace(workspaceID)
	if recovery == nil {
		return nil
	}
	recovery.WrappedSecretCount = count
	recovery.LastWrappedAt = time.Now().UTC()
	s.State.Recoveries[workspaceID] = *recovery
	metadata := map[string]string{"count": fmt.Sprintf("%d", count), "recipient": recovery.RecipientID, "workspace": workspaceSlug}
	s.Audit(s.State.UserID, "recovery_wrapped", "allowed", workspaceSlug, "", "recovery-wrapped active remote secrets", metadata)
	return s.Save()
}

func (s *FileStore) RecoveryWrappedCount(workspaceID string) int {
	recovery := s.RecoveryForWorkspace(workspaceID)
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

func deterministicLocalWorkspaceID(vaultID, slug string) string {
	digest := sha256.Sum256([]byte(vaultID + ":" + slug))
	return "lws_" + hex.EncodeToString(digest[:8])
}

func (s *FileStore) LocalWorkspace(value string) (asiri.LocalWorkspace, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return asiri.LocalWorkspace{}, false
	}
	for _, workspace := range s.State.Workspaces {
		if workspace.ID == value || workspace.CanonicalSlug == value || workspace.Alias == value {
			return workspace, true
		}
	}
	return asiri.LocalWorkspace{}, false
}

func (s *FileStore) LocalWorkspaceByRemoteID(remoteWorkspaceID string) (asiri.LocalWorkspace, bool) {
	for _, workspace := range s.State.Workspaces {
		if remoteWorkspaceID != "" && workspace.RemoteWorkspaceID == remoteWorkspaceID {
			return workspace, true
		}
	}
	return asiri.LocalWorkspace{}, false
}

func (s *FileStore) LocalWorkspaces() []asiri.LocalWorkspace {
	workspaces := make([]asiri.LocalWorkspace, 0, len(s.State.Workspaces))
	for _, workspace := range s.State.Workspaces {
		workspaces = append(workspaces, workspace)
	}
	sort.Slice(workspaces, func(i, j int) bool {
		return workspaces[i].CanonicalSlug < workspaces[j].CanonicalSlug
	})
	return workspaces
}

func (s *FileStore) CreateLocalWorkspace(slug string) (asiri.LocalWorkspace, error) {
	if err := s.RequireInitialized(); err != nil {
		return asiri.LocalWorkspace{}, err
	}
	slug = strings.TrimSpace(slug)
	if err := ValidateWorkspaceSlug(slug); err != nil {
		return asiri.LocalWorkspace{}, err
	}
	if _, exists := s.LocalWorkspace(slug); exists {
		return asiri.LocalWorkspace{}, fmt.Errorf("workspace %s already exists", slug)
	}
	if s.State.Workspaces == nil {
		s.State.Workspaces = map[string]asiri.LocalWorkspace{}
	}
	now := time.Now().UTC()
	workspace := asiri.LocalWorkspace{ID: NewID("lws"), CanonicalSlug: slug, Kind: "local", CreatedAt: now, UpdatedAt: now}
	s.State.Workspaces[workspace.ID] = workspace
	s.Audit(s.State.UserID, "local_workspace_created", "allowed", slug, "", "local workspace created", map[string]string{"workspace": workspace.ID})
	if err := s.Save(); err != nil {
		delete(s.State.Workspaces, workspace.ID)
		return asiri.LocalWorkspace{}, err
	}
	return workspace, nil
}

func (s *FileStore) SetLocalWorkspaceAlias(value, alias string) (asiri.LocalWorkspace, error) {
	workspace, ok := s.LocalWorkspace(value)
	if !ok {
		return asiri.LocalWorkspace{}, fmt.Errorf("local workspace %s not found", value)
	}
	alias = strings.TrimSpace(alias)
	if err := ValidateWorkspaceSlug(alias); err != nil {
		return asiri.LocalWorkspace{}, err
	}
	if alias == workspace.CanonicalSlug {
		return asiri.LocalWorkspace{}, errors.New("workspace alias must differ from the canonical slug")
	}
	for _, existing := range s.State.Workspaces {
		if existing.ID != workspace.ID && (existing.CanonicalSlug == alias || existing.Alias == alias) {
			return asiri.LocalWorkspace{}, fmt.Errorf("workspace alias %s is already in use", alias)
		}
	}
	workspace.Alias = alias
	workspace.UpdatedAt = time.Now().UTC()
	s.State.Workspaces[workspace.ID] = workspace
	s.Audit(s.State.UserID, "local_workspace_alias_changed", "allowed", workspace.CanonicalSlug, "", "local workspace alias changed", map[string]string{"alias": alias, "workspace": workspace.ID})
	if err := s.Save(); err != nil {
		return asiri.LocalWorkspace{}, err
	}
	return workspace, nil
}

func (s *FileStore) RegisterRemoteWorkspace(canonicalSlug, alias, kind, remoteWorkspaceID string) (asiri.LocalWorkspace, error) {
	if err := ValidateWorkspaceSlug(canonicalSlug); err != nil {
		return asiri.LocalWorkspace{}, err
	}
	if alias != "" {
		if err := ValidateWorkspaceSlug(alias); err != nil {
			return asiri.LocalWorkspace{}, err
		}
	}
	if remoteWorkspaceID == "" {
		return asiri.LocalWorkspace{}, errors.New("remote workspace id is required")
	}
	if workspace, ok := s.LocalWorkspaceByRemoteID(remoteWorkspaceID); ok {
		if workspace.CanonicalSlug != canonicalSlug {
			return asiri.LocalWorkspace{}, fmt.Errorf("remote workspace %s canonical slug changed from %s to %s", remoteWorkspaceID, workspace.CanonicalSlug, canonicalSlug)
		}
		for _, existing := range s.State.Workspaces {
			if existing.ID != workspace.ID && localWorkspaceIdentityCollision(existing, canonicalSlug, alias) {
				return asiri.LocalWorkspace{}, fmt.Errorf("remote workspace identity collides with local workspace %s", existing.CanonicalSlug)
			}
		}
		workspace.Alias = alias
		workspace.Kind = firstNonEmptyString(kind, workspace.Kind, "remote")
		workspace.UpdatedAt = time.Now().UTC()
		s.State.Workspaces[workspace.ID] = workspace
		return workspace, nil
	}
	for _, existing := range s.State.Workspaces {
		if localWorkspaceIdentityCollision(existing, canonicalSlug, alias) {
			return asiri.LocalWorkspace{}, fmt.Errorf("remote workspace identity collides with local workspace %s", existing.CanonicalSlug)
		}
	}
	now := time.Now().UTC()
	workspace := asiri.LocalWorkspace{ID: NewID("lws"), CanonicalSlug: canonicalSlug, Alias: alias, Kind: firstNonEmptyString(kind, "remote"), RemoteWorkspaceID: remoteWorkspaceID, CreatedAt: now, UpdatedAt: now}
	s.State.Workspaces[workspace.ID] = workspace
	if s.State.RemoteBindings == nil {
		s.State.RemoteBindings = map[string]asiri.RemoteWorkspaceBinding{}
	}
	s.State.RemoteBindings[canonicalSlug] = asiri.RemoteWorkspaceBinding{WorkspaceID: remoteWorkspaceID, WorkspaceSlug: canonicalSlug, BoundAt: now}
	return workspace, nil
}

func localWorkspaceIdentityCollision(existing asiri.LocalWorkspace, canonicalSlug, alias string) bool {
	for _, value := range []string{canonicalSlug, alias} {
		if value != "" && (existing.CanonicalSlug == value || existing.Alias == value) {
			return true
		}
	}
	return false
}

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
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
	if workspace, ok := s.LocalWorkspace(prefix); ok {
		workspace.RemoteWorkspaceID = remoteWorkspaceID
		workspace.UpdatedAt = time.Now().UTC()
		s.State.Workspaces[workspace.ID] = workspace
	}
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
	workspace, hasWorkspace := s.LocalWorkspace(oldSlug)
	if hasWorkspace {
		for _, existing := range s.State.Workspaces {
			if existing.ID != workspace.ID && (existing.CanonicalSlug == newSlug || existing.Alias == newSlug || existing.CanonicalSlug == oldSlug || existing.Alias == oldSlug) {
				s.deleteDataKeyAccounts(newAccounts...)
				return fmt.Errorf("cannot rename workspace prefix because workspace identity %s already exists", newSlug)
			}
		}
		workspace.CanonicalSlug = newSlug
		if workspace.Alias == "" {
			workspace.Alias = oldSlug
		}
		workspace.RemoteWorkspaceID = remoteWorkspaceID
		workspace.UpdatedAt = time.Now().UTC()
		s.State.Workspaces[workspace.ID] = workspace
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

func (s *FileStore) RemoteWrappedKeyForSecretVersionPublicKey(workspaceID, scope, name string, version int, remoteDeviceID, encryptionPublicKey string) (RemoteWrappedKey, error) {
	if err := s.RequireInitialized(); err != nil {
		return RemoteWrappedKey{}, err
	}
	if s.State.ControlPlane == nil {
		return RemoteWrappedKey{}, errors.New("asiri is not linked to a control plane")
	}
	if err := s.requirePrefixBoundToWorkspace(scope, workspaceID, "rewrap secrets"); err != nil {
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
	var lock *stateFileLock
	if !s.stateLockHeld {
		var err error
		lock, err = acquireStateFileLock(s.Path)
		if err != nil {
			return err
		}
		if err := s.requireCurrentStateSnapshot(); err != nil {
			_ = lock.Close()
			return err
		}
		s.stateLockHeld = true
		defer func() {
			s.stateLockHeld = false
			_ = lock.Close()
		}()
	}
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
	auditLen := len(s.State.Audit)
	s.Audit(s.State.UserID, "local_key_material_cleared", "allowed", "", "", reason, nil)
	if err := s.Save(); err != nil {
		if len(s.State.Audit) > auditLen {
			s.State.Audit = s.State.Audit[:auditLen]
		}
		bytes, writeErr := s.writeStateFile()
		if writeErr != nil {
			return fmt.Errorf("%w; failed to persist local key quarantine: %v", err, writeErr)
		}
		s.loadedStateDigest = sha256.Sum256(bytes)
		s.loadedStateExists = true
		s.loadedStateKnown = true
		if deleteErr != nil {
			return deleteErr
		}
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
	if s.State.VaultID != "" {
		if err := keystore.Delete(auditLedgerDataKeyAccount(s.State.VaultID)); err != nil {
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

func (s *FileStore) requirePrefixBoundToWorkspace(scope, workspaceID, action string) error {
	if s.State.ControlPlane == nil {
		return errors.New("asiri is not linked to a control plane")
	}
	if workspaceID == "" {
		return errors.New("workspace is required")
	}
	prefix := WorkspacePrefix(scope)
	binding, ok := s.RemoteBindingForPrefix(prefix)
	if !ok {
		return fmt.Errorf("workspace prefix %s is not bound to a control-plane workspace; push or pull it before trying to %s", prefix, action)
	}
	if binding.WorkspaceID != workspaceID {
		return fmt.Errorf("workspace prefix %s is bound to workspace id %s, not requested workspace id %s; refusing to %s", prefix, binding.WorkspaceID, workspaceID, action)
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
	event := asiri.AuditEvent{ID: NewID("aud"), Actor: actor, Action: action, Scope: scope, SecretNameHash: secretNameHash, Result: result, Reason: reason, Metadata: metadata, CreatedAt: time.Now().UTC()}
	event.Digest = AuditEventDigest(event)
	s.State.Audit = append([]asiri.AuditEvent{event}, s.State.Audit...)
}

type RemoteAuditAck struct {
	LocalAuditID  string
	EventDigest   string
	RemoteEventID string
	SyncedAt      time.Time
}

func (s *FileStore) LatestAuditEventID() string {
	if len(s.State.Audit) == 0 {
		return ""
	}
	return s.State.Audit[0].ID
}

func (s *FileStore) AuditEventByID(id string) (asiri.AuditEvent, bool) {
	for _, event := range s.State.Audit {
		if event.ID == id {
			return event, true
		}
	}
	return asiri.AuditEvent{}, false
}

func (s *FileStore) MarkAuditEventFailed(id, reason string) bool {
	for index := range s.State.Audit {
		if s.State.Audit[index].ID != id {
			continue
		}
		s.State.Audit[index].Result = "failed"
		s.State.Audit[index].Reason = reason
		s.State.Audit[index].RemoteEventID = ""
		s.State.Audit[index].RemoteSyncedAt = nil
		s.State.Audit[index].Digest = AuditEventDigest(s.State.Audit[index])
		return true
	}
	return false
}

func (s *FileStore) MarkAuditEventsRemoteAcked(acks []RemoteAuditAck) {
	if len(acks) == 0 {
		return
	}
	byID := map[string]RemoteAuditAck{}
	for _, ack := range acks {
		byID[ack.LocalAuditID] = ack
	}
	for index := range s.State.Audit {
		ack, ok := byID[s.State.Audit[index].ID]
		if !ok {
			continue
		}
		s.ensureAuditDigest(&s.State.Audit[index])
		if ack.EventDigest != "" && ack.EventDigest != s.State.Audit[index].Digest {
			continue
		}
		s.State.Audit[index].RemoteEventID = ack.RemoteEventID
		value := ack.SyncedAt
		if value.IsZero() {
			value = time.Now().UTC()
		}
		s.State.Audit[index].RemoteSyncedAt = &value
	}
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

func (s *FileStore) SetEnvelopeAuditModes(scopes []asiri.ScopeAuditMode) {
	if s.State.EnvelopeAuditModes == nil {
		s.State.EnvelopeAuditModes = map[string]asiri.AuditMode{}
	}
	for _, scope := range scopes {
		path := strings.Trim(scope.Path, "/")
		if path == "" {
			continue
		}
		mode := normalizeAuditMode(scope.ResolvedAuditMode)
		s.State.EnvelopeAuditModes[path] = mode
	}
}

func (s *FileStore) ResolveEnvelopeAuditMode(scope string) asiri.AuditMode {
	if s == nil || len(s.State.EnvelopeAuditModes) == 0 {
		return asiri.AuditModeBuffered
	}
	current := strings.Trim(scope, "/")
	for current != "" {
		if mode, ok := s.State.EnvelopeAuditModes[current]; ok {
			return normalizeAuditMode(mode)
		}
		index := strings.LastIndex(current, "/")
		if index < 0 {
			break
		}
		current = current[:index]
	}
	return asiri.AuditModeBuffered
}

func normalizeAuditMode(mode asiri.AuditMode) asiri.AuditMode {
	if mode == asiri.AuditModeStrict {
		return asiri.AuditModeStrict
	}
	return asiri.AuditModeBuffered
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
	account, err := newSecretDataKeyAccount(workspaceID)
	if err != nil {
		return nil, "", err
	}
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

func newSecretDataKeyAccount(workspaceID string) (string, error) {
	bytes := make([]byte, 9)
	if _, err := io.ReadFull(rand.Reader, bytes); err != nil {
		return "", err
	}
	return keystore.DataKeyAccount(workspaceID, "key_"+hex.EncodeToString(bytes)), nil
}

func nextSecretVersion(versions []asiri.SecretVersion) int {
	next := 1
	for _, version := range versions {
		if version.Version >= next {
			next = version.Version + 1
		}
	}
	return next
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
