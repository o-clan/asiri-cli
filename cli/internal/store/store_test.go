package store

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/o-clan/asiri/cli/internal/asiri"
	"github.com/o-clan/asiri/cli/internal/keystore"
	"github.com/zalando/go-keyring"
)

func TestMain(m *testing.M) {
	keyring.MockInit()
	restore := keystore.UseGoKeyringForTesting()
	code := m.Run()
	restore()
	os.Exit(code)
}

func TestEncryptedLocalSecretStoreDoesNotPersistPlaintext(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	st, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.InitializeLocal(); err != nil {
		t.Fatal(err)
	}
	st.State.Devices = append(st.State.Devices, asiri.Device{ID: "dev_test", Name: "test", Kind: "laptop", Status: asiri.DeviceTrusted})
	if err := st.Save(); err != nil {
		t.Fatal(err)
	}
	secretValue := "qa_plaintext_do_not_store"
	if _, err := st.AddSecret("qa/openai/api_key", secretValue); err != nil {
		t.Fatal(err)
	}
	bytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(bytes), secretValue) {
		t.Fatalf("local state persisted plaintext secret: %s", string(bytes))
	}
	value, secret, err := st.GetSecret("qa/openai/api_key")
	if err != nil {
		t.Fatal(err)
	}
	if value != secretValue {
		t.Fatalf("decrypt mismatch: got %q", value)
	}
	if secret.NameHash == "" || !strings.HasPrefix(secret.NameHash, "sn_") {
		t.Fatalf("expected secret name hash, got %q", secret.NameHash)
	}
}

func TestRemoteTombstoneRetiresDeletedVersionsAndAddUsesNextVersion(t *testing.T) {
	st := testInitializedStore(t)
	device := testDevice(t, "tombstone-device")
	st.State.Devices = append(st.State.Devices, device)
	st.State.LocalDeviceID = device.ID
	bindPrefixForTest(t, st, "ledger", "org_ledger")
	secret, err := st.AddSecret("ledger/prod/API_KEY", "v1-secret")
	if err != nil {
		t.Fatal(err)
	}
	account := secret.Versions[0].DataKeyAccount
	deletionAt := time.Now().UTC()
	changed, err := st.ReconcileRemoteTombstones("org_ledger", "ledger", []asiri.SecretTombstone{{
		WorkspaceID:           "org_ledger",
		Scope:                 "ledger/prod",
		Name:                  "API_KEY",
		DeletedThroughVersion: 1,
		DeletedAt:             deletionAt,
	}})
	if err != nil {
		t.Fatal(err)
	}
	if changed != 1 {
		t.Fatalf("expected one local secret to be retired, got %d", changed)
	}
	retired := st.State.Secrets[SecretKey("ledger/prod", "API_KEY")]
	if retired.ActiveVersion != 0 || retired.Versions[0].Status != "deleted" {
		t.Fatalf("expected v1 to be tombstoned, got %#v", retired)
	}
	if _, err := keystore.Load(account); err != nil {
		t.Fatalf("tombstone must preserve recoverable local key material: %v", err)
	}
	recreated, err := st.AddSecret("ledger/prod/API_KEY", "v2-secret")
	if err != nil {
		t.Fatal(err)
	}
	if recreated.ActiveVersion != 2 {
		t.Fatalf("expected explicit add after tombstone to create v2, got v%d", recreated.ActiveVersion)
	}
	localTombstone, ok := st.SecretTombstone("org_ledger", "ledger/prod", "API_KEY")
	if !ok || localTombstone.DeletedThroughVersion != 1 || localTombstone.ReconciledAt.IsZero() {
		t.Fatalf("expected v1 tombstone to remain as recreation proof, got %#v", localTombstone)
	}
	if _, err := st.ReconcileRemoteTombstones("org_ledger", "ledger", []asiri.SecretTombstone{{
		WorkspaceID:           "org_ledger",
		Scope:                 "ledger/prod",
		Name:                  "API_KEY",
		DeletedThroughVersion: 1,
		DeletedAt:             deletionAt,
	}}); err != nil {
		t.Fatal(err)
	}
	refreshedTombstone, _ := st.SecretTombstone("org_ledger", "ledger/prod", "API_KEY")
	if !refreshedTombstone.ReconciledAt.Equal(localTombstone.ReconciledAt) {
		t.Fatalf("unchanged tombstone refresh reset recreation provenance: before=%s after=%s", localTombstone.ReconciledAt, refreshedTombstone.ReconciledAt)
	}
	if _, err := st.ReconcileRemoteTombstones("org_ledger", "ledger", []asiri.SecretTombstone{{
		WorkspaceID:           "org_ledger",
		Scope:                 "ledger/prod",
		Name:                  "API_KEY",
		DeletedThroughVersion: 1,
		DeletedAt:             deletionAt.Add(time.Second),
	}}); err != nil {
		t.Fatal(err)
	}
	repeatedDeletionTombstone, _ := st.SecretTombstone("org_ledger", "ledger/prod", "API_KEY")
	if !repeatedDeletionTombstone.ReconciledAt.After(refreshedTombstone.ReconciledAt) {
		t.Fatalf("repeated same-version deletion did not reset reconciliation provenance: before=%s after=%s", refreshedTombstone.ReconciledAt, repeatedDeletionTombstone.ReconciledAt)
	}
	refreshedTombstone = repeatedDeletionTombstone
	refreshedTombstone.ReconciledAt = time.Unix(1, 0).UTC()
	st.State.SecretTombstones[SecretTombstoneKey("org_ledger", "ledger/prod", "API_KEY")] = refreshedTombstone
	if _, err := st.ReconcileRemoteTombstones("org_ledger", "ledger", []asiri.SecretTombstone{{
		WorkspaceID:           "org_ledger",
		Scope:                 "ledger/prod",
		Name:                  "API_KEY",
		DeletedThroughVersion: 2,
		DeletedAt:             time.Now().UTC(),
	}}); err != nil {
		t.Fatal(err)
	}
	advancedTombstone, _ := st.SecretTombstone("org_ledger", "ledger/prod", "API_KEY")
	if !advancedTombstone.ReconciledAt.After(refreshedTombstone.ReconciledAt) {
		t.Fatalf("higher deletion floor did not advance reconciliation provenance: before=%s after=%s", refreshedTombstone.ReconciledAt, advancedTombstone.ReconciledAt)
	}
	if _, err := st.ReconcileRemoteTombstones("org_ledger", "ledger", []asiri.SecretTombstone{{
		WorkspaceID:           "org_ledger",
		Scope:                 "ledger/prod",
		Name:                  "API_KEY",
		DeletedThroughVersion: 1,
		DeletedAt:             time.Now().UTC(),
	}}); err != nil {
		t.Fatal(err)
	}
	restoredFloorTombstone, _ := st.SecretTombstone("org_ledger", "ledger/prod", "API_KEY")
	if !restoredFloorTombstone.ReconciledAt.Equal(advancedTombstone.ReconciledAt) {
		t.Fatalf("lower deletion floor reset reconciliation provenance: before=%s after=%s", advancedTombstone.ReconciledAt, restoredFloorTombstone.ReconciledAt)
	}
}

func TestRemoteTombstoneReconciliationPreservesFilteredWorkspaceEntries(t *testing.T) {
	st := testInitializedStore(t)
	firstSeen := time.Unix(10, 0).UTC()
	st.State.SecretTombstones = map[string]asiri.SecretTombstone{
		SecretTombstoneKey("org_ledger", "ledger/prod", "VISIBLE_KEY"): {
			WorkspaceID:           "org_ledger",
			Scope:                 "ledger/prod",
			Name:                  "VISIBLE_KEY",
			DeletedThroughVersion: 1,
			ReconciledAt:          firstSeen,
		},
		SecretTombstoneKey("org_ledger", "ledger/prod", "FILTERED_KEY"): {
			WorkspaceID:           "org_ledger",
			Scope:                 "ledger/prod",
			Name:                  "FILTERED_KEY",
			DeletedThroughVersion: 2,
			ReconciledAt:          firstSeen,
		},
	}

	if _, err := st.ReconcileRemoteTombstones("org_ledger", "ledger", []asiri.SecretTombstone{{
		WorkspaceID:           "org_ledger",
		Scope:                 "ledger/prod",
		Name:                  "VISIBLE_KEY",
		DeletedThroughVersion: 1,
		DeletedAt:             time.Now().UTC(),
	}}); err != nil {
		t.Fatal(err)
	}

	filtered, ok := st.SecretTombstone("org_ledger", "ledger/prod", "FILTERED_KEY")
	if !ok || filtered.DeletedThroughVersion != 2 || !filtered.ReconciledAt.Equal(firstSeen) {
		t.Fatalf("filtered tombstone was discarded or changed: %#v", filtered)
	}
}

func TestSyncImportRejectsPartialBundleBeforeMutation(t *testing.T) {
	st := testInitializedStore(t)
	beforeAudit := len(st.State.Audit)
	imported, err := st.importRemoteSecretVersions("org_ledger", "ledger", []RemoteSecretVersion{{
		OrgID: "org_ledger",
		Scope: "ledger/prod",
	}}, false, true, func(RemoteSecretVersion) ([]byte, bool, error) {
		t.Fatal("malformed record must be rejected before key preparation")
		return nil, false, nil
	})
	var partial *RemoteImportPartialError
	if imported != 0 || !errors.As(err, &partial) || len(partial.Skipped) != 1 {
		t.Fatalf("expected atomic partial rejection, got imported=%d err=%v", imported, err)
	}
	if len(st.State.Audit) != beforeAudit || len(st.State.Secrets) != 0 || len(st.State.RemoteBindings) != 0 {
		t.Fatalf("partial sync mutated local state: %#v", st.State)
	}
}

func TestSyncImportPreservesNewerLocalActiveVersionForPush(t *testing.T) {
	const (
		workspaceID   = "org_sync_newer"
		workspaceSlug = "sync-newer"
		path          = "sync-newer/prod/API_KEY"
	)
	source := testInitializedStore(t)
	sourceDevice := testDevice(t, "sync-source")
	source.State.Devices = append(source.State.Devices, sourceDevice)
	expires := time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339)
	if err := source.LinkControlPlane("http://control.test", workspaceID, workspaceSlug, "usr_owner", "dev_sync_source", "at_source", "rt_source", 3600, expires); err != nil {
		t.Fatal(err)
	}
	bindPrefixForTest(t, source, workspaceSlug, workspaceID)
	if _, err := source.AddSecret(path, "remote-v1"); err != nil {
		t.Fatal(err)
	}
	if _, err := source.AddSecret(path, "remote-v2"); err != nil {
		t.Fatal(err)
	}
	remote, err := source.RemoteSecretVersionsForPrefix(workspaceID, workspaceSlug, "dev_sync_source", workspaceSlug)
	if err != nil || len(remote) != 1 || remote[0].Version != 2 {
		t.Fatalf("unexpected remote fixture: %#v err=%v", remote, err)
	}
	remoteKey, err := source.dataKeyForSecretVersion(remote[0].Scope, remote[0].Name, remote[0].Version)
	if err != nil {
		t.Fatal(err)
	}

	target := testInitializedStore(t)
	targetDevice := testDevice(t, "sync-target")
	target.State.Devices = append(target.State.Devices, targetDevice)
	bindPrefixForTest(t, target, workspaceSlug, workspaceID)
	for _, value := range []string{"local-v1", "local-v2", "local-v3"} {
		if _, err := target.AddSecret(path, value); err != nil {
			t.Fatal(err)
		}
	}
	imported, err := target.importRemoteSecretVersions(workspaceID, workspaceSlug, remote, true, true, func(RemoteSecretVersion) ([]byte, bool, error) {
		return remoteKey, true, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if imported != 0 {
		t.Fatalf("sync should leave the newer local version for push, imported=%d", imported)
	}
	secret := target.State.Secrets[SecretKey("sync-newer/prod", "API_KEY")]
	if secret.ActiveVersion != 3 || secret.Versions[2].Status != "active" {
		t.Fatalf("newer local version was demoted during sync: %#v", secret)
	}
}

func TestSyncImportRejectsDifferentEqualVersionWithoutReplacingLocalValue(t *testing.T) {
	const (
		workspaceID   = "org_sync_equal"
		workspaceSlug = "sync-equal"
		path          = "sync-equal/prod/API_KEY"
	)
	source := testInitializedStore(t)
	sourceDevice := testDevice(t, "sync-equal-source")
	source.State.Devices = append(source.State.Devices, sourceDevice)
	expires := time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339)
	if err := source.LinkControlPlane("http://control.test", workspaceID, workspaceSlug, "usr_owner", "dev_sync_equal_source", "at_source", "rt_source", 3600, expires); err != nil {
		t.Fatal(err)
	}
	bindPrefixForTest(t, source, workspaceSlug, workspaceID)
	if _, err := source.AddSecret(path, "remote-value"); err != nil {
		t.Fatal(err)
	}
	remote, err := source.RemoteSecretVersionsForPrefix(workspaceID, workspaceSlug, "dev_sync_equal_source", workspaceSlug)
	if err != nil || len(remote) != 1 {
		t.Fatalf("unexpected remote fixture: %#v err=%v", remote, err)
	}
	remoteKey, err := source.dataKeyForSecretVersion(remote[0].Scope, remote[0].Name, remote[0].Version)
	if err != nil {
		t.Fatal(err)
	}

	target := testInitializedStore(t)
	targetDevice := testDevice(t, "sync-equal-target")
	target.State.Devices = append(target.State.Devices, targetDevice)
	bindPrefixForTest(t, target, workspaceSlug, workspaceID)
	if _, err := target.AddSecret(path, "local-value"); err != nil {
		t.Fatal(err)
	}
	localBefore := target.State.Secrets[SecretKey("sync-equal/prod", "API_KEY")].Versions[0]
	imported, err := target.importRemoteSecretVersions(workspaceID, workspaceSlug, remote, true, true, func(RemoteSecretVersion) ([]byte, bool, error) {
		return remoteKey, true, nil
	})
	var conflictErr *RemoteImportConflictError
	if imported != 0 || !errors.As(err, &conflictErr) || len(conflictErr.Conflicts) != 1 {
		t.Fatalf("expected one equal-version conflict without import, imported=%d err=%v", imported, err)
	}
	localAfter := target.State.Secrets[SecretKey("sync-equal/prod", "API_KEY")].Versions[0]
	if localAfter.Ciphertext != localBefore.Ciphertext || localAfter.DataKeyAccount != localBefore.DataKeyAccount || localAfter.Status != "active" {
		t.Fatalf("sync replaced the conflicting local version: before=%#v after=%#v", localBefore, localAfter)
	}
	value, _, err := target.GetSecret(path)
	if err != nil || value != "local-value" {
		t.Fatalf("local value was not preserved: value=%q err=%v", value, err)
	}
}

func TestStaleWriterCannotMixSecretCiphertextAndDataKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	initial, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	initial.UseDefaultFileKeyStore()
	t.Cleanup(keystore.ClearConfiguredFileKeyStoreDir)
	if err := initial.InitializeLocal(); err != nil {
		t.Fatal(err)
	}
	initial.State.Devices = append(initial.State.Devices, asiri.Device{ID: "dev_test", Name: "test", Kind: "laptop", Status: asiri.DeviceTrusted})
	if err := initial.Save(); err != nil {
		t.Fatal(err)
	}

	first, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	stale, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	firstSecret, err := first.AddSecret("qa/concurrent/API_KEY", "first-value")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stale.AddSecret("qa/concurrent/API_KEY", "stale-value"); !errors.Is(err, ErrConcurrentStateChange) {
		t.Fatalf("expected stale writer rejection, got %v", err)
	}

	staleAccount := stale.State.Secrets[SecretKey("qa/concurrent", "API_KEY")].Versions[0].DataKeyAccount
	firstAccount := firstSecret.Versions[0].DataKeyAccount
	if staleAccount == firstAccount {
		t.Fatal("concurrent writers reused a secret data-key account")
	}
	if _, err := keystore.Load(staleAccount); err == nil {
		t.Fatal("rejected stale writer left its data key behind")
	}
	reloaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	value, _, err := reloaded.GetSecret("qa/concurrent/API_KEY")
	if err != nil {
		t.Fatal(err)
	}
	if value != "first-value" {
		t.Fatalf("stale writer changed the stored value: got %q", value)
	}
}

func TestLifecycleLockSerializesConcurrentSecretRotations(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	initial, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	initial.UseDefaultFileKeyStore()
	t.Cleanup(keystore.ClearConfiguredFileKeyStoreDir)
	if err := initial.InitializeLocal(); err != nil {
		t.Fatal(err)
	}
	initial.State.Devices = append(initial.State.Devices, asiri.Device{ID: "dev_test", Name: "test", Kind: "laptop", Status: asiri.DeviceTrusted})
	if err := initial.Save(); err != nil {
		t.Fatal(err)
	}

	const writers = 16
	start := make(chan struct{})
	errorsCh := make(chan error, writers)
	var wait sync.WaitGroup
	for index := 0; index < writers; index++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			<-start
			lock, err := acquireStateFileLock(path)
			if err != nil {
				errorsCh <- err
				return
			}
			writer, err := Load(path)
			if err == nil {
				writer.stateLockHeld = true
				_, err = writer.AddSecret("qa/concurrent/API_KEY", fmt.Sprintf("value-%d", index))
				writer.stateLockHeld = false
			}
			if closeErr := lock.Close(); err == nil {
				err = closeErr
			}
			if err != nil {
				errorsCh <- err
			}
		}(index)
	}
	close(start)
	wait.Wait()
	close(errorsCh)
	for err := range errorsCh {
		t.Fatal(err)
	}

	reloaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	secret := reloaded.State.Secrets[SecretKey("qa/concurrent", "API_KEY")]
	if len(secret.Versions) != writers || secret.ActiveVersion != writers {
		t.Fatalf("expected %d contiguous versions, got active=%d versions=%d", writers, secret.ActiveVersion, len(secret.Versions))
	}
	accounts := map[string]struct{}{}
	for _, version := range secret.Versions {
		if _, err := reloaded.decryptSecretVersion(version); err != nil {
			t.Fatalf("version %d is not decryptable: %v", version.Version, err)
		}
		if _, exists := accounts[version.DataKeyAccount]; exists {
			t.Fatalf("version %d reused data-key account %s", version.Version, version.DataKeyAccount)
		}
		accounts[version.DataKeyAccount] = struct{}{}
	}
}

func TestAddSecretUsesMaximumStoredVersion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	st, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.InitializeLocal(); err != nil {
		t.Fatal(err)
	}
	st.State.Devices = append(st.State.Devices, asiri.Device{ID: "dev_test", Name: "test", Kind: "laptop", Status: asiri.DeviceTrusted})
	if err := st.Save(); err != nil {
		t.Fatal(err)
	}
	if _, err := st.AddSecret("prod/app/API_KEY", "one"); err != nil {
		t.Fatal(err)
	}
	secret := st.State.Secrets[SecretKey("prod/app", "API_KEY")]
	secret.Versions[0].Version = 4
	secret.ActiveVersion = 4
	st.State.Secrets[SecretKey("prod/app", "API_KEY")] = secret
	if err := st.Save(); err != nil {
		t.Fatal(err)
	}
	rotated, err := st.AddSecret("prod/app/API_KEY", "two")
	if err != nil {
		t.Fatal(err)
	}
	if rotated.ActiveVersion != 5 {
		t.Fatalf("expected version 5 after gapped history, got %d", rotated.ActiveVersion)
	}
}

func TestStaleQuarantineDoesNotDeleteOrOverwriteNewerState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	current, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := current.InitializeLocal(); err != nil {
		t.Fatal(err)
	}
	current.State.Devices = append(current.State.Devices, asiri.Device{ID: "dev_test", Name: "test", Kind: "laptop", Status: asiri.DeviceTrusted})
	if err := current.Save(); err != nil {
		t.Fatal(err)
	}
	stale, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := current.AddSecret("prod/app/API_KEY", "still-readable"); err != nil {
		t.Fatal(err)
	}
	if err := stale.QuarantineLocalKeys("test stale writer"); !errors.Is(err, ErrConcurrentStateChange) {
		t.Fatalf("expected stale quarantine rejection, got %v", err)
	}
	reloaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	value, _, err := reloaded.GetSecret("prod/app/API_KEY")
	if err != nil {
		t.Fatal(err)
	}
	if value != "still-readable" {
		t.Fatal("stale quarantine changed the newer secret")
	}
}

func TestAuditLedgerEncryptsLocalEventsAndDetectsTampering(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	st, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	st.UseDefaultFileKeyStore()
	t.Cleanup(keystore.ClearConfiguredFileKeyStoreDir)
	if err := st.InitializeLocal(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("offline local vault initialized")) {
		t.Fatalf("audit reason should not be stored as plaintext: %s", string(raw))
	}
	var state asiri.State
	if err := json.Unmarshal(raw, &state); err != nil {
		t.Fatal(err)
	}
	if len(state.AuditLedger) == 0 || state.AuditLedgerHead == nil {
		t.Fatal("expected encrypted audit ledger and signed head")
	}
	if state.AuditLedgerHead.SignatureAlg != "hmac-sha256" || state.AuditLedgerHead.SignerDeviceID != "" {
		t.Fatalf("audit ledger head should be anchored to the audit key, got %#v", state.AuditLedgerHead)
	}
	for _, record := range state.AuditLedger {
		if record.SignatureAlg != "hmac-sha256" || record.SignerDeviceID != "" {
			t.Fatalf("audit ledger record should be anchored to the audit key, got %#v", record)
		}
	}
	var missingHead map[string]any
	if err := json.Unmarshal(raw, &missingHead); err != nil {
		t.Fatal(err)
	}
	delete(missingHead, "auditLedgerHead")
	missingHeadBytes, err := json.MarshalIndent(missingHead, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, missingHeadBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("expected missing audit ledger head to fail load")
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	var plaintextFallback map[string]any
	if err := json.Unmarshal(raw, &plaintextFallback); err != nil {
		t.Fatal(err)
	}
	delete(plaintextFallback, "auditLedger")
	delete(plaintextFallback, "auditLedgerHead")
	plaintextFallback["audit"] = []map[string]any{{
		"id":        "aud_fake",
		"actor":     "attacker",
		"action":    "secret_read",
		"result":    "allowed",
		"reason":    "fake plaintext audit downgrade",
		"createdAt": time.Now().UTC().Format(time.RFC3339),
	}}
	plaintextFallbackBytes, err := json.MarshalIndent(plaintextFallback, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, plaintextFallbackBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("expected plaintext audit downgrade to fail load")
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	missingLedger := state
	missingLedger.AuditLedger = nil
	missingLedger.AuditLedgerHead = nil
	missingLedgerBytes, err := json.MarshalIndent(missingLedger, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, missingLedgerBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("expected missing audit ledger to fail load")
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	state.AuditLedger[0].Ciphertext = "tampered"
	tampered, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, tampered, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("expected tampered audit ledger to fail load")
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := keystore.Delete(auditLedgerDataKeyAccount(state.VaultID)); err != nil {
		t.Fatal(err)
	}
	keyless, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := keyless.Save(); !errors.Is(err, ErrAuditLedgerKeyUnavailable) {
		t.Fatalf("expected save without audit ledger key to fail, got %v", err)
	}
}

func TestAuditLedgerKeyRolledBackWhenLegacyStateSaveFails(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	now := time.Now().UTC()
	legacy := map[string]any{
		"version":   1,
		"vaultId":   "vault_legacy",
		"userId":    "usr_legacy",
		"keyStore":  KeyStoreFile,
		"keyRefs":   []any{},
		"devices":   []any{},
		"secrets":   map[string]any{},
		"policies":  []any{},
		"createdAt": now.Format(time.RFC3339),
		"updatedAt": now.Format(time.RFC3339),
		"audit": []map[string]any{{
			"id":        "aud_legacy",
			"actor":     "usr_legacy",
			"action":    "secret_read",
			"result":    "allowed",
			"reason":    "legacy plaintext audit",
			"createdAt": now.Format(time.RFC3339),
		}},
	}
	raw, err := json.MarshalIndent(legacy, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	st, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(keystore.ClearConfiguredFileKeyStoreDir)
	account := auditLedgerDataKeyAccount(st.State.VaultID)
	if _, err := keystore.Load(account); err == nil {
		t.Fatal("legacy load should not create an audit ledger key")
	}
	badPath := filepath.Join(t.TempDir(), "state-dir")
	if err := os.Mkdir(badPath, 0o700); err != nil {
		t.Fatal(err)
	}
	st.Path = badPath
	if err := st.Save(); err == nil {
		t.Fatal("expected save failure")
	}
	if _, err := keystore.Load(account); err == nil {
		t.Fatal("new audit ledger key remained after failed save")
	}
	reloaded, err := Load(path)
	if err != nil {
		t.Fatalf("legacy state should remain loadable after failed save: %v", err)
	}
	if len(reloaded.State.Audit) != 1 || reloaded.State.Audit[0].ID != "aud_legacy" {
		t.Fatalf("legacy audit was not recovered after failed save: %#v", reloaded.State.Audit)
	}
}

func TestInitializeLocalStateDoesNotPersistWorkspaceSlug(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	st, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.InitializeLocal(); err != nil {
		t.Fatal(err)
	}
	bytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(bytes), "workspaceSlug") || strings.Contains(string(bytes), "remoteWorkspaceId") {
		t.Fatalf("local state persisted removed workspace fields: %s", string(bytes))
	}
	if st.State.VaultID == "" {
		t.Fatal("expected local vault id")
	}
}

func TestPreviousWorkspaceFieldsMigrateToVaultIDAndPrefixBinding(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	previous := `{
  "version": 1,
  "workspaceId": "ws_previous",
  "workspaceSlug": "oclan-co",
  "remoteWorkspaceId": "org_oclan",
  "remoteWorkspaceSlug": "oclan-co",
  "userId": "local-human",
  "keyStore": "platform",
  "keyRefs": [],
  "devices": [],
  "secrets": {},
  "policies": [],
  "audit": []
}`
	if err := os.WriteFile(path, []byte(previous), 0o600); err != nil {
		t.Fatal(err)
	}
	st, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.State.VaultID != "ws_previous" {
		t.Fatalf("previous workspace id was not preserved as vault id: %#v", st.State)
	}
	binding, ok := st.RemoteBindingForPrefix("oclan-co")
	if !ok || binding.WorkspaceID != "org_oclan" {
		t.Fatalf("previous remote binding was not migrated: %#v", st.State.RemoteBindings)
	}
}

func TestPreviousBoundWorkspaceIDMigratesToFreshVaultID(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	previous := `{
  "version": 1,
  "workspaceId": "org_oclan",
  "workspaceSlug": "oclan-co",
  "remoteWorkspaceId": "org_oclan",
  "remoteWorkspaceSlug": "oclan-co",
  "userId": "local-human",
  "keyStore": "platform",
  "keyRefs": [],
  "devices": [],
  "secrets": {},
  "policies": [],
  "audit": []
}`
	if err := os.WriteFile(path, []byte(previous), 0o600); err != nil {
		t.Fatal(err)
	}
	st, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.State.VaultID == "" || st.State.VaultID == "org_oclan" {
		t.Fatalf("expected fresh local vault id, got %#v", st.State)
	}
	binding, ok := st.RemoteBindingForPrefix("oclan-co")
	if !ok || binding.WorkspaceID != "org_oclan" {
		t.Fatalf("previous remote binding was not migrated: %#v", st.State.RemoteBindings)
	}
}

func TestLegacyOidcControlPlaneSessionIsRemovedOnLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	accessAccount := "legacy-oidc-access"
	refreshAccount := "legacy-oidc-refresh"
	if err := keystore.Store(accessAccount, "at_legacy"); err != nil {
		t.Fatal(err)
	}
	if err := keystore.Store(refreshAccount, "rt_legacy"); err != nil {
		t.Fatal(err)
	}
	previous := `{
  "version": 1,
  "vaultId": "vault_local",
  "userId": "usr_local",
  "keyStore": "platform",
  "keyRefs": [
    {"purpose": "control-plane-access-token", "account": "legacy-oidc-access"},
    {"purpose": "control-plane-refresh-token", "account": "legacy-oidc-refresh"}
  ],
  "controlPlane": {
    "origin": "https://asiri.dev",
    "workspaceId": "org_prod",
    "workspaceSlug": "prod",
    "userId": "usr_local",
    "source": "oidc",
    "accessTokenAccount": "legacy-oidc-access",
    "refreshTokenAccount": "legacy-oidc-refresh"
  },
  "devices": [],
  "secrets": {},
  "policies": [],
  "audit": []
}`
	if err := os.WriteFile(path, []byte(previous), 0o600); err != nil {
		t.Fatal(err)
	}
	st, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.State.ControlPlane != nil {
		t.Fatalf("legacy OIDC session was not removed: %#v", st.State.ControlPlane)
	}
	if _, err := keystore.Load(accessAccount); err == nil {
		t.Fatal("legacy OIDC access token was not deleted")
	}
	if _, err := keystore.Load(refreshAccount); err == nil {
		t.Fatal("legacy OIDC refresh token was not deleted")
	}
	if len(st.State.KeyRefs) != 0 {
		t.Fatalf("legacy OIDC key refs were not removed: %#v", st.State.KeyRefs)
	}
}

func TestRuntimeAccessUsesAuthenticatedIdentityInsteadOfLabels(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	st, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.InitializeLocal(); err != nil {
		t.Fatal(err)
	}
	st.State.Devices = append(st.State.Devices, asiri.Device{ID: "dev_test", Name: "test", Kind: "laptop", Status: asiri.DeviceTrusted})
	if _, err := st.AddSecret("qa/openai/api_key", "secret"); err != nil {
		t.Fatal(err)
	}
	allowed, reason := st.CheckPolicy(st.State.UserID, "qa/openai/api_key", "read")
	if !allowed || !strings.Contains(reason, "authenticated user") {
		t.Fatalf("expected authenticated user read, got allowed=%v reason=%q", allowed, reason)
	}
	allowed, reason = st.CheckPolicy("codex", "qa/openai/api_key", "inject")
	if allowed || !strings.Contains(reason, "not authenticated") {
		t.Fatalf("audit label must not authorize runtime access, got allowed=%v reason=%q", allowed, reason)
	}
}

func TestAuthenticatedControlPlaneUserCanUseLocalRuntime(t *testing.T) {
	st := testInitializedStore(t)
	device := testDevice(t, "test")
	st.State.Devices = append(st.State.Devices, device)
	st.State.LocalDeviceID = device.ID
	if err := st.Save(); err != nil {
		t.Fatal(err)
	}
	if _, err := st.AddSecret("oclan-co/local/asiri/API_KEY", "secret"); err != nil {
		t.Fatal(err)
	}
	allowed, reason := st.CheckPolicy(st.State.UserID, "oclan-co/local/asiri/API_KEY", "read")
	if !allowed || !strings.Contains(reason, "authenticated user") {
		t.Fatalf("expected local authenticated user access, got allowed=%v reason=%q", allowed, reason)
	}
	expires := time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339)
	if err := st.LinkControlPlaneForDevice("http://control.test", "org_oclan", "oclan-co", "usr_owner", "dev_remote", device.ID, "at", "rt", 3600, expires); err != nil {
		t.Fatal(err)
	}
	allowed, reason = st.CheckPolicy("usr_owner", "oclan-co/local/asiri/API_KEY", "inject")
	if !allowed || !strings.Contains(reason, "authenticated user") {
		t.Fatalf("expected linked authenticated user access, got allowed=%v reason=%q", allowed, reason)
	}
	allowed, reason = st.CheckPolicy("usr_owner ", "oclan-co/local/asiri/API_KEY", "inject")
	if !allowed || !strings.Contains(reason, "authenticated user") {
		t.Fatalf("expected normalized linked user access, got allowed=%v reason=%q", allowed, reason)
	}
}

func TestServiceAccountLinkUsesIsolatedRuntimeSubject(t *testing.T) {
	st := testInitializedStore(t)
	device := testDevice(t, "service-host")
	st.State.Devices = append(st.State.Devices, device)
	st.State.LocalDeviceID = device.ID
	runtimeSubject := ServiceAccountRuntimeSubject("svc_prod")
	st.State.Policies = []asiri.Policy{
		{ID: "pol_slug", Subject: "prod-api", ScopePattern: "prod/api", SecretPattern: "DATABASE_URL", Actions: []string{"read"}, ApprovalMode: "none"},
		{ID: "pol_runtime", Subject: runtimeSubject, ScopePattern: "prod/api", SecretPattern: "DATABASE_URL", Actions: []string{"read"}, ApprovalMode: "none"},
	}
	expires := time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339)
	if err := st.LinkServiceAccountControlPlane("http://control.test", "org_prod", "prod", "usr_owner", "svc_prod", "prod-api", "Production API", "dev_remote", device.ID, "at", "rt", 3600, expires); err != nil {
		t.Fatal(err)
	}
	if runtimeSubject == "prod-api" || runtimeSubject == "" {
		t.Fatalf("service account runtime subject must be ID-derived, got %q", runtimeSubject)
	}
	if len(st.State.Policies) != 1 || st.State.Policies[0].ID != "pol_slug" {
		t.Fatalf("link should clear only previously synced runtime policies: %#v", st.State.Policies)
	}
	if allowed, _ := st.CheckPolicy(runtimeSubject, "prod/api/DATABASE_URL", "read"); allowed {
		t.Fatal("same-slug local policy must not authorize the service account runtime identity")
	}
}

func TestRevokingCurrentLocalDeviceClearsKeyMaterialAndBlocksDecryption(t *testing.T) {
	st := testInitializedStore(t)
	current := testDevice(t, "current")
	other := testDevice(t, "other")
	st.State.Devices = append(st.State.Devices, current, other)
	st.State.LocalDeviceID = current.ID
	st.AddKeyRef("device-encryption-private-key", keystore.DeviceKeyAccount(current.ID, "encryption-private"))
	st.AddKeyRef("device-signing-private-key", keystore.DeviceKeyAccount(current.ID, "signing-private"))
	st.AddKeyRef("device-encryption-private-key", keystore.DeviceKeyAccount(other.ID, "encryption-private"))
	st.AddKeyRef("device-signing-private-key", keystore.DeviceKeyAccount(other.ID, "signing-private"))
	if err := st.Save(); err != nil {
		t.Fatal(err)
	}
	if _, err := st.AddSecret("oclan-co/local/asiri/API_KEY", "secret"); err != nil {
		t.Fatal(err)
	}
	account := st.State.Secrets[SecretKey("oclan-co/local/asiri", "API_KEY")].Versions[0].DataKeyAccount
	if _, err := keystore.Load(account); err != nil {
		t.Fatal(err)
	}
	if err := st.RevokeDevice(current.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := keystore.Load(account); err == nil {
		t.Fatal("revoking the current local device should delete local data keys")
	}
	if _, _, err := st.GetSecret("oclan-co/local/asiri/API_KEY"); err == nil || !strings.Contains(err.Error(), "trusted local device") {
		t.Fatalf("expected revoked current device to block decryption, got %v", err)
	}
	if len(st.State.KeyRefs) != 0 {
		t.Fatalf("expected local key refs to be cleared, got %#v", st.State.KeyRefs)
	}
	if st.State.Devices[1].Status != asiri.DeviceTrusted {
		t.Fatalf("non-current device status should be preserved, got %#v", st.State.Devices[1])
	}
}

func TestRevokeLastTrustedLocalDeviceWithActiveSecretsFails(t *testing.T) {
	st := testInitializedStore(t)
	st.State.Devices = append(st.State.Devices, testDevice(t, "current"))
	if err := st.Save(); err != nil {
		t.Fatal(err)
	}
	current, err := st.ActiveDevice()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.AddSecret("oclan-co/local/asiri/API_KEY", "secret"); err != nil {
		t.Fatal(err)
	}
	err = st.RevokeDevice(current.ID)
	if err == nil || !strings.Contains(err.Error(), "cannot revoke the last trusted local device") {
		t.Fatalf("expected last trusted device revoke to be blocked, got %v", err)
	}
	if got, err := st.ActiveDevice(); err != nil || got.ID != current.ID {
		t.Fatalf("expected current device to remain trusted, got device=%#v err=%v", got, err)
	}
}

func TestUnboundMultiDeviceStateFailsClosedAfterLocalRevoke(t *testing.T) {
	st := testInitializedStore(t)
	current := testDevice(t, "current")
	st.State.Devices = append(st.State.Devices, current)
	if err := st.Save(); err != nil {
		t.Fatal(err)
	}
	if _, err := st.AddSecret("oclan-co/local/asiri/API_KEY", "secret"); err != nil {
		t.Fatal(err)
	}
	account := st.State.Secrets[SecretKey("oclan-co/local/asiri", "API_KEY")].Versions[0].DataKeyAccount
	if _, err := keystore.Load(account); err != nil {
		t.Fatal(err)
	}
	other := testDevice(t, "other")
	st.State.Devices = append(st.State.Devices, other)
	st.AddKeyRef("device-encryption-private-key", keystore.DeviceKeyAccount(other.ID, "encryption-private"))
	st.AddKeyRef("device-signing-private-key", keystore.DeviceKeyAccount(other.ID, "signing-private"))
	if err := st.Save(); err != nil {
		t.Fatal(err)
	}
	if err := st.RevokeDevice(current.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := keystore.Load(account); err == nil {
		t.Fatal("unbound local revoke should clear local data keys")
	}
	if _, _, err := st.GetSecret("oclan-co/local/asiri/API_KEY"); err == nil || !strings.Contains(err.Error(), "local device binding is missing") {
		t.Fatalf("expected unbound multi-device state to fail closed, got %v", err)
	}
}

func TestQuarantineLocalKeysFailsClosedWhenPlatformDeletionFails(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	st, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.InitializeLocal(); err != nil {
		t.Fatal(err)
	}
	device := testDevice(t, "test")
	st.State.Devices = append(st.State.Devices, device)
	st.State.LocalDeviceID = device.ID
	st.State.KeyRefs = append(st.State.KeyRefs, asiri.KeyRef{Purpose: "missing", Account: "missing-account"})
	if err := st.Save(); err != nil {
		t.Fatal(err)
	}
	restoreFailure := keystore.FailPlatformOperationsForTesting(nil, nil, errors.New("delete failed"))
	t.Cleanup(restoreFailure)
	if err := st.QuarantineLocalKeys("remote device is no longer trusted"); err == nil {
		t.Fatal("expected failed platform deletion")
	}
	restoreFailure()
	reloaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(reloaded.State.KeyRefs) != 0 {
		t.Fatalf("failed quarantine should remove key refs from local state: %#v", reloaded.State.KeyRefs)
	}
	if reloaded.State.ControlPlane != nil {
		t.Fatal("failed quarantine should clear control-plane link")
	}
	if reloaded.State.Devices[0].Status != asiri.DeviceRevoked {
		t.Fatalf("failed quarantine should revoke trusted devices locally: %#v", reloaded.State.Devices[0])
	}
}

func TestAuditLedgerPropagatesTemporaryKeychainReadFailures(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	st, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.InitializeLocal(); err != nil {
		t.Fatal(err)
	}
	st.Audit(st.State.UserID, "test_event", "allowed", "", "", "test", nil)
	if err := st.Save(); err != nil {
		t.Fatal(err)
	}

	for _, injected := range []error{keystore.ErrPlatformAuthentication, keystore.ErrPlatformTimeout} {
		restoreFailure := keystore.FailPlatformOperationsForTesting(nil, injected, nil)
		_, loadErr := Load(path)
		restoreFailure()
		if !errors.Is(loadErr, injected) {
			t.Fatalf("expected %v to propagate, got %v", injected, loadErr)
		}
		reloaded, loadErr := Load(path)
		if loadErr != nil {
			t.Fatalf("original audit ledger did not load after recovery: %v", loadErr)
		}
		if len(reloaded.State.Audit) == 0 {
			t.Fatal("original audit ledger was lost after temporary Keychain failure")
		}
	}
}

func TestParseSecretPathUsesLastSlashForMultiLevelScopes(t *testing.T) {
	cases := []struct {
		fullPath string
		scope    string
		name     string
	}{
		{fullPath: "cloudflare/prod-token", scope: "cloudflare", name: "prod-token"},
		{fullPath: "qa/cloudflare/prod-token", scope: "qa/cloudflare", name: "prod-token"},
		{fullPath: "org/team/cloudflare/prod-token", scope: "org/team/cloudflare", name: "prod-token"},
	}
	for _, tc := range cases {
		scope, name, err := ParseSecretPath(tc.fullPath)
		if err != nil {
			t.Fatalf("ParseSecretPath(%q) returned error: %v", tc.fullPath, err)
		}
		if scope != tc.scope || name != tc.name {
			t.Fatalf("ParseSecretPath(%q) = scope %q name %q, want scope %q name %q", tc.fullPath, scope, name, tc.scope, tc.name)
		}
	}
}

func TestWorkspacePrefixBindingRejectsDifferentWorkspaceID(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	st, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.InitializeLocal(); err != nil {
		t.Fatal(err)
	}
	device := testDevice(t, "test")
	st.State.Devices = append(st.State.Devices, device)
	st.AddKeyRef("device-signing-private-key", keystore.DeviceKeyAccount(device.ID, "signing-private"))
	if err := st.BindWorkspacePrefix("oclan-co", "org_a", "oclan-co"); err != nil {
		t.Fatal(err)
	}
	binding, ok := st.RemoteBindingForPrefix("oclan-co")
	if !ok || binding.WorkspaceID != "org_a" {
		t.Fatalf("expected prefix to bind org_a, got %#v", st.State.RemoteBindings)
	}
	err = st.BindWorkspacePrefix("oclan-co", "org_b", "oclan-co")
	if err == nil || !strings.Contains(err.Error(), "already bound") {
		t.Fatalf("expected prefix collision rejection, got %v", err)
	}
}

func TestDeviceSigningPrivateKeyUsesBoundLocalDevice(t *testing.T) {
	st := testInitializedStore(t)
	first := testDevice(t, "first")
	second := testDevice(t, "second")
	st.State.Devices = append(st.State.Devices, first, second)
	st.AddKeyRef("device-signing-private-key", keystore.DeviceKeyAccount(first.ID, "signing-private"))
	st.AddKeyRef("device-signing-private-key", keystore.DeviceKeyAccount(second.ID, "signing-private"))
	expires := time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339)
	if err := st.LinkControlPlaneForDevice("http://control.test", "org_oclan", "oclan-co", "usr_owner", "dev_remote_second", second.ID, "at", "rt", 3600, expires); err != nil {
		t.Fatal(err)
	}
	privateKey, err := st.DeviceSigningPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	publicBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if got := base64.StdEncoding.EncodeToString(publicBytes); got != second.SigningPublicKey {
		t.Fatalf("selected signing key for wrong local device: got %q want %q", got, second.SigningPublicKey)
	}
	if err := st.RevokeDevice(second.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.DeviceSigningPrivateKey(); err == nil || !strings.Contains(err.Error(), "trusted local device") {
		t.Fatalf("expected revoked local device to block signing, got %v", err)
	}
}

func TestBindWorkspacePrefixReencryptsLocalSecretsToRemoteWorkspaceID(t *testing.T) {
	st := testInitializedStore(t)
	device := testDevice(t, "source")
	st.State.Devices = append(st.State.Devices, device)
	if err := st.Save(); err != nil {
		t.Fatal(err)
	}
	if _, err := st.AddSecret("oclan-co/local/asiri/API_KEY", "secret"); err != nil {
		t.Fatal(err)
	}
	oldVaultID := st.State.VaultID
	oldVersion := st.State.Secrets[SecretKey("oclan-co/local/asiri", "API_KEY")].Versions[0]
	expires := time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339)
	if err := st.LinkControlPlaneForDevice("http://control.test", "org_oclan", "oclan-co", "usr_owner", "dev_remote", device.ID, "at", "rt", 3600, expires); err != nil {
		t.Fatal(err)
	}
	if err := st.BindWorkspacePrefix("oclan-co", "org_oclan", "oclan-co"); err != nil {
		t.Fatal(err)
	}
	if st.State.VaultID != oldVaultID {
		t.Fatalf("vault id should stay local: %#v", st.State)
	}
	binding, ok := st.RemoteBindingForPrefix("oclan-co")
	if !ok || binding.WorkspaceID != "org_oclan" {
		t.Fatalf("prefix binding not updated: %#v", st.State.RemoteBindings)
	}
	version := st.State.Secrets[SecretKey("oclan-co/local/asiri", "API_KEY")].Versions[0]
	if version.AAD == oldVersion.AAD || !strings.HasPrefix(version.AAD, "org_oclan:") {
		t.Fatalf("secret AAD was not rebound to remote workspace id: old=%q new=%q", oldVersion.AAD, version.AAD)
	}
	if version.DataKeyAccount == oldVersion.DataKeyAccount || strings.Contains(version.DataKeyAccount, oldVaultID) {
		t.Fatalf("data key account was not rebound: old=%q new=%q", oldVersion.DataKeyAccount, version.DataKeyAccount)
	}
	versions, err := st.RemoteSecretVersionsForPrefix("org_oclan", "oclan-co", "dev_remote", "oclan-co")
	if err != nil {
		t.Fatal(err)
	}
	if len(versions) != 1 || !remoteAADMatches(versions[0]) {
		t.Fatalf("remote version metadata should match after rebind: %#v", versions)
	}
	if _, err := st.AddSecret("oclan-co/local/asiri/NEW_KEY", "new-secret"); err != nil {
		t.Fatal(err)
	}
	newVersion := st.State.Secrets[SecretKey("oclan-co/local/asiri", "NEW_KEY")].Versions[0]
	if !strings.HasPrefix(newVersion.AAD, "org_oclan:") || !strings.HasPrefix(newVersion.DataKeyAccount, "workspace:org_oclan:") {
		t.Fatalf("new bound-prefix secret should use remote workspace id: %#v", newVersion)
	}
	rotated, err := st.RotateDataKeysForPrefix("oclan-co")
	if err != nil {
		t.Fatal(err)
	}
	if rotated != 2 {
		t.Fatalf("expected two bound-prefix rotations, got %d", rotated)
	}
	rotatedVersion := st.State.Secrets[SecretKey("oclan-co/local/asiri", "API_KEY")].Versions[1]
	if !strings.HasPrefix(rotatedVersion.AAD, "org_oclan:") || !strings.HasPrefix(rotatedVersion.DataKeyAccount, "workspace:org_oclan:") {
		t.Fatalf("rotated bound-prefix secret should use remote workspace id: %#v", rotatedVersion)
	}
}

func TestRemoteSecretVersionsUseRequestedWorkspaceAndDeviceInsteadOfSessionProvenance(t *testing.T) {
	st := testInitializedStore(t)
	device := testDevice(t, "source")
	st.State.Devices = append(st.State.Devices, device)
	if err := st.Save(); err != nil {
		t.Fatal(err)
	}
	if _, err := st.AddSecret("target-co/local/asiri/API_KEY", "secret"); err != nil {
		t.Fatal(err)
	}
	expires := time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339)
	if err := st.LinkControlPlaneForDevice("http://control.test", "org_login", "login-co", "usr_owner", "dev_login", device.ID, "at", "rt", 3600, expires); err != nil {
		t.Fatal(err)
	}
	if err := st.BindWorkspacePrefix("target-co", "org_target", "target-co"); err != nil {
		t.Fatal(err)
	}

	versions, err := st.RemoteSecretVersionsForPrefix("org_target", "target-co", "dev_target", "target-co")
	if err != nil {
		t.Fatal(err)
	}
	if st.State.ControlPlane.WorkspaceID != "org_login" || st.State.ControlPlane.DeviceID != "dev_login" {
		t.Fatalf("test session provenance changed unexpectedly: %#v", st.State.ControlPlane)
	}
	if len(versions) != 1 {
		t.Fatalf("expected one remote version, got %#v", versions)
	}
	version := versions[0]
	if version.OrgID != "org_target" || version.CreatedByDeviceID != "dev_target" {
		t.Fatalf("remote version used session provenance instead of requested target: %#v", version)
	}
	if len(version.WrappedKeys) != 1 || version.WrappedKeys[0].RecipientID != "dev_target" {
		t.Fatalf("remote version was not wrapped to the requested device: %#v", version.WrappedKeys)
	}
	if _, err := st.UnwrapDeviceDataKey("dev_target", version.WrappedKeys); err != nil {
		t.Fatalf("requested target device could not unwrap its data key: %v", err)
	}
	if _, err := st.UnwrapDeviceDataKey("dev_login", version.WrappedKeys); err == nil {
		t.Fatal("session-provenance device unexpectedly unwrapped the target device key")
	}
}

func TestRenameWorkspacePrefixReencryptsLocalSecrets(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	st, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.InitializeLocal(); err != nil {
		t.Fatal(err)
	}
	st.State.Devices = append(st.State.Devices, asiri.Device{ID: "dev_test", Name: "test", Kind: "laptop", Status: asiri.DeviceTrusted})
	if err := st.Save(); err != nil {
		t.Fatal(err)
	}
	if _, err := st.AddSecret("google-com/recipe-app/API_KEY", "secret"); err != nil {
		t.Fatal(err)
	}
	oldAAD := st.State.Secrets[SecretKey("google-com/recipe-app", "API_KEY")].Versions[0].AAD
	if err := st.RenameWorkspacePrefix("google-com", "oclan-co", "org_oclan"); err != nil {
		t.Fatal(err)
	}
	binding, ok := st.RemoteBindingForPrefix("oclan-co")
	if !ok || binding.WorkspaceID != "org_oclan" {
		t.Fatalf("workspace binding not updated: %#v", st.State)
	}
	value, secret, err := st.GetSecret("oclan-co/recipe-app/API_KEY")
	if err != nil {
		t.Fatal(err)
	}
	if value != "secret" {
		t.Fatalf("renamed secret decrypted to %q", value)
	}
	if secret.Versions[0].AAD == oldAAD || !strings.Contains(secret.Versions[0].AAD, "oclan-co/recipe-app") {
		t.Fatalf("secret version was not reencrypted with renamed path: %q", secret.Versions[0].AAD)
	}
	if _, _, err := st.GetSecret("google-com/recipe-app/API_KEY"); err == nil {
		t.Fatal("old secret path should not resolve after rename")
	}
}

func TestRegisterRemoteWorkspacePreservesLocalWorkspaceAndRejectsIdentityCollisions(t *testing.T) {
	st := testInitializedStore(t)
	local, err := st.CreateLocalWorkspace("xai-dev")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.RegisterRemoteWorkspace("personal-example-com", "personal", "personal", "org_personal"); err != nil {
		t.Fatal(err)
	}
	preserved, ok := st.LocalWorkspace(local.ID)
	if !ok || preserved.CanonicalSlug != "xai-dev" || preserved.RemoteWorkspaceID != "" {
		t.Fatalf("local workspace was replaced by remote registration: %#v", preserved)
	}
	if len(st.State.Workspaces) != 2 {
		t.Fatalf("expected separate local and remote workspaces, got %#v", st.State.Workspaces)
	}
	if _, err := st.RegisterRemoteWorkspace("xai-dev", "remote-xai", "custom", "org_xai"); err == nil || !strings.Contains(err.Error(), "collides") {
		t.Fatalf("expected canonical collision, got %v", err)
	}
	if _, err := st.SetLocalWorkspaceAlias(local.ID, "xai"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.RegisterRemoteWorkspace("xai", "remote-alias", "custom", "org_alias"); err == nil || !strings.Contains(err.Error(), "collides") {
		t.Fatalf("expected local alias collision, got %v", err)
	}
}

func TestAdoptRemoteWorkspaceBindsExactCanonicalSlug(t *testing.T) {
	st := testInitializedStore(t)
	device := testDevice(t, "source")
	st.State.Devices = append(st.State.Devices, device)
	if err := st.Save(); err != nil {
		t.Fatal(err)
	}
	local, err := st.CreateLocalWorkspace("testamy-com")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.AddSecret("testamy-com/common/API_KEY", "secret"); err != nil {
		t.Fatal(err)
	}
	oldAAD := st.State.Secrets[SecretKey("testamy-com/common", "API_KEY")].Versions[0].AAD

	workspace, err := st.AdoptRemoteWorkspace("testamy-com", "testamy", "domain", "org_testamy")
	if err != nil {
		t.Fatal(err)
	}
	if workspace.ID != local.ID || workspace.RemoteWorkspaceID != "org_testamy" || workspace.Alias != "testamy" || workspace.Kind != "domain" {
		t.Fatalf("unexpected adopted workspace: %#v", workspace)
	}
	binding, ok := st.RemoteBindingForPrefix("testamy-com")
	if !ok || binding.WorkspaceID != "org_testamy" {
		t.Fatalf("workspace prefix was not bound to remote identity: %#v", binding)
	}
	version := st.State.Secrets[SecretKey("testamy-com/common", "API_KEY")].Versions[0]
	if version.AAD == oldAAD || !strings.HasPrefix(version.AAD, "org_testamy:") {
		t.Fatalf("local secret was not rebound to remote identity: %#v", version)
	}
	value, _, err := st.GetSecret("testamy-com/common/API_KEY")
	if err != nil || value != "secret" {
		t.Fatalf("adopted local secret did not remain decryptable: value=%q err=%v", value, err)
	}
}

func TestAdoptRemoteWorkspaceRejectsAnotherWorkspaceAliasBeforeBinding(t *testing.T) {
	st := testInitializedStore(t)
	device := testDevice(t, "source")
	st.State.Devices = append(st.State.Devices, device)
	if err := st.Save(); err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateLocalWorkspace("testamy-com"); err != nil {
		t.Fatal(err)
	}
	other, err := st.CreateLocalWorkspace("other-com")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.SetLocalWorkspaceAlias(other.ID, "testamy"); err != nil {
		t.Fatal(err)
	}

	if _, err := st.AdoptRemoteWorkspace("testamy-com", "testamy", "domain", "org_testamy"); err == nil || !strings.Contains(err.Error(), "collides") {
		t.Fatalf("expected alias collision, got %v", err)
	}
	workspace, ok := st.LocalWorkspace("testamy-com")
	if !ok || workspace.RemoteWorkspaceID != "" {
		t.Fatalf("failed adoption changed local workspace identity: %#v", workspace)
	}
	if _, ok := st.RemoteBindingForPrefix("testamy-com"); ok {
		t.Fatal("failed adoption bound the local prefix")
	}
}

func TestAdoptRemoteWorkspaceRejectsAlreadyRegisteredRemoteIDBeforeBinding(t *testing.T) {
	st := testInitializedStore(t)
	device := testDevice(t, "source")
	st.State.Devices = append(st.State.Devices, device)
	if err := st.Save(); err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateLocalWorkspace("testamy-com"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.RegisterRemoteWorkspace("other-com", "", "domain", "org_testamy"); err != nil {
		t.Fatal(err)
	}

	if _, err := st.AdoptRemoteWorkspace("testamy-com", "", "domain", "org_testamy"); err == nil || !strings.Contains(err.Error(), "already registered") {
		t.Fatalf("expected registered remote id collision, got %v", err)
	}
	workspace, ok := st.LocalWorkspace("testamy-com")
	if !ok || workspace.RemoteWorkspaceID != "" {
		t.Fatalf("failed adoption changed local workspace identity: %#v", workspace)
	}
	if _, ok := st.RemoteBindingForPrefix("testamy-com"); ok {
		t.Fatal("failed adoption bound the local prefix")
	}
}

func TestMigratedUnboundWorkspaceUsesNewCanonicalizationKind(t *testing.T) {
	st := testInitializedStore(t)
	st.State.Devices = append(st.State.Devices, asiri.Device{ID: "dev_test", Name: "test", Kind: "laptop", Status: asiri.DeviceTrusted})
	if err := st.Save(); err != nil {
		t.Fatal(err)
	}
	if _, err := st.AddSecret("xai-dev/app/API_KEY", "secret"); err != nil {
		t.Fatal(err)
	}
	st.State.Workspaces = nil
	if err := st.Save(); err != nil {
		t.Fatal(err)
	}
	reloaded, err := Load(st.Path)
	if err != nil {
		t.Fatal(err)
	}
	workspace, ok := reloaded.LocalWorkspace("xai-dev")
	if !ok || workspace.Kind != "local" || workspace.RemoteWorkspaceID != "" {
		t.Fatalf("migrated offline workspace should use first-sync canonicalization: %#v", workspace)
	}
}

func TestRemoveSecretKeepsDataKeyWhenSaveFails(t *testing.T) {
	st := testInitializedStore(t)
	st.State.Devices = append(st.State.Devices, asiri.Device{ID: "dev_test", Name: "test", Kind: "laptop", Status: asiri.DeviceTrusted})
	if err := st.Save(); err != nil {
		t.Fatal(err)
	}
	if _, err := st.AddSecret("oclan-co/local/asiri/API_KEY", "secret"); err != nil {
		t.Fatal(err)
	}
	account := st.State.Secrets[SecretKey("oclan-co/local/asiri", "API_KEY")].Versions[0].DataKeyAccount
	if _, err := keystore.Load(account); err != nil {
		t.Fatal(err)
	}
	badPath := filepath.Join(t.TempDir(), "state-dir")
	if err := os.Mkdir(badPath, 0o700); err != nil {
		t.Fatal(err)
	}
	st.Path = badPath
	if err := st.RemoveSecret("oclan-co/local/asiri/API_KEY"); err == nil {
		t.Fatal("expected save failure")
	}
	if _, err := keystore.Load(account); err != nil {
		t.Fatalf("data key was deleted before state was saved: %v", err)
	}
}

func TestAddSecretDeletesNewDataKeyWhenSaveFails(t *testing.T) {
	st := testInitializedStore(t)
	st.State.Devices = append(st.State.Devices, asiri.Device{ID: "dev_test", Name: "test", Kind: "laptop", Status: asiri.DeviceTrusted})
	if err := st.Save(); err != nil {
		t.Fatal(err)
	}
	badPath := filepath.Join(t.TempDir(), "state-dir")
	if err := os.Mkdir(badPath, 0o700); err != nil {
		t.Fatal(err)
	}
	st.Path = badPath
	if _, err := st.AddSecret("oclan-co/local/asiri/API_KEY", "secret"); err == nil {
		t.Fatal("expected save failure")
	}
	secret := st.State.Secrets[SecretKey("oclan-co/local/asiri", "API_KEY")]
	if len(secret.Versions) != 1 {
		t.Fatalf("expected in-memory failed version for cleanup check, got %#v", secret.Versions)
	}
	account := secret.Versions[0].DataKeyAccount
	if _, err := keystore.Load(account); err == nil {
		t.Fatal("new data key remained after failed save")
	}
}

func TestRenameWorkspacePrefixKeepsOldDataKeyWhenSaveFails(t *testing.T) {
	st := testInitializedStore(t)
	st.State.Devices = append(st.State.Devices, asiri.Device{ID: "dev_test", Name: "test", Kind: "laptop", Status: asiri.DeviceTrusted})
	if err := st.Save(); err != nil {
		t.Fatal(err)
	}
	if _, err := st.AddSecret("google-com/recipe-app/API_KEY", "secret"); err != nil {
		t.Fatal(err)
	}
	account := st.State.Secrets[SecretKey("google-com/recipe-app", "API_KEY")].Versions[0].DataKeyAccount
	if _, err := keystore.Load(account); err != nil {
		t.Fatal(err)
	}
	badPath := filepath.Join(t.TempDir(), "state-dir")
	if err := os.Mkdir(badPath, 0o700); err != nil {
		t.Fatal(err)
	}
	st.Path = badPath
	if err := st.RenameWorkspacePrefix("google-com", "oclan-co", "org_oclan"); err == nil {
		t.Fatal("expected save failure")
	}
	if _, err := keystore.Load(account); err != nil {
		t.Fatalf("old data key was deleted before renamed state was saved: %v", err)
	}
	renamed := st.State.Secrets[SecretKey("oclan-co/recipe-app", "API_KEY")]
	if len(renamed.Versions) != 1 {
		t.Fatalf("expected in-memory renamed version for cleanup check, got %#v", renamed.Versions)
	}
	newAccount := renamed.Versions[0].DataKeyAccount
	if newAccount != account {
		if _, err := keystore.Load(newAccount); err == nil {
			t.Fatal("new rename data key remained after failed save")
		}
	}
}

func TestRenameWorkspacePrefixRejectsCollisionBeforeCreatingDataKeys(t *testing.T) {
	st := testInitializedStore(t)
	st.State.Devices = append(st.State.Devices, asiri.Device{ID: "dev_test", Name: "test", Kind: "laptop", Status: asiri.DeviceTrusted})
	if err := st.Save(); err != nil {
		t.Fatal(err)
	}
	if _, err := st.AddSecret("google-com/recipe-app/API_KEY", "source"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.AddSecret("oclan-co/recipe-app/API_KEY", "target"); err != nil {
		t.Fatal(err)
	}
	target := st.State.Secrets[SecretKey("oclan-co/recipe-app", "API_KEY")]
	targetAccount := target.Versions[0].DataKeyAccount
	targetKey, err := keystore.Load(targetAccount)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.RenameWorkspacePrefix("google-com", "oclan-co", "org_oclan"); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("expected rename collision, got %v", err)
	}
	afterKey, err := keystore.Load(targetAccount)
	if err != nil {
		t.Fatalf("target data key was deleted after rejected rename: %v", err)
	}
	if afterKey != targetKey {
		t.Fatal("target data key changed after rejected rename")
	}
	value, _, err := st.GetSecret("oclan-co/recipe-app/API_KEY")
	if err != nil {
		t.Fatal(err)
	}
	if value != "target" {
		t.Fatalf("target secret decrypted to %q", value)
	}
}

func TestRecoverySetupDoesNotPersistRecoveryKeyAndWrapsRemoteVersions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	st, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.InitializeLocal(); err != nil {
		t.Fatal(err)
	}
	st.State.Devices = append(st.State.Devices, asiri.Device{ID: "dev_test", Name: "test", Kind: "laptop", Status: asiri.DeviceTrusted, EncryptionPublicKey: testPublicKey(t)})
	if err := st.Save(); err != nil {
		t.Fatal(err)
	}
	if _, err := st.AddSecret("oclan-co/local/asiri/API_KEY", "secret"); err != nil {
		t.Fatal(err)
	}
	expires := time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339)
	if err := st.LinkControlPlane("http://control.test", "org_oclan", "oclan-co", "usr_owner", "dev_remote", "at", "rt", 3600, expires); err != nil {
		t.Fatal(err)
	}
	bindPrefixForTest(t, st, "oclan-co", "org_oclan")
	setup, err := st.SetupRecovery("org_oclan", "oclan-co", false)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(setup.Key, "asiri_recovery_") {
		t.Fatalf("unexpected recovery key format: %q", setup.Key)
	}
	if setup.PublicKey == "" {
		t.Fatal("recovery setup should expose public key metadata for remote registration")
	}
	bytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(bytes), setup.Key) {
		t.Fatal("local state persisted raw recovery key")
	}
	recovery := st.RecoveryForWorkspace("org_oclan")
	if recovery == nil || recovery.PublicKey == "" || recovery.RecipientID == "" {
		t.Fatalf("recovery metadata missing: %#v", st.State.Recoveries)
	}
	versions, err := st.RemoteSecretVersionsForPrefix("org_oclan", "oclan-co", "dev_remote", "oclan-co")
	if err != nil {
		t.Fatal(err)
	}
	if len(versions) != 1 {
		t.Fatalf("expected one remote version, got %d", len(versions))
	}
	if len(versions[0].WrappedKeys) != 2 {
		t.Fatalf("expected device and recovery wrapped keys, got %#v", versions[0].WrappedKeys)
	}
	if versions[0].WrappedKeys[1].RecipientType != "recovery" || versions[0].WrappedKeys[1].RecipientID != recovery.RecipientID || versions[0].WrappedKeys[1].WrapAlgorithm != "recovery-hkdf-aes256gcm" {
		t.Fatalf("expected recovery wrapped key, got %#v", versions[0].WrappedKeys[1])
	}
	if st.RecoveryForWorkspace("org_peter") != nil {
		t.Fatalf("unrelated workspace should not inherit recovery metadata: %#v", st.State.Recoveries)
	}
}

func TestRecoveryWrappedCountsAreTrackedPerWorkspace(t *testing.T) {
	st := testInitializedStore(t)
	st.State.Devices = append(st.State.Devices, testDevice(t, "source"))
	if err := st.Save(); err != nil {
		t.Fatal(err)
	}
	st.State.Recoveries = map[string]asiri.RecoveryConfig{
		"org_oclan": {
			RecipientID:          "rec_oclan",
			PublicKey:            "public-oclan",
			PublicKeyFingerprint: "fingerprint-oclan",
			CreatedAt:            time.Now().UTC(),
		},
		"org_peter": {
			RecipientID:          "rec_peter",
			PublicKey:            "public-peter",
			PublicKeyFingerprint: "fingerprint-peter",
			CreatedAt:            time.Now().UTC(),
		},
	}
	if err := st.MarkRecoveryWrapped("org_oclan", "oclan-co", 2); err != nil {
		t.Fatal(err)
	}
	if st.RecoveryWrappedCount("org_oclan") != 2 {
		t.Fatalf("target workspace recovery count was not tracked: %#v", st.State.Recoveries)
	}
	if st.RecoveryWrappedCount("org_peter") != 0 {
		t.Fatalf("unrelated workspace should not share recovery count: %#v", st.State.Recoveries)
	}
	if st.State.Recoveries["org_oclan"].WrappedSecretCount != 2 {
		t.Fatalf("expected workspace-local count, got %#v", st.State.Recoveries)
	}
}

func TestRemoteSecretVersionsUseDistinctDataKeys(t *testing.T) {
	st := testInitializedStore(t)
	st.State.Devices = append(st.State.Devices, testDevice(t, "source"))
	if err := st.Save(); err != nil {
		t.Fatal(err)
	}
	if _, err := st.AddSecret("oclan-co/local/asiri/API_KEY", "first-secret"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.AddSecret("oclan-co/local/asiri/OTHER_KEY", "second-secret"); err != nil {
		t.Fatal(err)
	}
	expires := time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339)
	if err := st.LinkControlPlane("http://control.test", "org_oclan", "oclan-co", "usr_owner", "dev_source", "at_source", "rt_source", 3600, expires); err != nil {
		t.Fatal(err)
	}
	bindPrefixForTest(t, st, "oclan-co", "org_oclan")
	versions, err := st.RemoteSecretVersionsForPrefix("org_oclan", "oclan-co", "dev_source", "oclan-co")
	if err != nil {
		t.Fatal(err)
	}
	if len(versions) != 2 {
		t.Fatalf("expected two remote versions, got %d", len(versions))
	}
	firstKey, err := st.UnwrapDeviceDataKey("dev_source", versions[0].WrappedKeys)
	if err != nil {
		t.Fatal(err)
	}
	secondKey, err := st.UnwrapDeviceDataKey("dev_source", versions[1].WrappedKeys)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(firstKey, secondKey) {
		t.Fatal("distinct remote secrets must not unwrap to the same data key")
	}
	if _, err := decryptWithKey(firstKey, versions[1].Nonce, versions[1].Ciphertext, []byte(versions[1].AAD)); err == nil {
		t.Fatal("first secret data key decrypted the second secret")
	}
}

func TestRewrapCanUseStoredStaleVersionDataKey(t *testing.T) {
	source := testInitializedStore(t)
	sourceDevice := testDevice(t, "source")
	source.State.Devices = append(source.State.Devices, sourceDevice)
	if err := source.Save(); err != nil {
		t.Fatal(err)
	}
	if _, err := source.AddSecret("oclan-co/local/asiri/API_KEY", "first-secret"); err != nil {
		t.Fatal(err)
	}
	expires := time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339)
	if err := source.LinkControlPlane("http://control.test", "org_oclan", "oclan-co", "usr_owner", "dev_source", "at_source", "rt_source", 3600, expires); err != nil {
		t.Fatal(err)
	}
	bindPrefixForTest(t, source, "oclan-co", "org_oclan")
	remoteVersions, err := source.RemoteSecretVersionsForPrefix("org_oclan", "oclan-co", "dev_source", "oclan-co")
	if err != nil {
		t.Fatal(err)
	}
	if len(remoteVersions) != 1 || remoteVersions[0].Version != 1 {
		t.Fatalf("expected remote version 1, got %#v", remoteVersions)
	}
	if _, err := source.AddSecret("oclan-co/local/asiri/API_KEY", "second-secret"); err != nil {
		t.Fatal(err)
	}
	target := testInitializedStore(t)
	targetDevice := testDevice(t, "target")
	target.State.Devices = append(target.State.Devices, targetDevice)
	if err := target.Save(); err != nil {
		t.Fatal(err)
	}
	if err := target.LinkControlPlane("http://control.test", "org_oclan", "oclan-co", "usr_owner", "dev_target", "at_target", "rt_target", 3600, expires); err != nil {
		t.Fatal(err)
	}
	bindPrefixForTest(t, target, "oclan-co", "org_oclan")
	wrapped, err := source.RemoteWrappedKeyForSecretVersionPublicKey("org_oclan", "oclan-co/local/asiri", "API_KEY", 1, "dev_target", targetDevice.EncryptionPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	rewrappedKey, err := target.UnwrapDeviceDataKey("dev_target", []RemoteWrappedKey{wrapped})
	if err != nil {
		t.Fatal(err)
	}
	versionOneKey, err := source.dataKeyForSecretVersion("oclan-co/local/asiri", "API_KEY", 1)
	if err != nil {
		t.Fatal(err)
	}
	versionTwoKey, err := source.dataKeyForSecretVersion("oclan-co/local/asiri", "API_KEY", 2)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(rewrappedKey, versionOneKey) {
		t.Fatal("rewrap did not use the remote version's data key")
	}
	if bytes.Equal(rewrappedKey, versionTwoKey) {
		t.Fatal("rewrap used the current local version key for an older remote version")
	}
}

func TestRemoteWrappedKeyForRemoteVersionPublicKey(t *testing.T) {
	source := testInitializedStore(t)
	sourceDevice := testDevice(t, "source")
	source.State.Devices = append(source.State.Devices, sourceDevice)
	if err := source.Save(); err != nil {
		t.Fatal(err)
	}
	if _, err := source.AddSecret("oclan-co/local/asiri/API_KEY", "secret"); err != nil {
		t.Fatal(err)
	}
	expires := time.Now().UTC().Add(time.Hour).Format(time.RFC3339)
	if err := source.LinkControlPlane("http://control.test", "org_oclan", "oclan-co", "usr_owner", "dev_source", "at_source", "rt_source", 3600, expires); err != nil {
		t.Fatal(err)
	}
	bindPrefixForTest(t, source, "oclan-co", "org_oclan")
	remoteVersions, err := source.RemoteSecretVersionsForPrefix("org_oclan", "oclan-co", "dev_source", "oclan-co")
	if err != nil {
		t.Fatal(err)
	}
	if len(remoteVersions) != 1 {
		t.Fatalf("expected one remote version, got %d", len(remoteVersions))
	}
	target := testInitializedStore(t)
	targetDevice := testDevice(t, "target")
	target.State.Devices = append(target.State.Devices, targetDevice)
	if err := target.Save(); err != nil {
		t.Fatal(err)
	}
	if err := target.LinkControlPlane("http://control.test", "org_oclan", "oclan-co", "usr_owner", "dev_target", "at_target", "rt_target", 3600, expires); err != nil {
		t.Fatal(err)
	}

	rewrapped, err := source.RemoteWrappedKeyForRemoteVersionPublicKey("dev_source", remoteVersions[0].WrappedKeys, "dev_target", targetDevice.EncryptionPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	actualKey, err := target.UnwrapDeviceDataKey("dev_target", []RemoteWrappedKey{rewrapped})
	if err != nil {
		t.Fatal(err)
	}
	expectedKey, err := source.UnwrapDeviceDataKey("dev_source", remoteVersions[0].WrappedKeys)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(actualKey, expectedKey) {
		t.Fatal("remote rewrap changed the data key")
	}
}

func TestRecoveryKeyRestoresRemoteSecretsOnAnotherDevice(t *testing.T) {
	sourcePath := filepath.Join(t.TempDir(), "source.json")
	source, err := Load(sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := source.InitializeLocal(); err != nil {
		t.Fatal(err)
	}
	sourceDevice := testDevice(t, "source")
	source.State.Devices = append(source.State.Devices, sourceDevice)
	if err := source.Save(); err != nil {
		t.Fatal(err)
	}
	if _, err := source.AddSecret("oclan-co/local/asiri/API_KEY", "restored-secret"); err != nil {
		t.Fatal(err)
	}
	expires := time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339)
	if err := source.LinkControlPlane("http://control.test", "org_oclan", "oclan-co", "usr_owner", "dev_source", "at_source", "rt_source", 3600, expires); err != nil {
		t.Fatal(err)
	}
	bindPrefixForTest(t, source, "oclan-co", "org_oclan")
	setup, err := source.SetupRecovery("org_oclan", "oclan-co", false)
	if err != nil {
		t.Fatal(err)
	}
	versions, err := source.RemoteSecretVersionsForPrefix("org_oclan", "oclan-co", "dev_source", "oclan-co")
	if err != nil {
		t.Fatal(err)
	}

	targetPath := filepath.Join(t.TempDir(), "target.json")
	target, err := Load(targetPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := target.InitializeLocal(); err != nil {
		t.Fatal(err)
	}
	targetDevice := testDevice(t, "target")
	target.State.Devices = append(target.State.Devices, targetDevice)
	if err := target.Save(); err != nil {
		t.Fatal(err)
	}
	if err := target.LinkControlPlane("http://control.test", "org_oclan", "oclan-co", "usr_owner", "dev_target", "at_target", "rt_target", 3600, expires); err != nil {
		t.Fatal(err)
	}
	bindPrefixForTest(t, target, "oclan-co", "org_oclan")
	imported, identity, err := target.ImportRecoveryRemoteSecretVersions("org_oclan", "oclan-co", versions, setup.Key, false)
	if err != nil {
		t.Fatal(err)
	}
	sourceRecovery := source.RecoveryForWorkspace("org_oclan")
	if sourceRecovery == nil {
		t.Fatal("source recovery metadata missing")
	}
	if identity.RecipientID != sourceRecovery.RecipientID {
		t.Fatalf("unexpected recovery identity: %#v", identity)
	}
	if imported != 1 {
		t.Fatalf("expected one imported secret, got %d", imported)
	}
	value, _, err := target.GetSecret("oclan-co/local/asiri/API_KEY")
	if err != nil {
		t.Fatal(err)
	}
	if value != "restored-secret" {
		t.Fatalf("restored secret mismatch: %q", value)
	}
	wrapped, err := target.RemoteWrappedKeyForSecretVersionPublicKey("org_oclan", "oclan-co/local/asiri", "API_KEY", versions[0].Version, "dev_target", targetDevice.EncryptionPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if wrapped.RecipientID != "dev_target" || wrapped.WrapAlgorithm != "p256-hkdf-aes256gcm" {
		t.Fatalf("unexpected recovered device wrapped key: %#v", wrapped)
	}
}

func TestImportRemoteSecretRejectsRelabeledAAD(t *testing.T) {
	source := testInitializedStore(t)
	source.State.Devices = append(source.State.Devices, testDevice(t, "source"))
	if err := source.Save(); err != nil {
		t.Fatal(err)
	}
	if _, err := source.AddSecret("oclan-co/local/asiri/API_KEY", "restored-secret"); err != nil {
		t.Fatal(err)
	}
	expires := time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339)
	if err := source.LinkControlPlane("http://control.test", "org_oclan", "oclan-co", "usr_owner", "dev_source", "at_source", "rt_source", 3600, expires); err != nil {
		t.Fatal(err)
	}
	bindPrefixForTest(t, source, "oclan-co", "org_oclan")
	versions, err := source.RemoteSecretVersionsForPrefix("org_oclan", "oclan-co", "dev_source", "oclan-co")
	if err != nil {
		t.Fatal(err)
	}
	versions[0].Scope = "oclan-co/local/other"
	if _, err := source.ImportRemoteSecretVersions("org_oclan", "oclan-co", "dev_source", versions, true); err == nil || !strings.Contains(err.Error(), "encryption metadata") {
		t.Fatalf("expected AAD mismatch rejection, got %v", err)
	}
}

func TestImportRemoteSecretSkipsMalformedEnvelopeAndImportsValidSecret(t *testing.T) {
	source := testInitializedStore(t)
	sourceDevice := testDevice(t, "source")
	source.State.Devices = append(source.State.Devices, sourceDevice)
	if err := source.Save(); err != nil {
		t.Fatal(err)
	}
	if _, err := source.AddSecret("oclan-co/local/asiri/BAD", "poisoned-secret"); err != nil {
		t.Fatal(err)
	}
	if _, err := source.AddSecret("oclan-co/local/asiri/GOOD", "valid-secret"); err != nil {
		t.Fatal(err)
	}
	expires := time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339)
	if err := source.LinkControlPlane("http://control.test", "org_oclan", "oclan-co", "usr_owner", "dev_source", "at_source", "rt_source", 3600, expires); err != nil {
		t.Fatal(err)
	}
	bindPrefixForTest(t, source, "oclan-co", "org_oclan")
	versions, err := source.RemoteSecretVersionsForPrefix("org_oclan", "oclan-co", "dev_source", "oclan-co")
	if err != nil {
		t.Fatal(err)
	}
	if len(versions) != 2 {
		t.Fatalf("expected two remote versions, got %d", len(versions))
	}

	target := testInitializedStore(t)
	targetDevice := testDevice(t, "target")
	target.State.Devices = append(target.State.Devices, targetDevice)
	if err := target.Save(); err != nil {
		t.Fatal(err)
	}
	if err := target.LinkControlPlane("http://control.test", "org_oclan", "oclan-co", "usr_owner", "dev_target", "at_target", "rt_target", 3600, expires); err != nil {
		t.Fatal(err)
	}
	bindPrefixForTest(t, target, "oclan-co", "org_oclan")
	for i := range versions {
		wrapped, err := source.RemoteWrappedKeyForSecretVersionPublicKey("org_oclan", versions[i].Scope, versions[i].Name, versions[i].Version, "dev_target", targetDevice.EncryptionPublicKey)
		if err != nil {
			t.Fatal(err)
		}
		versions[i].WrappedKeys = []RemoteWrappedKey{wrapped}
	}
	versions[0].AAD = strings.Replace(versions[0].AAD, ":BAD:", ":OTHER:", 1)

	imported, err := target.ImportRemoteSecretVersions("org_oclan", "oclan-co", "dev_target", versions, true)
	if imported != 1 {
		t.Fatalf("expected valid remote secret to import despite malformed neighbor, got %d imports and err %v", imported, err)
	}
	if err == nil || !strings.Contains(err.Error(), "skipped 1 malformed remote secret version") || !strings.Contains(err.Error(), "BAD") {
		t.Fatalf("expected partial malformed-envelope report, got %v", err)
	}
	value, _, err := target.GetSecret("oclan-co/local/asiri/GOOD")
	if err != nil {
		t.Fatal(err)
	}
	if value != "valid-secret" {
		t.Fatalf("valid secret mismatch: %q", value)
	}
	if _, _, err := target.GetSecret("oclan-co/local/asiri/BAD"); err == nil {
		t.Fatal("malformed remote secret should not be imported")
	}
	if len(target.State.Audit) < 2 || target.State.Audit[0].Action != "control_plane_import" || target.State.Audit[1].Action != "control_plane_import_quarantine" {
		t.Fatalf("expected import and quarantine audit entries, got %#v", target.State.Audit)
	}
}

func TestImportRemoteSecretRejectsForeignWorkspacePrefix(t *testing.T) {
	source := testInitializedStore(t)
	source.State.Devices = append(source.State.Devices, testDevice(t, "source"))
	if err := source.Save(); err != nil {
		t.Fatal(err)
	}
	if _, err := source.AddSecret("google-com/local/asiri/API_KEY", "poisoned-secret"); err != nil {
		t.Fatal(err)
	}
	expires := time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339)
	if err := source.LinkControlPlane("http://control.test", "org_oclan", "oclan-co", "usr_owner", "dev_source", "at_source", "rt_source", 3600, expires); err != nil {
		t.Fatal(err)
	}
	if err := source.BindWorkspacePrefix("google-com", "org_oclan", "oclan-co"); err != nil {
		t.Fatal(err)
	}
	versions, err := source.RemoteSecretVersionsForPrefix("org_oclan", "google-com", "dev_source", "google-com")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := source.ImportRemoteSecretVersions("org_oclan", "oclan-co", "dev_source", versions, true); err == nil || !strings.Contains(err.Error(), "path prefix is google-com") {
		t.Fatalf("expected foreign prefix rejection, got %v", err)
	}
}

func TestImportRemoteSecretRequiresWorkspaceID(t *testing.T) {
	st := testInitializedStore(t)
	st.State.Devices = append(st.State.Devices, testDevice(t, "source"))
	if err := st.Save(); err != nil {
		t.Fatal(err)
	}
	if _, err := st.AddSecret("oclan-co/local/asiri/API_KEY", "secret"); err != nil {
		t.Fatal(err)
	}
	expires := time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339)
	if err := st.LinkControlPlane("http://control.test", "org_oclan", "oclan-co", "usr_owner", "dev_source", "at_source", "rt_source", 3600, expires); err != nil {
		t.Fatal(err)
	}
	bindPrefixForTest(t, st, "oclan-co", "org_oclan")
	versions, err := st.RemoteSecretVersionsForPrefix("org_oclan", "oclan-co", "dev_source", "oclan-co")
	if err != nil {
		t.Fatal(err)
	}
	versions[0].OrgID = ""
	if _, err := st.ImportRemoteSecretVersions("org_oclan", "oclan-co", "dev_source", versions, true); err == nil || !strings.Contains(err.Error(), "missing workspace id") {
		t.Fatalf("expected missing workspace id rejection, got %v", err)
	}
}

func TestImportRemoteSecretAcceptsEqualLocalValueWithDifferentEnvelope(t *testing.T) {
	const (
		workspaceID   = "org_oclan"
		workspaceSlug = "oclan-co"
		secretPath    = "oclan-co/local/asiri/API_KEY"
	)
	expires := time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339)

	source := testInitializedStore(t)
	sourceDevice := testDevice(t, "source")
	source.State.Devices = append(source.State.Devices, sourceDevice)
	if err := source.Save(); err != nil {
		t.Fatal(err)
	}
	if _, err := source.AddSecret(secretPath, "shared-secret"); err != nil {
		t.Fatal(err)
	}
	if err := source.LinkControlPlane("http://control.test", workspaceID, workspaceSlug, "usr_owner", "dev_source", "at_source", "rt_source", 3600, expires); err != nil {
		t.Fatal(err)
	}
	bindPrefixForTest(t, source, workspaceSlug, workspaceID)
	versions, err := source.RemoteSecretVersionsForPrefix(workspaceID, workspaceSlug, "dev_source", workspaceSlug)
	if err != nil || len(versions) != 1 {
		t.Fatalf("unexpected source versions: count=%d err=%v", len(versions), err)
	}

	target := testInitializedStore(t)
	targetDevice := testDevice(t, "target")
	target.State.Devices = append(target.State.Devices, targetDevice)
	if err := target.Save(); err != nil {
		t.Fatal(err)
	}
	if _, err := target.AddSecret(secretPath, "shared-secret"); err != nil {
		t.Fatal(err)
	}
	if err := target.LinkControlPlane("http://control.test", workspaceID, workspaceSlug, "usr_owner", "dev_target", "at_target", "rt_target", 3600, expires); err != nil {
		t.Fatal(err)
	}
	bindPrefixForTest(t, target, workspaceSlug, workspaceID)
	localBefore := target.State.Secrets[SecretKey("oclan-co/local/asiri", "API_KEY")].Versions[0]
	if localBefore.Ciphertext == versions[0].Ciphertext {
		t.Fatal("test requires independently encrypted local and remote envelopes")
	}
	wrapped, err := source.RemoteWrappedKeyForSecretVersionPublicKey(workspaceID, versions[0].Scope, versions[0].Name, versions[0].Version, "dev_target", targetDevice.EncryptionPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	versions[0].WrappedKeys = []RemoteWrappedKey{wrapped}

	imported, err := target.ImportRemoteSecretVersions(workspaceID, workspaceSlug, "dev_target", versions, false)
	if err != nil {
		t.Fatal(err)
	}
	if imported != 1 {
		t.Fatalf("expected one reconciled remote version, got %d", imported)
	}
	active := activeSecretVersion(target.State.Secrets[SecretKey("oclan-co/local/asiri", "API_KEY")])
	if active == nil || active.AAD != versions[0].AAD || active.Ciphertext != versions[0].Ciphertext {
		t.Fatalf("equal local value did not adopt the remote envelope: %#v", active)
	}
	if active.DataKeyAccount != localBefore.DataKeyAccount {
		t.Fatal("equal-value reconciliation should reuse the existing local data-key account")
	}
	value, _, err := target.GetSecret(secretPath)
	if err != nil || value != "shared-secret" {
		t.Fatalf("reconciled secret is not usable: value=%q err=%v", value, err)
	}
}

func TestImportRemoteSecretRejectsLocalConflictWithoutForce(t *testing.T) {
	st := testInitializedStore(t)
	st.State.Devices = append(st.State.Devices, testDevice(t, "source"))
	if err := st.Save(); err != nil {
		t.Fatal(err)
	}
	if _, err := st.AddSecret("oclan-co/local/asiri/API_KEY", "local-secret"); err != nil {
		t.Fatal(err)
	}
	expires := time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339)
	if err := st.LinkControlPlane("http://control.test", "org_oclan", "oclan-co", "usr_owner", "dev_source", "at_source", "rt_source", 3600, expires); err != nil {
		t.Fatal(err)
	}
	bindPrefixForTest(t, st, "oclan-co", "org_oclan")
	versions, err := st.RemoteSecretVersionsForPrefix("org_oclan", "oclan-co", "dev_source", "oclan-co")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.AddSecret("oclan-co/local/asiri/API_KEY", "changed-local-secret"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.ImportRemoteSecretVersions("org_oclan", "oclan-co", "dev_source", versions, false); err == nil {
		t.Fatal("expected conflict rejection")
	} else {
		var conflictErr *RemoteImportConflictError
		if !errors.As(err, &conflictErr) || len(conflictErr.Conflicts) != 1 {
			t.Fatalf("expected one typed conflict, got %v", err)
		}
		conflict := conflictErr.Conflicts[0]
		if SecretKey(conflict.Scope, conflict.Name) != "oclan-co/local/asiri/API_KEY" || conflict.LocalVersion != 2 || conflict.RemoteVersion != 1 {
			t.Fatalf("unexpected conflict metadata: %#v", conflict)
		}
	}
	if _, err := st.ImportRemoteSecretVersions("org_oclan", "oclan-co", "dev_source", versions, true); err != nil {
		t.Fatalf("force import should replace local active version: %v", err)
	}
}

func TestImportRemoteSecretListsAllLocalConflictsAndComparisonFailuresWithoutPartialImport(t *testing.T) {
	const (
		workspaceID   = "org_oclan"
		workspaceSlug = "oclan-co"
		scope         = "oclan-co/prod/asiri"
	)
	expires := time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339)

	source := testInitializedStore(t)
	sourceDevice := testDevice(t, "source")
	source.State.Devices = append(source.State.Devices, sourceDevice)
	if err := source.Save(); err != nil {
		t.Fatal(err)
	}
	for _, secret := range []struct {
		name  string
		value string
	}{
		{name: "ZETA_KEY", value: "remote-zeta"},
		{name: "MIDDLE_KEY", value: "remote-middle"},
		{name: "BROKEN_KEY", value: "remote-broken"},
		{name: "ALPHA_KEY", value: "remote-alpha"},
	} {
		if _, err := source.AddSecret(SecretKey(scope, secret.name), secret.value); err != nil {
			t.Fatal(err)
		}
	}
	if err := source.LinkControlPlane("http://control.test", workspaceID, workspaceSlug, "usr_owner", "dev_source", "at_source", "rt_source", 3600, expires); err != nil {
		t.Fatal(err)
	}
	bindPrefixForTest(t, source, workspaceSlug, workspaceID)
	versions, err := source.RemoteSecretVersionsForPrefix(workspaceID, workspaceSlug, "dev_source", workspaceSlug)
	if err != nil || len(versions) != 4 {
		t.Fatalf("unexpected source versions: count=%d err=%v", len(versions), err)
	}
	remoteDataKeys := make(map[string][]byte, len(versions))
	for _, version := range versions {
		dataKey, err := source.dataKeyForSecretVersion(version.Scope, version.Name, version.Version)
		if err != nil {
			t.Fatal(err)
		}
		remoteDataKeys[SecretKey(version.Scope, version.Name)] = dataKey
	}

	target := testInitializedStore(t)
	targetDevice := testDevice(t, "target")
	target.State.Devices = append(target.State.Devices, targetDevice)
	if err := target.Save(); err != nil {
		t.Fatal(err)
	}
	for _, secret := range []struct {
		name  string
		value string
	}{
		{name: "ALPHA_KEY", value: "local-alpha"},
		{name: "BROKEN_KEY", value: "local-broken"},
		{name: "ZETA_KEY", value: "local-zeta"},
	} {
		if _, err := target.AddSecret(SecretKey(scope, secret.name), secret.value); err != nil {
			t.Fatal(err)
		}
	}
	for _, secret := range []struct {
		name  string
		value string
	}{
		{name: "ALPHA_KEY", value: "local-alpha-v2"},
		{name: "ZETA_KEY", value: "local-zeta-v2"},
	} {
		if _, err := target.AddSecret(SecretKey(scope, secret.name), secret.value); err != nil {
			t.Fatal(err)
		}
	}
	if err := target.LinkControlPlane("http://control.test", workspaceID, workspaceSlug, "usr_owner", "dev_target", "at_target", "rt_target", 3600, expires); err != nil {
		t.Fatal(err)
	}
	bindPrefixForTest(t, target, workspaceSlug, workspaceID)
	for left, right := 0, len(versions)-1; left < right; left, right = left+1, right-1 {
		versions[left], versions[right] = versions[right], versions[left]
	}

	wantPaths := []string{
		"oclan-co/prod/asiri/ALPHA_KEY",
		"oclan-co/prod/asiri/ZETA_KEY",
	}
	var blockedVersion RemoteSecretVersion
	var partialVersion RemoteSecretVersion
	for _, version := range versions {
		if version.Name == "BROKEN_KEY" {
			blockedVersion = version
		}
		if version.Name == "MIDDLE_KEY" {
			partialVersion = version
		}
	}
	if blockedVersion.Name == "" || partialVersion.Name == "" {
		t.Fatal("blocked-key or partial remote fixture not found")
	}
	for _, injected := range []error{keystore.ErrPlatformAuthentication, keystore.ErrPlatformTimeout} {
		partialCause := keystore.ErrPlatformAuthentication
		if errors.Is(injected, keystore.ErrPlatformAuthentication) {
			partialCause = keystore.ErrPlatformTimeout
		}
		restoreFailure := keystore.FailPlatformOperationsForTesting(nil, injected, nil)
		imported, err := target.importRemoteSecretVersions(workspaceID, workspaceSlug, versions, false, false, func(remote RemoteSecretVersion) ([]byte, bool, error) {
			if remote.Name == "MIDDLE_KEY" {
				return nil, false, fmt.Errorf("remote key preparation failed: %w", partialCause)
			}
			return remoteDataKeys[SecretKey(remote.Scope, remote.Name)], true, nil
		})
		restoreFailure()
		if err == nil {
			t.Fatal("expected aggregate conflict rejection")
		}
		if imported != 0 {
			t.Fatalf("conflicting import reported %d imported secrets", imported)
		}
		var conflictErr *RemoteImportConflictError
		if !errors.As(err, &conflictErr) {
			t.Fatalf("expected typed conflict error, got %T: %v", err, err)
		}
		if !errors.Is(err, injected) {
			t.Fatalf("aggregate conflict error lost %v: %v", injected, err)
		}
		if !errors.Is(err, partialCause) {
			t.Fatalf("aggregate conflict error lost partial cause %v: %v", partialCause, err)
		}
		if len(conflictErr.Conflicts) != 2 {
			t.Fatalf("expected two conflicts, got %#v", conflictErr.Conflicts)
		}
		unresolvedPaths := map[string]bool{}
		for _, unresolved := range conflictErr.Unresolved {
			unresolvedPaths[remoteImportSkippedLabel(unresolved)] = true
		}
		if len(conflictErr.Unresolved) != 2 || !unresolvedPaths["oclan-co/prod/asiri/BROKEN_KEY"] || !unresolvedPaths["oclan-co/prod/asiri/MIDDLE_KEY"] {
			t.Fatalf("expected the comparison failure alongside conflicts, got %#v", conflictErr.Unresolved)
		}
		for i, conflict := range conflictErr.Conflicts {
			if got := SecretKey(conflict.Scope, conflict.Name); got != wantPaths[i] {
				t.Fatalf("conflict %d path = %q, want %q", i, got, wantPaths[i])
			}
			if conflict.LocalVersion != 2 || conflict.RemoteVersion != 1 {
				t.Fatalf("conflict %d versions unexpected: %#v", i, conflict)
			}
		}
		message := err.Error()
		if alpha, zeta := strings.Index(message, wantPaths[0]), strings.Index(message, wantPaths[1]); alpha < 0 || zeta < 0 || alpha >= zeta {
			t.Fatalf("conflict message should list every key in order: %s", message)
		}
		for _, expected := range []string{"2 additional remote secrets could not be prepared", "oclan-co/prod/asiri/BROKEN_KEY", "cannot be compared with the local active version", "oclan-co/prod/asiri/MIDDLE_KEY", "remote key preparation failed"} {
			if !strings.Contains(message, expected) {
				t.Fatalf("conflict message missing comparison failure %q: %s", expected, message)
			}
		}

		restoreFailure = keystore.FailPlatformOperationsForTesting(nil, injected, nil)
		_, standaloneErr := target.importRemoteSecretVersions(workspaceID, workspaceSlug, []RemoteSecretVersion{blockedVersion}, false, false, func(remote RemoteSecretVersion) ([]byte, bool, error) {
			return remoteDataKeys[SecretKey(remote.Scope, remote.Name)], true, nil
		})
		restoreFailure()
		if !errors.Is(standaloneErr, injected) {
			t.Fatalf("standalone comparison error lost %v: %v", injected, standaloneErr)
		}

		_, partialErr := target.importRemoteSecretVersions(workspaceID, workspaceSlug, []RemoteSecretVersion{partialVersion}, false, false, func(remote RemoteSecretVersion) ([]byte, bool, error) {
			return nil, false, fmt.Errorf("remote key preparation failed: %w", partialCause)
		})
		if !errors.Is(partialErr, partialCause) {
			t.Fatalf("partial import error lost %v: %v", partialCause, partialErr)
		}
	}
	if _, ok := target.State.Secrets[SecretKey(scope, "MIDDLE_KEY")]; ok {
		t.Fatal("non-conflicting remote secret was imported despite aggregate conflict rejection")
	}
	for _, secret := range []struct {
		name  string
		value string
	}{
		{name: "ALPHA_KEY", value: "local-alpha-v2"},
		{name: "ZETA_KEY", value: "local-zeta-v2"},
	} {
		value, _, err := target.GetSecret(SecretKey(scope, secret.name))
		if err != nil {
			t.Fatal(err)
		}
		if value != secret.value {
			t.Fatalf("local value for %s changed during rejected import", secret.name)
		}
	}
}

func TestRotateDataKeysReencryptsActiveSecrets(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	st, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.InitializeLocal(); err != nil {
		t.Fatal(err)
	}
	st.State.Devices = append(st.State.Devices, testDevice(t, "rotator"))
	if err := st.Save(); err != nil {
		t.Fatal(err)
	}
	if _, err := st.AddSecret("oclan-co/prod/asiri/API_KEY", "rotate-me"); err != nil {
		t.Fatal(err)
	}
	before := st.State.Secrets[SecretKey("oclan-co/prod/asiri", "API_KEY")]
	rotated, err := st.RotateDataKeys()
	if err != nil {
		t.Fatal(err)
	}
	if rotated != 1 {
		t.Fatalf("expected one rotated secret, got %d", rotated)
	}
	after := st.State.Secrets[SecretKey("oclan-co/prod/asiri", "API_KEY")]
	if after.ActiveVersion != before.ActiveVersion+1 {
		t.Fatalf("expected active version to advance, before=%d after=%d", before.ActiveVersion, after.ActiveVersion)
	}
	if after.Versions[0].Status != "stale" || after.Versions[1].Status != "active" {
		t.Fatalf("unexpected version statuses: %#v", after.Versions)
	}
	if after.Versions[0].Ciphertext == after.Versions[1].Ciphertext {
		t.Fatal("rotation should re-encrypt ciphertext")
	}
	value, _, err := st.GetSecret("oclan-co/prod/asiri/API_KEY")
	if err != nil {
		t.Fatal(err)
	}
	if value != "rotate-me" {
		t.Fatalf("rotated secret mismatch: %q", value)
	}
}

func TestRemoteSecretVersionsRejectsStaleSelectedVersion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	st, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.InitializeLocal(); err != nil {
		t.Fatal(err)
	}
	device := testDevice(t, "push-device")
	st.State.Devices = append(st.State.Devices, device)
	if err := st.Save(); err != nil {
		t.Fatal(err)
	}
	if _, err := st.AddSecret("oclan-co/prod/asiri/API_KEY", "rotate-me"); err != nil {
		t.Fatal(err)
	}
	expires := time.Now().UTC().Add(7 * 24 * time.Hour).Format(time.RFC3339)
	if err := st.LinkControlPlaneForDevice("http://control.test", "org_oclan", "oclan-co", "usr_owner", "dev_remote", device.ID, "at", "rt", 3600, expires); err != nil {
		t.Fatal(err)
	}
	if err := st.BindWorkspacePrefix("oclan-co", "org_oclan", "oclan-co"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.RotateDataKeysForPrefix("oclan-co"); err != nil {
		t.Fatal(err)
	}
	active := st.State.Secrets[SecretKey("oclan-co/prod/asiri", "API_KEY")]
	remote, err := st.RemoteSecretVersionsForRefsWithRecovery("org_oclan", "oclan-co", "dev_remote", []LocalSecretRef{{
		Scope:   "oclan-co/prod/asiri",
		Name:    "API_KEY",
		Version: active.ActiveVersion,
	}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(remote) != 1 || !remote[0].CreatedAt.Equal(active.Versions[len(active.Versions)-1].CreatedAt) {
		t.Fatalf("remote upload candidate lost local creation time: %#v", remote)
	}
	_, err = st.RemoteSecretVersionsForRefsWithRecovery("org_oclan", "oclan-co", "dev_remote", []LocalSecretRef{{
		Scope:   "oclan-co/prod/asiri",
		Name:    "API_KEY",
		Version: 1,
	}}, nil)
	if err == nil {
		t.Fatal("stale selected version should be rejected")
	}
	if !strings.Contains(err.Error(), "push only supports active versions") {
		t.Fatalf("unexpected stale version error: %v", err)
	}
}

func testPublicKey(t *testing.T) string {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(publicBytes)
}

func testDevice(t *testing.T, name string) asiri.Device {
	t.Helper()
	deviceID := NewID("dev")
	encryptionPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signingPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	encryptionPrivateBytes, err := x509.MarshalECPrivateKey(encryptionPrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	signingPrivateBytes, err := x509.MarshalECPrivateKey(signingPrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	encryptionPublicBytes, err := x509.MarshalPKIXPublicKey(&encryptionPrivateKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	signingPublicBytes, err := x509.MarshalPKIXPublicKey(&signingPrivateKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := keystore.Store(keystore.DeviceKeyAccount(deviceID, "encryption-private"), base64.StdEncoding.EncodeToString(encryptionPrivateBytes)); err != nil {
		t.Fatal(err)
	}
	if err := keystore.Store(keystore.DeviceKeyAccount(deviceID, "signing-private"), base64.StdEncoding.EncodeToString(signingPrivateBytes)); err != nil {
		t.Fatal(err)
	}
	return asiri.Device{
		ID:                  deviceID,
		Name:                name,
		Kind:                "laptop",
		Status:              asiri.DeviceTrusted,
		EncryptionPublicKey: base64.StdEncoding.EncodeToString(encryptionPublicBytes),
		SigningPublicKey:    base64.StdEncoding.EncodeToString(signingPublicBytes),
		CreatedAt:           time.Now().UTC(),
	}
}

func testInitializedStore(t *testing.T) *FileStore {
	t.Helper()
	st, err := Load(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := st.InitializeLocal(); err != nil {
		t.Fatal(err)
	}
	return st
}

func bindPrefixForTest(t *testing.T, st *FileStore, prefix, workspaceID string) {
	t.Helper()
	if err := st.BindWorkspacePrefix(prefix, workspaceID, prefix); err != nil {
		t.Fatal(err)
	}
}
