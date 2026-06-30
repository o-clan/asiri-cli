package store

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/o-clan/asiri/cli/internal/asiri"
	"github.com/o-clan/asiri/cli/internal/keystore"
	"github.com/zalando/go-keyring"
)

func TestMain(m *testing.M) {
	keyring.MockInit()
	os.Exit(m.Run())
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

func TestAgentRawReadRequiresExplicitPolicy(t *testing.T) {
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
	allowed, reason := st.CheckPolicy("codex", "qa/openai/api_key", "read")
	if allowed || !strings.Contains(reason, "explicit policy") {
		t.Fatalf("expected denied raw read, got allowed=%v reason=%q", allowed, reason)
	}
	if _, err := st.Grant("codex", "qa/openai/api_key", []string{"inject"}); err != nil {
		t.Fatal(err)
	}
	allowed, reason = st.CheckPolicy("codex", "qa/openai/api_key", "inject")
	if !allowed {
		t.Fatalf("expected inject allowed, got %q", reason)
	}
}

func TestReservedHumanSubjectCannotImpersonateHuman(t *testing.T) {
	st := testInitializedStore(t, "oclan-co")
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
	if allowed || !strings.Contains(reason, "reserved") {
		t.Fatalf("expected reserved human subject denial, got allowed=%v reason=%q", allowed, reason)
	}
	if _, err := st.Grant(st.State.UserID, "oclan-co/local/asiri/API_KEY", []string{"read"}); err == nil || !strings.Contains(err.Error(), "reserved") {
		t.Fatalf("expected reserved human grant rejection, got %v", err)
	}
	if _, err := st.Grant(st.State.UserID+" ", "oclan-co/local/asiri/API_KEY", []string{"read"}); err == nil || !strings.Contains(err.Error(), "reserved") {
		t.Fatalf("expected whitespace-spoofed human grant rejection, got %v", err)
	}
	if _, err := st.Deny(st.State.UserID, "oclan-co/local/asiri/*"); err == nil || !strings.Contains(err.Error(), "reserved") {
		t.Fatalf("expected reserved human deny rejection, got %v", err)
	}
	expires := time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339)
	if err := st.LinkControlPlaneForDevice("http://control.test", "org_oclan", "oclan-co", "usr_owner", "dev_remote", device.ID, "at", "rt", 3600, expires); err != nil {
		t.Fatal(err)
	}
	allowed, reason = st.CheckPolicy("usr_owner", "oclan-co/local/asiri/API_KEY", "inject")
	if allowed || !strings.Contains(reason, "reserved") {
		t.Fatalf("expected reserved remote human subject denial, got allowed=%v reason=%q", allowed, reason)
	}
	allowed, reason = st.CheckPolicy("usr_owner ", "oclan-co/local/asiri/API_KEY", "inject")
	if allowed || !strings.Contains(reason, "reserved") {
		t.Fatalf("expected whitespace-spoofed remote human subject denial, got allowed=%v reason=%q", allowed, reason)
	}
}

func TestRevokingCurrentLocalDeviceClearsKeyMaterialAndBlocksDecryption(t *testing.T) {
	st := testInitializedStore(t, "oclan-co")
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
	st := testInitializedStore(t, "oclan-co")
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
	st := testInitializedStore(t, "oclan-co")
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
	keyring.MockInitWithError(errors.New("delete failed"))
	t.Cleanup(keyring.MockInit)
	if err := st.QuarantineLocalKeys("remote device is no longer trusted"); err == nil {
		t.Fatal("expected failed platform deletion")
	}
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
	st := testInitializedStore(t, "oclan-co")
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
	st := testInitializedStore(t, "oclan-co")
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
	versions, err := st.RemoteSecretVersionsForPrefix("oclan-co")
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

func TestRemoveSecretKeepsDataKeyWhenSaveFails(t *testing.T) {
	st := testInitializedStore(t, "oclan-co")
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
	st := testInitializedStore(t, "oclan-co")
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
	st := testInitializedStore(t, "google-com")
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
	st := testInitializedStore(t, "google-com")
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
	setup, err := st.SetupRecovery(false)
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
	recovery := st.ActiveRecovery()
	if recovery == nil || recovery.PublicKey == "" || recovery.RecipientID == "" {
		t.Fatalf("recovery metadata missing: %#v", st.State.Recoveries)
	}
	versions, err := st.RemoteSecretVersionsForPrefix("oclan-co")
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
	if err := st.LinkControlPlane("http://control.test", "org_peter", "peter-dev", "usr_owner", "dev_remote", "at2", "rt2", 3600, expires); err != nil {
		t.Fatal(err)
	}
	if st.ActiveRecovery() != nil {
		t.Fatalf("second workspace should not inherit recovery metadata: %#v", st.State.Recoveries)
	}
}

func TestRecoveryWrappedCountsAreTrackedPerActiveWorkspace(t *testing.T) {
	st := testInitializedStore(t, "oclan-co")
	st.State.Devices = append(st.State.Devices, testDevice(t, "source"))
	if err := st.Save(); err != nil {
		t.Fatal(err)
	}
	expires := time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339)
	if err := st.LinkControlPlane("http://control.test", "org_oclan", "oclan-co", "usr_owner", "dev_remote", "at", "rt", 3600, expires); err != nil {
		t.Fatal(err)
	}
	st.State.Recoveries = map[string]asiri.RecoveryConfig{"org_oclan": {
		RecipientID:          "rec_test",
		PublicKey:            "public",
		PublicKeyFingerprint: "fingerprint",
		CreatedAt:            time.Now().UTC(),
	}}
	if err := st.MarkRecoveryWrapped("oclan-co", 2); err != nil {
		t.Fatal(err)
	}
	if st.RecoveryWrappedCountForPrefix("oclan-co") != 2 {
		t.Fatalf("active workspace recovery count was not tracked: %#v", st.State.Recoveries)
	}
	if st.RecoveryWrappedCountForPrefix("peter-dev") != 0 {
		t.Fatalf("inactive workspace should not share recovery count: %#v", st.State.Recoveries)
	}
	if st.State.Recoveries["org_oclan"].WrappedSecretCount != 2 {
		t.Fatalf("expected workspace-local count, got %#v", st.State.Recoveries)
	}
}

func TestRemoteSecretVersionsUseDistinctDataKeys(t *testing.T) {
	st := testInitializedStore(t, "oclan-co")
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
	versions, err := st.RemoteSecretVersionsForPrefix("oclan-co")
	if err != nil {
		t.Fatal(err)
	}
	if len(versions) != 2 {
		t.Fatalf("expected two remote versions, got %d", len(versions))
	}
	firstKey, err := st.UnwrapDeviceDataKey(versions[0].WrappedKeys)
	if err != nil {
		t.Fatal(err)
	}
	secondKey, err := st.UnwrapDeviceDataKey(versions[1].WrappedKeys)
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
	source := testInitializedStore(t, "oclan-co")
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
	remoteVersions, err := source.RemoteSecretVersionsForPrefix("oclan-co")
	if err != nil {
		t.Fatal(err)
	}
	if len(remoteVersions) != 1 || remoteVersions[0].Version != 1 {
		t.Fatalf("expected remote version 1, got %#v", remoteVersions)
	}
	if _, err := source.AddSecret("oclan-co/local/asiri/API_KEY", "second-secret"); err != nil {
		t.Fatal(err)
	}
	target := testInitializedStore(t, "oclan-co")
	targetDevice := testDevice(t, "target")
	target.State.Devices = append(target.State.Devices, targetDevice)
	if err := target.Save(); err != nil {
		t.Fatal(err)
	}
	if err := target.LinkControlPlane("http://control.test", "org_oclan", "oclan-co", "usr_owner", "dev_target", "at_target", "rt_target", 3600, expires); err != nil {
		t.Fatal(err)
	}
	bindPrefixForTest(t, target, "oclan-co", "org_oclan")
	wrapped, err := source.RemoteWrappedKeyForSecretVersionPublicKey("oclan-co/local/asiri", "API_KEY", 1, "dev_target", targetDevice.EncryptionPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	rewrappedKey, err := target.UnwrapDeviceDataKey([]RemoteWrappedKey{wrapped})
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
	setup, err := source.SetupRecovery(false)
	if err != nil {
		t.Fatal(err)
	}
	versions, err := source.RemoteSecretVersionsForPrefix("oclan-co")
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
	imported, identity, err := target.ImportRecoveryRemoteSecretVersions(versions, setup.Key, false)
	if err != nil {
		t.Fatal(err)
	}
	sourceRecovery := source.ActiveRecovery()
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
	wrapped, err := target.RemoteWrappedKeyForSecretVersionPublicKey("oclan-co/local/asiri", "API_KEY", versions[0].Version, "dev_target", targetDevice.EncryptionPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if wrapped.RecipientID != "dev_target" || wrapped.WrapAlgorithm != "p256-hkdf-aes256gcm" {
		t.Fatalf("unexpected recovered device wrapped key: %#v", wrapped)
	}
}

func TestImportRemoteSecretRejectsRelabeledAAD(t *testing.T) {
	source := testInitializedStore(t, "oclan-co")
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
	versions, err := source.RemoteSecretVersionsForPrefix("oclan-co")
	if err != nil {
		t.Fatal(err)
	}
	versions[0].Scope = "oclan-co/local/other"
	if _, err := source.ImportRemoteSecretVersions(versions, true); err == nil || !strings.Contains(err.Error(), "encryption metadata") {
		t.Fatalf("expected AAD mismatch rejection, got %v", err)
	}
}

func TestImportRemoteSecretSkipsMalformedEnvelopeAndImportsValidSecret(t *testing.T) {
	source := testInitializedStore(t, "oclan-co")
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
	versions, err := source.RemoteSecretVersionsForPrefix("oclan-co")
	if err != nil {
		t.Fatal(err)
	}
	if len(versions) != 2 {
		t.Fatalf("expected two remote versions, got %d", len(versions))
	}

	target := testInitializedStore(t, "oclan-co")
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
		wrapped, err := source.RemoteWrappedKeyForSecretVersionPublicKey(versions[i].Scope, versions[i].Name, versions[i].Version, "dev_target", targetDevice.EncryptionPublicKey)
		if err != nil {
			t.Fatal(err)
		}
		versions[i].WrappedKeys = []RemoteWrappedKey{wrapped}
	}
	versions[0].AAD = strings.Replace(versions[0].AAD, ":BAD:", ":OTHER:", 1)

	imported, err := target.ImportRemoteSecretVersions(versions, true)
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
	source := testInitializedStore(t, "oclan-co")
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
	versions, err := source.RemoteSecretVersionsForPrefix("google-com")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := source.ImportRemoteSecretVersions(versions, true); err == nil || !strings.Contains(err.Error(), "path prefix is google-com") {
		t.Fatalf("expected foreign prefix rejection, got %v", err)
	}
}

func TestImportRemoteSecretRejectsLocalConflictWithoutForce(t *testing.T) {
	st := testInitializedStore(t, "oclan-co")
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
	versions, err := st.RemoteSecretVersionsForPrefix("oclan-co")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.AddSecret("oclan-co/local/asiri/API_KEY", "changed-local-secret"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.ImportRemoteSecretVersions(versions, false); err == nil || !strings.Contains(err.Error(), "conflicts with a local active version") {
		t.Fatalf("expected conflict rejection, got %v", err)
	}
	if _, err := st.ImportRemoteSecretVersions(versions, true); err != nil {
		t.Fatalf("force import should replace local active version: %v", err)
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

func testInitializedStore(t *testing.T, workspace string) *FileStore {
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
