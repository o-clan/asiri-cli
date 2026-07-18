package cli

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/o-clan/asiri/cli/internal/asiri"
	"github.com/o-clan/asiri/cli/internal/store"
	"golang.org/x/term"
)

func (a App) rekey(st *store.FileStore, args []string) int {
	if err := st.RequireInitialized(); err != nil {
		return a.fail(err)
	}
	if st.State.ControlPlane == nil {
		return a.fail(errors.New("asiri is not linked to a control plane"))
	}
	if err := rejectServiceAccountControlPlaneMutation(st); err != nil {
		return a.fail(err)
	}
	workspaceArg, remaining, err := splitWorkspaceFlag(args, "rekey", true)
	if err != nil {
		return a.fail(err)
	}
	if err := rejectUnknownArgs(remaining, "--yes"); err != nil {
		return a.fail(err)
	}
	accessToken, err := ensureControlPlaneAccess(st.State.ControlPlane.Origin, st)
	if err != nil {
		return a.fail(err)
	}
	target, accessToken, err := a.remoteWorkspaceTarget(st, accessToken, workspaceArg)
	if err != nil {
		return a.fail(err)
	}
	if binding, ok := st.RemoteBindingForPrefix(target.Slug); !ok || binding.WorkspaceID != target.ID {
		return a.fail(fmt.Errorf("workspace prefix %s must be pushed or pulled before rekey", target.Slug))
	}
	refs := st.ActiveSecretRefs()
	selectedRefs := make([]store.LocalSecretRef, 0, len(refs))
	for _, ref := range refs {
		if store.WorkspacePrefix(ref.Scope) == target.Slug {
			selectedRefs = append(selectedRefs, ref)
		}
	}
	if len(selectedRefs) == 0 {
		fmt.Fprintln(a.Out, "No local active secrets to rekey")
		return 0
	}
	options, err := remoteWriteOptions(st, st.State.ControlPlane.Origin, accessToken, target, selectedRefs)
	if err != nil {
		return a.fail(err)
	}
	if !options.Workspace.CanWrite {
		return a.fail(fmt.Errorf("workspace %s cannot write %s", target.Slug, fullPathList(options.Workspace.Paths)))
	}
	if _, err := getActiveRemoteRecoveryRecipient(st, st.State.ControlPlane.Origin, target.ID, accessToken); err != nil {
		return a.fail(err)
	}
	rotated, err := st.RotateDataKeysForPrefix(target.Slug)
	if err != nil {
		return a.fail(err)
	}
	if rotated == 0 {
		fmt.Fprintln(a.Out, "No local active secrets to rekey")
		return 0
	}
	fmt.Fprintf(a.Out, "✓ Re-encrypted %d local secret(s) with new scoped data keys\n", rotated)
	return a.push(st, args)
}

func (a App) rewrap(st *store.FileStore, args []string) int {
	if err := st.RequireInitialized(); err != nil {
		return a.fail(err)
	}
	if st.State.ControlPlane == nil {
		return a.fail(errors.New("asiri is not linked to a control plane"))
	}
	if err := rejectServiceAccountControlPlaneMutation(st); err != nil {
		return a.fail(err)
	}
	workspaceArg, remaining, err := splitWorkspaceFlag(args, "rewrap", true)
	if err != nil {
		return a.fail(err)
	}
	if err := rejectUnknownArgs(remaining); err != nil {
		return a.fail(err)
	}
	accessToken, err := ensureControlPlaneAccess(st.State.ControlPlane.Origin, st)
	if err != nil {
		return a.fail(err)
	}
	target, accessToken, err := a.remoteWorkspaceTarget(st, accessToken, workspaceArg)
	if err != nil {
		return a.fail(err)
	}
	stats, err := a.rewrapWorkspace(st, accessToken, target)
	if err != nil {
		return a.fail(err)
	}
	st.Audit(st.State.UserID, "control_plane_rewrap", "allowed", "", "", "wrapped local data keys to trusted remote devices", map[string]string{"secrets": fmt.Sprintf("%d", stats.Updated), "wrappedKeys": fmt.Sprintf("%d", stats.Added), "workspace": target.Slug})
	if err := st.Save(); err != nil {
		return a.fail(err)
	}
	if stats.Added == 0 && stats.SkippedUnavailable > 0 {
		fmt.Fprintf(a.Out, "No remote secrets can be rewrapped from this machine; %d active remote secret version(s) cannot be decrypted by this device\n", stats.SkippedUnavailable)
		return 0
	}
	if stats.Added == 0 {
		fmt.Fprintln(a.Out, "No trusted devices need wrapped keys")
		return 0
	}
	fmt.Fprintf(a.Out, "✓ Rewrapped %d key(s) across %d secret version(s) in workspace %s\n", stats.Added, stats.Updated, target.Slug)
	return 0
}

type rewrapStats struct {
	Updated            int
	Added              int
	SkippedUnavailable int
}

func (a App) rewrapWorkspace(st *store.FileStore, accessToken string, target remoteWorkspaceResponse) (rewrapStats, error) {
	metadataSecrets, status, err := listRemoteSecretMetadata(st, st.State.ControlPlane.Origin, target.ID, accessToken, false)
	if err != nil {
		return rewrapStats{}, err
	}
	secrets := metadataSecrets
	encryptedByVersion := map[string]remoteSecretRecord{}
	if status == http.StatusNotFound {
		secrets, err = listRemoteSecrets(st, st.State.ControlPlane.Origin, target.ID, accessToken, "", false)
		if err != nil {
			return rewrapStats{}, err
		}
		for _, secret := range secrets {
			encryptedByVersion[pushVersionKey(secret.Scope, secret.Name, secret.Version)] = secret
		}
	} else {
		encryptedSecrets, err := listRemoteSecrets(st, st.State.ControlPlane.Origin, target.ID, accessToken, "", false)
		if err != nil {
			return rewrapStats{}, err
		}
		for _, secret := range encryptedSecrets {
			encryptedByVersion[pushVersionKey(secret.Scope, secret.Name, secret.Version)] = secret
		}
	}
	wrappingTargets, batchTargetsSupported, err := listRemoteWrappingTargets(st, st.State.ControlPlane.Origin, target.ID, accessToken)
	if err != nil {
		return rewrapStats{}, err
	}
	stats := rewrapStats{}
	entries := make([]remoteWrappedKeyBatchEntry, 0)
	for _, secret := range secrets {
		if secret.Status != "active" {
			continue
		}
		localAvailable := localSecretVersionExists(st, secret.Scope, secret.Name, secret.Version)
		encrypted, remoteAvailable := encryptedByVersion[pushVersionKey(secret.Scope, secret.Name, secret.Version)]
		if !localAvailable && !remoteAvailable {
			stats.SkippedUnavailable++
			continue
		}
		devices, found := wrappingTargets[secret.ID]
		if !batchTargetsSupported {
			devices, err = listRemoteWrappingDevices(st, st.State.ControlPlane.Origin, target.ID, secret.Scope, secret.Name, accessToken)
			if err != nil {
				return rewrapStats{}, fmt.Errorf("refusing to rewrap without authorized targets for %s/%s: %w", secret.Scope, secret.Name, err)
			}
		} else if !found {
			return rewrapStats{}, fmt.Errorf("refusing to rewrap without authorized targets for %s/%s", secret.Scope, secret.Name)
		}
		missing := make([]store.RemoteWrappedKey, 0)
		for _, device := range devices {
			if device.Status != "trusted" || device.EncryptionPublicKey == "" {
				continue
			}
			if remoteSecretHasRecipient(secret, device.ID) {
				continue
			}
			var wrapped store.RemoteWrappedKey
			if remoteAvailable {
				wrapped, err = st.RemoteWrappedKeyForRemoteVersionPublicKey(target.CurrentDeviceID, encrypted.WrappedKeys, device.ID, device.EncryptionPublicKey)
			}
			if !remoteAvailable || (err != nil && localAvailable) {
				wrapped, err = st.RemoteWrappedKeyForSecretVersionPublicKey(target.ID, secret.Scope, secret.Name, secret.Version, device.ID, device.EncryptionPublicKey)
			}
			if err != nil {
				return rewrapStats{}, err
			}
			missing = append(missing, wrapped)
		}
		if len(missing) == 0 {
			continue
		}
		entries = append(entries, remoteWrappedKeyBatchEntry{SecretID: secret.ID, WrappedKeys: missing, LocalRepair: true})
	}
	if len(entries) == 0 {
		return stats, nil
	}
	batchWritesSupported := true
	for start := 0; start < len(entries); start += 100 {
		end := start + 100
		if end > len(entries) {
			end = len(entries)
		}
		supported, err := addRemoteWrappedKeysBatch(st, st.State.ControlPlane.Origin, target.ID, accessToken, entries[start:end])
		if err != nil {
			return rewrapStats{}, err
		}
		if !supported {
			batchWritesSupported = false
			break
		}
	}
	if !batchWritesSupported {
		for _, entry := range entries {
			if err := addRemoteWrappedKeys(st, st.State.ControlPlane.Origin, target.ID, entry.SecretID, accessToken, entry.WrappedKeys, entry.LocalRepair); err != nil {
				return rewrapStats{}, err
			}
		}
	}
	for _, entry := range entries {
		stats.Updated++
		stats.Added += len(entry.WrappedKeys)
	}
	return stats, nil
}

func (a App) recovery(st *store.FileStore, args []string) int {
	if len(args) == 0 {
		return a.fail(errors.New("recovery subcommand required"))
	}
	if err := st.RequireInitialized(); err != nil {
		return a.fail(err)
	}
	switch args[0] {
	case "status":
		if st.State.ControlPlane == nil {
			return a.fail(errors.New("asiri is not linked to a control plane"))
		}
		workspaceArg, remaining, err := splitWorkspaceFlag(args[1:], "recovery status", true)
		if err != nil {
			return a.fail(err)
		}
		if err := rejectUnknownArgs(remaining); err != nil {
			return a.fail(err)
		}
		accessToken, err := ensureControlPlaneAccess(st.State.ControlPlane.Origin, st)
		if err != nil {
			return a.fail(err)
		}
		target, accessToken, err := a.remoteWorkspaceTarget(st, accessToken, workspaceArg)
		if err != nil {
			return a.fail(err)
		}
		type recoveryStatusRow struct {
			Workspace   string
			Status      string
			Fingerprint string
			Wrapped     int
			Note        string
		}
		row := recoveryStatusRow{Workspace: target.Slug}
		if st.State.Recoveries == nil {
			st.State.Recoveries = map[string]asiri.RecoveryConfig{}
		}
		recovery, err := getActiveRemoteRecoveryRecipient(st, st.State.ControlPlane.Origin, target.ID, accessToken)
		if err != nil {
			return a.fail(err)
		}
		if recovery == nil {
			delete(st.State.Recoveries, target.ID)
			row.Status = "not-configured"
		} else {
			if existing, ok := st.State.Recoveries[target.ID]; ok && existing.RecipientID == recovery.RecipientID {
				recovery.CreatedAt = existing.CreatedAt
				recovery.LastWrappedAt = existing.LastWrappedAt
				recovery.WrappedSecretCount = existing.WrappedSecretCount
			}
			st.State.Recoveries[target.ID] = *recovery
			row.Status = "configured"
			row.Fingerprint = recovery.PublicKeyFingerprint
			row.Wrapped = st.RecoveryWrappedCount(target.ID)
		}
		if err := st.Save(); err != nil {
			return a.fail(err)
		}
		tw := tabwriter.NewWriter(a.Out, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "WORKSPACE\tSTATUS\tFINGERPRINT\tWRAPPED\tNOTE")
		fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t%s\n", row.Workspace, row.Status, row.Fingerprint, row.Wrapped, row.Note)
		if err := tw.Flush(); err != nil {
			return a.fail(err)
		}
		return 0
	case "setup":
		if st.State.ControlPlane == nil {
			return a.fail(errors.New("asiri is not linked to a control plane"))
		}
		if err := rejectServiceAccountControlPlaneMutation(st); err != nil {
			return a.fail(err)
		}
		workspaceArg, remaining, err := splitWorkspaceFlag(args[1:], "recovery setup", true)
		if err != nil {
			return a.fail(err)
		}
		if err := rejectUnknownArgs(remaining, "--force", "--output-file"); err != nil {
			return a.fail(err)
		}
		outputPath, hasOutput, err := optionalFlagValue(remaining, "--output-file")
		if err != nil {
			return a.fail(err)
		}
		outFile, isTerminalOutput := a.Out.(*os.File)
		if !hasOutput && (!isTerminalOutput || !term.IsTerminal(int(outFile.Fd()))) {
			return a.fail(errors.New("recovery setup requires --output-file in non-interactive mode"))
		}
		accessToken, err := ensureControlPlaneAccess(st.State.ControlPlane.Origin, st)
		if err != nil {
			return a.fail(err)
		}
		target, accessToken, err := a.remoteWorkspaceTarget(st, accessToken, workspaceArg)
		if err != nil {
			return a.fail(err)
		}
		force := hasFlag(remaining, "--force")
		remoteRecovery, err := getActiveRemoteRecoveryRecipient(st, st.State.ControlPlane.Origin, target.ID, accessToken)
		if err != nil {
			return a.fail(err)
		}
		if !force && remoteRecovery != nil {
			return a.fail(fmt.Errorf("recovery is already configured for workspace %s; use --force to replace it", target.Slug))
		}
		setup, err := st.GenerateRecoverySetup()
		if err != nil {
			return a.fail(err)
		}
		var outputFile *os.File
		removeOutputOnFailure := false
		if hasOutput {
			outputFile, err = reserveExclusiveSecretFile(outputPath)
			if err != nil {
				return a.fail(err)
			}
			removeOutputOnFailure = true
			defer func() {
				_ = outputFile.Close()
				if removeOutputOnFailure {
					_ = os.Remove(outputPath)
				}
			}()
		}
		replacements, covered, remoteWrapped, err := a.prepareRemoteRecoveryReplacementKeys(st, accessToken, target, setup.Config)
		if err != nil {
			return a.fail(err)
		}
		if hasOutput {
			if err := writeReservedSecretFile(outputFile, []byte(setup.Key+"\n")); err != nil {
				return a.fail(err)
			}
			removeOutputOnFailure = false
			fmt.Fprintf(a.Out, "Recovery key written to %s\n", outputPath)
		} else {
			fmt.Fprintln(a.Out, "Recovery key:")
			fmt.Fprintln(a.Out, setup.Key)
			fmt.Fprintln(a.Out, "Copy this key to a secure place, for example a password app or a printed copy. Asiri will not show it again.")
		}
		if remoteRecovery != nil {
			if err := replaceRemoteRecoveryRecipient(st, st.State.ControlPlane.Origin, target.ID, target.CurrentDeviceID, accessToken, setup, replacements); err != nil {
				return a.fail(fmt.Errorf("recovery key delivered, but remote replacement failed: %w", err))
			}
		} else if err := registerRemoteRecoveryRecipient(st, st.State.ControlPlane.Origin, target.ID, target.CurrentDeviceID, accessToken, setup, replacements); err != nil {
			return a.fail(fmt.Errorf("recovery key delivered, but remote registration failed: %w", err))
		}
		st.CommitRecoverySetup(target.ID, target.Slug, setup)
		if covered > 0 {
			if err := st.MarkRecoveryWrapped(target.ID, target.Slug, covered); err != nil {
				return a.fail(err)
			}
		} else if err := st.Save(); err != nil {
			return a.fail(err)
		}
		fmt.Fprintf(a.Out, "✓ Recovery configured (%s)\n", setup.Fingerprint)
		if len(replacements) > 0 {
			fmt.Fprintf(a.Out, "✓ Added recovery wrapping to %d remote secret(s)\n", len(replacements))
		}
		if remoteWrapped > 0 {
			fmt.Fprintf(a.Out, "✓ Used current remote key material for %d secret version(s) not stored locally\n", remoteWrapped)
		}
		return 0
	case "restore":
		return a.recoveryRestore(st, args[1:])
	default:
		return a.fail(fmt.Errorf("unknown recovery command %q", args[0]))
	}
}

func recoverySecretVersionSummary(secrets []remoteSecretRecord) string {
	const limit = 3
	capacity := len(secrets)
	if capacity > limit {
		capacity = limit
	}
	labels := make([]string, 0, capacity)
	for index, secret := range secrets {
		if index == limit {
			break
		}
		labels = append(labels, fmt.Sprintf("%s v%d", shortSecretPath(secret.Scope, secret.Name), secret.Version))
	}
	if len(secrets) > limit {
		labels = append(labels, fmt.Sprintf("and %d more", len(secrets)-limit))
	}
	return strings.Join(labels, ", ")
}
func (a App) recoveryRestore(st *store.FileStore, args []string) int {
	if st.State.ControlPlane == nil {
		return a.fail(errors.New("asiri is not linked to a control plane"))
	}
	if err := rejectServiceAccountControlPlaneMutation(st); err != nil {
		return a.fail(err)
	}
	workspaceArg, remaining, err := splitWorkspaceFlag(args, "recovery restore", true)
	if err != nil {
		return a.fail(err)
	}
	if err := rejectUnknownArgs(remaining, "--stdin", "--key-file", "--force"); err != nil {
		return a.fail(err)
	}
	recoveryKey, err := a.readSensitiveInput(remaining, "Recovery key", "--key-file", "--key")
	if err != nil {
		return a.fail(err)
	}
	identity, err := store.RecoveryKeyIdentityForKey(recoveryKey)
	if err != nil {
		return a.fail(err)
	}
	accessToken, err := ensureControlPlaneAccess(st.State.ControlPlane.Origin, st)
	if err != nil {
		return a.fail(err)
	}
	target, accessToken, err := a.remoteWorkspaceTarget(st, accessToken, workspaceArg)
	if err != nil {
		return a.fail(err)
	}
	secrets, err := listRemoteSecrets(st, st.State.ControlPlane.Origin, target.ID, accessToken, identity.RecipientID, false)
	if err != nil {
		return a.fail(err)
	}
	activeVersions := remoteRecordsToVersions(secrets)
	if len(activeVersions) == 0 {
		if err := commitRecoveryIdentity(st, target.ID, identity, 0); err != nil {
			return a.fail(err)
		}
		fmt.Fprintln(a.Out, "No remote active secrets to restore")
		return 0
	}
	imported, identity, err := st.ImportRecoveryRemoteSecretVersions(target.ID, target.Slug, activeVersions, recoveryKey, hasFlag(remaining, "--force"))
	if err != nil {
		return a.fail(err)
	}
	rewrapped, err := a.addRecoveredDeviceWrappedKeys(st, accessToken, target, secrets, identity.RecipientID)
	if err != nil {
		return a.fail(err)
	}
	if err := commitRecoveryIdentity(st, target.ID, identity, imported); err != nil {
		return a.fail(err)
	}
	fmt.Fprintf(a.Out, "✓ Restored %d remote secret(s) and registered this device on %d secret(s)\n", imported, rewrapped)
	return 0
}

func commitRecoveryIdentity(st *store.FileStore, workspaceID string, identity store.RecoveryKeyIdentity, wrappedCount int) error {
	if st.State.Recoveries == nil {
		st.State.Recoveries = map[string]asiri.RecoveryConfig{}
	}
	now := time.Now().UTC()
	st.State.Recoveries[workspaceID] = asiri.RecoveryConfig{
		RecipientID:          identity.RecipientID,
		PublicKey:            identity.PublicKey,
		PublicKeyFingerprint: identity.Fingerprint,
		CreatedAt:            now,
		WrappedSecretCount:   wrappedCount,
		LastWrappedAt:        now,
	}
	return st.Save()
}

func (a App) addRecoveredDeviceWrappedKeys(st *store.FileStore, accessToken string, target remoteWorkspaceResponse, secrets []remoteSecretRecord, recoveryRecipientID string) (int, error) {
	device, err := st.ActiveDevice()
	if err != nil {
		return 0, err
	}
	updated := 0
	for _, secret := range secrets {
		if secret.Status != "active" {
			continue
		}
		if !remoteSecretHasRecoveryRecipient(secret, recoveryRecipientID) || remoteSecretHasRecipient(secret, target.CurrentDeviceID) {
			continue
		}
		if !localSecretVersionExists(st, secret.Scope, secret.Name, secret.Version) {
			continue
		}
		wrapped, err := st.RemoteWrappedKeyForSecretVersionPublicKey(target.ID, secret.Scope, secret.Name, secret.Version, target.CurrentDeviceID, device.EncryptionPublicKey)
		if err != nil {
			return updated, err
		}
		if err := addRecoveryRestoredWrappedKeys(st, st.State.ControlPlane.Origin, target.ID, secret.ID, accessToken, recoveryRecipientID, []store.RemoteWrappedKey{wrapped}); err != nil {
			return updated, err
		}
		updated += 1
	}
	return updated, nil
}

func (a App) prepareRemoteRecoveryReplacementKeys(st *store.FileStore, accessToken string, target remoteWorkspaceResponse, recovery asiri.RecoveryConfig) ([]recoveryRecipientReplacement, int, int, error) {
	if st.State.ControlPlane == nil {
		return nil, 0, 0, nil
	}
	encryptedSecrets, err := listRemoteSecrets(st, st.State.ControlPlane.Origin, target.ID, accessToken, "", false)
	if err != nil {
		return nil, 0, 0, err
	}
	metadataSecrets, status, err := listRemoteSecretMetadata(st, st.State.ControlPlane.Origin, target.ID, accessToken, false)
	if err != nil {
		return nil, 0, 0, err
	}
	secrets := metadataSecrets
	if status == http.StatusNotFound {
		secrets = encryptedSecrets
	}
	encryptedByVersion := make(map[string]remoteSecretRecord, len(encryptedSecrets))
	for _, secret := range encryptedSecrets {
		encryptedByVersion[pushVersionKey(secret.Scope, secret.Name, secret.Version)] = secret
	}
	replacements := make([]recoveryRecipientReplacement, 0, len(secrets))
	missingAccess := make([]remoteSecretRecord, 0)
	covered := 0
	remoteWrapped := 0
	for _, secret := range secrets {
		if secret.Status != "active" {
			continue
		}
		if remoteSecretHasRecoveryRecipient(secret, recovery.RecipientID) {
			covered += 1
			continue
		}
		var key store.RemoteWrappedKey
		encrypted, remoteAvailable := encryptedByVersion[pushVersionKey(secret.Scope, secret.Name, secret.Version)]
		if remoteAvailable {
			key, err = st.RecoveryWrappedKeyForRemoteVersion(target.CurrentDeviceID, encrypted.WrappedKeys, recovery)
			if err == nil && !localSecretVersionExists(st, secret.Scope, secret.Name, secret.Version) {
				remoteWrapped += 1
			}
		}
		if (!remoteAvailable || err != nil) && localSecretVersionExists(st, secret.Scope, secret.Name, secret.Version) {
			key, err = st.RecoveryWrappedKeyForSecretVersionWithConfig(target.Slug, secret.Scope, secret.Name, secret.Version, recovery)
		} else if !remoteAvailable {
			missingAccess = append(missingAccess, secret)
			continue
		}
		if err != nil {
			missingAccess = append(missingAccess, secret)
			continue
		}
		replacements = append(replacements, recoveryRecipientReplacement{SecretID: secret.ID, WrappedKey: key})
		covered += 1
	}
	if len(missingAccess) > 0 {
		return nil, 0, 0, fmt.Errorf(
			"recovery setup cannot cover %d active remote secret version(s) because this device cannot decrypt them (%s); run asiri rewrap --workspace %s from another trusted device that has the matching key material, then retry",
			len(missingAccess), recoverySecretVersionSummary(missingAccess), target.Slug,
		)
	}
	return replacements, covered, remoteWrapped, nil
}
