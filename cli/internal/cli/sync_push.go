package cli

import (
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/o-clan/asiri/cli/internal/asiri"
	"github.com/o-clan/asiri/cli/internal/store"
)

func (a App) push(st *store.FileStore, args []string) int {
	return a.pushWithMode(st, args, false)
}

func (a App) pushForSync(st *store.FileStore, args []string) int {
	return a.pushWithMode(st, args, true)
}

func (a App) pushWithMode(st *store.FileStore, args []string, reconcile bool) int {
	if err := st.RequireInitialized(); err != nil {
		return a.fail(err)
	}
	if st.State.ControlPlane == nil {
		return a.fail(errors.New("asiri is not linked to a control plane"))
	}
	if err := rejectServiceAccountControlPlaneMutation(st); err != nil {
		return a.fail(err)
	}
	pushOptions, err := parsePushArgs(args)
	if err != nil {
		return a.fail(err)
	}
	var accessToken string
	err = a.withProgress("Checking control-plane session", func() error {
		var accessErr error
		accessToken, accessErr = ensureControlPlaneAccess(st.State.ControlPlane.Origin, st)
		return accessErr
	})
	if err != nil {
		return a.fail(err)
	}
	stop := false
	workspaceMessage := ""
	preparePush := func() error {
		var prepareErr error
		pushOptions, accessToken, stop, workspaceMessage, prepareErr = a.prepareLocalWorkspacePush(st, pushOptions, accessToken)
		return prepareErr
	}
	if pushOptions.DryRun {
		err = preparePush()
	} else {
		err = a.withProgress("Preparing workspace", preparePush)
	}
	if err != nil {
		return a.fail(err)
	}
	if workspaceMessage != "" {
		fmt.Fprintln(a.Out, workspaceMessage)
	}
	if stop {
		return 0
	}
	var target remoteWorkspaceResponse
	err = a.withProgress("Resolving workspace", func() error {
		var targetErr error
		if reconcile {
			target, accessToken, targetErr = a.remoteWorkspaceTarget(st, accessToken, pushOptions.Workspace)
		} else {
			target, accessToken, targetErr = a.pushWorkspaceTarget(st, accessToken, pushOptions.Workspace)
		}
		return targetErr
	})
	if err != nil {
		return a.fail(err)
	}
	refs := st.ActiveSecretRefs()
	if len(refs) == 0 {
		fmt.Fprintln(a.Out, "No local active secrets to push")
		return 0
	}
	selectedRefs, err := selectPushRefs(st, refs, target, pushOptions)
	if err != nil {
		return a.fail(err)
	}
	if len(selectedRefs) == 0 {
		if reconcile {
			fmt.Fprintf(a.Out, "No local active secrets to publish for workspace %s\n", target.Slug)
			return 0
		}
		return a.fail(fmt.Errorf("no local active secrets under workspace %s; local prefixes are %s", target.Slug, strings.Join(localSecretWorkspacePrefixes(refs), ", ")))
	}
	if reconcile && target.CanWrite != nil && !*target.CanWrite {
		fmt.Fprintf(a.Out, "No writable local secret versions to publish for workspace %s\n", target.Slug)
		return 0
	}
	if binding, ok := st.RemoteBindingForPrefix(target.Slug); ok && binding.WorkspaceID != target.ID {
		return a.fail(fmt.Errorf("workspace prefix %s is bound to another control-plane workspace", target.Slug))
	}
	var plan remotePushPlanResponse
	err = a.withProgress(fmt.Sprintf("Planning encrypted push for %d secret(s)", len(selectedRefs)), func() error {
		var planErr error
		plan, planErr = remotePushPlan(st, st.State.ControlPlane.Origin, accessToken, target, selectedRefs)
		return planErr
	})
	if err != nil {
		return a.fail(err)
	}
	if reconcile {
		selectedRefs, err = writablePushRefs(selectedRefs, plan.Workspace.Paths)
		if err != nil {
			return a.fail(err)
		}
		if len(selectedRefs) == 0 {
			fmt.Fprintf(a.Out, "No writable local secret versions to publish for workspace %s\n", target.Slug)
			return 0
		}
	} else if !plan.Workspace.CanWrite {
		return a.fail(fmt.Errorf("workspace %s cannot write %s", target.Slug, fullPathList(plan.Workspace.Paths)))
	}
	if pushOptions.DryRun {
		if st.State.RemoteBindings == nil {
			st.State.RemoteBindings = map[string]asiri.RemoteWorkspaceBinding{}
		}
		st.State.RemoteBindings[target.Slug] = asiri.RemoteWorkspaceBinding{
			WorkspaceID:   target.ID,
			WorkspaceSlug: target.Slug,
			BoundAt:       time.Now().UTC(),
		}
	} else {
		if err := st.BindWorkspacePrefix(target.Slug, target.ID, target.Slug); err != nil {
			return a.fail(err)
		}
	}
	var recovery *asiri.RecoveryConfig
	if plan.Recovery != nil {
		if plan.Recovery.Status != "active" || plan.Recovery.RecipientID == "" || plan.Recovery.PublicKey == "" || plan.Recovery.PublicKeyFingerprint == "" {
			return a.fail(errors.New("control plane returned incomplete recovery recipient metadata"))
		}
		recovery = &asiri.RecoveryConfig{
			RecipientID:          plan.Recovery.RecipientID,
			PublicKey:            plan.Recovery.PublicKey,
			PublicKeyFingerprint: plan.Recovery.PublicKeyFingerprint,
			CreatedAt:            time.Now().UTC(),
		}
	}
	var versions []store.RemoteSecretVersion
	err = a.withProgress(fmt.Sprintf("Wrapping keys for %d secret(s)", len(selectedRefs)), func() error {
		var versionsErr error
		versions, versionsErr = st.RemoteSecretVersionsForRefsWithRecovery(target.ID, target.Slug, target.CurrentDeviceID, selectedRefs, recovery)
		if versionsErr != nil {
			return versionsErr
		}
		wrappingTargets := make(map[string][]remoteDeviceResponse, len(plan.Targets))
		seenWrappingTargets := make(map[string]bool, len(plan.Targets))
		for _, candidate := range plan.Targets {
			key := store.SecretKey(candidate.Scope, candidate.Name)
			if candidate.Scope == "" || candidate.Name == "" || seenWrappingTargets[key] {
				return errors.New("control plane returned invalid push wrapping targets")
			}
			seenWrappingTargets[key] = true
			wrappingTargets[key] = candidate.Devices
		}
		for i := range versions {
			devices, ok := wrappingTargets[store.SecretKey(versions[i].Scope, versions[i].Name)]
			if !ok {
				return fmt.Errorf("trusted device discovery failed; refusing to push without authorized wrapping targets for %s/%s", versions[i].Scope, versions[i].Name)
			}
			if err := addTrustedDeviceWrappedKeysToVersions(st, target.ID, versions[i:i+1], devices); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return a.fail(err)
	}
	remoteSecrets := mergeRemoteSecretRecords(plan.EncryptedSecrets, plan.Secrets)
	reconciled, err := reconcilePushVersionsWithTombstones(versions, remoteSecrets, plan.Tombstones, st.State.SecretTombstones, target.ID)
	if pushOptions.DryRun {
		printPushDryRun(a.Out, target.Slug, reconciled)
		if err != nil {
			return a.fail(err)
		}
		return 0
	}
	if err != nil {
		return a.fail(err)
	}
	if len(reconciled.Upload)+len(reconciled.Rewrap) > 0 {
		err := a.withProgress("Committing encrypted push", func() error {
			return commitRemotePushBatch(st, st.State.ControlPlane.Origin, target.ID, accessToken, reconciled.Upload, reconciled.Rewrap, reconciled.Recreate)
		})
		if err != nil {
			return a.fail(err)
		}
	}
	rewrappedKeys := 0
	for _, candidate := range reconciled.Rewrap {
		rewrappedKeys += len(candidate.Missing)
	}
	rewrappedSecrets := len(reconciled.Rewrap)
	if recovery != nil {
		if st.State.Recoveries == nil {
			st.State.Recoveries = map[string]asiri.RecoveryConfig{}
		}
		nextRecovery := *recovery
		if existing, ok := st.State.Recoveries[target.ID]; ok && existing.RecipientID == recovery.RecipientID {
			nextRecovery.WrappedSecretCount = existing.WrappedSecretCount
			nextRecovery.LastWrappedAt = existing.LastWrappedAt
		}
		if pushOptions.HasTargets() && nextRecovery.WrappedSecretCount < len(versions) {
			nextRecovery.WrappedSecretCount = len(versions)
			nextRecovery.LastWrappedAt = time.Now().UTC()
		}
		st.State.Recoveries[target.ID] = nextRecovery
		if !pushOptions.HasTargets() {
			if err := st.MarkRecoveryWrapped(target.ID, target.Slug, len(versions)); err != nil {
				return a.fail(err)
			}
		}
	} else if st.RecoveryForWorkspace(target.ID) != nil {
		delete(st.State.Recoveries, target.ID)
	}
	st.Audit(st.State.UserID, "control_plane_push", "allowed", "", "", "pushed encrypted local secret versions", map[string]string{"count": fmt.Sprintf("%d", len(reconciled.Upload)), "workspace": target.Slug, "skipped": fmt.Sprintf("%d", reconciled.SkippedExisting+reconciled.SkippedOlder), "rewrappedKeys": fmt.Sprintf("%d", rewrappedKeys)})
	if err := st.Save(); err != nil {
		return a.fail(err)
	}
	if len(reconciled.Upload) == 0 {
		fmt.Fprintf(a.Out, "No new local secret versions to push to workspace %s", target.Slug)
		if reconciled.SkippedExisting+reconciled.SkippedOlder > 0 {
			fmt.Fprintf(a.Out, " (%d skipped)", reconciled.SkippedExisting+reconciled.SkippedOlder)
		}
		fmt.Fprintln(a.Out)
	} else if len(selectedRefs) != len(refs) || pushOptions.HasTargets() {
		fmt.Fprintf(a.Out, "✓ Pushed %d encrypted secret version(s) to workspace %s; %d skipped\n", len(reconciled.Upload), target.Slug, reconciled.SkippedExisting+reconciled.SkippedOlder)
	} else {
		fmt.Fprintf(a.Out, "✓ Pushed %d encrypted secret version(s) to workspace %s; %d skipped\n", len(reconciled.Upload), target.Slug, reconciled.SkippedExisting+reconciled.SkippedOlder)
	}
	if rewrappedKeys > 0 {
		fmt.Fprintf(a.Out, "✓ Rewrapped %d trusted-device key(s) across %d existing secret version(s)\n", rewrappedKeys, rewrappedSecrets)
	}
	return 0
}

func writablePushRefs(refs []store.LocalSecretRef, paths []writePathOption) ([]store.LocalSecretRef, error) {
	options := make(map[string]bool, len(paths))
	for _, path := range paths {
		if path.Scope == "" || path.Name == "" {
			return nil, errors.New("control plane returned an invalid push path")
		}
		key := store.SecretKey(path.Scope, path.Name)
		if _, exists := options[key]; exists {
			return nil, errors.New("control plane returned duplicate push paths")
		}
		options[key] = path.CanWrite
	}
	writable := make([]store.LocalSecretRef, 0, len(refs))
	for _, ref := range refs {
		canWrite, ok := options[store.SecretKey(ref.Scope, ref.Name)]
		if !ok {
			return nil, fmt.Errorf("control plane omitted push permission for %s", store.SecretKey(ref.Scope, ref.Name))
		}
		if canWrite {
			writable = append(writable, ref)
		}
	}
	return writable, nil
}

func (a App) prepareLocalWorkspacePush(st *store.FileStore, options pushOptions, accessToken string) (pushOptions, string, bool, string, error) {
	workspace, ok := st.LocalWorkspace(options.Workspace)
	if !ok {
		return options, accessToken, false, "", nil
	}
	if workspace.RemoteWorkspaceID != "" {
		options.Workspace = workspace.CanonicalSlug
		return options, accessToken, false, "", nil
	}
	desiredAlias := workspace.Alias
	if desiredAlias == "" {
		desiredAlias = workspace.CanonicalSlug
	}
	if options.DryRun {
		fmt.Fprintf(a.Out, "Workspace %s would receive a canonical slug in the form %s-<8 characters>; alias %s would be retained.\n", workspace.CanonicalSlug, workspace.CanonicalSlug, desiredAlias)
		return options, accessToken, true, "", nil
	}
	if err := requireHumanMemberSession(st); err != nil {
		return options, accessToken, false, "", err
	}
	var remote remoteWorkspaceResponse
	endpoint := strings.TrimRight(st.State.ControlPlane.Origin, "/") + "/v1/workspaces/sync"
	body := map[string]string{"localWorkspaceId": workspace.ID, "localSlug": workspace.CanonicalSlug, "alias": desiredAlias}
	if err := postJSONBearer(st, endpoint, accessToken, body, &remote); err != nil {
		return options, accessToken, false, "", err
	}
	if remote.ID == "" || remote.Slug == "" {
		return options, accessToken, false, "", errors.New("control plane did not return the canonical workspace identity")
	}
	if remote.Alias != desiredAlias {
		return options, accessToken, false, "", errors.New("control plane returned a different workspace alias")
	}
	oldSlug := workspace.CanonicalSlug
	if err := st.RenameWorkspacePrefix(oldSlug, remote.Slug, remote.ID); err != nil {
		return options, accessToken, false, "", err
	}
	options.Workspace = remote.Slug
	message := fmt.Sprintf("✓ Workspace %s synced as %s; alias %s retained", oldSlug, remote.Slug, desiredAlias)
	return options, latestControlPlaneBearer(st, accessToken), false, message, nil
}

type pushOptions struct {
	Workspace string
	Scopes    []string
	Secrets   []string
	Version   int
	DryRun    bool
}

func (o pushOptions) HasTargets() bool {
	return len(o.Scopes) > 0 || len(o.Secrets) > 0 || o.Version > 0
}

func parsePushArgs(args []string) (pushOptions, error) {
	workspaceArg, remaining, err := splitWorkspaceFlag(args, "push", true)
	if err != nil {
		return pushOptions{}, err
	}
	options := pushOptions{Workspace: workspaceArg}
	for i := 0; i < len(remaining); i++ {
		arg := remaining[i]
		switch arg {
		case "--yes":
			// Backward-compatible no-op for older scripts.
		case "--dry-run":
			options.DryRun = true
		case "--scope":
			if i+1 >= len(remaining) || strings.HasPrefix(remaining[i+1], "-") {
				return pushOptions{}, errors.New("push --scope requires a scope")
			}
			options.Scopes = append(options.Scopes, remaining[i+1])
			i++
		case "--secret":
			if i+1 >= len(remaining) || strings.HasPrefix(remaining[i+1], "-") {
				return pushOptions{}, errors.New("push --secret requires scope/name")
			}
			options.Secrets = append(options.Secrets, remaining[i+1])
			i++
		case "--version":
			if i+1 >= len(remaining) || strings.HasPrefix(remaining[i+1], "-") {
				return pushOptions{}, errors.New("push --version requires a positive integer")
			}
			version, err := strconv.Atoi(remaining[i+1])
			if err != nil || version <= 0 {
				return pushOptions{}, errors.New("push --version requires a positive integer")
			}
			options.Version = version
			i++
		default:
			if strings.HasPrefix(arg, "-") {
				return pushOptions{}, fmt.Errorf("unknown option %q", arg)
			}
			return pushOptions{}, fmt.Errorf("unexpected push argument %q; use --scope or --secret", arg)
		}
	}
	if options.Version > 0 && (len(options.Secrets) != 1 || len(options.Scopes) != 0) {
		return pushOptions{}, errors.New("push --version requires exactly one --secret and no --scope")
	}
	return options, nil
}

func selectPushRefs(st *store.FileStore, refs []store.LocalSecretRef, target remoteWorkspaceResponse, options pushOptions) ([]store.LocalSecretRef, error) {
	if !options.HasTargets() {
		selected := make([]store.LocalSecretRef, 0, len(refs))
		for _, ref := range refs {
			if store.WorkspacePrefix(ref.Scope) == target.Slug {
				selected = append(selected, ref)
			}
		}
		return selected, nil
	}
	pathTarget := workspacePathTarget{Slug: target.Slug, KnownSlugs: knownWorkspaceSlugs(st)}
	selected := map[string]store.LocalSecretRef{}
	addRef := func(ref store.LocalSecretRef) {
		key := store.SecretKey(ref.Scope, ref.Name)
		selected[key] = ref
	}
	for _, shortScope := range options.Scopes {
		scope, err := workspacePrefixedScope(pathTarget, shortScope, "push")
		if err != nil {
			return nil, err
		}
		for _, ref := range refs {
			if ref.Scope == scope {
				addRef(ref)
			}
		}
	}
	for _, shortSecret := range options.Secrets {
		fullPath, err := workspacePrefixedPath(pathTarget, shortSecret, "push")
		if err != nil {
			return nil, err
		}
		scope, name, err := store.ParseSecretPath(fullPath)
		if err != nil {
			return nil, err
		}
		secret, ok := st.State.Secrets[store.SecretKey(scope, name)]
		if !ok {
			return nil, fmt.Errorf("local secret %s not found", fullPath)
		}
		version := secret.ActiveVersion
		if options.Version > 0 {
			version = options.Version
		}
		addRef(store.LocalSecretRef{Scope: scope, Name: name, Version: version})
	}
	selectedRefs := make([]store.LocalSecretRef, 0, len(selected))
	for _, ref := range selected {
		selectedRefs = append(selectedRefs, ref)
	}
	sort.Slice(selectedRefs, func(i, j int) bool {
		left := store.SecretKey(selectedRefs[i].Scope, selectedRefs[i].Name)
		right := store.SecretKey(selectedRefs[j].Scope, selectedRefs[j].Name)
		if left == right {
			return selectedRefs[i].Version < selectedRefs[j].Version
		}
		return left < right
	})
	if len(selectedRefs) == 0 {
		return nil, errors.New("no local active secrets matched push target")
	}
	return selectedRefs, nil
}

type pushReconcileResult struct {
	Upload          []store.RemoteSecretVersion
	Rewrap          []pushRewrapCandidate
	Recreate        []remotePushBatchRecreate
	SkippedExisting int
	SkippedOlder    int
	Conflicts       []string
}

type pushRewrapCandidate struct {
	SecretID string
	Missing  []store.RemoteWrappedKey
}

func reconcilePushVersions(local []store.RemoteSecretVersion, remote []remoteSecretRecord) (pushReconcileResult, error) {
	return reconcilePushVersionsWithTombstones(local, remote, nil, nil, "")
}

func reconcilePushVersionsWithTombstones(local []store.RemoteSecretVersion, remote []remoteSecretRecord, tombstones []asiri.SecretTombstone, localTombstones map[string]asiri.SecretTombstone, workspaceID string) (pushReconcileResult, error) {
	result := pushReconcileResult{Upload: []store.RemoteSecretVersion{}}
	byVersion := map[string]remoteSecretRecord{}
	maxVersion := map[string]int{}
	for _, item := range remote {
		key := store.SecretKey(item.Scope, item.Name)
		if item.Version > maxVersion[key] {
			maxVersion[key] = item.Version
		}
		byVersion[pushVersionKey(item.Scope, item.Name, item.Version)] = item
	}
	tombstoneByKey := map[string]asiri.SecretTombstone{}
	for _, tombstone := range tombstones {
		tombstoneByKey[store.SecretKey(tombstone.Scope, tombstone.Name)] = tombstone
	}
	conflicts := []string{}
	tombstoneConflicts := []string{}
	for _, item := range local {
		key := store.SecretKey(item.Scope, item.Name)
		if tombstone, ok := tombstoneByKey[key]; ok {
			if item.Version <= tombstone.DeletedThroughVersion {
				tombstoneConflicts = append(tombstoneConflicts, fmt.Sprintf("%s v%d (deleted through v%d)", key, item.Version, tombstone.DeletedThroughVersion))
				continue
			}
			if maxVersion[key] <= tombstone.DeletedThroughVersion {
				localTombstone, locallyReconciled := localTombstones[store.SecretTombstoneKey(workspaceID, item.Scope, item.Name)]
				switch {
				case item.Version > tombstone.DeletedThroughVersion && locallyReconciled && localTombstone.DeletedThroughVersion == tombstone.DeletedThroughVersion && !localTombstone.ReconciledAt.IsZero() && item.CreatedAt.After(localTombstone.ReconciledAt):
					result.Recreate = append(result.Recreate, remotePushBatchRecreate{OrgID: workspaceID, Scope: item.Scope, Name: item.Name, DeletedThroughVersion: tombstone.DeletedThroughVersion})
				default:
					tombstoneConflicts = append(tombstoneConflicts, fmt.Sprintf("%s v%d (requires a new version created after deletion-ledger reconciliation)", key, item.Version))
					continue
				}
			}
		}
		if existing, ok := byVersion[pushVersionKey(item.Scope, item.Name, item.Version)]; ok {
			if existing.Status == "active" && remoteSecretEnvelopeComparable(existing) && remoteSecretEnvelopeMatches(item, existing) {
				missing := missingRemoteWrappedKeysForRecord(item.WrappedKeys, existing)
				if len(missing) == 0 {
					result.SkippedExisting++
					continue
				}
				if allDeviceWrappedKeys(missing) {
					result.Rewrap = append(result.Rewrap, pushRewrapCandidate{SecretID: existing.ID, Missing: missing})
					result.SkippedExisting++
					continue
				}
			}
			conflicts = append(conflicts, fmt.Sprintf("%s v%d", key, item.Version))
			continue
		}
		if maxVersion[key] > item.Version {
			result.SkippedOlder++
			continue
		}
		result.Upload = append(result.Upload, item)
	}
	sort.Strings(conflicts)
	result.Conflicts = conflicts
	if len(tombstoneConflicts) > 0 {
		sort.Strings(tombstoneConflicts)
		return result, fmt.Errorf("control-plane deletion ledger blocks %s; run `asiri sync --workspace %s`, then add or rotate each blocked secret to a new local version before publishing again", strings.Join(tombstoneConflicts, ", "), store.WorkspacePrefix(local[0].Scope))
	}
	if len(conflicts) > 0 {
		return result, fmt.Errorf("remote secret version conflict for %s; pull first or rotate locally to a newer version", strings.Join(conflicts, ", "))
	}
	return result, nil
}

func addTrustedDeviceWrappedKeysToVersions(st *store.FileStore, workspaceID string, versions []store.RemoteSecretVersion, devices []remoteDeviceResponse) error {
	targets := make([]remoteDeviceResponse, 0)
	for _, device := range devices {
		if device.Status == "trusted" && device.ID != "" && device.EncryptionPublicKey != "" {
			targets = append(targets, device)
		}
	}
	sort.Slice(targets, func(i, j int) bool {
		return targets[i].ID < targets[j].ID
	})
	for i := range versions {
		for _, device := range targets {
			if remoteVersionHasRecipient(versions[i], device.ID) {
				continue
			}
			wrapped, err := st.RemoteWrappedKeyForSecretVersionPublicKey(workspaceID, versions[i].Scope, versions[i].Name, versions[i].Version, device.ID, device.EncryptionPublicKey)
			if err != nil {
				return err
			}
			versions[i].WrappedKeys = append(versions[i].WrappedKeys, wrapped)
		}
	}
	return nil
}

func remoteVersionHasRecipient(version store.RemoteSecretVersion, deviceID string) bool {
	for _, key := range version.WrappedKeys {
		if key.RecipientType == "device" && key.RecipientID == deviceID {
			return true
		}
	}
	return false
}

func pushVersionKey(scope, name string, version int) string {
	return store.SecretKey(scope, name) + "\x00" + strconv.Itoa(version)
}

func listOutputRowKey(scope, name string, version int, includeInactive bool) string {
	if includeInactive {
		return pushVersionKey(scope, name, version)
	}
	return store.SecretKey(scope, name)
}

func remoteSecretEnvelopeMatches(local store.RemoteSecretVersion, remote remoteSecretRecord) bool {
	return local.Algorithm == remote.Algorithm &&
		local.Nonce == remote.Nonce &&
		local.Ciphertext == remote.Ciphertext &&
		local.AAD == remote.AAD
}

func remoteSecretEnvelopeComparable(remote remoteSecretRecord) bool {
	return remote.Algorithm != "" && remote.Nonce != "" && remote.Ciphertext != "" && remote.AAD != ""
}

func remoteSecretWrappedKeysMatch(local []store.RemoteWrappedKey, remote []store.RemoteWrappedKey) bool {
	return len(missingRemoteWrappedKeys(local, remote)) == 0
}

func missingRemoteWrappedKeys(local []store.RemoteWrappedKey, remote []store.RemoteWrappedKey) []store.RemoteWrappedKey {
	remoteKeys := map[string]bool{}
	for _, key := range remote {
		remoteKeys[remoteWrappedKeyIdentity(key)] = true
	}
	missing := []store.RemoteWrappedKey{}
	for _, key := range local {
		if !remoteKeys[remoteWrappedKeyIdentity(key)] {
			missing = append(missing, key)
		}
	}
	return missing
}

func missingRemoteWrappedKeysForRecord(local []store.RemoteWrappedKey, remote remoteSecretRecord) []store.RemoteWrappedKey {
	remoteKeys := map[string]bool{}
	for _, key := range remote.WrappedKeys {
		remoteKeys[remoteWrappedKeyIdentity(key)] = true
	}
	for _, key := range remote.WrappedRecipients {
		remoteKeys[key.RecipientType+"\x00"+key.RecipientID+"\x00"+key.WrapAlgorithm] = true
	}
	missing := []store.RemoteWrappedKey{}
	for _, key := range local {
		if !remoteKeys[remoteWrappedKeyIdentity(key)] {
			missing = append(missing, key)
		}
	}
	return missing
}

func allDeviceWrappedKeys(keys []store.RemoteWrappedKey) bool {
	for _, key := range keys {
		if key.RecipientType != "device" {
			return false
		}
	}
	return true
}

func remoteWrappedKeyIdentity(key store.RemoteWrappedKey) string {
	return key.RecipientType + "\x00" + key.RecipientID + "\x00" + key.WrapAlgorithm
}

func printPushDryRun(out io.Writer, workspace string, result pushReconcileResult) {
	fmt.Fprintf(out, "Would push %d encrypted secret version(s) to workspace %s", len(result.Upload), workspace)
	skipped := result.SkippedExisting + result.SkippedOlder
	if skipped > 0 {
		fmt.Fprintf(out, "; %d would be skipped", skipped)
	}
	fmt.Fprintln(out)
	rewrappedKeys := 0
	for _, candidate := range result.Rewrap {
		rewrappedKeys += len(candidate.Missing)
	}
	if rewrappedKeys > 0 {
		fmt.Fprintf(out, "Would rewrap %d trusted-device key(s) across %d existing secret version(s)\n", rewrappedKeys, len(result.Rewrap))
	}
	if len(result.Conflicts) > 0 {
		fmt.Fprintf(out, "Conflicts (pull first or rotate locally to a newer version):\n")
		for _, c := range result.Conflicts {
			fmt.Fprintf(out, "  %s\n", c)
		}
	}
}
