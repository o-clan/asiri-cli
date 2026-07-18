package cli

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/o-clan/asiri/cli/internal/asiri"
	"github.com/o-clan/asiri/cli/internal/keystore"
	"github.com/o-clan/asiri/cli/internal/store"
)

func (a App) initLocal(st *store.FileStore, args []string) int {
	deviceName, deviceKind, err := parseInitArgs(args)
	if err != nil {
		return a.fail(err)
	}
	if deviceName == "" {
		hostname, hostErr := os.Hostname()
		if hostErr != nil || hostname == "" {
			deviceName = "local-device"
		} else {
			deviceName = hostname
		}
	}
	usedFileKeyStore := false
	if err := st.InitializeLocal(); err != nil {
		if errors.Is(err, keystore.ErrPlatformUnavailable) && keystore.FileKeyStoreDir() == "" {
			st.State = asiri.State{}
			st.UseDefaultFileKeyStore()
			usedFileKeyStore = true
			if err := st.InitializeLocal(); err != nil {
				return a.fail(err)
			}
		} else {
			return a.fail(err)
		}
	}
	device, refs, err := createDevice(deviceName, deviceKind)
	if errors.Is(err, keystore.ErrPlatformUnavailable) && keystore.FileKeyStoreDir() == "" {
		st.UseDefaultFileKeyStore()
		device, refs, err = createDevice(deviceName, deviceKind)
		usedFileKeyStore = err == nil
	}
	if err != nil {
		_ = st.DeletePlatformKeys()
		_ = os.Remove(st.Path)
		return a.fail(err)
	}
	st.State.Devices = append(st.State.Devices, device)
	st.State.LocalDeviceID = device.ID
	for _, ref := range refs {
		st.AddKeyRef(ref.Purpose, ref.Account)
	}
	st.Audit(st.State.UserID, "device_enrolled", "allowed", "", "", "local device trusted", map[string]string{"device": deviceName})
	if err := st.Save(); err != nil {
		_ = st.DeletePlatformKeys()
		_ = os.Remove(st.Path)
		return a.fail(err)
	}
	fmt.Fprintf(a.Out, "✓ Initialized local Asiri vault with trusted device %s\n", deviceName)
	if usedFileKeyStore {
		fmt.Fprintf(a.Out, "  Platform keyring unavailable; using local file key store at %s\n", keystore.FileKeyStoreDir())
	}
	return 0
}

func parseInitArgs(args []string) (string, string, error) {
	deviceName := ""
	deviceKind := ""
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--device":
			if i+1 >= len(args) || strings.HasPrefix(args[i+1], "--") {
				return "", "", errors.New("--device requires a value")
			}
			deviceName = args[i+1]
			i++
		case "--kind":
			if i+1 >= len(args) || strings.HasPrefix(args[i+1], "--") {
				return "", "", errors.New("--kind requires a value")
			}
			deviceKind = args[i+1]
			i++
		case "--workspace":
			return "", "", errors.New("asiri init no longer accepts --workspace; local vaults do not have workspace slugs")
		default:
			return "", "", fmt.Errorf("unknown init argument %q", args[i])
		}
	}
	if deviceKind == "" {
		deviceKind = detectedDeviceKind(runtime.GOOS, os.Getenv, runningInContainer())
	}
	if err := validateDeviceKind(deviceKind); err != nil {
		return "", "", err
	}
	return deviceName, deviceKind, nil
}

func (a App) login(st *store.FileStore, args []string) int {
	if err := st.RequireInitialized(); err != nil {
		return a.fail(err)
	}
	if err := validateLoginArgs(args); err != nil {
		return a.fail(err)
	}
	force := hasFlag(args, "--force")
	origin := loginOrigin(args, st)
	if err := validateControlPlaneOrigin(origin); err != nil {
		return a.fail(err)
	}
	if st.State.ControlPlane != nil && !force && st.State.ControlPlane.Source == "service-account" {
		return a.fail(errors.New("service account session active; run asiri logout first, or asiri login --force to replace it"))
	}
	if st.State.ControlPlane != nil && !force && origin != st.State.ControlPlane.Origin {
		return a.fail(errors.New("an existing control-plane session is linked to a different origin; use asiri login --force to replace it safely"))
	}
	if st.State.ControlPlane != nil && force {
		refreshToken, err := st.ControlPlaneRefreshToken()
		if err != nil {
			return a.fail(fmt.Errorf("cannot replace the existing control-plane session safely: %w", err))
		}
		if err := logoutDeviceSession(st, st.State.ControlPlane.Origin, refreshToken); err != nil {
			return a.fail(fmt.Errorf("cannot replace the existing control-plane session safely: %w", err))
		}
	}
	if st.State.ControlPlane != nil && !force {
		result, status, err := refreshDeviceSession(origin, st)
		if err == nil && status == http.StatusOK {
			if err := st.RefreshControlPlane(result.AccessToken, result.ExpiresIn, result.RefreshExpiresAt); err != nil {
				return a.fail(err)
			}
			fmt.Fprintln(a.Out, "✓ Control-plane account session refreshed")
			return 0
		}
		if err == nil && remoteDeviceRevoked(status, result.Error, result.Message) {
			return a.fail(revokedDeviceRecoveryError(st, ""))
		}
		if err == nil && remoteDeviceNotTrusted(status, result.Error, result.Message) {
			return a.fail(untrustedSessionRecoveryError(st))
		}
		if err != nil || status != http.StatusUnauthorized {
			if err != nil {
				return a.fail(err)
			}
			return a.fail(fmt.Errorf("control plane returned HTTP %d", status))
		}
	}
	device, err := st.ActiveDevice()
	if err != nil {
		return a.fail(err)
	}
	start, err := startDeviceCodeLogin(origin, "", *device)
	if err != nil {
		return a.fail(err)
	}
	fmt.Fprintf(a.Out, "Open %s\n", start.VerificationURIComplete)
	fmt.Fprintf(a.Out, "Code: %s\n", start.UserCode)
	result, err := pollDeviceCodeLogin(st, origin, start)
	if err != nil {
		return a.fail(err)
	}
	if err := st.LinkControlPlaneForDevice(origin, result.OrgID, result.WorkspaceSlug, result.UserID, result.DeviceID, device.ID, result.AccessToken, result.RefreshToken, result.ExpiresIn, result.RefreshExpiresAt); err != nil {
		return a.fail(err)
	}
	fmt.Fprintln(a.Out, "✓ Linked local device to control-plane account")
	return 0
}

func validateLoginArgs(args []string) error {
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--force":
		case "--origin":
			if i+1 >= len(args) || strings.HasPrefix(args[i+1], "--") {
				return errors.New("--origin requires a URL")
			}
			i++
		case "--workspace", "-w":
			return errors.New("login does not accept --workspace; select a workspace on each scoped command")
		default:
			return fmt.Errorf("unknown login argument %q", args[i])
		}
	}
	return nil
}

func loginOrigin(args []string, st *store.FileStore) string {
	if origin := strings.TrimRight(flagValue(args, "--origin", ""), "/"); origin != "" {
		return origin
	}
	if origin := strings.TrimRight(os.Getenv("ASIRI_CONTROL_PLANE_ORIGIN"), "/"); origin != "" {
		return origin
	}
	if st.State.ControlPlane != nil && !hasFlag(args, "--force") {
		return st.State.ControlPlane.Origin
	}
	return defaultControlPlaneOrigin
}

func (a App) logout(st *store.FileStore, args []string) int {
	if err := st.RequireInitialized(); err != nil {
		return a.fail(err)
	}
	if st.State.ControlPlane == nil {
		fmt.Fprintln(a.Out, "✓ Already logged out")
		return 0
	}
	refreshToken, err := st.ControlPlaneRefreshToken()
	if err == nil {
		_ = logoutDeviceSession(st, st.State.ControlPlane.Origin, refreshToken)
	}
	if err := st.ClearControlPlane(); err != nil {
		return a.fail(err)
	}
	fmt.Fprintln(a.Out, "✓ Logged out")
	return 0
}

func (a App) whoami(st *store.FileStore, args []string) int {
	if err := rejectUnknownArgs(args); err != nil {
		return a.fail(err)
	}
	if err := st.RequireInitialized(); err != nil {
		return a.fail(err)
	}
	if st.State.ControlPlane == nil {
		return a.fail(errors.New("asiri is not linked to a control plane"))
	}
	accessToken, err := ensureControlPlaneAccess(st.State.ControlPlane.Origin, st)
	if err != nil {
		return a.fail(err)
	}
	var result remoteWhoamiResponse
	endpoint := strings.TrimRight(st.State.ControlPlane.Origin, "/") + "/v1/whoami"
	if err := getJSONBearer(st, endpoint, accessToken, &result); err != nil {
		return a.fail(err)
	}
	localDeviceName := "-"
	if device, err := st.ActiveDevice(); err == nil && device.Name != "" {
		localDeviceName = device.Name
	}
	remoteDeviceID := firstNonEmpty(result.Device.ID, result.Session.DeviceID, st.State.ControlPlane.DeviceID)
	tw := tabwriter.NewWriter(a.Out, 0, 0, 2, ' ', 0)
	fmt.Fprintf(tw, "USER ID\t%s\n", printable(firstNonEmpty(result.User.ID, st.State.ControlPlane.UserID)))
	fmt.Fprintf(tw, "EMAIL\t%s\n", printable(result.User.Email))
	fmt.Fprintf(tw, "NAME\t%s\n", printable(result.User.DisplayName))
	fmt.Fprintf(tw, "ROLE\t%s\n", printable(result.User.Role))
	fmt.Fprintf(tw, "STATUS\t%s\n", printable(result.User.Status))
	if result.Session.ServiceAccountSlug != "" || st.State.ControlPlane.ServiceAccountSlug != "" {
		fmt.Fprintf(tw, "IDENTITY\tservice account\n")
		fmt.Fprintf(tw, "WORKSPACE\t%s\n", printable(firstNonEmpty(result.Workspace.Slug, st.State.ControlPlane.WorkspaceSlug)))
		fmt.Fprintf(tw, "SERVICE ACCOUNT\t%s\n", printable(firstNonEmpty(result.Session.ServiceAccountSlug, st.State.ControlPlane.ServiceAccountSlug)))
		if firstNonEmpty(result.Session.ServiceAccountName, st.State.ControlPlane.ServiceAccountName) != "" {
			fmt.Fprintf(tw, "SERVICE ACCOUNT NAME\t%s\n", printable(firstNonEmpty(result.Session.ServiceAccountName, st.State.ControlPlane.ServiceAccountName)))
		}
		if firstNonEmpty(result.Session.ApprovedByUserID, st.State.ControlPlane.ApprovedByUserID) != "" {
			fmt.Fprintf(tw, "APPROVED BY\t%s\n", printable(firstNonEmpty(result.Session.ApprovedByUserID, st.State.ControlPlane.ApprovedByUserID)))
		}
	}
	fmt.Fprintf(tw, "LOCAL DEVICE\t%s\n", printable(localDeviceName))
	fmt.Fprintf(tw, "AUTH DEVICE\t%s\n", printable(remoteDeviceID))
	fmt.Fprintf(tw, "ORIGIN\t%s\n", printable(st.State.ControlPlane.Origin))
	if err := tw.Flush(); err != nil {
		return a.fail(err)
	}
	return 0
}

func startDeviceCodeLogin(origin, workspaceSlug string, device asiri.Device) (deviceCodeStartResponse, error) {
	return startDeviceCodeLoginWithServiceAccount(origin, workspaceSlug, "", device)
}

func startServiceAccountDeviceCodeLogin(origin, workspaceSlug, serviceAccountSlug string, device asiri.Device) (deviceCodeStartResponse, error) {
	return startDeviceCodeLoginWithServiceAccount(origin, workspaceSlug, serviceAccountSlug, device)
}

func startDeviceCodeLoginWithServiceAccount(origin, workspaceSlug, serviceAccountSlug string, device asiri.Device) (deviceCodeStartResponse, error) {
	body := map[string]string{
		"deviceName":          device.Name,
		"kind":                string(device.Kind),
		"encryptionPublicKey": device.EncryptionPublicKey,
		"signingPublicKey":    device.SigningPublicKey,
	}
	if workspaceSlug != "" {
		body["workspaceSlug"] = workspaceSlug
	}
	if serviceAccountSlug != "" {
		body["serviceAccountSlug"] = serviceAccountSlug
	}
	var result deviceCodeStartResponse
	if err := postJSON(origin+"/v1/auth/device-code/start", body, &result); err != nil {
		return result, err
	}
	if result.DeviceCode == "" || result.UserCode == "" || result.VerificationURIComplete == "" {
		return result, errors.New("control plane returned an incomplete device-code response")
	}
	if err := validateDeviceCodeApprovalOrigin(origin, result.VerificationURIComplete); err != nil {
		return result, err
	}
	if result.Interval <= 0 {
		result.Interval = 2
	}
	return result, nil
}

func validateDeviceCodeApprovalOrigin(controlPlaneOrigin, approvalURL string) error {
	controlPlane, err := url.Parse(controlPlaneOrigin)
	if err != nil || controlPlane.Scheme == "" || controlPlane.Host == "" {
		return fmt.Errorf("invalid control-plane origin %q", controlPlaneOrigin)
	}
	approval, err := url.Parse(approvalURL)
	if err != nil || approval.Scheme == "" || approval.Host == "" {
		return fmt.Errorf("control plane returned invalid approval URL %q", approvalURL)
	}
	controlPlaneURLOrigin := urlOrigin(controlPlane)
	approvalURLOrigin := urlOrigin(approval)
	if approvalURLOrigin != controlPlaneURLOrigin {
		if isLoopbackHost(controlPlane.Hostname()) && isLoopbackHost(approval.Hostname()) {
			return nil
		}
		return fmt.Errorf("device-code approval URL origin %s does not match control-plane origin %s", approvalURLOrigin, controlPlaneURLOrigin)
	}
	return nil
}

func urlOrigin(parsed *url.URL) string {
	return parsed.Scheme + "://" + parsed.Host
}

func pollDeviceCodeLogin(st *store.FileStore, origin string, start deviceCodeStartResponse) (deviceCodeTokenResponse, error) {
	deadline := time.Now().Add(time.Duration(start.ExpiresIn) * time.Second)
	if start.ExpiresIn <= 0 {
		deadline = time.Now().Add(10 * time.Minute)
	}
	interval := time.Duration(start.Interval) * time.Second
	if interval <= 0 {
		interval = 250 * time.Millisecond
	}
	for {
		var result deviceCodeTokenResponse
		status, err := postJSONDeviceCodeClaimStatus(st, origin+"/v1/auth/device-code/token", map[string]string{"deviceCode": start.DeviceCode}, credentialHash(start.DeviceCode), &result)
		if err != nil {
			return result, err
		}
		if status == http.StatusOK && result.Status == "approved" {
			if result.OrgID == "" || result.WorkspaceSlug == "" || result.UserID == "" || result.DeviceID == "" || result.AccessToken == "" || result.RefreshToken == "" {
				return result, errors.New("control plane approved login without link metadata")
			}
			return result, nil
		}
		if result.Error != "" && result.Error != "authorization_pending" {
			return result, fmt.Errorf("device-code login failed: %s", result.Error)
		}
		if time.Now().After(deadline) {
			return result, errors.New("device-code login timed out")
		}
		time.Sleep(interval)
	}
}

func pollDeviceCodeTrust(st *store.FileStore, origin string, start deviceCodeStartResponse) (deviceCodeTokenResponse, error) {
	deadline := time.Now().Add(time.Duration(start.ExpiresIn) * time.Second)
	if start.ExpiresIn <= 0 {
		deadline = time.Now().Add(10 * time.Minute)
	}
	interval := time.Duration(start.Interval) * time.Second
	if interval <= 0 {
		interval = 250 * time.Millisecond
	}
	for {
		var result deviceCodeTokenResponse
		status, err := postJSONDeviceCodeClaimStatus(st, origin+"/v1/auth/device-code/token", map[string]any{"deviceCode": start.DeviceCode, "trustOnly": true}, credentialHash(start.DeviceCode), &result)
		if err != nil {
			return result, err
		}
		if status == http.StatusOK && result.Status == "approved" {
			hasAccessToken := result.AccessToken != ""
			hasRefreshToken := result.RefreshToken != ""
			if hasRefreshToken {
				if result.DeviceID == "" {
					return result, errors.New("control plane issued a device-trust session without a device id; session cleanup could not run")
				}
				cleanupErr := logoutDeviceSessionForDevice(st, origin, result.RefreshToken, result.DeviceID)
				result.AccessToken = ""
				result.RefreshToken = ""
				if cleanupErr != nil {
					return result, fmt.Errorf("device trust succeeded, but the temporary server session could not be revoked: %w", cleanupErr)
				}
				if !hasAccessToken {
					return result, errors.New("control plane returned incomplete device-trust session credentials")
				}
				if result.SessionIssued != nil && !*result.SessionIssued {
					return result, errors.New("control plane returned session credentials for a trust-only claim")
				}
			} else if hasAccessToken {
				return result, errors.New("control plane issued a device-trust access token without a refresh token; session cleanup could not run")
			} else if result.SessionIssued == nil || *result.SessionIssued {
				return result, errors.New("control plane did not confirm a trust-only device-code claim")
			}
			if result.OrgID == "" || result.WorkspaceSlug == "" || result.UserID == "" || result.DeviceID == "" {
				return result, errors.New("control plane approved device trust without link metadata")
			}
			return result, nil
		}
		if result.Error != "" && result.Error != "authorization_pending" {
			return result, fmt.Errorf("device-code trust failed: %s", result.Error)
		}
		if time.Now().After(deadline) {
			return result, errors.New("device-code trust timed out")
		}
		time.Sleep(interval)
	}
}

func refreshDeviceSession(origin string, st *store.FileStore) (sessionRefreshResponse, int, error) {
	var result sessionRefreshResponse
	refreshToken, err := st.ControlPlaneRefreshToken()
	if err != nil {
		return result, 0, err
	}
	status, err := postJSONDeviceSignedStatus(st, origin+"/v1/auth/session/refresh", map[string]string{"refreshToken": refreshToken}, credentialHash(refreshToken), &result)
	if err != nil {
		return result, status, err
	}
	if status == http.StatusOK {
		if result.Status != "approved" || result.AccessToken == "" || result.OrgID == "" || result.WorkspaceSlug == "" || result.UserID == "" || result.DeviceID == "" {
			return result, status, errors.New("control plane refreshed session without link metadata")
		}
	}
	return result, status, nil
}

func logoutDeviceSession(st *store.FileStore, origin, refreshToken string) error {
	if st.State.ControlPlane == nil || st.State.ControlPlane.DeviceID == "" {
		return errors.New("control plane device is not linked")
	}
	return logoutDeviceSessionForDevice(st, origin, refreshToken, st.State.ControlPlane.DeviceID)
}

func logoutDeviceSessionForDevice(st *store.FileStore, origin, refreshToken, remoteDeviceID string) error {
	var failure controlPlaneFailureResponse
	status, err := postJSONDeviceSignedForDeviceStatus(st, origin+"/v1/auth/session/logout", map[string]string{"refreshToken": refreshToken}, credentialHash(refreshToken), remoteDeviceID, &failure)
	if err != nil {
		return err
	}
	if status < http.StatusOK || status >= http.StatusMultipleChoices {
		if failure.Message != "" {
			return fmt.Errorf("control plane returned HTTP %d: %s", status, failure.Message)
		}
		if failure.Error != "" {
			return fmt.Errorf("control plane returned HTTP %d: %s", status, failure.Error)
		}
		return fmt.Errorf("control plane returned HTTP %d", status)
	}
	return nil
}
