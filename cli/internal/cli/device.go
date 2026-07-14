package cli

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/o-clan/asiri/cli/internal/asiri"
	"github.com/o-clan/asiri/cli/internal/keystore"
	"github.com/o-clan/asiri/cli/internal/store"
)

type deviceTrustOptions struct {
	Workspace string
	Origin    string
}

func parseDeviceTrustArgs(args []string) (deviceTrustOptions, error) {
	options := deviceTrustOptions{}
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--workspace":
			if options.Workspace != "" {
				return options, errors.New("device trust accepts one --workspace value")
			}
			if i+1 >= len(args) || strings.HasPrefix(args[i+1], "--") {
				return options, errors.New("--workspace requires a slug")
			}
			slug, err := localWorkspaceSlug(args[i+1])
			if err != nil {
				return options, err
			}
			options.Workspace = slug
			i++
		case "--all":
			return options, errors.New("device trust requires one --workspace <slug>; --all is not supported")
		case "--origin":
			if i+1 >= len(args) || strings.HasPrefix(args[i+1], "--") {
				return options, errors.New("--origin requires a URL")
			}
			options.Origin = strings.TrimRight(args[i+1], "/")
			i++
		default:
			return options, fmt.Errorf("unknown device trust argument %q", args[i])
		}
	}
	if options.Workspace == "" {
		return options, errors.New("device trust requires --workspace <slug>")
	}
	return options, nil
}

func deviceTrustOrigin(st *store.FileStore, explicit string) string {
	if explicit != "" {
		return explicit
	}
	if origin := strings.TrimRight(os.Getenv("ASIRI_CONTROL_PLANE_ORIGIN"), "/"); origin != "" {
		return origin
	}
	if st.State.ControlPlane != nil && st.State.ControlPlane.Origin != "" {
		return st.State.ControlPlane.Origin
	}
	return defaultControlPlaneOrigin
}

func (a App) deviceStatus(st *store.FileStore, args []string) int {
	if err := st.RequireInitialized(); err != nil {
		return a.fail(err)
	}
	if st.State.ControlPlane == nil {
		return a.fail(errors.New("asiri is not linked to a control plane"))
	}
	workspaceArg, remaining, err := splitWorkspaceFlag(args, "device status", true)
	if err != nil {
		return a.fail(err)
	}
	if err := rejectUnknownArgs(remaining); err != nil {
		return a.fail(err)
	}
	if err := requireServiceAccountWorkspace(st, workspaceArg); err != nil {
		return a.fail(err)
	}
	accessToken, err := ensureControlPlaneAccess(st.State.ControlPlane.Origin, st)
	if err != nil {
		return a.fail(err)
	}
	includeSecrets := st.State.ControlPlane.Source != "service-account"
	workspaceResult, err := listRemoteWorkspaceOverview(st, st.State.ControlPlane.Origin, accessToken, workspaceArg, includeSecrets, false)
	if err != nil {
		return a.fail(err)
	}
	target, err := requireRemoteWorkspace(workspaceResult.Organizations, workspaceArg)
	if err != nil {
		return a.fail(err)
	}
	remoteSecrets := workspaceResult.Secrets
	var secretsErr error
	secretsKnown := false
	if includeSecrets {
		secretsKnown = remoteSecrets != nil
		if !secretsKnown {
			secretsErr = errors.New("control plane did not return workspace secret metadata")
		}
	}
	keySummaries := workspaceKeySummaries(st, []remoteWorkspaceResponse{target}, remoteSecrets, secretsKnown)
	fmt.Fprintf(a.Out, "This device: %s\n", currentDeviceDescription(st))
	tw := tabwriter.NewWriter(a.Out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "WORKSPACE\tROLE\tTHIS DEVICE\tACCOUNT WRITE\tKEYS\tNEXT\tREMOTE DEVICE")
	keySummary := keySummaries[target.Slug]
	remoteDevice := target.CurrentDeviceID
	if remoteDevice == "" {
		remoteDevice = "-"
	}
	fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", target.Slug, workspaceRoleLabel(target, st.State.UserID), deviceTrustLabelForWorkspace(target), boolPointerLabel(target.CanWrite), keySummary.Keys, keySummary.Next, remoteDevice)
	if err := tw.Flush(); err != nil {
		return a.fail(err)
	}
	if secretsErr != nil {
		fmt.Fprintf(a.Err, "asiri: remote key coverage unavailable: %s\n", secretsErr)
	}
	return 0
}

func (a App) deviceTrust(st *store.FileStore, args []string) int {
	if err := st.RequireInitialized(); err != nil {
		return a.fail(err)
	}
	if err := rejectServiceAccountControlPlaneMutation(st); err != nil {
		return a.fail(err)
	}
	options, err := parseDeviceTrustArgs(args)
	if err != nil {
		return a.fail(err)
	}
	origin := deviceTrustOrigin(st, options.Origin)
	if err := validateControlPlaneOrigin(origin); err != nil {
		return a.fail(err)
	}
	device, err := st.ActiveDevice()
	if err != nil {
		return a.fail(err)
	}
	if st.State.ControlPlane == nil {
		return a.fail(errors.New("device trust requires an existing control-plane session"))
	}
	accessToken, err := ensureControlPlaneAccess(st.State.ControlPlane.Origin, st)
	if err != nil {
		return a.fail(err)
	}
	workspaceResult, err := listRemoteWorkspaceOverview(st, st.State.ControlPlane.Origin, accessToken, options.Workspace, false, false)
	if err != nil {
		return a.fail(err)
	}
	if target, ok := findWorkspace(workspaceResult.Organizations, options.Workspace); ok {
		if explicitWorkspaceDeviceStatus(target) == "revoked" {
			return a.fail(revokedDeviceRecoveryError(st, target.Slug))
		}
		if workspaceDeviceTrusted(target) {
			fmt.Fprintf(a.Out, "This device is already trusted for workspace %s\n", options.Workspace)
			return 0
		}
		if !workspaceCanApproveDevice(target) {
			return a.fail(fmt.Errorf("this account cannot approve devices for workspace %s", options.Workspace))
		}
	}
	if _, err := a.trustDeviceInWorkspace(st, origin, accessToken, options.Workspace, *device); err != nil {
		return a.fail(err)
	}
	return 0
}

func (a App) trustDeviceInWorkspace(st *store.FileStore, origin, accessToken, workspaceSlug string, device asiri.Device) (deviceCodeTokenResponse, error) {
	start, err := startDeviceCodeLogin(origin, workspaceSlug, device)
	if err != nil {
		return deviceCodeTokenResponse{}, err
	}
	fmt.Fprintf(a.Out, "\nTrust this device for workspace %s\n", workspaceSlug)
	fmt.Fprintf(a.Out, "Open %s\n", start.VerificationURIComplete)
	fmt.Fprintf(a.Out, "Code: %s\n", start.UserCode)
	result, err := pollDeviceCodeTrust(st, origin, start)
	if err != nil {
		return result, err
	}
	if st.State.ControlPlane == nil || result.UserID != st.State.ControlPlane.UserID {
		return result, errors.New("control plane approved device trust for a different account")
	}
	if result.WorkspaceSlug != workspaceSlug {
		return result, fmt.Errorf("control plane approved workspace %s, expected %s", result.WorkspaceSlug, workspaceSlug)
	}
	fmt.Fprintf(a.Out, "✓ This device is trusted for workspace %s\n", result.WorkspaceSlug)
	target := remoteWorkspaceResponse{ID: result.OrgID, Slug: result.WorkspaceSlug, CurrentDeviceTrusted: boolPtr(true), CanPull: boolPtr(true), CurrentDeviceID: result.DeviceID}
	stats, err := a.rewrapWorkspace(st, accessToken, target)
	if err != nil {
		fmt.Fprintf(a.Err, "asiri: trusted device, but automatic rewrap could not run: %s\n", err)
		return result, nil
	}
	if stats.Added > 0 {
		st.Audit(st.State.UserID, "control_plane_rewrap", "allowed", "", "", "automatically wrapped local data keys after device trust", map[string]string{"secrets": fmt.Sprintf("%d", stats.Updated), "wrappedKeys": fmt.Sprintf("%d", stats.Added), "workspace": result.WorkspaceSlug})
		if err := st.Save(); err != nil {
			return result, err
		}
		fmt.Fprintf(a.Out, "✓ Automatically rewrapped %d key(s) across %d secret version(s) in workspace %s\n", stats.Added, stats.Updated, result.WorkspaceSlug)
	} else if stats.SkippedMissingLocal > 0 {
		fmt.Fprintf(a.Out, "No local key material available to rewrap %d active remote secret version(s) in workspace %s\n", stats.SkippedMissingLocal, result.WorkspaceSlug)
	}
	return result, nil
}

func (a App) device(st *store.FileStore, args []string) int {
	if len(args) == 0 {
		return a.fail(errors.New("device subcommand required"))
	}
	switch args[0] {
	case "name":
		if err := rejectUnknownArgs(args[1:]); err != nil {
			return a.fail(err)
		}
		if err := st.RequireInitialized(); err != nil {
			return a.fail(err)
		}
		device, err := st.ActiveDevice()
		if err != nil {
			return a.fail(err)
		}
		if device.Name == "" {
			return a.fail(errors.New("local device has no name"))
		}
		fmt.Fprintln(a.Out, device.Name)
		return 0
	case "enroll":
		if err := st.RequireInitialized(); err != nil {
			return a.fail(err)
		}
		name := flagValue(args[1:], "--name", "")
		if name == "" {
			return a.fail(errors.New("--name is required"))
		}
		if st.State.ControlPlane != nil {
			return a.fail(errors.New("device enroll requires no linked control-plane session; run asiri logout first, then rerun asiri device enroll --name <new-name>. The local vault and secrets are preserved"))
		}
		if err := rejectServiceAccountLocalMutation(st); err != nil {
			return a.fail(err)
		}
		device, refs, err := createDevice(name)
		if err != nil {
			return a.fail(err)
		}
		st.State.Devices = append(st.State.Devices, device)
		st.State.LocalDeviceID = device.ID
		for _, ref := range refs {
			st.AddKeyRef(ref.Purpose, ref.Account)
		}
		st.Audit(st.State.UserID, "device_enrolled", "allowed", "", "", "local device trusted", map[string]string{"device": name})
		if err := st.Save(); err != nil {
			return a.fail(err)
		}
		fmt.Fprintf(a.Out, "✓ Device %s enrolled and trusted (%s)\n", name, device.ID)
		return 0
	case "status":
		return a.deviceStatus(st, args[1:])
	case "trust":
		return a.deviceTrust(st, args[1:])
	case "list":
		if err := st.RequireInitialized(); err != nil {
			return a.fail(err)
		}
		workspaceArg, remaining, err := splitWorkspaceFlag(args[1:], "device list", false)
		if err != nil {
			return a.fail(err)
		}
		if err := rejectUnknownArgs(remaining, "--local", "--remote", "--include-revoked"); err != nil {
			return a.fail(err)
		}
		local := hasFlag(remaining, "--local")
		remote := hasFlag(remaining, "--remote")
		includeRevoked := hasFlag(remaining, "--include-revoked")
		if local && remote {
			return a.fail(errors.New("use either --local or --remote, not both"))
		}
		if !local && !remote {
			return a.fail(errors.New("device list requires --local or --remote"))
		}
		if local && workspaceArg != "" {
			return a.fail(errors.New("device list --local does not accept --workspace"))
		}
		if remote {
			if st.State.ControlPlane == nil {
				return a.fail(errors.New("asiri is not linked to a control plane"))
			}
			if workspaceArg == "" {
				return a.fail(errors.New("device list --remote requires --workspace <slug>"))
			}
			accessToken, err := ensureControlPlaneAccess(st.State.ControlPlane.Origin, st)
			if err != nil {
				return a.fail(err)
			}
			target, accessToken, err := a.remoteWorkspaceTarget(st, accessToken, workspaceArg)
			if err != nil {
				return a.fail(err)
			}
			type deviceListRow struct {
				Workspace string
				ID        string
				Name      string
				Kind      string
				Status    string
				Note      string
			}
			rows := []deviceListRow{}
			devices, err := listRemoteDevices(st, st.State.ControlPlane.Origin, target.ID, accessToken, includeRevoked)
			if err != nil {
				return a.fail(err)
			}
			for _, device := range devices {
				if !includeRevoked && device.Status == "revoked" {
					continue
				}
				rows = append(rows, deviceListRow{Workspace: target.Slug, ID: device.ID, Name: device.Name, Kind: device.Kind, Status: device.Status})
			}
			tw := tabwriter.NewWriter(a.Out, 0, 0, 2, ' ', 0)
			fmt.Fprintln(tw, "WORKSPACE\tID\tNAME\tKIND\tSTATUS\tNOTE")
			for _, row := range rows {
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", row.Workspace, row.ID, row.Name, row.Kind, row.Status, row.Note)
			}
			if err := tw.Flush(); err != nil {
				return a.fail(err)
			}
			return 0
		}
		if len(st.State.Devices) == 0 {
			fmt.Fprintln(a.Out, "No devices enrolled")
			return 0
		}
		for _, device := range st.State.Devices {
			if !includeRevoked && device.Status == asiri.DeviceRevoked {
				continue
			}
			fmt.Fprintf(a.Out, "%s\t%s\t%s\t%s\n", device.ID, device.Name, device.Kind, device.Status)
		}
		return 0
	case "revoke":
		remote := hasFlag(args[1:], "--remote")
		revokeArgs := args[1:]
		if remote {
			workspaceArg, remaining, err := splitWorkspaceFlag(revokeArgs, "device revoke", true)
			if err != nil {
				return a.fail(err)
			}
			if err := rejectUnknownArgs(remaining, "--remote"); err != nil {
				return a.fail(err)
			}
			deviceRef := firstPositional(remaining)
			if deviceRef == "" {
				return a.fail(errors.New("device revoke requires a device name or id"))
			}
			if err := st.RequireInitialized(); err != nil {
				return a.fail(err)
			}
			if st.State.ControlPlane == nil {
				return a.fail(errors.New("asiri is not linked to a control plane"))
			}
			if err := rejectServiceAccountControlPlaneMutation(st); err != nil {
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
			devices, err := listRemoteDevices(st, st.State.ControlPlane.Origin, target.ID, accessToken, false)
			if err != nil {
				return a.fail(err)
			}
			selected, err := requireRemoteDeviceInWorkspace(devices, deviceRef, target.Slug)
			if err != nil {
				return a.fail(err)
			}
			device, err := revokeRemoteDevice(st, st.State.ControlPlane.Origin, target.ID, selected.ID, accessToken)
			if err != nil {
				return a.fail(err)
			}
			label := device.Name
			if label == "" {
				label = device.ID
			}
			fmt.Fprintf(a.Out, "✓ Remote device %s revoked in workspace %s; rotate affected secrets after suspected compromise\n", label, target.Slug)
			return 0
		}
		if workspaceArg, _, err := splitWorkspaceFlag(revokeArgs, "device revoke", false); err != nil {
			return a.fail(err)
		} else if workspaceArg != "" {
			return a.fail(errors.New("device revoke --workspace requires --remote"))
		}
		if err := rejectUnknownArgs(revokeArgs); err != nil {
			return a.fail(err)
		}
		if err := rejectServiceAccountLocalMutation(st); err != nil {
			return a.fail(err)
		}
		deviceRef := firstPositional(revokeArgs)
		if deviceRef == "" {
			return a.fail(errors.New("device revoke requires a device name or id"))
		}
		if err := st.RevokeDevice(deviceRef); err != nil {
			return a.fail(err)
		}
		fmt.Fprintf(a.Out, "✓ Device %s revoked; rotate affected secrets after suspected compromise\n", deviceRef)
		return 0
	default:
		return a.fail(fmt.Errorf("unknown device command %q", args[0]))
	}
}

func createDevice(name string) (asiri.Device, []asiri.KeyRef, error) {
	deviceID := store.NewID("dev")
	encryptionPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return asiri.Device{}, nil, err
	}
	signingPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return asiri.Device{}, nil, err
	}
	encryptionPrivateBytes, err := x509.MarshalECPrivateKey(encryptionPrivateKey)
	if err != nil {
		return asiri.Device{}, nil, err
	}
	signingPrivateBytes, err := x509.MarshalECPrivateKey(signingPrivateKey)
	if err != nil {
		return asiri.Device{}, nil, err
	}
	encryptionPublicBytes, err := x509.MarshalPKIXPublicKey(&encryptionPrivateKey.PublicKey)
	if err != nil {
		return asiri.Device{}, nil, err
	}
	signingPublicBytes, err := x509.MarshalPKIXPublicKey(&signingPrivateKey.PublicKey)
	if err != nil {
		return asiri.Device{}, nil, err
	}
	encryptionAccount := keystore.DeviceKeyAccount(deviceID, "encryption-private")
	signingAccount := keystore.DeviceKeyAccount(deviceID, "signing-private")
	if err := keystore.Store(encryptionAccount, base64.StdEncoding.EncodeToString(encryptionPrivateBytes)); err != nil {
		return asiri.Device{}, nil, err
	}
	if err := keystore.Store(signingAccount, base64.StdEncoding.EncodeToString(signingPrivateBytes)); err != nil {
		_ = keystore.Delete(encryptionAccount)
		return asiri.Device{}, nil, err
	}
	return asiri.Device{
			ID:                  deviceID,
			Name:                name,
			Kind:                "laptop",
			Status:              asiri.DeviceTrusted,
			EncryptionPublicKey: base64.StdEncoding.EncodeToString(encryptionPublicBytes),
			SigningPublicKey:    base64.StdEncoding.EncodeToString(signingPublicBytes),
			CreatedAt:           time.Now().UTC(),
		}, []asiri.KeyRef{
			{Purpose: "device-encryption-private-key", Account: encryptionAccount},
			{Purpose: "device-signing-private-key", Account: signingAccount},
		}, nil
}
