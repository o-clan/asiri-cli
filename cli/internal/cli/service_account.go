package cli

import (
	"errors"
	"fmt"
	"strings"
	"text/tabwriter"

	"github.com/o-clan/asiri/cli/internal/store"
)

func (a App) serviceAccount(st *store.FileStore, args []string) int {
	if len(args) == 0 {
		return a.fail(errors.New("service-account subcommand required"))
	}
	switch args[0] {
	case "create":
		return a.serviceAccountCreate(st, args[1:])
	case "list":
		return a.serviceAccountList(st, args[1:])
	case "disable":
		return a.serviceAccountDisable(st, args[1:])
	case "grant":
		return a.serviceAccountGrant(st, args[1:])
	case "login":
		return a.serviceAccountLogin(st, args[1:])
	default:
		return a.fail(fmt.Errorf("unknown service-account command %q", args[0]))
	}
}

type serviceAccountCreateOptions struct {
	Workspace string
	Slug      string
	Name      string
}

func parseServiceAccountCreateArgs(args []string) (serviceAccountCreateOptions, error) {
	var options serviceAccountCreateOptions
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--workspace":
			if options.Workspace != "" {
				return options, errors.New("service-account create accepts one --workspace value")
			}
			if i+1 >= len(args) || strings.HasPrefix(args[i+1], "--") {
				return options, errors.New("--workspace requires a slug")
			}
			options.Workspace = args[i+1]
			i++
		case "--slug":
			if i+1 >= len(args) || strings.HasPrefix(args[i+1], "--") {
				return options, errors.New("--slug requires a slug")
			}
			options.Slug = args[i+1]
			i++
		case "--name":
			if i+1 >= len(args) || strings.HasPrefix(args[i+1], "--") {
				return options, errors.New("--name requires a value")
			}
			options.Name = args[i+1]
			i++
		case "--origin":
			if i+1 >= len(args) || strings.HasPrefix(args[i+1], "--") {
				return options, errors.New("--origin requires a URL")
			}
			i++
		default:
			return options, fmt.Errorf("unknown service-account create argument %q", args[i])
		}
	}
	if options.Workspace == "" {
		return options, errors.New("service-account create requires --workspace")
	}
	if options.Slug == "" {
		return options, errors.New("service-account create requires --slug")
	}
	if options.Name == "" {
		return options, errors.New("service-account create requires --name")
	}
	return options, nil
}

type serviceAccountSelectOptions struct {
	Workspace      string
	ServiceAccount string
	All            bool
}

func parseServiceAccountSelectArgs(args []string, command string) (serviceAccountSelectOptions, error) {
	var options serviceAccountSelectOptions
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--workspace":
			if options.Workspace != "" {
				return options, fmt.Errorf("service-account %s accepts one --workspace value", command)
			}
			if i+1 >= len(args) || strings.HasPrefix(args[i+1], "--") {
				return options, errors.New("--workspace requires a slug")
			}
			options.Workspace = args[i+1]
			i++
		case "--service-account":
			if i+1 >= len(args) || strings.HasPrefix(args[i+1], "--") {
				return options, errors.New("--service-account requires a slug or id")
			}
			options.ServiceAccount = args[i+1]
			i++
		case "--all":
			options.All = true
		case "--origin":
			if i+1 >= len(args) || strings.HasPrefix(args[i+1], "--") {
				return options, errors.New("--origin requires a URL")
			}
			i++
		default:
			return options, fmt.Errorf("unknown service-account %s argument %q", command, args[i])
		}
	}
	if options.Workspace == "" {
		return options, fmt.Errorf("service-account %s requires --workspace", command)
	}
	if command != "list" && options.ServiceAccount == "" {
		return options, fmt.Errorf("service-account %s requires --service-account", command)
	}
	return options, nil
}

type serviceAccountGrantOptions struct {
	Workspace      string
	ServiceAccount string
	ScopePattern   string
	SecretPattern  string
	Actions        []string
	ApprovalMode   string
	ExpiresAt      string
}

func parseServiceAccountGrantArgs(args []string) (serviceAccountGrantOptions, error) {
	options := serviceAccountGrantOptions{ApprovalMode: "none"}
	for i := 0; i < len(args); i++ {
		if action, ok := servicePolicyAction(args[i]); ok {
			if !stringSliceContains(options.Actions, action) {
				options.Actions = append(options.Actions, action)
			}
			continue
		}
		switch args[i] {
		case "--workspace":
			if options.Workspace != "" {
				return options, errors.New("service-account grant accepts one --workspace value")
			}
			if i+1 >= len(args) || strings.HasPrefix(args[i+1], "--") {
				return options, errors.New("--workspace requires a slug")
			}
			options.Workspace = args[i+1]
			i++
		case "--service-account":
			if i+1 >= len(args) || strings.HasPrefix(args[i+1], "--") {
				return options, errors.New("--service-account requires a slug or id")
			}
			options.ServiceAccount = args[i+1]
			i++
		case "--scope":
			if i+1 >= len(args) || strings.HasPrefix(args[i+1], "--") {
				return options, errors.New("--scope requires a value")
			}
			options.ScopePattern = args[i+1]
			i++
		case "--secret":
			if i+1 >= len(args) || strings.HasPrefix(args[i+1], "--") {
				return options, errors.New("--secret requires a value")
			}
			options.SecretPattern = args[i+1]
			i++
		case "--approval-mode":
			if i+1 >= len(args) || strings.HasPrefix(args[i+1], "--") {
				return options, errors.New("--approval-mode requires a value")
			}
			options.ApprovalMode = args[i+1]
			i++
		case "--expires-at":
			if i+1 >= len(args) || strings.HasPrefix(args[i+1], "--") {
				return options, errors.New("--expires-at requires a value")
			}
			expiresAt, err := normalizeFutureTimestamp(args[i+1], "--expires-at")
			if err != nil {
				return options, err
			}
			options.ExpiresAt = expiresAt
			i++
		case "--origin":
			if i+1 >= len(args) || strings.HasPrefix(args[i+1], "--") {
				return options, errors.New("--origin requires a URL")
			}
			i++
		default:
			return options, fmt.Errorf("unknown service-account grant argument %q", args[i])
		}
	}
	if options.Workspace == "" {
		return options, errors.New("service-account grant requires --workspace")
	}
	if options.ServiceAccount == "" {
		return options, errors.New("service-account grant requires --service-account")
	}
	if options.ScopePattern == "" {
		return options, errors.New("service-account grant requires --scope")
	}
	if options.SecretPattern == "" {
		return options, errors.New("service-account grant requires --secret")
	}
	if len(options.Actions) == 0 {
		return options, errors.New("service-account grant requires --inject-only, --read, --mount, --broker, --sign, or --proxy-local")
	}
	if options.ApprovalMode != "none" && options.ApprovalMode != "require-owner" {
		return options, errors.New("--approval-mode must be none or require-owner")
	}
	return options, nil
}

func servicePolicyAction(flag string) (string, bool) {
	switch flag {
	case "--read":
		return "read", true
	case "--inject-only":
		return "inject", true
	case "--mount":
		return "mount", true
	case "--broker":
		return "broker", true
	case "--sign":
		return "sign", true
	case "--proxy-local":
		return "proxy-local", true
	default:
		return "", false
	}
}

func (a App) serviceAccountCreate(st *store.FileStore, args []string) int {
	if err := st.RequireInitialized(); err != nil {
		return a.fail(err)
	}
	if err := rejectServiceAccountControlPlaneMutation(st); err != nil {
		return a.fail(err)
	}
	options, err := parseServiceAccountCreateArgs(args)
	if err != nil {
		return a.fail(err)
	}
	origin := loginOrigin(args, st)
	accessToken, err := ensureControlPlaneAccess(origin, st)
	if err != nil {
		return a.fail(err)
	}
	target, accessToken, err := a.remoteWorkspaceTarget(st, accessToken, options.Workspace)
	if err != nil {
		return a.fail(err)
	}
	account, err := createRemoteServiceAccount(st, st.State.ControlPlane.Origin, accessToken, target.ID, options.Slug, options.Name)
	if err != nil {
		return a.fail(err)
	}
	fmt.Fprintf(a.Out, "✓ Created service account %s in workspace %s (%s)\n", account.Slug, target.Slug, account.ID)
	return 0
}

func (a App) serviceAccountList(st *store.FileStore, args []string) int {
	if err := st.RequireInitialized(); err != nil {
		return a.fail(err)
	}
	options, err := parseServiceAccountSelectArgs(args, "list")
	if err != nil {
		return a.fail(err)
	}
	origin := loginOrigin(args, st)
	accessToken, err := ensureControlPlaneAccess(origin, st)
	if err != nil {
		return a.fail(err)
	}
	target, accessToken, err := a.remoteWorkspaceTarget(st, accessToken, options.Workspace)
	if err != nil {
		return a.fail(err)
	}
	accounts, err := listRemoteServiceAccounts(st, st.State.ControlPlane.Origin, target.ID, accessToken, options.All)
	if err != nil {
		return a.fail(err)
	}
	tw := tabwriter.NewWriter(a.Out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "SLUG\tNAME\tSTATUS\tID")
	for _, account := range accounts {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", account.Slug, account.Name, account.Status, account.ID)
	}
	_ = tw.Flush()
	return 0
}

func (a App) serviceAccountDisable(st *store.FileStore, args []string) int {
	if err := st.RequireInitialized(); err != nil {
		return a.fail(err)
	}
	if err := rejectServiceAccountControlPlaneMutation(st); err != nil {
		return a.fail(err)
	}
	options, err := parseServiceAccountSelectArgs(args, "disable")
	if err != nil {
		return a.fail(err)
	}
	origin := loginOrigin(args, st)
	accessToken, err := ensureControlPlaneAccess(origin, st)
	if err != nil {
		return a.fail(err)
	}
	target, accessToken, err := a.remoteWorkspaceTarget(st, accessToken, options.Workspace)
	if err != nil {
		return a.fail(err)
	}
	account, err := requireRemoteServiceAccount(st, st.State.ControlPlane.Origin, target.ID, accessToken, options.ServiceAccount)
	if err != nil {
		return a.fail(err)
	}
	disabled, err := disableRemoteServiceAccount(st, st.State.ControlPlane.Origin, accessToken, target.ID, account.ID)
	if err != nil {
		return a.fail(err)
	}
	fmt.Fprintf(a.Out, "✓ Disabled service account %s in workspace %s\n", disabled.Slug, target.Slug)
	return 0
}

func (a App) serviceAccountGrant(st *store.FileStore, args []string) int {
	if err := st.RequireInitialized(); err != nil {
		return a.fail(err)
	}
	if err := rejectServiceAccountControlPlaneMutation(st); err != nil {
		return a.fail(err)
	}
	options, err := parseServiceAccountGrantArgs(args)
	if err != nil {
		return a.fail(err)
	}
	origin := loginOrigin(args, st)
	accessToken, err := ensureControlPlaneAccess(origin, st)
	if err != nil {
		return a.fail(err)
	}
	target, accessToken, err := a.remoteWorkspaceTarget(st, accessToken, options.Workspace)
	if err != nil {
		return a.fail(err)
	}
	scopePattern, err := workspacePrefixedPattern(workspacePathTarget{Slug: target.Slug, KnownSlugs: knownWorkspaceSlugs(st)}, options.ScopePattern, "service-account grant")
	if err != nil {
		return a.fail(err)
	}
	account, err := requireRemoteServiceAccount(st, st.State.ControlPlane.Origin, target.ID, accessToken, options.ServiceAccount)
	if err != nil {
		return a.fail(err)
	}
	policy, created, err := ensureRemoteServiceAccountPolicy(st, st.State.ControlPlane.Origin, accessToken, target.ID, account.Slug, serviceAccountGrantOptions{
		ScopePattern:  scopePattern,
		SecretPattern: options.SecretPattern,
		Actions:       options.Actions,
		ApprovalMode:  options.ApprovalMode,
		ExpiresAt:     options.ExpiresAt,
	})
	if err != nil {
		return a.fail(err)
	}
	if created {
		fmt.Fprintf(a.Out, "✓ Added service policy %s for service account %s on %s/%s\n", policy.ID, account.Slug, policy.ScopePattern, policy.SecretPattern)
	} else {
		fmt.Fprintf(a.Out, "✓ Service policy %s already grants service account %s on %s/%s\n", policy.ID, account.Slug, policy.ScopePattern, policy.SecretPattern)
	}
	return 0
}

func (a App) serviceAccountLogin(st *store.FileStore, args []string) int {
	if err := st.RequireInitialized(); err != nil {
		return a.fail(err)
	}
	if st.State.ControlPlane != nil {
		return a.fail(errors.New("service-account login requires no existing control-plane session; run asiri logout first or use an isolated ASIRI_HOME"))
	}
	options, err := parseServiceAccountSelectArgs(args, "login")
	if err != nil {
		return a.fail(err)
	}
	origin := loginOrigin(args, st)
	if err := validateControlPlaneOrigin(origin); err != nil {
		return a.fail(err)
	}
	device, err := st.ActiveDevice()
	if err != nil {
		return a.fail(err)
	}
	start, err := startServiceAccountDeviceCodeLogin(origin, options.Workspace, options.ServiceAccount, *device)
	if err != nil {
		return a.fail(err)
	}
	fmt.Fprintf(a.Out, "Open %s\n", start.VerificationURIComplete)
	fmt.Fprintf(a.Out, "Code: %s\n", start.UserCode)
	result, err := pollDeviceCodeLogin(st, origin, start)
	if err != nil {
		return a.fail(err)
	}
	if result.ServiceAccountID == "" || result.ServiceAccountSlug == "" {
		return a.fail(errors.New("control plane approved login without service account metadata"))
	}
	if result.WorkspaceSlug != options.Workspace || result.ServiceAccountSlug != options.ServiceAccount {
		return a.fail(errors.New("control plane approved a different workspace or service account than requested"))
	}
	if err := st.LinkServiceAccountControlPlane(origin, result.OrgID, result.WorkspaceSlug, result.UserID, result.ServiceAccountID, result.ServiceAccountSlug, result.ServiceAccountName, result.DeviceID, device.ID, result.AccessToken, result.RefreshToken, result.ExpiresIn, result.RefreshExpiresAt); err != nil {
		return a.fail(err)
	}
	fmt.Fprintf(a.Out, "✓ Linked service account %s to workspace %s\n", result.ServiceAccountSlug, result.WorkspaceSlug)
	return 0
}
