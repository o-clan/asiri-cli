package cli

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"text/tabwriter"
	"unicode"

	"github.com/o-clan/asiri/cli/internal/store"
)

func (a App) member(st *store.FileStore, args []string) int {
	if len(args) == 0 {
		return a.fail(errors.New("member subcommand required"))
	}
	switch args[0] {
	case "list":
		return a.memberList(st, args[1:])
	case "access":
		return a.memberAccess(st, args[1:])
	default:
		return a.fail(fmt.Errorf("unknown member command %q", args[0]))
	}
}

func (a App) memberAccess(st *store.FileStore, args []string) int {
	if len(args) == 0 {
		return a.fail(errors.New("member access subcommand required"))
	}
	switch args[0] {
	case "list":
		return a.memberAccessList(st, args[1:])
	case "grant":
		return a.memberAccessGrant(st, args[1:])
	case "revoke":
		return a.memberAccessRevoke(st, args[1:])
	default:
		return a.fail(fmt.Errorf("unknown member access command %q", args[0]))
	}
}

type memberListOptions struct {
	Workspace string
	All       bool
}

type memberAccessListOptions struct {
	Workspace string
	Member    string
	All       bool
}

type memberAccessGrantOptions struct {
	Workspace          string
	Member             string
	Envelope           string
	Secret             string
	IncludeDescendants bool
	TargetType         string
	Scope              string
	SecretName         string
}

type memberAccessRevokeOptions struct {
	Workspace string
	GrantID   string
}

func memberFlagValue(args []string, index *int, flag string) (string, error) {
	if *index+1 >= len(args) || strings.HasPrefix(args[*index+1], "--") {
		return "", fmt.Errorf("%s requires a value", flag)
	}
	*index = *index + 1
	return args[*index], nil
}

func parseMemberListArgs(args []string) (memberListOptions, error) {
	var options memberListOptions
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--workspace":
			value, err := memberFlagValue(args, &i, "--workspace")
			if err != nil {
				return options, err
			}
			if options.Workspace != "" {
				return options, errors.New("member list accepts one --workspace value")
			}
			options.Workspace = value
		case "--all":
			options.All = true
		case "--origin":
			if _, err := memberFlagValue(args, &i, "--origin"); err != nil {
				return options, err
			}
		default:
			return options, fmt.Errorf("unknown member list argument %q", args[i])
		}
	}
	if options.Workspace == "" {
		return options, errors.New("member list requires --workspace")
	}
	return options, nil
}

func parseMemberAccessListArgs(args []string) (memberAccessListOptions, error) {
	var options memberAccessListOptions
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--workspace":
			value, err := memberFlagValue(args, &i, "--workspace")
			if err != nil {
				return options, err
			}
			if options.Workspace != "" {
				return options, errors.New("member access list accepts one --workspace value")
			}
			options.Workspace = value
		case "--member":
			value, err := memberFlagValue(args, &i, "--member")
			if err != nil {
				return options, err
			}
			if options.Member != "" {
				return options, errors.New("member access list accepts one --member value")
			}
			options.Member = value
		case "--all":
			options.All = true
		case "--origin":
			if _, err := memberFlagValue(args, &i, "--origin"); err != nil {
				return options, err
			}
		default:
			return options, fmt.Errorf("unknown member access list argument %q", args[i])
		}
	}
	if options.Workspace == "" {
		return options, errors.New("member access list requires --workspace")
	}
	return options, nil
}

func parseMemberAccessGrantArgs(args []string) (memberAccessGrantOptions, error) {
	var options memberAccessGrantOptions
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--workspace":
			value, err := memberFlagValue(args, &i, "--workspace")
			if err != nil {
				return options, err
			}
			if options.Workspace != "" {
				return options, errors.New("member access grant accepts one --workspace value")
			}
			options.Workspace = value
		case "--member":
			value, err := memberFlagValue(args, &i, "--member")
			if err != nil {
				return options, err
			}
			if options.Member != "" {
				return options, errors.New("member access grant accepts one --member value")
			}
			options.Member = value
		case "--envelope":
			value, err := memberFlagValue(args, &i, "--envelope")
			if err != nil {
				return options, err
			}
			if options.Envelope != "" {
				return options, errors.New("member access grant accepts one --envelope value")
			}
			options.Envelope = value
		case "--secret":
			value, err := memberFlagValue(args, &i, "--secret")
			if err != nil {
				return options, err
			}
			if options.Secret != "" {
				return options, errors.New("member access grant accepts one --secret value")
			}
			options.Secret = value
		case "--include-descendants":
			options.IncludeDescendants = true
		case "--origin":
			if _, err := memberFlagValue(args, &i, "--origin"); err != nil {
				return options, err
			}
		default:
			return options, fmt.Errorf("unknown member access grant argument %q", args[i])
		}
	}
	if options.Workspace == "" {
		return options, errors.New("member access grant requires --workspace")
	}
	if options.Member == "" {
		return options, errors.New("member access grant requires --member")
	}
	if (options.Envelope == "") == (options.Secret == "") {
		return options, errors.New("member access grant requires exactly one of --envelope or --secret")
	}
	if options.Secret != "" && options.IncludeDescendants {
		return options, errors.New("--include-descendants can only be used with --envelope")
	}
	return options, nil
}

func parseMemberAccessRevokeArgs(args []string) (memberAccessRevokeOptions, error) {
	var options memberAccessRevokeOptions
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--workspace":
			value, err := memberFlagValue(args, &i, "--workspace")
			if err != nil {
				return options, err
			}
			if options.Workspace != "" {
				return options, errors.New("member access revoke accepts one --workspace value")
			}
			options.Workspace = value
		case "--grant":
			value, err := memberFlagValue(args, &i, "--grant")
			if err != nil {
				return options, err
			}
			if options.GrantID != "" {
				return options, errors.New("member access revoke accepts one --grant value")
			}
			options.GrantID = value
		case "--origin":
			if _, err := memberFlagValue(args, &i, "--origin"); err != nil {
				return options, err
			}
		default:
			return options, fmt.Errorf("unknown member access revoke argument %q", args[i])
		}
	}
	if options.Workspace == "" {
		return options, errors.New("member access revoke requires --workspace")
	}
	if options.GrantID == "" {
		return options, errors.New("member access revoke requires --grant")
	}
	return options, nil
}

func requireHumanMemberSession(st *store.FileStore) error {
	if st != nil && st.State.ControlPlane != nil && st.State.ControlPlane.Source == "service-account" {
		return errors.New("member management requires a human session; run asiri logout, then asiri login")
	}
	return nil
}

func (a App) memberList(st *store.FileStore, args []string) int {
	if err := st.RequireInitialized(); err != nil {
		return a.fail(err)
	}
	if err := requireHumanMemberSession(st); err != nil {
		return a.fail(err)
	}
	options, err := parseMemberListArgs(args)
	if err != nil {
		return a.fail(err)
	}
	target, accessToken, err := a.memberWorkspaceTarget(st, args, options.Workspace)
	if err != nil {
		return a.fail(err)
	}
	members, err := listRemoteMembers(st, st.State.ControlPlane.Origin, target.ID, accessToken, options.All)
	if err != nil {
		return a.fail(err)
	}
	sort.SliceStable(members, func(i, j int) bool {
		return strings.ToLower(memberDisplayLabel(members[i])) < strings.ToLower(memberDisplayLabel(members[j]))
	})
	tw := tabwriter.NewWriter(a.Out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tEMAIL\tROLE\tSTATUS\tUSER ID")
	for _, member := range members {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", memberDisplayLabel(member), safeMemberPrintable(member.UserEmail), safeMemberOutput(member.Role), safeMemberOutput(member.Status), safeMemberOutput(member.UserID))
	}
	_ = tw.Flush()
	return 0
}

func (a App) memberAccessList(st *store.FileStore, args []string) int {
	if err := st.RequireInitialized(); err != nil {
		return a.fail(err)
	}
	if err := requireHumanMemberSession(st); err != nil {
		return a.fail(err)
	}
	options, err := parseMemberAccessListArgs(args)
	if err != nil {
		return a.fail(err)
	}
	target, accessToken, err := a.memberWorkspaceTarget(st, args, options.Workspace)
	if err != nil {
		return a.fail(err)
	}
	members, err := listRemoteMembers(st, st.State.ControlPlane.Origin, target.ID, accessToken, true)
	if err != nil {
		return a.fail(err)
	}
	var selectedUserID string
	if options.Member != "" {
		member, err := requireRemoteMember(members, options.Member, false)
		if err != nil {
			return a.fail(err)
		}
		selectedUserID = member.UserID
	}
	grants, err := listRemoteMemberAccessGrants(st, st.State.ControlPlane.Origin, target.ID, accessToken, options.All)
	if err != nil {
		return a.fail(err)
	}
	membersByUserID := make(map[string]remoteMemberResponse, len(members))
	for _, member := range members {
		membersByUserID[member.UserID] = member
	}
	sort.SliceStable(grants, func(i, j int) bool {
		left := memberDisplayLabel(membersByUserID[grants[i].UserID]) + memberAccessTarget(target.Slug, grants[i])
		right := memberDisplayLabel(membersByUserID[grants[j].UserID]) + memberAccessTarget(target.Slug, grants[j])
		return strings.ToLower(left) < strings.ToLower(right)
	})
	tw := tabwriter.NewWriter(a.Out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "PERSON\tEMAIL\tACCESS\tDESCENDANTS\tSTATUS\tGRANT ID")
	for _, grant := range grants {
		if selectedUserID != "" && grant.UserID != selectedUserID {
			continue
		}
		member := membersByUserID[grant.UserID]
		descendants := "-"
		if grant.TargetType == "envelope" {
			descendants = "no"
			if grant.IncludeDescendants {
				descendants = "yes"
			}
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", memberDisplayLabel(member), safeMemberPrintable(member.UserEmail), memberAccessTarget(target.Slug, grant), descendants, safeMemberOutput(grant.Status), safeMemberOutput(grant.ID))
	}
	_ = tw.Flush()
	return 0
}

func (a App) memberAccessGrant(st *store.FileStore, args []string) int {
	if err := st.RequireInitialized(); err != nil {
		return a.fail(err)
	}
	if err := requireHumanMemberSession(st); err != nil {
		return a.fail(err)
	}
	options, err := parseMemberAccessGrantArgs(args)
	if err != nil {
		return a.fail(err)
	}
	target, accessToken, err := a.memberWorkspaceTarget(st, args, options.Workspace)
	if err != nil {
		return a.fail(err)
	}
	members, err := listRemoteMembers(st, st.State.ControlPlane.Origin, target.ID, accessToken, false)
	if err != nil {
		return a.fail(err)
	}
	member, err := requireRemoteMember(members, options.Member, true)
	if err != nil {
		return a.fail(err)
	}
	options, err = normalizeMemberAccessGrant(st, target.Slug, options)
	if err != nil {
		return a.fail(err)
	}
	grant, created, err := createRemoteMemberAccessGrant(st, st.State.ControlPlane.Origin, accessToken, target.ID, member.UserID, options)
	if err != nil {
		return a.fail(err)
	}
	if created {
		fmt.Fprintf(a.Out, "✓ Granted access to %s (%s): %s [%s]\n", memberDisplayLabel(member), safeMemberPrintable(member.UserEmail), memberAccessTarget(target.Slug, grant), safeMemberOutput(grant.ID))
	} else {
		fmt.Fprintf(a.Out, "✓ Access already exists for %s (%s): %s [%s]\n", memberDisplayLabel(member), safeMemberPrintable(member.UserEmail), memberAccessTarget(target.Slug, grant), safeMemberOutput(grant.ID))
	}
	fmt.Fprintf(a.Out, "Next: asiri rewrap --workspace %s\n", target.Slug)
	return 0
}

func (a App) memberAccessRevoke(st *store.FileStore, args []string) int {
	if err := st.RequireInitialized(); err != nil {
		return a.fail(err)
	}
	if err := requireHumanMemberSession(st); err != nil {
		return a.fail(err)
	}
	options, err := parseMemberAccessRevokeArgs(args)
	if err != nil {
		return a.fail(err)
	}
	target, accessToken, err := a.memberWorkspaceTarget(st, args, options.Workspace)
	if err != nil {
		return a.fail(err)
	}
	grants, err := listRemoteMemberAccessGrants(st, st.State.ControlPlane.Origin, target.ID, accessToken, true)
	if err != nil {
		return a.fail(err)
	}
	grant, ok := findRemoteMemberAccessGrant(grants, options.GrantID)
	if !ok {
		return a.fail(fmt.Errorf("member access grant %s is not visible in workspace %s", safeMemberPrintable(options.GrantID), target.Slug))
	}
	if grant.Status == "revoked" {
		fmt.Fprintf(a.Out, "✓ Member access grant %s is already revoked\n", safeMemberOutput(grant.ID))
		return 0
	}
	members, err := listRemoteMembers(st, st.State.ControlPlane.Origin, target.ID, accessToken, true)
	if err != nil {
		return a.fail(err)
	}
	member := remoteMemberResponse{UserID: grant.UserID}
	for _, candidate := range members {
		if candidate.UserID == grant.UserID {
			member = candidate
			break
		}
	}
	revoked, err := revokeRemoteMemberAccessGrant(st, st.State.ControlPlane.Origin, accessToken, target.ID, grant.ID)
	if err != nil {
		return a.fail(err)
	}
	fmt.Fprintf(a.Out, "✓ Revoked access for %s (%s): %s [%s]\n", memberDisplayLabel(member), safeMemberPrintable(member.UserEmail), memberAccessTarget(target.Slug, revoked), safeMemberOutput(revoked.ID))
	fmt.Fprintln(a.Out, "Existing decrypted or cached copies are not erased. Another active grant may still allow access.")
	return 0
}

func (a App) memberWorkspaceTarget(st *store.FileStore, args []string, workspace string) (remoteWorkspaceResponse, string, error) {
	origin := loginOrigin(args, st)
	accessToken, err := ensureControlPlaneAccess(origin, st)
	if err != nil {
		return remoteWorkspaceResponse{}, "", err
	}
	return a.remoteWorkspaceTarget(st, accessToken, workspace)
}

func requireRemoteMember(members []remoteMemberResponse, selector string, activeMemberOnly bool) (remoteMemberResponse, error) {
	selector = strings.TrimSpace(selector)
	matches := make([]remoteMemberResponse, 0, 1)
	for _, member := range members {
		if member.UserID == selector || (member.UserEmail != "" && strings.EqualFold(member.UserEmail, selector)) {
			matches = append(matches, member)
		}
	}
	if len(matches) == 0 {
		return remoteMemberResponse{}, fmt.Errorf("member %s is not visible; use an exact email or user id from member list", safeMemberPrintable(selector))
	}
	if len(matches) > 1 {
		return remoteMemberResponse{}, fmt.Errorf("member %s is ambiguous; use the user id from member list", safeMemberPrintable(selector))
	}
	member := matches[0]
	if activeMemberOnly && (member.Role != "member" || member.Status != "active") {
		return remoteMemberResponse{}, errors.New("secret access can only be granted to an active workspace member")
	}
	return member, nil
}

func normalizeMemberAccessGrant(st *store.FileStore, workspaceSlug string, options memberAccessGrantOptions) (memberAccessGrantOptions, error) {
	target := workspacePathTarget{Slug: workspaceSlug, KnownSlugs: knownWorkspaceSlugs(st)}
	if options.Envelope != "" {
		options.TargetType = "envelope"
		if strings.TrimSpace(options.Envelope) == "/" {
			options.Scope = workspaceSlug
			return options, nil
		}
		scope, err := workspacePrefixedScope(target, options.Envelope, "member access grant")
		if err != nil {
			return options, err
		}
		options.Scope = scope
		return options, nil
	}
	path, err := workspacePrefixedPath(target, options.Secret, "member access grant")
	if err != nil {
		return options, err
	}
	scope, name, err := store.ParseSecretPath(path)
	if err != nil {
		return options, err
	}
	options.TargetType = "secret"
	options.Scope = scope
	options.SecretName = name
	return options, nil
}

func findRemoteMemberAccessGrant(grants []remoteMemberAccessGrantResponse, grantID string) (remoteMemberAccessGrantResponse, bool) {
	for _, grant := range grants {
		if grant.ID == grantID {
			return grant, true
		}
	}
	return remoteMemberAccessGrantResponse{}, false
}

func memberDisplayLabel(member remoteMemberResponse) string {
	if value := strings.TrimSpace(member.UserDisplayName); value != "" {
		return safeMemberOutput(value)
	}
	if value := strings.TrimSpace(member.UserEmail); value != "" {
		return safeMemberOutput(value)
	}
	return safeMemberPrintable(member.UserID)
}

func memberAccessTarget(workspaceSlug string, grant remoteMemberAccessGrantResponse) string {
	if grant.TargetType == "secret" {
		return "secret:" + safeMemberOutput(shortSecretPath(grant.Scope, grant.SecretName))
	}
	shortScope := strings.TrimPrefix(grant.Scope, workspaceSlug+"/")
	if grant.Scope == workspaceSlug || shortScope == "" {
		shortScope = "/"
	}
	return "envelope:" + safeMemberOutput(shortScope)
}

func safeMemberPrintable(value string) string {
	return printable(safeMemberOutput(value))
}

func safeMemberOutput(value string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.In(r, unicode.Cf, unicode.Zl, unicode.Zp) {
			return '\uFFFD'
		}
		return r
	}, value)
}
