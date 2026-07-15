package cli

import (
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/o-clan/asiri/cli/internal/store"
)

func listRemoteMembers(st *store.FileStore, origin, orgID, accessToken string, includeInactive bool) ([]remoteMemberResponse, error) {
	var result remoteMembersResponse
	params := url.Values{"orgId": []string{orgID}}
	if includeInactive {
		params.Set("includeInactive", "1")
	}
	endpoint := fmt.Sprintf("%s/v1/members?%s", strings.TrimRight(origin, "/"), params.Encode())
	if err := getJSONBearer(st, endpoint, accessToken, &result); err != nil {
		return nil, err
	}
	for _, member := range result.Members {
		if member.ID == "" || member.UserID == "" || member.OrgID != orgID {
			return nil, errors.New("control plane returned invalid member metadata")
		}
	}
	return result.Members, nil
}

func listRemoteMemberAccessGrants(st *store.FileStore, origin, orgID, accessToken string, includeInactive bool) ([]remoteMemberAccessGrantResponse, error) {
	var result remoteMemberAccessGrantsResponse
	params := url.Values{"orgId": []string{orgID}}
	if includeInactive {
		params.Set("includeInactive", "1")
	}
	endpoint := fmt.Sprintf("%s/v1/secret-access-grants?%s", strings.TrimRight(origin, "/"), params.Encode())
	if err := getJSONBearer(st, endpoint, accessToken, &result); err != nil {
		return nil, err
	}
	for _, grant := range result.SecretAccessGrants {
		if grant.ID == "" || grant.UserID == "" || grant.OrgID != orgID {
			return nil, errors.New("control plane returned invalid member access metadata")
		}
	}
	return result.SecretAccessGrants, nil
}

func createRemoteMemberAccessGrant(st *store.FileStore, origin, accessToken, orgID, userID string, options memberAccessGrantOptions) (remoteMemberAccessGrantResponse, bool, error) {
	var result remoteMemberAccessGrantResponse
	body := map[string]any{
		"orgId":              orgID,
		"userId":             userID,
		"targetType":         options.TargetType,
		"scope":              options.Scope,
		"includeDescendants": options.IncludeDescendants,
	}
	if options.SecretName != "" {
		body["secretName"] = options.SecretName
	}
	status, err := postJSONBearerStatus(st, strings.TrimRight(origin, "/")+"/v1/secret-access-grants", accessToken, body, &result)
	if err != nil {
		return result, false, err
	}
	if result.ID == "" {
		return result, false, errors.New("control plane created member access without metadata")
	}
	if result.OrgID != orgID || result.UserID != userID || result.TargetType != options.TargetType || result.Scope != options.Scope || result.SecretName != options.SecretName || result.IncludeDescendants != options.IncludeDescendants {
		return result, false, errors.New("control plane created member access for a different target")
	}
	return result, status == 201, nil
}

func revokeRemoteMemberAccessGrant(st *store.FileStore, origin, accessToken, orgID, grantID string) (remoteMemberAccessGrantResponse, error) {
	var result remoteMemberAccessGrantResponse
	endpoint := fmt.Sprintf("%s/v1/secret-access-grants/%s/revoke", strings.TrimRight(origin, "/"), url.PathEscape(grantID))
	if _, err := postJSONBearerStatus(st, endpoint, accessToken, map[string]any{}, &result); err != nil {
		return result, err
	}
	if result.ID == "" {
		return result, errors.New("control plane revoked member access without metadata")
	}
	if result.ID != grantID || result.OrgID != orgID || result.Status != "revoked" {
		return result, errors.New("control plane revoked a different member access grant")
	}
	return result, nil
}
