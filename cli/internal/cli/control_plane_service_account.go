package cli

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/o-clan/asiri/cli/internal/store"
)

func createRemoteServiceAccount(st *store.FileStore, origin, accessToken, orgID, slug, name string) (remoteServiceAccountResponse, error) {
	var result remoteServiceAccountResponse
	body := map[string]string{"orgId": orgID, "slug": slug, "name": name}
	if err := postJSONBearer(st, strings.TrimRight(origin, "/")+"/v1/service-accounts", accessToken, body, &result); err != nil {
		return result, err
	}
	if result.ID == "" || result.Slug == "" {
		return result, errors.New("control plane created service account without metadata")
	}
	return result, nil
}

func listRemoteServiceAccounts(st *store.FileStore, origin, orgID, accessToken string, includeInactive bool) ([]remoteServiceAccountResponse, error) {
	var result remoteServiceAccountsResponse
	params := url.Values{"orgId": []string{orgID}}
	if includeInactive {
		params.Set("includeInactive", "1")
	}
	endpoint := fmt.Sprintf("%s/v1/service-accounts?%s", strings.TrimRight(origin, "/"), params.Encode())
	if err := getJSONBearer(st, endpoint, accessToken, &result); err != nil {
		return nil, err
	}
	return result.ServiceAccounts, nil
}

func findRemoteServiceAccount(accounts []remoteServiceAccountResponse, value string) (remoteServiceAccountResponse, bool) {
	for _, account := range accounts {
		if account.ID == value || account.Slug == value {
			return account, true
		}
	}
	return remoteServiceAccountResponse{}, false
}

func requireRemoteServiceAccount(st *store.FileStore, origin, orgID, accessToken, value string) (remoteServiceAccountResponse, error) {
	accounts, err := listRemoteServiceAccounts(st, origin, orgID, accessToken, true)
	if err != nil {
		return remoteServiceAccountResponse{}, err
	}
	account, ok := findRemoteServiceAccount(accounts, value)
	if !ok {
		return remoteServiceAccountResponse{}, fmt.Errorf("service account %s is not visible", value)
	}
	return account, nil
}

func disableRemoteServiceAccount(st *store.FileStore, origin, accessToken, orgID, accountID string) (remoteServiceAccountResponse, error) {
	var result remoteServiceAccountResponse
	endpoint := fmt.Sprintf("%s/v1/service-accounts/%s/disable", strings.TrimRight(origin, "/"), url.PathEscape(accountID))
	if err := postJSONBearer(st, endpoint, accessToken, map[string]string{"orgId": orgID}, &result); err != nil {
		return result, err
	}
	if result.ID == "" || result.Slug == "" {
		return result, errors.New("control plane disabled service account without metadata")
	}
	return result, nil
}

func listRemotePolicies(st *store.FileStore, origin, orgID, accessToken string) ([]remotePolicyResponse, error) {
	var result remotePoliciesResponse
	endpoint := fmt.Sprintf("%s/v1/policies?orgId=%s", strings.TrimRight(origin, "/"), url.QueryEscape(orgID))
	if err := getJSONBearer(st, endpoint, accessToken, &result); err != nil {
		return nil, err
	}
	return result.Policies, nil
}

func ensureRemoteServiceAccountPolicy(st *store.FileStore, origin, accessToken, orgID, serviceAccountSlug string, options serviceAccountGrantOptions) (remotePolicyResponse, bool, error) {
	policies, err := listRemotePolicies(st, origin, orgID, accessToken)
	if err != nil {
		return remotePolicyResponse{}, false, err
	}
	for _, policy := range policies {
		if policy.SubjectType == "service" &&
			policy.SubjectID == serviceAccountSlug &&
			policy.ScopePattern == options.ScopePattern &&
			policy.SecretPattern == options.SecretPattern &&
			policy.ApprovalMode == options.ApprovalMode &&
			normalizeTimestampForCompare(policy.ExpiresAt) == normalizeTimestampForCompare(options.ExpiresAt) &&
			sameStringSet(policy.Actions, options.Actions) {
			return policy, false, nil
		}
	}
	var result remotePolicyResponse
	body := map[string]any{
		"orgId":         orgID,
		"subjectType":   "service",
		"subjectId":     serviceAccountSlug,
		"scopePattern":  options.ScopePattern,
		"secretPattern": options.SecretPattern,
		"actions":       options.Actions,
		"approvalMode":  options.ApprovalMode,
	}
	if options.ExpiresAt != "" {
		body["expiresAt"] = options.ExpiresAt
	}
	if err := postJSONBearer(st, strings.TrimRight(origin, "/")+"/v1/policies", accessToken, body, &result); err != nil {
		return result, false, err
	}
	if result.ID == "" {
		return result, false, errors.New("control plane created policy without metadata")
	}
	return result, true, nil
}

func stringSliceContains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func sameStringSet(left, right []string) bool {
	return containsStringSet(left, right) && containsStringSet(right, left)
}

func containsStringSet(available, required []string) bool {
	availableSet := map[string]bool{}
	for _, value := range available {
		availableSet[value] = true
	}
	for _, value := range required {
		if !availableSet[value] {
			return false
		}
	}
	return true
}

func normalizeTimestampForCompare(value string) string {
	if value == "" {
		return ""
	}
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return value
	}
	return parsed.UTC().Format(time.RFC3339Nano)
}

func normalizeFutureTimestamp(value, flag string) (string, error) {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return "", fmt.Errorf("%s must be an RFC3339 timestamp", flag)
	}
	parsed = parsed.UTC()
	if !parsed.After(time.Now().UTC()) {
		return "", fmt.Errorf("%s must be in the future", flag)
	}
	return parsed.Format(time.RFC3339), nil
}

func stringMapsEqual(left, right map[string]string) bool {
	if len(left) != len(right) {
		return false
	}
	for key, leftValue := range left {
		if right[key] != leftValue {
			return false
		}
	}
	return true
}
