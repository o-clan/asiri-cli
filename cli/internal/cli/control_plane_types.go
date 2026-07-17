package cli

import (
	"time"

	"github.com/o-clan/asiri/cli/internal/asiri"
	"github.com/o-clan/asiri/cli/internal/store"
)

type deviceCodeStartResponse struct {
	DeviceCode              string `json:"deviceCode"`
	UserCode                string `json:"userCode"`
	VerificationURI         string `json:"verificationUri"`
	VerificationURIComplete string `json:"verificationUriComplete"`
	WorkspaceSlug           string `json:"workspaceSlug"`
	ServiceAccountSlug      string `json:"serviceAccountSlug"`
	ExpiresIn               int    `json:"expiresIn"`
	Interval                int    `json:"interval"`
}

type pushWorkspacePlan struct {
	Prefix string
	Refs   []store.LocalSecretRef
}

type deviceCodeTokenResponse struct {
	Status             string `json:"status"`
	Error              string `json:"error"`
	Message            string `json:"message"`
	SessionIssued      *bool  `json:"sessionIssued"`
	OrgID              string `json:"orgId"`
	WorkspaceSlug      string `json:"workspaceSlug"`
	UserID             string `json:"userId"`
	ServiceAccountID   string `json:"serviceAccountId"`
	ServiceAccountSlug string `json:"serviceAccountSlug"`
	ServiceAccountName string `json:"serviceAccountName"`
	ApprovedByUserID   string `json:"approvedByUserId"`
	DeviceID           string `json:"deviceId"`
	AccessToken        string `json:"accessToken"`
	RefreshToken       string `json:"refreshToken"`
	ExpiresIn          int    `json:"expiresIn"`
	RefreshExpiresAt   string `json:"refreshExpiresAt"`
	Interval           int    `json:"interval"`
}

type sessionRefreshResponse struct {
	Status             string `json:"status"`
	Error              string `json:"error"`
	Message            string `json:"message"`
	OrgID              string `json:"orgId"`
	WorkspaceSlug      string `json:"workspaceSlug"`
	UserID             string `json:"userId"`
	ServiceAccountID   string `json:"serviceAccountId"`
	ServiceAccountSlug string `json:"serviceAccountSlug"`
	ServiceAccountName string `json:"serviceAccountName"`
	ApprovedByUserID   string `json:"approvedByUserId"`
	DeviceID           string `json:"deviceId"`
	AccessToken        string `json:"accessToken"`
	ExpiresIn          int    `json:"expiresIn"`
	RefreshExpiresAt   string `json:"refreshExpiresAt"`
}

type remoteWhoamiResponse struct {
	User      remoteUserResponse          `json:"user"`
	Workspace remoteWorkspaceResponse     `json:"workspace"`
	Device    remoteWhoamiDeviceResponse  `json:"device"`
	Session   remoteWhoamiSessionResponse `json:"session"`
}

type remoteUserResponse struct {
	ID          string `json:"id"`
	Email       string `json:"email"`
	DisplayName string `json:"displayName"`
	Role        string `json:"role"`
	Status      string `json:"status"`
}

type remoteWhoamiDeviceResponse struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Kind   string `json:"kind"`
	Status string `json:"status"`
}

type remoteWhoamiSessionResponse struct {
	IdentityType       string `json:"identityType"`
	WorkspaceID        string `json:"workspaceId"`
	DeviceID           string `json:"deviceId"`
	ServiceAccountID   string `json:"serviceAccountId"`
	ServiceAccountSlug string `json:"serviceAccountSlug"`
	ServiceAccountName string `json:"serviceAccountName"`
	ApprovedByUserID   string `json:"approvedByUserId"`
	Source             string `json:"source"`
	Status             string `json:"status"`
	ExpiresAt          string `json:"expiresAt"`
}

type remoteWorkspaceResponse struct {
	ID                   string `json:"id"`
	Name                 string `json:"name"`
	Slug                 string `json:"slug"`
	OwnerUserID          string `json:"ownerUserId"`
	Role                 string `json:"role"`
	CanPull              *bool  `json:"canPull"`
	CanWrite             *bool  `json:"canWrite"`
	CurrentDeviceTrusted *bool  `json:"currentDeviceTrusted"`
	CurrentDeviceStatus  string `json:"currentDeviceStatus"`
	CurrentDeviceID      string `json:"currentDeviceId"`
	CanApproveDevice     *bool  `json:"canApproveDevice"`
}

type remoteWorkspacesResponse struct {
	Organizations []remoteWorkspaceResponse   `json:"organizations"`
	Secrets       []visibleRemoteSecretRecord `json:"secrets,omitempty"`
}

type remoteMemberResponse struct {
	ID              string `json:"id"`
	OrgID           string `json:"orgId"`
	UserID          string `json:"userId"`
	Role            string `json:"role"`
	Status          string `json:"status"`
	UserEmail       string `json:"userEmail"`
	UserDisplayName string `json:"userDisplayName"`
	CreatedAt       string `json:"createdAt"`
	RemovedAt       string `json:"removedAt"`
}

type remoteMembersResponse struct {
	Members []remoteMemberResponse `json:"members"`
}

type remoteMemberAccessGrantResponse struct {
	ID                 string `json:"id"`
	OrgID              string `json:"orgId"`
	UserID             string `json:"userId"`
	TargetType         string `json:"targetType"`
	Scope              string `json:"scope"`
	SecretName         string `json:"secretName"`
	IncludeDescendants bool   `json:"includeDescendants"`
	Status             string `json:"status"`
	GrantedByUserID    string `json:"grantedByUserId"`
	CreatedAt          string `json:"createdAt"`
	RevokedAt          string `json:"revokedAt"`
	RevokedByUserID    string `json:"revokedByUserId"`
}

type remoteMemberAccessGrantsResponse struct {
	SecretAccessGrants []remoteMemberAccessGrantResponse `json:"secretAccessGrants"`
}

type remoteServiceAccountResponse struct {
	ID              string `json:"id"`
	OrgID           string `json:"orgId"`
	Slug            string `json:"slug"`
	Name            string `json:"name"`
	Status          string `json:"status"`
	CreatedByUserID string `json:"createdByUserId"`
}

type remoteServiceAccountsResponse struct {
	ServiceAccounts []remoteServiceAccountResponse `json:"serviceAccounts"`
}

type remotePolicyResponse struct {
	ID            string   `json:"id"`
	OrgID         string   `json:"orgId"`
	SubjectType   string   `json:"subjectType"`
	SubjectID     string   `json:"subjectId"`
	ScopePattern  string   `json:"scopePattern"`
	SecretPattern string   `json:"secretPattern"`
	Actions       []string `json:"actions"`
	ApprovalMode  string   `json:"approvalMode"`
	ExpiresAt     string   `json:"expiresAt"`
}

type remotePoliciesResponse struct {
	Policies []remotePolicyResponse `json:"policies"`
}

type writeOptionsResponse struct {
	RequestedWorkspaceSlug string               `json:"requestedWorkspaceSlug"`
	Workspace              writeWorkspaceOption `json:"workspace"`
}

type writeWorkspaceOption struct {
	ID       string            `json:"id"`
	Slug     string            `json:"slug"`
	CanWrite bool              `json:"canWrite"`
	Paths    []writePathOption `json:"paths"`
}

type writePathOption struct {
	Scope              string `json:"scope"`
	Name               string `json:"name"`
	FullPath           string `json:"fullPath"`
	RequiredCapability string `json:"requiredCapability"`
	CanWrite           bool   `json:"canWrite"`
}

type remoteDeviceResponse struct {
	ID                  string `json:"id"`
	Name                string `json:"name"`
	Kind                string `json:"kind"`
	Status              string `json:"status"`
	EncryptionPublicKey string `json:"encryptionPublicKey"`
}

type syncBundleResponse struct {
	OrgID            string                      `json:"orgId"`
	DeviceID         string                      `json:"deviceId"`
	IssuedAt         string                      `json:"issuedAt"`
	EncryptedSecrets []store.RemoteSecretVersion `json:"encryptedSecrets"`
	Policies         []syncPolicyResponse        `json:"policies"`
	Scopes           []syncScopeResponse         `json:"scopes"`
}

type syncScopeResponse = asiri.ScopeAuditMode

type syncPolicyResponse struct {
	ID            string     `json:"id"`
	SubjectType   string     `json:"subjectType"`
	SubjectID     string     `json:"subjectId"`
	ScopePattern  string     `json:"scopePattern"`
	SecretPattern string     `json:"secretPattern"`
	Actions       []string   `json:"actions"`
	ApprovalMode  string     `json:"approvalMode"`
	CreatedAt     time.Time  `json:"createdAt"`
	ExpiresAt     *time.Time `json:"expiresAt,omitempty"`
}

type remoteDevicesResponse struct {
	Devices []remoteDeviceResponse `json:"devices"`
}

type remoteWrappingTargetResponse struct {
	SecretID string                 `json:"secretId"`
	Devices  []remoteDeviceResponse `json:"devices"`
}

type remoteWrappingTargetsResponse struct {
	Targets []remoteWrappingTargetResponse `json:"targets"`
}

type remoteSecretsResponse struct {
	Secrets []remoteSecretRecord `json:"secrets"`
}

type remoteSecretRecord struct {
	ID                string                   `json:"id"`
	OrgID             string                   `json:"orgId"`
	Scope             string                   `json:"scope"`
	Name              string                   `json:"name"`
	Version           int                      `json:"version"`
	Algorithm         string                   `json:"algorithm"`
	Nonce             string                   `json:"nonce"`
	Ciphertext        string                   `json:"ciphertext"`
	AAD               string                   `json:"aad"`
	Status            string                   `json:"status"`
	WrappedKeys       []store.RemoteWrappedKey `json:"wrappedKeys"`
	WrappedRecipients []remoteWrappedRecipient `json:"wrappedRecipients"`
	CreatedByDeviceID string                   `json:"createdByDeviceId"`
	CreatedAt         time.Time                `json:"createdAt"`
}

type remoteWrappedRecipient struct {
	RecipientType string `json:"recipientType"`
	RecipientID   string `json:"recipientId"`
	WrapAlgorithm string `json:"wrapAlgorithm"`
}

type recoveryRecipientReplacement struct {
	SecretID   string                 `json:"secretId"`
	WrappedKey store.RemoteWrappedKey `json:"wrappedKey"`
}

type remoteRecoveryRecipientResponse struct {
	RecipientID          string `json:"recipientId"`
	PublicKey            string `json:"publicKey"`
	PublicKeyFingerprint string `json:"publicKeyFingerprint"`
	Status               string `json:"status"`
}

type visibleRemoteSecretRecord struct {
	ID                     string                   `json:"id"`
	OrgID                  string                   `json:"orgId"`
	WorkspaceSlug          string                   `json:"workspaceSlug"`
	Scope                  string                   `json:"scope"`
	Name                   string                   `json:"name"`
	Version                int                      `json:"version"`
	Status                 string                   `json:"status"`
	CanWrite               bool                     `json:"canWrite"`
	WrappedToCurrentDevice *bool                    `json:"wrappedToCurrentDevice"`
	CurrentDeviceID        string                   `json:"currentDeviceId"`
	WrappedKeys            []store.RemoteWrappedKey `json:"wrappedKeys"`
	PurgeAfter             string                   `json:"purgeAfter"`
}
