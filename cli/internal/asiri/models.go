package asiri

import "time"

const ProductName = "Asiri"

type DeviceStatus string

const (
	DeviceTrusted DeviceStatus = "trusted"
	DeviceRevoked DeviceStatus = "revoked"
)

type Device struct {
	ID                  string       `json:"id"`
	Name                string       `json:"name"`
	Kind                string       `json:"kind"`
	Status              DeviceStatus `json:"status"`
	EncryptionPublicKey string       `json:"encryptionPublicKey"`
	SigningPublicKey    string       `json:"signingPublicKey"`
	CreatedAt           time.Time    `json:"createdAt"`
	RevokedAt           *time.Time   `json:"revokedAt,omitempty"`
}

type KeyRef struct {
	Purpose string `json:"purpose"`
	Account string `json:"account"`
}

type ControlPlaneLink struct {
	Origin               string    `json:"origin"`
	WorkspaceID          string    `json:"workspaceId"`
	WorkspaceSlug        string    `json:"workspaceSlug"`
	UserID               string    `json:"userId"`
	WorkloadID           string    `json:"workloadId,omitempty"`
	WorkloadSlug         string    `json:"workloadSlug,omitempty"`
	DeviceID             string    `json:"deviceId"`
	LocalDeviceID        string    `json:"localDeviceId"`
	Source               string    `json:"source,omitempty"`
	AccessTokenAccount   string    `json:"accessTokenAccount"`
	RefreshTokenAccount  string    `json:"refreshTokenAccount"`
	AccessTokenExpiresAt time.Time `json:"accessTokenExpiresAt"`
	RefreshExpiresAt     time.Time `json:"refreshExpiresAt"`
	LinkedAt             time.Time `json:"linkedAt"`
}

type RemoteWorkspaceBinding struct {
	WorkspaceID   string    `json:"workspaceId"`
	WorkspaceSlug string    `json:"workspaceSlug,omitempty"`
	BoundAt       time.Time `json:"boundAt,omitempty"`
}

type RecoveryConfig struct {
	RecipientID          string    `json:"recipientId"`
	PublicKey            string    `json:"publicKey"`
	PublicKeyFingerprint string    `json:"publicKeyFingerprint"`
	CreatedAt            time.Time `json:"createdAt"`
	LastWrappedAt        time.Time `json:"lastWrappedAt,omitempty"`
	WrappedSecretCount   int       `json:"wrappedSecretCount,omitempty"`
}

type SecretVersion struct {
	Version        int       `json:"version"`
	Algorithm      string    `json:"algorithm"`
	Nonce          string    `json:"nonce"`
	AAD            string    `json:"aad"`
	Ciphertext     string    `json:"ciphertext"`
	DataKeyAccount string    `json:"dataKeyAccount,omitempty"`
	Status         string    `json:"status"`
	CreatedAt      time.Time `json:"createdAt"`
}

type Secret struct {
	Scope         string          `json:"scope"`
	Name          string          `json:"name"`
	NameHash      string          `json:"nameHash"`
	Versions      []SecretVersion `json:"versions"`
	ActiveVersion int             `json:"activeVersion"`
	CreatedAt     time.Time       `json:"createdAt"`
	UpdatedAt     time.Time       `json:"updatedAt"`
}

type Policy struct {
	ID            string     `json:"id"`
	Subject       string     `json:"subject"`
	ScopePattern  string     `json:"scopePattern"`
	SecretPattern string     `json:"secretPattern"`
	Actions       []string   `json:"actions"`
	ApprovalMode  string     `json:"approvalMode"`
	CreatedAt     time.Time  `json:"createdAt"`
	ExpiresAt     *time.Time `json:"expiresAt,omitempty"`
}

type AuditEvent struct {
	ID             string            `json:"id"`
	Actor          string            `json:"actor"`
	Action         string            `json:"action"`
	Scope          string            `json:"scope,omitempty"`
	SecretNameHash string            `json:"secretNameHash,omitempty"`
	Result         string            `json:"result"`
	Reason         string            `json:"reason,omitempty"`
	Metadata       map[string]string `json:"metadata,omitempty"`
	CreatedAt      time.Time         `json:"createdAt"`
	RemoteSyncedAt *time.Time        `json:"remoteSyncedAt,omitempty"`
}

type State struct {
	Version        int                               `json:"version"`
	VaultID        string                            `json:"vaultId"`
	RemoteBindings map[string]RemoteWorkspaceBinding `json:"remoteBindings,omitempty"`
	UserID         string                            `json:"userId"`
	LocalDeviceID  string                            `json:"localDeviceId,omitempty"`
	KeyStore       string                            `json:"keyStore"`
	KeyRefs        []KeyRef                          `json:"keyRefs"`
	ControlPlane   *ControlPlaneLink                 `json:"controlPlane,omitempty"`
	Recoveries     map[string]RecoveryConfig         `json:"recoveries,omitempty"`
	Devices        []Device                          `json:"devices"`
	Secrets        map[string]Secret                 `json:"secrets"`
	Policies       []Policy                          `json:"policies"`
	Audit          []AuditEvent                      `json:"audit"`
	CreatedAt      time.Time                         `json:"createdAt"`
	UpdatedAt      time.Time                         `json:"updatedAt"`
}
