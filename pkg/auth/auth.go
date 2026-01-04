package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/zrougamed/orion-belt/pkg/common"
	"github.com/zrougamed/orion-belt/pkg/database"
	"golang.org/x/crypto/ssh"
)

// AuthService handles authentication and authorization
type AuthService struct {
	store  database.Store
	logger *common.Logger
}

// NewAuthService creates a new authentication service
func NewAuthService(store database.Store, logger *common.Logger) *AuthService {
	return &AuthService{
		store:  store,
		logger: logger,
	}
}

// AuthenticateUser authenticates a user with public key
func (a *AuthService) AuthenticateUser(ctx context.Context, username string, publicKey ssh.PublicKey) (*common.User, error) {
	user, err := a.store.GetUserByUsername(ctx, username)
	if err != nil {
		a.logger.Warn("User not found: %s", username)
		return nil, fmt.Errorf("authentication failed")
	}

	// Parse stored public key
	storedKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(user.PublicKey))
	if err != nil {
		a.logger.Error("Failed to parse stored public key for user %s: %v", username, err)
		return nil, fmt.Errorf("authentication failed")
	}

	// Compare keys
	if !keyEquals(publicKey, storedKey) {
		a.logger.Warn("Public key mismatch for user: %s", username)
		return nil, fmt.Errorf("authentication failed")
	}

	a.logger.Info("User authenticated: %s", username)
	return user, nil
}

// CheckPermission checks if a user has permission to access a machine
func (a *AuthService) CheckPermission(ctx context.Context, userID, machineID, accessType string) error {
	// Check if user is admin
	user, err := a.store.GetUser(ctx, userID)
	if err != nil {
		return fmt.Errorf("failed to get user: %w", err)
	}

	if user.IsAdmin {
		a.logger.Debug("Admin access granted for user %s", userID)
		return nil
	}

	// Check ReBAC permissions
	hasPermission, err := a.store.HasPermission(ctx, userID, machineID, accessType)
	if err != nil {
		return fmt.Errorf("failed to check permission: %w", err)
	}

	if !hasPermission {
		a.logger.Warn("Permission denied for user %s on machine %s", userID, machineID)
		return database.ErrPermissionDenied
	}

	a.logger.Debug("Permission granted for user %s on machine %s", userID, machineID)
	return nil
}

// CheckPermissionWithRemoteUser checks if a user has permission with specific remote user
func (a *AuthService) CheckPermissionWithRemoteUser(ctx context.Context, userID, machineID, accessType, remoteUser string) error {
	// Check if user is admin
	user, err := a.store.GetUser(ctx, userID)
	if err != nil {
		return fmt.Errorf("failed to get user: %w", err)
	}

	if user.IsAdmin {
		a.logger.Debug("Admin access granted for user %s", userID)
		return nil
	}

	// Check ReBAC permissions with remote user
	hasPermission, err := a.store.HasPermissionWithRemoteUser(ctx, userID, machineID, accessType, remoteUser)
	if err != nil {
		return fmt.Errorf("failed to check permission: %w", err)
	}

	if !hasPermission {
		a.logger.Warn("Permission denied for user %s on machine %s as remote user %s", userID, machineID, remoteUser)
		return fmt.Errorf("permission denied: %s not allowed to access %s", remoteUser, machineID)
	}

	a.logger.Debug("Permission granted for user %s on machine %s as remote user %s", userID, machineID, remoteUser)
	return nil
}

// GrantPermission grants a user permission to access a machine
func (a *AuthService) GrantPermission(ctx context.Context, userID, machineID, accessType string, remoteUsers []string, grantedBy string, duration *time.Duration) error {
	var expiresAt *time.Time
	if duration != nil {
		t := time.Now().Add(*duration)
		expiresAt = &t
	}

	permission := common.NewPermission(userID, machineID, accessType, remoteUsers, grantedBy, expiresAt)

	if err := a.store.CreatePermission(ctx, permission); err != nil {
		return fmt.Errorf("failed to create permission: %w", err)
	}

	a.logger.Info("Permission granted: user=%s, machine=%s, type=%s, remote_users=%v",
		userID, machineID, accessType, remoteUsers)
	return nil
}

// RevokePermission revokes a user's permission
func (a *AuthService) RevokePermission(ctx context.Context, permissionID string) error {
	if err := a.store.DeletePermission(ctx, permissionID); err != nil {
		return fmt.Errorf("failed to revoke permission: %w", err)
	}

	a.logger.Info("Permission revoked: %s", permissionID)
	return nil
}

// RequestTemporaryAccess creates a temporary access request
func (a *AuthService) RequestTemporaryAccess(ctx context.Context, userID, machineID string, remoteUsers []string, reason string, duration int) (*common.AccessRequest, error) {
	request := common.NewAccessRequest(userID, machineID, remoteUsers, reason, duration)

	if err := a.store.CreateAccessRequest(ctx, request); err != nil {
		return nil, fmt.Errorf("failed to create access request: %w", err)
	}

	a.logger.Info("Access request created: user=%s, machine=%s, remote_users=%v, duration=%d", userID, machineID, remoteUsers, duration)
	return request, nil
}

// ApproveAccessRequest approves a temporary access request
func (a *AuthService) ApproveAccessRequest(ctx context.Context, requestID, reviewerID string) error {
	request, err := a.store.GetAccessRequest(ctx, requestID)
	if err != nil {
		return fmt.Errorf("failed to get access request: %w", err)
	}

	if request.Status != "pending" {
		return fmt.Errorf("request is not pending")
	}

	// Update request status
	now := time.Now()
	expiresAt := now.Add(time.Duration(request.Duration) * time.Second)
	request.Status = "approved"
	request.ReviewedAt = &now
	request.ReviewedBy = &reviewerID
	request.ExpiresAt = &expiresAt

	if err := a.store.UpdateAccessRequest(ctx, request); err != nil {
		return fmt.Errorf("failed to update access request: %w", err)
	}

	// Grant temporary permission with the requested remote users
	duration := time.Duration(request.Duration) * time.Second
	if err := a.GrantPermission(ctx, request.UserID, request.MachineID, "both", request.RemoteUsers, reviewerID, &duration); err != nil {
		return fmt.Errorf("failed to grant permission: %w", err)
	}

	a.logger.Info("Access request approved: %s by %s", requestID, reviewerID)
	return nil
}

// RejectAccessRequest rejects a temporary access request
func (a *AuthService) RejectAccessRequest(ctx context.Context, requestID, reviewerID string) error {
	request, err := a.store.GetAccessRequest(ctx, requestID)
	if err != nil {
		return fmt.Errorf("failed to get access request: %w", err)
	}

	if request.Status != "pending" {
		return fmt.Errorf("request is not pending")
	}

	now := time.Now()
	request.Status = "rejected"
	request.ReviewedAt = &now
	request.ReviewedBy = &reviewerID

	if err := a.store.UpdateAccessRequest(ctx, request); err != nil {
		return fmt.Errorf("failed to update access request: %w", err)
	}

	a.logger.Info("Access request rejected: %s by %s", requestID, reviewerID)
	return nil
}

// GetPendingRequests returns all pending access requests
func (a *AuthService) GetPendingRequests(ctx context.Context) ([]*common.AccessRequest, error) {
	return a.store.ListPendingAccessRequests(ctx)
}

// GenerateSSHKeyPair generates a new SSH key pair
func GenerateSSHKeyPair() (privateKey, publicKey string, err error) {
	// Generate RSA key pair
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate key pair: %w", err)
	}

	// TODO: implement support for ECDSA, Ed25519, Ed448, FIDO
	privateKeyPEM := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}
	privateKeyBytes := pem.EncodeToMemory(privateKeyPEM)

	// Generate public key in SSH format
	sshPublicKey, err := ssh.NewPublicKey(&key.PublicKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate SSH public key: %w", err)
	}
	publicKeyBytes := ssh.MarshalAuthorizedKey(sshPublicKey)

	return string(privateKeyBytes), string(publicKeyBytes), nil
}

// keyEquals compares two SSH public keys
func keyEquals(a, b ssh.PublicKey) bool {
	return string(a.Marshal()) == string(b.Marshal())
}

// GenerateAPIKey creates a new API key for a user
func (a *AuthService) GenerateAPIKey(ctx context.Context, userID, name string, expiresAt *time.Time) (*common.APIKey, string, error) {
	// Generate a cryptographically secure random key
	rawKey, err := generateSecureToken(32)
	if err != nil {
		return nil, "", fmt.Errorf("failed to generate API key: %w", err)
	}

	// Hash the key for storage
	keyHash := hashKey(rawKey)

	// Store only the prefix for display (first 8 chars)
	keyPrefix := rawKey[:8]

	// Create the API key record
	apiKey := common.NewAPIKey(userID, name, keyHash, keyPrefix, expiresAt)

	// Save to database
	if err := a.store.CreateAPIKey(ctx, apiKey); err != nil {
		return nil, "", fmt.Errorf("failed to create API key: %w", err)
	}

	a.logger.Info("API key created: user=%s name=%s prefix=%s", userID, name, keyPrefix)

	// Return the API key record and the raw key
	return apiKey, rawKey, nil
}

// RevokeAPIKey revokes an API key
func (a *AuthService) RevokeAPIKey(ctx context.Context, keyID string) error {
	if err := a.store.RevokeAPIKey(ctx, keyID); err != nil {
		return fmt.Errorf("failed to revoke API key: %w", err)
	}

	a.logger.Info("API key revoked: %s", keyID)
	return nil
}

// ListUserAPIKeys returns all API keys for a user
func (a *AuthService) ListUserAPIKeys(ctx context.Context, userID string) ([]*common.APIKey, error) {
	keys, err := a.store.ListUserAPIKeys(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to list API keys: %w", err)
	}
	return keys, nil
}

// CreateSession creates a new HTTP session for a user
func (a *AuthService) CreateSession(ctx context.Context, userID, ipAddress, userAgent string, duration time.Duration) (*common.HTTPSession, string, error) {
	// Generate a cryptographically secure session token
	rawToken, err := generateSecureToken(32)
	if err != nil {
		return nil, "", fmt.Errorf("failed to generate session token: %w", err)
	}

	// Hash the token for storage
	tokenHash := hashKey(rawToken)

	// Calculate expiration
	expiresAt := time.Now().Add(duration)

	// Create the session record
	session := common.NewHTTPSession(userID, tokenHash, ipAddress, userAgent, expiresAt)

	// Save to database
	if err := a.store.CreateHTTPSession(ctx, session); err != nil {
		return nil, "", fmt.Errorf("failed to create session: %w", err)
	}

	a.logger.Info("HTTP session created: user=%s ip=%s duration=%v", userID, ipAddress, duration)

	return session, rawToken, nil
}

// DestroySession destroys an HTTP session
func (a *AuthService) DestroySession(ctx context.Context, sessionID string) error {
	if err := a.store.DeleteHTTPSession(ctx, sessionID); err != nil {
		return fmt.Errorf("failed to destroy session: %w", err)
	}

	a.logger.Info("HTTP session destroyed: %s", sessionID)
	return nil
}

// CleanupExpiredSessions removes all expired HTTP sessions
func (a *AuthService) CleanupExpiredSessions(ctx context.Context) error {
	if err := a.store.DeleteExpiredHTTPSessions(ctx); err != nil {
		return fmt.Errorf("failed to cleanup expired sessions: %w", err)
	}
	return nil
}

// generateSecureToken generates a cryptographically secure random token
func generateSecureToken(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	// Use base64 URL encoding (safe for URLs and headers)
	return base64.URLEncoding.EncodeToString(bytes), nil
}

// hashKey creates a SHA256 hash of a key/token
func hashKey(key string) string {
	hash := sha256.Sum256([]byte(key))
	return hex.EncodeToString(hash[:])
}

// ValidateAPIKeyFormat checks if an API key has the correct format
func ValidateAPIKeyFormat(key string) bool {
	// Decode from base64
	decoded, err := base64.URLEncoding.DecodeString(key)
	if err != nil {
		return false
	}
	// Should be 32 bytes
	return len(decoded) == 32
}
