package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
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

// GrantPermission grants a user permission to access a machine
func (a *AuthService) GrantPermission(ctx context.Context, userID, machineID, accessType, grantedBy string, duration *time.Duration) error {
	var expiresAt *time.Time
	if duration != nil {
		t := time.Now().Add(*duration)
		expiresAt = &t
	}

	permission := common.NewPermission(userID, machineID, accessType, grantedBy, expiresAt)

	if err := a.store.CreatePermission(ctx, permission); err != nil {
		return fmt.Errorf("failed to create permission: %w", err)
	}

	a.logger.Info("Permission granted: user=%s, machine=%s, type=%s", userID, machineID, accessType)
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
func (a *AuthService) RequestTemporaryAccess(ctx context.Context, userID, machineID, reason string, duration int) (*common.AccessRequest, error) {
	request := common.NewAccessRequest(userID, machineID, reason, duration)

	if err := a.store.CreateAccessRequest(ctx, request); err != nil {
		return nil, fmt.Errorf("failed to create access request: %w", err)
	}

	a.logger.Info("Access request created: user=%s, machine=%s, duration=%d", userID, machineID, duration)
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

	// Grant temporary permission
	duration := time.Duration(request.Duration) * time.Second
	if err := a.GrantPermission(ctx, request.UserID, request.MachineID, "both", reviewerID, &duration); err != nil {
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

	// Encode private key to PEM
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
