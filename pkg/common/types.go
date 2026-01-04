package common

import (
	"fmt"
	"path/filepath"
	"time"

	"github.com/google/uuid"
)

// User represents a system user
type User struct {
	ID        string    `json:"id"`
	Username  string    `json:"username"`
	Email     string    `json:"email"`
	PublicKey string    `json:"public_key"`
	IsAdmin   bool      `json:"is_admin"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Machine represents a target machine
type Machine struct {
	ID         string            `json:"id"`
	Name       string            `json:"name"`
	Hostname   string            `json:"hostname"`
	Port       int               `json:"port"`
	Tags       map[string]string `json:"tags"`
	AgentID    string            `json:"agent_id"`
	IsActive   bool              `json:"is_active"`
	LastSeenAt *time.Time        `json:"last_seen_at,omitempty"`
	CreatedAt  time.Time         `json:"created_at"`
	UpdatedAt  time.Time         `json:"updated_at"`
}

// Session represents an SSH session
type Session struct {
	ID            string     `json:"id"`
	UserID        string     `json:"user_id"`
	MachineID     string     `json:"machine_id"`
	RemoteUser    string     `json:"remote_user"` // User on target machine (root, user, etc)
	StartTime     time.Time  `json:"start_time"`
	EndTime       *time.Time `json:"end_time,omitempty"`
	RecordingPath string     `json:"recording_path"`
	Status        string     `json:"status"` // active, completed, terminated
	CreatedAt     time.Time  `json:"created_at"`
}

// AccessRequest represents a temporary access request
type AccessRequest struct {
	ID          string     `json:"id"`
	UserID      string     `json:"user_id"`
	MachineID   string     `json:"machine_id"`
	RemoteUsers []string   `json:"remote_users"` // Allowed remote users ["root", "user"]
	Reason      string     `json:"reason"`
	Duration    int        `json:"duration"` // in seconds
	Status      string     `json:"status"`   // pending, approved, rejected, expired
	RequestedAt time.Time  `json:"requested_at"`
	ReviewedAt  *time.Time `json:"reviewed_at,omitempty"`
	ReviewedBy  *string    `json:"reviewed_by,omitempty"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
}

// Permission represents a ReBAC permission
type Permission struct {
	ID          string     `json:"id"`
	UserID      string     `json:"user_id"`
	MachineID   string     `json:"machine_id"`
	AccessType  string     `json:"access_type"`  // ssh, scp, both
	RemoteUsers []string   `json:"remote_users"` // Allowed remote users ["root", "user", "postgres"]
	GrantedBy   string     `json:"granted_by"`
	GrantedAt   time.Time  `json:"granted_at"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
}

// AuditLog represents an audit log entry
type AuditLog struct {
	ID        string                 `json:"id"`
	UserID    string                 `json:"user_id"`
	Action    string                 `json:"action"`
	Resource  string                 `json:"resource"`
	Metadata  map[string]interface{} `json:"metadata"`
	IPAddress string                 `json:"ip_address"`
	Timestamp time.Time              `json:"timestamp"`
}

// APIKey represents an API key for authentication
type APIKey struct {
	ID         string     `json:"id"`
	UserID     string     `json:"user_id"`
	Name       string     `json:"name"`       // Human-readable name for the key
	KeyHash    string     `json:"-"`          // SHA256 hash of the actual key
	KeyPrefix  string     `json:"key_prefix"` // First 8 chars for identification
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
}

// HTTPSession represents an HTTP session
type HTTPSession struct {
	ID         string    `json:"id"`
	UserID     string    `json:"user_id"`
	Token      string    `json:"-"`
	IPAddress  string    `json:"ip_address"`
	UserAgent  string    `json:"user_agent"`
	ExpiresAt  time.Time `json:"expires_at"`
	CreatedAt  time.Time `json:"created_at"`
	LastSeenAt time.Time `json:"last_seen_at"`
}

// NewUser creates a new user
func NewUser(username, email, publicKey string, isAdmin bool) *User {
	now := time.Now()
	return &User{
		ID:        uuid.New().String(),
		Username:  username,
		Email:     email,
		PublicKey: publicKey,
		IsAdmin:   isAdmin,
		CreatedAt: now,
		UpdatedAt: now,
	}
}

// NewMachine creates a new machine
func NewMachine(name, hostname string, port int, tags map[string]string) *Machine {
	now := time.Now()
	return &Machine{
		ID:        uuid.New().String(),
		Name:      name,
		Hostname:  hostname,
		Port:      port,
		Tags:      tags,
		IsActive:  false,
		CreatedAt: now,
		UpdatedAt: now,
	}
}

// NewSession creates a new session
func NewSession(userID, machineID, remoteUser, storagePath string) *Session {
	sessionID := uuid.New().String()
	recordingPath := filepath.Join(storagePath, fmt.Sprintf("%s.txt", sessionID))
	return &Session{
		ID:            sessionID,
		UserID:        userID,
		MachineID:     machineID,
		RemoteUser:    remoteUser,
		StartTime:     time.Now(),
		RecordingPath: recordingPath,
		Status:        "active",
		CreatedAt:     time.Now(),
	}
}

// NewAccessRequest creates a new access request
func NewAccessRequest(userID, machineID string, remoteUsers []string, reason string, duration int) *AccessRequest {
	return &AccessRequest{
		ID:          uuid.New().String(),
		UserID:      userID,
		MachineID:   machineID,
		RemoteUsers: remoteUsers,
		Reason:      reason,
		Duration:    duration,
		Status:      "pending",
		RequestedAt: time.Now(),
	}
}

// NewPermission creates a new permission
func NewPermission(userID, machineID, accessType string, remoteUsers []string, grantedBy string, expiresAt *time.Time) *Permission {
	return &Permission{
		ID:          uuid.New().String(),
		UserID:      userID,
		MachineID:   machineID,
		AccessType:  accessType,
		RemoteUsers: remoteUsers,
		GrantedBy:   grantedBy,
		GrantedAt:   time.Now(),
		ExpiresAt:   expiresAt,
	}
}

// NewAuditLog creates a new audit log entry
func NewAuditLog(userID, action, resource, ipAddress string, metadata map[string]interface{}) *AuditLog {
	return &AuditLog{
		ID:        uuid.New().String(),
		UserID:    userID,
		Action:    action,
		Resource:  resource,
		Metadata:  metadata,
		IPAddress: ipAddress,
		Timestamp: time.Now(),
	}
}

// NewAPIKey creates a new API key
func NewAPIKey(userID, name, keyHash, keyPrefix string, expiresAt *time.Time) *APIKey {
	return &APIKey{
		ID:        uuid.New().String(),
		UserID:    userID,
		Name:      name,
		KeyHash:   keyHash,
		KeyPrefix: keyPrefix,
		ExpiresAt: expiresAt,
		CreatedAt: time.Now(),
	}
}

// NewHTTPSession creates a new HTTP session
func NewHTTPSession(userID, token, ipAddress, userAgent string, expiresAt time.Time) *HTTPSession {
	now := time.Now()
	return &HTTPSession{
		ID:         uuid.New().String(),
		UserID:     userID,
		Token:      token,
		IPAddress:  ipAddress,
		UserAgent:  userAgent,
		ExpiresAt:  expiresAt,
		CreatedAt:  now,
		LastSeenAt: now,
	}
}
