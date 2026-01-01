package common

import (
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
	LastSeenAt *time.Time        `json:"last_seen_at,omitempty"` // Pointer to handle NULL
	CreatedAt  time.Time         `json:"created_at"`
	UpdatedAt  time.Time         `json:"updated_at"`
}

// Session represents an SSH session
type Session struct {
	ID            string     `json:"id"`
	UserID        string     `json:"user_id"`
	MachineID     string     `json:"machine_id"`
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
	ID         string     `json:"id"`
	UserID     string     `json:"user_id"`
	MachineID  string     `json:"machine_id"`
	AccessType string     `json:"access_type"` // ssh, scp, both
	GrantedBy  string     `json:"granted_by"`
	GrantedAt  time.Time  `json:"granted_at"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
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
func NewSession(userID, machineID, recordingPath string) *Session {
	return &Session{
		ID:            uuid.New().String(),
		UserID:        userID,
		MachineID:     machineID,
		StartTime:     time.Now(),
		RecordingPath: recordingPath,
		Status:        "active",
		CreatedAt:     time.Now(),
	}
}

// NewAccessRequest creates a new access request
func NewAccessRequest(userID, machineID, reason string, duration int) *AccessRequest {
	return &AccessRequest{
		ID:          uuid.New().String(),
		UserID:      userID,
		MachineID:   machineID,
		Reason:      reason,
		Duration:    duration,
		Status:      "pending",
		RequestedAt: time.Now(),
	}
}

// NewPermission creates a new permission
func NewPermission(userID, machineID, accessType, grantedBy string, expiresAt *time.Time) *Permission {
	return &Permission{
		ID:         uuid.New().String(),
		UserID:     userID,
		MachineID:  machineID,
		AccessType: accessType,
		GrantedBy:  grantedBy,
		GrantedAt:  time.Now(),
		ExpiresAt:  expiresAt,
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
