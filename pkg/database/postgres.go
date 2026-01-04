package database

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/lib/pq"
	_ "github.com/lib/pq"
	"github.com/zrougamed/orion-belt/pkg/common"
)

func init() {
	Register("postgres", NewPostgresStore)
}

// PostgresStore implements Store interface for PostgreSQL
type PostgresStore struct {
	db *sql.DB
}

// NewPostgresStore creates a new PostgreSQL store
func NewPostgresStore(connectionString string) (Store, error) {
	db, err := sql.Open("postgres", connectionString)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrConnectionFailed, err)
	}

	return &PostgresStore{db: db}, nil
}

// Connect establishes database connection
func (s *PostgresStore) Connect(ctx context.Context) error {
	return s.db.PingContext(ctx)
}

// Close closes the database connection
func (s *PostgresStore) Close() error {
	return s.db.Close()
}

// Ping checks database connectivity
func (s *PostgresStore) Ping(ctx context.Context) error {
	return s.db.PingContext(ctx)
}

// Migrate runs database migrations
func (s *PostgresStore) Migrate(ctx context.Context) error {
	migrations := []string{
		`CREATE TABLE IF NOT EXISTS users (
			id VARCHAR(36) PRIMARY KEY,
			username VARCHAR(255) UNIQUE NOT NULL,
			email VARCHAR(255) NOT NULL,
			public_key TEXT NOT NULL,
			is_admin BOOLEAN DEFAULT FALSE,
			created_at TIMESTAMP NOT NULL,
			updated_at TIMESTAMP NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS machines (
			id VARCHAR(36) PRIMARY KEY,
			name VARCHAR(255) UNIQUE NOT NULL,
			hostname VARCHAR(255) NOT NULL,
			port INTEGER NOT NULL,
			tags JSONB,
			agent_id VARCHAR(36),
			is_active BOOLEAN DEFAULT FALSE,
			last_seen_at TIMESTAMP,
			created_at TIMESTAMP NOT NULL,
			updated_at TIMESTAMP NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS sessions (
			id VARCHAR(36) PRIMARY KEY,
			user_id VARCHAR(36) NOT NULL REFERENCES users(id),
			machine_id VARCHAR(36) NOT NULL REFERENCES machines(id),
			remote_user VARCHAR(255) NOT NULL,
			start_time TIMESTAMP NOT NULL,
			end_time TIMESTAMP,
			recording_path TEXT NOT NULL,
			status VARCHAR(50) NOT NULL,
			created_at TIMESTAMP NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS access_requests (
			id VARCHAR(36) PRIMARY KEY,
			user_id VARCHAR(36) NOT NULL REFERENCES users(id),
			machine_id VARCHAR(36) NOT NULL REFERENCES machines(id),
			remote_users TEXT[] NOT NULL,
			reason TEXT NOT NULL,
			duration INTEGER NOT NULL,
			status VARCHAR(50) NOT NULL,
			requested_at TIMESTAMP NOT NULL,
			reviewed_at TIMESTAMP,
			reviewed_by VARCHAR(36) REFERENCES users(id),
			expires_at TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS permissions (
			id VARCHAR(36) PRIMARY KEY,
			user_id VARCHAR(36) NOT NULL REFERENCES users(id),
			machine_id VARCHAR(36) NOT NULL REFERENCES machines(id),
			access_type VARCHAR(50) NOT NULL,
			remote_users TEXT[] NOT NULL,
			granted_by VARCHAR(36) NOT NULL REFERENCES users(id),
			granted_at TIMESTAMP NOT NULL,
			expires_at TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS audit_logs (
			id VARCHAR(36) PRIMARY KEY,
			user_id VARCHAR(36) REFERENCES users(id),
			action VARCHAR(255) NOT NULL,
			resource VARCHAR(255) NOT NULL,
			metadata JSONB,
			ip_address VARCHAR(45) NOT NULL,
			timestamp TIMESTAMP NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS api_keys (
			id VARCHAR(36) PRIMARY KEY,
			user_id VARCHAR(36) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			name VARCHAR(255) NOT NULL,
			key_hash VARCHAR(64) NOT NULL UNIQUE,
			key_prefix VARCHAR(16) NOT NULL,
			last_used_at TIMESTAMP,
			expires_at TIMESTAMP,
			created_at TIMESTAMP NOT NULL,
			revoked_at TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS http_sessions (
			id VARCHAR(36) PRIMARY KEY,
			user_id VARCHAR(36) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			token_hash VARCHAR(64) NOT NULL UNIQUE,
			ip_address VARCHAR(45) NOT NULL,
			user_agent TEXT,
			expires_at TIMESTAMP NOT NULL,
			created_at TIMESTAMP NOT NULL,
			last_seen_at TIMESTAMP NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id)`,
		`CREATE INDEX IF NOT EXISTS idx_sessions_machine_id ON sessions(machine_id)`,
		`CREATE INDEX IF NOT EXISTS idx_sessions_status ON sessions(status)`,
		`CREATE INDEX IF NOT EXISTS idx_permissions_user_id ON permissions(user_id)`,
		`CREATE INDEX IF NOT EXISTS idx_permissions_machine_id ON permissions(machine_id)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id ON audit_logs(user_id)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp ON audit_logs(timestamp)`,
		`CREATE INDEX IF NOT EXISTS idx_api_keys_user_id ON api_keys(user_id)`,
		`CREATE INDEX IF NOT EXISTS idx_api_keys_key_hash ON api_keys(key_hash)`,
		`CREATE INDEX IF NOT EXISTS idx_api_keys_expires_at ON api_keys(expires_at)`,
		`CREATE INDEX IF NOT EXISTS idx_http_sessions_user_id ON http_sessions(user_id)`,
		`CREATE INDEX IF NOT EXISTS idx_http_sessions_token_hash ON http_sessions(token_hash)`,
		`CREATE INDEX IF NOT EXISTS idx_http_sessions_expires_at ON http_sessions(expires_at)`,
	}

	for _, migration := range migrations {
		if _, err := s.db.ExecContext(ctx, migration); err != nil {
			return fmt.Errorf("%w: %v", ErrMigrationFailed, err)
		}
	}

	return nil
}

// CreateUser creates a new user
func (s *PostgresStore) CreateUser(ctx context.Context, user *common.User) error {
	query := `INSERT INTO users (id, username, email, public_key, is_admin, created_at, updated_at)
			  VALUES ($1, $2, $3, $4, $5, $6, $7)`

	_, err := s.db.ExecContext(ctx, query,
		user.ID, user.Username, user.Email, user.PublicKey,
		user.IsAdmin, user.CreatedAt, user.UpdatedAt)

	if err != nil {
		return fmt.Errorf("failed to create user: %w", err)
	}
	return nil
}

// GetUser retrieves a user by ID
func (s *PostgresStore) GetUser(ctx context.Context, id string) (*common.User, error) {
	query := `SELECT id, username, email, public_key, is_admin, created_at, updated_at
			  FROM users WHERE id = $1`

	user := &common.User{}
	err := s.db.QueryRowContext(ctx, query, id).Scan(
		&user.ID, &user.Username, &user.Email, &user.PublicKey,
		&user.IsAdmin, &user.CreatedAt, &user.UpdatedAt)

	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}
	return user, nil
}

// GetUserByUsername retrieves a user by username
func (s *PostgresStore) GetUserByUsername(ctx context.Context, username string) (*common.User, error) {
	query := `SELECT id, username, email, public_key, is_admin, created_at, updated_at
			  FROM users WHERE username = $1`

	user := &common.User{}
	err := s.db.QueryRowContext(ctx, query, username).Scan(
		&user.ID, &user.Username, &user.Email, &user.PublicKey,
		&user.IsAdmin, &user.CreatedAt, &user.UpdatedAt)

	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}
	return user, nil
}

// UpdateUser updates an existing user
func (s *PostgresStore) UpdateUser(ctx context.Context, user *common.User) error {
	query := `UPDATE users SET email = $1, public_key = $2, is_admin = $3, updated_at = $4
			  WHERE id = $5`

	result, err := s.db.ExecContext(ctx, query,
		user.Email, user.PublicKey, user.IsAdmin, time.Now(), user.ID)

	if err != nil {
		return fmt.Errorf("failed to update user: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return ErrNotFound
	}
	return nil
}

// DeleteUser deletes a user
func (s *PostgresStore) DeleteUser(ctx context.Context, id string) error {
	query := `DELETE FROM users WHERE id = $1`
	result, err := s.db.ExecContext(ctx, query, id)

	if err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return ErrNotFound
	}
	return nil
}

// ListUsers lists users with pagination
func (s *PostgresStore) ListUsers(ctx context.Context, limit, offset int) ([]*common.User, error) {
	query := `SELECT id, username, email, public_key, is_admin, created_at, updated_at
			  FROM users ORDER BY created_at DESC LIMIT $1 OFFSET $2`

	rows, err := s.db.QueryContext(ctx, query, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to list users: %w", err)
	}
	defer rows.Close()

	var users []*common.User
	for rows.Next() {
		user := &common.User{}
		if err := rows.Scan(&user.ID, &user.Username, &user.Email, &user.PublicKey,
			&user.IsAdmin, &user.CreatedAt, &user.UpdatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan user: %w", err)
		}
		users = append(users, user)
	}

	return users, nil
}

// CreateMachine creates a new machine
func (s *PostgresStore) CreateMachine(ctx context.Context, machine *common.Machine) error {
	tags, _ := json.Marshal(machine.Tags)
	query := `INSERT INTO machines (id, name, hostname, port, tags, agent_id, is_active, last_seen_at, created_at, updated_at)
			  VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`

	_, err := s.db.ExecContext(ctx, query,
		machine.ID, machine.Name, machine.Hostname, machine.Port, tags,
		machine.AgentID, machine.IsActive, machine.LastSeenAt,
		machine.CreatedAt, machine.UpdatedAt)

	if err != nil {
		return fmt.Errorf("failed to create machine: %w", err)
	}
	return nil
}

// GetMachine retrieves a machine by ID
func (s *PostgresStore) GetMachine(ctx context.Context, id string) (*common.Machine, error) {
	query := `SELECT id, name, hostname, port, tags, agent_id, is_active, last_seen_at, created_at, updated_at
			  FROM machines WHERE id = $1`

	machine := &common.Machine{}
	var tags []byte
	err := s.db.QueryRowContext(ctx, query, id).Scan(
		&machine.ID, &machine.Name, &machine.Hostname, &machine.Port, &tags,
		&machine.AgentID, &machine.IsActive, &machine.LastSeenAt,
		&machine.CreatedAt, &machine.UpdatedAt)

	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get machine: %w", err)
	}

	json.Unmarshal(tags, &machine.Tags)
	return machine, nil
}

// GetMachineByName retrieves a machine by name
func (s *PostgresStore) GetMachineByName(ctx context.Context, name string) (*common.Machine, error) {
	query := `SELECT id, name, hostname, port, tags, agent_id, is_active, last_seen_at, created_at, updated_at
			  FROM machines WHERE name = $1`

	machine := &common.Machine{}
	var tags []byte
	err := s.db.QueryRowContext(ctx, query, name).Scan(
		&machine.ID, &machine.Name, &machine.Hostname, &machine.Port, &tags,
		&machine.AgentID, &machine.IsActive, &machine.LastSeenAt,
		&machine.CreatedAt, &machine.UpdatedAt)

	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get machine: %w", err)
	}

	json.Unmarshal(tags, &machine.Tags)
	return machine, nil
}

// UpdateMachine updates an existing machine
func (s *PostgresStore) UpdateMachine(ctx context.Context, machine *common.Machine) error {
	tags, _ := json.Marshal(machine.Tags)
	query := `UPDATE machines SET hostname = $1, port = $2, tags = $3, agent_id = $4,
			  is_active = $5, last_seen_at = $6, updated_at = $7 WHERE id = $8`

	result, err := s.db.ExecContext(ctx, query,
		machine.Hostname, machine.Port, tags, machine.AgentID,
		machine.IsActive, machine.LastSeenAt, time.Now(), machine.ID)

	if err != nil {
		return fmt.Errorf("failed to update machine: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return ErrNotFound
	}
	return nil
}

// DeleteMachine deletes a machine
func (s *PostgresStore) DeleteMachine(ctx context.Context, id string) error {
	query := `DELETE FROM machines WHERE id = $1`
	result, err := s.db.ExecContext(ctx, query, id)

	if err != nil {
		return fmt.Errorf("failed to delete machine: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return ErrNotFound
	}
	return nil
}

// ListMachines lists machines with pagination
func (s *PostgresStore) ListMachines(ctx context.Context, limit, offset int) ([]*common.Machine, error) {
	query := `SELECT id, name, hostname, port, tags, agent_id, is_active, last_seen_at, created_at, updated_at
			  FROM machines ORDER BY created_at DESC LIMIT $1 OFFSET $2`

	rows, err := s.db.QueryContext(ctx, query, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to list machines: %w", err)
	}
	defer rows.Close()

	var machines []*common.Machine
	for rows.Next() {
		machine := &common.Machine{}
		var tags []byte
		if err := rows.Scan(&machine.ID, &machine.Name, &machine.Hostname, &machine.Port, &tags,
			&machine.AgentID, &machine.IsActive, &machine.LastSeenAt,
			&machine.CreatedAt, &machine.UpdatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan machine: %w", err)
		}
		json.Unmarshal(tags, &machine.Tags)
		machines = append(machines, machine)
	}

	return machines, nil
}

// ListActiveMachines lists active machines
func (s *PostgresStore) ListActiveMachines(ctx context.Context) ([]*common.Machine, error) {
	query := `SELECT id, name, hostname, port, tags, agent_id, is_active, last_seen_at, created_at, updated_at
			  FROM machines WHERE is_active = true ORDER BY name`

	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to list active machines: %w", err)
	}
	defer rows.Close()

	var machines []*common.Machine
	for rows.Next() {
		machine := &common.Machine{}
		var tags []byte
		if err := rows.Scan(&machine.ID, &machine.Name, &machine.Hostname, &machine.Port, &tags,
			&machine.AgentID, &machine.IsActive, &machine.LastSeenAt,
			&machine.CreatedAt, &machine.UpdatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan machine: %w", err)
		}
		json.Unmarshal(tags, &machine.Tags)
		machines = append(machines, machine)
	}

	return machines, nil
}

// CreateSession creates a new session
func (s *PostgresStore) CreateSession(ctx context.Context, session *common.Session) error {
	query := `INSERT INTO sessions (id, user_id, machine_id, remote_user, start_time, end_time, recording_path, status, created_at)
			  VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`

	_, err := s.db.ExecContext(ctx, query,
		session.ID, session.UserID, session.MachineID, session.RemoteUser,
		session.StartTime, session.EndTime, session.RecordingPath,
		session.Status, session.CreatedAt)

	if err != nil {
		return fmt.Errorf("failed to create session: %w", err)
	}
	return nil
}

// GetSession retrieves a session by ID
func (s *PostgresStore) GetSession(ctx context.Context, id string) (*common.Session, error) {
	query := `SELECT id, user_id, machine_id, start_time, end_time, recording_path, status, created_at
			  FROM sessions WHERE id = $1`

	session := &common.Session{}
	err := s.db.QueryRowContext(ctx, query, id).Scan(
		&session.ID, &session.UserID, &session.MachineID,
		&session.StartTime, &session.EndTime, &session.RecordingPath,
		&session.Status, &session.CreatedAt)

	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get session: %w", err)
	}
	return session, nil
}

// UpdateSession updates an existing session
func (s *PostgresStore) UpdateSession(ctx context.Context, session *common.Session) error {
	query := `UPDATE sessions SET end_time = $1, status = $2 WHERE id = $3`

	result, err := s.db.ExecContext(ctx, query, session.EndTime, session.Status, session.ID)

	if err != nil {
		return fmt.Errorf("failed to update session: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return ErrNotFound
	}
	return nil
}

// ListActiveSessions lists all active sessions
func (s *PostgresStore) ListActiveSessions(ctx context.Context) ([]*common.Session, error) {
	query := `SELECT id, user_id, machine_id, start_time, end_time, recording_path, status, created_at
			  FROM sessions WHERE status = 'active' ORDER BY start_time DESC`

	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to list active sessions: %w", err)
	}
	defer rows.Close()

	var sessions []*common.Session
	for rows.Next() {
		session := &common.Session{}
		if err := rows.Scan(&session.ID, &session.UserID, &session.MachineID,
			&session.StartTime, &session.EndTime, &session.RecordingPath,
			&session.Status, &session.CreatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan session: %w", err)
		}
		sessions = append(sessions, session)
	}

	return sessions, nil
}

// ListUserSessions lists sessions for a specific user
func (s *PostgresStore) ListUserSessions(ctx context.Context, userID string, limit, offset int) ([]*common.Session, error) {
	query := `SELECT id, user_id, machine_id, start_time, end_time, recording_path, status, created_at
			  FROM sessions WHERE user_id = $1 ORDER BY start_time DESC LIMIT $2 OFFSET $3`

	rows, err := s.db.QueryContext(ctx, query, userID, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to list user sessions: %w", err)
	}
	defer rows.Close()

	var sessions []*common.Session
	for rows.Next() {
		session := &common.Session{}
		if err := rows.Scan(&session.ID, &session.UserID, &session.MachineID,
			&session.StartTime, &session.EndTime, &session.RecordingPath,
			&session.Status, &session.CreatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan session: %w", err)
		}
		sessions = append(sessions, session)
	}

	return sessions, nil
}

// EndSession marks a session as ended
func (s *PostgresStore) EndSession(ctx context.Context, id string, endTime time.Time) error {
	query := `UPDATE sessions SET end_time = $1, status = 'completed' WHERE id = $2`

	result, err := s.db.ExecContext(ctx, query, endTime, id)

	if err != nil {
		return fmt.Errorf("failed to end session: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return ErrNotFound
	}
	return nil
}

// CreateAccessRequest creates a new access request
func (s *PostgresStore) CreateAccessRequest(ctx context.Context, request *common.AccessRequest) error {
	query := `INSERT INTO access_requests (id, user_id, machine_id, reason, duration, status, requested_at, reviewed_at, reviewed_by, expires_at)
			  VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`

	_, err := s.db.ExecContext(ctx, query,
		request.ID, request.UserID, request.MachineID, request.Reason,
		request.Duration, request.Status, request.RequestedAt,
		request.ReviewedAt, request.ReviewedBy, request.ExpiresAt)

	if err != nil {
		return fmt.Errorf("failed to create access request: %w", err)
	}
	return nil
}

// GetAccessRequest retrieves an access request by ID
func (s *PostgresStore) GetAccessRequest(ctx context.Context, id string) (*common.AccessRequest, error) {
	query := `SELECT id, user_id, machine_id, reason, duration, status, requested_at, reviewed_at, reviewed_by, expires_at
			  FROM access_requests WHERE id = $1`

	request := &common.AccessRequest{}
	err := s.db.QueryRowContext(ctx, query, id).Scan(
		&request.ID, &request.UserID, &request.MachineID, &request.Reason,
		&request.Duration, &request.Status, &request.RequestedAt,
		&request.ReviewedAt, &request.ReviewedBy, &request.ExpiresAt)

	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get access request: %w", err)
	}
	return request, nil
}

// UpdateAccessRequest updates an existing access request
func (s *PostgresStore) UpdateAccessRequest(ctx context.Context, request *common.AccessRequest) error {
	query := `UPDATE access_requests SET status = $1, reviewed_at = $2, reviewed_by = $3, expires_at = $4
			  WHERE id = $5`

	result, err := s.db.ExecContext(ctx, query,
		request.Status, request.ReviewedAt, request.ReviewedBy,
		request.ExpiresAt, request.ID)

	if err != nil {
		return fmt.Errorf("failed to update access request: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return ErrNotFound
	}
	return nil
}

// ListPendingAccessRequests lists all pending access requests
func (s *PostgresStore) ListPendingAccessRequests(ctx context.Context) ([]*common.AccessRequest, error) {
	query := `SELECT id, user_id, machine_id, reason, duration, status, requested_at, reviewed_at, reviewed_by, expires_at
			  FROM access_requests WHERE status = 'pending' ORDER BY requested_at DESC`

	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to list pending access requests: %w", err)
	}
	defer rows.Close()

	var requests []*common.AccessRequest
	for rows.Next() {
		request := &common.AccessRequest{}
		if err := rows.Scan(&request.ID, &request.UserID, &request.MachineID, &request.Reason,
			&request.Duration, &request.Status, &request.RequestedAt,
			&request.ReviewedAt, &request.ReviewedBy, &request.ExpiresAt); err != nil {
			return nil, fmt.Errorf("failed to scan access request: %w", err)
		}
		requests = append(requests, request)
	}

	return requests, nil
}

// ListUserAccessRequests lists access requests for a specific user
func (s *PostgresStore) ListUserAccessRequests(ctx context.Context, userID string, limit, offset int) ([]*common.AccessRequest, error) {
	query := `SELECT id, user_id, machine_id, reason, duration, status, requested_at, reviewed_at, reviewed_by, expires_at
			  FROM access_requests WHERE user_id = $1 ORDER BY requested_at DESC LIMIT $2 OFFSET $3`

	rows, err := s.db.QueryContext(ctx, query, userID, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to list user access requests: %w", err)
	}
	defer rows.Close()

	var requests []*common.AccessRequest
	for rows.Next() {
		request := &common.AccessRequest{}
		if err := rows.Scan(&request.ID, &request.UserID, &request.MachineID, &request.Reason,
			&request.Duration, &request.Status, &request.RequestedAt,
			&request.ReviewedAt, &request.ReviewedBy, &request.ExpiresAt); err != nil {
			return nil, fmt.Errorf("failed to scan access request: %w", err)
		}
		requests = append(requests, request)
	}

	return requests, nil
}

// CreatePermission with remote_users array
func (s *PostgresStore) CreatePermission(ctx context.Context, permission *common.Permission) error {
	query := `INSERT INTO permissions (id, user_id, machine_id, access_type, remote_users, granted_by, granted_at, expires_at)
			  VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`

	// Convert []string to PostgreSQL array
	remoteUsers := pq.Array(permission.RemoteUsers)

	_, err := s.db.ExecContext(ctx, query,
		permission.ID, permission.UserID, permission.MachineID,
		permission.AccessType, remoteUsers, permission.GrantedBy,
		permission.GrantedAt, permission.ExpiresAt)

	if err != nil {
		return fmt.Errorf("failed to create permission: %w", err)
	}
	return nil
}

// GetPermission - scan remote_users array
func (s *PostgresStore) GetPermission(ctx context.Context, id string) (*common.Permission, error) {
	query := `SELECT id, user_id, machine_id, access_type, remote_users, granted_by, granted_at, expires_at
			  FROM permissions WHERE id = $1`

	permission := &common.Permission{}
	var remoteUsers pq.StringArray

	err := s.db.QueryRowContext(ctx, query, id).Scan(
		&permission.ID, &permission.UserID, &permission.MachineID,
		&permission.AccessType, &remoteUsers, &permission.GrantedBy,
		&permission.GrantedAt, &permission.ExpiresAt)

	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get permission: %w", err)
	}

	permission.RemoteUsers = []string(remoteUsers)
	return permission, nil
}

// Check permission with specific remote user
func (s *PostgresStore) HasPermissionWithRemoteUser(ctx context.Context, userID, machineID, accessType, remoteUser string) (bool, error) {
	query := `SELECT COUNT(*) FROM permissions
			  WHERE user_id = $1 AND machine_id = $2 AND
			  (access_type = $3 OR access_type = 'both') AND
			  $4 = ANY(remote_users) AND
			  (expires_at IS NULL OR expires_at > NOW())`

	var count int
	err := s.db.QueryRowContext(ctx, query, userID, machineID, accessType, remoteUser).Scan(&count)

	if err != nil {
		return false, fmt.Errorf("failed to check permission: %w", err)
	}

	return count > 0, nil
}

// DeletePermission deletes a permission
func (s *PostgresStore) DeletePermission(ctx context.Context, id string) error {
	query := `DELETE FROM permissions WHERE id = $1`
	result, err := s.db.ExecContext(ctx, query, id)

	if err != nil {
		return fmt.Errorf("failed to delete permission: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return ErrNotFound
	}
	return nil
}

// ListUserPermissions lists permissions for a specific user
func (s *PostgresStore) ListUserPermissions(ctx context.Context, userID string) ([]*common.Permission, error) {
	query := `SELECT id, user_id, machine_id, access_type, granted_by, granted_at, expires_at
			  FROM permissions WHERE user_id = $1 AND (expires_at IS NULL OR expires_at > NOW())
			  ORDER BY granted_at DESC`

	rows, err := s.db.QueryContext(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to list user permissions: %w", err)
	}
	defer rows.Close()

	var permissions []*common.Permission
	for rows.Next() {
		permission := &common.Permission{}
		if err := rows.Scan(&permission.ID, &permission.UserID, &permission.MachineID,
			&permission.AccessType, &permission.GrantedBy, &permission.GrantedAt,
			&permission.ExpiresAt); err != nil {
			return nil, fmt.Errorf("failed to scan permission: %w", err)
		}
		permissions = append(permissions, permission)
	}

	return permissions, nil
}

// ListMachinePermissions lists permissions for a specific machine
func (s *PostgresStore) ListMachinePermissions(ctx context.Context, machineID string) ([]*common.Permission, error) {
	query := `SELECT id, user_id, machine_id, access_type, granted_by, granted_at, expires_at
			  FROM permissions WHERE machine_id = $1 AND (expires_at IS NULL OR expires_at > NOW())
			  ORDER BY granted_at DESC`

	rows, err := s.db.QueryContext(ctx, query, machineID)
	if err != nil {
		return nil, fmt.Errorf("failed to list machine permissions: %w", err)
	}
	defer rows.Close()

	var permissions []*common.Permission
	for rows.Next() {
		permission := &common.Permission{}
		if err := rows.Scan(&permission.ID, &permission.UserID, &permission.MachineID,
			&permission.AccessType, &permission.GrantedBy, &permission.GrantedAt,
			&permission.ExpiresAt); err != nil {
			return nil, fmt.Errorf("failed to scan permission: %w", err)
		}
		permissions = append(permissions, permission)
	}

	return permissions, nil
}

// HasPermission checks if a user has permission to access a machine
func (s *PostgresStore) HasPermission(ctx context.Context, userID, machineID, accessType string) (bool, error) {
	query := `SELECT COUNT(*) FROM permissions
			  WHERE user_id = $1 AND machine_id = $2 AND
			  (access_type = $3 OR access_type = 'both') AND
			  (expires_at IS NULL OR expires_at > NOW())`

	var count int
	err := s.db.QueryRowContext(ctx, query, userID, machineID, accessType).Scan(&count)

	if err != nil {
		return false, fmt.Errorf("failed to check permission: %w", err)
	}

	return count > 0, nil
}

// CreateAuditLog creates a new audit log entry
func (s *PostgresStore) CreateAuditLog(ctx context.Context, log *common.AuditLog) error {
	metadata, _ := json.Marshal(log.Metadata)
	query := `INSERT INTO audit_logs (id, user_id, action, resource, metadata, ip_address, timestamp)
			  VALUES ($1, $2, $3, $4, $5, $6, $7)`

	_, err := s.db.ExecContext(ctx, query,
		log.ID, log.UserID, log.Action, log.Resource,
		metadata, log.IPAddress, log.Timestamp)

	if err != nil {
		return fmt.Errorf("failed to create audit log: %w", err)
	}
	return nil
}

// ListAuditLogs lists audit logs with pagination and filters
func (s *PostgresStore) ListAuditLogs(ctx context.Context, limit, offset int, filters map[string]interface{}) ([]*common.AuditLog, error) {
	query := `SELECT id, user_id, action, resource, metadata, ip_address, timestamp
			  FROM audit_logs ORDER BY timestamp DESC LIMIT $1 OFFSET $2`

	rows, err := s.db.QueryContext(ctx, query, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to list audit logs: %w", err)
	}
	defer rows.Close()

	var logs []*common.AuditLog
	for rows.Next() {
		log := &common.AuditLog{}
		var metadata []byte
		if err := rows.Scan(&log.ID, &log.UserID, &log.Action, &log.Resource,
			&metadata, &log.IPAddress, &log.Timestamp); err != nil {
			return nil, fmt.Errorf("failed to scan audit log: %w", err)
		}
		json.Unmarshal(metadata, &log.Metadata)
		logs = append(logs, log)
	}

	return logs, nil
}

// GetSessionDetails retrieves a session with user and machine names
func (s *PostgresStore) GetSessionDetails(ctx context.Context, id string) (map[string]interface{}, error) {
	query := `
        SELECT 
            s.id, s.start_time, s.end_time, s.recording_path, s.status,
            u.username, u.email,
            m.name as machine_name, m.hostname
        FROM sessions s
        JOIN users u ON s.user_id = u.id
        JOIN machines m ON s.machine_id = m.id
        WHERE s.id = $1`

	var startTime time.Time
	var endTime sql.NullTime
	var idStr, path, status, username, email, mName, mHost string

	err := s.db.QueryRowContext(ctx, query, id).Scan(
		&idStr, &startTime, &endTime, &path, &status,
		&username, &email, &mName, &mHost,
	)

	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get session details: %w", err)
	}

	return map[string]interface{}{
		"id":             idStr,
		"username":       username,
		"machine_name":   mName,
		"hostname":       mHost,
		"start_time":     startTime,
		"end_time":       endTime.Time,
		"recording_path": path,
		"status":         status,
	}, nil
}

func (s *PostgresStore) ListUserSessionsWithMachineNames(ctx context.Context, userID string, limit, offset int) ([]map[string]interface{}, error) {
	query := `
        SELECT s.id, s.start_time, s.status, m.name
        FROM sessions s
        JOIN machines m ON s.machine_id = m.id
        WHERE s.user_id = $1 
        ORDER BY s.start_time DESC LIMIT $2 OFFSET $3`

	rows, err := s.db.QueryContext(ctx, query, userID, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []map[string]interface{}
	for rows.Next() {
		var id, status, machineName string
		var start time.Time
		rows.Scan(&id, &start, &status, &machineName)
		results = append(results, map[string]interface{}{
			"id":           id,
			"start_time":   start,
			"status":       status,
			"machine_name": machineName,
		})
	}
	return results, nil
}

// CreateAPIKey creates a new API key
func (s *PostgresStore) CreateAPIKey(ctx context.Context, key *common.APIKey) error {
	query := `
		INSERT INTO api_keys (id, user_id, name, key_hash, key_prefix, expires_at, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`
	_, err := s.db.ExecContext(ctx, query,
		key.ID, key.UserID, key.Name, key.KeyHash, key.KeyPrefix, key.ExpiresAt, key.CreatedAt)
	return err
}

// GetAPIKey retrieves an API key by ID
func (s *PostgresStore) GetAPIKey(ctx context.Context, id string) (*common.APIKey, error) {
	query := `
		SELECT id, user_id, name, key_hash, key_prefix, last_used_at, expires_at, created_at, revoked_at
		FROM api_keys
		WHERE id = $1
	`

	key := &common.APIKey{}
	err := s.db.QueryRowContext(ctx, query, id).Scan(
		&key.ID, &key.UserID, &key.Name, &key.KeyHash, &key.KeyPrefix,
		&key.LastUsedAt, &key.ExpiresAt, &key.CreatedAt, &key.RevokedAt,
	)

	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	return key, err
}

// GetAPIKeyByHash retrieves an API key by its hash
func (s *PostgresStore) GetAPIKeyByHash(ctx context.Context, keyHash string) (*common.APIKey, error) {
	query := `
		SELECT id, user_id, name, key_hash, key_prefix, last_used_at, expires_at, created_at, revoked_at
		FROM api_keys
		WHERE key_hash = $1 AND revoked_at IS NULL
	`

	key := &common.APIKey{}
	err := s.db.QueryRowContext(ctx, query, keyHash).Scan(
		&key.ID, &key.UserID, &key.Name, &key.KeyHash, &key.KeyPrefix,
		&key.LastUsedAt, &key.ExpiresAt, &key.CreatedAt, &key.RevokedAt,
	)

	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	return key, err
}

// ListUserAPIKeys retrieves all API keys for a user
func (s *PostgresStore) ListUserAPIKeys(ctx context.Context, userID string) ([]*common.APIKey, error) {
	query := `
		SELECT id, user_id, name, key_hash, key_prefix, last_used_at, expires_at, created_at, revoked_at
		FROM api_keys
		WHERE user_id = $1
		ORDER BY created_at DESC
	`

	rows, err := s.db.QueryContext(ctx, query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var keys []*common.APIKey
	for rows.Next() {
		key := &common.APIKey{}
		err := rows.Scan(
			&key.ID, &key.UserID, &key.Name, &key.KeyHash, &key.KeyPrefix,
			&key.LastUsedAt, &key.ExpiresAt, &key.CreatedAt, &key.RevokedAt,
		)
		if err != nil {
			return nil, err
		}
		keys = append(keys, key)
	}

	return keys, rows.Err()
}

// UpdateAPIKeyLastUsed updates the last used timestamp for an API key
func (s *PostgresStore) UpdateAPIKeyLastUsed(ctx context.Context, id string, lastUsedAt time.Time) error {
	query := `UPDATE api_keys SET last_used_at = $1 WHERE id = $2`
	_, err := s.db.ExecContext(ctx, query, lastUsedAt, id)
	return err
}

// RevokeAPIKey marks an API key as revoked
func (s *PostgresStore) RevokeAPIKey(ctx context.Context, id string) error {
	query := `UPDATE api_keys SET revoked_at = $1 WHERE id = $2`
	_, err := s.db.ExecContext(ctx, query, time.Now(), id)
	return err
}

// DeleteAPIKey permanently deletes an API key
func (s *PostgresStore) DeleteAPIKey(ctx context.Context, id string) error {
	query := `DELETE FROM api_keys WHERE id = $1`
	_, err := s.db.ExecContext(ctx, query, id)
	return err
}

// CreateHTTPSession creates a new HTTP session
func (s *PostgresStore) CreateHTTPSession(ctx context.Context, session *common.HTTPSession) error {
	query := `
		INSERT INTO http_sessions (id, user_id, token_hash, ip_address, user_agent, expires_at, created_at, last_seen_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`
	_, err := s.db.ExecContext(ctx, query,
		session.ID, session.UserID, session.Token, session.IPAddress, session.UserAgent,
		session.ExpiresAt, session.CreatedAt, session.LastSeenAt)
	return err
}

// GetHTTPSession retrieves an HTTP session by ID
func (s *PostgresStore) GetHTTPSession(ctx context.Context, id string) (*common.HTTPSession, error) {
	query := `
		SELECT id, user_id, token_hash, ip_address, user_agent, expires_at, created_at, last_seen_at
		FROM http_sessions
		WHERE id = $1
	`

	session := &common.HTTPSession{}
	err := s.db.QueryRowContext(ctx, query, id).Scan(
		&session.ID, &session.UserID, &session.Token, &session.IPAddress,
		&session.UserAgent, &session.ExpiresAt, &session.CreatedAt, &session.LastSeenAt,
	)

	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	return session, err
}

// GetHTTPSessionByToken retrieves an HTTP session by its token hash
func (s *PostgresStore) GetHTTPSessionByToken(ctx context.Context, tokenHash string) (*common.HTTPSession, error) {
	query := `
		SELECT id, user_id, token_hash, ip_address, user_agent, expires_at, created_at, last_seen_at
		FROM http_sessions
		WHERE token_hash = $1 AND expires_at > NOW()
	`

	session := &common.HTTPSession{}
	err := s.db.QueryRowContext(ctx, query, tokenHash).Scan(
		&session.ID, &session.UserID, &session.Token, &session.IPAddress,
		&session.UserAgent, &session.ExpiresAt, &session.CreatedAt, &session.LastSeenAt,
	)

	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	return session, err
}

// UpdateHTTPSessionLastSeen updates the last seen timestamp for an HTTP session
func (s *PostgresStore) UpdateHTTPSessionLastSeen(ctx context.Context, id string, lastSeenAt time.Time) error {
	query := `UPDATE http_sessions SET last_seen_at = $1 WHERE id = $2`
	_, err := s.db.ExecContext(ctx, query, lastSeenAt, id)
	return err
}

// DeleteHTTPSession deletes an HTTP session
func (s *PostgresStore) DeleteHTTPSession(ctx context.Context, id string) error {
	query := `DELETE FROM http_sessions WHERE id = $1`
	_, err := s.db.ExecContext(ctx, query, id)
	return err
}

// DeleteExpiredHTTPSessions deletes all expired HTTP sessions
func (s *PostgresStore) DeleteExpiredHTTPSessions(ctx context.Context) error {
	query := `DELETE FROM http_sessions WHERE expires_at < NOW()`
	result, err := s.db.ExecContext(ctx, query)
	if err != nil {
		return err
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected > 0 {
		fmt.Printf("Cleaned up %d expired sessions\n", rowsAffected)
	}
	return nil
}
