package database

import (
	"context"
	"time"

	"github.com/zrougamed/orion-belt/pkg/common"
)

// Store defines the interface for database operations
type Store interface {
	// User operations
	CreateUser(ctx context.Context, user *common.User) error
	GetUser(ctx context.Context, id string) (*common.User, error)
	GetUserByUsername(ctx context.Context, username string) (*common.User, error)
	UpdateUser(ctx context.Context, user *common.User) error
	DeleteUser(ctx context.Context, id string) error
	ListUsers(ctx context.Context, limit, offset int) ([]*common.User, error)

	// Machine operations
	CreateMachine(ctx context.Context, machine *common.Machine) error
	GetMachine(ctx context.Context, id string) (*common.Machine, error)
	GetMachineByName(ctx context.Context, name string) (*common.Machine, error)
	UpdateMachine(ctx context.Context, machine *common.Machine) error
	DeleteMachine(ctx context.Context, id string) error
	ListMachines(ctx context.Context, limit, offset int) ([]*common.Machine, error)
	ListActiveMachines(ctx context.Context) ([]*common.Machine, error)

	// Session operations
	CreateSession(ctx context.Context, session *common.Session) error
	GetSession(ctx context.Context, id string) (*common.Session, error)
	UpdateSession(ctx context.Context, session *common.Session) error
	ListActiveSessions(ctx context.Context) ([]*common.Session, error)
	ListUserSessions(ctx context.Context, userID string, limit, offset int) ([]*common.Session, error)
	EndSession(ctx context.Context, id string, endTime time.Time) error

	// Access request operations
	CreateAccessRequest(ctx context.Context, request *common.AccessRequest) error
	GetAccessRequest(ctx context.Context, id string) (*common.AccessRequest, error)
	UpdateAccessRequest(ctx context.Context, request *common.AccessRequest) error
	ListPendingAccessRequests(ctx context.Context) ([]*common.AccessRequest, error)
	ListUserAccessRequests(ctx context.Context, userID string, limit, offset int) ([]*common.AccessRequest, error)

	// Permission operations
	CreatePermission(ctx context.Context, permission *common.Permission) error
	GetPermission(ctx context.Context, id string) (*common.Permission, error)
	DeletePermission(ctx context.Context, id string) error
	ListUserPermissions(ctx context.Context, userID string) ([]*common.Permission, error)
	ListMachinePermissions(ctx context.Context, machineID string) ([]*common.Permission, error)
	HasPermission(ctx context.Context, userID, machineID, accessType string) (bool, error)

	// Audit log operations
	CreateAuditLog(ctx context.Context, log *common.AuditLog) error
	ListAuditLogs(ctx context.Context, limit, offset int, filters map[string]interface{}) ([]*common.AuditLog, error)

	// Lifecycle
	Connect(ctx context.Context) error
	Close() error
	Ping(ctx context.Context) error
	Migrate(ctx context.Context) error
}

// Factory is a function that creates a new Store instance
type Factory func(connectionString string) (Store, error)

var factories = make(map[string]Factory)

// Register registers a database factory
func Register(driver string, factory Factory) {
	factories[driver] = factory
}

// NewStore creates a new Store instance based on the driver
func NewStore(driver, connectionString string) (Store, error) {
	factory, ok := factories[driver]
	if !ok {
		return nil, ErrUnsupportedDriver
	}
	return factory(connectionString)
}
