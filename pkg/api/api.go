package api

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/zrougamed/orion-belt/pkg/auth"
	"github.com/zrougamed/orion-belt/pkg/common"
	"github.com/zrougamed/orion-belt/pkg/database"
)

// APIServer provides REST API endpoints
type APIServer struct {
	store       database.Store
	authService *auth.AuthService
	logger      *common.Logger
	router      *gin.Engine
}

// NewAPIServer creates a new API server
func NewAPIServer(store database.Store, authService *auth.AuthService, logger *common.Logger) *APIServer {
	gin.SetMode(gin.ReleaseMode)

	api := &APIServer{
		store:       store,
		authService: authService,
		logger:      logger,
		router:      gin.New(),
	}

	// Middleware
	api.router.Use(gin.Recovery())
	api.router.Use(api.loggingMiddleware())

	// Routes
	api.setupRoutes()

	return api
}

// setupRoutes configures all API routes
func (s *APIServer) setupRoutes() {
	// Health check endpoint
	s.router.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"status":  "healthy",
			"service": "orion-belt-api",
		})
	})

	v1 := s.router.Group("/api/v1")

	// Public endpoints
	public := v1.Group("/public")
	{
		public.POST("/register/agent", s.registerAgent)
		public.POST("/register/client", s.registerClient)
		public.POST("/login", s.login)
		public.POST("/login/key", s.loginWithKey)
	}

	// Protected endpoints
	// TODO: implemet password auth with machine registration
	protected := v1.Group("/")
	protected.Use(s.authMiddleware())
	{
		// Authentication & current user
		protected.POST("/logout", s.logout)
		protected.GET("/auth/me", s.getCurrentUser)

		// API Key management
		protected.POST("/api-keys", s.createAPIKey)
		protected.GET("/api-keys", s.listAPIKeys)
		protected.POST("/api-keys/:id/revoke", s.revokeAPIKey)
		protected.DELETE("/api-keys/:id", s.deleteAPIKey)

		// User management
		protected.GET("/users", s.listUsers)
		protected.GET("/users/:id", s.getUser)

		// Machine management
		protected.GET("/machines", s.listMachines)
		protected.GET("/machines/:id", s.getMachine)

		// Permission management
		protected.GET("/permissions/user/:id", s.getUserPermissions)
		protected.GET("/permissions/machine/:id", s.getMachinePermissions)

		// Access request management
		protected.GET("/access-requests", s.listAccessRequests)
		protected.GET("/access-requests/pending", s.listPendingAccessRequests)
		protected.POST("/access-requests", s.createAccessRequest)
		protected.GET("/access-requests/:id", s.getAccessRequest)

		// Session management
		protected.GET("/sessions", s.listSessions)
		protected.GET("/sessions/active", s.listActiveSessions)
		protected.GET("/sessions/:id", s.getSession)
		protected.GET("/sessions/:id/content", s.getSessionContent)

		// Audit logs
		protected.GET("/audit-logs", s.listAuditLogs)
	}

	// Admin-only endpoints
	admin := v1.Group("/admin")
	admin.Use(s.authMiddleware())
	admin.Use(s.adminMiddleware())
	{
		// User management
		admin.PUT("/users/:id", s.updateUser)
		admin.DELETE("/users/:id", s.deleteUser)

		// Machine management
		admin.POST("/machines", s.createMachine)
		admin.PUT("/machines/:id", s.updateMachine)
		admin.DELETE("/machines/:id", s.deleteMachine)

		// Permission management
		admin.POST("/permissions", s.grantPermission)
		admin.DELETE("/permissions/:id", s.revokePermission)

		// Access request management
		admin.POST("/access-requests/:id/approve", s.approveAccessRequest)
		admin.POST("/access-requests/:id/reject", s.rejectAccessRequest)
	}
}

// RegisterAgentRequest represents an agent registration request
type RegisterAgentRequest struct {
	Name      string            `json:"name" binding:"required"`
	Hostname  string            `json:"hostname" binding:"required"`
	Port      int               `json:"port" binding:"required"`
	PublicKey string            `json:"public_key" binding:"required"`
	Tags      map[string]string `json:"tags"`
}

// RegisterAgentResponse represents an agent registration response
type RegisterAgentResponse struct {
	UserID    string `json:"user_id"`
	MachineID string `json:"machine_id"`
	Message   string `json:"message"`
}

// LoginWithKeyRequest represents an API key login request
type LoginWithKeyRequest struct {
	Username  string `json:"username" binding:"required"`
	PublicKey string `json:"public_key" binding:"required"`
}

// LoginWithKeyResponse represents an API key login response
type LoginWithKeyResponse struct {
	APIKey    string     `json:"api_key"`
	ExpiresAt *time.Time `json:"expires_at"`
	User      struct {
		ID       string `json:"id"`
		Username string `json:"username"`
		Email    string `json:"email"`
		IsAdmin  bool   `json:"is_admin"`
	} `json:"user"`
}

func normalizeKey(k string) string {
	parts := strings.Fields(strings.TrimSpace(k))
	if len(parts) >= 2 {
		// Returns "ssh-rsa <key-data>"
		return parts[0] + " " + parts[1]
	}
	return k
}

// loginWithKey handles API key-based authentication for client tools
// This is specifically for osh/ocp/oadmin tools, not web sessions
func (s *APIServer) loginWithKey(c *gin.Context) {
	var req LoginWithKeyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	ctx := c.Request.Context()

	// Get user by username
	user, err := s.store.GetUserByUsername(ctx, req.Username)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}

	// Verify the public key matches what's in the database
	// The public key should be in OpenSSH format
	if normalizeKey(user.PublicKey) != normalizeKey(req.PublicKey) {
		s.logger.Info("user %s", user.PublicKey)
		s.logger.Info("req %s", req.PublicKey)
		s.logger.Warn("Public key mismatch for user: %s", req.Username)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}

	// Generate API key with 24 hour expiration for CLI tools
	expiresAt := time.Now().Add(24 * time.Hour)
	apiKey, rawKey, err := s.authService.GenerateAPIKey(
		ctx,
		user.ID,
		"CLI Authentication",
		&expiresAt,
	)
	if err != nil {
		s.logger.Error("Failed to create API key: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create API key"})
		return
	}

	s.logger.Info("API key created for user: %s (ID: %s)", user.Username, user.ID)

	response := LoginWithKeyResponse{
		APIKey:    rawKey, // Return the raw key, not the hash
		ExpiresAt: apiKey.ExpiresAt,
	}
	response.User.ID = user.ID
	response.User.Username = user.Username
	response.User.Email = user.Email
	response.User.IsAdmin = user.IsAdmin

	c.JSON(http.StatusOK, response)
}

// registerAgent handles agent registration
func (s *APIServer) registerAgent(c *gin.Context) {
	var req RegisterAgentRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	ctx := context.Background()

	// Check if agent already exists
	existingMachine, _ := s.store.GetMachineByName(ctx, req.Name)
	if existingMachine != nil {
		c.JSON(http.StatusConflict, gin.H{"error": "agent already registered"})
		return
	}

	// Create user account for agent
	agentUser := common.NewUser(req.Name, fmt.Sprintf("%s@agent.orion-belt", req.Name), req.PublicKey, false)
	if err := s.store.CreateUser(ctx, agentUser); err != nil {
		s.logger.Error("Failed to create agent user: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to register agent"})
		return
	}

	// Create machine record
	machine := common.NewMachine(req.Name, req.Hostname, req.Port, req.Tags)
	machine.AgentID = agentUser.ID
	if err := s.store.CreateMachine(ctx, machine); err != nil {
		// Rollback user creation
		s.store.DeleteUser(ctx, agentUser.ID)
		s.logger.Error("Failed to create machine: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to register agent"})
		return
	}

	s.logger.Info("Agent registered: %s (user_id=%s, machine_id=%s)", req.Name, agentUser.ID, machine.ID)

	c.JSON(http.StatusCreated, RegisterAgentResponse{
		UserID:    agentUser.ID,
		MachineID: machine.ID,
		Message:   "Agent registered successfully",
	})
}

// RegisterClientRequest represents a client registration request
type RegisterClientRequest struct {
	Username  string `json:"username" binding:"required"`
	Email     string `json:"email" binding:"required"`
	PublicKey string `json:"public_key" binding:"required"`
	IsAdmin   bool   `json:"is_admin"`
}

// RegisterClientResponse represents a client registration response
type RegisterClientResponse struct {
	UserID  string `json:"user_id"`
	Message string `json:"message"`
}

// registerClient handles client registration
func (s *APIServer) registerClient(c *gin.Context) {
	var req RegisterClientRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	ctx := context.Background()

	// Check if user already exists
	existingUser, _ := s.store.GetUserByUsername(ctx, req.Username)
	if existingUser != nil {
		c.JSON(http.StatusConflict, gin.H{"error": "username already exists"})
		return
	}

	// Create user account
	user := common.NewUser(req.Username, req.Email, req.PublicKey, req.IsAdmin)
	if err := s.store.CreateUser(ctx, user); err != nil {
		s.logger.Error("Failed to create user: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to register client"})
		return
	}

	s.logger.Info("Client registered: %s (user_id=%s, is_admin=%v)", req.Username, user.ID, req.IsAdmin)

	c.JSON(http.StatusCreated, RegisterClientResponse{
		UserID:  user.ID,
		Message: "Client registered successfully",
	})
}

// CreateAccessRequestRequest represents an access request creation
type CreateAccessRequestRequest struct {
	MachineID   string   `json:"machine_id" binding:"required"`
	RemoteUsers []string `json:"remote_users" binding:"required"`
	Reason      string   `json:"reason" binding:"required"`
	Duration    int      `json:"duration" binding:"required"` // in seconds
}

// createAccessRequest handles access request creation
func (s *APIServer) createAccessRequest(c *gin.Context) {
	var req CreateAccessRequestRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Get user ID from context (set by auth middleware)
	userID, _ := c.Get("user_id")

	ctx := context.Background()
	accessReq := common.NewAccessRequest(
		userID.(string),
		req.MachineID,
		req.RemoteUsers,
		req.Reason,
		req.Duration,
	)

	if err := s.store.CreateAccessRequest(ctx, accessReq); err != nil {
		s.logger.Error("Failed to create access request: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create access request"})
		return
	}

	s.logger.Info("Access request created: request_id=%s, user_id=%s, machine_id=%s",
		accessReq.ID, userID, req.MachineID)

	c.JSON(http.StatusCreated, accessReq)
}

// getAccessRequest gets a specific access request by ID
func (s *APIServer) getAccessRequest(c *gin.Context) {
	requestID := c.Param("id")
	ctx := context.Background()

	request, err := s.store.GetAccessRequest(ctx, requestID)
	if err != nil {
		if err == database.ErrNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "access request not found"})
			return
		}
		s.logger.Error("Failed to get access request: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get access request"})
		return
	}

	c.JSON(http.StatusOK, request)
}

// ApproveAccessRequestRequest represents an approval request
type ApproveAccessRequestRequest struct {
	ReviewerID string `json:"reviewer_id" binding:"required"`
}

// approveAccessRequest handles access request approval
func (s *APIServer) approveAccessRequest(c *gin.Context) {
	requestID := c.Param("id")

	var req ApproveAccessRequestRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	ctx := context.Background()

	// Approve the request
	if err := s.authService.ApproveAccessRequest(ctx, requestID, req.ReviewerID); err != nil {
		s.logger.Error("Failed to approve access request: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Get updated request
	accessReq, err := s.store.GetAccessRequest(ctx, requestID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "request approved but failed to fetch"})
		return
	}

	s.logger.Info("Access request approved: request_id=%s, reviewer_id=%s", requestID, req.ReviewerID)

	c.JSON(http.StatusOK, accessReq)
}

// RejectAccessRequestRequest represents a rejection request
type RejectAccessRequestRequest struct {
	ReviewerID string `json:"reviewer_id" binding:"required"`
}

// rejectAccessRequest handles access request rejection
func (s *APIServer) rejectAccessRequest(c *gin.Context) {
	requestID := c.Param("id")

	var req RejectAccessRequestRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	ctx := context.Background()

	// Reject the request
	if err := s.authService.RejectAccessRequest(ctx, requestID, req.ReviewerID); err != nil {
		s.logger.Error("Failed to reject access request: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Get updated request
	accessReq, err := s.store.GetAccessRequest(ctx, requestID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "request rejected but failed to fetch"})
		return
	}

	s.logger.Info("Access request rejected: request_id=%s, reviewer_id=%s", requestID, req.ReviewerID)

	c.JSON(http.StatusOK, accessReq)
}

// listPendingAccessRequests lists all pending access requests
func (s *APIServer) listPendingAccessRequests(c *gin.Context) {
	ctx := context.Background()

	requests, err := s.store.ListPendingAccessRequests(ctx)
	if err != nil {
		s.logger.Error("Failed to list pending access requests: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list requests"})
		return
	}

	c.JSON(http.StatusOK, requests)
}

// listAccessRequests lists access requests with pagination
func (s *APIServer) listAccessRequests(c *gin.Context) {
	ctx := context.Background()
	requests, err := s.store.ListPendingAccessRequests(ctx)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, requests)
}

// Placeholder implementations for other endpoints
func (s *APIServer) listUsers(c *gin.Context) {
	ctx := context.Background()
	users, err := s.store.ListUsers(ctx, 100, 0)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, users)
}

func (s *APIServer) getUser(c *gin.Context) {
	ctx := context.Background()
	user, err := s.store.GetUser(ctx, c.Param("id"))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
		return
	}
	c.JSON(http.StatusOK, user)
}

func (s *APIServer) updateUser(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "not implemented yet"})
}

func (s *APIServer) deleteUser(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "not implemented yet"})
}

func (s *APIServer) listMachines(c *gin.Context) {
	ctx := context.Background()
	machines, err := s.store.ListMachines(ctx, 100, 0)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, machines)
}

func (s *APIServer) getMachine(c *gin.Context) {
	ctx := context.Background()
	machine, err := s.store.GetMachine(ctx, c.Param("id"))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "machine not found"})
		return
	}
	c.JSON(http.StatusOK, machine)
}

func (s *APIServer) createMachine(c *gin.Context) {
	// TODO: implement machine registration
	c.JSON(http.StatusOK, gin.H{"error": "not implemented yet"})
}

func (s *APIServer) updateMachine(c *gin.Context) {
	// TODO: implement machine update
	c.JSON(http.StatusOK, gin.H{"message": "not implemented yet"})
}

func (s *APIServer) deleteMachine(c *gin.Context) {
	// TODO: implement machine archive and delete
	c.JSON(http.StatusOK, gin.H{"message": "not implemented yet"})
}

func (s *APIServer) getUserPermissions(c *gin.Context) {
	ctx := context.Background()
	permissions, err := s.store.ListUserPermissions(ctx, c.Param("id"))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, permissions)
}

func (s *APIServer) getMachinePermissions(c *gin.Context) {
	ctx := context.Background()
	permissions, err := s.store.ListMachinePermissions(ctx, c.Param("id"))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, permissions)
}

func (s *APIServer) grantPermission(c *gin.Context) {
	var req struct {
		UserID     string `json:"user_id" binding:"required"`
		MachineID  string `json:"machine_id" binding:"required"`
		AccessType string `json:"access_type" binding:"required"` // 'ssh', 'scp', or 'both'
		ExpiresAt  string `json:"expires_at"`                     // Optional
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// TODO: add proper checks with ReBac
	adminID, _ := c.Get("user_id")

	permission := &common.Permission{
		ID:         uuid.New().String(),
		UserID:     req.UserID,
		MachineID:  req.MachineID,
		AccessType: req.AccessType,
		GrantedBy:  adminID.(string),
		GrantedAt:  time.Now(),
	}

	if err := s.store.CreatePermission(context.Background(), permission); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, permission)
}

func (s *APIServer) revokePermission(c *gin.Context) {
	ctx := context.Background()
	if err := s.store.DeletePermission(ctx, c.Param("id")); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "permission revoked"})
}

func (s *APIServer) listSessions(c *gin.Context) {
	ctx := context.Background()

	sessions, err := s.store.ListActiveSessions(ctx)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, sessions)
}

func (s *APIServer) listActiveSessions(c *gin.Context) {
	ctx := context.Background()
	sessions, err := s.store.ListActiveSessions(ctx)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, sessions)
}

func (s *APIServer) getSession(c *gin.Context) {
	ctx := context.Background()
	session, err := s.store.GetSession(ctx, c.Param("id"))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "session not found"})
		return
	}
	c.JSON(http.StatusOK, session)
}

func (s *APIServer) getSessionContent(c *gin.Context) {
	ctx := context.Background()
	session, err := s.store.GetSession(ctx, c.Param("id"))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "session not found"})
		return
	}

	// Ensure the recording exists on disk
	if _, err := os.Stat(session.RecordingPath); os.IsNotExist(err) {
		c.JSON(http.StatusNotFound, gin.H{"error": "recording file missing on server"})
		return
	}
	// serve the file
	c.File(session.RecordingPath)
}

func (s *APIServer) listAuditLogs(c *gin.Context) {
	ctx := context.Background()
	logs, err := s.store.ListAuditLogs(ctx, 100, 0, nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, logs)
}
