package api

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

// CreateAPIKeyRequest represents a request to create an API key
type CreateAPIKeyRequest struct {
	Name      string `json:"name" binding:"required"`
	ExpiresIn *int   `json:"expires_in"` // Duration in days (optional)
}

// CreateAPIKeyResponse represents the response when creating an API key
type CreateAPIKeyResponse struct {
	ID        string     `json:"id"`
	Name      string     `json:"name"`
	APIKey    string     `json:"api_key"`
	KeyPrefix string     `json:"key_prefix"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
}

// createAPIKey handles API key creation
func (s *APIServer) createAPIKey(c *gin.Context) {
	var req CreateAPIKeyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Get authenticated user
	userID, _ := c.Get("user_id")
	ctx := c.Request.Context()

	// Calculate expiration
	var expiresAt *time.Time
	if req.ExpiresIn != nil {
		expiry := time.Now().AddDate(0, 0, *req.ExpiresIn)
		expiresAt = &expiry
	}

	// Generate API key
	apiKey, rawKey, err := s.authService.GenerateAPIKey(ctx, userID.(string), req.Name, expiresAt)
	if err != nil {
		s.logger.Error("Failed to create API key: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create API key"})
		return
	}

	c.JSON(http.StatusCreated, CreateAPIKeyResponse{
		ID:        apiKey.ID,
		Name:      apiKey.Name,
		APIKey:    rawKey,
		KeyPrefix: apiKey.KeyPrefix,
		ExpiresAt: apiKey.ExpiresAt,
		CreatedAt: apiKey.CreatedAt,
	})
}

// listAPIKeys lists all API keys for the authenticated user
func (s *APIServer) listAPIKeys(c *gin.Context) {
	userID, _ := c.Get("user_id")
	ctx := c.Request.Context()

	keys, err := s.authService.ListUserAPIKeys(ctx, userID.(string))
	if err != nil {
		s.logger.Error("Failed to list API keys: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list API keys"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"api_keys": keys})
}

// revokeAPIKey revokes an API key
func (s *APIServer) revokeAPIKey(c *gin.Context) {
	keyID := c.Param("id")
	userID, _ := c.Get("user_id")
	ctx := c.Request.Context()

	// TODO: implemet auth checks
	key, err := s.store.GetAPIKey(ctx, keyID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "API key not found"})
		return
	}

	// TODO: implemet auth checks
	isAdmin, _ := c.Get("is_admin")
	if key.UserID != userID.(string) && !isAdmin.(bool) {
		c.JSON(http.StatusForbidden, gin.H{"error": "access denied"})
		return
	}

	// Revoke the key
	if err := s.authService.RevokeAPIKey(ctx, keyID); err != nil {
		s.logger.Error("Failed to revoke API key: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to revoke API key"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "API key revoked successfully"})
}

// deleteAPIKey permanently deletes an API key
func (s *APIServer) deleteAPIKey(c *gin.Context) {
	keyID := c.Param("id")
	userID, _ := c.Get("user_id")
	ctx := c.Request.Context()

	// TODO: implemet auth checks
	key, err := s.store.GetAPIKey(ctx, keyID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "API key not found"})
		return
	}

	// TODO: implemet auth checks
	isAdmin, _ := c.Get("is_admin")
	if key.UserID != userID.(string) && !isAdmin.(bool) {
		c.JSON(http.StatusForbidden, gin.H{"error": "access denied"})
		return
	}

	// Delete the key
	if err := s.store.DeleteAPIKey(ctx, keyID); err != nil {
		s.logger.Error("Failed to delete API key: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete API key"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "API key deleted successfully"})
}

// LoginRequest represents a login request
type LoginRequest struct {
	Username  string `json:"username" binding:"required"`
	Password  string `json:"password"`   // TODO: implemet proper password auth
	PublicKey string `json:"public_key"` // TODO: implemet proper key auth
}

// LoginResponse represents a login response
type LoginResponse struct {
	SessionToken string    `json:"session_token"`
	ExpiresAt    time.Time `json:"expires_at"`
	User         struct {
		ID       string `json:"id"`
		Username string `json:"username"`
		Email    string `json:"email"`
		IsAdmin  bool   `json:"is_admin"`
	} `json:"user"`
}

// login handles user login and session creation
func (s *APIServer) login(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	ctx := c.Request.Context()

	// TODO: implemet auth checks and password checks
	user, err := s.store.GetUserByUsername(ctx, req.Username)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}

	// Create session TTL 60m for web clients
	session, _, err := s.authService.CreateSession(
		ctx,
		user.ID,
		c.ClientIP(),
		c.Request.UserAgent(),
		60*time.Minute,
	)
	if err != nil {
		s.logger.Error("Failed to create session: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create session"})
		return
	}

	// Create an API key for CLI tools TTL 24h
	expiresAt := time.Now().Add(24 * time.Hour)
	_, rawKey, err := s.authService.GenerateAPIKey(
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

	response := LoginResponse{
		SessionToken: rawKey,
		ExpiresAt:    session.ExpiresAt,
	}
	response.User.ID = user.ID
	response.User.Username = user.Username
	response.User.Email = user.Email
	response.User.IsAdmin = user.IsAdmin

	c.JSON(http.StatusOK, response)
}

// logout handles user logout (session destruction)
func (s *APIServer) logout(c *gin.Context) {
	authMethod, _ := c.Get("auth_method")
	if authMethod != "session" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "not logged in via session"})
		return
	}

	sessionToken := c.GetHeader("X-Session-Token")
	if sessionToken == "" {
		if cookie, err := c.Cookie("session_token"); err == nil {
			sessionToken = cookie
		}
	}

	if sessionToken == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "no session token provided"})
		return
	}

	ctx := c.Request.Context()

	tokenHash := hashSessionToken(sessionToken)
	session, err := s.store.GetHTTPSessionByToken(ctx, tokenHash)
	if err == nil {
		_ = s.authService.DestroySession(ctx, session.ID)
	}

	c.JSON(http.StatusOK, gin.H{"message": "logged out successfully"})
}

// getCurrentUser returns the currently authenticated user
func (s *APIServer) getCurrentUser(c *gin.Context) {
	// TODO: implemet auth checks
	userID, _ := c.Get("user_id")
	ctx := c.Request.Context()

	user, err := s.store.GetUser(ctx, userID.(string))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
		return
	}

	c.JSON(http.StatusOK, user)
}
