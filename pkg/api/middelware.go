package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/zrougamed/orion-belt/pkg/common"
	"github.com/zrougamed/orion-belt/pkg/metrics"
)

// AuthContext holds the authenticated user context
type AuthContext struct {
	UserID     string
	Username   string
	IsAdmin    bool
	AuthMethod string // "api_key", "session", "bearer"
}

// loggingMiddleware logs all HTTP requests
func (s *APIServer) loggingMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path
		method := c.Request.Method

		c.Next()

		duration := time.Since(start)
		status := c.Writer.Status()

		s.logger.Info("%s %s %d %v", method, path, status, duration)
	}
}

// authMiddleware enforces authentication for protected endpoints
func (s *APIServer) authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx := c.Request.Context()

		// Try API Key authentication
		if apiKey := c.GetHeader("X-API-Key"); apiKey != "" {
			if user, err := s.validateAPIKey(ctx, apiKey); err == nil {
				s.setAuthContext(c, user.ID, user.Username, user.IsAdmin, "api_key")
				c.Next()
				return
			}
		}

		// Try Session Token authentication
		sessionToken := c.GetHeader("X-Session-Token")
		if sessionToken == "" {
			if cookie, err := c.Cookie("session_token"); err == nil {
				sessionToken = cookie
			}
		}
		if sessionToken != "" {
			if user, err := s.validateSession(ctx, sessionToken); err == nil {
				s.setAuthContext(c, user.ID, user.Username, user.IsAdmin, "session")
				c.Next()
				return
			}
		}

		// Try Bearer Token authentication
		if authHeader := c.GetHeader("Authorization"); authHeader != "" {
			if strings.HasPrefix(authHeader, "Bearer ") {
				bearerToken := strings.TrimPrefix(authHeader, "Bearer ")
				if user, err := s.validateBearerToken(ctx, bearerToken); err == nil {
					s.setAuthContext(c, user.ID, user.Username, user.IsAdmin, "bearer")
					c.Next()
					return
				}
			}
		}

		// No valid authentication found
		metrics.Default.IncAuthFailure()
		s.logger.Warn("Authentication failed for %s %s from %s", c.Request.Method, c.Request.URL.Path, c.ClientIP())
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "authentication required",
		})
		c.Abort()
	}
}

// adminMiddleware requires the authenticated user to be an admin
func (s *APIServer) adminMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		isAdmin, exists := c.Get("is_admin")
		if !exists || !isAdmin.(bool) {
			userID, _ := c.Get("user_id")
			s.logger.Warn("Admin access denied for user: %v", userID)
			c.JSON(http.StatusForbidden, gin.H{
				"error": "admin privileges required",
			})
			c.Abort()
			return
		}
		c.Next()
	}
}

// setAuthContext sets authentication context in the Gin context
func (s *APIServer) setAuthContext(c *gin.Context, userID, username string, isAdmin bool, authMethod string) {
	c.Set("user_id", userID)
	c.Set("username", username)
	c.Set("is_admin", isAdmin)
	c.Set("auth_method", authMethod)
	c.Set("authenticated", true)
}

// validateAPIKey validates an API key and returns the associated user
func (s *APIServer) validateAPIKey(ctx context.Context, apiKey string) (*common.User, error) {
	keyHash := hashAPIKey(apiKey)

	key, err := s.store.GetAPIKeyByHash(ctx, keyHash)
	if err != nil {
		return nil, fmt.Errorf("invalid API key")
	}

	if key.RevokedAt != nil {
		return nil, fmt.Errorf("API key has been revoked")
	}

	if key.ExpiresAt != nil && time.Now().After(*key.ExpiresAt) {
		return nil, fmt.Errorf("API key has expired")
	}

	go func() {
		_ = s.store.UpdateAPIKeyLastUsed(ctx, key.ID, time.Now())
	}()

	user, err := s.store.GetUser(ctx, key.UserID)
	if err != nil {
		return nil, fmt.Errorf("user not found for API key")
	}

	s.logger.Debug("API key authenticated: user=%s key=%s", user.Username, key.Name)
	return user, nil
}

// validateSession validates a session token and returns the associated user
func (s *APIServer) validateSession(ctx context.Context, sessionToken string) (*common.User, error) {
	tokenHash := hashSessionToken(sessionToken)

	session, err := s.store.GetHTTPSessionByToken(ctx, tokenHash)
	if err != nil {
		return nil, fmt.Errorf("invalid session token")
	}

	if time.Now().After(session.ExpiresAt) {
		_ = s.store.DeleteHTTPSession(ctx, session.ID)
		return nil, fmt.Errorf("session has expired")
	}

	go func() {
		_ = s.store.UpdateHTTPSessionLastSeen(ctx, session.ID, time.Now())
	}()

	user, err := s.store.GetUser(ctx, session.UserID)
	if err != nil {
		return nil, fmt.Errorf("user not found for session")
	}

	s.logger.Debug("Session authenticated: user=%s", user.Username)
	return user, nil
}

// validateBearerToken validates a JWT bearer token
func (s *APIServer) validateBearerToken(ctx context.Context, token string) (*common.User, error) {
	if s.jwt == nil || !s.jwt.Enabled() {
		return nil, fmt.Errorf("JWT authentication not configured")
	}

	claims, err := s.jwt.Validate(token)
	if err != nil {
		return nil, err
	}

	user, err := s.store.GetUser(ctx, claims.UserID)
	if err != nil {
		return nil, fmt.Errorf("user not found for token")
	}

	s.logger.Debug("JWT authenticated: user=%s", user.Username)
	return user, nil
}

// hashAPIKey creates a SHA256 hash of an API key
func hashAPIKey(key string) string {
	hash := sha256.Sum256([]byte(key))
	return hex.EncodeToString(hash[:])
}

// hashSessionToken creates a SHA256 hash of a session token
func hashSessionToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}

// Start starts the API server
func (s *APIServer) Start(addr string) error {
	s.logger.Info("Starting API server on %s", addr)
	return s.router.Run(addr)
}

// Router returns the Gin router
func (s *APIServer) Router() *gin.Engine {
	return s.router
}
