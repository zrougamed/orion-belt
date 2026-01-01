package api

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

func (s *APIServer) loggingMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path

		c.Next()

		duration := time.Since(start)
		s.logger.Info("%s %s %d %v", c.Request.Method, path, c.Writer.Status(), duration)
	}
}

func (s *APIServer) authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// TODO: Implement proper authentication (JWT, API keys, etc.)
		// For now, we use a simple API key or skip authentication
		apiKey := c.GetHeader("X-API-Key")
		if apiKey == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "missing API key"})
			c.Abort()
			return
		}

		// TODO: Validate API key against database
		c.Set("user_id", "current-user-id")
		c.Next()
	}
}

// Start starts the API server
func (s *APIServer) Start(addr string) error {
	s.logger.Info("Starting API server on %s", addr)
	return s.router.Run(addr)
}

// Router returns the Gin router (for testing)
func (s *APIServer) Router() *gin.Engine {
	return s.router
}
