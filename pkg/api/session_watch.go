package api

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

// sessionWatchWS is a read-only live view of an active recorded session.
// GET /sessions/:id/watch (WebSocket) — privileged viewers or the session owner.
func (s *APIServer) sessionWatchWS(c *gin.Context) {
	if s.recorder == nil || s.recorder.Hub() == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "live watch unavailable"})
		return
	}
	sessionID := c.Param("id")
	ctx := c.Request.Context()
	session, err := s.store.GetSession(ctx, sessionID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "session not found"})
		return
	}
	if session.Status != "active" {
		c.JSON(http.StatusConflict, gin.H{"error": "session is not active"})
		return
	}
	if !isPrivilegedViewer(c) {
		userID, _ := c.Get("user_id")
		if uid, _ := userID.(string); session.UserID != uid {
			c.JSON(http.StatusNotFound, gin.H{"error": "session not found"})
			return
		}
	}

	if _, err := s.recorder.GetRecorder(sessionID); err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": "session recording not active on this node"})
		return
	}

	conn, err := upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		return
	}
	defer conn.Close()

	s.recordAudit(c, "session.watch.start", "session:"+sessionID, nil)

	ch := s.recorder.Hub().Subscribe(sessionID)
	defer s.recorder.Hub().Unsubscribe(sessionID, ch)

	_ = conn.SetReadDeadline(time.Now().Add(24 * time.Hour))
	go func() {
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	}()

	for data := range ch {
		_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
		if err := conn.WriteMessage(2, data); err != nil { // BinaryMessage — raw PTY bytes
			return
		}
	}
}
