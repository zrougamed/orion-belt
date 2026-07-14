package api

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/zrougamed/orion-belt/pkg/common"
	"github.com/zrougamed/orion-belt/pkg/database"
	"github.com/zrougamed/orion-belt/pkg/notify"
)

// listNotifications returns the authenticated user's notifications, most
// recent first. Always scoped to the caller — there is no "list everyone's
// notifications" mode, even for admins.
func (s *APIServer) listNotifications(c *gin.Context) {
	ctx := c.Request.Context()
	userID, _ := c.Get("user_id")
	uid, _ := userID.(string)

	limit := 50
	if v := c.Query("limit"); v != "" {
		if n, err := fmt.Sscanf(v, "%d", &limit); n == 1 && err == nil && limit > 0 {
			if limit > 200 {
				limit = 200
			}
		}
	}

	notifications, err := s.store.ListUserNotifications(ctx, uid, limit, 0)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if notifications == nil {
		notifications = []*common.Notification{}
	}
	c.JSON(http.StatusOK, notifications)
}

func (s *APIServer) unreadNotificationCount(c *gin.Context) {
	ctx := c.Request.Context()
	userID, _ := c.Get("user_id")
	uid, _ := userID.(string)

	count, err := s.store.CountUnreadNotifications(ctx, uid)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"unread": count})
}

func (s *APIServer) markNotificationRead(c *gin.Context) {
	ctx := c.Request.Context()
	userID, _ := c.Get("user_id")
	uid, _ := userID.(string)

	if err := s.store.MarkNotificationRead(ctx, c.Param("id"), uid); err != nil {
		if err == database.ErrNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "notification not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "marked read"})
}

func (s *APIServer) markAllNotificationsRead(c *gin.Context) {
	ctx := c.Request.Context()
	userID, _ := c.Get("user_id")
	uid, _ := userID.(string)

	if err := s.store.MarkAllNotificationsRead(ctx, uid); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "all marked read"})
}

func (s *APIServer) getNotificationPrefs(c *gin.Context) {
	uid, _ := c.Get("user_id")
	prefs, err := s.store.GetNotificationPrefs(c.Request.Context(), uid.(string))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, prefs)
}

func (s *APIServer) putNotificationPrefs(c *gin.Context) {
	uid, _ := c.Get("user_id")
	var prefs common.NotificationPrefs
	if err := c.ShouldBindJSON(&prefs); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	prefs.UserID = uid.(string)
	if err := s.store.UpsertNotificationPrefs(c.Request.Context(), &prefs); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, prefs)
}

func (s *APIServer) deliverNotification(ctx context.Context, userID, notifType string, data map[string]string) {
	if s.store == nil {
		return
	}
	prefs, _ := s.store.GetNotificationPrefs(ctx, userID)
	if !prefs.AllowsInApp(notifType) {
		return
	}
	title, body := notify.Render(notifType, data)
	meta := map[string]interface{}{}
	for k, v := range data {
		meta[k] = v
	}
	n := common.NewNotification(userID, notifType, title, body, meta)
	if err := s.store.CreateNotification(ctx, n); err != nil && s.logger != nil {
		s.logger.Warn("failed to create notification: %v", err)
	}
}

func (s *APIServer) notifyAccessRequestApproved(ctx context.Context, req *common.AccessRequest) {
	if req == nil {
		return
	}
	machineName := req.MachineID
	if m, err := s.store.GetMachine(ctx, req.MachineID); err == nil && m != nil {
		machineName = m.Name
	}
	s.deliverNotification(ctx, req.UserID, "access_request.approved", map[string]string{
		"machine":      machineName,
		"machine_id":   req.MachineID,
		"request_id":   req.ID,
		"remote_users": strings.Join(req.RemoteUsers, ", "),
		"ttl":          notify.FormatTTL(req.ExpiresAt),
	})
}

func (s *APIServer) notifyAccessRequestRejected(ctx context.Context, req *common.AccessRequest) {
	if req == nil {
		return
	}
	machineName := req.MachineID
	if m, err := s.store.GetMachine(ctx, req.MachineID); err == nil && m != nil {
		machineName = m.Name
	}
	s.deliverNotification(ctx, req.UserID, "access_request.rejected", map[string]string{
		"machine":      machineName,
		"machine_id":   req.MachineID,
		"request_id":   req.ID,
		"remote_users": strings.Join(req.RemoteUsers, ", "),
	})
}

// expireStaleAccessRequests marks old pending JIT requests as expired.
func (s *APIServer) expireStaleAccessRequests(ctx context.Context) {
	n, err := s.store.ExpireStalePendingAccessRequests(ctx, 7*24*time.Hour)
	if err != nil {
		if s.logger != nil {
			s.logger.Warn("expire access requests: %v", err)
		}
		return
	}
	if n > 0 && s.logger != nil {
		s.logger.Info("Expired %d stale pending access requests", n)
	}
}
