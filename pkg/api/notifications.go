package api

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/zrougamed/orion-belt/pkg/common"
	"github.com/zrougamed/orion-belt/pkg/database"
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

// unreadNotificationCount returns how many unread notifications the
// authenticated user has, for the bell widget's badge.
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

// markNotificationRead marks a single notification as read. Scoped to the
// caller: a user cannot mark another user's notification as read.
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

// markAllNotificationsRead marks all of the caller's unread notifications as read.
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

// notifyAccessRequestApproved creates the in-app "your JIT request was
// approved" notification for the requester. Best-effort: failures are
// logged, never surfaced to the approver's response.
func (s *APIServer) notifyAccessRequestApproved(ctx context.Context, req *common.AccessRequest) {
	if s.store == nil || req == nil {
		return
	}

	machineName := req.MachineID
	if s.store != nil {
		if m, err := s.store.GetMachine(ctx, req.MachineID); err == nil && m != nil {
			machineName = m.Name
		}
	}

	ttl := "unlimited"
	if req.ExpiresAt != nil {
		ttl = "until " + req.ExpiresAt.Format(time.RFC3339)
	}

	n := common.NewNotification(
		req.UserID,
		"access_request.approved",
		"Access request approved",
		fmt.Sprintf("Your access request for %s (%s) was approved — access %s.",
			machineName, joinRemoteUsers(req.RemoteUsers), ttl),
		map[string]interface{}{
			"request_id": req.ID,
			"machine_id": req.MachineID,
			"expires_at": req.ExpiresAt,
		},
	)
	if err := s.store.CreateNotification(ctx, n); err != nil && s.logger != nil {
		s.logger.Warn("failed to create approval notification: %v", err)
	}
}

func joinRemoteUsers(users []string) string {
	if len(users) == 0 {
		return "as allowed"
	}
	out := "as " + users[0]
	for _, u := range users[1:] {
		out += ", " + u
	}
	return out
}
