package common

// NotificationPrefs stores per-user channel toggles for event types.
type NotificationPrefs struct {
	UserID       string `json:"user_id"`
	InAppEnabled bool   `json:"in_app_enabled"`
	EmailEnabled bool   `json:"email_enabled"`
	// EventTypes: empty = all; otherwise allow-list of notification types.
	EventTypes []string `json:"event_types"`
}

// DefaultNotificationPrefs returns sensible defaults (in-app on, email off).
func DefaultNotificationPrefs(userID string) *NotificationPrefs {
	return &NotificationPrefs{
		UserID:       userID,
		InAppEnabled: true,
		EmailEnabled: false,
		EventTypes:   nil,
	}
}

// Allows reports whether eventType should be delivered on the in-app channel.
func (p *NotificationPrefs) AllowsInApp(eventType string) bool {
	if p == nil {
		return true
	}
	if !p.InAppEnabled {
		return false
	}
	if len(p.EventTypes) == 0 {
		return true
	}
	for _, t := range p.EventTypes {
		if t == eventType {
			return true
		}
	}
	return false
}
