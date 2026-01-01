package main

import (
	"context"
	"fmt"
	"log"

	"github.com/zrougamed/orion-belt/pkg/plugin"
)

// NotificationPlugin sends notifications on various events
type NotificationPlugin struct {
	name    string
	version string
	config  map[string]interface{}
}

// NewNotificationPlugin creates a new notification plugin
func NewNotificationPlugin() plugin.Plugin {
	return &NotificationPlugin{
		name:    "notification",
		version: "1.0.0",
	}
}

// Name returns the plugin name
func (p *NotificationPlugin) Name() string {
	return p.name
}

// Version returns the plugin version
func (p *NotificationPlugin) Version() string {
	return p.version
}

// Initialize initializes the plugin
func (p *NotificationPlugin) Initialize(ctx context.Context, config map[string]interface{}) error {
	p.config = config
	log.Printf("[NotificationPlugin] Initialized with config: %v", config)
	return nil
}

// Shutdown shuts down the plugin
func (p *NotificationPlugin) Shutdown(ctx context.Context) error {
	log.Printf("[NotificationPlugin] Shutting down")
	return nil
}

// OnHook handles plugin hooks
func (p *NotificationPlugin) OnHook(ctx context.Context, hook plugin.Hook, hookCtx *plugin.HookContext) error {
	switch hook {
	case plugin.HookSessionStart:
		return p.onSessionStart(hookCtx)
	case plugin.HookSessionEnd:
		return p.onSessionEnd(hookCtx)
	case plugin.HookAccessRequest:
		return p.onAccessRequest(hookCtx)
	case plugin.HookAccessGranted:
		return p.onAccessGranted(hookCtx)
	default:
		// Ignore other hooks
		return nil
	}
}

func (p *NotificationPlugin) onSessionStart(ctx *plugin.HookContext) error {
	log.Printf("[NotificationPlugin] Session started: user=%s, machine=%s, session=%s",
		ctx.UserID, ctx.MachineID, ctx.SessionID)

	// TODO: Send actual notification (email, Slack, etc.)
	return nil
}

func (p *NotificationPlugin) onSessionEnd(ctx *plugin.HookContext) error {
	log.Printf("[NotificationPlugin] Session ended: user=%s, machine=%s, session=%s",
		ctx.UserID, ctx.MachineID, ctx.SessionID)

	// TODO: Send actual notification
	return nil
}

func (p *NotificationPlugin) onAccessRequest(ctx *plugin.HookContext) error {
	log.Printf("[NotificationPlugin] Access requested: user=%s, machine=%s",
		ctx.UserID, ctx.MachineID)

	// TODO: Send notification to admins
	fmt.Println("Notification: New access request needs admin approval")
	return nil
}

func (p *NotificationPlugin) onAccessGranted(ctx *plugin.HookContext) error {
	log.Printf("[NotificationPlugin] Access granted: user=%s, machine=%s",
		ctx.UserID, ctx.MachineID)

	// TODO: Send notification to user
	fmt.Println("Notification: Access has been granted")
	return nil
}

// Ensure NotificationPlugin implements both Plugin and HookPlugin interfaces
var _ plugin.Plugin = (*NotificationPlugin)(nil)
var _ plugin.HookPlugin = (*NotificationPlugin)(nil)
