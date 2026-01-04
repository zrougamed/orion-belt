package plugin

import (
	"context"
	"fmt"
	"sync"

	"github.com/zrougamed/orion-belt/pkg/common"
)

// Plugin defines the interface for Orion-Belt plugins
type Plugin interface {
	// Name returns the plugin name
	Name() string

	// Version returns the plugin version
	Version() string

	// Initialize initializes the plugin
	Initialize(ctx context.Context, config map[string]interface{}) error

	// Shutdown cleanly shuts down the plugin
	Shutdown(ctx context.Context) error
}

// Hook defines different plugin hook points
type Hook string

const (
	// HookPreAuth is called before authentication
	HookPreAuth Hook = "pre_auth"

	// HookPostAuth is called after successful authentication
	HookPostAuth Hook = "post_auth"

	// HookPreConnect is called before establishing connection
	HookPreConnect Hook = "pre_connect"

	// HookPostConnect is called after connection is established
	HookPostConnect Hook = "post_connect"

	// HookPreDisconnect is called before disconnection
	HookPreDisconnect Hook = "pre_disconnect"

	// HookPostDisconnect is called after disconnection
	HookPostDisconnect Hook = "post_disconnect"

	// HookSessionStart is called when session starts
	HookSessionStart Hook = "session_start"

	// HookSessionEnd is called when session ends
	HookSessionEnd Hook = "session_end"

	// HookAccessRequest is called when access is requested
	HookAccessRequest Hook = "access_request"

	// HookAccessGranted is called when access is granted
	HookAccessGranted Hook = "access_granted"
)

// HookContext contains context for hook execution
type HookContext struct {
	UserID    string
	MachineID string
	SessionID string
	Data      map[string]interface{}
}

// HookPlugin defines the interface for plugins that respond to hooks
type HookPlugin interface {
	Plugin

	// OnHook is called when a hook is triggered
	OnHook(ctx context.Context, hook Hook, hookCtx *HookContext) error
}

// Manager manages plugins
type Manager struct {
	plugins     map[string]Plugin
	hookPlugins map[Hook][]HookPlugin
	logger      *common.Logger
	loader      *PluginLoader
	mu          sync.RWMutex
}

// NewManager creates a new plugin manager
func NewManager(logger *common.Logger) *Manager {
	return &Manager{
		plugins:     make(map[string]Plugin),
		hookPlugins: make(map[Hook][]HookPlugin),
		logger:      logger,
	}
}

// SetPluginDirectory sets the plugin directory and creates a loader
func (m *Manager) SetPluginDirectory(pluginDir string) {
	m.loader = NewPluginLoader(m, pluginDir)
}

// LoadPlugins discovers and loads all plugins from the configured directory
func (m *Manager) LoadPlugins(ctx context.Context) error {
	if m.loader == nil {
		return fmt.Errorf("plugin directory not configured")
	}
	return m.loader.LoadAll(ctx)
}

// LoadPlugin loads a single plugin from the specified path
func (m *Manager) LoadPlugin(ctx context.Context, path string) error {
	if m.loader == nil {
		return fmt.Errorf("plugin loader not initialized")
	}
	return m.loader.LoadPlugin(ctx, path)
}

// Register registers a plugin
func (m *Manager) Register(plugin Plugin) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	name := plugin.Name()
	if _, exists := m.plugins[name]; exists {
		return fmt.Errorf("plugin already registered: %s", name)
	}

	m.plugins[name] = plugin

	// If plugin implements HookPlugin, register for hooks
	if hookPlugin, ok := plugin.(HookPlugin); ok {
		// Register for all hooks (plugins can filter in OnHook)
		allHooks := []Hook{
			HookPreAuth, HookPostAuth, HookPreConnect, HookPostConnect,
			HookPreDisconnect, HookPostDisconnect, HookSessionStart,
			HookSessionEnd, HookAccessRequest, HookAccessGranted,
		}

		for _, hook := range allHooks {
			m.hookPlugins[hook] = append(m.hookPlugins[hook], hookPlugin)
		}
	}

	m.logger.Info("Registered plugin: %s v%s", name, plugin.Version())
	return nil
}

// Unregister unregisters a plugin
func (m *Manager) Unregister(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	plugin, exists := m.plugins[name]
	if !exists {
		return fmt.Errorf("plugin not found: %s", name)
	}

	delete(m.plugins, name)

	// Remove from hook plugins
	if hookPlugin, ok := plugin.(HookPlugin); ok {
		for hook, plugins := range m.hookPlugins {
			for i, p := range plugins {
				if p == hookPlugin {
					m.hookPlugins[hook] = append(plugins[:i], plugins[i+1:]...)
					break
				}
			}
		}
	}

	m.logger.Info("Unregistered plugin: %s", name)
	return nil
}

// Get returns a plugin by name
func (m *Manager) Get(name string) (Plugin, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	plugin, exists := m.plugins[name]
	if !exists {
		return nil, fmt.Errorf("plugin not found: %s", name)
	}

	return plugin, nil
}

// List returns all registered plugins
func (m *Manager) List() []Plugin {
	m.mu.RLock()
	defer m.mu.RUnlock()

	plugins := make([]Plugin, 0, len(m.plugins))
	for _, plugin := range m.plugins {
		plugins = append(plugins, plugin)
	}

	return plugins
}

// TriggerHook triggers a hook and calls all registered hook plugins
func (m *Manager) TriggerHook(ctx context.Context, hook Hook, hookCtx *HookContext) error {
	m.mu.RLock()
	plugins := m.hookPlugins[hook]
	m.mu.RUnlock()

	for _, plugin := range plugins {
		if err := plugin.OnHook(ctx, hook, hookCtx); err != nil {
			m.logger.Error("Hook %s failed for plugin %s: %v", hook, plugin.Name(), err)
			return fmt.Errorf("hook %s failed: %w", hook, err)
		}
	}

	return nil
}

// InitializeAll initializes all registered plugins.
func (m *Manager) InitializeAll(ctx context.Context, configs map[string]map[string]interface{}) map[string]error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	failed := make(map[string]error)

	for name, plugin := range m.plugins {
		config := configs[name]
		if config == nil {
			config = make(map[string]interface{})
		}

		if err := plugin.Initialize(ctx, config); err != nil {
			failed[name] = fmt.Errorf("initialize plugin %s: %w", name, err)
		}
	}

	if len(failed) == 0 {
		return nil
	}
	return failed
}

// ShutdownAll shuts down all registered plugins
func (m *Manager) ShutdownAll(ctx context.Context) error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for name, plugin := range m.plugins {
		if err := plugin.Shutdown(ctx); err != nil {
			m.logger.Error("Failed to shutdown plugin %s: %v", name, err)
		}
	}

	return nil
}
