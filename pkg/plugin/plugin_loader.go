package plugin

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"plugin"
	"strings"
)

// PluginLoader handles dynamic loading of plugins from .so files
type PluginLoader struct {
	manager    *Manager
	pluginDir  string
	loadedLibs map[string]*plugin.Plugin
}

// NewPluginLoader creates a new plugin loader
func NewPluginLoader(manager *Manager, pluginDir string) *PluginLoader {
	return &PluginLoader{
		manager:    manager,
		pluginDir:  pluginDir,
		loadedLibs: make(map[string]*plugin.Plugin),
	}
}

// LoadAll discovers and loads all plugins from the plugin directory
func (l *PluginLoader) LoadAll(ctx context.Context) error {
	// Check if plugin directory exists
	if _, err := os.Stat(l.pluginDir); os.IsNotExist(err) {
		l.manager.logger.Warn("Plugin directory does not exist: %s", l.pluginDir)
		return nil
	}

	// Read directory
	entries, err := os.ReadDir(l.pluginDir)
	if err != nil {
		return fmt.Errorf("failed to read plugin directory: %w", err)
	}

	// Load each .so file
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		// Only load .so files
		if !strings.HasSuffix(entry.Name(), ".so") {
			continue
		}

		pluginPath := filepath.Join(l.pluginDir, entry.Name())
		if err := l.LoadPlugin(ctx, pluginPath); err != nil {
			l.manager.logger.Error("Failed to load plugin %s: %v", entry.Name(), err)
			// Continue loading other plugins even if one fails
			continue
		}
	}

	return nil
}

// LoadPlugin loads a single plugin from a .so file
func (l *PluginLoader) LoadPlugin(ctx context.Context, path string) error {
	l.manager.logger.Info("Loading plugin from: %s", path)

	// Open the plugin
	p, err := plugin.Open(path)
	if err != nil {
		return fmt.Errorf("failed to open plugin: %w", err)
	}

	// Look for the NewPlugin symbol
	symNewPlugin, err := p.Lookup("NewPlugin")
	if err != nil {
		return fmt.Errorf("plugin does not export NewPlugin function: %w", err)
	}

	// Type assert to function that returns Plugin
	newPluginFunc, ok := symNewPlugin.(func() Plugin)
	if !ok {
		return fmt.Errorf("NewPlugin has incorrect signature, expected func() Plugin")
	}

	// Create plugin instance
	pluginInstance := newPluginFunc()

	// Register with manager
	if err := l.manager.Register(pluginInstance); err != nil {
		return fmt.Errorf("failed to register plugin: %w", err)
	}

	// Store reference to loaded library
	l.loadedLibs[pluginInstance.Name()] = p

	l.manager.logger.Info("Successfully loaded plugin: %s v%s",
		pluginInstance.Name(), pluginInstance.Version())

	return nil
}

// LoadPluginWithConfig loads a plugin and initializes it with config
func (l *PluginLoader) LoadPluginWithConfig(ctx context.Context, path string, config map[string]interface{}) error {
	if err := l.LoadPlugin(ctx, path); err != nil {
		return err
	}

	var pluginName string
	for name := range l.loadedLibs {
		pluginName = name
	}

	if pluginName == "" {
		return fmt.Errorf("no plugin was loaded")
	}

	plugin, err := l.manager.Get(pluginName)
	if err != nil {
		return err
	}

	// Initialize with config
	return plugin.Initialize(ctx, config)
}

// UnloadPlugin unloads a plugin (note: Go plugins can't actually be unloaded)
func (l *PluginLoader) UnloadPlugin(name string) error {
	l.manager.logger.Warn("Attempting to unload plugin %s (Note: Go plugins cannot be truly unloaded from memory)", name)

	// Unregister from manager
	if err := l.manager.Unregister(name); err != nil {
		return err
	}

	// Remove from loaded libs map
	delete(l.loadedLibs, name)

	return nil
}

// GetLoadedPlugins returns a list of loaded plugin library paths
func (l *PluginLoader) GetLoadedPlugins() map[string]*plugin.Plugin {
	return l.loadedLibs
}
