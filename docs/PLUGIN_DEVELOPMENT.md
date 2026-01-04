# Orion-Belt Plugin Development Guide

## Overview

Orion-Belt supports dynamic plugin loading using Go's native `plugin` package. Plugins are compiled as `.so` (shared object) files and loaded at runtime by the server.

## Plugin Architecture

Plugins implement the `Plugin` interface and optionally the `HookPlugin` interface to respond to system events:

```go
type Plugin interface {
    Name() string
    Version() string
    Initialize(ctx context.Context, config map[string]interface{}) error
    Shutdown(ctx context.Context) error
}

type HookPlugin interface {
    Plugin
    OnHook(ctx context.Context, hook Hook, hookCtx *HookContext) error
}
```

## Available Hooks

- `HookPreAuth` - Before user authentication
- `HookPostAuth` - After successful authentication
- `HookPreConnect` - Before establishing connection to target machine
- `HookPostConnect` - After connection established
- `HookPreDisconnect` - Before disconnection
- `HookPostDisconnect` - After disconnection
- `HookSessionStart` - When a session starts
- `HookSessionEnd` - When a session ends
- `HookAccessRequest` - When user requests access
- `HookAccessGranted` - When access is granted

## Creating a Plugin

### Step 1: Create Plugin Directory Structure

```bash
mkdir -p plugins/my-plugin
cd plugins/my-plugin
```

### Step 2: Implement the Plugin

Create `main.go`:

```go
package main

import (
    "context"
    "log"
    
    "github.com/zrougamed/orion-belt/pkg/plugin"
)

type MyPlugin struct {
    name    string
    version string
    config  map[string]interface{}
}

// NewPlugin is the required entry point - MUST be exported
func NewPlugin() plugin.Plugin {
    return &MyPlugin{
        name:    "my-plugin",
        version: "1.0.0",
    }
}

func (p *MyPlugin) Name() string {
    return p.name
}

func (p *MyPlugin) Version() string {
    return p.version
}

func (p *MyPlugin) Initialize(ctx context.Context, config map[string]interface{}) error {
    p.config = config
    log.Printf("[%s] Initialized with config: %v", p.name, config)
    return nil
}

func (p *MyPlugin) Shutdown(ctx context.Context) error {
    log.Printf("[%s] Shutting down", p.name)
    return nil
}

// Implement HookPlugin interface
func (p *MyPlugin) OnHook(ctx context.Context, hook plugin.Hook, hookCtx *plugin.HookContext) error {
    switch hook {
    case plugin.HookSessionStart:
        log.Printf("[%s] Session started: user=%s, machine=%s", 
            p.name, hookCtx.UserID, hookCtx.MachineID)
    case plugin.HookSessionEnd:
        log.Printf("[%s] Session ended: user=%s, machine=%s", 
            p.name, hookCtx.UserID, hookCtx.MachineID)
    }
    return nil
}

// Verify interface implementation at compile time
var _ plugin.Plugin = (*MyPlugin)(nil)
var _ plugin.HookPlugin = (*MyPlugin)(nil)
```

### Step 3: Build the Plugin

```bash
# From the plugin directory
go build -buildmode=plugin -o my-plugin.so main.go

# Or use the Makefile
cd ../..
make plugins
```

### Step 4: Install the Plugin

```bash
# Copy to plugin directory
sudo mkdir -p /etc/orion-belt/plugins
sudo cp my-plugin.so /etc/orion-belt/plugins/
```

### Step 5: Configure the Plugin

Add configuration to `server.yaml`:

```yaml
server:
  plugin_dir: "/etc/orion-belt/plugins"

plugins:
  my-plugin:
    setting1: "value1"
    setting2: 42
    enabled: true
```

## Plugin Development Best Practices

### 1. Always Export NewPlugin Function

The plugin loader looks for a `NewPlugin() plugin.Plugin` function. This MUST be exported (capital N).

```go
func NewPlugin() plugin.Plugin {
    return &MyPlugin{}
}
```

### 2. Handle Configuration Safely

Always check types when accessing config values:

```go
func (p *MyPlugin) Initialize(ctx context.Context, config map[string]interface{}) error {
    if val, ok := config["setting"].(string); ok {
        p.setting = val
    } else {
        p.setting = "default"
    }
    return nil
}
```

### 3. Filter Hooks in OnHook

Not all hooks may be relevant to your plugin. Filter in `OnHook`:

```go
func (p *MyPlugin) OnHook(ctx context.Context, hook plugin.Hook, hookCtx *plugin.HookContext) error {
    // Only handle specific hooks
    switch hook {
    case plugin.HookSessionStart, plugin.HookSessionEnd:
        // Handle these hooks
        return p.handleSession(hookCtx)
    default:
        // Ignore others
        return nil
    }
}
```

### 4. Error Handling

If a plugin returns an error from `OnHook`, the hook execution stops and the error is logged. Use this wisely:

```go
func (p *MyPlugin) OnHook(ctx context.Context, hook plugin.Hook, hookCtx *plugin.HookContext) error {
    // Critical error - block operation
    if !p.validateUser(hookCtx.UserID) {
        return fmt.Errorf("user validation failed")
    }
    
    // Non-critical - just log
    if err := p.sendNotification(); err != nil {
        log.Printf("Failed to send notification: %v", err)
        // Don't return error - allow operation to continue
    }
    
    return nil
}
```

### 5. Resource Cleanup

Always clean up resources in `Shutdown`:

```go
func (p *MyPlugin) Shutdown(ctx context.Context) error {
    if p.connection != nil {
        p.connection.Close()
    }
    if p.logFile != nil {
        p.logFile.Close()
    }
    return nil
}
```

## Plugin Examples

### Example 1: Audit Logger Plugin

Logs all events to a file:

```go
type AuditPlugin struct {
    logFile *os.File
}

func (p *AuditPlugin) OnHook(ctx context.Context, hook plugin.Hook, hookCtx *plugin.HookContext) error {
    logLine := fmt.Sprintf("[%s] %s - User: %s, Machine: %s\n",
        time.Now().Format(time.RFC3339),
        hook,
        hookCtx.UserID,
        hookCtx.MachineID,
    )
    p.logFile.WriteString(logLine)
    return nil
}
```

### Example 2: Slack Notification Plugin

Sends notifications to Slack:

```go
type SlackPlugin struct {
    webhookURL string
}

func (p *SlackPlugin) OnHook(ctx context.Context, hook plugin.Hook, hookCtx *plugin.HookContext) error {
    if hook == plugin.HookAccessRequest {
        message := fmt.Sprintf("Access request: User %s → Machine %s",
            hookCtx.UserID, hookCtx.MachineID)
        return p.sendToSlack(message)
    }
    return nil
}
```

### Example 3: Rate Limiting Plugin

Prevents abuse by rate limiting:

```go
type RateLimitPlugin struct {
    limits map[string]*rate.Limiter
    mu     sync.RWMutex
}

func (p *RateLimitPlugin) OnHook(ctx context.Context, hook plugin.Hook, hookCtx *plugin.HookContext) error {
    if hook == plugin.HookPreAuth {
        if !p.checkRateLimit(hookCtx.UserID) {
            return fmt.Errorf("rate limit exceeded")
        }
    }
    return nil
}
```

## Testing Plugins

### Manual Testing

```bash
# Build plugin
go build -buildmode=plugin -o test-plugin.so main.go

# Start server with plugin directory
orion-belt-server --config server.yaml

# Check logs for plugin loading
tail -f /var/log/orion-belt/server.log | grep plugin
```

### Unit Testing

While `.so` plugins can't be unit tested directly, you can test the plugin logic:

```go
package main

import (
    "context"
    "testing"
)

func TestPluginInitialize(t *testing.T) {
    p := NewPlugin().(*MyPlugin)
    
    config := map[string]interface{}{
        "setting": "value",
    }
    
    if err := p.Initialize(context.Background(), config); err != nil {
        t.Fatalf("Initialize failed: %v", err)
    }
}
```

## Important Limitations

### 1. Plugin Versioning

Plugins MUST be compiled with the exact same Go version as the server. Mismatched versions will fail to load.

### 2. Cannot Unload Plugins

Go plugins cannot be unloaded from memory once loaded. Restarting the server is required to update plugins.

### 3. Platform Specific

Go plugins only work on Linux and macOS. Windows is not supported.

### 4. Dependency Compatibility

Plugins must use compatible versions of shared dependencies with the server.

## Troubleshooting

### Plugin Not Loading

Check:
- Plugin file has `.so` extension
- Plugin is in configured `plugin_dir`
- `NewPlugin()` function is exported
- Plugin compiled with same Go version as server
- Check server logs for specific error

### Plugin Crashes Server

- Ensure plugin doesn't panic
- Add recover() in critical sections
- Test plugin thoroughly before deployment

### Hook Not Firing

- Verify plugin implements `HookPlugin` interface
- Check `OnHook` method signature is correct
- Ensure plugin is registered successfully (check logs)

## Distribution

When distributing plugins:

1. Document required Go version
2. Provide installation instructions
3. Include example configuration
4. Document required dependencies
5. Provide version compatibility matrix

## Security Considerations

1. **Validate all inputs** from config and hooks
2. **Sanitize data** before using in external systems
3. **Handle credentials securely** (use environment variables or key management)
4. **Log security events** appropriately
5. **Test error paths** thoroughly

