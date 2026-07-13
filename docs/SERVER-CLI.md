# Orion-Belt Server CLI

Command-line interface for managing the Orion-Belt server, agents, users, and permissions.

## Configuration

The server looks for configuration files in the following order:

1. Path specified with `--config` flag
2. `/etc/orion-belt/server.yaml`
3. `<executable-dir>/../config/server.yaml`
4. `<executable-dir>/config/server.yaml`
5. `./config/server.yaml`
6. `./server.yaml`

### Check Configuration

```bash
# Show which config file will be used
orion-belt-server config path

# Show all search paths
orion-belt-server config locations

# Display current configuration
orion-belt-server config show
```

Example output:
```
$ orion-belt-server config locations
Config file search paths (in order):
  1. [✗] /etc/orion-belt/server.yaml
  2. [✓] /opt/orion-belt/config/server.yaml
  3. [✗] /opt/orion-belt/bin/config/server.yaml
  4. [✗] ./config/server.yaml
  5. [✗] ./server.yaml

Note: The first existing file will be used.
```

## Server Management

### Start the Server

```bash
# Start with default config
orion-belt-server
orion-belt-server start

# Start with specific config
orion-belt-server --config /path/to/config.yaml

# Start with debug logging
orion-belt-server --log-level debug
```

## Agent Management

### Register an Agent

```bash
orion-belt-server agent register \
  --name <agent-name> \
  --key "<ssh-public-key>" \
  [--hostname <hostname>] \
  [--port <port>] \
  [--tags key1=value1,key2=value2]
```

**Examples:**

```bash
# Basic registration
orion-belt-server agent register \
  --name machine-32 \
  --key "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKHHyXRMTiKfb3h..."

# With hostname and tags
orion-belt-server agent register \
  --name web-01 \
  --key "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC..." \
  --hostname 192.168.1.100 \
  --port 22 \
  --tags environment=production,role=web

# With multiple tags
orion-belt-server agent register \
  --name db-01 \
  --key "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample..." \
  --tags environment=production,role=database,tier=backend
```

**Output:**
```
Agent registered successfully:
  Name:       machine-32
  User ID:    uuid-abc-123
  Machine ID: uuid-def-456
  Hostname:   machine-32
  Port:       22

Agent 'machine-32' can now connect to the server using:
  orion-belt-agent -c /path/to/agent.yaml
```

### List Agents

```bash
orion-belt-server agent list
```

**Output:**
```
NAME         HOSTNAME       PORT  STATUS   LAST SEEN             TAGS
----         --------       ----  ------   ---------             ----
machine-32   machine-32     22    online   2026-01-04 10:30:15   
web-01       192.168.1.100  22    online   2026-01-04 10:25:00   environment=production, role=web
db-01        192.168.1.101  22    offline  2026-01-04 09:15:30   environment=production, role=database
```

### Delete an Agent

```bash
orion-belt-server agent delete <agent-name>
```

**Example:**
```bash
orion-belt-server agent delete machine-32
# Output: Agent 'machine-32' deleted successfully.
```

## User Management

### Create a User

```bash
orion-belt-server user create \
  --name <username> \
  --email <email> \
  --key "<ssh-public-key>" \
  [--admin]
```

**Examples:**

```bash
# Create regular user
orion-belt-server user create \
  --name alice \
  --email alice@example.com \
  --key "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC..."

# Create admin user
orion-belt-server user create \
  --name admin \
  --email admin@example.com \
  --key "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample..." \
  --admin
```

**Output:**
```
User created successfully:
  Username: alice
  Email:    alice@example.com
  User ID:  uuid-xyz-789
  Admin:    false

User 'alice' can now connect using:
  osh machine-name
```

### List Users

```bash
orion-belt-server user list
```

**Output:**
```
USERNAME  EMAIL                  ADMIN  CREATED
--------  -----                  -----  -------
admin     admin@example.com      yes    2026-01-04 08:00:00
alice     alice@example.com      no     2026-01-04 09:15:30
bob       bob@example.com        no     2026-01-04 10:30:15
```

### Delete a User

```bash
orion-belt-server user delete <username>
```

**Example:**
```bash
orion-belt-server user delete alice
# Output: User 'alice' deleted successfully.
```

## Permission Management

### Grant Permission

```bash
orion-belt-server permission grant \
  --user <username> \
  --machine <machine-name> \
  --type <access-type> \
  [--duration <seconds>]
```

**Access Types:**
- `ssh` - SSH access only
- `scp` - SCP (file transfer) access only
- `both` - Both SSH and SCP access

**Examples:**

```bash
# Grant permanent SSH access
orion-belt-server permission grant \
  --user alice \
  --machine web-01 \
  --type ssh

# Grant temporary access (1 hour = 3600 seconds)
orion-belt-server permission grant \
  --user bob \
  --machine db-01 \
  --type both \
  --duration 3600

# Grant temporary access (8 hours)
orion-belt-server permission grant \
  --user alice \
  --machine db-01 \
  --type ssh \
  --duration 28800
```

**Output:**
```
Permission granted successfully:
  User:        alice
  Machine:     web-01
  Access Type: ssh
  Duration:    permanent
```

Or with expiration:
```
Permission granted successfully:
  User:        bob
  Machine:     db-01
  Access Type: both
  Duration:    3600 seconds
  Expires:     2026-01-04 11:30:15
```

### List Permissions

```bash
# List permissions for a specific user
orion-belt-server permission list <username>
```

**Example:**
```bash
orion-belt-server permission list alice
```

**Output:**
```
Permissions for user 'alice':

MACHINE  ACCESS TYPE  GRANTED     EXPIRES
-------  -----------  -------     -------
web-01   ssh          2026-01-04  never
db-01    ssh          2026-01-04  2026-01-04 11:30:15
```

## Session Management

### List Active Sessions

```bash
orion-belt-server session list
```

**Output:**
```
USER   MACHINE  START TIME           DURATION
----   -------  ----------           --------
alice  web-01   2026-01-04 10:30:15  5m30s
bob    db-01    2026-01-04 10:32:00  3m45s
```

## Common Workflows

### 1. Register and Grant Access to a New Machine

```bash
# 1. Register the agent
orion-belt-server agent register \
  --name app-server-01 \
  --key "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample..." \
  --hostname 10.0.1.50 \
  --tags environment=production,role=application

# 2. Grant access to a user
orion-belt-server permission grant \
  --user alice \
  --machine app-server-01 \
  --type ssh

# 3. Verify
orion-belt-server agent list
orion-belt-server permission list alice
```

### 2. Onboard a New User

```bash
# 1. Create the user
orion-belt-server user create \
  --name charlie \
  --email charlie@example.com \
  --key "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCExample..."

# 2. Grant access to specific machines
orion-belt-server permission grant \
  --user charlie \
  --machine web-01 \
  --type ssh

orion-belt-server permission grant \
  --user charlie \
  --machine app-server-01 \
  --type both

# 3. Verify
orion-belt-server permission list charlie
```

### 3. Grant Temporary Emergency Access

```bash
# Grant 2-hour access to production database
orion-belt-server permission grant \
  --user alice \
  --machine prod-db-01 \
  --type ssh \
  --duration 7200
```

## Global Flags

All commands support these global flags:

```bash
-c      Config file path (default: auto-detect)
-l      Log level: debug, info, warn, error (default: info)
```

**Examples:**

```bash
# Use specific config
orion-belt-server -c /custom/path/config.yaml agent list

# Enable debug logging
orion-belt-server -l debug user list

# Combine both
orion-belt-server -c /custom/config.yaml -l debug agent register ...
```

## Tips

1. **Check config before running commands:**

```bash
orion-belt-server config path
```
2. **Use tab completion** (if shell completion is set up)
3. **SSH key format:** Keys must start with `ssh-rsa`, `ssh-ed25519`, `ecdsa-sha2-nistp256`, etc.
4. **View all available commands:**
```bash
orion-belt-server --help
orion-belt-server agent --help
orion-belt-server user --help
```
5. **Durations are in seconds:**
   - 1 hour = 3600
   - 8 hours = 28800
   - 1 day = 86400
   - 1 week = 604800