# Orion Belt - Architecture Overview

## System Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           CLIENT LAYER                                  │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ┌──────────────┐                          ┌──────────────┐             │
│  │   osh CLI    │                          │   ocp CLI    │             │
│  │  (SSH Tool)  │                          │  (SCP Tool)  │             │
│  └──────┬───────┘                          └──────┬───────┘             │
│         │                                         │                     │
│         └─────────────────┬─────────────────────┘                       │
│                           │ SSH Protocol (Port 2222)                    │
└───────────────────────────┼─────────────────────────────────────────────┘
                            │
                            ▼
┌────────────────────────────────────────────────────────────────────────┐
│                        GATEWAY SERVER                                  │
├────────────────────────────────────────────────────────────────────────┤
│                                                                        │
│  ┌────────────────────────────────────────────────────────────┐        │
│  │              SSH Proxy Server (Port 2222)                  │        │
│  │  • Public Key Authentication                               │        │
│  │  • Session Management                                      │        │
│  │  • Connection Routing                                      │        │
│  └────────┬──────────────────────────────────────┬────────────┘        │
│           │                                      │                     │
│  ┌────────▼────────┐                   ┌─────────▼──────────┐          │
│  │  Auth Service   │◄──────────────────┤  Session Recorder  │          │
│  │  • ReBAC        │                   │  • Input/Output    │          │
│  │  • Permissions  │                   │  • Timestamped     │          │
│  │  • Access Req.  │                   │  • Replay Ready    │          │
│  └────────┬────────┘                   └────────────────────┘          │
│           │                                                            │
│  ┌────────▼────────────────────────────────────────────────┐           │
│  │              PostgreSQL Database                        │           │
│  │  Tables: users, machines, sessions, permissions,        │           │
│  │          access_requests, audit_logs                    │           │
│  └─────────────────────────────────────────────────────────┘           │
│                                                                        │
│  ┌─────────────────────────────────────────────────────────┐           │
│  │            REST API Server (Port 8080)                  │           │
│  │  • Agent Registration                                   │           │
│  │  • User Management                                      │           │
│  │  • Access Request Approval                              │           │
│  │  • Session Playback                                     │           │
│  └─────────────────────────────────────────────────────────┘           │
│                                                                        │
└────────────────────────────────────────────────────────────────────────┘
                            │
                            │ SSH Reverse Tunnel (Agent Connections)
                            │
        ┌───────────────────┼───────────────────┐
        │                   │                   │
        ▼                   ▼                   ▼
┌───────────────┐   ┌───────────────┐   ┌───────────────┐
│  Agent VM 1   │   │  Agent VM 2   │   │  Agent VM N   │
│               │   │               │   │               │
│ ┌───────────┐ │   │ ┌───────────┐ │   │ ┌───────────┐ │
│ │Agent Proc │ │   │ │Agent Proc │ │   │ │Agent Proc │ │
│ │• SSH Conn │ │   │ │• SSH Conn │ │   │ │• SSH Conn │ │
│ │• Heartbeat│ │   │ │• Heartbeat│ │   │ │• Heartbeat│ │
│ └─────┬─────┘ │   │ └─────┬─────┘ │   │ └─────┬─────┘ │
│       │       │   │       │       │   │       │       │
│ ┌─────▼─────┐ │   │ ┌─────▼─────┐ │   │ ┌─────▼─────┐ │
│ │Local SSHD │ │   │ │Local SSHD │ │   │ │Local SSHD │ │
│ │Port 22    │ │   │ │Port 22    │ │   │ │Port 22    │ │
│ └───────────┘ │   │ └───────────┘ │   │ └───────────┘ │
└───────────────┘   └───────────────┘   └───────────────┘
```

## How It Works

### 1. Agent Registration & Connection
Agents establish persistent SSH connections to the gateway server. Each agent authenticates using SSH keys and registers its machine identity. The gateway maintains these reverse tunnels, enabling it to reach target machines behind firewalls.

### 2. Client Authentication
Clients connect to the gateway using custom `osh`/`ocp` tools via SSH protocol. Authentication uses public key cryptography. The gateway validates credentials against PostgreSQL and checks ReBAC permissions before allowing access.

### 3. Connection Flow
When a client requests access to a target machine, the gateway:
- Authenticates the user
- Checks permissions (ReBAC)
- If permitted: Opens direct-tcpip channel through agent's reverse tunnel
- If denied: Offers to create access request for admin approval
- Records entire session (input/output with timestamps)

### 4. Session Recording
All interactions are captured at the gateway level. The recorder creates timestamped logs of every keystroke and output, enabling complete session replay for audit and compliance purposes.

### 5. Access Request Workflow
Unprivileged users can request temporary access. Admins receive notifications and approve/deny via REST API. Upon approval, time-limited permissions are automatically created and enforced.

## Key Features

**Security**: All traffic encrypted via SSH. Public key authentication. ReBAC permissions. Session recording. Audit logs.

**Scalability**: Agents use reverse tunnels, so no inbound firewall rules needed. Single gateway handles multiple target machines.

**Auditability**: Complete session recordings. Timestamped audit logs. Permission tracking. Access request history.

**Flexibility**: Temporary access grants. Tag-based machine grouping. Plugin system for notifications and custom workflows.

## Data Flow Example

```
Client (osh web-01) 
    → Gateway SSH Auth 
    → Permission Check 
    → Agent Reverse Tunnel (direct-tcpip) 
    → Local SSHD on web-01 
    → Shell Session
    → All I/O recorded
    → Session log stored
```

## Technology Stack

- **Language**: Go
- **Database**: PostgreSQL
- **Protocol**: SSH (golang.org/x/crypto/ssh)
- **Architecture**: Bastion/Jump Host pattern with reverse tunnels
- **Deployment**: Alpine Linux, Docker, or any Unix-like system