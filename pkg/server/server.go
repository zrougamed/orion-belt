package server

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/zrougamed/orion-belt/pkg/api"
	"github.com/zrougamed/orion-belt/pkg/auth"
	"github.com/zrougamed/orion-belt/pkg/authz"
	"github.com/zrougamed/orion-belt/pkg/common"
	"github.com/zrougamed/orion-belt/pkg/database"
	"github.com/zrougamed/orion-belt/pkg/metrics"
	"github.com/zrougamed/orion-belt/pkg/plugin"
	"github.com/zrougamed/orion-belt/pkg/recording"
	webauthnlib "github.com/go-webauthn/webauthn/webauthn"
	"golang.org/x/crypto/ssh"
)

// Server represents the Orion-Belt SSH server
type Server struct {
	config        *common.Config
	store         database.Store
	authService   *auth.AuthService
	recorder      *recording.Recorder
	pluginManager *plugin.Manager
	logger        *common.Logger
	sshConfig     *ssh.ServerConfig
	listener      net.Listener
	apiServer     *api.APIServer
	agents        map[string]*AgentConnection
	agentsMu      sync.RWMutex
	shutdown      chan struct{}
}

// AgentConnection represents a connection from an agent
type AgentConnection struct {
	MachineID string
	SSHConn   *ssh.ServerConn
	Channels  <-chan ssh.NewChannel
	Requests  <-chan *ssh.Request
	LastSeen  time.Time
}

// New creates a new Orion-Belt server
func New(config *common.Config, logger *common.Logger) (*Server, error) {
	// Initialize database
	store, err := database.NewStore(config.Database.Driver, config.Database.ConnectionString)
	if err != nil {
		return nil, fmt.Errorf("failed to create database store: %w", err)
	}

	// Connect to database
	ctx := context.Background()
	if err := store.Connect(ctx); err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	// Run migrations
	if err := store.Migrate(ctx); err != nil {
		return nil, fmt.Errorf("failed to run migrations: %w", err)
	}

	// Initialize services
	authService := auth.NewAuthService(store, logger)

	if fga, err := authz.NewOpenFGA(config.Auth.OpenFGA, logger); err != nil {
		return nil, fmt.Errorf("openfga config: %w", err)
	} else if fga != nil {
		authService.SetAuthorizer(fga)
		logger.Info("OpenFGA authorizer enabled (%s)", config.Auth.OpenFGA.APIURL)
	}

	// Initialize recorder
	storagePath := resolveDirWithCreate(
		config.Recording.StoragePath,
		"/etc/orion-belt/recordings",
		logger,
	)
	recorder, err := recording.NewRecorder(storagePath, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to create recorder: %w", err)
	}

	recCrypto, err := recording.NewCrypto(config.Recording.EncryptionKey, logger)
	if err != nil {
		return nil, fmt.Errorf("recording encryption: %w", err)
	}
	recorder.SetCrypto(recCrypto)
	if recCrypto.Enabled() {
		logger.Info("Session recording encryption enabled")
	}

	var wa *webauthnlib.WebAuthn
	if config.Auth.WebAuthn.Enabled {
		display := config.Auth.WebAuthn.RPDisplay
		if display == "" {
			display = "Orion Belt"
		}
		rpid := config.Auth.WebAuthn.RPID
		if rpid == "" {
			rpid = "localhost"
		}
		origins := config.Auth.WebAuthn.Origins
		if len(origins) == 0 {
			origins = []string{"http://localhost:8080", "https://localhost:8080"}
		}
		wa, err = webauthnlib.New(&webauthnlib.Config{
			RPDisplayName: display,
			RPID:          rpid,
			RPOrigins:     origins,
		})
		if err != nil {
			return nil, fmt.Errorf("webauthn: %w", err)
		}
		logger.Info("WebAuthn/FIDO2 enabled (rp_id=%s)", rpid)
	}

	// Initialize plugin manager
	pluginManager := plugin.NewManager(logger)
	pluginDir := resolveDirWithCreate(
		config.Server.PluginDir,
		"/etc/orion-belt/plugins",
		logger,
	)
	pluginManager.SetPluginDirectory(pluginDir)

	// Load all plugins from the directory
	if err := pluginManager.LoadPlugins(ctx); err != nil {
		logger.Warn("Failed to load plugins: %v", err)
		// log and continue on failure
	}

	// Initialize loaded plugins with their configs
	if len(config.Plugins) > 0 {
		if failed := pluginManager.InitializeAll(ctx, config.Plugins); failed != nil {
			for name, err := range failed {
				logger.Warn("plugin %s failed: %v", name, err)
			}
		}
	}

	// Initialize API server
	apiServer := api.NewAPIServer(store, authService, logger, api.Options{
		JWTSecret:          config.Auth.JWTSecret,
		JWTExpiryHours:     config.Auth.JWTExpiryHours,
		PluginManager:      pluginManager,
		MetricsEnabled:     true,
		MFARequired:        config.Auth.MFARequired,
		RecordingCrypt:     recCrypto,
		Recorder:           recorder,
		WebAuthn:           wa,
		RateLimitPerMinute: config.Auth.RateLimitPerMinute,
	})

	server := &Server{
		config:        config,
		store:         store,
		authService:   authService,
		recorder:      recorder,
		pluginManager: pluginManager,
		apiServer:     apiServer,
		logger:        logger,
		agents:        make(map[string]*AgentConnection),
		shutdown:      make(chan struct{}),
	}

	apiServer.SetAgentCommander(server)
	apiServer.SetTerminalBridge(server)

	// Configure SSH server
	if err := server.setupSSHConfig(); err != nil {
		return nil, fmt.Errorf("failed to setup SSH config: %w", err)
	}

	return server, nil
}

// setupSSHConfig sets up the SSH server configuration
func (s *Server) setupSSHConfig() error {
	s.sshConfig = &ssh.ServerConfig{
		PublicKeyCallback: s.handlePublicKeyAuth,
		ServerVersion:     "SSH-2.0-OrionBelt",
	}

	// Load host key
	if s.config.Server.SSHHostKey != "" {
		privateBytes, err := os.ReadFile(s.config.Server.SSHHostKey)
		if err != nil {
			return fmt.Errorf("failed to read host key: %w", err)
		}

		private, err := ssh.ParsePrivateKey(privateBytes)
		if err != nil {
			return fmt.Errorf("failed to parse host key: %w", err)
		}

		s.sshConfig.AddHostKey(private)
	} else {
		return fmt.Errorf("SSH host key not configured")
	}

	return nil
}

// Start starts the SSH server
func (s *Server) Start() error {
	// Determine API port (default to 8080 if not configured)
	apiPort := s.config.Server.APIPort
	if apiPort == 0 {
		apiPort = 8080
	}

	// Start API server in a goroutine
	apiAddr := fmt.Sprintf("%s:%d", s.config.Server.Host, apiPort)
	go func() {
		if err := s.apiServer.Start(apiAddr); err != nil {
			s.logger.Error("API server error: %v", err)
		}
	}()

	// Start SSH server
	addr := fmt.Sprintf("%s:%d", s.config.Server.Host, s.config.Server.Port)

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", addr, err)
	}
	s.listener = listener

	s.logger.Info("Starting Orion-Belt SSH server on %s", addr)

	// Periodic recording retention cleanup
	if s.config.Recording.RetentionDays > 0 {
		go s.runRetentionLoop()
	}

	for {
		select {
		case <-s.shutdown:
			return nil
		default:
			tcpConn, err := listener.Accept()
			if err != nil {
				select {
				case <-s.shutdown:
					return nil
				default:
					s.logger.Error("Failed to accept connection: %v", err)
					continue
				}
			}

			go s.handleConnection(tcpConn)
		}
	}
}

// handleConnection handles a new TCP connection
func (s *Server) handleConnection(tcpConn net.Conn) {
	// Perform SSH handshake
	sshConn, chans, reqs, err := ssh.NewServerConn(tcpConn, s.sshConfig)
	if err != nil {
		s.logger.Debug("SSH handshake failed: %v", err)
		tcpConn.Close()
		return
	}

	// Get authenticated user from connection metadata
	user := sshConn.Permissions.Extensions["user"]
	userID := sshConn.Permissions.Extensions["user_id"]

	s.logger.Info("New SSH connection from user: %s (ID: %s)", user, userID)

	// Check if this is an agent connection
	ctx := context.Background()
	machine, err := s.store.GetMachineByName(ctx, user)
	if err == nil {
		s.logger.Info("Machine found in database: %s (agent_id: %s, user_id: %s)", machine.Name, machine.AgentID, userID)
		// Check if the user is the agent for this machine
		if machine.AgentID == userID {
			// This is an agent connection
			s.handleAgentConnection(sshConn, chans, reqs, machine)
			return
		} else {
			s.logger.Info("User %s is not the agent for machine %s (expected agent_id: %s, got user_id: %s)", user, machine.Name, machine.AgentID, userID)
		}
	} else {
		s.logger.Info("Machine lookup failed for user '%s': %v", user, err)
	}

	s.logger.Info("Treating connection as client connection for user: %s", user)

	// This is a client connection
	sshUser := sshConn.Permissions.Extensions["ssh_user"]
	if sshUser == "" {
		sshUser = user
	}
	s.handleClientConnection(sshConn, chans, reqs, userID, user, sshUser)
}

// handlePublicKeyAuth handles SSH public key authentication
func (s *Server) handlePublicKeyAuth(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	username := conn.User()

	s.logger.Debug("Authentication attempt for user: %s", username)

	// Convert ssh.PublicKey to the type expected by AuthenticateUser
	user, err := s.authService.AuthenticateUser(context.Background(), username, key)
	if err != nil {
		s.logger.Warn("Authentication failed for user: %s", username)
		return nil, fmt.Errorf("authentication failed")
	}

	if s.config.Auth.MFARequired && !user.MFAEnabled {
		s.logger.Warn("SSH denied for %s: MFA enrollment required", username)
		return nil, fmt.Errorf("mfa enrollment required")
	}

	// Store user info in permissions
	perms := &ssh.Permissions{
		Extensions: map[string]string{
			"user":     user.Username,
			"user_id":  user.ID,
			"ssh_user": conn.User(), // may include +machine for OpenSSH agentless
		},
	}

	// Trigger post-auth hook (auth already succeeded)
	hookCtx := &plugin.HookContext{
		UserID: user.ID,
		Data:   make(map[string]interface{}),
	}
	s.pluginManager.TriggerHook(context.Background(), plugin.HookPostAuth, hookCtx)

	return perms, nil
}

// handleAgentConnection handles an agent SSH connection
func (s *Server) handleAgentConnection(sshConn *ssh.ServerConn, chans <-chan ssh.NewChannel, reqs <-chan *ssh.Request, machine *common.Machine) {
	s.logger.Info("Agent connection detected for machine: %s", machine.Name)

	// Register agent
	agentConn := &AgentConnection{
		MachineID: machine.ID,
		SSHConn:   sshConn,
		Channels:  chans,
		Requests:  reqs,
		LastSeen:  time.Now(),
	}

	s.agentsMu.Lock()
	s.agents[machine.ID] = agentConn
	agentCount := len(s.agents)
	s.agentsMu.Unlock()
	metrics.Default.SetAgentsConnected(int64(agentCount))

	// Update machine status
	ctx := context.Background()
	now := time.Now()
	machine.IsActive = true
	machine.LastSeenAt = &now
	s.store.UpdateMachine(ctx, machine)

	s.logger.Info("Agent registered: %s", machine.Name)

	// Handle global requests (like keepalive)
	go func() {
		for req := range reqs {
			s.logger.Debug("Agent global request: %s", req.Type)
			if req.WantReply {
				req.Reply(false, nil)
			}
		}
	}()

	// Handle agent channels
	go func() {
		for newChannel := range chans {
			if newChannel.ChannelType() != "session" {
				newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
				continue
			}

			channel, requests, err := newChannel.Accept()
			if err != nil {
				s.logger.Error("Failed to accept channel: %v", err)
				continue
			}

			// Handle session requests
			go s.handleAgentSession(channel, requests, machine)
		}
	}()

	// Wait for connection to close
	sshConn.Wait()

	// Unregister agent
	s.agentsMu.Lock()
	delete(s.agents, machine.ID)
	agentCount = len(s.agents)
	s.agentsMu.Unlock()
	metrics.Default.SetAgentsConnected(int64(agentCount))

	// Update machine status
	machine.IsActive = false
	s.store.UpdateMachine(ctx, machine)

	s.logger.Info("Agent disconnected: %s", machine.Name)
}

// handleAgentSession handles agent session requests
func (s *Server) handleAgentSession(channel ssh.Channel, requests <-chan *ssh.Request, machine *common.Machine) {
	defer channel.Close()

	for req := range requests {
		switch req.Type {
		case "exec":
			// Parse command
			var payload struct {
				Command string
			}
			if err := ssh.Unmarshal(req.Payload, &payload); err != nil {
				req.Reply(false, nil)
				continue
			}

			s.logger.Debug("Agent exec request: %s", payload.Command)

			// Handle agent commands
			switch payload.Command {
			case "agent-register":
				req.Reply(true, nil)
				channel.Write([]byte("Agent registered\n"))
				channel.SendRequest("exit-status", false, []byte{0, 0, 0, 0})
			case "heartbeat":
				req.Reply(true, nil)
				// Update last seen
				s.agentsMu.Lock()
				if agent, exists := s.agents[machine.ID]; exists {
					agent.LastSeen = time.Now()
				}
				s.agentsMu.Unlock()
				channel.SendRequest("exit-status", false, []byte{0, 0, 0, 0})
				channel.Close()
			default:
				req.Reply(false, nil)
			}

		default:
			if req.WantReply {
				req.Reply(false, nil)
			}
		}
	}
}

// handleClientConnection handles a client SSH connection
func (s *Server) handleClientConnection(sshConn *ssh.ServerConn, chans <-chan ssh.NewChannel, reqs <-chan *ssh.Request, userID, username, sshUser string) {
	defer sshConn.Close()

	// Discard global requests
	go ssh.DiscardRequests(reqs)

	// Handle each channel
	for newChannel := range chans {
		if newChannel.ChannelType() != "session" {
			newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
			continue
		}

		channel, requests, err := newChannel.Accept()
		if err != nil {
			s.logger.Error("Failed to accept channel: %v", err)
			continue
		}

		go s.handleClientSession(channel, requests, userID, username, sshUser)
	}
}

// handleClientSession handles a client session (osh or vanilla OpenSSH).
func (s *Server) handleClientSession(channel ssh.Channel, requests <-chan *ssh.Request, userID, username, sshUser string) {
	defer channel.Close()

	var (
		ptyReq    *ptyRequest
		wantShell bool
		target    string
	)

	_, remoteUser, machineFromUser := common.ParseGatewaySSHUser(sshUser)
	if machineFromUser != "" {
		target = common.FormatTarget(remoteUser, machineFromUser)
	}

	for req := range requests {
		switch req.Type {
		case "exec":
			var payload struct {
				Command string
			}
			if err := ssh.Unmarshal(req.Payload, &payload); err != nil {
				req.Reply(false, nil)
				return
			}
			s.logger.Info("Client exec command: '%s'", payload.Command)
			req.Reply(true, nil)
			s.proxyToMachine(channel, payload.Command, userID, username, ptyReq, nil)
			return

		case "shell":
			wantShell = true
			req.Reply(true, nil)

		case "pty-req":
			ptyReq = &ptyRequest{}
			_ = ssh.Unmarshal(req.Payload, ptyReq)
			req.Reply(true, nil)

		case "env":
			req.Reply(true, nil)

		case "subsystem":
			var payload struct{ Name string }
			if err := ssh.Unmarshal(req.Payload, &payload); err == nil && payload.Name == "sftp" {
				req.Reply(false, nil)
				channel.Write([]byte("SFTP subsystem not available; use ocp or the web file browser.\n"))
				return
			}
			if req.WantReply {
				req.Reply(false, nil)
			}

		default:
			if req.WantReply {
				req.Reply(false, nil)
			}
		}

		if wantShell {
			if target == "" {
				msg := "Orion-Belt Gateway (OpenSSH compatible)\n\n" +
					"Usage:\n" +
					"  ssh alice+web-01@gateway              # interactive shell as root@web-01\n" +
					"  ssh alice+bob%web-01@gateway          # interactive shell as bob@web-01\n" +
					"  ssh alice@gateway 'bob@web-01'        # exec form (also works)\n" +
					"  ssh alice@gateway 'bob@web-01 uptime' # remote command\n\n" +
					"See docs/openssh-clients.md for ssh_config snippets.\n"
				channel.Write([]byte(msg))
				return
			}
			s.proxyToMachine(channel, target, userID, username, ptyReq, requests)
			return
		}
	}
}

type ptyRequest struct {
	Term     string
	Columns  uint32
	Rows     uint32
	Width    uint32
	Height   uint32
	Modelist string
}

// proxyToMachine proxies a client session to a target machine through an agent
func (s *Server) proxyToMachine(clientChannel ssh.Channel, commandLine, userID, username string, ptyReq *ptyRequest, remainingReqs <-chan *ssh.Request) {
	ctx := context.Background()

	s.logger.Info("proxyToMachine called: commandLine='%s', user='%s', userID='%s'", commandLine, username, userID)

	var remoteUser, machineName, remoteCommand string
	parts := strings.SplitN(commandLine, " ", 2)
	target := parts[0]
	if len(parts) > 1 {
		remoteCommand = parts[1]
	}

	// Extract remoteUser@machine
	if strings.Contains(target, "@") {
		userMachine := strings.SplitN(target, "@", 2)
		remoteUser = userMachine[0]
		machineName = userMachine[1]
	} else {
		machineName = target
		remoteUser = "root" // default
	}
	s.logger.Info("Gateway user '%s' connecting to '%s@%s'", username, remoteUser, machineName)

	machine, err := s.store.GetMachineByName(ctx, machineName)
	if err != nil {
		s.logger.Error("Machine not found in database: %s (error: %v)", machineName, err)
		clientChannel.Write([]byte(fmt.Sprintf("Machine not found: %s\n", machineName)))
		clientChannel.SendRequest("exit-status", false, []byte{0, 0, 0, 1})
		return
	}

	s.logger.Info("Machine found: %s (ID: %s, active: %v)", machine.Name, machine.ID, machine.IsActive)

	if err := s.authService.CheckPermissionWithRemoteUser(ctx, userID, machine.ID, "ssh", remoteUser); err != nil {
		s.logger.Warn("Permission denied: %s cannot access %s@%s", username, remoteUser, machineName)

		errorMsg := "\n> Permission denied\n"
		errorMsg += fmt.Sprintf("   Gateway user: %s\n", username)
		errorMsg += fmt.Sprintf("   Target: %s@%s\n\n", remoteUser, machineName)
		errorMsg += fmt.Sprintf("You don't have permission to access '%s' on %s\n", remoteUser, machineName)
		errorMsg += "Contact your administrator or request access\n\n"

		clientChannel.Write([]byte(errorMsg))
		clientChannel.SendRequest("exit-status", false, []byte{0, 0, 0, 1})
		return
	}

	// Get agent connection
	s.agentsMu.RLock()
	agentConn, exists := s.agents[machine.ID]
	s.agentsMu.RUnlock()

	if !exists || !machine.IsActive {
		clientChannel.Write([]byte("Machine is not available\n"))
		clientChannel.SendRequest("exit-status", false, []byte{0, 0, 0, 1})
		return
	}

	// Create session record
	recordingPath := s.recorder.GetRecordingStoragePath()
	session := common.NewSession(userID, machine.ID, remoteUser, recordingPath)

	if err := s.store.CreateSession(ctx, session); err != nil {
		s.logger.Error("Failed to create session record: %v", err)
	}

	// Start recording
	sessionRecorder, err := s.recorder.StartRecording(session.ID)
	if err != nil {
		s.logger.Error("Failed to start recording: %v", err)
	}

	// Trigger session start hook
	hookCtx := &plugin.HookContext{
		UserID:    userID,
		MachineID: machine.ID,
		SessionID: session.ID,
		Data:      make(map[string]interface{}),
	}
	s.pluginManager.TriggerHook(ctx, plugin.HookSessionStart, hookCtx)
	metrics.Default.SessionStarted()

	s.logger.Info("Opening session channel to agent")

	agentChannel, agentReqs, err := agentConn.SSHConn.Conn.OpenChannel("session", nil)
	if err != nil {
		s.logger.Error("Failed to open session channel: %v", err)
		clientChannel.Write([]byte(fmt.Sprintf("Failed to connect to machine: %v\n", err)))
		clientChannel.SendRequest("exit-status", false, []byte{0, 0, 0, 1})
		return
	}

	s.logger.Info("Successfully opened session channel to agent")

	// Forward PTY request to agent when present (OpenSSH interactive)
	if ptyReq != nil && remoteCommand == "" {
		ok, err := agentChannel.SendRequest("pty-req", true, ssh.Marshal(ptyReq))
		if err != nil || !ok {
			s.logger.Warn("Failed to forward pty-req to agent: ok=%v err=%v", ok, err)
		}
	}

	// Forward window-change from client while session is live
	if remainingReqs != nil {
		go func() {
			for req := range remainingReqs {
				switch req.Type {
				case "window-change":
					agentChannel.SendRequest("window-change", false, req.Payload)
					if req.WantReply {
						req.Reply(true, nil)
					}
				default:
					if req.WantReply {
						req.Reply(false, nil)
					}
				}
			}
		}()
	}

	if remoteCommand != "" {
		s.logger.Info("Executing command on agent: %s", remoteCommand)
		if strings.Contains(remoteCommand, "scp") {
			s.logger.Debug("Directing SCP command to agent: %s", remoteCommand)
		}
		s.executeCommand(clientChannel, agentChannel, agentReqs, remoteCommand, sessionRecorder)
	} else {
		s.logger.Info("Starting interactive shell on agent")
		s.startInteractiveShell(clientChannel, agentChannel, agentReqs, sessionRecorder, remoteUser)
	}

	endTime := time.Now()
	s.store.EndSession(ctx, session.ID, endTime)
	s.recorder.StopRecording(session.ID)

	s.pluginManager.TriggerHook(ctx, plugin.HookSessionEnd, hookCtx)
	metrics.Default.SessionEnded()

	s.logger.Info("Session ended for user: %s", username)
}

func splitFirst(s string) []string {
	for i := 0; i < len(s); i++ {
		if s[i] == ' ' {
			return []string{s[:i], s[i+1:]}
		}
	}
	return []string{s}
}

func (s *Server) executeCommand(clientChannel, agentChannel ssh.Channel, agentReqs <-chan *ssh.Request, command string, recorder *recording.SessionRecorder) {
	exitStatusReceived := make(chan struct{})

	go func() {
		for req := range agentReqs {
			if req.Type == "exit-status" {
				clientChannel.SendRequest("exit-status", false, req.Payload)
				s.logger.Debug("Forwarded exit-status to client")

				if req.WantReply {
					req.Reply(true, nil)
				}
				close(exitStatusReceived)
				continue
			}
			if req.WantReply {
				req.Reply(true, nil)
			}
		}
	}()

	ok, err := agentChannel.SendRequest("exec", true, ssh.Marshal(&struct{ Command string }{command}))
	if err != nil {
		s.logger.Error("Failed to send exec request: %v", err)
		clientChannel.Write([]byte(fmt.Sprintf("Failed to execute command: %v\n", err)))
		clientChannel.SendRequest("exit-status", false, []byte{0, 0, 0, 1})
		return
	}
	if !ok {
		s.logger.Error("Exec request rejected by agent")
		clientChannel.Write([]byte("Command execution rejected\n"))
		clientChannel.SendRequest("exit-status", false, []byte{0, 0, 0, 1})
		return
	}

	s.logger.Info("Command execution started on agent")

	s.proxyConnection(clientChannel, agentChannel, recorder, true)

	select {
	case <-exitStatusReceived:
		s.logger.Info("Exit status received and forwarded successfully")
	case <-time.After(5 * time.Second):
		s.logger.Warn("Timeout waiting for exit status")
		clientChannel.SendRequest("exit-status", false, []byte{0, 0, 0, 1})
	}

	clientChannel.CloseWrite()
}

func (s *Server) startInteractiveShell(clientChannel, agentChannel ssh.Channel, agentReqs <-chan *ssh.Request, recorder *recording.SessionRecorder, username string) {
	statusDone := make(chan struct{})
	var once sync.Once
	go func() {
		for req := range agentReqs {
			switch req.Type {
			case "exit-status":
				once.Do(func() {
					clientChannel.SendRequest("exit-status", false, req.Payload)
					s.logger.Debug("Forwarded exit-status to client")
					close(statusDone)
				})
			default:
				if req.WantReply {
					req.Reply(true, nil)
				}
			}
		}
	}()

	type shellPayload struct {
		User string
	}

	payload := shellPayload{User: username}
	encodedPayload := ssh.Marshal(payload)
	ok, err := agentChannel.SendRequest("shell", true, encodedPayload)
	if err != nil || !ok {
		s.logger.Error("Shell request failed")
		return
	}

	s.logger.Info("Interactive shell started on agent")

	s.proxyConnection(clientChannel, agentChannel, recorder, false)

	select {
	case <-statusDone:
		s.logger.Debug("Exit status confirmed")
	case <-time.After(1 * time.Second):
		s.logger.Warn("Timed out waiting for exit status")
	}

	agentChannel.Close()
	clientChannel.Close()
}

// proxyConnection proxies data between client and agent with output-only recording.
func (s *Server) proxyConnection(client, agent ssh.Channel, recorder *recording.SessionRecorder, waitBoth bool) {
	var wg sync.WaitGroup
	wg.Add(2)

	done := make(chan struct{}, 2)

	// Client -> Agent (keystrokes are not recorded; PTY echo covers input in the cast)
	go func() {
		defer wg.Done()
		io.Copy(agent, client)

		if cw, ok := agent.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
		}
		s.logger.Debug("Client -> Agent I/O closed")
		done <- struct{}{}
	}()

	// Agent -> Client (PTY output → cast)
	go func() {
		defer wg.Done()
		var out io.Writer = client
		if recorder != nil {
			out = recording.NewRecordingWriter(client, recorder)
		}
		io.Copy(out, agent)

		client.CloseWrite()
		s.logger.Debug("Agent -> Client I/O closed")
		done <- struct{}{}
	}()

	if waitBoth {
		wg.Wait()
	} else {
		<-done
		s.logger.Debug("First I/O direction finished, stopping proxy for shell")
	}
}

// Stop stops the SSH server
func (s *Server) Stop(ctx context.Context) error {
	s.logger.Info("Shutting down server...")

	close(s.shutdown)

	if s.listener != nil {
		s.listener.Close()
	}

	if err := s.pluginManager.ShutdownAll(ctx); err != nil {
		s.logger.Error("Failed to shutdown plugins: %v", err)
	}

	if err := s.store.Close(); err != nil {
		s.logger.Error("Failed to close database: %v", err)
	}

	return nil
}

// GetPluginManager returns the plugin manager
func (s *Server) GetPluginManager() *plugin.Manager {
	return s.pluginManager
}

// GetStore returns the database store
func (s *Server) GetStore() database.Store {
	return s.store
}

// GetAuthService returns the auth service
func (s *Server) GetAuthService() *auth.AuthService {
	return s.authService
}

// runRetentionLoop periodically deletes expired recordings.
func (s *Server) runRetentionLoop() {
	ticker := time.NewTicker(6 * time.Hour)
	defer ticker.Stop()
	path := s.recorder.GetRecordingStoragePath()
	days := s.config.Recording.RetentionDays
	if _, err := recording.EnforceRetention(path, days, s.logger); err != nil {
		s.logger.Warn("retention cleanup: %v", err)
	}
	for {
		select {
		case <-s.shutdown:
			return
		case <-ticker.C:
			if _, err := recording.EnforceRetention(path, days, s.logger); err != nil {
				s.logger.Warn("retention cleanup: %v", err)
			}
		}
	}
}

// ResolveMachine looks up a machine by name for the web terminal bridge.
func (s *Server) ResolveMachine(name string) (*common.Machine, error) {
	return s.store.GetMachineByName(context.Background(), name)
}

// OpenAgentSession opens a session channel to a connected agent.
func (s *Server) OpenAgentSession(machineID, remoteUser string) (ssh.Channel, <-chan *ssh.Request, error) {
	s.agentsMu.RLock()
	agentConn, exists := s.agents[machineID]
	s.agentsMu.RUnlock()
	if !exists {
		return nil, nil, fmt.Errorf("agent not connected")
	}
	return agentConn.SSHConn.Conn.OpenChannel("session", nil)
}

// ListConnectedAgents returns machine IDs of connected agents.
func (s *Server) ListConnectedAgents() []string {
	s.agentsMu.RLock()
	defer s.agentsMu.RUnlock()
	ids := make([]string, 0, len(s.agents))
	for id := range s.agents {
		ids = append(ids, id)
	}
	return ids
}

// SendAgentCommand opens a session to a connected agent and runs a control/exec command.
func (s *Server) SendAgentCommand(machineID, command string) ([]byte, error) {
	s.agentsMu.RLock()
	agentConn, exists := s.agents[machineID]
	s.agentsMu.RUnlock()
	if !exists {
		return nil, fmt.Errorf("agent not connected: %s", machineID)
	}

	channel, reqs, err := agentConn.SSHConn.Conn.OpenChannel("session", nil)
	if err != nil {
		return nil, fmt.Errorf("open agent channel: %w", err)
	}
	defer channel.Close()

	go ssh.DiscardRequests(reqs)

	ok, err := channel.SendRequest("exec", true, ssh.Marshal(&struct{ Command string }{command}))
	if err != nil {
		return nil, fmt.Errorf("send command: %w", err)
	}
	if !ok {
		return nil, fmt.Errorf("command rejected by agent")
	}

	var buf strings.Builder
	done := make(chan struct{})
	go func() {
		io.Copy(&buf, channel)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(15 * time.Second):
		return nil, fmt.Errorf("agent command timed out")
	}

	return []byte(buf.String()), nil
}

func resolveDirWithCreate(path, fallback string, logger *common.Logger) string {
	if path == "" {
		path = fallback
	}

	if err := os.MkdirAll(path, 0o755); err != nil {
		logger.Warn("failed to create directory: %s", err.Error())
		return fallback
	}

	return path
}
