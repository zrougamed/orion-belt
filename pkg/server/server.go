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
	"github.com/zrougamed/orion-belt/pkg/common"
	"github.com/zrougamed/orion-belt/pkg/database"
	"github.com/zrougamed/orion-belt/pkg/plugin"
	"github.com/zrougamed/orion-belt/pkg/recording"
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
	apiServer := api.NewAPIServer(store, authService, logger)

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
	s.handleClientConnection(sshConn, chans, reqs, userID, user)
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

	// Store user info in permissions
	perms := &ssh.Permissions{
		Extensions: map[string]string{
			"user":    user.Username,
			"user_id": user.ID,
		},
	}

	// Trigger pre-auth hook
	hookCtx := &plugin.HookContext{
		UserID: user.ID,
		Data:   make(map[string]interface{}),
	}
	s.pluginManager.TriggerHook(context.Background(), plugin.HookPreAuth, hookCtx)

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
	s.agentsMu.Unlock()

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
	s.agentsMu.Unlock()

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
func (s *Server) handleClientConnection(sshConn *ssh.ServerConn, chans <-chan ssh.NewChannel, reqs <-chan *ssh.Request, userID, username string) {
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

		go s.handleClientSession(channel, requests, userID, username)
	}
}

// handleClientSession handles a client session
func (s *Server) handleClientSession(channel ssh.Channel, requests <-chan *ssh.Request, userID, username string) {
	defer channel.Close()

	var machineName string
	var shell bool

	// Handle session setup requests
	for req := range requests {
		switch req.Type {
		case "exec":
			// Parse the target machine from exec command
			var payload struct {
				Command string
			}
			if err := ssh.Unmarshal(req.Payload, &payload); err != nil {
				req.Reply(false, nil)
				return
			}

			s.logger.Info("Client exec command: '%s'", payload.Command)
			machineName = payload.Command
			req.Reply(true, nil)

			// Execute the proxying
			s.proxyToMachine(channel, machineName, userID, username)
			return

		case "shell":
			shell = true
			req.Reply(true, nil)

		case "pty-req":
			req.Reply(true, nil)

		default:
			if req.WantReply {
				req.Reply(false, nil)
			}
		}

		if shell {
			channel.Write([]byte("Orion-Belt Gateway\nUsage: ssh user@server machine-name\n"))
			return
		}
	}
}

// proxyToMachine proxies a client session to a target machine through an agent
func (s *Server) proxyToMachine(clientChannel ssh.Channel, commandLine, userID, username string) {
	ctx := context.Background()

	s.logger.Info("proxyToMachine called: commandLine='%s', user='%s', userID='%s'", commandLine, username, userID)

	var machineName, remoteCommand string
	parts := splitFirst(commandLine)
	machineName = parts[0]
	if len(parts) > 1 {
		remoteCommand = parts[1]
	}

	s.logger.Info("Parsed: machine='%s', command='%s'", machineName, remoteCommand)

	machine, err := s.store.GetMachineByName(ctx, machineName)
	if err != nil {
		s.logger.Error("Machine not found in database: %s (error: %v)", machineName, err)
		clientChannel.Write([]byte(fmt.Sprintf("Machine not found: %s\n", machineName)))
		clientChannel.SendRequest("exit-status", false, []byte{0, 0, 0, 1})
		return
	}

	s.logger.Info("Machine found: %s (ID: %s, active: %v)", machine.Name, machine.ID, machine.IsActive)

	// Check permissions
	if err := s.authService.CheckPermission(ctx, userID, machine.ID, "ssh"); err != nil {
		clientChannel.Write([]byte("Permission denied\n"))
		s.logger.Warn("Permission denied for user %s to machine %s", username, machineName)
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
	session := common.NewSession(userID, machine.ID, recordingPath)

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

	s.logger.Info("Opening session channel to agent")

	agentChannel, agentReqs, err := agentConn.SSHConn.Conn.OpenChannel("session", nil)
	if err != nil {
		s.logger.Error("Failed to open session channel: %v", err)
		clientChannel.Write([]byte(fmt.Sprintf("Failed to connect to machine: %v\n", err)))
		clientChannel.SendRequest("exit-status", false, []byte{0, 0, 0, 1})
		return
	}

	s.logger.Info("Successfully opened session channel to agent")

	if remoteCommand != "" {
		s.logger.Info("Executing command on agent: %s", remoteCommand)
		if strings.Contains(remoteCommand, "scp") {
			s.logger.Debug("Directing SCP command to agent: %s", remoteCommand)
		}
		s.executeCommand(clientChannel, agentChannel, agentReqs, remoteCommand, sessionRecorder)
	} else {
		s.logger.Info("Starting interactive shell on agent")
		s.startInteractiveShell(clientChannel, agentChannel, agentReqs, sessionRecorder)
	}

	endTime := time.Now()
	s.store.EndSession(ctx, session.ID, endTime)
	s.recorder.StopRecording(session.ID)

	s.pluginManager.TriggerHook(ctx, plugin.HookSessionEnd, hookCtx)

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

func (s *Server) startInteractiveShell(clientChannel, agentChannel ssh.Channel, agentReqs <-chan *ssh.Request, recorder *recording.SessionRecorder) {
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

	ok, err := agentChannel.SendRequest("shell", true, nil)
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

// proxyConnection proxies data between client and agent with recording
func (s *Server) proxyConnection(client, agent ssh.Channel, recorder *recording.SessionRecorder, waitBoth bool) {
	var wg sync.WaitGroup
	wg.Add(2)

	done := make(chan struct{}, 2)

	// Client -> Agent
	go func() {
		defer wg.Done()
		reader := recording.NewRecordingReader(client, recorder)
		io.Copy(agent, reader)

		if cw, ok := agent.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
		}
		s.logger.Debug("Client -> Agent I/O closed")
		done <- struct{}{}
	}()

	// Agent -> Client
	go func() {
		defer wg.Done()
		writer := recording.NewRecordingWriter(client, recorder)
		io.Copy(writer, agent)

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
