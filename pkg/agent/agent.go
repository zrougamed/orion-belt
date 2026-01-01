package agent

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"time"

	"github.com/creack/pty"
	"github.com/zrougamed/orion-belt/pkg/common"
	gossh "golang.org/x/crypto/ssh"
)

// Agent represents an Orion-Belt agent
type Agent struct {
	config    *common.Config
	logger    *common.Logger
	sshClient *gossh.Client
	sshConn   gossh.Conn
	machineID string
}

// New creates a new agent
func New(config *common.Config, logger *common.Logger) (*Agent, error) {
	return &Agent{
		config: config,
		logger: logger,
	}, nil
}

// Start starts the agent
func (a *Agent) Start() error {
	a.logger.Info("Starting Orion-Belt agent: %s", a.config.Agent.Name)

	// Connect to server
	if err := a.connectToServer(); err != nil {
		return fmt.Errorf("failed to connect to server: %w", err)
	}

	// Keep connection alive
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := a.sendHeartbeat(); err != nil {
				a.logger.Error("Heartbeat failed: %v", err)
				// Attempt to reconnect
				if err := a.connectToServer(); err != nil {
					a.logger.Error("Failed to reconnect: %v", err)
				}
			}
		}
	}
}

// connectToServer establishes connection to the server
func (a *Agent) connectToServer() error {
	// Load SSH key from file
	keyData, err := os.ReadFile(a.config.Auth.KeyFile)
	if err != nil {
		return fmt.Errorf("failed to read private key file: %w", err)
	}

	key, err := gossh.ParsePrivateKey(keyData)
	if err != nil {
		return fmt.Errorf("failed to parse private key: %w", err)
	}

	a.logger.Info("Attempting to authenticate as user: %s", a.config.Agent.Name)
	a.logger.Debug("Using key file: %s", a.config.Auth.KeyFile)

	config := &gossh.ClientConfig{
		User: a.config.Agent.Name,
		Auth: []gossh.AuthMethod{
			gossh.PublicKeys(key),
		},
		HostKeyCallback: gossh.InsecureIgnoreHostKey(), // TODO: Implement proper host key verification
		Timeout:         10 * time.Second,
	}

	serverAddr := fmt.Sprintf("%s:%d", a.config.Server.Host, a.config.Server.Port)
	a.logger.Info("Connecting to server: %s", serverAddr)

	// Dial with custom connection to handle incoming channels
	conn, err := net.Dial("tcp", serverAddr)
	if err != nil {
		return fmt.Errorf("failed to dial server: %w", err)
	}

	// Perform SSH handshake
	sshConn, chans, reqs, err := gossh.NewClientConn(conn, serverAddr, config)
	if err != nil {
		conn.Close()
		return fmt.Errorf("failed to establish SSH connection: %w", err)
	}

	// Store the connection - we'll use this for heartbeats
	a.sshConn = sshConn
	a.logger.Info("Connected to server: %s", serverAddr)

	a.logger.Debug("Setting up channel handlers...")

	// Handle incoming channel requests from server (for direct-tcpip)
	// IMPORTANT: We must handle these ourselves, not let ssh.NewClient consume them
	go a.handleChannels(chans)

	a.logger.Debug("Channel handler started")

	// Handle global requests
	go gossh.DiscardRequests(reqs)

	a.logger.Debug("Global request handler started")

	// Start listening for connections
	go a.listenForConnections()

	a.logger.Debug("Agent fully initialized and ready")

	return nil
}

// handleChannels handles incoming channel requests from the server
func (a *Agent) handleChannels(chans <-chan gossh.NewChannel) {
	a.logger.Info("handleChannels started - waiting for incoming channels...")
	channelCount := 0
	for newChannel := range chans {
		channelCount++
		a.logger.Info("=== Received channel #%d ===", channelCount)
		go a.handleChannel(newChannel)
	}
	a.logger.Warn("handleChannels exiting - channel closed")
}

// handleChannel handles a single channel request
func (a *Agent) handleChannel(newChannel gossh.NewChannel) {
	a.logger.Info(">>> handleChannel called")
	a.logger.Info(">>> Channel type: %s", newChannel.ChannelType())
	a.logger.Debug(">>> Channel extra data length: %d bytes", len(newChannel.ExtraData()))

	// Accept the channel first
	a.logger.Debug(">>> Accepting channel...")
	channel, requests, err := newChannel.Accept()
	if err != nil {
		a.logger.Error("!!! Failed to accept channel: %v", err)
		return
	}
	a.logger.Info(">>> Channel accepted successfully")

	// Handle based on channel type
	a.logger.Debug(">>> Routing to handler based on type: %s", newChannel.ChannelType())
	switch newChannel.ChannelType() {
	case "direct-tcpip":
		a.logger.Info(">>> Routing to handleDirectTCPIP")
		a.handleDirectTCPIP(channel, requests, newChannel.ExtraData())
	case "session":
		a.logger.Info(">>> Routing to handleSessionChannel")
		a.handleSessionChannel(channel, requests)
	default:
		a.logger.Warn(">>> Unsupported channel type: %s", newChannel.ChannelType())
		return
	}
	a.logger.Info(">>> handleChannel completed")
}

// handleDirectTCPIP handles direct-tcpip channel (SSH connection forwarding)
func (a *Agent) handleDirectTCPIP(channel gossh.Channel, requests <-chan *gossh.Request, extraData []byte) {
	// Parse the channel request
	var directTCPIPMsg struct {
		DestAddr   string
		DestPort   uint32
		OriginAddr string
		OriginPort uint32
	}

	if err := gossh.Unmarshal(extraData, &directTCPIPMsg); err != nil {
		a.logger.Error("Failed to parse direct-tcpip request: %v", err)
		return
	}

	a.logger.Info("direct-tcpip request to %s:%d - starting interactive shell with PTY", directTCPIPMsg.DestAddr, directTCPIPMsg.DestPort)

	// Handle PTY requests
	go func() {
		for req := range requests {
			a.logger.Debug("Channel request: %s", req.Type)
			if req.WantReply {
				req.Reply(true, nil) // Accept all requests
			}
		}
	}()

	// Send welcome message
	channel.Write([]byte(fmt.Sprintf("=== Connected to %s ===\r\n", a.config.Agent.Name)))

	// Start shell with PTY
	a.logger.Info("Starting interactive shell with PTY...")

	// Use /bin/sh for Alpine Linux compatibility
	cmd := exec.Command("/bin/sh")
	cmd.Env = append(os.Environ(), "TERM=xterm-256color")

	// Start the command with a PTY
	ptmx, err := pty.Start(cmd)
	if err != nil {
		a.logger.Error("Failed to start shell with PTY: %v", err)
		channel.Write([]byte(fmt.Sprintf("Failed to start shell: %v\r\n", err)))
		return
	}
	defer ptmx.Close()

	a.logger.Info("Shell started with PTY (PID: %d)", cmd.Process.Pid)

	// Copy I/O between channel and PTY
	done := make(chan struct{})

	// PTY -> Channel (reads from PTY, writes to channel)
	go func() {
		io.Copy(channel, ptmx)
		a.logger.Debug("PTY->Channel copy finished")
		// Signal that we're done
		done <- struct{}{}
	}()

	// Channel -> PTY (reads from channel, writes to PTY)
	go func() {
		io.Copy(ptmx, channel)
		a.logger.Debug("Channel->PTY copy finished")
	}()

	// Wait for PTY->Channel to finish (this happens when shell exits and PTY closes)
	<-done

	// Close PTY to break the Channel->PTY copy
	ptmx.Close()

	a.logger.Debug("I/O copy completed, waiting for shell to exit...")

	// Wait for shell process to exit
	err = cmd.Wait()

	// Send exit status to client
	exitStatus := 0
	if err != nil {
		a.logger.Info("Shell exited with error: %v", err)
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitStatus = exitErr.ExitCode()
		} else {
			exitStatus = 1
		}
	} else {
		a.logger.Info("Shell exited successfully")
	}

	// Send exit-status request
	statusMsg := make([]byte, 4)
	statusMsg[0] = byte(exitStatus >> 24)
	statusMsg[1] = byte(exitStatus >> 16)
	statusMsg[2] = byte(exitStatus >> 8)
	statusMsg[3] = byte(exitStatus)

	_, err = channel.SendRequest("exit-status", false, statusMsg)

	// Close the channel now that we're done
	channel.Close()
	a.logger.Debug("handleDirectTCPIP completed")
}

// handleSessionChannel handles session channel
func (a *Agent) handleSessionChannel(channel gossh.Channel, requests <-chan *gossh.Request) {
	a.logger.Info("Session channel opened")

	// Handle session requests
	for req := range requests {
		switch req.Type {
		case "exec":
			// Handle exec requests
			var payload struct {
				Command string
			}
			if err := gossh.Unmarshal(req.Payload, &payload); err != nil {
				req.Reply(false, nil)
				continue
			}

			a.logger.Debug("Exec request: %s", payload.Command)

			// Handle specific commands
			switch payload.Command {
			case "heartbeat":
				req.Reply(true, nil)
				channel.SendRequest("exit-status", false, []byte{0, 0, 0, 0})
			default:
				req.Reply(false, nil)
			}

		default:
			if req.WantReply {
				req.Reply(false, nil)
			}
		}
	}

	// Close the channel when done
	channel.Close()
	a.logger.Debug("handleSessionChannel completed")
}

// listenForConnections keeps the SSH connection alive
func (a *Agent) listenForConnections() {
	a.logger.Info("Agent connected and ready - waiting for client connections...")

	// The connection is kept alive by the heartbeat loop in Start()
	// Server automatically registers the agent when it detects the connection
	// Server will use direct-tcpip channels to forward client connections
}

// sendHeartbeat sends a heartbeat to the server
func (a *Agent) sendHeartbeat() error {
	if a.sshConn == nil {
		return fmt.Errorf("not connected to server")
	}

	// Open a session channel for the heartbeat
	channel, reqs, err := a.sshConn.OpenChannel("session", nil)
	if err != nil {
		return fmt.Errorf("failed to open session channel: %w", err)
	}
	defer channel.Close()

	// Discard requests
	go gossh.DiscardRequests(reqs)

	// Send exec request
	ok, err := channel.SendRequest("exec", true, gossh.Marshal(&struct{ Command string }{"heartbeat"}))
	if err != nil {
		return fmt.Errorf("failed to send heartbeat: %w", err)
	}
	if !ok {
		return fmt.Errorf("heartbeat request rejected")
	}

	return nil
}

// Stop stops the agent
func (a *Agent) Stop(ctx context.Context) error {
	a.logger.Info("Stopping agent...")

	if a.sshConn != nil {
		a.sshConn.Close()
	}

	return nil
}

// TODO: to be implemented with server commands
// executeCommand executes a shell command
func (a *Agent) executeCommand(command string) (string, error) {
	cmd := exec.Command("sh", "-c", command)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("command failed: %w", err)
	}

	return string(output), nil
}
