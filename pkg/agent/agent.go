package agent

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"sync"
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

	// Store the connection
	a.sshConn = sshConn
	a.logger.Info("Connected to server: %s", serverAddr)

	a.logger.Debug("Setting up channel handlers...")

	go a.handleChannels(chans)

	a.logger.Debug("Channel handler started")

	// Handle global requests
	go gossh.DiscardRequests(reqs)

	a.logger.Debug("Global request handler started")

	a.logger.Debug("Agent fully initialized and ready")

	return nil
}

// handleChannels handles incoming channel requests from the server
func (a *Agent) handleChannels(chans <-chan gossh.NewChannel) {
	a.logger.Info("handleChannels started - waiting for incoming channels...")
	for newChannel := range chans {
		a.logger.Info("Received channel type: %s", newChannel.ChannelType())

		if newChannel.ChannelType() != "session" {
			a.logger.Warn("Rejecting non-session channel: %s", newChannel.ChannelType())
			newChannel.Reject(gossh.UnknownChannelType, "only session channels supported")
			continue
		}

		go a.handleSession(newChannel)
	}
	a.logger.Warn("Channel handler exiting")
}

// handleSession handles a single session request
func (a *Agent) handleSession(newChannel gossh.NewChannel) {
	a.logger.Info("Accepting session channel")

	channel, requests, err := newChannel.Accept()
	if err != nil {
		a.logger.Error("Failed to accept channel: %v", err)
		return
	}

	a.logger.Info("Session channel accepted, waiting for requests...")

	var ptyReq *ptyRequestMsg
	var execCommand string

	for req := range requests {
		a.logger.Debug("Session request: %s", req.Type)

		switch req.Type {
		case "pty-req":
			ptyReq = &ptyRequestMsg{}
			if err := gossh.Unmarshal(req.Payload, ptyReq); err != nil {
				a.logger.Error("Failed to parse pty-req: %v", err)
				req.Reply(false, nil)
			} else {
				a.logger.Info("PTY requested: %s %dx%d", ptyReq.Term, ptyReq.Columns, ptyReq.Rows)
				req.Reply(true, nil)
			}

		case "shell":
			var payload struct {
				User string
			}
			if err := gossh.Unmarshal(req.Payload, &payload); err != nil {
				a.logger.Error("Failed to parse exec payload: %v", err)
				req.Reply(false, nil)
				continue
			}
			username := payload.User
			a.logger.Info("Shell requested")

			req.Reply(true, nil)

			a.startShell(channel, username, ptyReq)
			channel.Close()
			return

		case "exec":
			var payload struct {
				Command string
			}
			if err := gossh.Unmarshal(req.Payload, &payload); err != nil {
				a.logger.Error("Failed to parse exec payload: %v", err)
				req.Reply(false, nil)
				continue
			}

			execCommand = payload.Command
			a.logger.Info("Exec requested: %s", execCommand)
			req.Reply(true, nil)

			a.executeCommand(channel, execCommand)
			return

		case "env":
			req.Reply(true, nil)

		default:
			a.logger.Debug("Unsupported request: %s", req.Type)
			if req.WantReply {
				req.Reply(false, nil)
			}
		}
	}

	a.logger.Info("Session ended without exec or shell request")
	channel.Close()
}

type ptyRequestMsg struct {
	Term     string
	Columns  uint32
	Rows     uint32
	Width    uint32
	Height   uint32
	Modelist string
}

func (a *Agent) startShell(channel gossh.Channel, username string, ptyReq *ptyRequestMsg) {
	a.logger.Info("Starting interactive shell")

	cmd := exec.Command("su", "-", username)
	cmd.Env = append(os.Environ(), "TERM=xterm-256color")

	if ptyReq != nil {
		cmd.Env = append(cmd.Env, fmt.Sprintf("TERM=%s", ptyReq.Term))
	}

	ptmx, err := pty.Start(cmd)
	if err != nil {
		a.logger.Error("Failed to start shell with PTY: %v", err)
		channel.Write([]byte(fmt.Sprintf("Failed to start shell: %v\r\n", err)))
		a.sendExitStatus(channel, 1)
		return
	}
	defer ptmx.Close()

	if ptyReq != nil {
		pty.Setsize(ptmx, &pty.Winsize{
			Rows: uint16(ptyReq.Rows),
			Cols: uint16(ptyReq.Columns),
		})
	}

	a.logger.Info("Shell started with PTY (PID: %d)", cmd.Process.Pid)

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		io.Copy(channel, ptmx)
		a.logger.Debug("PTY->Channel copy finished")
		channel.CloseWrite()
	}()

	go func() {
		defer wg.Done()
		io.Copy(ptmx, channel)
		a.logger.Debug("Channel->PTY copy finished")
	}()

	// Wait for PTY->Channel to finish
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
	}
	// Send exit-status request
	a.sendExitStatus(channel, exitStatus)

	// Close the channel
	ptmx.Close()
	channel.CloseWrite()
	wg.Wait()

	a.logger.Debug("Closing channel after shell completion")
	channel.Close()
}

func (a *Agent) executeCommand(channel gossh.Channel, command string) {
	a.logger.Info("Executing command: %s", command)

	cmd := exec.Command("/bin/sh", "-c", command)
	cmd.Env = os.Environ()

	stdin, err := cmd.StdinPipe()
	if err != nil {
		a.logger.Error("Failed to get stdin pipe: %v", err)
		channel.Write([]byte(fmt.Sprintf("Failed to execute command: %v\n", err)))
		a.sendExitStatus(channel, 1)
		return
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		a.logger.Error("Failed to get stdout pipe: %v", err)
		channel.Write([]byte(fmt.Sprintf("Failed to execute command: %v\n", err)))
		a.sendExitStatus(channel, 1)
		return
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		a.logger.Error("Failed to get stderr pipe: %v", err)
		channel.Write([]byte(fmt.Sprintf("Failed to execute command: %v\n", err)))
		a.sendExitStatus(channel, 1)
		return
	}

	if err := cmd.Start(); err != nil {
		a.logger.Error("Failed to start command: %v", err)
		channel.Write([]byte(fmt.Sprintf("Failed to execute command: %v\n", err)))
		a.sendExitStatus(channel, 1)
		return
	}

	a.logger.Info("Command started (PID: %d)", cmd.Process.Pid)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		io.Copy(stdin, channel)
		stdin.Close()
		a.logger.Debug("Channel->stdin copy finished")
	}()
	go func() {
		defer wg.Done()
		io.Copy(channel, stdout)
		a.logger.Debug("stdout->Channel copy finished")
	}()
	go func() {
		defer wg.Done()
		io.Copy(channel.Stderr(), stderr)
		a.logger.Debug("stderr->Channel copy finished")
	}()

	cmdErr := cmd.Wait()
	a.logger.Debug("Command process finished, waiting for output I/O to complete")

	wg.Wait()
	a.logger.Debug("All output I/O finished")

	exitStatus := 0
	if cmdErr != nil {
		if exitErr, ok := cmdErr.(*exec.ExitError); ok {
			exitStatus = exitErr.ExitCode()
		} else {
			exitStatus = 1
		}
		a.logger.Info("Command exited with error: %v (status: %d)", cmdErr, exitStatus)
	} else {
		a.logger.Info("Command exited successfully")
	}

	a.sendExitStatus(channel, exitStatus)
	a.logger.Debug("Closing write side of channel after command completion")
	channel.CloseWrite()
}

func (a *Agent) sendExitStatus(channel gossh.Channel, status int) {
	statusMsg := make([]byte, 4)
	statusMsg[0] = byte(status >> 24)
	statusMsg[1] = byte(status >> 16)
	statusMsg[2] = byte(status >> 8)
	statusMsg[3] = byte(status)

	ok, err := channel.SendRequest("exit-status", true, statusMsg)
	if err != nil || !ok {
		a.logger.Warn("Failed to send exit status (ack: %v, err: %v)", ok, err)
	} else {
		a.logger.Debug("Sent exit status: %d and received ACK", status)
	}
}

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
