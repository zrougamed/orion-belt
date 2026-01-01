package client

import (
	"fmt"
	"io"
	"os"

	"github.com/zrougamed/orion-belt/pkg/common"
	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

// SSHClient represents an Orion-Belt SSH client
type SSHClient struct {
	config *common.Config
	logger *common.Logger
}

// NewSSHClient creates a new SSH client
func NewSSHClient(config *common.Config, logger *common.Logger) (*SSHClient, error) {
	return &SSHClient{
		config: config,
		logger: logger,
	}, nil
}

// Connect connects to a target machine through the Orion-Belt server
func (c *SSHClient) Connect(target string, username string) error {
	c.logger.Info("Connecting to %s through Orion-Belt server", target)

	// Load SSH key
	keyData, err := os.ReadFile(c.config.Auth.KeyFile)
	if err != nil {
		return fmt.Errorf("failed to read SSH key: %w", err)
	}

	signer, err := ssh.ParsePrivateKey(keyData)
	if err != nil {
		return fmt.Errorf("failed to parse private key: %w", err)
	}

	// Configure SSH client
	// Get username from parameter, environment, or use root as fallback
	if username == "" {
		username = os.Getenv("USER")
		if username == "" {
			username = "root" // Default for Docker containers
		}
	}

	config := &ssh.ClientConfig{
		User: username,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // TODO: Implement proper host key verification
	}

	c.logger.Info("Authenticating as user: %s", username)

	// Connect to Orion-Belt server
	serverAddr := fmt.Sprintf("%s:%d", c.config.Server.Host, c.config.Server.Port)
	client, err := ssh.Dial("tcp", serverAddr, config)
	if err != nil {
		return fmt.Errorf("failed to connect to server: %w", err)
	}
	defer client.Close()

	// Create session
	session, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("failed to create session: %w", err)
	}
	defer session.Close()

	// Set up terminal
	fd := int(os.Stdin.Fd())
	oldState, err := term.MakeRaw(fd)
	if err != nil {
		return fmt.Errorf("failed to set raw mode: %w", err)
	}
	defer term.Restore(fd, oldState)

	// Get terminal size
	width, height, err := term.GetSize(fd)
	if err != nil {
		width, height = 80, 24
	}

	// Request PTY
	modes := ssh.TerminalModes{
		ssh.ECHO:          1,
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	}

	if err := session.RequestPty("xterm-256color", height, width, modes); err != nil {
		return fmt.Errorf("failed to request PTY: %w", err)
	}

	// Set up I/O
	session.Stdout = os.Stdout
	session.Stderr = os.Stderr
	session.Stdin = os.Stdin

	// Run shell with target as argument
	if err := session.Run(target); err != nil {
		return fmt.Errorf("session error: %w", err)
	}

	return nil
}

// RequestAccess requests temporary access to a machine
func (c *SSHClient) RequestAccess(target, reason string, duration int) error {
	c.logger.Info("Requesting access to %s for %d seconds", target, duration)

	// TODO: Implement API call to request access
	// This would make an HTTP request to the server's API endpoint

	fmt.Printf("Access request submitted for %s\n", target)
	fmt.Printf("Reason: %s\n", reason)
	fmt.Printf("Duration: %d seconds\n", duration)
	fmt.Println("Waiting for admin approval...")

	return nil
}

// ListMachines lists available machines
func (c *SSHClient) ListMachines() error {
	// TODO: Implement API call to list machines
	fmt.Println("Available machines:")
	fmt.Println("(API implementation needed)")
	return nil
}

// SCPClient represents an Orion-Belt SCP client
type SCPClient struct {
	config *common.Config
	logger *common.Logger
}

// NewSCPClient creates a new SCP client
func NewSCPClient(config *common.Config, logger *common.Logger) (*SCPClient, error) {
	return &SCPClient{
		config: config,
		logger: logger,
	}, nil
}

// Copy copies a file through the Orion-Belt server
func (c *SCPClient) Copy(source, destination string, isUpload bool) error {
	c.logger.Info("Copying %s to %s", source, destination)

	// Load SSH key
	keyData, err := os.ReadFile(c.config.Auth.KeyFile)
	if err != nil {
		return fmt.Errorf("failed to read SSH key: %w", err)
	}

	signer, err := ssh.ParsePrivateKey(keyData)
	if err != nil {
		return fmt.Errorf("failed to parse private key: %w", err)
	}

	// Configure SSH client
	config := &ssh.ClientConfig{
		User: os.Getenv("USER"),
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	// Connect to Orion-Belt server
	serverAddr := fmt.Sprintf("%s:%d", c.config.Server.Host, c.config.Server.Port)
	client, err := ssh.Dial("tcp", serverAddr, config)
	if err != nil {
		return fmt.Errorf("failed to connect to server: %w", err)
	}
	defer client.Close()

	// Create session
	session, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("failed to create session: %w", err)
	}
	defer session.Close()

	if isUpload {
		return c.uploadFile(session, source, destination)
	}
	return c.downloadFile(session, source, destination)
}

// uploadFile uploads a file to the remote machine
func (c *SCPClient) uploadFile(session *ssh.Session, source, destination string) error {
	file, err := os.Open(source)
	if err != nil {
		return fmt.Errorf("failed to open source file: %w", err)
	}
	defer file.Close()

	stat, err := file.Stat()
	if err != nil {
		return fmt.Errorf("failed to stat file: %w", err)
	}

	// Set up stdin for session
	stdin, err := session.StdinPipe()
	if err != nil {
		return fmt.Errorf("failed to get stdin: %w", err)
	}

	// Start SCP command on remote
	go func() {
		defer stdin.Close()

		// Send file header
		fmt.Fprintf(stdin, "C0644 %d %s\n", stat.Size(), stat.Name())

		// Send file content
		io.Copy(stdin, file)

		// Send terminator
		fmt.Fprint(stdin, "\x00")
	}()

	// Run SCP command
	if err := session.Run(fmt.Sprintf("scp -t %s", destination)); err != nil {
		return fmt.Errorf("scp failed: %w", err)
	}

	c.logger.Info("File uploaded successfully")
	return nil
}

// downloadFile downloads a file from the remote machine
func (c *SCPClient) downloadFile(session *ssh.Session, source, destination string) error {
	file, err := os.Create(destination)
	if err != nil {
		return fmt.Errorf("failed to create destination file: %w", err)
	}
	defer file.Close()

	// Set up stdout for session
	stdout, err := session.StdoutPipe()
	if err != nil {
		return fmt.Errorf("failed to get stdout: %w", err)
	}

	// Start SCP command on remote
	if err := session.Start(fmt.Sprintf("scp -f %s", source)); err != nil {
		return fmt.Errorf("failed to start scp: %w", err)
	}

	// Read file content
	io.Copy(file, stdout)

	// Wait for completion
	if err := session.Wait(); err != nil {
		return fmt.Errorf("scp failed: %w", err)
	}

	c.logger.Info("File downloaded successfully")
	return nil
}
