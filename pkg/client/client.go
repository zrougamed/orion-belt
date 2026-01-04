package client

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

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
	// Parse target for user@machine format
	targetMachine := target
	targetUser := username
	targetSSHUser := username

	if strings.Contains(target, "@") {
		parts := strings.SplitN(target, "@", 2)
		if len(parts) == 2 {
			targetMachine = parts[1]
			targetSSHUser = parts[0]
		}
	}

	c.logger.Info("Connecting to %s through Orion-Belt server", targetMachine)

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
	if targetUser == "" {
		targetUser = os.Getenv("USER")
		if targetUser == "" {
			targetUser = "root"
		}
	}

	config := &ssh.ClientConfig{
		User: targetUser,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // TODO: Implement proper host key verification
	}

	c.logger.Info("Authenticating as user: %s", targetUser)

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
	if term.IsTerminal(fd) {
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
	}

	// Set up I/O
	if term.IsTerminal(fd) {
		// Wrap Stdout and Stderr to handle the "staircase" effect
		session.Stdout = &rawModeWriter{os.Stdout}
		session.Stderr = &rawModeWriter{os.Stderr}
	} else {
		session.Stdout = os.Stdout
		session.Stderr = os.Stderr
	}
	session.Stdin = os.Stdin

	// Start shell with target as argument
	connectionStr := targetSSHUser + "@" + targetMachine
	if err := session.Start(connectionStr); err != nil {
		return fmt.Errorf("failed to start session: %w", err)
	}

	err = session.Wait()
	if err != nil {
		if exitErr, ok := err.(*ssh.ExitError); ok {
			os.Exit(exitErr.ExitStatus())
		}
		return fmt.Errorf("session wait error: %w", err)
	}

	return nil
}

type rawModeWriter struct {
	io.Writer
}

func (w *rawModeWriter) Write(p []byte) (n int, err error) {
	s := strings.ReplaceAll(string(p), "\n", "\r\n")
	_, err = w.Writer.Write([]byte(s))
	return len(p), err
}

// RequestAccess requests temporary access to a machine
func (c *SSHClient) RequestAccess(target, reason string, duration int) error {
	c.logger.Info("Requesting access to %s for %d seconds", target, duration)

	// TODO: Implement API call to request access

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
func (c *SCPClient) Copy(username, source, destination string, isUpload bool) error {
	var machine, remotePath, localPath string

	if isUpload {
		localPath = source
		parts := splitMachinePath(destination)
		if len(parts) != 2 {
			return fmt.Errorf("invalid destination format, expected machine:path, got: %s", destination)
		}
		machine = parts[0]
		remotePath = parts[1]
	} else {
		localPath = destination
		parts := splitMachinePath(source)
		if len(parts) != 2 {
			return fmt.Errorf("invalid source format, expected machine:path, got: %s", source)
		}
		machine = parts[0]
		remotePath = parts[1]
	}

	localPath = expandLocalPath(localPath)

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
		User: username,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	// Connect to Orion-Belt server
	serverAddr := fmt.Sprintf("%s:%d", c.config.Server.Host, c.config.Server.Port)
	c.logger.Debug("Connecting to server %s", serverAddr)
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
		return c.uploadFile(session, localPath, machine, remotePath)
	}
	return c.downloadFile(session, localPath, machine, remotePath)
}

func expandLocalPath(path string) string {
	if path == "." || path == "./" {
		wd, _ := os.Getwd()
		return wd
	}
	if len(path) > 0 && path[0] == '~' {
		home, _ := os.UserHomeDir()
		return home + path[1:]
	}
	return path
}

// uploadFile uploads a file to the remote machine
func (c *SCPClient) uploadFile(session *ssh.Session, source, machine, remotePath string) error {
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
	scpCmd := fmt.Sprintf("%s scp -t %s", machine, remotePath)
	if err := session.Run(scpCmd); err != nil {
		return fmt.Errorf("scp upload failed: %w", err)
	}

	c.logger.Info("File uploaded successfully")
	return nil
}

// downloadFile downloads a file from the remote machine
func (c *SCPClient) downloadFile(session *ssh.Session, destination, machine, remotePath string) error {
	stdout, err := session.StdoutPipe()
	if err != nil {
		return err
	}
	stdin, err := session.StdinPipe()
	if err != nil {
		return err
	}

	scpCmd := fmt.Sprintf("%s scp -f %s", machine, remotePath)
	if err := session.Start(scpCmd); err != nil {
		return err
	}

	fmt.Fprint(stdin, "\x00")
	var header string
	buf := make([]byte, 1)
	for {
		_, err := stdout.Read(buf)
		if err != nil || buf[0] == '\n' {
			break
		}
		header += string(buf)
	}

	if len(header) == 0 {
		return fmt.Errorf("failed to read SCP header (empty response)")
	}
	var perms string
	var size int64
	var filename string
	_, err = fmt.Sscanf(header, "C%s %d %s", &perms, &size, &filename)
	if err != nil {
		return fmt.Errorf("failed to parse SCP header '%s': %w", header, err)
	}

	finalLocalPath := destination
	info, err := os.Stat(destination)
	if err == nil && info.IsDir() {
		finalLocalPath = filepath.Join(destination, filename)
	}

	file, err := os.Create(finalLocalPath)
	if err != nil {
		return fmt.Errorf("failed to create local file: %w", err)
	}
	defer file.Close()

	fmt.Fprint(stdin, "\x00")
	_, err = io.Copy(file, io.LimitReader(stdout, size))
	if err != nil {
		return fmt.Errorf("failed during data transfer: %w", err)
	}

	finalBuf := make([]byte, 1)
	_, _ = stdout.Read(finalBuf)

	fmt.Fprint(stdin, "\x00")

	stdin.Close()
	return session.Wait()
}

// splitMachinePath splits user@machine:path or machine:path
func splitMachinePath(spec string) []string {
	// Handle user@machine:path format
	atIndex := strings.Index(spec, "@")
	colonIndex := strings.Index(spec, ":")

	if colonIndex == -1 {
		return []string{spec}
	}

	// If @ comes before :, it's part of the machine spec
	if atIndex != -1 && atIndex < colonIndex {
		// user@machine:path format
		return []string{spec[:colonIndex], spec[colonIndex+1:]}
	}

	// machine:path format
	return []string{spec[:colonIndex], spec[colonIndex+1:]}
}
