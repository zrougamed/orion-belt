package common

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// HostKeyConfig controls SSH host key verification for clients and agents.
type HostKeyConfig struct {
	// KnownHosts is the path to a known_hosts file. Defaults to ~/.ssh/orion_known_hosts.
	KnownHosts string
	// StrictHostKeyChecking: "yes" (reject unknown), "ask"/"" (TOFU — trust on first use), "no" (insecure).
	StrictHostKeyChecking string
}

// NewHostKeyCallback returns an ssh.HostKeyCallback based on config.
// Empty StrictHostKeyChecking defaults to TOFU ("ask").
func NewHostKeyCallback(cfg HostKeyConfig, logger *Logger) (ssh.HostKeyCallback, error) {
	mode := strings.ToLower(strings.TrimSpace(cfg.StrictHostKeyChecking))
	if mode == "" {
		mode = "ask"
	}

	if mode == "no" {
		if logger != nil {
			logger.Warn("SSH host key verification disabled (strict_host_key_checking=no)")
		}
		return ssh.InsecureIgnoreHostKey(), nil
	}

	path := cfg.KnownHosts
	if path == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("resolve known_hosts path: %w", err)
		}
		path = filepath.Join(home, ".ssh", "orion_known_hosts")
	} else if strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("resolve home for known_hosts: %w", err)
		}
		path = filepath.Join(home, path[2:])
	}

	if err := ensureKnownHostsFile(path); err != nil {
		return nil, err
	}

	base, err := knownhosts.New(path)
	if err != nil {
		return nil, fmt.Errorf("load known_hosts %s: %w", path, err)
	}

	var mu sync.Mutex

	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		err := base(hostname, remote, key)
		if err == nil {
			return nil
		}

		keyErr, ok := err.(*knownhosts.KeyError)
		if !ok {
			return err
		}

		// Key changed — always reject
		if len(keyErr.Want) > 0 {
			return fmt.Errorf("WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED for %s: %w", hostname, err)
		}

		// Unknown host
		if mode == "yes" {
			return fmt.Errorf("host key for %s not in known_hosts (%s); refusing connection", hostname, path)
		}

		// TOFU: record and accept
		mu.Lock()
		defer mu.Unlock()
		line := knownhosts.Line([]string{knownhosts.Normalize(hostname)}, key)
		if appendErr := appendKnownHost(path, line); appendErr != nil {
			return fmt.Errorf("trust-on-first-use failed to write known_hosts: %w", appendErr)
		}
		if logger != nil {
			logger.Info("TOFU: learned host key for %s (%s)", hostname, ssh.FingerprintSHA256(key))
		}
		// Reload callback so subsequent checks see the new entry
		reloaded, reloadErr := knownhosts.New(path)
		if reloadErr == nil {
			base = reloaded
		}
		return nil
	}, nil
}

func ensureKnownHostsFile(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("create known_hosts directory: %w", err)
	}
	f, err := os.OpenFile(path, os.O_RDONLY|os.O_CREATE, 0600)
	if err != nil {
		return fmt.Errorf("create known_hosts file: %w", err)
	}
	return f.Close()
}

func appendKnownHost(path, line string) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0600)
	if err != nil {
		return err
	}
	defer f.Close()

	// Avoid duplicate lines
	existing, _ := os.ReadFile(path)
	scanner := bufio.NewScanner(strings.NewReader(string(existing)))
	for scanner.Scan() {
		if strings.TrimSpace(scanner.Text()) == line {
			return nil
		}
	}

	_, err = fmt.Fprintln(f, line)
	return err
}
