package common

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Config represents the base configuration structure
type Config struct {
	Server    ServerConfig                      `yaml:"server"`
	Database  DatabaseConfig                    `yaml:"database,omitempty"`
	Auth      AuthConfig                        `yaml:"auth,omitempty"`
	Agent     AgentConfig                       `yaml:"agent,omitempty"`
	Recording RecordingConfig                   `yaml:"recording,omitempty"`
	Plugins   map[string]map[string]interface{} `yaml:"plugins"`
}

// ServerConfig contains server-specific configuration
type ServerConfig struct {
	Host        string `yaml:"host"`
	Port        int    `yaml:"port"`
	APIPort     int    `yaml:"api_port,omitempty"`
	SSHHostKey  string `yaml:"ssh_host_key,omitempty"`
	APIEndpoint string `yaml:"api_endpoint,omitempty"`
	PluginDir   string `yaml:"plugin_dir"`
}

// DatabaseConfig contains database configuration
type DatabaseConfig struct {
	Driver           string `yaml:"driver"`
	ConnectionString string `yaml:"connection_string"`
}

// AuthConfig contains authentication configuration
type AuthConfig struct {
	KeyFile         string `yaml:"key_file,omitempty"`
	ReBACEnabled    bool   `yaml:"rebac_enabled,omitempty"`
	AllowTempAccess bool   `yaml:"allow_temp_access,omitempty"`
}

// AgentConfig contains agent-specific configuration
type AgentConfig struct {
	Name string            `yaml:"name"`
	Tags map[string]string `yaml:"tags,omitempty"`
}

// RecordingConfig contains session recording configuration
type RecordingConfig struct {
	Enabled       bool   `yaml:"enabled"`
	StoragePath   string `yaml:"storage_path"`
	RetentionDays int    `yaml:"retention_days,omitempty"`
}

// LoadConfig loads configuration from a YAML file
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	return &config, nil
}

// SaveConfig saves configuration to a YAML file
func SaveConfig(path string, config *Config) error {
	data, err := yaml.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}
