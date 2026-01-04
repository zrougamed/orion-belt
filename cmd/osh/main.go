package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/zrougamed/orion-belt/pkg/client"
	"github.com/zrougamed/orion-belt/pkg/common"
)

var (
	configFile     string
	requestAccess  bool
	accessDuration int
	accessReason   string
	listMachines   bool
	username       string
)

var rootCmd = &cobra.Command{
	Use:   "osh [user@]machine",
	Short: "Orion-Belt SSH Client",
	Long:  `osh is the Orion-Belt SSH client for connecting to machines through the Orion-Belt server.`,
	Args:  cobra.MaximumNArgs(1),
	Run:   runSSH,
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&configFile, "config", "c", os.ExpandEnv("$HOME/.orion-belt/client.yaml"), "config file path")
	rootCmd.Flags().BoolVarP(&requestAccess, "request-access", "r", false, "request temporary access")
	rootCmd.Flags().IntVarP(&accessDuration, "duration", "d", 3600, "access duration in seconds")
	rootCmd.Flags().StringVar(&accessReason, "reason", "", "reason for access request")
	rootCmd.Flags().BoolVarP(&listMachines, "list", "l", false, "list available machines")
	rootCmd.Flags().StringVarP(&username, "user", "u", "", "Orion Belt username for authentication")
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func runSSH(cmd *cobra.Command, args []string) {
	logger := common.NewLogger(common.INFO)

	// Load configuration
	config, err := common.LoadConfig(configFile)
	if err != nil {
		// Use default config if file doesn't exist
		config = &common.Config{
			Server: common.ServerConfig{
				Host: "localhost",
				Port: 2222,
			},
			Auth: common.AuthConfig{
				KeyFile: os.ExpandEnv("$HOME/.ssh/id_rsa"),
			},
		}
	}

	// Create client
	sshClient, err := client.NewSSHClient(config, logger)
	if err != nil {
		logger.Fatal("Failed to create SSH client: %v", err)
	}

	// Handle list machines
	if listMachines {
		if err := sshClient.ListMachines(); err != nil {
			logger.Fatal("Failed to list machines: %v", err)
		}
		return
	}

	// Check for target argument
	if len(args) == 0 {
		fmt.Println("Usage: osh [user@]machine")
		fmt.Println("       osh --list")
		fmt.Println("       osh --request-access [user@]machine --reason \"reason\" --duration 3600")
		os.Exit(1)
	}

	target := args[0]

	// Handle access request
	if requestAccess {
		if accessReason == "" {
			logger.Fatal("Access reason is required (use --reason)")
		}

		if err := sshClient.RequestAccess(target, accessReason, accessDuration); err != nil {
			logger.Fatal("Failed to request access: %v", err)
		}
		return
	}

	usernameConfig := config.Auth.User
	if username == "" && usernameConfig == "" {
		logger.Fatal("Configuration error: Username is missing in your config or use --user")
	} else if username == "" {
		username = usernameConfig
	}

	// Connect to machine
	if err := sshClient.Connect(target, username); err != nil {
		logger.Fatal("Connection failed: %v", err)
	}
}
