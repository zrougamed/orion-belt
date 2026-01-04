package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/zrougamed/orion-belt/pkg/client"
	"github.com/zrougamed/orion-belt/pkg/common"
)

var (
	configFile string
	username   string
	recursive  bool
)

var rootCmd = &cobra.Command{
	Use:   "ocp source destination",
	Short: "Orion-Belt SCP Client",
	Long:  `ocp is the Orion-Belt SCP client for copying files through the Orion-Belt server.`,
	Args:  cobra.ExactArgs(2),
	Run:   runSCP,
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&configFile, "config", "c", os.ExpandEnv("$HOME/.orion-belt/client.yaml"), "config file path")
	rootCmd.Flags().StringVarP(&username, "user", "u", "", "Orion Belt username for authentication")
	rootCmd.Flags().BoolVarP(&recursive, "recursive", "r", false, "recursively copy directories")
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func runSCP(cmd *cobra.Command, args []string) {
	logger := common.NewLogger(common.INFO)

	source := args[0]
	destination := args[1]

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
	scpClient, err := client.NewSCPClient(config, logger)
	if err != nil {
		logger.Fatal("Failed to create SCP client: %v", err)
	}

	// Determine if upload or download
	isUpload := !strings.Contains(source, ":")

	usernameConfig := config.Auth.User
	if username == "" && usernameConfig == "" {
		logger.Fatal("Configuration error: Username is missing in your config or use --user")
	} else if username == "" {
		username = usernameConfig
	}

	// Copy file
	if err := scpClient.Copy(username, source, destination, isUpload); err != nil {
		logger.Fatal("Copy failed: %v", err)
	}

	logger.Info("Copy completed successfully")
}
