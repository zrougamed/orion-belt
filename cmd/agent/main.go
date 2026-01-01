package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
	"github.com/zrougamed/orion-belt/pkg/agent"
	"github.com/zrougamed/orion-belt/pkg/common"
)

var (
	configFile string
	logLevel   string
)

var rootCmd = &cobra.Command{
	Use:   "orion-belt-agent",
	Short: "Orion-Belt Agent",
	Long:  `Orion-Belt agent runs on target machines to receive SSH connections.`,
	Run:   runAgent,
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&configFile, "config", "c", "/etc/orion-belt/agent.yaml", "config file path")
	rootCmd.PersistentFlags().StringVarP(&logLevel, "log-level", "l", "info", "log level (debug, info, warn, error)")
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func runAgent(cmd *cobra.Command, args []string) {
	// Parse log level
	level := common.INFO
	switch logLevel {
	case "debug":
		level = common.DEBUG
	case "warn":
		level = common.WARN
	case "error":
		level = common.ERROR
	}

	logger := common.NewLogger(level)

	// Load configuration
	config, err := common.LoadConfig(configFile)
	if err != nil {
		logger.Fatal("Failed to load config: %v", err)
	}

	// Create agent
	agt, err := agent.New(config, logger)
	if err != nil {
		logger.Fatal("Failed to create agent: %v", err)
	}

	// Set up signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	// Start agent in goroutine
	errChan := make(chan error, 1)
	go func() {
		errChan <- agt.Start()
	}()

	// Wait for shutdown signal or error
	select {
	case sig := <-sigChan:
		logger.Info("Received signal: %v", sig)
		ctx := context.Background()
		if err := agt.Stop(ctx); err != nil {
			logger.Error("Error stopping agent: %v", err)
		}
	case err := <-errChan:
		if err != nil {
			logger.Fatal("Agent error: %v", err)
		}
	}

	logger.Info("Agent stopped")
}
