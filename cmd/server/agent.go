package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"
	"github.com/zrougamed/orion-belt/pkg/common"
	"github.com/zrougamed/orion-belt/pkg/database"
)

var (
	agentName     string
	agentKey      string
	agentHostname string
	agentPort     int
	agentTags     []string
)

var agentCmd = &cobra.Command{
	Use:   "agent",
	Short: "Manage agents",
	Long:  `Register, list, and manage Orion-Belt agents.`,
}

var agentRegisterCmd = &cobra.Command{
	Use:   "register",
	Short: "Register a new agent",
	Long:  `Register a new agent machine with the Orion-Belt server.`,
	Example: `  orion-belt-server agent register --name web-01 --key "ssh-rsa AAAAB3..." --hostname 192.168.1.100 --port 22
  orion-belt-server agent register --name db-01 --key "ssh-ed25519 AAAAC3..." --tags environment=production,role=database`,
	Run: runAgentRegister,
}

var agentListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all registered agents",
	Long:  `List all agents registered with the Orion-Belt server.`,
	Run:   runAgentList,
}

var agentDeleteCmd = &cobra.Command{
	Use:   "delete NAME",
	Short: "Delete an agent",
	Long:  `Delete an agent and its associated machine record.`,
	Args:  cobra.ExactArgs(1),
	Run:   runAgentDelete,
}

func init() {
	agentCmd.AddCommand(agentRegisterCmd)
	agentCmd.AddCommand(agentListCmd)
	agentCmd.AddCommand(agentDeleteCmd)

	// Register flags
	agentRegisterCmd.Flags().StringVarP(&agentName, "name", "n", "", "agent name (required)")
	agentRegisterCmd.Flags().StringVarP(&agentKey, "key", "k", "", "agent SSH public key (required)")
	agentRegisterCmd.Flags().StringVarP(&agentHostname, "hostname", "H", "", "agent hostname (defaults to name)")
	agentRegisterCmd.Flags().IntVarP(&agentPort, "port", "p", 22, "SSH port on the agent machine")
	agentRegisterCmd.Flags().StringSliceVarP(&agentTags, "tags", "t", []string{}, "comma-separated key=value tags")

	agentRegisterCmd.MarkFlagRequired("name")
	agentRegisterCmd.MarkFlagRequired("key")
}

func runAgentRegister(cmd *cobra.Command, args []string) {
	logger := getLogger()
	config, err := loadConfig()
	if err != nil {
		logger.Fatal("Failed to load config: %v", err)
	}

	// Initialize database
	store, err := database.NewStore(config.Database.Driver, config.Database.ConnectionString)
	if err != nil {
		logger.Fatal("Failed to create database store: %v", err)
	}

	ctx := context.Background()
	if err := store.Connect(ctx); err != nil {
		logger.Fatal("Failed to connect to database: %v", err)
	}
	defer store.Close()

	// Validate public key format
	if !strings.HasPrefix(agentKey, "ssh-") {
		logger.Fatal("Invalid SSH public key format. Key must start with ssh-rsa, ssh-ed25519, etc.")
	}

	// Use name as hostname if not provided
	if agentHostname == "" {
		agentHostname = agentName
	}

	// Parse tags
	tagMap := make(map[string]string)
	for _, tag := range agentTags {
		parts := strings.SplitN(tag, "=", 2)
		if len(parts) == 2 {
			tagMap[parts[0]] = parts[1]
		}
	}

	// Check if agent already exists
	existingMachine, _ := store.GetMachineByName(ctx, agentName)
	if existingMachine != nil {
		logger.Fatal("Agent with name '%s' already exists", agentName)
	}

	// Create user account for agent
	agentUser := common.NewUser(agentName, fmt.Sprintf("%s@agent.orion-belt", agentName), agentKey, false)
	if err := store.CreateUser(ctx, agentUser); err != nil {
		logger.Fatal("Failed to create agent user: %v", err)
	}

	// Create machine record
	machine := common.NewMachine(agentName, agentHostname, agentPort, tagMap)
	machine.AgentID = agentUser.ID
	if err := store.CreateMachine(ctx, machine); err != nil {
		// Rollback user creation
		store.DeleteUser(ctx, agentUser.ID)
		logger.Fatal("Failed to create machine: %v", err)
	}

	logger.Info("Agent registered successfully:")
	fmt.Printf("  Name:       %s\n", agentName)
	fmt.Printf("  User ID:    %s\n", agentUser.ID)
	fmt.Printf("  Machine ID: %s\n", machine.ID)
	fmt.Printf("  Hostname:   %s\n", agentHostname)
	fmt.Printf("  Port:       %d\n", agentPort)
	if len(tagMap) > 0 {
		fmt.Printf("  Tags:       ")
		first := true
		for k, v := range tagMap {
			if !first {
				fmt.Printf(", ")
			}
			fmt.Printf("%s=%s", k, v)
			first = false
		}
		fmt.Println()
	}

	fmt.Printf("\nAgent '%s' can now connect to the server using:\n", agentName)
	fmt.Printf("  orion-belt-agent -c /path/to/agent.yaml\n")
}

func runAgentList(cmd *cobra.Command, args []string) {
	logger := getLogger()
	config, err := loadConfig()
	if err != nil {
		logger.Fatal("Failed to load config: %v", err)
	}

	// Initialize database
	store, err := database.NewStore(config.Database.Driver, config.Database.ConnectionString)
	if err != nil {
		logger.Fatal("Failed to create database store: %v", err)
	}

	ctx := context.Background()
	if err := store.Connect(ctx); err != nil {
		logger.Fatal("Failed to connect to database: %v", err)
	}
	defer store.Close()

	// List all machines
	machines, err := store.ListMachines(ctx, 1000, 0)
	if err != nil {
		logger.Fatal("Failed to list machines: %v", err)
	}

	if len(machines) == 0 {
		fmt.Println("No agents registered.")
		return
	}

	// Print table
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "NAME\tHOSTNAME\tPORT\tSTATUS\tLAST SEEN\tTAGS")
	fmt.Fprintln(w, "----\t--------\t----\t------\t---------\t----")

	for _, machine := range machines {
		status := "offline"
		if machine.IsActive {
			status = "online"
		}

		lastSeen := "never"
		if machine.LastSeenAt != nil {
			lastSeen = machine.LastSeenAt.Format("2006-01-02 15:04:05")
		}

		tags := ""
		if len(machine.Tags) > 0 {
			tagPairs := []string{}
			for k, v := range machine.Tags {
				tagPairs = append(tagPairs, fmt.Sprintf("%s=%s", k, v))
			}
			tags = strings.Join(tagPairs, ", ")
		}

		fmt.Fprintf(w, "%s\t%s\t%d\t%s\t%s\t%s\n",
			machine.Name, machine.Hostname, machine.Port, status, lastSeen, tags)
	}
	w.Flush()
}

func runAgentDelete(cmd *cobra.Command, args []string) {
	agentName := args[0]
	logger := getLogger()
	config, err := loadConfig()
	if err != nil {
		logger.Fatal("Failed to load config: %v", err)
	}

	// Initialize database
	store, err := database.NewStore(config.Database.Driver, config.Database.ConnectionString)
	if err != nil {
		logger.Fatal("Failed to create database store: %v", err)
	}

	ctx := context.Background()
	if err := store.Connect(ctx); err != nil {
		logger.Fatal("Failed to connect to database: %v", err)
	}
	defer store.Close()

	// Get machine
	machine, err := store.GetMachineByName(ctx, agentName)
	if err != nil {
		logger.Fatal("Agent '%s' not found", agentName)
	}

	// Delete machine
	if err := store.DeleteMachine(ctx, machine.ID); err != nil {
		logger.Fatal("Failed to delete machine: %v", err)
	}

	// Delete associated user
	if machine.AgentID != "" {
		if err := store.DeleteUser(ctx, machine.AgentID); err != nil {
			logger.Warn("Failed to delete agent user: %v", err)
		}
	}

	fmt.Printf("Agent '%s' deleted successfully.\n", agentName)
}
