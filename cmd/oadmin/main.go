package main

import (
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	"github.com/zrougamed/orion-belt/pkg/client"
	"github.com/zrougamed/orion-belt/pkg/common"
	"golang.org/x/crypto/ssh"
)

var (
	configFile string
	username   string
)

var rootCmd = &cobra.Command{
	Use:   "oadmin",
	Short: "Orion-Belt Admin CLI",
	Long:  `oadmin is the Orion-Belt admin tool for managing access requests and system operations.`,
}

var requestsCmd = &cobra.Command{
	Use:   "requests",
	Short: "Manage access requests",
	Long:  `List, approve, and reject access requests.`,
}

var listRequestsCmd = &cobra.Command{
	Use:   "list",
	Short: "List pending access requests",
	Run:   runListRequests,
}

var approveCmd = &cobra.Command{
	Use:   "approve [request-id]",
	Short: "Approve an access request",
	Args:  cobra.ExactArgs(1),
	Run:   runApprove,
}

var rejectCmd = &cobra.Command{
	Use:   "reject [request-id]",
	Short: "Reject an access request",
	Args:  cobra.ExactArgs(1),
	Run:   runReject,
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&configFile, "config", "c", os.ExpandEnv("$HOME/.orion-belt/client.yaml"), "config file path")
	rootCmd.PersistentFlags().StringVarP(&username, "user", "u", "", "Orion Belt username for authentication")

	requestsCmd.AddCommand(listRequestsCmd)
	requestsCmd.AddCommand(approveCmd)
	requestsCmd.AddCommand(rejectCmd)
	rootCmd.AddCommand(requestsCmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func getAPIClient() (*client.APIClient, error) {
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

	// Get API endpoint
	apiEndpoint := config.Server.APIEndpoint
	if apiEndpoint == "" {
		apiEndpoint = fmt.Sprintf("http://%s:8080", config.Server.Host)
	}

	// Load SSH key
	keyData, err := os.ReadFile(config.Auth.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read SSH key: %w", err)
	}

	signer, err := ssh.ParsePrivateKey(keyData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	// Get username
	user := username
	if user == "" {
		user = config.Auth.User
		if user == "" {
			user = os.Getenv("USER")
			if user == "" {
				return nil, fmt.Errorf("username not configured")
			}
		}
	}

	return client.NewAPIClient(apiEndpoint, user, signer, logger)
}

func runListRequests(cmd *cobra.Command, args []string) {
	apiClient, err := getAPIClient()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	requests, err := apiClient.ListPendingAccessRequests()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error listing requests: %v\n", err)
		os.Exit(1)
	}

	if len(requests) == 0 {
		fmt.Println("No pending access requests.")
		return
	}

	fmt.Printf("Pending Access Requests (%d):\n\n", len(requests))

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "REQUEST ID\tUSER\tMACHINE\tREMOTE USER\tREASON\tDURATION\tREQUESTED")
	fmt.Fprintln(w, "----------\t----\t-------\t-----------\t------\t--------\t---------")

	for _, req := range requests {
		duration := formatDuration(time.Duration(req.Duration) * time.Second)
		requestedAgo := formatDuration(time.Since(req.RequestedAt))
		remoteUser := "default"
		if len(req.RemoteUsers) > 0 {
			remoteUser = req.RemoteUsers[0]
		}

		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			req.ID,
			req.UserID[:8]+"...",
			req.MachineID[:8]+"...",
			remoteUser,
			truncate(req.Reason, 20),
			duration,
			requestedAgo,
		)
	}

	w.Flush()

	fmt.Println("\nUse 'oadmin requests approve <request-id>' to approve")
	fmt.Println("Use 'oadmin requests reject <request-id>' to reject")
}

func runApprove(cmd *cobra.Command, args []string) {
	requestID := args[0]

	apiClient, err := getAPIClient()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// Get current user ID (reviewer)
	// For now, we'll use the username as reviewer ID
	// In production, you'd want to get the actual user ID from the API
	reviewerID := username
	if reviewerID == "" {
		reviewerID = os.Getenv("USER")
	}

	if err := apiClient.ApproveAccessRequest(requestID, reviewerID); err != nil {
		fmt.Fprintf(os.Stderr, "Error approving request: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("✓ Access request %s approved\n", requestID[:8]+"...")
}

func runReject(cmd *cobra.Command, args []string) {
	requestID := args[0]

	apiClient, err := getAPIClient()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// Get current user ID (reviewer)
	reviewerID := username
	if reviewerID == "" {
		reviewerID = os.Getenv("USER")
	}

	if err := apiClient.RejectAccessRequest(requestID, reviewerID); err != nil {
		fmt.Fprintf(os.Stderr, "Error rejecting request: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("✗ Access request %s rejected\n", requestID[:8]+"...")
}

func formatDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	} else if d < time.Hour {
		return fmt.Sprintf("%dm", int(d.Minutes()))
	} else if d < 24*time.Hour {
		return fmt.Sprintf("%dh", int(d.Hours()))
	} else {
		return fmt.Sprintf("%dd", int(d.Hours()/24))
	}
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
