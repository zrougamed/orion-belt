package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/zrougamed/orion-belt/pkg/common"
	"golang.org/x/crypto/ssh"
)

// APIClient handles REST API communication with the Orion-Belt server
type APIClient struct {
	baseURL    string
	httpClient *http.Client
	apiKey     string
	logger     *common.Logger
}

// Machine represents a machine from the API
type Machine struct {
	ID         string            `json:"id"`
	Name       string            `json:"name"`
	Hostname   string            `json:"hostname"`
	Port       int               `json:"port"`
	Tags       map[string]string `json:"tags"`
	AgentID    string            `json:"agent_id"`
	IsActive   bool              `json:"is_active"`
	LastSeenAt *time.Time        `json:"last_seen_at"`
	CreatedAt  time.Time         `json:"created_at"`
	UpdatedAt  time.Time         `json:"updated_at"`
}

// AccessRequest represents an access request from the API
type AccessRequest struct {
	ID          string     `json:"id"`
	UserID      string     `json:"user_id"`
	MachineID   string     `json:"machine_id"`
	RemoteUsers []string   `json:"remote_users"`
	Reason      string     `json:"reason"`
	Duration    int        `json:"duration"`
	Status      string     `json:"status"`
	RequestedAt time.Time  `json:"requested_at"`
	ReviewedAt  *time.Time `json:"reviewed_at"`
	ReviewedBy  *string    `json:"reviewed_by"`
	ExpiresAt   *time.Time `json:"expires_at"`
}

// NewAPIClient creates a new API client with authentication
func NewAPIClient(baseURL, username string, signer ssh.Signer, logger *common.Logger) (*APIClient, error) {
	client := &APIClient{
		baseURL:    baseURL,
		httpClient: &http.Client{Timeout: 30 * time.Second},
		logger:     logger,
	}

	// Authenticate and get API key
	if err := client.authenticate(username, signer); err != nil {
		return nil, fmt.Errorf("authentication failed: %w", err)
	}

	return client, nil
}

// authenticate obtains an API key using SSH public key authentication
func (c *APIClient) authenticate(username string, signer ssh.Signer) error {
	// Get the public key in OpenSSH authorized_keys format
	publicKey := string(ssh.MarshalAuthorizedKey(signer.PublicKey()))

	// Send login request with public key
	loginReq := map[string]interface{}{
		"username":   username,
		"public_key": publicKey,
	}

	var loginResp struct {
		APIKey    string    `json:"api_key"`
		ExpiresAt time.Time `json:"expires_at"`
	}

	// Use the key-based login endpoint
	if err := c.doRequestNoAuth("POST", "/api/v1/public/login/key", loginReq, &loginResp); err != nil {
		return err
	}

	if loginResp.APIKey == "" {
		return fmt.Errorf("no API key returned from login")
	}

	c.apiKey = loginResp.APIKey
	c.logger.Info("Successfully authenticated, API key expires at: %s", loginResp.ExpiresAt.Format(time.RFC3339))
	return nil
}

// doRequestNoAuth performs an HTTP request without authentication (for login)
func (c *APIClient) doRequestNoAuth(method, path string, body interface{}, result interface{}) error {
	var reqBody io.Reader
	if body != nil {
		jsonData, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("failed to marshal request: %w", err)
		}
		reqBody = bytes.NewBuffer(jsonData)
	}

	req, err := http.NewRequest(method, c.baseURL+path, reqBody)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("API error (status %d): %s", resp.StatusCode, string(respBody))
	}

	if result != nil && len(respBody) > 0 {
		if err := json.Unmarshal(respBody, result); err != nil {
			return fmt.Errorf("failed to parse response: %w", err)
		}
	}

	return nil
}

// doRequest performs an HTTP request to the API
func (c *APIClient) doRequest(method, path string, body interface{}, result interface{}) error {
	var reqBody io.Reader
	if body != nil {
		jsonData, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("failed to marshal request: %w", err)
		}
		reqBody = bytes.NewBuffer(jsonData)
	}

	req, err := http.NewRequest(method, c.baseURL+path, reqBody)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	if c.apiKey != "" {
		req.Header.Set("X-API-Key", c.apiKey)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("API error (status %d): %s", resp.StatusCode, string(respBody))
	}

	if result != nil && len(respBody) > 0 {
		if err := json.Unmarshal(respBody, result); err != nil {
			return fmt.Errorf("failed to parse response: %w", err)
		}
	}

	return nil
}

// ListMachines retrieves all available machines
func (c *APIClient) ListMachines() ([]Machine, error) {
	var machines []Machine
	if err := c.doRequest("GET", "/api/v1/machines", nil, &machines); err != nil {
		return nil, err
	}
	return machines, nil
}

// GetMachineByName retrieves a machine by its name
func (c *APIClient) GetMachineByName(name string) (*Machine, error) {
	machines, err := c.ListMachines()
	if err != nil {
		return nil, err
	}

	for _, machine := range machines {
		if machine.Name == name {
			return &machine, nil
		}
	}

	return nil, fmt.Errorf("machine %s not found", name)
}

// CreateAccessRequest creates a new access request
func (c *APIClient) CreateAccessRequest(request map[string]interface{}) (*AccessRequest, error) {
	var accessReq AccessRequest
	if err := c.doRequest("POST", "/api/v1/access-requests", request, &accessReq); err != nil {
		return nil, err
	}
	return &accessReq, nil
}

// GetAccessRequest retrieves an access request by ID
func (c *APIClient) GetAccessRequest(requestID string) (*AccessRequest, error) {
	var accessReq AccessRequest
	if err := c.doRequest("GET", "/api/v1/access-requests/"+requestID, nil, &accessReq); err != nil {
		return nil, err
	}
	return &accessReq, nil
}

// ListPendingAccessRequests retrieves all pending access requests (admin only)
func (c *APIClient) ListPendingAccessRequests() ([]AccessRequest, error) {
	var requests []AccessRequest
	if err := c.doRequest("GET", "/api/v1/access-requests/pending", nil, &requests); err != nil {
		return nil, err
	}
	return requests, nil
}

// ApproveAccessRequest approves an access request (admin only)
func (c *APIClient) ApproveAccessRequest(requestID, reviewerID string) error {
	req := map[string]string{"reviewer_id": reviewerID}
	return c.doRequest("POST", fmt.Sprintf("/api/v1/admin/access-requests/%s/approve", requestID), req, nil)
}

// RejectAccessRequest rejects an access request (admin only)
func (c *APIClient) RejectAccessRequest(requestID, reviewerID string) error {
	req := map[string]string{"reviewer_id": reviewerID}
	return c.doRequest("POST", fmt.Sprintf("/api/v1/admin/access-requests/%s/reject", requestID), req, nil)
}
