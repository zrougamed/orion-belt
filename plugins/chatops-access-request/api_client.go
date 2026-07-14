package chatops

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// apiClient talks back to Orion Belt's own REST API, using the admin API key
// supplied in this plugin's config. Used both to enrich the outbound chat
// message with human-readable names, and to actually approve/reject access
// requests when an approver clicks a button or magic link.
type apiClient struct {
	baseURL    string
	apiKey     string
	httpClient *http.Client
}

func newAPIClient(baseURL, apiKey string) *apiClient {
	return &apiClient{
		baseURL: strings.TrimRight(baseURL, "/"),
		apiKey:  apiKey,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// apiError captures the {"error": "..."} shape returned by the core API on
// non-2xx responses.
type apiError struct {
	Error string `json:"error"`
}

func (c *apiClient) do(ctx context.Context, method, path string, body io.Reader) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, body)
	if err != nil {
		return nil, 0, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("X-API-Key", c.apiKey)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("read response: %w", err)
	}
	return respBody, resp.StatusCode, nil
}

// GetUsername returns the username for a user ID, or an error if the lookup
// fails for any reason (not found, network error, bad response). Callers
// should treat this as best-effort and fall back to the raw ID.
func (c *apiClient) GetUsername(ctx context.Context, userID string) (string, error) {
	body, status, err := c.do(ctx, http.MethodGet, "/api/v1/users/"+userID, nil)
	if err != nil {
		return "", err
	}
	if status < 200 || status >= 300 {
		return "", fmt.Errorf("get user: status %d", status)
	}
	var user struct {
		Username string `json:"username"`
	}
	if err := json.Unmarshal(body, &user); err != nil {
		return "", fmt.Errorf("decode user: %w", err)
	}
	if user.Username == "" {
		return "", fmt.Errorf("user has no username")
	}
	return user.Username, nil
}

// GetMachineName returns the display name for a machine ID.
func (c *apiClient) GetMachineName(ctx context.Context, machineID string) (string, error) {
	body, status, err := c.do(ctx, http.MethodGet, "/api/v1/machines/"+machineID, nil)
	if err != nil {
		return "", err
	}
	if status < 200 || status >= 300 {
		return "", fmt.Errorf("get machine: status %d", status)
	}
	var machine struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(body, &machine); err != nil {
		return "", fmt.Errorf("decode machine: %w", err)
	}
	if machine.Name == "" {
		return "", fmt.Errorf("machine has no name")
	}
	return machine.Name, nil
}

// resolveAction performs the admin approve/reject call for a request ID.
// action must be "approve" or "deny" ("deny" is mapped to the API's
// "/reject" route). Returns a human-readable error suitable for display in
// chat/HTML on failure.
func (c *apiClient) resolveAction(ctx context.Context, requestID, action string) error {
	var route string
	switch action {
	case "approve":
		route = "approve"
	case "deny":
		route = "reject"
	default:
		return fmt.Errorf("unknown action %q", action)
	}

	body, status, err := c.do(ctx, http.MethodPost, "/api/v1/admin/access-requests/"+requestID+"/"+route, strings.NewReader("{}"))
	if err != nil {
		return err
	}
	if status < 200 || status >= 300 {
		var apiErr apiError
		if jsonErr := json.Unmarshal(body, &apiErr); jsonErr == nil && apiErr.Error != "" {
			return fmt.Errorf("%s", apiErr.Error)
		}
		return fmt.Errorf("request failed with status %d", status)
	}
	return nil
}
