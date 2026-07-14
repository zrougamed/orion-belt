package chatops

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// postRocketChat sends a message with attachment buttons to a Rocket.Chat
// Incoming Webhook. NOTE (honest capability disclosure): like Teams, a plain
// Rocket.Chat incoming webhook has no way to receive a callback when a button
// is clicked - Rocket.Chat's "button" action in an attachment just opens a
// URL. So, as with Teams, this uses signed magic links (see sign.go) that hit
// this plugin's own /approve and /deny routes rather than a native
// interactive callback.
func (p *ChatOpsPlugin) postRocketChat(ctx context.Context, text, requestID string) error {
	approveURL, err := signMagicLink(p.cfg.PublicBaseURL, p.cfg.ApprovalSecret, requestID, "approve")
	if err != nil {
		return fmt.Errorf("sign approve link: %w", err)
	}
	denyURL, err := signMagicLink(p.cfg.PublicBaseURL, p.cfg.ApprovalSecret, requestID, "deny")
	if err != nil {
		return fmt.Errorf("sign deny link: %w", err)
	}

	payload := map[string]interface{}{
		"text": text,
		"attachments": []map[string]interface{}{
			{
				"title": "Access Request",
				"text":  text,
				"actions": []map[string]interface{}{
					{"type": "button", "text": "Approve", "url": approveURL},
					{"type": "button", "text": "Deny", "url": denyURL},
				},
			},
		},
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal rocketchat payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.cfg.RocketChat.WebhookURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build rocketchat request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("rocketchat request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("rocketchat webhook returned status %d: %s", resp.StatusCode, string(respBody))
	}
	return nil
}
